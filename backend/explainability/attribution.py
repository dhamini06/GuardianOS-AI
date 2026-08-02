"""Feature attribution -> natural-language reasons."""

from __future__ import annotations

from backend.features.extractor import ProcessFeatures

# Features whose semantics are strong enough to surface in an explanation.
# High-cardinality counters (num_children, unique_binaries_spawned,
# process_depth) are kept for the model but produce confusing reasons when
# they deviate (e.g. "launched many distinct binaries (0.0)").
_REASONABLE_FEATURES = {
    "exec_frequency",
    "script_interpreters",
    "tmp_execs",
    "downloads",
    "connections_per_min",
    "suspicious_ports",
    "privilege_escalations",
    "chain_length",
    "file_writes_per_min",
    "unique_remote_ips",
}

_REASON_TEMPLATES: dict[str, tuple[str, bool]] = {
    "exec_frequency": ("executed binaries at an unusually high rate ({value} exec/s)", False),
    "script_interpreters": ("spawned script interpreters (python/bash/perl/sh)", True),
    "tmp_execs": ("executed code from world-writable /tmp or /dev/shm", True),
    "downloads": ("downloaded content from remote hosts", True),
    "connections_per_min": ("made many outbound connections ({value}/min)", True),
    "suspicious_ports": ("dialed out on non-standard high ports", True),
    "privilege_escalations": ("performed a privilege escalation", True),
    "chain_length": ("exhibited an unusually long behaviour chain ({value} events)", True),
    "file_writes_per_min": ("wrote files at an elevated rate ({value}/min)", False),
    "unique_remote_ips": ("contacted many distinct remote IPs ({value})", False),
}

_STRONG_SIGNALS = {
    "script_interpreters",
    "tmp_execs",
    "downloads",
    "connections_per_min",
    "suspicious_ports",
    "privilege_escalations",
}

#: Minimum attribution a feature needs, relative to the strongest feature.
_RELATIVE_MIN = 0.35
_MAX_REASONS = 5


def reasons_from_contributions(vector: ProcessFeatures, contributions: dict[str, float]) -> tuple[list[str], int]:
    """Turn feature attribution into reasons plus a strong-signal count."""
    candidates = {k: v for k, v in contributions.items() if k in _REASONABLE_FEATURES}
    if not candidates:
        return [], 0

    strongest = max(candidates.values())
    cutoff = max(0.005, strongest * _RELATIVE_MIN)

    ordered = sorted(
        ((k, v) for k, v in candidates.items() if v >= cutoff),
        key=lambda kv: kv[1],
        reverse=True,
    )

    reasons: list[str] = []
    strong_count = 0
    for feature, _delta in ordered[:_MAX_REASONS]:
        template, is_strong = _REASON_TEMPLATES[feature]
        if is_strong:
            strong_count += 1
        reasons.append(_render(template, value=_fmt(vector.values.get(feature, 0.0))))

    # Hard-signal reasons are appended regardless of ML attribution so that
    # classic kill-chain indicators are always explained to the analyst.
    signal_reasons, signal_count = _signal_reasons(vector)
    strong_count += signal_count
    for reason in signal_reasons:
        if reason not in reasons:
            reasons.append(reason)
    return reasons[: _MAX_REASONS + len(signal_reasons)], strong_count


def _signal_reasons(vector: ProcessFeatures) -> tuple[list[str], int]:
    v = vector.values
    reasons: list[str] = []
    strong = 0
    if v.get("tmp_execs", 0.0) > 0:
        reasons.append("executed code from world-writable /tmp or /dev/shm")
        strong += 1
    if v.get("suspicious_ports", 0.0) > 0:
        reasons.append("dialed out on non-standard high ports")
        strong += 1
    if v.get("privilege_escalations", 0.0) > 0:
        reasons.append("performed a privilege escalation")
        strong += 1
    if v.get("script_interpreters", 0.0) >= 2:
        reasons.append("spawned script interpreters (python/bash/perl/sh)")
        strong += 1
    return reasons, strong


def narrative_for(
    vector: ProcessFeatures,
    reasons: list[str],
    strong_count: int,
    techniques: list,
) -> str:
    """Compose the top-level analyst summary sentence."""
    exe = vector.basename
    technique_ids = {m.technique_id for m in techniques}

    if "T1059.004" in technique_ids and any("non-standard high ports" in r or "privilege escalation" in r for r in reasons):
        return (
            f"{exe} spawns a shell that dials out on a non-standard high port "
            f"after downloading a payload - this behaviour chain resembles a "
            f"REVERSE SHELL. Investigate immediately."
        )
    if strong_count >= 2 or any("executed code from world-writable" in r for r in reasons):
        return (
            f"{exe} deviates from the machine's learned baseline with a "
            f"behaviour chain resembling a malicious download-and-execute "
            f"workflow (script interpreter -> download -> run from /tmp)."
        )
    if strong_count == 1:
        return (
            f"{exe} shows a single strong behavioural deviation from the "
            f"learned baseline that warrants review."
        )
    return (
        f"{exe} shows mild deviations from the learned baseline; "
        f"confidence is low and this may be new but legitimate activity."
    )


def _render(template: str, **kw) -> str:
    return template.format(**kw)


def _fmt(value: float) -> str:
    return f"{value:.1f}" if abs(value) >= 10 or float(value).is_integer() else f"{value:.2f}"
