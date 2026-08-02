"""MITRE ATT&CK technique mapping based on observed behaviour patterns.

The mapper works on the behaviour chain reconstructed from events rather than
on raw scores, which is what makes the mapping *explainable*: each technique
maps back to concrete observable evidence and carries a confidence that grows
with the strength of that evidence. Rules are deliberately narrow so normal
activity (a pip install, a browser fetch) does not false-positive.
"""

from __future__ import annotations

from backend.core.analysis import MitreReference
from backend.core.events import EventKind, KernelEvent

_BASE = "https://attack.mitre.org/techniques"

#: Interpreters that dominate malware chains (LOLBins + scripting runtimes).
_INTERPRETER_EXES = {"bash", "sh", "python", "python3", "perl", "ruby"}
#: Downloader binaries used to stage payloads.
_DOWNLOADERS = {"curl", "wget"}
#: Locations payloads are staged in before execution.
_STAGING_DIRS = ("/tmp", "/dev/shm", "/var/tmp", "/run/user")
#: Persistence drop paths (cron + systemd user/system units).
_CRON_DIRS = ("/etc/cron", "/var/spool/cron")
_SYSTEMD_DIRS = ("/etc/systemd/system", "/usr/lib/systemd/system", "~/.config/systemd")

#: Technique metadata keyed by technique id.
_METADATA: dict[str, tuple[str, str]] = {
    "T1059.004": ("Unix Shell", "Execution"),
    "T1059.006": ("Python", "Execution"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1204.002": ("Malicious File", "Execution"),
    "T1548.003": ("Sudo and Sudo Caching", "Privilege Escalation"),
    "T1071.001": ("Web Protocols", "Command and Control"),
    "T1053.003": ("Cron", "Persistence"),
    "T1543.002": ("Systemd Service", "Persistence"),
}

_STRONG_CONF = 0.85
_BASE_CONF = 0.65


def _ref(technique_id: str, confidence: float) -> MitreReference:
    name, tactic = _METADATA[technique_id]
    return MitreReference(
        technique_id=technique_id,
        name=name,
        tactic=tactic,
        url=f"{_BASE}/{technique_id.replace('.', '/')}",
        confidence=round(min(1.0, max(0.0, confidence)), 3),
    )


def map_techniques(events: list[KernelEvent]) -> list[MitreReference]:
    """Map an observed behaviour chain to relevant ATT&CK techniques."""
    if not events:
        return []
    found: list[MitreReference] = []
    chain = sorted(events, key=lambda e: e.timestamp)

    created = [e for e in chain if e.kind == EventKind.PROCESS_CREATED]
    execs = [e for e in chain if e.kind == EventKind.EXEC]
    connects = [e for e in chain if e.kind == EventKind.NETWORK_CONNECT]
    writes = [e for e in chain if e.kind == EventKind.FILE_WRITE]
    escalations = [e for e in chain if e.kind == EventKind.PRIVILEGE_ESCALATION]

    pids = {e.pid for e in chain}
    created_exes = {e.exe.split("/")[-1] for e in created}
    exec_exes = {e.exe.split("/")[-1] for e in execs}

    # A shell or interpreter spawned BY another interpreter.
    interp_children = [e for e in created if e.basename in _INTERPRETER_EXES]
    interp_spawns_interp = any(
        e.ppid in pids and _pid_exe(e.ppid, chain) in _INTERPRETER_EXES
        for e in interp_children
    )
    if interp_spawns_interp:
        python_parent = any(
            _pid_exe(e.ppid, chain).startswith("python") for e in interp_children
        )
        technique = "T1059.006" if python_parent else "T1059.004"
        conf = _BASE_CONF + 0.1 * min(len(interp_children), 2) + (0.1 if connects else 0.0)
        found.append(_ref(technique, conf))

    # Ingress tool transfer: a downloader fetches something that lands in a
    # staging directory (not a normal package manager flow).
    downloader = any(b in _DOWNLOADERS for b in (created_exes | exec_exes))
    staged_write = any(_in_dirs(e.details.get("path", ""), _STAGING_DIRS) for e in writes)
    if downloader and staged_write and connects:
        conf = _BASE_CONF + (0.15 if len(connects) > 1 else 0.05) + (0.1 if staged_write else 0.0)
        found.append(_ref("T1105", conf))

    # Malicious file execution: a binary executed directly from a staging dir.
    tmp_execs = [e for e in execs if e.exe.startswith(_STAGING_DIRS)]
    if tmp_execs:
        conf = _STRONG_CONF + 0.1 * min(len(tmp_execs), 2)
        found.append(_ref("T1204.002", conf))

    # Command and control: a shell making a high-port outbound connection.
    shell_high_port = [
        e for e in chain
        if e.basename in _INTERPRETER_EXES
        and e.kind == EventKind.NETWORK_CONNECT
        and _is_high_port(e.details.get("remote_port"))
    ]
    if shell_high_port:
        conf = _BASE_CONF + 0.1 * min(len(shell_high_port), 2)
        found.append(_ref("T1059.004", conf))

    if escalations:
        conf = _STRONG_CONF + 0.05 * min(len(escalations), 2)
        found.append(_ref("T1548.003", conf))

    # Persistence: cron jobs / systemd units dropped onto disk.
    cron_writes = [e for e in writes if _in_dirs(e.details.get("path", ""), _CRON_DIRS)]
    if cron_writes:
        found.append(_ref("T1053.003", _STRONG_CONF + 0.1 * min(len(cron_writes), 2)))
    systemd_writes = [e for e in writes if _in_dirs(e.details.get("path", ""), _SYSTEMD_DIRS)]
    if systemd_writes:
        found.append(_ref("T1543.002", _STRONG_CONF + 0.1 * min(len(systemd_writes), 2)))

    # Generic fallback: any outbound connection without a more specific rule.
    if connects and not any(t in _METADATA for t in ("T1105", "T1059.004")):
        found.append(_ref("T1071.001", 0.5))

    return _dedupe(found)


def _pid_exe(pid: int, chain: list[KernelEvent]) -> str:
    for e in chain:
        if e.pid == pid:
            return e.basename
    return ""


def _in_dirs(path: str, dirs: tuple[str, ...]) -> bool:
    return any(path.startswith(d) for d in dirs)


def _is_high_port(port: int | None) -> bool:
    if not port:
        return False
    return port > 1024 and port not in (8080, 8000)


def _dedupe(refs: list[MitreReference]) -> list[MitreReference]:
    seen: set[str] = set()
    out: list[MitreReference] = []
    for ref in refs:
        if ref.technique_id not in seen:
            seen.add(ref.technique_id)
            out.append(ref)
    return out
