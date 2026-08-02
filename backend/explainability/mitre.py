"""MITRE ATT&CK technique mapping based on observed behaviour patterns.

The mapper works on the behaviour chain reconstructed from events rather than
on raw scores, which is what makes the mapping *explainable*: each technique
maps back to concrete observable evidence. Rules are deliberately narrow so
normal activity (a pip install, a browser fetch) does not false-positive.
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


def _ref(technique_id: str, name: str, tactic: str) -> MitreReference:
    return MitreReference(
        technique_id=technique_id,
        name=name,
        tactic=tactic,
        url=f"{_BASE}/{technique_id.replace('.', '/')}",
    )


TECHNIQUES: dict[str, MitreReference] = {
    "T1059.004": _ref("T1059.004", "Unix Shell", "Execution"),
    "T1059.006": _ref("T1059.006", "Python", "Execution"),
    "T1105": _ref("T1105", "Ingress Tool Transfer", "Command and Control"),
    "T1204.002": _ref("T1204.002", "Malicious File", "Execution"),
    "T1548.003": _ref("T1548.003", "Sudo and Sudo Caching", "Privilege Escalation"),
    "T1071.001": _ref("T1071.001", "Web Protocols", "Command and Control"),
}


def map_techniques(events: list[KernelEvent]) -> list[MitreReference]:
    """Map an observed behaviour chain to relevant ATT&CK techniques."""
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
    interp_spawns_interp = any(
        e.basename in _INTERPRETER_EXES and e.ppid in pids
        and _pid_exe(e.ppid, chain) in _INTERPRETER_EXES
        for e in created
    )
    if interp_spawns_interp:
        python_parent = any(_pid_exe(e.ppid, chain).startswith("python") for e in created if e.basename in _INTERPRETER_EXES)
        found.append(TECHNIQUES["T1059.006"] if python_parent else TECHNIQUES["T1059.004"])

    # Ingress tool transfer: a downloader fetches something that lands in a
    # staging directory (not a normal package manager flow).
    downloader = any(b in _DOWNLOADERS for b in (created_exes | exec_exes))
    staged_write = any(
        _in_staging(e.details.get("path", "")) for e in writes
    )
    if downloader and staged_write and connects:
        found.append(TECHNIQUES["T1105"])

    # Malicious file execution: a binary executed directly from a staging dir.
    if any(e.exe.startswith(_STAGING_DIRS) for e in execs):
        found.append(TECHNIQUES["T1204.002"])

    # Command and control: a shell making a high-port outbound connection.
    shell_high_port = any(
        e.basename in _INTERPRETER_EXES
        and e.kind == EventKind.NETWORK_CONNECT
        and _is_high_port(e.details.get("remote_port"))
        for e in chain
    )
    if shell_high_port:
        found.append(TECHNIQUES["T1059.004"])

    if escalations:
        found.append(TECHNIQUES["T1548.003"])

    # Generic fallback: any outbound connection without a more specific rule.
    if connects and not any(t in TECHNIQUES for t in ("T1105", "T1059.004")):
        found.append(TECHNIQUES["T1071.001"])

    return _dedupe(found)


def _pid_exe(pid: int, chain: list[KernelEvent]) -> str:
    for e in chain:
        if e.pid == pid:
            return e.basename
    return ""


def _in_staging(path: str) -> bool:
    return any(path.startswith(d) for d in _STAGING_DIRS)


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
