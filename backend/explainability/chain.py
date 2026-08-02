"""Behaviour chain reconstruction for explanations."""

from __future__ import annotations

from backend.core.analysis import ChainStep
from backend.core.events import EventKind, KernelEvent
from backend.features.extractor import INTERPRETERS, SUSPICIOUS_DIRS


def build_chain(events: list[KernelEvent]) -> list[ChainStep]:
    """Rebuild a readable, ordered behaviour chain from a process family."""
    steps: list[ChainStep] = []
    for position, event in enumerate(sorted(events, key=lambda e: e.timestamp), start=1):
        description, suspicious = _describe(event)
        steps.append(
            ChainStep(
                position=position,
                description=description,
                kind=event.kind.value,
                exe=event.basename,
                pid=event.pid,
                suspicious=suspicious,
                detail=event.cwd,
            )
        )
    return steps


def _describe(event: KernelEvent) -> tuple[str, bool]:
    kind = event.kind
    exe = event.basename
    parent_exe = event.cmdline[0].split("/")[-1] if event.cmdline else exe
    suspicious = False

    if kind == EventKind.PROCESS_CREATED:
        if exe in {i.split("/")[-1] for i in INTERPRETERS}:
            suspicious = True
            return f"{parent_exe} spawned script interpreter {exe}", suspicious
        return f"Process {exe} created", suspicious

    if kind == EventKind.EXEC:
        if event.exe.startswith(SUSPICIOUS_DIRS):
            suspicious = True
            return f"Executable launched from {event.exe}", suspicious
        return f"Executed {event.exe}", suspicious

    if kind == EventKind.NETWORK_CONNECT:
        ip = event.details.get("remote_ip")
        port = event.details.get("remote_port")
        suspicious = is_suspicious_connect(ip, port)
        return f"Outbound connection to {ip}:{port} (tcp)", suspicious

    if kind == EventKind.FILE_WRITE:
        path = event.details.get("path", "?")
        if any(path.startswith(d) for d in SUSPICIOUS_DIRS):
            suspicious = True
            return f"Payload written to {path}", suspicious
        return f"File write: {path}", suspicious

    if kind == EventKind.PRIVILEGE_ESCALATION:
        return (
            f"Privilege escalation {event.details.get('from_uid')} -> "
            f"{event.details.get('to_uid')}",
            True,
        )

    if kind == EventKind.PROCESS_EXITED:
        return f"Process {exe} exited", False

    return f"{kind.value}: {event.exe}", suspicious


def is_suspicious_connect(ip: str | None, port: int | None) -> bool:
    """Heuristic: is a remote connection suspicious on its own?"""
    if not ip or not port:
        return False
    if ip.startswith(("10.", "192.168.", "127.", "169.254.")):
        return False
    if ip == "127.0.0.1" or ip.startswith(("::1", "fe80:")):
        return False
    if port in (80, 443, 22, 53):
        return False
    return port > 1024
