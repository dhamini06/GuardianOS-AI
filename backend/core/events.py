"""Kernel telemetry event model.

The ``KernelEvent`` is the canonical, telemetry-source-agnostic record that
flows through the entire pipeline (Layer 1 output).

Any telemetry provider (psutil polling, auditd, eBPF, Tracee) must normalise
its raw output into :class:`KernelEvent` instances so downstream layers never
need to know where a datum came from.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class EventKind(StrEnum):
    """High level categories of kernel-observable activity."""

    PROCESS_CREATED = "process_created"
    PROCESS_EXITED = "process_exited"
    EXEC = "exec"
    NETWORK_CONNECT = "network_connect"
    FILE_WRITE = "file_write"
    FILE_READ = "file_read"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    AUTHENTICATION = "authentication"
    MODULE_LOAD = "module_load"
    SOCKET_BIND = "socket_bind"
    SIGNAL = "signal"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


@dataclass(slots=True)
class KernelEvent:
    """A single normalised operating-system security-relevant event."""

    kind: EventKind
    pid: int
    ppid: int
    exe: str
    cmdline: tuple[str, ...]
    timestamp: float = field(default_factory=time.time)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    uid: int = 0
    username: str = "unknown"
    cwd: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def basename(self) -> str:
        """Executable basename, e.g. ``/usr/bin/bash`` -> ``bash``."""
        return self.exe.split("/")[-1].split("\\")[-1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "kind": self.kind.value,
            "timestamp": self.timestamp,
            "pid": self.pid,
            "ppid": self.ppid,
            "exe": self.exe,
            "cmdline": list(self.cmdline),
            "uid": self.uid,
            "username": self.username,
            "cwd": self.cwd,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> KernelEvent:
        return cls(
            kind=EventKind(data["kind"]),
            timestamp=float(data["timestamp"]),
            event_id=data["event_id"],
            pid=int(data["pid"]),
            ppid=int(data["ppid"]),
            exe=data["exe"],
            cmdline=tuple(data.get("cmdline", ())),
            uid=int(data.get("uid", 0)),
            username=data.get("username", "unknown"),
            cwd=data.get("cwd"),
            details=data.get("details", {}),
        )


def event_chain_key(event: KernelEvent) -> str:
    """Stable grouping key used to reconstruct process behaviour chains.

    Chains are grouped by the top-most ancestor (root process of the session)
    plus the initial binary, so that a Python process spawning bash spawning
    curl forms a single analysable chain.
    """
    root = event.details.get("session_leader") or event.ppid
    return f"{root}:{event.basename}"


def make_event(
    kind: EventKind,
    *,
    pid: int,
    ppid: int,
    exe: str,
    cmdline: tuple[str, ...] = (),
    uid: int = 0,
    username: str = "unknown",
    cwd: str | None = None,
    details: dict[str, Any] | None = None,
    timestamp: float | None = None,
    session_leader: int | None = None,
) -> KernelEvent:
    """Factory helper that fills sane defaults and chain metadata."""
    merged: dict[str, Any] = dict(details or {})
    if session_leader is not None:
        merged["session_leader"] = session_leader
    return KernelEvent(
        kind=kind,
        pid=pid,
        ppid=ppid,
        exe=exe,
        cmdline=cmdline,
        uid=uid,
        username=username,
        cwd=cwd,
        details=merged,
        timestamp=timestamp or time.time(),
    )
