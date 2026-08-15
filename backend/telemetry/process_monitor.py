"""psutil-based cross-platform process monitor.

MVP telemetry provider. It diffs process snapshots to emit
``PROCESS_CREATED`` / ``PROCESS_EXITED`` / ``EXEC`` events and diffs TCP/UDP
connection tables to emit ``NETWORK_CONNECT`` events.

This provider works identically on the Linux target and on developer
machines (e.g. Windows/macOS), which keeps local development and CI honest.
Kernel-level precision (eBPF/auditd/Tracee) is a later milestone behind the
same :class:`~backend.telemetry.base.TelemetryProvider` interface.
"""

from __future__ import annotations

import time
from typing import Any

import psutil

from backend.core.events import EventKind, KernelEvent, make_event
from backend.core.logging import get_logger
from backend.telemetry.base import ProviderHealth, TelemetryError

logger = get_logger("telemetry.process_monitor")


def _safe(fn, default: Any = None) -> Any:
    try:
        return fn()
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError, ValueError):
        return default


class ProcessMonitor:
    """A pull-based, diffing process/network monitor backed by psutil."""

    def __init__(self, *, include_network: bool = True) -> None:
        self.include_network = include_network
        self._known_procs: dict[int, tuple[str, float]] = {}
        self._known_conns: set[tuple] = set()
        self._started = False
        self._events_delivered = 0
        self._last_collect_at: float | None = None
        self._last_error: str | None = None

    # -- lifecycle --------------------------------------------------------
    def start(self) -> None:
        self._started = True
        self._events_delivered = 0
        self._last_collect_at = None
        self._last_error = None
        self._baseline()

    def stop(self) -> None:
        self._started = False
        self._known_procs.clear()
        self._known_conns.clear()

    # -- core -------------------------------------------------------------
    def collect(self) -> list[KernelEvent]:
        if not self._started:
            raise TelemetryError("ProcessMonitor.collect() called before start()")
        try:
            events = self._diff_processes()
            if self.include_network:
                events.extend(self._diff_network())
        except Exception as exc:  # noqa: BLE001 - psutil surfaces transient OS faults
            self._last_error = f"{type(exc).__name__}: {exc}"
            raise
        self._events_delivered += len(events)
        self._last_collect_at = time.time()
        return events

    def status(self) -> ProviderHealth:
        return ProviderHealth(
            provider="process_monitor",
            running=self._started,
            last_collect_at=self._last_collect_at,
            events_delivered=self._events_delivered,
            last_error=self._last_error,
        )

    # -- internals --------------------------------------------------------
    def _baseline(self) -> None:
        self._known_procs = self._snapshot_processes()
        self._known_conns = self._snapshot_connections()

    def _snapshot_processes(self) -> dict[int, tuple[str, float]]:
        snap: dict[int, tuple[str, float]] = {}
        for proc in psutil.process_iter(["pid", "create_time"]):
            pid = _safe(lambda p=proc: p.info["pid"])
            ct = _safe(lambda p=proc: p.info["create_time"])
            if pid is not None and ct is not None:
                snap[pid] = (proc.name(), ct)
        return snap

    def _snapshot_connections(self) -> set[tuple]:
        conns: set[tuple] = set()
        for conn in _safe(psutil.net_connections, []):
            laddr = conn.laddr if conn.laddr else ("", 0)
            raddr = conn.raddr if conn.raddr else ("", 0)
            conns.add((conn.pid, conn.fd, conn.family, conn.type, laddr, raddr, conn.status))
        return conns

    def _diff_processes(self) -> list[KernelEvent]:
        now_snapshot = self._snapshot_processes()
        events: list[KernelEvent] = []

        for pid, (name, ct) in now_snapshot.items():
            if pid not in self._known_procs:
                events.append(self._build_process_event(pid, name, EventKind.PROCESS_CREATED, created=ct))
            elif self._known_procs[pid][1] != ct:
                # create_time changed => old process exited and a new PID was reused.
                events.append(
                    make_event(
                        EventKind.PROCESS_EXITED,
                        pid=pid,
                        ppid=0,
                        exe=self._known_procs[pid][0],
                        details={"reason": "pid_reused"},
                    )
                )
                events.append(self._build_process_event(pid, name, EventKind.PROCESS_CREATED, created=ct))

        for pid, (name, _) in self._known_procs.items():
            if pid not in now_snapshot:
                events.append(
                    make_event(EventKind.PROCESS_EXITED, pid=pid, ppid=0, exe=name, details={"reason": "exited"})
                )

        self._known_procs = now_snapshot
        return events

    def _build_process_event(
        self,
        pid: int,
        name: str,
        kind: EventKind,
        *,
        created: float | None = None,
    ) -> KernelEvent:
        proc = _safe(lambda: psutil.Process(pid))
        exe = _safe(lambda: proc.exe(), name)
        cmdline = tuple(_safe(lambda: proc.cmdline(), []) or [])
        ppid = _safe(lambda: proc.ppid(), 0)
        username = _safe(lambda: proc.username(), "unknown")
        cwd = _safe(lambda: proc.cwd())
        created = created or _safe(lambda: proc.create_time(), time.time())
        details: dict[str, Any] = {"name": name, "create_time": created}
        return make_event(
            kind,
            pid=pid,
            ppid=ppid,
            exe=exe,
            cmdline=cmdline,
            username=username,
            cwd=cwd,
            details=details,
            timestamp=time.time(),
            session_leader=ppid,
        )

    def _diff_network(self) -> list[KernelEvent]:
        now_conns = self._snapshot_connections()
        events: list[KernelEvent] = []
        for conn in now_conns - self._known_conns:
            pid, _fd, family, _type, laddr, raddr, status = conn
            if status not in {"ESTABLISHED", "SYN_SENT"}:
                continue
            if not raddr or not raddr[0]:
                continue
            if family == 2:  # AF_INET
                events.append(
                    make_event(
                        EventKind.NETWORK_CONNECT,
                        pid=pid,
                        ppid=0,
                        exe=self._exe_for_pid(pid),
                        details={
                            "remote_ip": str(raddr[0]),
                            "remote_port": int(raddr[1]),
                            "local_ip": str(laddr[0]) if laddr else "",
                            "local_port": int(laddr[1]) if laddr else 0,
                            "protocol": "tcp",
                            "status": status,
                        },
                        session_leader=pid,
                    )
                )
        self._known_conns = now_conns
        return events

    def _exe_for_pid(self, pid: int) -> str:
        proc = _safe(lambda: psutil.Process(pid))
        return _safe(lambda: proc.exe(), proc.name() if proc else "unknown")
