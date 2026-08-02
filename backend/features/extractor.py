"""Behavioural feature extraction from windows of kernel events."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from backend.core.events import EventKind, KernelEvent
from backend.features.names import FEATURE_NAMES

# Executables treated as script interpreters; spawning one from another
# interpreter is a classic polyglot / LOLBin chain.
INTERPRETERS = {"/usr/bin/python3", "/usr/bin/python", "/usr/bin/bash", "/bin/bash", "/bin/sh", "/usr/bin/perl", "/usr/bin/ruby"}

# World-writable directories favoured by payload staging.
SUSPICIOUS_DIRS = ("/tmp", "/dev/shm", "/var/tmp", "/run/user")

@dataclass(slots=True)
class ProcessFeatures:
    """Numeric behavioural features plus the context needed for explanation."""

    pid: int
    exe: str
    chain_key: str
    window_start: float
    window_end: float
    values: dict[str, float] = field(default_factory=dict)
    related_events: list[KernelEvent] = field(default_factory=list)

    def to_vector(self) -> list[float]:
        """Return features in canonical :data:`FEATURE_NAMES` order."""
        return [self.values[name] for name in FEATURE_NAMES]

    @property
    def basename(self) -> str:
        """Executable basename of the chain root, e.g. ``python3``."""
        return self.exe.split("/")[-1].split("\\")[-1]

    def keys(self) -> list[str]:
        return FEATURE_NAMES


def _basename(path: str) -> str:
    return path.split("/")[-1].split("\\")[-1]


def _in_suspicious_dir(path: str) -> bool:
    return any(path.startswith(d) for d in SUSPICIOUS_DIRS)


class FeatureExtractor:
    """Aggregates a time window of events into per-process feature vectors.

    Feature vectors are computed per *behaviour chain* (a process family
    rooted at a session leader), because that is the natural unit the
    detector and explainer reason about.
    """

    def __init__(self) -> None:
        self._chain_depth: dict[str, int] = defaultdict(int)
        self._parent_by_pid: dict[int, int] = {}

    def extract(self, events: list[KernelEvent]) -> list[ProcessFeatures]:
        """Extract one feature vector per behaviour chain present in ``events``."""
        if not events:
            return []

        chains: dict[str, list[KernelEvent]] = defaultdict(list)
        for event in events:
            key = self._chain_key_for(event)
            chains[key].append(event)
            if event.kind in (EventKind.PROCESS_CREATED, EventKind.EXEC):
                self._parent_by_pid[event.pid] = event.ppid

        vectors: list[ProcessFeatures] = []
        for chain_key, chain_events in chains.items():
            vectors.append(self._extract_chain(chain_key=chain_key, events=chain_events))
        return vectors

    # -- per-chain --------------------------------------------------------
    def _extract_chain(
        self,
        *,
        chain_key: str,
        events: list[KernelEvent],
    ) -> ProcessFeatures:
        # Each chain is described by its OWN temporal span, not the whole
        # window's, so features stay stable as the window grows over time.
        chain_start = min(e.timestamp for e in events)
        chain_end = max(e.timestamp for e in events)
        duration = max(chain_end - chain_start, 1.0)
        created = [e for e in events if e.kind == EventKind.PROCESS_CREATED]
        execs = [e for e in events if e.kind == EventKind.EXEC]
        connects = [e for e in events if e.kind == EventKind.NETWORK_CONNECT]
        writes = [e for e in events if e.kind == EventKind.FILE_WRITE]
        escalations = [e for e in events if e.kind == EventKind.PRIVILEGE_ESCALATION]

        spawned = {e.exe for e in created}
        interpreters = [e for e in created if e.exe in INTERPRETERS]
        tmp_execs = [e for e in execs if _in_suspicious_dir(e.exe)]
        downloads = [e for e in connects if e.details.get("remote_port") in (80, 443)]
        remote_ips = {e.details.get("remote_ip") for e in connects}
        suspicious_ports = [
            e for e in connects if _is_suspicious_port(e.details.get("remote_port"))
        ]

        root_pid = min(e.pid for e in created) if created else (events[0].pid if events else 0)
        root_exe = created[0].exe if created else events[0].exe
        depth = self._depth_of(root_pid)

        values: dict[str, float] = {
            "num_children": float(len(created)),
            "exec_frequency": round(len(execs) / duration, 4),
            "unique_binaries_spawned": float(len(spawned)),
            "script_interpreters": float(len(interpreters)),
            "tmp_execs": float(len(tmp_execs)),
            "downloads": float(len(downloads)),
            "unique_remote_ips": float(len(remote_ips)),
            "connections_per_min": round(len(connects) / duration * 60.0, 4),
            "suspicious_ports": float(len(suspicious_ports)),
            "file_writes_per_min": round(len(writes) / duration * 60.0, 4),
            "privilege_escalations": float(len(escalations)),
            "process_depth": float(depth),
            "chain_length": float(len(events)),
        }

        return ProcessFeatures(
            pid=root_pid,
            exe=root_exe,
            chain_key=chain_key,
            window_start=chain_start,
            window_end=chain_end,
            values=values,
            related_events=events,
        )

    # -- helpers ----------------------------------------------------------
    def _chain_key_for(self, event: KernelEvent) -> str:
        # One chain per session/process family. Fall back to the parent pid
        # when the source does not report a session leader (e.g. psutil).
        return str(event.details.get("session_leader") or event.ppid)

    def _depth_of(self, pid: int) -> int:
        depth = 1
        seen: set[int] = set()
        current = pid
        while current in self._parent_by_pid and current not in seen:
            parent = self._parent_by_pid[current]
            if parent == current or parent == 0:
                break
            seen.add(current)
            depth += 1
            current = parent
        return depth


def _is_suspicious_port(port: int | None) -> bool:
    if not port:
        return False
    if port in (80, 443, 22, 53, 8000, 8080):
        return False
    return port > 1024
