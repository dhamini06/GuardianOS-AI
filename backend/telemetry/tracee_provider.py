"""Tracee provider (Linux, M3).

Runs ``tracee-ebpf --json`` as a subprocess and normalises its JSON event
stream into :class:`KernelEvent` records. Tracee is a full eBPF-based
runtime-tracing engine, so this provider gets precise ``execve``, ``open``,
``connect`` and ``setuid`` probes without maintaining custom BPF programs.

Requires Linux and the ``tracee-ebpf`` binary. For development use
``telemetry.provider=process_monitor``.
"""

from __future__ import annotations

import json

from backend.core.logging import get_logger
from backend.telemetry.base import TelemetryError
from backend.telemetry.parsers import normalize_kernel_record
from backend.telemetry.ring import BoundedProviderMixin, BoundedRing, DropCounter, RateLimiter
from backend.telemetry.sources import SubprocessLineSource, require_linux

logger = get_logger("telemetry.tracee")


class TraceeProvider(BoundedProviderMixin):
    """Subprocess-based Tracee consumer behind the :class:`TelemetryProvider` contract."""

    def __init__(
        self,
        *,
        binary: str = "tracee-ebpf",
        extra_args: list[str] | None = None,
        ring_capacity: int = 10_000,
        max_events: int = 500,
        rate_limit: float = 0.0,
    ) -> None:
        command = [binary, "--json", *(extra_args or [])]
        self._source = SubprocessLineSource(command)
        self._ring = BoundedRing(ring_capacity)
        self._drops = DropCounter()
        self._limiter = RateLimiter(rate_limit) if rate_limit and rate_limit > 0 else None
        self._max_events = max_events
        self._started = False

    # -- lifecycle --------------------------------------------------------
    def start(self) -> None:
        require_linux("TraceeProvider")
        self._source.start()
        self._started = True
        logger.info("TraceeProvider started")

    def stop(self) -> None:
        self._source.stop()
        self._started = False

    # -- core -------------------------------------------------------------
    def collect(self) -> list:
        if not self._started:
            raise TelemetryError("TraceeProvider.collect() called before start()")
        parsed: list = []
        for line in self._source.read_lines():
            if len(parsed) >= self._max_events:
                break
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            parsed.extend(normalize_kernel_record(data))
        return self._deliver(parsed)
