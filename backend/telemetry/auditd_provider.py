"""auditd log provider (Linux, M3).

Tails ``/var/log/audit/audit.log`` (or a configured path) and reassembles
multi-record audit events (``SYSCALL`` + ``EXECVE``/``PATH``/``SOCKADDR``)
into :class:`KernelEvent` records. Events are aggregated in a bounded ring,
dropped events are accounted, and delivery is capped by a per-second rate
limit and a per-collect budget so the pipeline never stalls.

Requires Linux. For development use ``telemetry.provider=process_monitor``.
"""

from __future__ import annotations

from backend.core.logging import get_logger
from backend.telemetry.base import TelemetryError
from backend.telemetry.parsers import AuditRecordParser
from backend.telemetry.ring import BoundedProviderMixin, BoundedRing, DropCounter, RateLimiter
from backend.telemetry.sources import AuditLogSource, require_linux

logger = get_logger("telemetry.auditd")


class AuditdProvider(BoundedProviderMixin):
    """Pull-based auditd log tailer behind the :class:`TelemetryProvider` contract."""

    def __init__(
        self,
        *,
        log_path: str = "/var/log/audit/audit.log",
        ring_capacity: int = 10_000,
        max_events: int = 500,
        rate_limit: float = 0.0,
    ) -> None:
        self._source = AuditLogSource(log_path)
        self._parser = AuditRecordParser()
        self._ring = BoundedRing(ring_capacity)
        self._drops = DropCounter()
        self._limiter = RateLimiter(rate_limit) if rate_limit and rate_limit > 0 else None
        self._max_events = max_events
        self._started = False

    # -- lifecycle --------------------------------------------------------
    def start(self) -> None:
        require_linux("AuditdProvider")
        self._source.start()
        self._started = True
        logger.info("AuditdProvider tailing %s", self._source.path)

    def stop(self) -> None:
        self._source.stop()
        self._started = False

    # -- core -------------------------------------------------------------
    def collect(self) -> list:
        if not self._started:
            raise TelemetryError("AuditdProvider.collect() called before start()")
        parsed: list = []
        for line in self._source.read_new_lines()[: self._max_events]:
            parsed.extend(self._parser.feed(line))
            if len(parsed) >= self._max_events:
                break
        parsed.extend(self._parser.flush())
        return self._deliver(parsed)
