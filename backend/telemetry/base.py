"""Telemetry provider contracts (Layer 1 interface)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from backend.core.events import KernelEvent


class TelemetryError(RuntimeError):
    """Raised when a telemetry source fails to collect events."""


@dataclass(slots=True)
class ProviderHealth:
    """Operational snapshot of a telemetry provider (M8).

    Exposed on the API ``/api/health`` and the dashboard so operators can see
    not just *whether* a provider is running, but how it is coping: drops,
    rate-limiting, subprocess restarts and the last error. All counters are
    cumulative since :meth:`TelemetryProvider.start`.
    """

    provider: str
    running: bool = False
    started_at: float | None = None
    last_collect_at: float | None = None
    events_delivered: int = 0
    drops_total: int = 0
    drops_recent: int = 0
    rate_limited: int = 0
    restarts: int = 0
    last_error: str | None = None
    source: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "running": self.running,
            "started_at": self.started_at,
            "last_collect_at": self.last_collect_at,
            "events_delivered": self.events_delivered,
            "drops_total": self.drops_total,
            "drops_recent": self.drops_recent,
            "rate_limited": self.rate_limited,
            "restarts": self.restarts,
            "last_error": self.last_error,
            "source": self.source,
        }


@runtime_checkable
class TelemetryProvider(Protocol):
    """Anything that produces :class:`KernelEvent` records.

    Providers are pull-based: the pipeline repeatedly calls :meth:`collect`
    (typically on a fixed interval) and drains whatever arrived since the
    previous call. Providers must be cheap to instantiate and idempotent.
    """

    def start(self) -> None:
        """Initialise the source (open handles, start pollers)."""
        ...

    def stop(self) -> None:
        """Release resources. Safe to call multiple times."""
        ...

    def collect(self) -> list[KernelEvent]:
        """Return events observed since the previous call."""
        ...

    def status(self) -> ProviderHealth:
        """Operational snapshot for dashboards and health checks."""
        ...
