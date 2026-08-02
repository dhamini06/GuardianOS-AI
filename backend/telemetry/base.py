"""Telemetry provider contracts (Layer 1 interface)."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from backend.core.events import KernelEvent


class TelemetryError(RuntimeError):
    """Raised when a telemetry source fails to collect events."""


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
