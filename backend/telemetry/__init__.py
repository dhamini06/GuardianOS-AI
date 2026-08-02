"""Telemetry layer (Layer 1).

Collects kernel-observable events from the host and normalises them into
:class:`~backend.core.events.KernelEvent` records. Telemetry sources are
pluggable behind the :class:`TelemetryProvider` protocol.
"""

from backend.telemetry.base import TelemetryError, TelemetryProvider
from backend.telemetry.demo_generator import DemoGenerator
from backend.telemetry.event_bus import EventBuffer
from backend.telemetry.process_monitor import ProcessMonitor

__all__ = [
    "TelemetryProvider",
    "TelemetryError",
    "EventBuffer",
    "ProcessMonitor",
    "DemoGenerator",
]
