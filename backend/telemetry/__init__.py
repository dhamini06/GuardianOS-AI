"""Telemetry layer (Layer 1).

Collects kernel-observable events from the host and normalises them into
:class:`~backend.core.events.KernelEvent` records. Telemetry sources are
pluggable behind the :class:`TelemetryProvider` protocol. Sources include
the cross-platform psutil :class:`ProcessMonitor`, the deterministic
:class:`DemoGenerator`, and Linux kernel-level providers (auditd log, Tracee,
eBPF/BCC) with bounded-ring aggregation, drop accounting and rate limits.
"""

from backend.telemetry.auditd_provider import AuditdProvider
from backend.telemetry.base import TelemetryError, TelemetryProvider
from backend.telemetry.bpf_provider import BPFProvider
from backend.telemetry.demo_generator import DemoGenerator
from backend.telemetry.event_bus import EventBuffer
from backend.telemetry.factory import create_provider
from backend.telemetry.process_monitor import ProcessMonitor
from backend.telemetry.tracee_provider import TraceeProvider

__all__ = [
    "TelemetryProvider",
    "TelemetryError",
    "EventBuffer",
    "ProcessMonitor",
    "DemoGenerator",
    "AuditdProvider",
    "TraceeProvider",
    "BPFProvider",
    "create_provider",
]
