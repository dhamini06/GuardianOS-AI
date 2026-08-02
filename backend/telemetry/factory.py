"""Telemetry provider registry.

Maps the ``telemetry.provider`` config value to a concrete provider
instance. Kernel-level sources (auditd/tracee/bpf) are Linux-only and fail
fast with a clear :class:`TelemetryError` on other platforms.
"""

from __future__ import annotations

from backend.core.config import AppConfig
from backend.telemetry.auditd_provider import AuditdProvider
from backend.telemetry.base import TelemetryProvider
from backend.telemetry.bpf_provider import BPFProvider
from backend.telemetry.demo_generator import DemoGenerator
from backend.telemetry.process_monitor import ProcessMonitor
from backend.telemetry.tracee_provider import TraceeProvider

PROVIDERS = ("process_monitor", "demo_generator", "auditd", "tracee", "bpf")


def create_provider(config: AppConfig) -> TelemetryProvider:
    """Instantiate the telemetry provider named by ``config.telemetry.provider``."""
    name = config.telemetry.provider
    tel = config.telemetry
    kwargs = {
        "ring_capacity": tel.ring_capacity,
        "max_events": tel.max_events_per_collect,
        "rate_limit": tel.rate_limit_per_second,
    }
    if name == "process_monitor":
        return ProcessMonitor()
    if name == "demo_generator":
        return DemoGenerator(scenario="normal", normal_runs=40)
    if name == "auditd":
        return AuditdProvider(log_path=tel.audit_log_path, **kwargs)
    if name == "tracee":
        return TraceeProvider(**kwargs)
    if name == "bpf":
        return BPFProvider(**kwargs)
    raise ValueError(
        f"Unknown telemetry provider {name!r}; expected one of {', '.join(PROVIDERS)}"
    )
