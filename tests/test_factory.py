"""Tests for the telemetry provider factory (M3)."""

from __future__ import annotations

import sys

import pytest

from backend.core.config import AppConfig
from backend.telemetry.auditd_provider import AuditdProvider
from backend.telemetry.base import TelemetryError
from backend.telemetry.bpf_provider import BPFProvider
from backend.telemetry.demo_generator import DemoGenerator
from backend.telemetry.factory import create_provider
from backend.telemetry.process_monitor import ProcessMonitor
from backend.telemetry.tracee_provider import TraceeProvider


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("process_monitor", ProcessMonitor),
        ("demo_generator", DemoGenerator),
        ("auditd", AuditdProvider),
        ("tracee", TraceeProvider),
        ("bpf", BPFProvider),
    ],
)
def test_factory_creates_named_provider(name, expected):
    config = AppConfig.load(overrides={"telemetry.provider": name})
    assert isinstance(create_provider(config), expected)


def test_factory_rejects_unknown_provider():
    config = AppConfig.load(overrides={"telemetry.provider": "alien"})
    with pytest.raises(ValueError, match="Unknown telemetry provider"):
        create_provider(config)


def test_kernel_providers_require_linux():
    if sys.platform == "linux":
        pytest.skip("kernel providers are expected to be usable on Linux")
    config = AppConfig.load(overrides={"telemetry.provider": "auditd"})
    provider = create_provider(config)
    with pytest.raises(TelemetryError, match="requires Linux"):
        provider.start()
