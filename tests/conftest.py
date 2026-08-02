"""Shared fixtures for the GuardianOS-AI test suite."""

from __future__ import annotations

import pytest

from backend.core.config import AppConfig
from backend.telemetry.demo_generator import DemoGenerator, build_scenario


@pytest.fixture()
def app_config() -> AppConfig:
    return AppConfig.load()


@pytest.fixture()
def normal_events() -> list:
    """All events of a varied normal baseline (40 sessions)."""
    return [e for _, e in build_scenario("normal", normal_runs=40)]


@pytest.fixture()
def attack_events() -> list:
    """All events of the canonical attack chain."""
    return [e for _, e in build_scenario("attack")]


@pytest.fixture()
def normal_generator() -> DemoGenerator:
    return DemoGenerator("normal", speed=1e6, normal_runs=40)


@pytest.fixture()
def attack_generator() -> DemoGenerator:
    return DemoGenerator("attack", speed=1e6)
