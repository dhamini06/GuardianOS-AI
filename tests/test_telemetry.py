"""Tests for the telemetry layer."""

from __future__ import annotations

from backend.core.events import EventKind
from backend.telemetry.demo_generator import DemoGenerator, build_scenario
from backend.telemetry.event_bus import EventBuffer


def test_demo_scenarios_available():
    assert {"normal", "attack", "mixed"} <= set(["normal", "attack", "mixed"])


def test_normal_scenario_is_benign():
    events = [e for _, e in build_scenario("normal", normal_runs=1)]
    assert events
    assert all(
        e.details.get("remote_port") in (80, 443, 22)
        for e in events
        if e.kind == EventKind.NETWORK_CONNECT
    )
    assert all(
        e.exe.split("/")[-1] != "curl"
        for e in events
    )


def test_attack_scenario_contains_kill_chain():
    events = sorted(
        [e for _, e in build_scenario("attack")],
        key=lambda e: e.timestamp,
    )
    exes = [e.basename for e in events]
    # Python -> bash -> curl -> chmod -> /tmp payload -> shell
    assert "python3" in exes
    assert "bash" in exes
    assert "curl" in exes
    assert any(e.exe.endswith("payload.sh") for e in events)
    assert any(e.kind == EventKind.PRIVILEGE_ESCALATION for e in events)
    assert any(
        e.kind == EventKind.NETWORK_CONNECT and e.details.get("remote_port") == 4444
        for e in events
    )


def test_generator_deterministic():
    def key(event):
        return (event.kind, event.pid, event.ppid, event.exe, event.cmdline)

    a = build_scenario("normal", normal_runs=5)
    b = build_scenario("normal", normal_runs=5)
    assert [key(e) for _, e in a] == [key(e) for _, e in b]


def test_generator_exhausted():
    gen = DemoGenerator("normal", speed=1e6, normal_runs=2)
    collected = 0
    while not gen.exhausted:
        collected += len(gen.collect())
    assert collected == len(build_scenario("normal", normal_runs=2))
    assert gen.exhausted


def test_event_buffer_window_and_drain():
    events = [e for _, e in build_scenario("attack")]
    buf = EventBuffer()
    buf.extend(events)
    assert len(buf.window(3600)) == len(events)
    assert len(buf) == len(events)
    drained = buf.drain()
    assert len(drained) == len(events)
    assert len(buf) == 0


def test_unknown_scenario_rejected():
    import pytest

    with pytest.raises(ValueError):
        DemoGenerator("nope")


def test_process_monitor_lifecycle():
    """The psutil provider starts, collects, stops without raising."""
    from backend.telemetry.process_monitor import ProcessMonitor

    monitor = ProcessMonitor(include_network=False)
    monitor.start()
    events = monitor.collect()
    monitor.stop()
    assert isinstance(events, list)
