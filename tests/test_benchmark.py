"""Opt-in performance benchmarks (M7d).

These tests measure telemetry hot paths against generous floors. They are
skipped by default because they add wall-clock time and absolute throughput
varies across CI runners; run them explicitly with ``GUARDIAN_BENCHMARK=1``:

    GUARDIAN_BENCHMARK=1 pytest tests/test_benchmark.py -v
"""

from __future__ import annotations

import os
import time

import pytest

from backend.core.events import EventKind, KernelEvent, make_event
from backend.telemetry.event_bus import EventBuffer
from backend.telemetry.ring import BoundedProviderMixin, BoundedRing, DropCounter
from scripts.benchmark_telemetry import bench_analyze_windows

pytestmark = pytest.mark.skipif(
    os.environ.get("GUARDIAN_BENCHMARK") != "1",
    reason="performance benchmarks are opt-in (set GUARDIAN_BENCHMARK=1)",
)


def _events(n: int) -> list[KernelEvent]:
    return [
        make_event(
            EventKind.PROCESS_CREATED,
            pid=1000 + i % 1000,
            ppid=1,
            exe="/usr/bin/python",
            uid=1000,
            username="dev",
            session_leader=1,
        )
        for i in range(n)
    ]


def _rate(count: int, elapsed: float) -> float:
    return count / max(elapsed, 1e-9)


def test_ring_throughput() -> None:
    events = _events(200_000)
    ring = BoundedRing(len(events))
    t0 = time.perf_counter()
    ring.push_many(events)
    ring.drain()
    assert _rate(len(events), time.perf_counter() - t0) >= 50_000


def test_event_buffer_throughput() -> None:
    events = _events(100_000)
    buffer = EventBuffer()
    t0 = time.perf_counter()
    buffer.extend(events)
    buffer.drain()
    assert _rate(len(events), time.perf_counter() - t0) >= 25_000


def test_deliver_throughput() -> None:
    events = _events(100_000)
    harness = _DeliverHarness()
    t0 = time.perf_counter()
    harness._deliver(events)
    assert _rate(len(events), time.perf_counter() - t0) >= 25_000


def test_analyze_window_latency() -> None:
    result = bench_analyze_windows(normal_runs=10, n_estimators=16, background_samples=4)
    assert result["windows"] >= 1
    assert result["first_window_s"] <= 10.0


class _DeliverHarness(BoundedProviderMixin):
    def __init__(self) -> None:
        self._ring = BoundedRing(100_000)
        self._drops = DropCounter()
        self._limiter = None
