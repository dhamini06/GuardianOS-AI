"""Telemetry performance benchmarks (M7d).

Measures the hot paths that carry kernel events end-to-end so regressions in
throughput or per-window latency are visible before release:

1. :class:`BoundedRing` push+drain throughput (collect-time buffering).
2. :class:`EventBuffer` extend+drain (thread-safe transfer point).
3. :class:`BoundedProviderMixin._deliver` (ring + drop counter + rate limit).
4. Pipeline :meth:`~backend.pipeline.GuardianPipeline.analyze_window` latency
   with lazy attribution (cold first window + steady-state windows).

Usage:
    python scripts/benchmark_telemetry.py [--events 200000] [--normal-runs 12]
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.core.config import AppConfig
from backend.core.events import EventKind, KernelEvent, make_event
from backend.pipeline import GuardianPipeline
from backend.telemetry.demo_generator import DemoGenerator
from backend.telemetry.event_bus import EventBuffer
from backend.telemetry.ring import BoundedProviderMixin, BoundedRing, DropCounter


def _event(i: int) -> KernelEvent:
    return make_event(
        EventKind.PROCESS_CREATED,
        pid=1000 + i % 1000,
        ppid=1,
        exe="/usr/bin/python",
        cmdline=("/usr/bin/python", "worker.py", str(i)),
        uid=1000,
        username="dev",
        session_leader=1,
    )


class _DeliverHarness(BoundedProviderMixin):
    def __init__(self, capacity: int) -> None:
        self._ring = BoundedRing(capacity)
        self._drops = DropCounter()
        self._limiter = None


def bench_ring(n: int) -> float:
    events = [_event(i) for i in range(n)]
    ring = BoundedRing(n)
    t0 = time.perf_counter()
    for _ in range(3):
        ring.push_many(events)
        ring.drain()
    elapsed = time.perf_counter() - t0
    return (3 * n) / elapsed


def bench_buffer(n: int) -> float:
    events = [_event(i) for i in range(n)]
    buffer = EventBuffer()
    t0 = time.perf_counter()
    for _ in range(3):
        buffer.extend(events)
        buffer.drain()
    elapsed = time.perf_counter() - t0
    return (3 * n) / elapsed


def bench_deliver(n: int) -> float:
    events = [_event(i) for i in range(n)]
    harness = _DeliverHarness(n)
    t0 = time.perf_counter()
    for _ in range(3):
        harness._deliver(events)
    elapsed = time.perf_counter() - t0
    return (3 * n) / elapsed


def bench_analyze_windows(
    *,
    normal_runs: int = 12,
    n_estimators: int = 32,
    background_samples: int = 8,
) -> dict:
    """Learn a baseline, replay the attack chain, time analyze_window.

    Returns a dict with the number of windows analysed, the cold (first)
    window latency, the steady-state mean latency and the total reports.
    """
    data_dir = Path(tempfile.mkdtemp(prefix="guardian-bench-"))
    config = AppConfig.load(
        overrides={
            "data_dir": str(data_dir),
            "storage.enabled": False,
            "detection.n_estimators": n_estimators,
            "detection.attribution_background_samples": background_samples,
            "detection.refit_interval_windows": 999,
        }
    )
    generator = DemoGenerator("normal", speed=1e6, normal_runs=normal_runs)
    pipeline = GuardianPipeline(config, telemetry=generator)
    while not generator.exhausted:
        pipeline.ingest_tick()
    pipeline.complete_learning()

    generator.reset("attack")
    generator.speed = 100.0
    timings: list[float] = []
    reports = 0
    windows = 0
    while not generator.exhausted and windows < 200:
        t0 = time.perf_counter()
        reports += len(pipeline.analyze_window())
        timings.append(time.perf_counter() - t0)
        windows += 1

    first = timings[0] if timings else 0.0
    mean = sum(timings) / len(timings) if timings else 0.0
    return {
        "windows": windows,
        "first_window_s": round(first, 4),
        "mean_window_s": round(mean, 4),
        "reports": reports,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=200_000)
    parser.add_argument("--normal-runs", type=int, default=12)
    args = parser.parse_args()

    n = args.events
    print("telemetry benchmarks")
    print(f"ring      push+drain: {bench_ring(n):>12,.0f} events/sec")
    print(f"buffer    extend+drain: {bench_buffer(n):>9,.0f} events/sec")
    print(f"deliver   ring+drops+limit: {bench_deliver(n):>6,.0f} events/sec")
    result = bench_analyze_windows(normal_runs=args.normal_runs)
    print(
        "analyze   {windows} windows, first={first_window_s}s, "
        "mean={mean_window_s}s, reports={reports}".format(**result)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
