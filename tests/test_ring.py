"""Tests for M3 low-overhead telemetry primitives (ring/drop/rate-limit)."""

from __future__ import annotations

import pytest

from backend.core.events import EventKind, make_event
from backend.telemetry.ring import BoundedProviderMixin, BoundedRing, DropCounter, RateLimiter


def _event(i: int = 0):
    return make_event(EventKind.EXEC, pid=i, ppid=0, exe=f"/bin/x{i}")


def test_ring_drops_new_events_when_full():
    ring = BoundedRing(capacity=2)
    assert ring.push(_event(1))
    assert ring.push(_event(2))
    assert not ring.push(_event(3))  # full -> dropped
    assert ring.dropped == 1
    assert len(ring) == 2


def test_ring_drain_empties():
    ring = BoundedRing(capacity=10)
    ring.push_many([_event(1), _event(2)])
    assert [e.pid for e in ring.drain()] == [1, 2]
    assert len(ring) == 0


def test_ring_push_many_returns_dropped_count():
    ring = BoundedRing(capacity=2)
    assert ring.push_many([_event(1), _event(2), _event(3), _event(4)]) == 2
    assert ring.dropped == 2


def test_ring_rejects_zero_capacity():
    with pytest.raises(ValueError):
        BoundedRing(0)


def test_drop_counter_aggregates():
    counter = DropCounter()
    counter.record(3)
    counter.record()
    assert counter.total == 4
    assert counter.take_recent() == 4
    assert counter.take_recent() == 0


def test_rate_limiter_burst_then_throttle(monkeypatch):
    now = 1000.0

    def fake_monotonic():
        return now

    monkeypatch.setattr("backend.telemetry.ring.time.monotonic", fake_monotonic)
    limiter = RateLimiter(per_second=10, burst=5)
    assert limiter.allow(5) == 5  # full burst
    assert limiter.allow(5) == 0  # no tokens left, no time passed


def test_rate_limiter_refills_over_time(monkeypatch):
    now = 1000.0

    def fake_monotonic():
        return now

    monkeypatch.setattr("backend.telemetry.ring.time.monotonic", fake_monotonic)
    limiter = RateLimiter(per_second=10, burst=5)
    assert limiter.allow(5) == 5
    now += 0.2  # 2 tokens accrue
    assert limiter.allow(5) == 2


def test_rate_limiter_rejects_zero_rate():
    with pytest.raises(ValueError):
        RateLimiter(per_second=0)


def test_bounded_provider_mixin_delivers_and_accounts(monkeypatch):
    now = 1000.0

    def fake_monotonic():
        return now

    monkeypatch.setattr("backend.telemetry.ring.time.monotonic", fake_monotonic)

    class Dummy(BoundedProviderMixin):
        def __init__(self):
            self._ring = BoundedRing(capacity=4)
            self._drops = DropCounter()
            self._limiter = RateLimiter(per_second=1, burst=2)

    dummy = Dummy()
    events = [_event(i) for i in range(10)]
    delivered = dummy._deliver(events)
    # ring drops 6, rate limiter (burst 2) lets 2 through, drops the rest.
    assert len(delivered) == 2
    stats = dummy.drop_stats()
    assert stats["total"] >= 8


def test_bounded_provider_status_tracks_delivery(monkeypatch):
    now = 1000.0

    def fake_monotonic():
        return now

    monkeypatch.setattr("backend.telemetry.ring.time.monotonic", fake_monotonic)

    class Dummy(BoundedProviderMixin):
        def __init__(self):
            self._ring = BoundedRing(capacity=100)
            self._drops = DropCounter()
            self._limiter = None

    dummy = Dummy()
    assert not dummy.status().running
    dummy.mark_started()
    dummy._deliver([_event(i) for i in range(3)])
    health = dummy.status()
    assert health.running
    assert health.provider == "provider"
    assert health.events_delivered == 3
    assert health.drops_total == 0
    assert health.last_collect_at is not None
    dummy.mark_stopped()
    assert not dummy.status().running


def test_bounded_provider_status_counts_rate_limited(monkeypatch):
    now = 1000.0

    def fake_monotonic():
        return now

    monkeypatch.setattr("backend.telemetry.ring.time.monotonic", fake_monotonic)

    class Dummy(BoundedProviderMixin):
        def __init__(self):
            self._ring = BoundedRing(capacity=100)
            self._drops = DropCounter()
            self._limiter = RateLimiter(per_second=1, burst=2)

    dummy = Dummy()
    dummy.mark_started()
    dummy._deliver([_event(i) for i in range(10)])
    health = dummy.status()
    assert health.events_delivered == 2
    assert health.rate_limited == 8
    assert health.drops_total == 0  # ring had capacity; the limiter held the rest
