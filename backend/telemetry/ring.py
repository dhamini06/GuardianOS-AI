"""Low-overhead telemetry primitives (M3).

Kernel-level sources can fire thousands of events per second. These small
building blocks bound memory, account for what had to be dropped, and keep
delivery within a configured rate so the pipeline stays responsive:

* :class:`BoundedRing` - fixed-capacity buffer that drops the *newest*
  events when full (the in-flight analysis window stays coherent) and counts
  every drop.
* :class:`DropCounter` - running and per-collect drop accounting.
* :class:`RateLimiter` - token bucket that caps delivered events per second.
* :class:`BoundedProviderMixin` - shared collect-time delivery logic for
  providers built on these primitives.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Iterable

from backend.core.events import KernelEvent


class BoundedRing:
    """Fixed-capacity buffer that drops new events when full, counting them."""

    def __init__(self, capacity: int) -> None:
        if capacity < 1:
            raise ValueError("ring capacity must be >= 1")
        self.capacity = capacity
        self._events: deque[KernelEvent] = deque()
        self._dropped = 0

    def push(self, event: KernelEvent) -> bool:
        if len(self._events) >= self.capacity:
            self._dropped += 1
            return False
        self._events.append(event)
        return True

    def push_many(self, events: Iterable[KernelEvent]) -> int:
        dropped = 0
        for event in events:
            if not self.push(event):
                dropped += 1
        return dropped

    def drain(self) -> list[KernelEvent]:
        out = list(self._events)
        self._events.clear()
        return out

    @property
    def dropped(self) -> int:
        return self._dropped

    def __len__(self) -> int:
        return len(self._events)


class DropCounter:
    """Running and recent drop accounting (e.g. for dashboards)."""

    def __init__(self) -> None:
        self._total = 0
        self._recent = 0

    def record(self, n: int = 1) -> None:
        if n <= 0:
            return
        self._total += n
        self._recent += n

    def take_recent(self) -> int:
        recent = self._recent
        self._recent = 0
        return recent

    @property
    def total(self) -> int:
        return self._total

    def snapshot(self) -> dict[str, int]:
        return {"total": self._total, "recent": self._recent}


class RateLimiter:
    """Token-bucket rate limiter; ``allow(n)`` returns how many of n may pass."""

    def __init__(self, per_second: float, burst: int | None = None) -> None:
        if per_second <= 0:
            raise ValueError("per_second must be > 0")
        self._rate = float(per_second)
        self._capacity = float(burst if burst is not None else max(1, int(per_second)))
        self._tokens = self._capacity
        self._last = time.monotonic()

    def allow(self, n: int) -> int:
        now = time.monotonic()
        self._tokens = min(self._capacity, self._tokens + (now - self._last) * self._rate)
        self._last = now
        granted = min(n, int(self._tokens))
        self._tokens -= granted
        return granted


class BoundedProviderMixin:
    """Shared delivery path for providers using a ring + drop + rate limit.

    Subclasses must set ``_ring``, ``_drops`` and (optionally) ``_limiter``
    and call :meth:`_deliver` with freshly parsed events.
    """

    def _deliver(self, raw_events: list[KernelEvent]) -> list[KernelEvent]:
        ring_drops = self._ring.push_many(raw_events)
        self._drops.record(ring_drops)
        out = self._ring.drain()
        if self._limiter is not None:
            allowed = self._limiter.allow(len(out))
            if allowed < len(out):
                self._drops.record(len(out) - allowed)
                out = out[:allowed]
        return out

    def drop_stats(self) -> dict[str, int]:
        return self._drops.snapshot()
