"""Low-overhead telemetry primitives (M3, hardened in M8).

Kernel-level sources can fire thousands of events per second. These small
building blocks bound memory, account for what had to be dropped, and keep
delivery within a configured rate so the pipeline stays responsive:

* :class:`BoundedRing` - fixed-capacity buffer that drops the *newest*
  events when full (the in-flight analysis window stays coherent) and counts
  every drop.
* :class:`DropCounter` - running and per-collect drop accounting.
* :class:`RateLimiter` - token bucket that caps delivered events per second.
* :class:`BoundedProviderMixin` - shared collect-time delivery logic for
  providers built on these primitives, including an operational
  :meth:`~BoundedProviderMixin.status` snapshot (drops, rate-limiting, last
  error) surfaced on the API health endpoint.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Iterable
from typing import Any

from backend.core.events import KernelEvent
from backend.telemetry.base import ProviderHealth


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
    and call :meth:`_deliver` with freshly parsed events. The mixin tracks
    delivery, ring drops, rate-limited events and the last error so
    :meth:`status` can describe how the source is coping under load.
    """

    _ring: BoundedRing
    _drops: DropCounter
    _limiter: RateLimiter | None
    _rate_drops: DropCounter

    _provider_name: str = "provider"
    _started_at: float | None = None
    _last_collect_at: float | None = None
    _last_error: str | None = None
    _events_delivered: int = 0

    # -- lifecycle hooks --------------------------------------------------
    def mark_started(self) -> None:
        """Reset the operational counters for a fresh start."""
        self._started_at = time.monotonic()
        self._last_collect_at = None
        self._last_error = None
        self._events_delivered = 0
        self._rate_counter().take_recent()  # reset recent rate accounting

    def mark_stopped(self) -> None:
        self._started_at = None

    def _mark_error(self, exc: BaseException) -> None:
        self._last_error = f"{type(exc).__name__}: {exc}"

    def _source_status(self) -> dict[str, Any]:
        """Source-specific diagnostics; overridden by concrete providers."""
        return {}

    def _rate_counter(self) -> DropCounter:
        """Lazily created rate-drop counter (kept in sync with ``_drops``)."""
        if getattr(self, "_rate_drops", None) is None:
            self._rate_drops = DropCounter()
        return self._rate_drops

    # -- core -------------------------------------------------------------
    def _deliver(self, raw_events: list[KernelEvent]) -> list[KernelEvent]:
        ring_drops = self._ring.push_many(raw_events)
        self._drops.record(ring_drops)
        out = self._ring.drain()
        if self._limiter is not None:
            allowed = self._limiter.allow(len(out))
            if allowed < len(out):
                dropped_by_rate = len(out) - allowed
                self._rate_counter().record(dropped_by_rate)
                self._drops.record(dropped_by_rate)
                out = out[:allowed]
        self._events_delivered += len(out)
        self._last_collect_at = time.monotonic()
        return out

    def drop_stats(self) -> dict[str, int]:
        """Combined (ring + rate) drop accounting, in-place counters."""
        return self._drops.snapshot()

    def status(self) -> ProviderHealth:
        """Operational snapshot; recent counters reset on each call."""
        rate = self._rate_counter()
        recent = self._drops.take_recent()
        rate_recent = rate.take_recent()
        return ProviderHealth(
            provider=self._provider_name,
            running=self._started_at is not None,
            started_at=self._started_at,
            last_collect_at=self._last_collect_at,
            events_delivered=self._events_delivered,
            drops_total=self._drops.total - rate.total,
            drops_recent=max(0, recent - rate_recent),
            rate_limited=rate.total,
            last_error=self._last_error,
            source=self._source_status(),
        )
