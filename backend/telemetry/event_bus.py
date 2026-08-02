"""Thread-safe event buffer.

The pipeline and telemetry sources may live in different threads; this small
synchronised container is the transfer point between them. It also provides
window slicing so feature engineering always sees bounded time windows.
"""

from __future__ import annotations

import threading
from collections import deque
from collections.abc import Iterable

from backend.core.events import KernelEvent


class EventBuffer:
    """A bounded, thread-safe queue of kernel events."""

    def __init__(self, maxlen: int = 100_000) -> None:
        self._events: deque[KernelEvent] = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def push(self, event: KernelEvent) -> None:
        with self._lock:
            self._events.append(event)

    def extend(self, events: Iterable[KernelEvent]) -> None:
        with self._lock:
            self._events.extend(events)

    def drain(self) -> list[KernelEvent]:
        """Remove and return all buffered events."""
        with self._lock:
            out = list(self._events)
            self._events.clear()
            return out

    def peek(self, since: float | None = None) -> list[KernelEvent]:
        """Return events without removing them; optional timestamp filter."""
        with self._lock:
            if since is None:
                return list(self._events)
            return [e for e in self._events if e.timestamp >= since]

    def window(self, window_seconds: float, now: float | None = None) -> list[KernelEvent]:
        """Return events newer than ``now - window_seconds`` without draining."""
        import time

        reference = now if now is not None else time.time()
        return self.peek(since=reference - window_seconds)

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)
