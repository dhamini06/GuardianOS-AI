"""Thread-safe ring buffer of recent pipeline changes for live streaming.

The WebSocket endpoint polls this log with a sequence number and only
delivers the changes a client has not seen yet. It is written by the
pipeline driver thread and read by asyncio WebSocket handlers.
"""

from __future__ import annotations

import threading
from collections import deque


class ChangeLog:
    """Monotonic, thread-safe log of the last ``maxlen`` changes."""

    def __init__(self, maxlen: int = 1000) -> None:
        self._deque: deque[tuple[int, str, dict]] = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._seq = 0

    def record(self, kind: str, data: dict) -> int:
        """Append a change; returns its global sequence number."""
        with self._lock:
            self._seq += 1
            self._deque.append((self._seq, kind, data))
            return self._seq

    def since(self, after_seq: int) -> list[dict]:
        """Return every recorded change with ``seq > after_seq``."""
        with self._lock:
            return [
                {"seq": seq, "kind": kind, "data": data}
                for seq, kind, data in self._deque
                if seq > after_seq
            ]

    @property
    def last_seq(self) -> int:
        with self._lock:
            return self._seq
