"""Per-IP token-bucket rate limiter middleware for FastAPI.

Limits API requests to a configurable rate per client IP. When the budget is
exhausted the middleware returns ``429 Too Many Requests`` with a
``Retry-After`` header.  The limiter is in-memory and resets on restart,
which is appropriate for a single-process deployment.
"""

from __future__ import annotations

import threading
import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class _TokenBucket:
    """Thread-safe single-client token bucket."""

    __slots__ = ("capacity", "rate", "tokens", "last_refill")

    def __init__(self, capacity: float, rate: float) -> None:
        self.capacity = capacity
        self.rate = rate  # tokens per second
        self.tokens = capacity
        self.last_refill = time.monotonic()

    def consume(self) -> tuple[bool, float]:
        """Try to consume one token.  Returns (allowed, retry_after_seconds)."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_refill = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True, 0.0
        # How long until 1 token is available?
        wait = (1.0 - self.tokens) / self.rate
        return False, wait


class RateLimitMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that enforces per-IP rate limits on /api routes."""

    def __init__(self, app, *, requests_per_minute: int = 60) -> None:
        super().__init__(app)
        self.rpm = requests_per_minute
        self._rate = requests_per_minute / 60.0  # tokens per second
        self._buckets: dict[str, _TokenBucket] = {}
        self._lock = threading.Lock()

    def _get_bucket(self, ip: str) -> _TokenBucket:
        with self._lock:
            bucket = self._buckets.get(ip)
            if bucket is None:
                bucket = _TokenBucket(capacity=self.rpm, rate=self._rate)
                self._buckets[ip] = bucket
            return bucket

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Only rate-limit /api routes; static files and SPA are unaffected.
        if not request.url.path.startswith("/api/"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        bucket = self._get_bucket(client_ip)
        allowed, retry_after = bucket.consume()
        if not allowed:
            return JSONResponse(
                {"detail": "Rate limit exceeded"},
                status_code=429,
                headers={"Retry-After": str(int(retry_after) + 1)},
            )
        return await call_next(request)
