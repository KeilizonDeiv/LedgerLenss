"""Sliding-window rate limiter used as a FastAPI dependency.

Trade-off: state is in-process, so with N replicas the effective limit is N x limit.
That's acceptable for a single node; for horizontal scaling swap the store for
Redis (same interface, INCR + EXPIRE) — the dependency signature doesn't change.
"""
import asyncio
import time
from collections import defaultdict, deque

from fastapi import Request

from app.core.errors import RateLimited


class SlidingWindowLimiter:
    def __init__(self, limit: int, window_seconds: float = 60.0) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def allow(self, key: str) -> bool:
        now = time.monotonic()
        async with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True


def rate_limit(bucket: str, setting_name: str):
    """Dependency factory: rate_limit("login", "login_rate_per_minute")."""

    async def _dependency(request: Request) -> None:
        state = request.app.state
        limiter = state.rate_limiters.get(bucket)
        if limiter is None:
            limiter = state.rate_limiters[bucket] = SlidingWindowLimiter(getattr(state.settings, setting_name))
        # Behind a proxy run uvicorn with --proxy-headers so client.host is the real IP.
        client = request.client.host if request.client else "unknown"
        if not await limiter.allow(f"{bucket}:{client}"):
            raise RateLimited(retry_after=60)

    return _dependency
