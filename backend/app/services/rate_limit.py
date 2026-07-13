"""Lightweight per-key rate limiting via Redis fixed-window counter."""
from __future__ import annotations

from redis.asyncio import Redis

from app.core.config import get_settings


async def check_rate_limit(key: str, limit: int, window_seconds: int) -> bool:
    """Returns True if this call is within the limit, False if it should be rejected."""
    settings = get_settings()
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    try:
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, window_seconds)
        return count <= limit
    finally:
        await redis.aclose()
