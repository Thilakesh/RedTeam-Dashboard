"""Redis-backed fixed-window rate limiter for auth endpoints.

A blunt INCR+EXPIRE fixed window — deliberately not a token bucket. Auth
endpoints (login, refresh, invite-accept) just need a ceiling against
credential stuffing / brute force, not smooth traffic shaping.
"""
from __future__ import annotations

from fastapi import HTTPException, Request, status

from app.core.redis import get_redis


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def rate_limit(key: str, max_requests: int, window_seconds: int):
    """FastAPI dependency factory. Limits by client IP, keyed by ``key``."""

    async def _dep(request: Request) -> None:
        redis = get_redis()
        redis_key = f"ratelimit:{key}:{_client_ip(request)}"
        count = await redis.incr(redis_key)
        if count == 1:
            await redis.expire(redis_key, window_seconds)
        if count > max_requests:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "too many requests, try again later",
            )

    return _dep
