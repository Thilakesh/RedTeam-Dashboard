"""Lightweight Redis-backed rate limiter.

Used directly from auth endpoints via `check()`. Not a global middleware —
only the endpoints we care about call it. Keeps the policy explicit and
visible at each rate-limited site.

Pattern: INCR a counter keyed by (rule, identifier). If the counter is 1
after the INCR, set EXPIRE on it. If the counter exceeds the rule's max,
raise HTTP 429.
"""
from __future__ import annotations

from fastapi import HTTPException, Request, status

from app.core.redis import get_redis


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    if request.client is not None:
        return request.client.host
    return "unknown"


async def check(*, rule: str, identifier: str, limit: int, window_seconds: int) -> None:
    """Raise 429 if (rule, identifier) has exceeded `limit` within `window_seconds`."""
    redis = get_redis()
    key = f"ratelimit:{rule}:{identifier}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, window_seconds)
    if count > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"rate limit exceeded: {rule}",
        )


async def check_login(request: Request, *, per_15min: int) -> None:
    await check(
        rule="login",
        identifier=_client_ip(request),
        limit=per_15min,
        window_seconds=15 * 60,
    )


async def check_refresh(request: Request, *, session_id: str, per_min: int) -> None:
    await check(
        rule="refresh",
        identifier=session_id,
        limit=per_min,
        window_seconds=60,
    )
