import json
import logging

from redis.asyncio import Redis

log = logging.getLogger(__name__)


async def cache_get(key: str, redis_url: str) -> list[dict] | None:
    """Return cached list of AssetRecord dicts, or None on miss/error."""
    try:
        async with Redis.from_url(redis_url, decode_responses=True) as r:
            raw = await r.get(key)
        return json.loads(raw) if raw else None
    except Exception as exc:
        log.debug("cache_get failed (non-fatal): %s", exc)
        return None


async def cache_set(key: str, redis_url: str, data: list[dict]) -> None:
    """Store list of AssetRecord dicts for 24 hours. Failure is silent."""
    try:
        async with Redis.from_url(redis_url, decode_responses=True) as r:
            await r.setex(key, 86400, json.dumps(data))
    except Exception as exc:
        log.debug("cache_set failed (non-fatal): %s", exc)
