"""Pooled async Redis client.

Single ConnectionPool reused process-wide. Replaces the per-call open/close
pattern in services/queue.py (Arq still uses its own pool internally).
"""
from __future__ import annotations

from functools import lru_cache

from redis.asyncio import ConnectionPool, Redis

from app.core.config import get_settings


@lru_cache
def _pool() -> ConnectionPool:
    return ConnectionPool.from_url(
        get_settings().redis_url,
        decode_responses=True,
        max_connections=50,
    )


def get_redis() -> Redis:
    """Return a Redis client backed by the shared pool. Do NOT call .close()."""
    return Redis(connection_pool=_pool())
