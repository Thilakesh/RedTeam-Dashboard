from arq import create_pool
from arq.connections import RedisSettings

from app.core.config import get_settings


def _redis_settings() -> RedisSettings:
    return RedisSettings.from_dsn(get_settings().redis_url)


async def enqueue_scan(scan_id: str) -> None:
    pool = await create_pool(_redis_settings())
    try:
        await pool.enqueue_job("run_scan", scan_id)
    finally:
        await pool.close()
