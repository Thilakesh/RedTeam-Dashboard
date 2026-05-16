from arq import create_pool
from arq.connections import RedisSettings

from app.core.config import get_settings


def _redis_settings() -> RedisSettings:
    return RedisSettings.from_dsn(get_settings().redis_url)


async def enqueue_scan(scan_id: str, profile: str = "quick") -> None:
    queue_name = "heavy" if profile == "deep" else "default"
    pool = await create_pool(_redis_settings())
    try:
        await pool.enqueue_job("run_scan", scan_id, _queue_name=queue_name)
    finally:
        await pool.close()


async def enqueue_vuln_scan(scan_id: str) -> None:
    pool = await create_pool(_redis_settings())
    try:
        await pool.enqueue_job("run_vuln_scan", scan_id, _queue_name="vuln")
    finally:
        await pool.close()


async def enqueue_investigation_task(task_id: str) -> None:
    pool = await create_pool(_redis_settings())
    try:
        await pool.enqueue_job(
            "run_investigation_task", task_id, _queue_name="investigation"
        )
    finally:
        await pool.close()
