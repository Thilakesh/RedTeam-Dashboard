"""Custom Prometheus gauges for arq queue depth + worker liveness (Phase 6 of
the observability roadmap). Standard HTTP request metrics come from
prometheus-fastapi-instrumentator (wired in main.py); this covers what it
can't see — Redis-side queue/worker state.

Reads arq's own per-queue health-check key (`{queue}:health-check`, written
by every running worker on its health-check interval) rather than scanning
Redis for job keys — it already contains queued/complete/failed/ongoing
counts as a single string, e.g. "Jul-13 14:19:40 j_complete=0 j_failed=0
j_retried=0 j_ongoing=0 queued=0". Absence of the key (it has a TTL) means no
worker for that queue has checked in recently.
"""
from __future__ import annotations

from prometheus_client import Gauge
from redis.asyncio import Redis

from app.core.config import get_settings

QUEUES = ("default", "heavy", "investigation")

ARQ_WORKER_UP = Gauge("arq_worker_up", "1 if the queue's health-check key is present", ["queue"])
ARQ_QUEUE_PENDING = Gauge("arq_queue_pending", "Jobs waiting in the queue", ["queue"])
ARQ_JOBS_COMPLETE = Gauge("arq_jobs_complete", "Jobs completed since last health check", ["queue"])
ARQ_JOBS_FAILED = Gauge("arq_jobs_failed", "Jobs failed since last health check", ["queue"])
ARQ_JOBS_ONGOING = Gauge("arq_jobs_ongoing", "Jobs currently running", ["queue"])


async def refresh_arq_metrics() -> None:
    settings = get_settings()
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    try:
        for queue in QUEUES:
            raw = await redis.get(f"{queue}:health-check")
            if raw is None:
                ARQ_WORKER_UP.labels(queue=queue).set(0)
                continue
            ARQ_WORKER_UP.labels(queue=queue).set(1)
            fields = dict(part.split("=", 1) for part in raw.split() if "=" in part)
            ARQ_QUEUE_PENDING.labels(queue=queue).set(int(fields.get("queued", 0)))
            ARQ_JOBS_COMPLETE.labels(queue=queue).set(int(fields.get("j_complete", 0)))
            ARQ_JOBS_FAILED.labels(queue=queue).set(int(fields.get("j_failed", 0)))
            ARQ_JOBS_ONGOING.labels(queue=queue).set(int(fields.get("j_ongoing", 0)))
    finally:
        await redis.aclose()
