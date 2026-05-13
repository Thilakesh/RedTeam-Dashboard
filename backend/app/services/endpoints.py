"""Endpoint upsert + observation persistence.

Mirrors `services/assets.py::upsert_assets` for the new endpoints/endpoint_observations
tables. Adapter side writes EndpointRecord dataclasses; this service writes them
batch-wise with ON CONFLICT against `uq_endpoint_identity`.

Hard rule: only vuln-tier adapters call this. Recon never touches endpoints.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlparse
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import func

from app.models.endpoint import Endpoint
from app.models.endpoint_observation import EndpointObservation

_BATCH_ROWS = 2000


@dataclass
class EndpointRecord:
    """Adapter output row passed into upsert_endpoints."""
    asset_id: UUID
    url: str                         # full canonical URL
    method: str = "GET"
    service_id: UUID | None = None
    status_code: int | None = None
    content_type: str | None = None
    content_length: int | None = None
    title: str | None = None
    is_login: bool = False
    is_signup: bool = False
    is_upload: bool = False
    is_api: bool = False
    is_admin: bool = False
    response_headers: dict = field(default_factory=dict)
    response_size: int | None = None


def _parse_path(url: str) -> str:
    parsed = urlparse(url)
    return parsed.path or "/"


async def upsert_endpoints(
    db: AsyncSession,
    *,
    target_id: UUID,
    scan_id: UUID,
    stage_id: UUID,
    source_tool: str,
    records: Iterable[EndpointRecord],
) -> int:
    """Upsert endpoints + write one EndpointObservation per record.

    Returns the count of observations written.
    """
    records = list(records)
    if not records:
        return 0

    for start in range(0, len(records), _BATCH_ROWS):
        chunk = records[start : start + _BATCH_ROWS]
        rows = [
            {
                "target_id": target_id,
                "asset_id": r.asset_id,
                "service_id": r.service_id,
                "url": r.url,
                "path": _parse_path(r.url),
                "method": r.method,
                "status_code": r.status_code,
                "content_type": r.content_type,
                "content_length": r.content_length,
                "title": r.title,
                "is_login": r.is_login,
                "is_signup": r.is_signup,
                "is_upload": r.is_upload,
                "is_api": r.is_api,
                "is_admin": r.is_admin,
                "source_tool": source_tool,
            }
            for r in chunk
        ]
        stmt = insert(Endpoint).values(rows)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_endpoint_identity",
            set_={
                "last_seen": func.now(),
                # Enrich on re-detection: prefer non-null new value, else keep stored.
                "status_code": func.coalesce(stmt.excluded.status_code, Endpoint.status_code),
                "content_type": func.coalesce(stmt.excluded.content_type, Endpoint.content_type),
                "content_length": func.coalesce(stmt.excluded.content_length, Endpoint.content_length),
                "title": func.coalesce(stmt.excluded.title, Endpoint.title),
                # Boolean classifier flags monotonically promote (False → True OK; never demote).
                "is_login": Endpoint.is_login.op("OR")(stmt.excluded.is_login),
                "is_signup": Endpoint.is_signup.op("OR")(stmt.excluded.is_signup),
                "is_upload": Endpoint.is_upload.op("OR")(stmt.excluded.is_upload),
                "is_api": Endpoint.is_api.op("OR")(stmt.excluded.is_api),
                "is_admin": Endpoint.is_admin.op("OR")(stmt.excluded.is_admin),
            },
        )
        await db.execute(stmt)

    # Resolve endpoint IDs back so we can write observations
    keys = {(r.url, r.method) for r in records}
    by_key: dict[tuple[str, str], UUID] = {}
    urls = list({u for u, _ in keys})
    for start in range(0, len(urls), _BATCH_ROWS):
        chunk_urls = urls[start : start + _BATCH_ROWS]
        existing = await db.execute(
            select(Endpoint.id, Endpoint.url, Endpoint.method).where(
                Endpoint.target_id == target_id,
                Endpoint.url.in_(chunk_urls),
            )
        )
        for eid, url, method in existing.all():
            by_key[(url, method)] = eid

    observations = [
        EndpointObservation(
            endpoint_id=by_key[(r.url, r.method)],
            scan_id=scan_id,
            stage_id=stage_id,
            status_code=r.status_code,
            response_size=r.response_size,
            content_type=r.content_type,
            response_headers=r.response_headers or {},
        )
        for r in records
        if (r.url, r.method) in by_key
    ]
    db.add_all(observations)
    await db.flush()
    return len(observations)
