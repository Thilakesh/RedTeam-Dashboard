"""Investigation-driven Endpoint enrichment.

Mirrors `services/endpoints.py::upsert_endpoints` for the investigation path. Key
differences:
- No EndpointObservation rows (investigation has no scan_id / stage_id).
- asset_id is required and comes from the InvestigationTask (the analyst
  picked an asset to scan, so every emitted endpoint binds to that asset).
- Classifier flags are applied here from path heuristics so ffuf/dirsearch
  don't each re-implement them (reuses `_classify` from
  `pipeline/vuln/adapters/endpoint_classifier`).

Boundary rule: still vuln-tier writes only — recon never touches endpoints.
"""
from __future__ import annotations

from urllib.parse import urlparse
from uuid import UUID

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import func

from app.models.endpoint import Endpoint
from app.pipeline.investigation.stage import EndpointRecord
from app.pipeline.investigation.endpoint_classifier import _classify


async def upsert_endpoint_enrichment(
    db: AsyncSession,
    *,
    target_id: UUID,
    asset_id: UUID,
    source_tool: str,
    record: EndpointRecord,
) -> None:
    """Upsert a single Endpoint row from an investigation EndpointRecord."""
    path = record.path or urlparse(record.url).path or "/"
    flags = _classify(path)
    row = {
        "target_id": target_id,
        "asset_id": asset_id,
        "service_id": None,
        "url": record.url[:2000],
        "path": path[:2000],
        "method": (record.method or "GET").upper()[:10],
        "status_code": record.status_code,
        "content_type": record.content_type[:200] if record.content_type else None,
        "content_length": record.content_length,
        "title": record.title[:500] if record.title else None,
        "is_login": flags["is_login"],
        "is_signup": flags["is_signup"],
        "is_upload": flags["is_upload"],
        "is_api": flags["is_api"],
        "is_admin": flags["is_admin"],
        "source_tool": source_tool[:50],
    }
    stmt = insert(Endpoint).values([row])
    stmt = stmt.on_conflict_do_update(
        constraint="uq_endpoint_identity",
        set_={
            "last_seen": func.now(),
            "status_code": func.coalesce(
                stmt.excluded.status_code, Endpoint.status_code
            ),
            "content_type": func.coalesce(
                stmt.excluded.content_type, Endpoint.content_type
            ),
            "content_length": func.coalesce(
                stmt.excluded.content_length, Endpoint.content_length
            ),
            "title": func.coalesce(stmt.excluded.title, Endpoint.title),
            # Boolean flags monotonically promote (False → True OK; never demote).
            "is_login": Endpoint.is_login.op("OR")(stmt.excluded.is_login),
            "is_signup": Endpoint.is_signup.op("OR")(stmt.excluded.is_signup),
            "is_upload": Endpoint.is_upload.op("OR")(stmt.excluded.is_upload),
            "is_api": Endpoint.is_api.op("OR")(stmt.excluded.is_api),
            "is_admin": Endpoint.is_admin.op("OR")(stmt.excluded.is_admin),
        },
    )
    await db.execute(stmt)
