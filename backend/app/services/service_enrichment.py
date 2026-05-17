"""Investigation-driven Service enrichment.

Mirrors `services/assets.py::_upsert_services` for the investigation path: takes
a `ServiceUpdateRecord` (from nmap_deep) and upserts/enriches the Service row
identified by (target_id, canonical_key). Investigation enrichment never
creates Asset/AssetObservation rows — it only updates existing Service rows or
appends services that the targeted deep scan discovered beyond what recon saw.

Resolution rule: if a matching Service exists (same target_id + canonical_key),
non-null fields from the record overwrite existing values (coalesce keeps old
on null). On insert, asset_id is left NULL — the analyst's deep scan didn't
necessarily come from an Asset(type='service') row.
"""
from __future__ import annotations

from uuid import UUID

from sqlalchemy import case, func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.service import Service
from app.pipeline.investigation.stage import ServiceUpdateRecord
from app.services.classify_service import classify_service


async def upsert_service_enrichment(
    db: AsyncSession,
    *,
    target_id: UUID,
    record: ServiceUpdateRecord,
) -> None:
    """Upsert one Service row from an investigation ServiceUpdateRecord."""
    canonical_key = f"{record.host}:{record.port}/{record.proto}"
    row = {
        "target_id": target_id,
        "asset_id": None,
        "host": record.host,
        "port": record.port,
        "proto": record.proto,
        "canonical_key": canonical_key,
        "state": "open",
        "service_name": record.service_name,
        "product": record.product,
        "version": record.version,
        "banner": record.banner,
        "cpes": record.cpes or [],
        "classification": classify_service(
            port=record.port, service_name=record.service_name
        ),
    }
    stmt = insert(Service).values([row])
    stmt = stmt.on_conflict_do_update(
        constraint="uq_service_identity",
        set_={
            "last_seen": func.now(),
            "state": stmt.excluded.state,
            "service_name": func.coalesce(
                stmt.excluded.service_name, Service.service_name
            ),
            "product": func.coalesce(stmt.excluded.product, Service.product),
            "version": func.coalesce(stmt.excluded.version, Service.version),
            "banner": func.coalesce(stmt.excluded.banner, Service.banner),
            # Only overwrite cpes when the new record carries any — keeps prior
            # recon-discovered CPEs when nmap_deep returns an empty list.
            "cpes": case(
                (func.cardinality(stmt.excluded.cpes) > 0, stmt.excluded.cpes),
                else_=Service.cpes,
            ),
            "classification": stmt.excluded.classification,
        },
    )
    await db.execute(stmt)
