from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import func

from app.models import Asset, AssetObservation
from app.models.service import Service
from app.models.technology import Technology
from app.pipeline.stage import AssetRecord


# Postgres's wire protocol caps a single statement at 32767 bind parameters. We chunk
# below that safely: assets has 5 cols/row → 6000 rows fits with headroom.
_BATCH_ROWS = 2000


async def upsert_assets(
    db: AsyncSession,
    *,
    target_id: UUID,
    scan_id: UUID,
    stage_id: UUID,
    source_tool: str,
    records: list[AssetRecord],
) -> int:
    """Upsert assets for a target and write one observation per record.

    Also dual-writes to the first-class `services` and `technologies` tables:
    - AssetRecord(type="service") → Service row (naabu/nmap)
    - AssetRecord(type="http_service") with payload.tech → Technology rows (httpx)

    Returns the number of observations written.
    """
    if not records:
        return 0

    for start in range(0, len(records), _BATCH_ROWS):
        chunk = records[start : start + _BATCH_ROWS]
        rows = [
            {
                "target_id": target_id,
                "type": r.type,
                "canonical_key": r.canonical_key,
                "attributes": r.payload,
            }
            for r in chunk
        ]
        stmt = insert(Asset).values(rows)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_asset_identity",
            set_={"last_seen": func.now()},
        )
        await db.execute(stmt)

    keys = {(r.type, r.canonical_key) for r in records}
    by_key: dict[tuple[str, str], UUID] = {}
    canonical_keys = list({k for _, k in keys})
    for start in range(0, len(canonical_keys), _BATCH_ROWS):
        chunk_keys = canonical_keys[start : start + _BATCH_ROWS]
        existing = await db.execute(
            select(Asset.id, Asset.type, Asset.canonical_key).where(
                Asset.target_id == target_id,
                Asset.canonical_key.in_(chunk_keys),
            )
        )
        for aid, t, k in existing.all():
            by_key[(t, k)] = aid

    observations = [
        AssetObservation(
            asset_id=by_key[(r.type, r.canonical_key)],
            scan_id=scan_id,
            stage_id=stage_id,
            source_tool=source_tool,
            confidence=r.confidence,
            payload=r.payload,
        )
        for r in records
        if (r.type, r.canonical_key) in by_key
    ]
    db.add_all(observations)
    await db.flush()

    # Dual-write to first-class tables during transition period.
    service_records = [r for r in records if r.type == "service"]
    if service_records:
        await _upsert_services(db, target_id=target_id, records=service_records, by_key=by_key)

    http_records = [r for r in records if r.type == "http_service"]
    if http_records:
        await _upsert_technologies(
            db, target_id=target_id, source_tool=source_tool, records=http_records, by_key=by_key
        )

    return len(observations)


async def _upsert_services(
    db: AsyncSession,
    *,
    target_id: UUID,
    records: list[AssetRecord],
    by_key: dict[tuple[str, str], UUID],
) -> None:
    """Upsert Service rows from type='service' AssetRecords.

    canonical_key format: "{host}:{port}/{proto}"
    payload keys: host, port, proto, state, service_name, product, version, cpes
    """
    rows = []
    for r in records:
        asset_id = by_key.get(("service", r.canonical_key))
        if asset_id is None:
            continue
        p = r.payload
        try:
            host_part, rest = r.canonical_key.rsplit(":", 1)
            port_str, proto = rest.split("/", 1)
            port = int(port_str)
        except (ValueError, IndexError):
            continue
        rows.append(
            {
                "target_id": target_id,
                "asset_id": asset_id,
                "host": p.get("host") or host_part,
                "port": port,
                "proto": proto,
                "canonical_key": r.canonical_key,
                "state": p.get("state") or "open",
                "service_name": p.get("service_name"),
                "product": p.get("product"),
                "version": p.get("version"),
                "cpes": p.get("cpes") or [],
            }
        )
    if not rows:
        return

    for start in range(0, len(rows), _BATCH_ROWS):
        chunk = rows[start : start + _BATCH_ROWS]
        stmt = insert(Service).values(chunk)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_service_identity",
            set_={
                "last_seen": func.now(),
                "state": stmt.excluded.state,
                # Enrich: update these only when nmap provides them (non-null wins)
                "service_name": func.coalesce(stmt.excluded.service_name, Service.service_name),
                "product": func.coalesce(stmt.excluded.product, Service.product),
                "version": func.coalesce(stmt.excluded.version, Service.version),
                "cpes": func.coalesce(stmt.excluded.cpes, Service.cpes),
            },
        )
        await db.execute(stmt)


async def _upsert_technologies(
    db: AsyncSession,
    *,
    target_id: UUID,
    source_tool: str,
    records: list[AssetRecord],
    by_key: dict[tuple[str, str], UUID],
) -> None:
    """Upsert Technology rows from tech list in http_service payload.

    Each AssetRecord(type="http_service") may carry payload["tech"] = ["WordPress 5.8", ...]
    Each entry is split into name + optional version by the last space+digit heuristic.
    """
    rows = []
    for r in records:
        asset_id = by_key.get(("http_service", r.canonical_key))
        if asset_id is None:
            continue
        tech_list: list[str] = r.payload.get("tech") or []
        for entry in tech_list:
            name, version = _split_tech_version(entry)
            rows.append(
                {
                    "target_id": target_id,
                    "asset_id": asset_id,
                    "name": name,
                    "version": version,
                    "source_tool": source_tool,
                }
            )
    if not rows:
        return

    for start in range(0, len(rows), _BATCH_ROWS):
        chunk = rows[start : start + _BATCH_ROWS]
        stmt = insert(Technology).values(chunk)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_tech_identity",
            set_={
                "last_seen": func.now(),
                "version": func.coalesce(stmt.excluded.version, Technology.version),
                "source_tool": stmt.excluded.source_tool,
            },
        )
        await db.execute(stmt)


def _split_tech_version(entry: str) -> tuple[str, str | None]:
    """Split "WordPress 5.8.3" → ("WordPress", "5.8.3"), "nginx" → ("nginx", None).

    Heuristic: if the last token starts with a digit, treat it as a version.
    """
    parts = entry.rsplit(" ", 1)
    if len(parts) == 2 and parts[1] and parts[1][0].isdigit():
        return parts[0], parts[1]
    return entry, None
