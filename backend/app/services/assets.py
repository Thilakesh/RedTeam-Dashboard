from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import func

from app.models import Asset, AssetObservation
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

    Returns the number of records written.
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
    return len(observations)
