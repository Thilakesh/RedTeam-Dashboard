"""HvtSignal upsert helper. Mirrors services/endpoints.py.

Used by panel_detector (rewritten in M-Vuln-6 to emit signals not vulns) and
by swagger_discoverer / endpoint_classifier when they detect HVT surface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable
from uuid import UUID

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import func

from app.models.hvt_signal import HvtSignal, HvtSignalType

_BATCH_ROWS = 2000


@dataclass
class HvtSignalRecord:
    asset_id: UUID
    signal_type: HvtSignalType
    score: float = 0.5
    confidence: int = 80
    endpoint_id: UUID | None = None
    service_id: UUID | None = None
    evidence: dict = field(default_factory=dict)


async def upsert_hvt_signals(
    db: AsyncSession,
    *,
    target_id: UUID,
    source_tool: str,
    records: Iterable[HvtSignalRecord],
) -> int:
    records = list(records)
    if not records:
        return 0
    for start in range(0, len(records), _BATCH_ROWS):
        chunk = records[start : start + _BATCH_ROWS]
        rows = [
            {
                "target_id": target_id,
                "asset_id": r.asset_id,
                "endpoint_id": r.endpoint_id,
                "service_id": r.service_id,
                "signal_type": r.signal_type,
                "score": r.score,
                "confidence": r.confidence,
                "evidence": r.evidence or {},
                "source_tool": source_tool,
            }
            for r in chunk
        ]
        stmt = insert(HvtSignal).values(rows)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_hvt_identity",
            set_={
                "last_seen": func.now(),
                "score": stmt.excluded.score,
                "confidence": stmt.excluded.confidence,
                "evidence": stmt.excluded.evidence,
            },
        )
        await db.execute(stmt)
    return len(records)
