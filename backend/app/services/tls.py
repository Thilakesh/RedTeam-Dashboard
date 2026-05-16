"""TLS observation upsert — append-only per probe.

Each testssl run on a service writes one new TlsObservation row (no dedup;
history per service is the desired model — analyst can see drift over time).
Resolves Service by (target_id, host, port). If no Service exists, the
observation is dropped (cannot dangle without an owning service row).
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Service, TlsObservation
from app.pipeline.investigation.stage import TlsObservationRecord


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


async def insert_tls_observation(
    db: AsyncSession,
    target_id: UUID,
    record: TlsObservationRecord,
) -> bool:
    """Returns True if row inserted, False if no matching Service found."""
    service_id = await db.scalar(
        select(Service.id)
        .where(
            Service.target_id == target_id,
            Service.host == record.host,
            Service.port == record.port,
        )
        .limit(1)
    )
    if service_id is None:
        return False

    db.add(
        TlsObservation(
            service_id=service_id,
            target_id=target_id,
            cert_subject=record.cert_subject,
            cert_issuer=record.cert_issuer,
            cert_not_before=_parse_iso(record.cert_not_before),
            cert_not_after=_parse_iso(record.cert_not_after),
            cert_san=record.cert_san or [],
            protocols=record.protocols or {},
            weak_ciphers=record.weak_ciphers or [],
            grade=record.grade,
        )
    )
    return True
