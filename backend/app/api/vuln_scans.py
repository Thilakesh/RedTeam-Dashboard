import asyncio
import json
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from redis.asyncio import Redis
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sse_starlette.sse import EventSourceResponse

from app.api.deps import CurrentUser, get_current_user, get_current_user_sse
from app.core.config import get_settings
from app.core.db import get_db
from app.models import Scan, ScanKind, ScanStatus, Target
from app.schemas.vuln import (
    VulnDiffOut,
    VulnOverview,
    VulnOut,
    VulnScanCreateRequest,
    VulnScanDetailOut,
    VulnScanOut,
    VulnsPage,
)
from app.services import vuln_view
from app.services.queue import enqueue_vuln_scan

router = APIRouter(prefix="/vuln-scans", tags=["vuln-scans"])


def _to_vuln_scan_out(scan: Scan, target_domain: str) -> VulnScanOut:
    return VulnScanOut(
        id=scan.id,
        target_domain=target_domain,
        parent_scan_id=scan.parent_scan_id,
        profile=scan.profile,
        status=scan.status.value,
        progress_pct=scan.progress_pct,
        intrusive=scan.intrusive,
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        error=scan.error,
    )


async def _get_vuln_scan(
    db: AsyncSession, scan_id: UUID, org_id: UUID
) -> tuple[Scan, str]:
    """Returns (scan, target_domain). Raises 404 if not found or wrong org."""
    row = (
        await db.execute(
            select(Scan, Target.domain)
            .join(Target, Target.id == Scan.target_id)
            .where(
                Scan.id == scan_id,
                Scan.org_id == org_id,
                Scan.kind == ScanKind.vuln_analysis,
            )
        )
    ).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "vuln scan not found")
    return row.Scan, row.domain


@router.post("", response_model=VulnScanOut, status_code=status.HTTP_201_CREATED)
async def create_vuln_scan(
    req: VulnScanCreateRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> VulnScanOut:
    # Validate parent scan: must belong to user's org, be a recon scan, and be completed
    parent_row = (
        await db.execute(
            select(Scan, Target.domain)
            .join(Target, Target.id == Scan.target_id)
            .where(
                Scan.id == req.parent_scan_id,
                Scan.org_id == user.org_id,
                Scan.kind == ScanKind.recon,
            )
        )
    ).first()

    if parent_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")

    parent_scan, target_domain = parent_row.Scan, parent_row.domain

    if parent_scan.status != ScanStatus.completed:
        raise HTTPException(status.HTTP_409_CONFLICT, "parent recon scan not complete")

    scan = Scan(
        kind=ScanKind.vuln_analysis,
        parent_scan_id=parent_scan.id,
        target_id=parent_scan.target_id,
        org_id=user.org_id,
        profile=req.profile,
        intrusive=req.intrusive,
        status=ScanStatus.created,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    await enqueue_vuln_scan(str(scan.id))

    return _to_vuln_scan_out(scan, target_domain)


@router.get("", response_model=list[VulnScanOut])
async def list_vuln_scans(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[VulnScanOut]:
    rows = (
        await db.execute(
            select(Scan, Target.domain)
            .join(Target, Target.id == Scan.target_id)
            .where(
                Scan.org_id == user.org_id,
                Scan.kind == ScanKind.vuln_analysis,
            )
            .order_by(desc(Scan.created_at))
            .limit(100)
        )
    ).all()
    return [_to_vuln_scan_out(scan, domain) for scan, domain in rows]


@router.get("/{scan_id}", response_model=VulnScanDetailOut)
async def get_vuln_scan(
    scan_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> VulnScanDetailOut:
    scan = await db.scalar(
        select(Scan)
        .options(selectinload(Scan.stages))
        .where(
            Scan.id == scan_id,
            Scan.org_id == user.org_id,
            Scan.kind == ScanKind.vuln_analysis,
        )
    )
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "vuln scan not found")

    target = await db.get(Target, scan.target_id)
    target_domain = target.domain if target else ""
    base = _to_vuln_scan_out(scan, target_domain)
    return VulnScanDetailOut(**base.model_dump(), stages=scan.stages)


@router.get("/{scan_id}/stream")
async def stream_vuln_scan(
    scan_id: UUID,
    user: CurrentUser = Depends(get_current_user_sse),
    db: AsyncSession = Depends(get_db),
):
    exists = await db.scalar(
        select(Scan.id).where(
            Scan.id == scan_id,
            Scan.org_id == user.org_id,
            Scan.kind == ScanKind.vuln_analysis,
        )
    )
    if exists is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "vuln scan not found")

    redis = Redis.from_url(get_settings().redis_url, decode_responses=True)
    channel = f"scan:{scan_id}"

    async def event_gen():
        pubsub = redis.pubsub()
        await pubsub.subscribe(channel)
        try:
            while True:
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=15.0)
                if msg is None:
                    yield {"event": "ping", "data": "{}"}
                    continue
                data = msg["data"]
                try:
                    parsed = json.loads(data)
                    event = parsed.get("event", "update")
                except (ValueError, TypeError):
                    event = "update"
                yield {"event": event, "data": data}
                if event in ("scan.completed", "scan.failed", "scan.stopped"):
                    await asyncio.sleep(0.1)
                    return
        finally:
            await pubsub.unsubscribe(channel)
            await pubsub.aclose()
            await redis.aclose()

    return EventSourceResponse(event_gen())


@router.get("/{scan_id}/overview", response_model=VulnOverview)
async def get_vuln_overview(
    scan_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> VulnOverview:
    await _get_vuln_scan(db, scan_id, user.org_id)
    data = await vuln_view.build_vuln_overview(db, scan_id)
    return VulnOverview(**data)


@router.get("/{scan_id}/vulnerabilities", response_model=VulnsPage)
async def list_vuln_scan_vulnerabilities(
    scan_id: UUID,
    severity: str | None = Query(None),
    status_filter: str | None = Query(None, alias="status"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> VulnsPage:
    await _get_vuln_scan(db, scan_id, user.org_id)
    total, rows = await vuln_view.build_vuln_rows(
        db,
        scan_id,
        severity=severity,
        status=status_filter,
        offset=offset,
        limit=limit,
    )
    items = [
        VulnOut(
            id=r.id,
            canonical_key=r.canonical_key,
            title=r.title,
            severity=r.severity,
            cvss_v3=r.cvss_v3,
            cve_ids=r.cve_ids,
            cwe_ids=r.cwe_ids,
            status=r.status,
            asset_id=r.asset_id,
            asset_label=r.asset_label,
            template_id=r.template_id,
            kev=r.kev,
            first_seen=r.first_seen,
            last_seen=r.last_seen,
        )
        for r in rows
    ]
    return VulnsPage(total=total, items=items)


def _vuln_row_to_out(r) -> VulnOut:
    return VulnOut(
        id=r.id,
        canonical_key=r.canonical_key,
        title=r.title,
        severity=r.severity,
        cvss_v3=r.cvss_v3,
        cve_ids=r.cve_ids,
        cwe_ids=r.cwe_ids,
        status=r.status,
        asset_id=r.asset_id,
        asset_label=r.asset_label,
        template_id=r.template_id,
        kev=r.kev,
        first_seen=r.first_seen,
        last_seen=r.last_seen,
    )


@router.get("/{scan_id}/diff", response_model=VulnDiffOut)
async def get_vuln_diff(
    scan_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> VulnDiffOut:
    """Diff vs previous completed vuln scan: new / seen / fixed_in_this_run."""
    await _get_vuln_scan(db, scan_id, user.org_id)
    data = await vuln_view.build_vuln_diff(db, scan_id)
    return VulnDiffOut(
        counts=data["counts"],
        new=[_vuln_row_to_out(r) for r in data["new"]],
        seen=[_vuln_row_to_out(r) for r in data["seen"]],
        fixed=[_vuln_row_to_out(r) for r in data["fixed"]],
        has_prior=data["has_prior"],
    )
