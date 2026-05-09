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
from app.models import Asset, AssetObservation, Project, Scan, ScanStatus, Target
from app.schemas.findings import FindingsPage
from app.schemas.scan import AssetOut, ScanCreateRequest, ScanDetailOut, ScanOut, ScanUpdateRequest
from app.schemas.subdomain_view import (
    CdnWafSummary,
    CountBucket,
    IpRow,
    PortRow,
    PortsPage,
    ScanOverview,
    SubdomainsPage,
    TechBucket,
)
from app.services import scan_view
from app.services.queue import enqueue_scan

router = APIRouter(prefix="/scans", tags=["scans"])


async def _default_project_id(db: AsyncSession, org_id: UUID) -> UUID:
    project_id = await db.scalar(
        select(Project.id).where(Project.org_id == org_id, Project.name == "default")
    )
    if project_id is None:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "no default project")
    return project_id


def _to_scan_out(scan: Scan, domain: str, authz_verified: bool = False) -> ScanOut:
    return ScanOut(
        id=scan.id,
        domain=domain,
        profile=scan.profile,
        status=scan.status,
        progress_pct=scan.progress_pct,
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        error=scan.error,
        target_authz_verified=authz_verified,
    )


async def _get_scan_and_domain(
    db: AsyncSession, scan_id: UUID, org_id: UUID
) -> tuple[Scan, str, bool]:
    """Returns (scan, domain, target_authz_verified)."""
    row = (
        await db.execute(
            select(Scan, Target.domain, Target.authorization_verified_at)
            .join(Target, Target.id == Scan.target_id)
            .where(Scan.id == scan_id, Scan.org_id == org_id)
        )
    ).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    return row.Scan, row.domain, row.authorization_verified_at is not None


@router.post("", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
async def create_scan(
    req: ScanCreateRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanOut:
    project_id = await _default_project_id(db, user.org_id)

    target = await db.scalar(
        select(Target).where(Target.project_id == project_id, Target.domain == req.domain)
    )
    if target is None:
        target = Target(project_id=project_id, domain=req.domain)
        db.add(target)
        await db.flush()

    initial_status = ScanStatus.created if req.autostart else ScanStatus.queued
    scan = Scan(target_id=target.id, org_id=user.org_id, profile=req.profile, status=initial_status)
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    if req.autostart:
        await enqueue_scan(str(scan.id), profile=scan.profile)

    return _to_scan_out(scan, target.domain, target.authorization_verified_at is not None)


@router.get("", response_model=list[ScanOut])
async def list_scans(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[ScanOut]:
    rows = (
        await db.execute(
            select(Scan, Target.domain, Target.authorization_verified_at)
            .join(Target, Target.id == Scan.target_id)
            .where(Scan.org_id == user.org_id)
            .order_by(desc(Scan.created_at))
            .limit(100)
        )
    ).all()
    return [_to_scan_out(scan, domain, authz_at is not None) for scan, domain, authz_at in rows]


@router.post("/{scan_id}/start", response_model=ScanOut)
async def start_scan(
    scan_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanOut:
    scan, domain, authz_verified = await _get_scan_and_domain(db, scan_id, user.org_id)
    if scan.status != ScanStatus.queued:
        raise HTTPException(status.HTTP_409_CONFLICT, "Scan is not in queued state")
    scan.status = ScanStatus.created
    await db.commit()
    await enqueue_scan(str(scan.id), profile=scan.profile)
    return _to_scan_out(scan, domain, authz_verified)


@router.post("/{scan_id}/stop", response_model=ScanOut)
async def stop_scan(
    scan_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanOut:
    scan, domain, authz_verified = await _get_scan_and_domain(db, scan_id, user.org_id)
    if scan.status not in (ScanStatus.created, ScanStatus.running):
        raise HTTPException(status.HTTP_409_CONFLICT, "Scan is not running")
    scan.status = ScanStatus.stopped
    scan.finished_at = datetime.now(timezone.utc)
    await db.commit()
    # Publish terminal event so SSE clients close the stream
    settings = get_settings()
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    try:
        payload = json.dumps({"event": "scan.stopped", "scan_id": str(scan_id)})
        await redis.publish(f"scan:{scan_id}", payload)
    finally:
        await redis.aclose()
    return _to_scan_out(scan, domain, authz_verified)


@router.patch("/{scan_id}", response_model=ScanOut)
async def update_scan(
    scan_id: UUID,
    req: ScanUpdateRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanOut:
    scan, domain, authz_verified = await _get_scan_and_domain(db, scan_id, user.org_id)
    if scan.status != ScanStatus.queued:
        raise HTTPException(status.HTTP_409_CONFLICT, "Only queued scans can be edited")
    scan.profile = req.profile
    await db.commit()
    return _to_scan_out(scan, domain, authz_verified)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    scan, _, _authz = await _get_scan_and_domain(db, scan_id, user.org_id)
    if scan.status != ScanStatus.queued:
        raise HTTPException(status.HTTP_409_CONFLICT, "Only queued scans can be deleted")
    await db.delete(scan)
    await db.commit()


@router.get("/{scan_id}", response_model=ScanDetailOut)
async def get_scan(
    scan_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanDetailOut:
    scan = await db.scalar(
        select(Scan)
        .options(selectinload(Scan.stages))
        .where(Scan.id == scan_id, Scan.org_id == user.org_id)
    )
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    target = await db.get(Target, scan.target_id)
    authz_verified = target.authorization_verified_at is not None if target else False
    base = _to_scan_out(scan, target.domain if target else "", authz_verified)
    return ScanDetailOut(**base.model_dump(), stages=scan.stages)


@router.get("/{scan_id}/assets", response_model=list[AssetOut])
async def list_scan_assets(
    scan_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[AssetOut]:
    scan = await db.scalar(
        select(Scan).where(Scan.id == scan_id, Scan.org_id == user.org_id)
    )
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")

    rows = await db.execute(
        select(Asset)
        .join(AssetObservation, AssetObservation.asset_id == Asset.id)
        .where(AssetObservation.scan_id == scan_id)
        .distinct()
        .order_by(Asset.canonical_key)
    )
    return [AssetOut.model_validate(a) for a in rows.scalars().all()]


async def _ensure_scan_visible(db: AsyncSession, scan_id: UUID, user: CurrentUser) -> None:
    exists = await db.scalar(
        select(Scan.id).where(Scan.id == scan_id, Scan.org_id == user.org_id)
    )
    if exists is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")


@router.get("/{scan_id}/subdomains", response_model=SubdomainsPage)
async def list_scan_subdomains(
    scan_id: UUID,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
    sort: str | None = Query(None),
    search: str | None = Query(None),
    status_codes: list[int] | None = Query(None, alias="status"),
    ip_tags: list[str] | None = Query(None, alias="ip_tag"),
    cdns: list[str] | None = Query(None, alias="cdn"),
    wafs: list[str] | None = Query(None, alias="waf"),
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SubdomainsPage:
    """The Subdomains tab — denormalized rows joined across the asset graph."""
    await _ensure_scan_visible(db, scan_id, user)
    rows = await scan_view.build_subdomain_rows(db, scan_id)
    rows = scan_view.filter_and_sort(
        rows,
        search=search,
        status=status_codes,
        ip_tags=ip_tags,
        cdns=cdns,
        wafs=wafs,
        sort=sort,
    )
    total = len(rows)
    start = (page - 1) * limit
    return SubdomainsPage(rows=rows[start : start + limit], total=total, page=page, limit=limit)


@router.get("/{scan_id}/overview", response_model=ScanOverview)
async def get_scan_overview(
    scan_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanOverview:
    await _ensure_scan_visible(db, scan_id, user)
    return await scan_view.build_overview(db, scan_id)


@router.get("/{scan_id}/ips", response_model=list[IpRow])
async def list_scan_ips(
    scan_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[IpRow]:
    await _ensure_scan_visible(db, scan_id, user)
    return await scan_view.build_ip_rows(db, scan_id)


@router.get("/{scan_id}/cdn-waf", response_model=CdnWafSummary)
async def get_cdn_waf_summary(
    scan_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> CdnWafSummary:
    await _ensure_scan_visible(db, scan_id, user)
    return await scan_view.build_cdn_waf_summary(db, scan_id)


@router.get("/{scan_id}/technologies", response_model=list[TechBucket])
async def get_scan_technologies(
    scan_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[TechBucket]:
    await _ensure_scan_visible(db, scan_id, user)
    return await scan_view.build_technologies(db, scan_id)


@router.get("/{scan_id}/ports", response_model=PortsPage)
async def list_scan_ports(
    scan_id: UUID,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> PortsPage:
    """Port/service inventory tab — open ports found by naabu, enriched by nmap."""
    await _ensure_scan_visible(db, scan_id, user)
    rows = await scan_view.build_port_rows(db, scan_id)
    total = len(rows)
    start = (page - 1) * limit
    return PortsPage(rows=rows[start : start + limit], total=total, page=page, limit=limit)


@router.get("/{scan_id}/findings", response_model=FindingsPage)
async def get_scan_findings(
    scan_id: UUID,
    severity: str | None = Query(None, pattern="^(HIGH|MED|LOW|INFO)$"),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> FindingsPage:
    """Prioritized risk findings for a deep scan, ordered by priority_rank ASC."""
    await _ensure_scan_visible(db, scan_id, user)
    offset = (page - 1) * limit
    total, items = await scan_view.build_findings(
        db, scan_id, severity=severity, offset=offset, limit=limit
    )
    return FindingsPage(total=total, items=items)


@router.get("/{scan_id}/stream")
async def stream_scan(
    scan_id: UUID,
    user: CurrentUser = Depends(get_current_user_sse),
    db: AsyncSession = Depends(get_db),
):
    scan = await db.scalar(
        select(Scan.id).where(Scan.id == scan_id, Scan.org_id == user.org_id)
    )
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")

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
