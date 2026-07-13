"""Dashboard overview aggregation.

Every query here is scoped by (org_id, created_by) — own resources only, same
ownership boundary as scans.py/operations.py/target_workspaces.py (see the
IDOR fix). No role, including admin, gets an org-wide view here either.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Asset,
    AssetObservation,
    Finding,
    Scan,
    ScanStatus,
    Target,
    TargetWorkspace,
)
from app.schemas.dashboard import (
    DashboardSummary,
    RecentScanRow,
    ScanActivityDay,
    TopFindingRow,
)

_ACTIVE_STATUSES = (ScanStatus.created, ScanStatus.queued, ScanStatus.running)
_ACTIVITY_DAYS = 7
_RECENT_SCANS_LIMIT = 5
_TOP_FINDINGS_LIMIT = 5


async def build_summary(db: AsyncSession, org_id: UUID, created_by: UUID) -> DashboardSummary:
    own_scan = (Scan.org_id == org_id) & (Scan.created_by == created_by)

    active_scans = await db.scalar(
        select(func.count(Scan.id)).where(own_scan, Scan.status.in_(_ACTIVE_STATUSES))
    ) or 0

    assets_tracked = await db.scalar(
        select(func.count(func.distinct(AssetObservation.asset_id)))
        .join(Scan, Scan.id == AssetObservation.scan_id)
        .where(own_scan)
    ) or 0

    workspaces = await db.scalar(
        select(func.count(TargetWorkspace.id)).where(
            TargetWorkspace.org_id == org_id, TargetWorkspace.created_by == created_by
        )
    ) or 0

    severity_rows = (
        await db.execute(
            select(Finding.severity, func.count(Finding.id))
            .join(Scan, Scan.id == Finding.scan_id)
            .where(own_scan)
            .group_by(Finding.severity)
        )
    ).all()
    severity_counts = {sev.value: count for sev, count in severity_rows}
    open_findings = sum(severity_counts.values())

    since = datetime.now(timezone.utc) - timedelta(days=_ACTIVITY_DAYS - 1)
    activity_rows = (
        await db.execute(
            select(func.date(Scan.finished_at), func.count(Scan.id))
            .where(
                own_scan,
                Scan.status == ScanStatus.completed,
                Scan.finished_at.is_not(None),
                Scan.finished_at >= since,
            )
            .group_by(func.date(Scan.finished_at))
        )
    ).all()
    activity_by_day = {day: count for day, count in activity_rows}
    today = datetime.now(timezone.utc).date()
    scan_activity = [
        ScanActivityDay(day=d, completed=activity_by_day.get(d, 0))
        for d in (today - timedelta(days=i) for i in range(_ACTIVITY_DAYS - 1, -1, -1))
    ]

    recent_rows = (
        await db.execute(
            select(Scan, Target.domain)
            .join(Target, Target.id == Scan.target_id)
            .where(own_scan)
            .order_by(Scan.created_at.desc())
            .limit(_RECENT_SCANS_LIMIT)
        )
    ).all()
    recent_scans = [
        RecentScanRow(
            id=scan.id,
            domain=domain,
            profile=scan.profile,
            status=scan.status.value if hasattr(scan.status, "value") else str(scan.status),
            progress_pct=scan.progress_pct,
            created_at=scan.created_at,
        )
        for scan, domain in recent_rows
    ]

    finding_rows = (
        await db.execute(
            select(Finding, Asset.canonical_key)
            .join(Scan, Scan.id == Finding.scan_id)
            .join(Asset, Asset.id == Finding.asset_id, isouter=True)
            .where(own_scan)
            .order_by(Finding.risk_score.desc())
            .limit(_TOP_FINDINGS_LIMIT)
        )
    ).all()
    top_findings = [
        TopFindingRow(
            scan_id=finding.scan_id,
            fqdn=fqdn or "",
            severity=finding.severity.value,
            risk_score=finding.risk_score,
            rationale=finding.rationale,
        )
        for finding, fqdn in finding_rows
    ]

    return DashboardSummary(
        active_scans=active_scans,
        assets_tracked=assets_tracked,
        open_findings=open_findings,
        workspaces=workspaces,
        severity_counts=severity_counts,
        scan_activity=scan_activity,
        recent_scans=recent_scans,
        top_findings=top_findings,
    )
