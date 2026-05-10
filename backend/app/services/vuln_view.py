from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Scan, ScanKind, ScanStatus
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability, VulnSeverity
from app.models.vuln_run_match import VulnRunMatch
from sqlalchemy import desc


@dataclass
class VulnRow:
    id: UUID
    canonical_key: str
    title: str
    severity: str
    cvss_v3: float | None
    cve_ids: list[str]
    cwe_ids: list[str]
    status: str
    asset_id: UUID
    asset_label: str
    template_id: str | None
    kev: bool
    first_seen: datetime
    last_seen: datetime


async def build_vuln_overview(db: AsyncSession, scan_id: UUID) -> dict:
    """Counts by severity + KEV count + distinct CVE count for a vuln scan."""
    rows = await db.execute(
        select(Vulnerability.severity, Vulnerability.kev, Vulnerability.cve_ids)
        .join(VulnRunMatch, VulnRunMatch.vulnerability_id == Vulnerability.id)
        .where(VulnRunMatch.scan_id == scan_id)
    )

    total = 0
    critical = high = med = low = info = 0
    kev_count = 0
    all_cves: set[str] = set()

    for severity, kev, cve_ids in rows.all():
        total += 1
        if kev:
            kev_count += 1
        if cve_ids:
            all_cves.update(cve_ids)
        match severity:
            case VulnSeverity.CRITICAL:
                critical += 1
            case VulnSeverity.HIGH:
                high += 1
            case VulnSeverity.MED:
                med += 1
            case VulnSeverity.LOW:
                low += 1
            case VulnSeverity.INFO:
                info += 1

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "med": med,
        "low": low,
        "info": info,
        "kev_count": kev_count,
        "cve_count": len(all_cves),
    }


async def build_vuln_rows(
    db: AsyncSession,
    scan_id: UUID,
    *,
    severity: str | None = None,
    status: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> tuple[int, list[VulnRow]]:
    """Paginated vulnerabilities for a vuln scan, scoped via vuln_run_matches."""
    base_q = (
        select(Vulnerability, Asset.canonical_key.label("asset_label"))
        .join(VulnRunMatch, VulnRunMatch.vulnerability_id == Vulnerability.id)
        .join(Asset, Asset.id == Vulnerability.asset_id)
        .where(VulnRunMatch.scan_id == scan_id)
    )

    if severity is not None:
        base_q = base_q.where(Vulnerability.severity == VulnSeverity(severity))
    if status is not None:
        base_q = base_q.where(Vulnerability.status == status)

    count_q = select(func.count()).select_from(base_q.subquery())
    total: int = (await db.scalar(count_q)) or 0

    page_q = base_q.order_by(Vulnerability.severity, Vulnerability.first_seen.desc()).offset(offset).limit(limit)
    result = await db.execute(page_q)

    vuln_rows = [
        VulnRow(
            id=v.id,
            canonical_key=v.canonical_key,
            title=v.title,
            severity=v.severity.value,
            cvss_v3=v.cvss_v3,
            cve_ids=v.cve_ids or [],
            cwe_ids=v.cwe_ids or [],
            status=v.status.value,
            asset_id=v.asset_id,
            asset_label=asset_label,
            template_id=v.template_id,
            kev=v.kev,
            first_seen=v.first_seen,
            last_seen=v.last_seen,
        )
        for v, asset_label in result.all()
    ]

    return total, vuln_rows


async def build_vuln_diff(db: AsyncSession, scan_id: UUID) -> dict:
    """Group this scan's vulns by VulnRunMatch.state (new/seen/fixed_in_this_run).

    Includes a `has_prior` flag indicating whether a previous vuln scan exists
    against the same target — when False, all detections are necessarily 'new'
    and the diff view tells the user "no prior scan to compare against".
    """
    target_id = await db.scalar(select(Scan.target_id).where(Scan.id == scan_id))

    has_prior = False
    if target_id is not None:
        prior = await db.scalar(
            select(Scan.id)
            .where(
                Scan.target_id == target_id,
                Scan.kind == ScanKind.vuln_analysis,
                Scan.status == ScanStatus.completed,
                Scan.id != scan_id,
            )
            .order_by(desc(Scan.finished_at))
            .limit(1)
        )
        has_prior = prior is not None

    rows = (
        await db.execute(
            select(Vulnerability, Asset.canonical_key.label("asset_label"), VulnRunMatch.state)
            .join(VulnRunMatch, VulnRunMatch.vulnerability_id == Vulnerability.id)
            .join(Asset, Asset.id == Vulnerability.asset_id)
            .where(VulnRunMatch.scan_id == scan_id)
            .order_by(Vulnerability.severity, Vulnerability.last_seen.desc())
        )
    ).all()

    new_rows: list[VulnRow] = []
    seen_rows: list[VulnRow] = []
    fixed_rows: list[VulnRow] = []

    for v, asset_label, state in rows:
        item = VulnRow(
            id=v.id,
            canonical_key=v.canonical_key,
            title=v.title,
            severity=v.severity.value,
            cvss_v3=v.cvss_v3,
            cve_ids=v.cve_ids or [],
            cwe_ids=v.cwe_ids or [],
            status=v.status.value,
            asset_id=v.asset_id,
            asset_label=asset_label,
            template_id=v.template_id,
            kev=v.kev,
            first_seen=v.first_seen,
            last_seen=v.last_seen,
        )
        if state == "new":
            new_rows.append(item)
        elif state == "fixed_in_this_run":
            fixed_rows.append(item)
        else:
            seen_rows.append(item)

    return {
        "counts": {
            "new": len(new_rows),
            "seen": len(seen_rows),
            "fixed": len(fixed_rows),
        },
        "new": new_rows,
        "seen": seen_rows,
        "fixed": fixed_rows,
        "has_prior": has_prior,
    }
