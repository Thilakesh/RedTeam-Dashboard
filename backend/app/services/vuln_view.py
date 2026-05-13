from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Scan, ScanKind, ScanStatus
from app.models.asset import Asset
from app.models.endpoint import Endpoint
from app.models.hvt_signal import HvtSignal
from app.models.service import Service, ServiceClassification
from app.models.technology import Technology
from app.models.tls_observation import TlsObservation
from app.models.vulnerability import Vulnerability, VulnSeverity
from app.models.vuln_run_match import VulnRunMatch
from app.services.hvt_score import compute_hvt_score
from sqlalchemy import desc


@dataclass
class VulnRow:
    id: UUID
    canonical_key: str
    title: str
    severity: str
    cvss_v3: float | None
    epss: float | None
    risk_score: float | None
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
    """Counts by severity + KEV count + distinct CVE count + HVT/exposure cards."""
    target_id = await db.scalar(select(Scan.target_id).where(Scan.id == scan_id))

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

    # HVT count + public service count (M-Vuln-8)
    hvt_count = 0
    public_service_count = 0
    top_risk_vulns: list[dict] = []

    if target_id is not None:
        hvt_count = (
            await db.scalar(
                select(func.count(HvtSignal.id)).where(HvtSignal.target_id == target_id)
            )
        ) or 0

        public_service_count = (
            await db.scalar(
                select(func.count(Service.id)).where(
                    Service.target_id == target_id,
                    Service.classification == ServiceClassification.web,
                )
            )
        ) or 0

        # Top 3 by risk_score for this scan
        top_rows = (
            await db.execute(
                select(
                    Vulnerability.id,
                    Vulnerability.title,
                    Vulnerability.severity,
                    Vulnerability.risk_score,
                    Vulnerability.kev,
                )
                .join(VulnRunMatch, VulnRunMatch.vulnerability_id == Vulnerability.id)
                .where(VulnRunMatch.scan_id == scan_id, Vulnerability.risk_score.is_not(None))
                .order_by(desc(Vulnerability.risk_score))
                .limit(3)
            )
        ).all()
        top_risk_vulns = [
            {
                "id": str(r.id),
                "title": r.title,
                "severity": r.severity.value if hasattr(r.severity, "value") else str(r.severity),
                "risk_score": r.risk_score,
                "kev": r.kev,
            }
            for r in top_rows
        ]

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "med": med,
        "low": low,
        "info": info,
        "kev_count": kev_count,
        "cve_count": len(all_cves),
        "hvt_count": hvt_count,
        "public_service_count": public_service_count,
        "top_risk_vulns": top_risk_vulns,
    }


async def build_vuln_rows(
    db: AsyncSession,
    scan_id: UUID,
    *,
    severity: str | None = None,
    status: str | None = None,
    kev_only: bool = False,
    hvt_only: bool = False,
    offset: int = 0,
    limit: int = 50,
) -> tuple[int, list[VulnRow]]:
    """Paginated vulns for a scan. Default sort: risk_score DESC NULLS LAST."""
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
    if kev_only:
        base_q = base_q.where(Vulnerability.kev.is_(True))
    if hvt_only:
        target_id_subq = select(Scan.target_id).where(Scan.id == scan_id).scalar_subquery()
        hvt_asset_ids_subq = (
            select(HvtSignal.asset_id).where(HvtSignal.target_id == target_id_subq).distinct()
        )
        base_q = base_q.where(Vulnerability.asset_id.in_(hvt_asset_ids_subq))

    count_q = select(func.count()).select_from(base_q.subquery())
    total: int = (await db.scalar(count_q)) or 0

    page_q = (
        base_q
        .order_by(desc(Vulnerability.risk_score).nullslast(), Vulnerability.first_seen.desc())
        .offset(offset)
        .limit(limit)
    )
    result = await db.execute(page_q)

    vuln_rows = [
        VulnRow(
            id=v.id,
            canonical_key=v.canonical_key,
            title=v.title,
            severity=v.severity.value,
            cvss_v3=v.cvss_v3,
            epss=v.epss,
            risk_score=v.risk_score,
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
            epss=v.epss,
            risk_score=v.risk_score,
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


async def build_by_service(db: AsyncSession, scan_id: UUID) -> list[dict]:
    """Vulns for this scan grouped by service, ordered by max risk_score DESC."""
    rows = (
        await db.execute(
            select(
                Vulnerability.id,
                Vulnerability.service_id,
                Vulnerability.severity,
                Vulnerability.risk_score,
                Service.canonical_key.label("service_key"),
                Service.host,
                Service.port,
                Service.classification,
                Service.product,
                Service.version,
            )
            .outerjoin(Service, Service.id == Vulnerability.service_id)
            .join(VulnRunMatch, VulnRunMatch.vulnerability_id == Vulnerability.id)
            .where(VulnRunMatch.scan_id == scan_id)
        )
    ).all()

    groups: dict[str, dict] = {}
    for row in rows:
        key = str(row.service_id) if row.service_id else "none"
        if key not in groups:
            groups[key] = {
                "service_id": row.service_id,
                "service_key": row.service_key or "No service",
                "host": row.host,
                "port": row.port,
                "classification": (
                    row.classification.value
                    if row.classification and hasattr(row.classification, "value")
                    else str(row.classification or "unknown")
                ),
                "product": row.product,
                "version": row.version,
                "vuln_count": 0,
                "severities": {},
                "max_risk_score": None,
            }
        g = groups[key]
        g["vuln_count"] += 1
        sev = row.severity.value if hasattr(row.severity, "value") else str(row.severity)
        g["severities"][sev] = g["severities"].get(sev, 0) + 1
        if row.risk_score is not None:
            if g["max_risk_score"] is None or row.risk_score > g["max_risk_score"]:
                g["max_risk_score"] = row.risk_score

    return sorted(
        groups.values(),
        key=lambda x: (x["max_risk_score"] or 0, x["vuln_count"]),
        reverse=True,
    )


async def build_by_technology(db: AsyncSession, scan_id: UUID) -> list[dict]:
    """Vulns for this scan grouped by technology, ordered by max risk_score DESC."""
    rows = (
        await db.execute(
            select(
                Vulnerability.id,
                Vulnerability.technology_id,
                Vulnerability.severity,
                Vulnerability.risk_score,
                Technology.name.label("tech_name"),
                Technology.version.label("tech_version"),
                Technology.cpe,
                Technology.category,
            )
            .outerjoin(Technology, Technology.id == Vulnerability.technology_id)
            .join(VulnRunMatch, VulnRunMatch.vulnerability_id == Vulnerability.id)
            .where(
                VulnRunMatch.scan_id == scan_id,
                Vulnerability.technology_id.is_not(None),
            )
        )
    ).all()

    groups: dict[str, dict] = {}
    for row in rows:
        key = str(row.technology_id)
        if key not in groups:
            groups[key] = {
                "technology_id": row.technology_id,
                "name": row.tech_name or "Unknown",
                "version": row.tech_version,
                "cpe": row.cpe,
                "category": row.category,
                "vuln_count": 0,
                "severities": {},
                "max_risk_score": None,
            }
        g = groups[key]
        g["vuln_count"] += 1
        sev = row.severity.value if hasattr(row.severity, "value") else str(row.severity)
        g["severities"][sev] = g["severities"].get(sev, 0) + 1
        if row.risk_score is not None:
            if g["max_risk_score"] is None or row.risk_score > g["max_risk_score"]:
                g["max_risk_score"] = row.risk_score

    return sorted(
        groups.values(),
        key=lambda x: (x["max_risk_score"] or 0, x["vuln_count"]),
        reverse=True,
    )


async def build_endpoint_rows(
    db: AsyncSession,
    scan_id: UUID,
    *,
    is_login: bool | None = None,
    is_admin: bool | None = None,
    is_api: bool | None = None,
    offset: int = 0,
    limit: int = 50,
) -> tuple[int, list]:
    """Paginated endpoints for the target of this vuln scan."""
    target_id = await db.scalar(select(Scan.target_id).where(Scan.id == scan_id))
    if target_id is None:
        return 0, []

    base_q = select(Endpoint).where(Endpoint.target_id == target_id)

    if is_login is not None:
        base_q = base_q.where(Endpoint.is_login == is_login)
    if is_admin is not None:
        base_q = base_q.where(Endpoint.is_admin == is_admin)
    if is_api is not None:
        base_q = base_q.where(Endpoint.is_api == is_api)

    count_q = select(func.count()).select_from(base_q.subquery())
    total: int = (await db.scalar(count_q)) or 0

    page_q = base_q.order_by(Endpoint.last_seen.desc()).offset(offset).limit(limit)
    result = (await db.execute(page_q)).scalars().all()
    return total, list(result)


async def build_tls_view(db: AsyncSession, scan_id: UUID) -> list[dict]:
    """Most recent TLS observation per service for the target of this scan."""
    target_id = await db.scalar(select(Scan.target_id).where(Scan.id == scan_id))
    if target_id is None:
        return []

    # Distinct on service_id: get the most recent observation per service
    latest_subq = (
        select(
            TlsObservation.service_id,
            func.max(TlsObservation.observed_at).label("max_obs"),
        )
        .where(TlsObservation.target_id == target_id)
        .group_by(TlsObservation.service_id)
        .subquery()
    )

    rows = (
        await db.execute(
            select(TlsObservation, Service.canonical_key.label("service_key"))
            .join(
                latest_subq,
                (TlsObservation.service_id == latest_subq.c.service_id)
                & (TlsObservation.observed_at == latest_subq.c.max_obs),
            )
            .join(Service, Service.id == TlsObservation.service_id)
            .order_by(TlsObservation.cert_not_after.asc().nullslast())
        )
    ).all()

    now = datetime.now(timezone.utc)
    result = []
    for tls, service_key in rows:
        days = None
        is_expired = False
        if tls.cert_not_after:
            delta = tls.cert_not_after.replace(tzinfo=timezone.utc) - now
            days = delta.days
            is_expired = days < 0

        # Deprecated protocols: those enabled that are TLSv1.0 or TLSv1.1
        deprecated = [
            proto
            for proto, enabled in (tls.protocols or {}).items()
            if enabled and proto in ("TLSv1.0", "TLSv1.1")
        ]

        result.append({
            "service_id": tls.service_id,
            "service_key": service_key,
            "cert_subject": tls.cert_subject,
            "cert_issuer": tls.cert_issuer,
            "cert_not_after": tls.cert_not_after,
            "days_until_expiry": days,
            "is_expired": is_expired,
            "grade": tls.grade,
            "weak_ciphers": tls.weak_ciphers or [],
            "deprecated_protocols": deprecated,
            "observed_at": tls.observed_at,
        })

    return result


async def build_hvt_rows(db: AsyncSession, scan_id: UUID) -> list[dict]:
    """HVT signals for the target of this scan, grouped by asset and scored."""
    target_id = await db.scalar(select(Scan.target_id).where(Scan.id == scan_id))
    if target_id is None:
        return []

    rows = (
        await db.execute(
            select(HvtSignal, Asset.canonical_key.label("asset_label"))
            .join(Asset, Asset.id == HvtSignal.asset_id)
            .where(HvtSignal.target_id == target_id)
            .order_by(HvtSignal.score.desc())
        )
    ).all()

    groups: dict = {}
    for sig, asset_label in rows:
        key = str(sig.asset_id)
        if key not in groups:
            groups[key] = {
                "asset_id": sig.asset_id,
                "asset_label": asset_label,
                "signals": [],
            }
        groups[key]["signals"].append({
            "signal_type": sig.signal_type.value if hasattr(sig.signal_type, "value") else str(sig.signal_type),
            "score": sig.score,
            "confidence": sig.confidence,
            "evidence": sig.evidence or {},
        })

    # Compute hvt_score per asset using existing service
    result = []
    for g in groups.values():
        class _Sig:
            def __init__(self, d):
                self.signal_type = d["signal_type"]
                self.score = d["score"]
        mock_sigs = [_Sig(s) for s in g["signals"]]
        g["hvt_score"] = round(compute_hvt_score(mock_sigs), 3)
        result.append(g)

    return sorted(result, key=lambda x: x["hvt_score"], reverse=True)


async def build_triage_view(db: AsyncSession, scan_id: UUID, *, limit: int = 20) -> dict:
    """Top-N vulns by risk_score for AI triage display."""
    rows = (
        await db.execute(
            select(Vulnerability, Asset.canonical_key.label("asset_label"))
            .join(VulnRunMatch, VulnRunMatch.vulnerability_id == Vulnerability.id)
            .join(Asset, Asset.id == Vulnerability.asset_id)
            .where(
                VulnRunMatch.scan_id == scan_id,
                Vulnerability.status.notin_(["fixed", "false_positive", "wont_fix"]),
            )
            .order_by(desc(Vulnerability.risk_score).nullslast())
            .limit(limit)
        )
    ).all()

    total_scored: int = (
        await db.scalar(
            select(func.count())
            .select_from(
                select(Vulnerability.id)
                .join(VulnRunMatch, VulnRunMatch.vulnerability_id == Vulnerability.id)
                .where(
                    VulnRunMatch.scan_id == scan_id,
                    Vulnerability.risk_score.is_not(None),
                )
                .subquery()
            )
        )
    ) or 0

    triage_rows = [
        {
            "id": v.id,
            "title": v.title,
            "severity": v.severity.value if hasattr(v.severity, "value") else str(v.severity),
            "risk_score": v.risk_score,
            "cvss_v3": v.cvss_v3,
            "epss": v.epss,
            "kev": v.kev,
            "cve_ids": v.cve_ids or [],
            "asset_label": asset_label,
            "description": v.description or "",
            "remediation": v.remediation,
        }
        for v, asset_label in rows
    ]

    return {"rows": triage_rows, "total_with_risk_score": total_scored}
