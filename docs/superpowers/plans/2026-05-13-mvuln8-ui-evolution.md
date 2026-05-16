# M-Vuln-8: UI Evolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add six new intelligence tabs to the vuln scan detail page (By Service, By Technology, Endpoints, TLS, HVTs, Triage), enhance existing Overview and Vulnerabilities tabs with risk-score sorting and new filters, add an endpoint detail page, and add a cross-scan target risk rollup at `/targets/[id]/risk`.

**Architecture:** Backend read models in `services/vuln_view.py` feed six new API endpoints in `api/vuln_scans.py`; a seventh endpoint for `/targets/{id}/risk` is added to `api/targets.py`. Frontend adds tabs to the existing `vuln-scans/[id]/page.tsx`, a new `endpoints/[endpoint_id]` child page, and a new `targets/[id]/risk` page. All data is target-scoped via `target_id` FK (tenant isolation pattern unchanged).

**Tech Stack:** Python 3.11, SQLAlchemy 2.0 async, FastAPI, Next.js 14, TanStack Query, shadcn/ui, TypeScript strict

---

## File Map

| Action | Path | Purpose |
|---|---|---|
| Modify | `backend/app/schemas/vuln.py` | Add 8 new Pydantic response types; extend `VulnOut` + `VulnOverview` |
| Modify | `backend/app/services/vuln_view.py` | Add 6 new read-model functions; update `build_vuln_overview` + `build_vuln_rows` |
| Modify | `backend/app/api/vuln_scans.py` | Add 6 new GET endpoints; update `/vulnerabilities` + `/overview` |
| Modify | `backend/app/api/targets.py` | Add `GET /targets/{id}/risk` endpoint |
| Modify | `frontend/lib/api.ts` | Add 8 new TypeScript types + 6 new API helper signatures |
| Modify | `frontend/app/vuln-scans/[id]/page.tsx` | Add 6 new tab components; update Overview + Vulnerabilities tabs |
| Create | `frontend/app/vuln-scans/[id]/endpoints/[endpoint_id]/page.tsx` | Endpoint detail page |
| Create | `frontend/app/targets/[id]/risk/page.tsx` | Cross-scan target risk rollup |
| Modify | `frontend/components/AppShell.tsx` | Add breadcrumbs for new routes |

---

## Task 1: Extend Pydantic schemas

**Files:**
- Modify: `backend/app/schemas/vuln.py`

- [ ] **Step 1: Add new response types + extend existing**

Open `backend/app/schemas/vuln.py`. Replace the entire file with:

```python
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.scan import StageOut


class VulnScanCreateRequest(BaseModel):
    parent_scan_id: UUID
    profile: str = Field(default="vuln_quick", pattern="^(vuln_quick|vuln_standard|vuln_deep)$")
    intrusive: bool = False


class VulnScanOut(BaseModel):
    id: UUID
    target_domain: str
    parent_scan_id: UUID | None
    profile: str
    status: str
    progress_pct: int
    intrusive: bool
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None

    class Config:
        from_attributes = True


class VulnScanDetailOut(VulnScanOut):
    stages: list[StageOut]


class VulnOverview(BaseModel):
    total: int
    critical: int
    high: int
    med: int
    low: int
    info: int
    kev_count: int
    cve_count: int
    # M-Vuln-8 additions
    hvt_count: int = 0
    public_service_count: int = 0
    top_risk_vulns: list[dict] = []


class VulnOut(BaseModel):
    id: UUID
    canonical_key: str
    title: str
    severity: str
    cvss_v3: float | None
    epss: float | None = None       # M-Vuln-8: added
    risk_score: float | None = None  # M-Vuln-8: added
    cve_ids: list[str]
    cwe_ids: list[str]
    status: str
    asset_id: UUID
    asset_label: str
    template_id: str | None
    kev: bool
    first_seen: datetime
    last_seen: datetime

    class Config:
        from_attributes = True


class VulnsPage(BaseModel):
    total: int
    items: list[VulnOut]


class VulnStatusUpdateRequest(BaseModel):
    status: str = Field(
        pattern="^(triaged|false_positive|fixed|wont_fix|open|reopened)$"
    )


class VulnDiffOut(BaseModel):
    counts: dict
    new: list[VulnOut]
    seen: list[VulnOut]
    fixed: list[VulnOut]
    has_prior: bool


# ── M-Vuln-8: By Service ──────────────────────────────────────────────────────

class ByServiceRow(BaseModel):
    service_id: UUID | None
    service_key: str          # host:port/proto  or "No service"
    host: str | None
    port: int | None
    classification: str
    product: str | None
    version: str | None
    vuln_count: int
    severities: dict          # {"CRITICAL": 1, "HIGH": 3, ...}
    max_risk_score: float | None


class ByServiceResponse(BaseModel):
    rows: list[ByServiceRow]


# ── M-Vuln-8: By Technology ───────────────────────────────────────────────────

class ByTechRow(BaseModel):
    technology_id: UUID | None
    name: str
    version: str | None
    cpe: str | None
    category: str | None
    vuln_count: int
    severities: dict
    max_risk_score: float | None


class ByTechResponse(BaseModel):
    rows: list[ByTechRow]


# ── M-Vuln-8: Endpoints ───────────────────────────────────────────────────────

class EndpointRow(BaseModel):
    id: UUID
    url: str
    path: str
    method: str
    status_code: int | None
    content_type: str | None
    title: str | None
    is_login: bool
    is_signup: bool
    is_upload: bool
    is_api: bool
    is_admin: bool
    source_tool: str
    first_seen: datetime
    last_seen: datetime


class EndpointsPage(BaseModel):
    total: int
    items: list[EndpointRow]


class EndpointDetail(EndpointRow):
    """Same shape as EndpointRow — returned by the endpoint-detail page."""
    pass


# ── M-Vuln-8: TLS ─────────────────────────────────────────────────────────────

class TlsRow(BaseModel):
    service_id: UUID
    service_key: str            # host:port
    cert_subject: str | None
    cert_issuer: str | None
    cert_not_after: datetime | None
    days_until_expiry: int | None   # None if cert_not_after missing; negative = expired
    is_expired: bool
    grade: str | None
    weak_ciphers: list[str]
    deprecated_protocols: list[str]  # TLSv1.0, TLSv1.1 when enabled
    observed_at: datetime


class TlsResponse(BaseModel):
    rows: list[TlsRow]


# ── M-Vuln-8: HVTs ────────────────────────────────────────────────────────────

class HvtSignalItem(BaseModel):
    signal_type: str
    score: float
    confidence: int
    evidence: dict


class HvtRow(BaseModel):
    asset_id: UUID
    asset_label: str
    hvt_score: float
    signals: list[HvtSignalItem]


class HvtResponse(BaseModel):
    rows: list[HvtRow]


# ── M-Vuln-8: Triage ──────────────────────────────────────────────────────────

class TriageVulnRow(BaseModel):
    id: UUID
    title: str
    severity: str
    risk_score: float | None
    cvss_v3: float | None
    epss: float | None
    kev: bool
    cve_ids: list[str]
    asset_label: str
    description: str
    remediation: str | None


class TriageResponse(BaseModel):
    rows: list[TriageVulnRow]
    total_with_risk_score: int    # how many vulns in this scan have risk_score set


# ── M-Vuln-8: Target Risk Rollup ─────────────────────────────────────────────

class TargetRiskVulnRow(BaseModel):
    id: UUID
    title: str
    severity: str
    risk_score: float | None
    kev: bool
    asset_label: str
    status: str


class TargetRiskView(BaseModel):
    target_id: UUID
    target_domain: str
    open_counts: dict             # {"critical": N, "high": N, ...}
    top_risk_vulns: list[TargetRiskVulnRow]
    hvt_count: int
    hvt_signal_summary: dict      # {"admin_panel": 3, "git_repo": 1, ...}
    endpoint_count: int
    latest_vuln_scan_id: UUID | None
    latest_vuln_scan_status: str | None
    latest_vuln_scan_created_at: datetime | None
```

- [ ] **Step 2: Verify the file imports cleanly**

```bash
cd "F:\Studies\AI\RedTeam Dashboard"
docker compose -f infra/docker-compose.yml exec backend python -c "
from app.schemas.vuln import (
    VulnOverview, VulnOut, ByServiceResponse, ByTechResponse,
    EndpointsPage, TlsResponse, HvtResponse, TriageResponse, TargetRiskView
)
print('schemas ok')
"
```

Expected: `schemas ok`

- [ ] **Step 3: Commit**

```bash
git add backend/app/schemas/vuln.py
git commit -m "feat(vuln): M-Vuln-8 schemas — 8 new response types + extend VulnOut/VulnOverview"
```

---

## Task 2: Backend read models — By Service + By Technology

**Files:**
- Modify: `backend/app/services/vuln_view.py`

- [ ] **Step 1: Add imports at top of `vuln_view.py`**

Open `backend/app/services/vuln_view.py`. Add these imports after the existing imports:

```python
from collections import defaultdict

from app.models.asset import Asset
from app.models.service import Service
from app.models.technology import Technology
```

(The `Asset` import is already there — only add `Service` and `Technology` if they're not present.)

- [ ] **Step 2: Add `build_by_service` after the existing functions**

```python
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
```

- [ ] **Step 3: Add `build_by_technology` after `build_by_service`**

```python
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
```

- [ ] **Step 4: Verify imports resolve**

```bash
docker compose -f infra/docker-compose.yml exec backend python -c "
from app.services.vuln_view import build_by_service, build_by_technology
print('ok')
"
```

Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/vuln_view.py
git commit -m "feat(vuln): add build_by_service + build_by_technology read models"
```

---

## Task 3: Backend read models — Endpoints + TLS

**Files:**
- Modify: `backend/app/services/vuln_view.py`

- [ ] **Step 1: Add imports at top of vuln_view.py (if not already present)**

Add after existing imports:

```python
from datetime import datetime, timezone

from app.models.endpoint import Endpoint
from app.models.tls_observation import TlsObservation
from app.models import Scan
```

- [ ] **Step 2: Add `build_endpoint_rows`**

```python
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
```

- [ ] **Step 3: Add `build_tls_view`**

```python
async def build_tls_view(db: AsyncSession, scan_id: UUID) -> list[dict]:
    """Most recent TLS observation per service for the target of this scan."""
    target_id = await db.scalar(select(Scan.target_id).where(Scan.id == scan_id))
    if target_id is None:
        return []

    # Distinct on service_id: get the most recent observation per service
    # Use a subquery to get max observed_at per service_id
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
```

- [ ] **Step 4: Verify imports resolve**

```bash
docker compose -f infra/docker-compose.yml exec backend python -c "
from app.services.vuln_view import build_endpoint_rows, build_tls_view
print('ok')
"
```

Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/vuln_view.py
git commit -m "feat(vuln): add build_endpoint_rows + build_tls_view read models"
```

---

## Task 4: Backend read models — HVTs + Triage

**Files:**
- Modify: `backend/app/services/vuln_view.py`

- [ ] **Step 1: Add imports (if not already present)**

```python
from app.models.hvt_signal import HvtSignal
from app.services.hvt_score import compute_hvt_score
```

- [ ] **Step 2: Add `build_hvt_rows`**

```python
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
        # Create mock objects that compute_hvt_score can read (.signal_type, .score)
        class _Sig:
            def __init__(self, d):
                self.signal_type = d["signal_type"]
                self.score = d["score"]
        mock_sigs = [_Sig(s) for s in g["signals"]]
        g["hvt_score"] = round(compute_hvt_score(mock_sigs), 3)
        result.append(g)

    return sorted(result, key=lambda x: x["hvt_score"], reverse=True)
```

- [ ] **Step 3: Add `build_triage_view`**

```python
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
```

- [ ] **Step 4: Verify imports resolve**

```bash
docker compose -f infra/docker-compose.yml exec backend python -c "
from app.services.vuln_view import build_hvt_rows, build_triage_view
print('ok')
"
```

Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/vuln_view.py
git commit -m "feat(vuln): add build_hvt_rows + build_triage_view read models"
```

---

## Task 5: Update existing read models — Overview + Vuln Rows

**Files:**
- Modify: `backend/app/services/vuln_view.py`

- [ ] **Step 1: Update `build_vuln_overview` to add HVT count + exposure count + top risk vulns**

Replace `build_vuln_overview` with:

```python
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

        from app.models.service import ServiceClassification
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
```

- [ ] **Step 2: Update `VulnRow` dataclass to include `risk_score` and `epss`**

Replace the `VulnRow` dataclass:

```python
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
```

- [ ] **Step 3: Update `build_vuln_rows` — new sort, new filters, new fields**

Replace `build_vuln_rows`:

```python
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
```

- [ ] **Step 4: Verify no import errors**

```bash
docker compose -f infra/docker-compose.yml exec backend python -c "
from app.services.vuln_view import build_vuln_overview, build_vuln_rows
print('ok')
"
```

Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/vuln_view.py
git commit -m "feat(vuln): update build_vuln_overview (HVT/exposure/top-risk) + build_vuln_rows (risk_score sort + kev/hvt filters)"
```

---

## Task 6: New API endpoints for six tabs + update existing

**Files:**
- Modify: `backend/app/api/vuln_scans.py`

- [ ] **Step 1: Add new schema imports**

At the top of `backend/app/api/vuln_scans.py`, update the `app.schemas.vuln` import to include the new types:

```python
from app.schemas.vuln import (
    ByServiceResponse,
    ByServiceRow,
    ByTechResponse,
    ByTechRow,
    EndpointDetail,
    EndpointRow,
    EndpointsPage,
    HvtResponse,
    HvtRow,
    HvtSignalItem,
    TlsResponse,
    TlsRow,
    TriageResponse,
    TriageVulnRow,
    VulnDiffOut,
    VulnOverview,
    VulnOut,
    VulnScanCreateRequest,
    VulnScanDetailOut,
    VulnScanOut,
    VulnsPage,
)
```

Also add this import for the endpoint detail lookup:

```python
from sqlalchemy.orm import selectinload

from app.models.endpoint import Endpoint
```

- [ ] **Step 2: Update `list_vuln_scan_vulnerabilities` to accept new filters + pass new fields**

Replace the `list_vuln_scan_vulnerabilities` function:

```python
@router.get("/{scan_id}/vulnerabilities", response_model=VulnsPage)
async def list_vuln_scan_vulnerabilities(
    scan_id: UUID,
    severity: str | None = Query(None),
    status_filter: str | None = Query(None, alias="status"),
    kev_only: bool = Query(False),
    hvt_only: bool = Query(False),
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
        kev_only=kev_only,
        hvt_only=hvt_only,
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
            epss=r.epss,
            risk_score=r.risk_score,
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
```

Also update the helper `_vuln_row_to_out` to pass new fields:

```python
def _vuln_row_to_out(r) -> VulnOut:
    return VulnOut(
        id=r.id,
        canonical_key=r.canonical_key,
        title=r.title,
        severity=r.severity,
        cvss_v3=r.cvss_v3,
        epss=getattr(r, "epss", None),
        risk_score=getattr(r, "risk_score", None),
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
```

- [ ] **Step 3: Add `GET /{scan_id}/by-service` endpoint**

Add after the `get_vuln_diff` function:

```python
@router.get("/{scan_id}/by-service", response_model=ByServiceResponse)
async def get_vulns_by_service(
    scan_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ByServiceResponse:
    await _get_vuln_scan(db, scan_id, user.org_id)
    rows_data = await vuln_view.build_by_service(db, scan_id)
    rows = [ByServiceRow(**r) for r in rows_data]
    return ByServiceResponse(rows=rows)
```

- [ ] **Step 4: Add `GET /{scan_id}/by-technology` endpoint**

```python
@router.get("/{scan_id}/by-technology", response_model=ByTechResponse)
async def get_vulns_by_technology(
    scan_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ByTechResponse:
    await _get_vuln_scan(db, scan_id, user.org_id)
    rows_data = await vuln_view.build_by_technology(db, scan_id)
    rows = [ByTechRow(**r) for r in rows_data]
    return ByTechResponse(rows=rows)
```

- [ ] **Step 5: Add `GET /{scan_id}/endpoints` endpoint**

```python
@router.get("/{scan_id}/endpoints", response_model=EndpointsPage)
async def list_scan_endpoints(
    scan_id: UUID,
    is_login: bool | None = Query(None),
    is_admin: bool | None = Query(None),
    is_api: bool | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> EndpointsPage:
    await _get_vuln_scan(db, scan_id, user.org_id)
    total, endpoints = await vuln_view.build_endpoint_rows(
        db, scan_id,
        is_login=is_login,
        is_admin=is_admin,
        is_api=is_api,
        offset=offset,
        limit=limit,
    )
    items = [EndpointRow(**ep.__dict__) for ep in endpoints]
    return EndpointsPage(total=total, items=items)


@router.get("/{scan_id}/endpoints/{endpoint_id}", response_model=EndpointDetail)
async def get_endpoint_detail(
    scan_id: UUID,
    endpoint_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> EndpointDetail:
    scan, _ = await _get_vuln_scan(db, scan_id, user.org_id)
    from sqlalchemy import select as _select
    ep = await db.scalar(
        _select(Endpoint).where(
            Endpoint.id == endpoint_id,
            Endpoint.target_id == scan.target_id,
        )
    )
    if ep is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "endpoint not found")
    return EndpointDetail(**ep.__dict__)
```

Note: `_get_vuln_scan` currently returns a tuple `(scan, target_domain)`. Verify by reading the function — if it returns just the tuple, extract `scan` with `scan, _ = await _get_vuln_scan(...)`.

- [ ] **Step 6: Add TLS, HVT, Triage endpoints**

```python
@router.get("/{scan_id}/tls", response_model=TlsResponse)
async def get_tls_view(
    scan_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TlsResponse:
    await _get_vuln_scan(db, scan_id, user.org_id)
    rows_data = await vuln_view.build_tls_view(db, scan_id)
    rows = [TlsRow(**r) for r in rows_data]
    return TlsResponse(rows=rows)


@router.get("/{scan_id}/hvts", response_model=HvtResponse)
async def get_hvts(
    scan_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> HvtResponse:
    await _get_vuln_scan(db, scan_id, user.org_id)
    rows_data = await vuln_view.build_hvt_rows(db, scan_id)
    rows = [
        HvtRow(
            asset_id=r["asset_id"],
            asset_label=r["asset_label"],
            hvt_score=r["hvt_score"],
            signals=[HvtSignalItem(**s) for s in r["signals"]],
        )
        for r in rows_data
    ]
    return HvtResponse(rows=rows)


@router.get("/{scan_id}/triage", response_model=TriageResponse)
async def get_triage(
    scan_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TriageResponse:
    await _get_vuln_scan(db, scan_id, user.org_id)
    data = await vuln_view.build_triage_view(db, scan_id)
    rows = [TriageVulnRow(**r) for r in data["rows"]]
    return TriageResponse(rows=rows, total_with_risk_score=data["total_with_risk_score"])
```

- [ ] **Step 7: Fix `_get_vuln_scan` return type — it must return Scan object for endpoint detail**

Open `api/vuln_scans.py`. The current `_get_vuln_scan` returns `(scan, domain)`. The endpoint detail endpoint needs `scan.target_id`. Verify the existing return: `return row.Scan, row.domain`. If correct, the endpoint detail call `scan, _ = await _get_vuln_scan(...)` works as-is.

- [ ] **Step 8: Smoke-test that FastAPI loads all routes**

```bash
docker compose -f infra/docker-compose.yml exec backend python -c "
from app.api.vuln_scans import router
routes = [r.path for r in router.routes]
required = ['/vuln-scans/{scan_id}/by-service', '/vuln-scans/{scan_id}/by-technology',
            '/vuln-scans/{scan_id}/endpoints', '/vuln-scans/{scan_id}/tls',
            '/vuln-scans/{scan_id}/hvts', '/vuln-scans/{scan_id}/triage']
for r in required:
    assert r in routes, f'missing route: {r}'
print('all routes present')
"
```

Expected: `all routes present`

- [ ] **Step 9: Commit**

```bash
git add backend/app/api/vuln_scans.py
git commit -m "feat(vuln): add 6 new tab API endpoints + update vulnerabilities endpoint (risk_score sort, kev/hvt filters)"
```

---

## Task 7: Target risk API endpoint

**Files:**
- Modify: `backend/app/api/targets.py`

- [ ] **Step 1: Add imports to targets.py**

Add after existing imports in `backend/app/api/targets.py`:

```python
from sqlalchemy import desc, func

from app.models import Scan, ScanKind, ScanStatus
from app.models.endpoint import Endpoint
from app.models.hvt_signal import HvtSignal
from app.models.vulnerability import Vulnerability, VulnStatus
from app.models.vuln_run_match import VulnRunMatch
from app.schemas.vuln import TargetRiskView, TargetRiskVulnRow
```

- [ ] **Step 2: Add `GET /targets/{id}/risk` endpoint**

Add at the bottom of `backend/app/api/targets.py`:

```python
@router.get("/{target_id}/risk", response_model=TargetRiskView)
async def get_target_risk(
    target_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TargetRiskView:
    """Cross-scan vulnerability + HVT rollup for a target."""
    from app.models import Target, Project
    from app.models.asset import Asset

    # Tenant gate
    target = await db.scalar(
        select(Target)
        .join(Project, Project.id == Target.project_id)
        .where(Target.id == target_id, Project.org_id == user.org_id)
    )
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")

    # Open vuln counts by severity across all scans for this target
    sev_rows = (
        await db.execute(
            select(Vulnerability.severity, func.count(Vulnerability.id).label("cnt"))
            .where(
                Vulnerability.target_id == target_id,
                Vulnerability.status.in_(["open", "triaged"]),
            )
            .group_by(Vulnerability.severity)
        )
    ).all()
    open_counts: dict = {"critical": 0, "high": 0, "med": 0, "low": 0, "info": 0}
    for sev, cnt in sev_rows:
        key = (sev.value if hasattr(sev, "value") else str(sev)).lower()
        open_counts[key] = cnt

    # Top 10 open vulns by risk_score
    top_rows = (
        await db.execute(
            select(Vulnerability, Asset.canonical_key.label("asset_label"))
            .join(Asset, Asset.id == Vulnerability.asset_id)
            .where(
                Vulnerability.target_id == target_id,
                Vulnerability.status.in_(["open", "triaged"]),
            )
            .order_by(desc(Vulnerability.risk_score).nullslast())
            .limit(10)
        )
    ).all()
    top_risk_vulns = [
        TargetRiskVulnRow(
            id=v.id,
            title=v.title,
            severity=v.severity.value if hasattr(v.severity, "value") else str(v.severity),
            risk_score=v.risk_score,
            kev=v.kev,
            asset_label=asset_label,
            status=v.status.value if hasattr(v.status, "value") else str(v.status),
        )
        for v, asset_label in top_rows
    ]

    # HVT inventory
    hvt_count = (
        await db.scalar(
            select(func.count(HvtSignal.id)).where(HvtSignal.target_id == target_id)
        )
    ) or 0

    signal_rows = (
        await db.execute(
            select(HvtSignal.signal_type, func.count(HvtSignal.id).label("cnt"))
            .where(HvtSignal.target_id == target_id)
            .group_by(HvtSignal.signal_type)
        )
    ).all()
    hvt_signal_summary = {
        (st.value if hasattr(st, "value") else str(st)): cnt
        for st, cnt in signal_rows
    }

    # Endpoint count
    endpoint_count = (
        await db.scalar(
            select(func.count(Endpoint.id)).where(Endpoint.target_id == target_id)
        )
    ) or 0

    # Latest vuln scan
    latest_scan = await db.scalar(
        select(Scan)
        .where(Scan.target_id == target_id, Scan.kind == ScanKind.vuln_analysis)
        .order_by(desc(Scan.created_at))
        .limit(1)
    )

    return TargetRiskView(
        target_id=target_id,
        target_domain=target.domain,
        open_counts=open_counts,
        top_risk_vulns=top_risk_vulns,
        hvt_count=hvt_count,
        hvt_signal_summary=hvt_signal_summary,
        endpoint_count=endpoint_count,
        latest_vuln_scan_id=latest_scan.id if latest_scan else None,
        latest_vuln_scan_status=latest_scan.status.value if latest_scan else None,
        latest_vuln_scan_created_at=latest_scan.created_at if latest_scan else None,
    )
```

- [ ] **Step 3: Smoke-test the route loads**

```bash
docker compose -f infra/docker-compose.yml exec backend python -c "
from app.api.targets import router
paths = [r.path for r in router.routes]
assert '/targets/{target_id}/risk' in paths, f'missing; got {paths}'
print('target risk route ok')
"
```

Expected: `target risk route ok`

- [ ] **Step 4: Commit**

```bash
git add backend/app/api/targets.py
git commit -m "feat(vuln): add GET /targets/{id}/risk cross-scan rollup endpoint"
```

---

## Task 8: Frontend api.ts — new types + helpers

**Files:**
- Modify: `frontend/lib/api.ts`

- [ ] **Step 1: Add new types to api.ts**

Open `frontend/lib/api.ts`. At the end of the type definitions section (before any function definitions), add:

```typescript
// M-Vuln-8 ── Extended existing types
export type VulnOut = {
  id: string;
  canonical_key: string;
  title: string;
  severity: string;
  cvss_v3: number | null;
  epss: number | null;
  risk_score: number | null;
  cve_ids: string[];
  cwe_ids: string[];
  status: string;
  asset_id: string;
  asset_label: string;
  template_id: string | null;
  kev: boolean;
  first_seen: string;
  last_seen: string;
};

export type VulnOverview = {
  total: number;
  critical: number;
  high: number;
  med: number;
  low: number;
  info: number;
  kev_count: number;
  cve_count: number;
  hvt_count: number;
  public_service_count: number;
  top_risk_vulns: Array<{
    id: string;
    title: string;
    severity: string;
    risk_score: number | null;
    kev: boolean;
  }>;
};

// By Service
export type ByServiceRow = {
  service_id: string | null;
  service_key: string;
  host: string | null;
  port: number | null;
  classification: string;
  product: string | null;
  version: string | null;
  vuln_count: number;
  severities: Record<string, number>;
  max_risk_score: number | null;
};
export type ByServiceResponse = { rows: ByServiceRow[] };

// By Technology
export type ByTechRow = {
  technology_id: string | null;
  name: string;
  version: string | null;
  cpe: string | null;
  category: string | null;
  vuln_count: number;
  severities: Record<string, number>;
  max_risk_score: number | null;
};
export type ByTechResponse = { rows: ByTechRow[] };

// Endpoints
export type EndpointRow = {
  id: string;
  url: string;
  path: string;
  method: string;
  status_code: number | null;
  content_type: string | null;
  title: string | null;
  is_login: boolean;
  is_signup: boolean;
  is_upload: boolean;
  is_api: boolean;
  is_admin: boolean;
  source_tool: string;
  first_seen: string;
  last_seen: string;
};
export type EndpointsPage = { total: number; items: EndpointRow[] };

// TLS
export type TlsRow = {
  service_id: string;
  service_key: string;
  cert_subject: string | null;
  cert_issuer: string | null;
  cert_not_after: string | null;
  days_until_expiry: number | null;
  is_expired: boolean;
  grade: string | null;
  weak_ciphers: string[];
  deprecated_protocols: string[];
  observed_at: string;
};
export type TlsResponse = { rows: TlsRow[] };

// HVTs
export type HvtSignalItem = {
  signal_type: string;
  score: number;
  confidence: number;
  evidence: Record<string, unknown>;
};
export type HvtRow = {
  asset_id: string;
  asset_label: string;
  hvt_score: number;
  signals: HvtSignalItem[];
};
export type HvtResponse = { rows: HvtRow[] };

// Triage
export type TriageVulnRow = {
  id: string;
  title: string;
  severity: string;
  risk_score: number | null;
  cvss_v3: number | null;
  epss: number | null;
  kev: boolean;
  cve_ids: string[];
  asset_label: string;
  description: string;
  remediation: string | null;
};
export type TriageResponse = {
  rows: TriageVulnRow[];
  total_with_risk_score: number;
};

// Target Risk
export type TargetRiskVulnRow = {
  id: string;
  title: string;
  severity: string;
  risk_score: number | null;
  kev: boolean;
  asset_label: string;
  status: string;
};
export type TargetRiskView = {
  target_id: string;
  target_domain: string;
  open_counts: Record<string, number>;
  top_risk_vulns: TargetRiskVulnRow[];
  hvt_count: number;
  hvt_signal_summary: Record<string, number>;
  endpoint_count: number;
  latest_vuln_scan_id: string | null;
  latest_vuln_scan_status: string | null;
  latest_vuln_scan_created_at: string | null;
};
```

**Important:** If `VulnOut` and `VulnOverview` are already defined in api.ts, replace them with the updated versions above rather than adding duplicates. Search for existing definitions first.

- [ ] **Step 2: Verify TypeScript compiles (type check only)**

```bash
cd "F:\Studies\AI\RedTeam Dashboard\frontend"
npx tsc --noEmit 2>&1 | head -30
```

Expected: zero errors (or pre-existing errors unchanged — do not introduce new ones)

- [ ] **Step 3: Commit**

```bash
git add frontend/lib/api.ts
git commit -m "feat(vuln): add M-Vuln-8 TypeScript types to api.ts"
```

---

## Task 9: Frontend — six new tab components

**Files:**
- Modify: `frontend/app/vuln-scans/[id]/page.tsx`

This task adds six tab components to `page.tsx`. Add them above the `VulnScanDetailContent` component. Each tab is self-contained.

- [ ] **Step 1: Add imports for new types at top of page.tsx**

Update the api.ts import line:

```typescript
import {
  api,
  sseUrl,
  type ByServiceResponse,
  type ByTechResponse,
  type EndpointsPage,
  type EndpointRow,
  type HvtResponse,
  type TlsResponse,
  type TriageResponse,
  type VulnDiff,
  type VulnScanDetail,
  type VulnOverview,
  type VulnOut,
  type VulnsPage,
} from "@/lib/api";
```

Also add `Link` if not imported, and these lucide icons:

```typescript
import { Globe, Calendar, Clock, ExternalLink, Shield, Server, Cpu, Network, Lock, Brain } from "lucide-react";
```

- [ ] **Step 2: Add `ByServiceTab` component**

Add before `OverviewTab`:

```typescript
function ByServiceTab({ scanId }: { scanId: string }) {
  const q = useQuery({
    queryKey: ["vuln-by-service", scanId],
    queryFn: () => api<ByServiceResponse>(`/vuln-scans/${scanId}/by-service`),
  });

  if (q.isLoading) return <p className="mt-4 text-sm text-muted-foreground">Loading…</p>;
  if (q.isError || !q.data) return <p className="mt-4 text-sm text-destructive">Failed to load.</p>;

  const rows = q.data.rows;
  if (rows.length === 0)
    return (
      <div className="mt-6 rounded-lg border border-dashed border-border p-8 text-center">
        <p className="text-sm text-muted-foreground">No service-linked vulnerabilities found.</p>
      </div>
    );

  const SEV_ORDER = ["CRITICAL", "HIGH", "MED", "LOW", "INFO"];
  const SEV_COLOR: Record<string, string> = {
    CRITICAL: "bg-red-500",
    HIGH: "bg-orange-500",
    MED: "bg-yellow-500",
    LOW: "bg-blue-400",
    INFO: "bg-gray-400",
  };

  return (
    <div className="mt-4 space-y-3">
      {rows.map((row, i) => (
        <div key={row.service_id ?? `none-${i}`} className="rounded-lg border border-border bg-card p-4">
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div>
              <div className="flex items-center gap-2">
                <Server className="h-4 w-4 text-muted-foreground" />
                <span className="font-mono text-sm font-medium">{row.service_key}</span>
                {row.classification !== "unknown" && (
                  <span className="rounded-full border border-border bg-muted px-2 py-0.5 text-xs">
                    {row.classification}
                  </span>
                )}
              </div>
              {(row.product || row.version) && (
                <p className="mt-1 text-xs text-muted-foreground">
                  {[row.product, row.version].filter(Boolean).join(" ")}
                </p>
              )}
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xs text-muted-foreground">{row.vuln_count} vulns</span>
              {row.max_risk_score != null && (
                <span className="text-xs font-semibold tabular-nums">
                  Risk: {row.max_risk_score.toFixed(2)}
                </span>
              )}
            </div>
          </div>
          <div className="mt-2 flex flex-wrap gap-1">
            {SEV_ORDER.filter((s) => (row.severities[s] ?? 0) > 0).map((s) => (
              <span
                key={s}
                className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-semibold text-white ${SEV_COLOR[s]}`}
              >
                {s} {row.severities[s]}
              </span>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
```

- [ ] **Step 3: Add `ByTechTab` component**

```typescript
function ByTechTab({ scanId }: { scanId: string }) {
  const q = useQuery({
    queryKey: ["vuln-by-tech", scanId],
    queryFn: () => api<ByTechResponse>(`/vuln-scans/${scanId}/by-technology`),
  });

  if (q.isLoading) return <p className="mt-4 text-sm text-muted-foreground">Loading…</p>;
  if (q.isError || !q.data) return <p className="mt-4 text-sm text-destructive">Failed to load.</p>;

  const rows = q.data.rows;
  if (rows.length === 0)
    return (
      <div className="mt-6 rounded-lg border border-dashed border-border p-8 text-center">
        <p className="text-sm text-muted-foreground">No technology-linked vulnerabilities found.</p>
      </div>
    );

  const SEV_ORDER = ["CRITICAL", "HIGH", "MED", "LOW", "INFO"];
  const SEV_COLOR: Record<string, string> = {
    CRITICAL: "bg-red-500", HIGH: "bg-orange-500",
    MED: "bg-yellow-500", LOW: "bg-blue-400", INFO: "bg-gray-400",
  };

  return (
    <div className="mt-4 rounded-lg border border-border overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="bg-muted/50 border-b border-border">
          <tr>
            {["Technology", "Category", "CPE", "Vulns", "Severity breakdown", "Max Risk"].map((h) => (
              <th key={h} className="px-3 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-muted-foreground whitespace-nowrap">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={row.technology_id ?? i} className="border-b border-border hover:bg-muted/30">
              <td className="px-3 py-2.5 font-medium">
                {row.name}
                {row.version && <span className="ml-1 text-xs text-muted-foreground">{row.version}</span>}
              </td>
              <td className="px-3 py-2.5 text-xs text-muted-foreground">{row.category ?? "—"}</td>
              <td className="px-3 py-2.5 text-xs font-mono text-muted-foreground max-w-[200px] truncate">{row.cpe ?? "—"}</td>
              <td className="px-3 py-2.5 tabular-nums font-semibold">{row.vuln_count}</td>
              <td className="px-3 py-2.5">
                <div className="flex flex-wrap gap-1">
                  {SEV_ORDER.filter((s) => (row.severities[s] ?? 0) > 0).map((s) => (
                    <span key={s} className={`inline-flex items-center rounded-full px-1.5 py-0.5 text-xs font-semibold text-white ${SEV_COLOR[s]}`}>
                      {s[0]}{row.severities[s]}
                    </span>
                  ))}
                </div>
              </td>
              <td className="px-3 py-2.5 tabular-nums text-xs">
                {row.max_risk_score != null ? row.max_risk_score.toFixed(2) : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
```

- [ ] **Step 4: Add `EndpointsTab` component**

```typescript
const ENDPOINT_FLAG_OPTIONS = [
  { label: "All", value: "all" },
  { label: "Admin", value: "is_admin" },
  { label: "Login", value: "is_login" },
  { label: "API", value: "is_api" },
  { label: "Upload", value: "is_upload" },
];

function EndpointsTab({ scanId }: { scanId: string }) {
  const [filter, setFilter] = useState("all");
  const [offset, setOffset] = useState(0);
  const PAGE_SIZE = 50;

  useEffect(() => setOffset(0), [filter]);

  const params = new URLSearchParams({ offset: String(offset), limit: String(PAGE_SIZE) });
  if (filter === "is_admin") params.set("is_admin", "true");
  else if (filter === "is_login") params.set("is_login", "true");
  else if (filter === "is_api") params.set("is_api", "true");
  else if (filter === "is_upload") params.set("is_upload", "true");

  const q = useQuery({
    queryKey: ["vuln-endpoints", scanId, filter, offset],
    queryFn: () => api<EndpointsPage>(`/vuln-scans/${scanId}/endpoints?${params}`),
  });

  const items = q.data?.items ?? [];
  const total = q.data?.total ?? 0;
  const hasMore = offset + PAGE_SIZE < total;

  return (
    <div className="mt-4 space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        {ENDPOINT_FLAG_OPTIONS.map((opt) => (
          <button
            key={opt.value}
            onClick={() => setFilter(opt.value)}
            className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
              filter === opt.value
                ? "border-primary bg-primary text-primary-foreground"
                : "border-border hover:bg-muted"
            }`}
          >
            {opt.label}
          </button>
        ))}
        {total > 0 && (
          <span className="ml-auto text-xs text-muted-foreground">{total} endpoint{total !== 1 ? "s" : ""}</span>
        )}
      </div>

      {q.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : q.isError ? (
        <p className="text-sm text-destructive">Failed to load endpoints.</p>
      ) : items.length === 0 ? (
        <div className="rounded-lg border border-dashed border-border p-8 text-center">
          <p className="text-sm text-muted-foreground">No endpoints discovered yet.</p>
        </div>
      ) : (
        <div className="rounded-lg border border-border overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-muted/50 border-b border-border">
              <tr>
                {["Method", "URL", "Status", "Title", "Flags", "Source"].map((h) => (
                  <th key={h} className="px-3 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-muted-foreground whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {items.map((ep) => (
                <tr key={ep.id} className="border-b border-border hover:bg-muted/30">
                  <td className="px-3 py-2 text-xs font-mono font-semibold">{ep.method}</td>
                  <td className="px-3 py-2 max-w-[300px]">
                    <Link
                      href={`/vuln-scans/${scanId}/endpoints/${ep.id}`}
                      className="text-xs font-mono text-primary hover:underline truncate block"
                      title={ep.url}
                    >
                      {ep.path}
                    </Link>
                  </td>
                  <td className="px-3 py-2 text-xs tabular-nums">
                    {ep.status_code ?? "—"}
                  </td>
                  <td className="px-3 py-2 text-xs text-muted-foreground max-w-[180px] truncate">
                    {ep.title ?? "—"}
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-1">
                      {ep.is_admin && <span className="rounded bg-red-100 text-red-700 px-1.5 py-0.5 text-xs font-semibold">admin</span>}
                      {ep.is_login && <span className="rounded bg-yellow-100 text-yellow-700 px-1.5 py-0.5 text-xs font-semibold">login</span>}
                      {ep.is_api && <span className="rounded bg-blue-100 text-blue-700 px-1.5 py-0.5 text-xs font-semibold">api</span>}
                      {ep.is_upload && <span className="rounded bg-purple-100 text-purple-700 px-1.5 py-0.5 text-xs font-semibold">upload</span>}
                    </div>
                  </td>
                  <td className="px-3 py-2 text-xs text-muted-foreground">{ep.source_tool}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {(offset > 0 || hasMore) && (
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          {offset > 0 && (
            <button onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))} className="px-3 py-1.5 rounded border border-border hover:bg-muted">
              Previous
            </button>
          )}
          <span>{offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}</span>
          {hasMore && (
            <button onClick={() => setOffset(offset + PAGE_SIZE)} className="px-3 py-1.5 rounded border border-border hover:bg-muted">
              Load more
            </button>
          )}
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 5: Add `TlsTab` component**

```typescript
function TlsTab({ scanId }: { scanId: string }) {
  const q = useQuery({
    queryKey: ["vuln-tls", scanId],
    queryFn: () => api<TlsResponse>(`/vuln-scans/${scanId}/tls`),
  });

  if (q.isLoading) return <p className="mt-4 text-sm text-muted-foreground">Loading…</p>;
  if (q.isError || !q.data) return <p className="mt-4 text-sm text-destructive">Failed to load TLS data.</p>;

  const rows = q.data.rows;
  if (rows.length === 0)
    return (
      <div className="mt-6 rounded-lg border border-dashed border-border p-8 text-center">
        <p className="text-sm text-muted-foreground">No TLS observations found. Run testssl in the vuln profile to populate this tab.</p>
      </div>
    );

  const gradeColor = (grade: string | null) => {
    if (!grade) return "text-muted-foreground";
    if (grade.startsWith("A")) return "text-green-600";
    if (grade.startsWith("B")) return "text-yellow-600";
    return "text-red-600";
  };

  return (
    <div className="mt-4 space-y-3">
      {rows.map((row) => (
        <div key={row.service_id} className={`rounded-lg border p-4 ${row.is_expired ? "border-red-300 bg-red-50 dark:bg-red-950/20" : "border-border bg-card"}`}>
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div className="flex items-center gap-2">
              <Lock className="h-4 w-4 text-muted-foreground" />
              <span className="font-mono text-sm font-medium">{row.service_key}</span>
              {row.grade && (
                <span className={`text-lg font-bold ${gradeColor(row.grade)}`}>{row.grade}</span>
              )}
            </div>
            {row.cert_not_after && (
              <div className="text-xs">
                {row.is_expired ? (
                  <span className="font-semibold text-red-600">Certificate expired {Math.abs(row.days_until_expiry!)} days ago</span>
                ) : (
                  <span className={row.days_until_expiry! < 30 ? "text-orange-600 font-semibold" : "text-muted-foreground"}>
                    Expires in {row.days_until_expiry} days
                  </span>
                )}
              </div>
            )}
          </div>
          {row.cert_subject && (
            <p className="mt-2 text-xs text-muted-foreground truncate">
              Subject: {row.cert_subject}
            </p>
          )}
          {row.deprecated_protocols.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1">
              {row.deprecated_protocols.map((p) => (
                <span key={p} className="rounded bg-orange-100 text-orange-700 px-2 py-0.5 text-xs font-semibold">
                  {p} enabled
                </span>
              ))}
            </div>
          )}
          {row.weak_ciphers.length > 0 && (
            <div className="mt-2">
              <span className="text-xs text-muted-foreground">Weak ciphers: </span>
              <span className="text-xs text-orange-600">{row.weak_ciphers.join(", ")}</span>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
```

- [ ] **Step 6: Add `HvtsTab` component**

```typescript
const HVT_SIGNAL_LABELS: Record<string, string> = {
  admin_panel: "Admin Panel",
  login_form: "Login Form",
  signup_form: "Sign-up Form",
  upload_form: "Upload Form",
  api_doc: "API Docs",
  dev_portal: "Dev Portal",
  jenkins: "Jenkins",
  wordpress: "WordPress",
  gitlab: "GitLab",
  k8s_dashboard: "K8s Dashboard",
  exposed_index: "Exposed Index",
  swagger: "Swagger",
  graphql: "GraphQL",
  git_repo: "Git Repo",
  env_file: ".env File",
  other: "Other",
};

const HVT_SIGNAL_COLOR: Record<string, string> = {
  admin_panel: "bg-red-100 text-red-700",
  jenkins: "bg-red-100 text-red-700",
  git_repo: "bg-red-100 text-red-700",
  env_file: "bg-red-100 text-red-700",
  k8s_dashboard: "bg-red-100 text-red-700",
  login_form: "bg-orange-100 text-orange-700",
  upload_form: "bg-orange-100 text-orange-700",
  wordpress: "bg-blue-100 text-blue-700",
  gitlab: "bg-purple-100 text-purple-700",
  api_doc: "bg-blue-100 text-blue-700",
  swagger: "bg-blue-100 text-blue-700",
  graphql: "bg-blue-100 text-blue-700",
};

function HvtsTab({ scanId }: { scanId: string }) {
  const q = useQuery({
    queryKey: ["vuln-hvts", scanId],
    queryFn: () => api<HvtResponse>(`/vuln-scans/${scanId}/hvts`),
  });

  if (q.isLoading) return <p className="mt-4 text-sm text-muted-foreground">Loading…</p>;
  if (q.isError || !q.data) return <p className="mt-4 text-sm text-destructive">Failed to load HVT data.</p>;

  const rows = q.data.rows;
  if (rows.length === 0)
    return (
      <div className="mt-6 rounded-lg border border-dashed border-border p-8 text-center">
        <p className="text-sm text-muted-foreground">No high-value target signals detected. Run panel_detector or swagger_discoverer to populate this tab.</p>
      </div>
    );

  return (
    <div className="mt-4 space-y-3">
      {rows.map((row) => (
        <div key={row.asset_id} className="rounded-lg border border-border bg-card p-4">
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-muted-foreground" />
              <span className="font-mono text-sm font-medium">{row.asset_label}</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="text-xs text-muted-foreground">HVT score</div>
              <div
                className={`text-sm font-bold tabular-nums ${
                  row.hvt_score > 0.7 ? "text-red-600" : row.hvt_score > 0.4 ? "text-orange-500" : "text-muted-foreground"
                }`}
              >
                {row.hvt_score.toFixed(2)}
              </div>
            </div>
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {row.signals.map((sig, i) => {
              const colorClass = HVT_SIGNAL_COLOR[sig.signal_type] ?? "bg-gray-100 text-gray-700";
              const label = HVT_SIGNAL_LABELS[sig.signal_type] ?? sig.signal_type;
              return (
                <span
                  key={i}
                  className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${colorClass}`}
                  title={`Score: ${sig.score.toFixed(2)}, Confidence: ${sig.confidence}%`}
                >
                  {label}
                </span>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}
```

- [ ] **Step 7: Add `TriageTab` component**

```typescript
function TriageTab({ scanId }: { scanId: string }) {
  const q = useQuery({
    queryKey: ["vuln-triage", scanId],
    queryFn: () => api<TriageResponse>(`/vuln-scans/${scanId}/triage`),
  });

  if (q.isLoading) return <p className="mt-4 text-sm text-muted-foreground">Loading triage data…</p>;
  if (q.isError || !q.data) return <p className="mt-4 text-sm text-destructive">Failed to load triage data.</p>;

  const { rows, total_with_risk_score } = q.data;

  if (rows.length === 0)
    return (
      <div className="mt-6 rounded-lg border border-dashed border-border p-8 text-center">
        <p className="text-sm text-muted-foreground">No triage data yet. Risk scores are populated by the correlator stage.</p>
      </div>
    );

  return (
    <div className="mt-4 space-y-4">
      <p className="text-xs text-muted-foreground">
        Top {rows.length} vulnerabilities by composite risk score. {total_with_risk_score} total have been scored.
      </p>
      {rows.map((row, i) => (
        <div key={row.id} className="rounded-lg border border-border bg-card p-4 space-y-2">
          <div className="flex items-start justify-between gap-3 flex-wrap">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-muted-foreground tabular-nums w-5">#{i + 1}</span>
              <SeverityBadge severity={row.severity} />
              <span className="font-medium text-sm">{row.title}</span>
              {row.kev && (
                <span className="rounded bg-red-100 text-red-700 px-1.5 py-0.5 text-xs font-bold">KEV</span>
              )}
            </div>
            <div className="flex items-center gap-3 text-xs text-muted-foreground">
              {row.risk_score != null && (
                <span className="font-semibold text-foreground">Risk: {row.risk_score.toFixed(2)}</span>
              )}
              {row.cvss_v3 != null && <span>CVSS: {row.cvss_v3.toFixed(1)}</span>}
              {row.epss != null && <span>EPSS: {(row.epss * 100).toFixed(1)}%</span>}
              <span className="font-mono">{row.asset_label}</span>
            </div>
          </div>
          {row.cve_ids.length > 0 && <CveBadges ids={row.cve_ids} />}
          {row.description && (
            <p className="text-xs text-muted-foreground leading-relaxed line-clamp-3">
              {row.description}
            </p>
          )}
          {row.remediation && (
            <div className="rounded-md border border-border bg-muted/40 p-3">
              <p className="text-xs font-semibold mb-1">Remediation</p>
              <p className="text-xs text-muted-foreground leading-relaxed">{row.remediation}</p>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
```

- [ ] **Step 8: Commit**

```bash
git add frontend/app/vuln-scans/[id]/page.tsx
git commit -m "feat(vuln): add ByService, ByTech, Endpoints, TLS, HVTs, Triage tab components"
```

---

## Task 10: Wire new tabs into the tab shell + update Overview + Vulnerabilities tabs

**Files:**
- Modify: `frontend/app/vuln-scans/[id]/page.tsx`

- [ ] **Step 1: Update `VALID_TABS` and `TabsList` in `VulnScanDetailContent`**

Find the `VALID_TABS` line:

```typescript
const VALID_TABS = ["overview", "vulnerabilities", "diff"];
```

Replace with:

```typescript
const VALID_TABS = [
  "overview", "vulnerabilities", "by-service", "by-tech",
  "endpoints", "tls", "hvts", "triage", "diff",
];
```

Find the `<TabsList>` block and replace with:

```typescript
<TabsList className="flex-wrap h-auto">
  <TabsTrigger value="overview">Overview</TabsTrigger>
  <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
  <TabsTrigger value="by-service">
    <Server className="h-3.5 w-3.5 mr-1.5" />
    By Service
  </TabsTrigger>
  <TabsTrigger value="by-tech">
    <Cpu className="h-3.5 w-3.5 mr-1.5" />
    By Tech
  </TabsTrigger>
  <TabsTrigger value="endpoints">
    <Network className="h-3.5 w-3.5 mr-1.5" />
    Endpoints
  </TabsTrigger>
  <TabsTrigger value="tls">
    <Lock className="h-3.5 w-3.5 mr-1.5" />
    TLS
  </TabsTrigger>
  <TabsTrigger value="hvts">
    <Shield className="h-3.5 w-3.5 mr-1.5" />
    HVTs
  </TabsTrigger>
  <TabsTrigger value="triage">
    <Brain className="h-3.5 w-3.5 mr-1.5" />
    Triage
  </TabsTrigger>
  <TabsTrigger value="diff">Diff</TabsTrigger>
</TabsList>
```

Add the six new `<TabsContent>` blocks inside the `<Tabs>` component, after the existing three:

```typescript
<TabsContent value="by-service">
  <ByServiceTab scanId={params.id} />
</TabsContent>
<TabsContent value="by-tech">
  <ByTechTab scanId={params.id} />
</TabsContent>
<TabsContent value="endpoints">
  <EndpointsTab scanId={params.id} />
</TabsContent>
<TabsContent value="tls">
  <TlsTab scanId={params.id} />
</TabsContent>
<TabsContent value="hvts">
  <HvtsTab scanId={params.id} />
</TabsContent>
<TabsContent value="triage">
  <TriageTab scanId={params.id} />
</TabsContent>
```

- [ ] **Step 2: Update `OverviewTab` to show HVT count + public services + top risk vulns**

Inside `OverviewTab`, after the existing KEV/CVE summary block, add:

```typescript
{/* HVT + exposure summary (M-Vuln-8) */}
{(d.hvt_count > 0 || d.public_service_count > 0) && (
  <div className="flex flex-wrap gap-3">
    {d.hvt_count > 0 && (
      <div className="inline-flex items-center gap-2 rounded-md border border-orange-300 bg-orange-50 dark:bg-orange-950/20 px-3 py-2">
        <Shield className="h-3.5 w-3.5 text-orange-600" />
        <span className="text-xs text-muted-foreground">HVT signals</span>
        <span className="text-sm font-semibold tabular-nums text-orange-600">{d.hvt_count}</span>
      </div>
    )}
    {d.public_service_count > 0 && (
      <div className="inline-flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2">
        <span className="text-xs text-muted-foreground">Public web services</span>
        <span className="text-sm font-semibold tabular-nums">{d.public_service_count}</span>
      </div>
    )}
  </div>
)}

{/* Top 3 risk-scored vulns */}
{d.top_risk_vulns.length > 0 && (
  <div>
    <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-2">
      Highest Risk
    </h3>
    <div className="space-y-1.5">
      {d.top_risk_vulns.map((v) => (
        <div key={v.id} className="flex items-center gap-2 rounded border border-border bg-card px-3 py-2">
          <SeverityBadge severity={v.severity} />
          <span className="text-sm font-medium flex-1 truncate">{v.title}</span>
          {v.kev && <span className="text-xs font-bold text-red-600">KEV</span>}
          {v.risk_score != null && (
            <span className="text-xs font-semibold tabular-nums text-muted-foreground">
              {v.risk_score.toFixed(2)}
            </span>
          )}
        </div>
      ))}
    </div>
  </div>
)}
```

- [ ] **Step 3: Update `VulnerabilitiesTab` — add KEV-only + HVT-only filters + risk_score column**

In `VulnerabilitiesTab`, add state for new filters:

```typescript
const [kevOnly, setKevOnly] = useState(false);
const [hvtOnly, setHvtOnly] = useState(false);
```

Update `useEffect` dependency array:

```typescript
useEffect(() => setOffset(0), [severity, status, kevOnly, hvtOnly]);
```

Update `params` construction:

```typescript
const params = new URLSearchParams({
  offset: String(offset),
  limit: String(PAGE_SIZE),
});
if (severity !== "All") params.set("severity", severity);
if (status !== "All") params.set("status", status);
if (kevOnly) params.set("kev_only", "true");
if (hvtOnly) params.set("hvt_only", "true");
```

Update `queryKey`:

```typescript
queryKey: ["vuln-list", scanId, severity, status, kevOnly, hvtOnly, offset],
```

Add KEV-only and HVT-only toggle buttons after the existing filter dropdowns:

```typescript
<button
  onClick={() => setKevOnly(!kevOnly)}
  className={`inline-flex items-center gap-1 rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
    kevOnly
      ? "border-red-400 bg-red-100 text-red-700"
      : "border-border hover:bg-muted"
  }`}
>
  KEV only
</button>
<button
  onClick={() => setHvtOnly(!hvtOnly)}
  className={`inline-flex items-center gap-1 rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
    hvtOnly
      ? "border-orange-400 bg-orange-100 text-orange-700"
      : "border-border hover:bg-muted"
  }`}
>
  HVT assets only
</button>
```

Add `Risk Score` as an extra column header after `CVSS`:

```typescript
"Risk",
```

And add the cell after the CVSS cell:

```typescript
<td className="px-3 py-2.5 tabular-nums text-xs">
  {v.risk_score != null ? v.risk_score.toFixed(2) : "—"}
</td>
```

- [ ] **Step 4: Verify TypeScript compiles**

```bash
cd "F:\Studies\AI\RedTeam Dashboard\frontend"
npx tsc --noEmit 2>&1 | head -30
```

Expected: zero new errors

- [ ] **Step 5: Commit**

```bash
git add frontend/app/vuln-scans/[id]/page.tsx
git commit -m "feat(vuln): wire 6 new tabs into detail page + update Overview + Vulnerabilities tabs"
```

---

## Task 11: Endpoint detail page

**Files:**
- Create: `frontend/app/vuln-scans/[id]/endpoints/[endpoint_id]/page.tsx`

- [ ] **Step 1: Create the page file**

```typescript
"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { ArrowLeft, Globe } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { api, type EndpointRow } from "@/lib/api";

export default function EndpointDetailPage({
  params,
}: {
  params: { id: string; endpoint_id: string };
}) {
  const q = useQuery({
    queryKey: ["endpoint-detail", params.id, params.endpoint_id],
    queryFn: () =>
      api<EndpointRow>(
        `/vuln-scans/${params.id}/endpoints/${params.endpoint_id}`
      ),
  });

  if (q.isLoading || !q.data) {
    return (
      <AppShell>
        <p className="text-sm text-muted-foreground">Loading endpoint…</p>
      </AppShell>
    );
  }

  const ep = q.data;

  const flags = [
    ep.is_admin && "admin",
    ep.is_login && "login",
    ep.is_api && "api",
    ep.is_upload && "upload",
    ep.is_signup && "signup",
  ].filter(Boolean) as string[];

  const FLAG_COLORS: Record<string, string> = {
    admin: "bg-red-100 text-red-700",
    login: "bg-yellow-100 text-yellow-700",
    api: "bg-blue-100 text-blue-700",
    upload: "bg-purple-100 text-purple-700",
    signup: "bg-green-100 text-green-700",
  };

  return (
    <AppShell>
      <div className="mb-6">
        <Link
          href={`/vuln-scans/${params.id}?tab=endpoints`}
          className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground mb-4"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Back to Endpoints
        </Link>
        <div className="flex items-center gap-3">
          <Globe className="h-5 w-5 text-primary" />
          <h1 className="text-xl font-semibold font-mono break-all">{ep.url}</h1>
        </div>
        {ep.title && <p className="mt-1 text-sm text-muted-foreground">{ep.title}</p>}
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-xs text-muted-foreground mb-1">Method</div>
          <div className="text-lg font-bold font-mono">{ep.method}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-xs text-muted-foreground mb-1">Status Code</div>
          <div className={`text-lg font-bold tabular-nums ${ep.status_code && ep.status_code < 400 ? "text-green-600" : "text-red-600"}`}>
            {ep.status_code ?? "—"}
          </div>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-xs text-muted-foreground mb-1">Content Type</div>
          <div className="text-sm font-mono truncate">{ep.content_type ?? "—"}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-xs text-muted-foreground mb-1">Source</div>
          <div className="text-sm">{ep.source_tool}</div>
        </div>
      </div>

      {flags.length > 0 && (
        <div className="mb-6">
          <p className="text-xs text-muted-foreground mb-2 uppercase font-semibold tracking-wide">Flags</p>
          <div className="flex flex-wrap gap-2">
            {flags.map((f) => (
              <span
                key={f}
                className={`rounded-full px-3 py-1 text-sm font-semibold ${FLAG_COLORS[f] ?? "bg-gray-100 text-gray-700"}`}
              >
                {f}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-xs text-muted-foreground mb-1">First seen</div>
          <div className="text-sm">{new Date(ep.first_seen).toLocaleString()}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-xs text-muted-foreground mb-1">Last seen</div>
          <div className="text-sm">{new Date(ep.last_seen).toLocaleString()}</div>
        </div>
      </div>
    </AppShell>
  );
}
```

- [ ] **Step 2: Add breadcrumb entry in AppShell.tsx**

Open `frontend/components/AppShell.tsx`. Find the breadcrumb logic (a series of `if` checks on `pathname`). Add:

```typescript
if (pathname.match(/^\/vuln-scans\/[^/]+\/endpoints\/[^/]+/)) {
  return [
    { label: "Vulnerability Scans", href: "/vuln-scans" },
    { label: scan_id_from_path, href: `/vuln-scans/${extractId(pathname)}` },
    { label: "Endpoint Detail" },
  ];
}
```

Since AppShell breadcrumbs are pattern-matched by prefix, look at existing patterns in the file and follow the same style. Typically it looks like:

```typescript
} else if (pathname.startsWith("/vuln-scans/") && pathname.includes("/endpoints/")) {
  breadcrumbs = [
    { label: "Vulnerability Scans", href: "/vuln-scans" },
    { label: pathname.split("/")[2].slice(0, 8) + "…", href: `/vuln-scans/${pathname.split("/")[2]}` },
    { label: "Endpoint" },
  ];
}
```

Read the existing breadcrumb block in AppShell.tsx and follow the exact same pattern used for other routes.

- [ ] **Step 3: Verify TypeScript compiles**

```bash
cd "F:\Studies\AI\RedTeam Dashboard\frontend"
npx tsc --noEmit 2>&1 | head -20
```

Expected: no new errors

- [ ] **Step 4: Commit**

```bash
git add frontend/app/vuln-scans/[id]/endpoints/[endpoint_id]/page.tsx frontend/components/AppShell.tsx
git commit -m "feat(vuln): add endpoint detail page + breadcrumb"
```

---

## Task 12: Target risk rollup page

**Files:**
- Create: `frontend/app/targets/[id]/risk/page.tsx`

- [ ] **Step 1: Create the page file**

```typescript
"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { ArrowLeft, Shield, Globe, ExternalLink } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { api, type TargetRiskView } from "@/lib/api";

const SEVERITY_COLOR: Record<string, string> = {
  critical: "text-red-600 bg-red-50 border-red-200",
  high: "text-orange-500 bg-orange-50 border-orange-200",
  med: "text-yellow-600 bg-yellow-50 border-yellow-200",
  low: "text-blue-500 bg-blue-50 border-blue-200",
  info: "text-gray-500 bg-gray-50 border-gray-200",
};

const SEVERITY_LABEL: Record<string, string> = {
  critical: "CRITICAL", high: "HIGH", med: "MED", low: "LOW", info: "INFO",
};

export default function TargetRiskPage({
  params,
}: {
  params: { id: string };
}) {
  const q = useQuery({
    queryKey: ["target-risk", params.id],
    queryFn: () => api<TargetRiskView>(`/targets/${params.id}/risk`),
  });

  if (q.isLoading || !q.data) {
    return (
      <AppShell>
        <p className="text-sm text-muted-foreground">Loading risk view…</p>
      </AppShell>
    );
  }

  const d = q.data;
  const totalOpen = Object.values(d.open_counts).reduce((a, b) => a + b, 0);

  return (
    <AppShell>
      <div className="mb-6">
        <Link
          href="/targets"
          className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground mb-4"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Back to Targets
        </Link>
        <div className="flex items-center gap-3">
          <Globe className="h-5 w-5 text-primary" />
          <h1 className="text-2xl font-semibold tracking-tight">{d.target_domain}</h1>
        </div>
        <p className="mt-1 text-sm text-muted-foreground">Risk Rollup — continuous monitoring view</p>
      </div>

      {/* Open vuln severity cards */}
      <section className="mb-8">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground mb-3">
          Open Vulnerabilities ({totalOpen})
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {["critical", "high", "med", "low", "info"].map((sev) => (
            <div
              key={sev}
              className={`rounded-lg border px-4 py-3 flex flex-col gap-1 ${SEVERITY_COLOR[sev]}`}
            >
              <div className="text-xs font-semibold uppercase tracking-wide">
                {SEVERITY_LABEL[sev]}
              </div>
              <div className="text-2xl font-bold tabular-nums leading-none">
                {d.open_counts[sev] ?? 0}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* HVT inventory */}
      {d.hvt_count > 0 && (
        <section className="mb-8">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground mb-3">
            HVT Signals ({d.hvt_count})
          </h2>
          <div className="flex flex-wrap gap-2">
            {Object.entries(d.hvt_signal_summary)
              .sort(([, a], [, b]) => b - a)
              .map(([type, count]) => (
                <div
                  key={type}
                  className="inline-flex items-center gap-1.5 rounded-full border border-orange-300 bg-orange-50 dark:bg-orange-950/20 px-3 py-1"
                >
                  <Shield className="h-3 w-3 text-orange-600" />
                  <span className="text-xs font-medium">{type.replace(/_/g, " ")}</span>
                  <span className="text-xs font-bold text-orange-700">{count}</span>
                </div>
              ))}
          </div>
        </section>
      )}

      {/* Endpoint surface */}
      <section className="mb-8">
        <div className="inline-flex items-center gap-2 rounded-md border border-border bg-card px-4 py-3">
          <span className="text-xs text-muted-foreground">Discovered endpoints</span>
          <span className="text-lg font-bold tabular-nums">{d.endpoint_count}</span>
        </div>
      </section>

      {/* Top 10 by risk score */}
      {d.top_risk_vulns.length > 0 && (
        <section className="mb-8">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground mb-3">
            Highest Risk Findings
          </h2>
          <div className="rounded-lg border border-border overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-muted/50 border-b border-border">
                <tr>
                  {["Severity", "Title", "Asset", "Risk Score", "Status"].map((h) => (
                    <th
                      key={h}
                      className="px-3 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-muted-foreground whitespace-nowrap"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {d.top_risk_vulns.map((v) => (
                  <tr key={v.id} className="border-b border-border hover:bg-muted/30">
                    <td className="px-3 py-2.5">
                      <span
                        className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold ${
                          SEVERITY_COLOR[v.severity.toLowerCase()] ?? "text-gray-500 bg-gray-100 border-gray-300"
                        }`}
                      >
                        {v.severity}
                      </span>
                    </td>
                    <td className="px-3 py-2.5 font-medium max-w-[260px]">
                      <span className="truncate block" title={v.title}>
                        {v.title}
                      </span>
                      {v.kev && (
                        <span className="text-xs text-red-600 font-semibold">KEV</span>
                      )}
                    </td>
                    <td className="px-3 py-2.5 text-xs font-mono text-muted-foreground max-w-[160px] truncate">
                      {v.asset_label}
                    </td>
                    <td className="px-3 py-2.5 tabular-nums text-xs font-semibold">
                      {v.risk_score != null ? v.risk_score.toFixed(2) : "—"}
                    </td>
                    <td className="px-3 py-2.5 text-xs text-muted-foreground">
                      {v.status.replace(/_/g, " ")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Latest vuln scan link */}
      {d.latest_vuln_scan_id && (
        <section>
          <div className="inline-flex items-center gap-2 text-sm">
            <span className="text-muted-foreground">Latest vuln scan:</span>
            <Link
              href={`/vuln-scans/${d.latest_vuln_scan_id}`}
              className="inline-flex items-center gap-1 text-primary hover:underline"
            >
              {d.latest_vuln_scan_status}
              <ExternalLink className="h-3 w-3" />
            </Link>
            {d.latest_vuln_scan_created_at && (
              <span className="text-xs text-muted-foreground">
                {new Date(d.latest_vuln_scan_created_at).toLocaleDateString()}
              </span>
            )}
          </div>
        </section>
      )}
    </AppShell>
  );
}
```

- [ ] **Step 2: Add breadcrumb for `/targets/[id]/risk` in AppShell.tsx**

In `frontend/components/AppShell.tsx`, add to the breadcrumb switch/if chain:

```typescript
} else if (pathname.match(/^\/targets\/[^/]+\/risk/)) {
  breadcrumbs = [
    { label: "Targets", href: "/targets" },
    { label: "Risk View" },
  ];
}
```

Follow the exact breadcrumb pattern already used in the file.

- [ ] **Step 3: Verify TypeScript compiles**

```bash
cd "F:\Studies\AI\RedTeam Dashboard\frontend"
npx tsc --noEmit 2>&1 | head -20
```

Expected: no new errors

- [ ] **Step 4: Commit**

```bash
git add frontend/app/targets/[id]/risk/page.tsx frontend/components/AppShell.tsx
git commit -m "feat(vuln): add /targets/[id]/risk rollup page + breadcrumb"
```

---

## Integration Verification

After all tasks are committed, run end-to-end checks:

```bash
# 1. All backend imports resolve
docker compose -f infra/docker-compose.yml exec backend python -c "
from app.services.vuln_view import (
    build_by_service, build_by_technology, build_endpoint_rows,
    build_tls_view, build_hvt_rows, build_triage_view,
    build_vuln_overview, build_vuln_rows
)
from app.api.vuln_scans import router as vs_router
from app.api.targets import router as t_router
paths = [r.path for r in vs_router.routes]
target_paths = [r.path for r in t_router.routes]
required = [
    '/vuln-scans/{scan_id}/by-service',
    '/vuln-scans/{scan_id}/by-technology',
    '/vuln-scans/{scan_id}/endpoints',
    '/vuln-scans/{scan_id}/endpoints/{endpoint_id}',
    '/vuln-scans/{scan_id}/tls',
    '/vuln-scans/{scan_id}/hvts',
    '/vuln-scans/{scan_id}/triage',
]
for r in required:
    assert r in paths, f'missing: {r}'
assert '/targets/{target_id}/risk' in target_paths
print('all imports and routes ok')
"

# 2. Docker containers restart successfully after code changes
docker compose -f infra/docker-compose.yml restart backend
docker compose -f infra/docker-compose.yml logs backend --tail=20
# Expected: 'Application startup complete' with no import errors

# 3. TypeScript type check
cd "F:\Studies\AI\RedTeam Dashboard\frontend"
npx tsc --noEmit 2>&1 | grep -c "error TS"
# Expected: 0 (or same count as before if pre-existing errors exist)

# 4. API smoke tests (requires running docker compose)
# Substitute a real scan_id and target_id from your DB
TOKEN=$(curl -s -X POST http://localhost:8000/auth/token -d "username=your@email.com&password=yourpw" | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
SCAN_ID="<your-completed-vuln-scan-id>"
TARGET_ID="<your-target-id>"

curl -sf -H "Authorization: Bearer $TOKEN" "http://localhost:8000/vuln-scans/$SCAN_ID/by-service" | python -m json.tool | head -20
curl -sf -H "Authorization: Bearer $TOKEN" "http://localhost:8000/vuln-scans/$SCAN_ID/by-technology" | python -m json.tool | head -20
curl -sf -H "Authorization: Bearer $TOKEN" "http://localhost:8000/vuln-scans/$SCAN_ID/endpoints?limit=5" | python -m json.tool | head -20
curl -sf -H "Authorization: Bearer $TOKEN" "http://localhost:8000/vuln-scans/$SCAN_ID/tls" | python -m json.tool | head -20
curl -sf -H "Authorization: Bearer $TOKEN" "http://localhost:8000/vuln-scans/$SCAN_ID/hvts" | python -m json.tool | head -20
curl -sf -H "Authorization: Bearer $TOKEN" "http://localhost:8000/vuln-scans/$SCAN_ID/triage" | python -m json.tool | head -20
curl -sf -H "Authorization: Bearer $TOKEN" "http://localhost:8000/targets/$TARGET_ID/risk" | python -m json.tool | head -20

# 5. UI smoke — navigate to http://localhost:3000/vuln-scans/<id>?tab=by-service
# Verify all 9 tabs appear. Navigate to each tab. Check:
# - No JS console errors
# - Tables render for tabs with data
# - Empty state shown for tabs with no data
# - Vulnerabilities tab shows risk_score column + KEV-only/HVT-only buttons
# - Overview shows HVT count card if HVT signals exist
# - Endpoints tab links to /vuln-scans/<id>/endpoints/<ep_id>
# Navigate to /targets/<id>/risk — severity cards + top-risk table render
```

---

## Self-Review

### Spec Coverage Check

| Spec requirement | Task |
|---|---|
| By Service tab | Tasks 2, 6, 9, 10 |
| By Technology tab | Tasks 2, 6, 9, 10 |
| Endpoints tab | Tasks 3, 6, 9, 10 |
| TLS tab | Tasks 3, 6, 9, 10 |
| HVTs tab | Tasks 4, 6, 9, 10 |
| Triage tab | Tasks 4, 6, 9, 10 |
| Endpoint detail page `/vuln-scans/[id]/endpoints/[endpoint_id]` | Tasks 6, 11 |
| Cross-scan rollup `/targets/[id]/risk` | Tasks 7, 12 |
| Overview: HVT count + exposure cards + top-risk vulns | Tasks 5, 10 |
| Vulnerabilities: default sort `risk_score DESC` | Task 5 |
| Vulnerabilities: KEV-only + HVT-only filters | Tasks 5, 6, 10 |
| Vulnerabilities: risk_score + epss columns | Tasks 1, 5, 10 |

### Placeholder Scan

No TBDs or "similar to" shortcuts. All code blocks are complete.

### Type Consistency

- `VulnRow.epss` and `VulnRow.risk_score` added in Task 5, passed to `VulnOut` in Task 6 ✓
- `VulnOverview.hvt_count` + `public_service_count` + `top_risk_vulns` added in Task 1, populated in Task 5 ✓
- `ByServiceRow.severities` is `dict` (Python) / `Record<string, number>` (TS) — consistent ✓
- `build_tls_view` returns `cert_not_after` as `datetime` — serialized by FastAPI as ISO string, read as `string | null` in TS ✓
- `_get_vuln_scan` in `vuln_scans.py` returns `(scan, domain)` tuple — Task 6 uses `scan, _ = await _get_vuln_scan(...)` for endpoint detail ✓
