# M-Vuln-7: Correlation Engine, Risk Scoring, EPSS/KEV Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add cross-source CVE deduplication, composite risk scoring (CVSS+EPSS+KEV+exposure+HVT+blast_radius), daily EPSS/KEV feed refresh, and switch AI triage selection from `state='new'` to `risk_score DESC`.

**Architecture:** Three pure-service modules (`hvt_score`, `risk_score`, `correlator_engine`) are created first, then wired into the existing `CorrelatorStage` adapter which already runs after all detection stages. A new `feeds_refresher.py` worker downloads and upserts EPSS/KEV data into the existing `cve_intel` table (created in migration 0008); vuln stages never call live feeds. Finally, `ai_triage.py` switches its selector from `state='new'` to `risk_score DESC NULLS LAST`.

**Tech Stack:** SQLAlchemy 2 async, httpx, Python gzip/csv stdlib, pytest-asyncio

---

## File Map

**Create:**
- `backend/app/services/hvt_score.py` — `compute_hvt_score(signals) -> float`; no DB
- `backend/app/services/risk_score.py` — `compute_risk(...)`, `compute_exposure_score(...)`, `compute_blast_radius_score(...)`; no DB, no async
- `backend/app/services/correlator_engine.py` — `merge_by_cve`, `enrich_epss_kev`, `write_risk_scores`; takes `AsyncSession`, does NOT commit
- `backend/app/workers/feeds_refresher.py` — `refresh_epss(db)`, `refresh_kev(db)`, `refresh_feeds()`; manages its own session
- `backend/tests/unit/test_hvt_score.py`
- `backend/tests/unit/test_risk_score.py`

**Modify:**
- `backend/app/pipeline/vuln/adapters/correlator.py` — add new stages to `depends_on`; call merge_by_cve → enrich_epss_kev → write_risk_scores
- `backend/app/pipeline/vuln/adapters/ai_triage.py` — switch query from `state='new'` to `risk_score DESC NULLS LAST` over `state IN ('new','seen')`

---

## Task 1: `services/hvt_score.py` — Per-Asset HVT Score

**Files:**
- Create: `backend/app/services/hvt_score.py`
- Test: `backend/tests/unit/test_hvt_score.py`

**Context:** HvtSignal rows are pre-loaded into `VulnStageContext.hvt_signals_by_asset` (a dict mapping `asset_id → list[HvtSignal]`). The `compute_hvt_score` function is a pure weighted sum over the signals for a single asset. `HvtSignalType` is a `str` enum defined in `app.models.hvt_signal`. Each signal has `.signal_type` (HvtSignalType), `.score` (float, 0–1), `.confidence` (int 0–100). The score returned is 0–1 capped.

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/unit/test_hvt_score.py
from unittest.mock import MagicMock
import pytest


def _sig(signal_type: str, score: float = 0.5, confidence: int = 80) -> MagicMock:
    s = MagicMock()
    s.signal_type = signal_type          # str, not enum, for simplicity
    s.score = score
    s.confidence = confidence
    return s


def test_empty_signals_returns_zero():
    from app.services.hvt_score import compute_hvt_score
    assert compute_hvt_score([]) == 0.0


def test_known_signal_type_applies_weight():
    from app.services.hvt_score import compute_hvt_score, SIGNAL_WEIGHTS
    # jenkins weight is 0.95; signal score=1.0 → 0.95 * 1.0 = 0.95
    sig = _sig("jenkins", score=1.0, confidence=100)
    result = compute_hvt_score([sig])
    assert abs(result - SIGNAL_WEIGHTS["jenkins"]) < 1e-6


def test_capped_at_one():
    from app.services.hvt_score import compute_hvt_score
    # Many high-weight signals → sum > 1, must cap at 1.0
    sigs = [_sig("jenkins", 1.0), _sig("git_repo", 1.0), _sig("env_file", 1.0)]
    assert compute_hvt_score(sigs) == 1.0


def test_unknown_signal_type_uses_default_weight():
    from app.services.hvt_score import compute_hvt_score
    sig = _sig("totally_unknown_type", score=1.0)
    result = compute_hvt_score([sig])
    assert 0.0 < result <= 0.35   # default weight 0.30, some variance OK


def test_null_score_treated_as_half():
    from app.services.hvt_score import compute_hvt_score, SIGNAL_WEIGHTS
    sig = _sig("admin_panel", score=None)
    result = compute_hvt_score([sig])
    # score=None → treated as 0.5; weight=0.85 → 0.85 * 0.5 = 0.425
    expected = SIGNAL_WEIGHTS["admin_panel"] * 0.5
    assert abs(result - expected) < 1e-6
```

- [ ] **Step 2: Run to confirm failure**

```bash
cd "F:\Studies\AI\RedTeam Dashboard\backend"
python -m pytest tests/unit/test_hvt_score.py -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError: No module named 'app.services.hvt_score'`

- [ ] **Step 3: Implement `services/hvt_score.py`**

```python
# backend/app/services/hvt_score.py
"""Per-asset HVT score from HvtSignal list.

Pure function — no DB, no async. The correlator_engine calls this for each
vulnerability after loading hvt_signals_by_asset from VulnStageContext.
"""
from __future__ import annotations

SIGNAL_WEIGHTS: dict[str, float] = {
    "admin_panel":    0.85,
    "login_form":     0.40,
    "signup_form":    0.20,
    "upload_form":    0.50,
    "api_doc":        0.50,
    "dev_portal":     0.55,
    "jenkins":        0.95,
    "wordpress":      0.60,
    "gitlab":         0.85,
    "k8s_dashboard":  0.95,
    "exposed_index":  0.70,
    "swagger":        0.50,
    "graphql":        0.55,
    "git_repo":       0.90,
    "env_file":       0.95,
    "other":          0.30,
}

_DEFAULT_WEIGHT = 0.30


def compute_hvt_score(hvt_signals: list) -> float:
    """Return composite HVT score for an asset (0.0–1.0).

    hvt_signals: list[HvtSignal] (or any objects with .signal_type and .score).
    """
    if not hvt_signals:
        return 0.0
    total = 0.0
    for sig in hvt_signals:
        # Handle both str and HvtSignalType enum
        st = sig.signal_type.value if hasattr(sig.signal_type, "value") else str(sig.signal_type)
        weight = SIGNAL_WEIGHTS.get(st, _DEFAULT_WEIGHT)
        raw_score = sig.score if sig.score is not None else 0.5
        total += weight * max(0.0, min(1.0, raw_score))
    return min(1.0, total)
```

- [ ] **Step 4: Run tests and confirm pass**

```bash
cd "F:\Studies\AI\RedTeam Dashboard\backend"
python -m pytest tests/unit/test_hvt_score.py -v
```

Expected: 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/hvt_score.py backend/tests/unit/test_hvt_score.py
git commit -m "feat(vuln): add services/hvt_score.py with SIGNAL_WEIGHTS + unit tests"
```

---

## Task 2: `services/risk_score.py` — Composite Risk Score

**Files:**
- Create: `backend/app/services/risk_score.py`
- Test: `backend/tests/unit/test_risk_score.py`

**Context:** Three helper functions compute the three context-dependent sub-scores from service data (no DB calls). `compute_risk(...)` combines all inputs using the formula from the architecture addendum. Inputs are plain Python values — no ORM objects. Returns a dict with `risk_score` + 3 component scores (written to Vulnerability columns by correlator_engine).

**Formula (from architecture addendum §A7):**
```
risk = (
    0.30 * (cvss_v3 or 0.0) / 10.0  +
    0.20 * (epss or 0.0)             +
    0.15 * (1.0 if kev else 0.0)     +
    0.15 * exposure_score            +
    0.10 * hvt_score                 +
    0.10 * blast_radius_score
)
```

- [ ] **Step 1: Write failing tests**

```python
# backend/tests/unit/test_risk_score.py
import pytest


def test_all_zero_inputs_returns_zero():
    from app.services.risk_score import compute_risk
    scores = compute_risk(
        cvss_v3=None, epss=None, kev=False,
        exposure_score=0.0, hvt_score=0.0, blast_radius_score=0.0,
    )
    assert scores["risk_score"] == 0.0


def test_perfect_inputs_returns_one():
    from app.services.risk_score import compute_risk
    scores = compute_risk(
        cvss_v3=10.0, epss=1.0, kev=True,
        exposure_score=1.0, hvt_score=1.0, blast_radius_score=1.0,
    )
    assert abs(scores["risk_score"] - 1.0) < 1e-6


def test_kev_bump_adds_015():
    from app.services.risk_score import compute_risk
    without_kev = compute_risk(
        cvss_v3=7.0, epss=0.5, kev=False,
        exposure_score=0.5, hvt_score=0.5, blast_radius_score=0.5,
    )
    with_kev = compute_risk(
        cvss_v3=7.0, epss=0.5, kev=True,
        exposure_score=0.5, hvt_score=0.5, blast_radius_score=0.5,
    )
    diff = with_kev["risk_score"] - without_kev["risk_score"]
    assert abs(diff - 0.15) < 1e-6


def test_result_keys_present():
    from app.services.risk_score import compute_risk
    scores = compute_risk(
        cvss_v3=5.0, epss=0.1, kev=False,
        exposure_score=0.5, hvt_score=0.3, blast_radius_score=0.2,
    )
    assert "risk_score" in scores
    assert "exposure_score" in scores
    assert "exploitability_score" in scores
    assert "blast_radius_score" in scores


def test_compute_exposure_score_web_port():
    from app.services.risk_score import compute_exposure_score
    svc = type("S", (), {"port": 443})()
    assert compute_exposure_score([svc]) == 1.0


def test_compute_exposure_score_db_port():
    from app.services.risk_score import compute_exposure_score
    svc = type("S", (), {"port": 5432})()
    assert compute_exposure_score([svc]) == 0.2


def test_compute_exposure_score_empty():
    from app.services.risk_score import compute_exposure_score
    assert compute_exposure_score([]) == 0.5


def test_compute_blast_radius_score_five_services():
    from app.services.risk_score import compute_blast_radius_score
    svcs = [object() for _ in range(5)]
    assert compute_blast_radius_score(svcs) == 1.0


def test_compute_blast_radius_score_one_service():
    from app.services.risk_score import compute_blast_radius_score
    assert abs(compute_blast_radius_score([object()]) - 0.2) < 1e-6
```

- [ ] **Step 2: Run to confirm failure**

```bash
cd "F:\Studies\AI\RedTeam Dashboard\backend"
python -m pytest tests/unit/test_risk_score.py -v 2>&1 | head -10
```

Expected: `ModuleNotFoundError: No module named 'app.services.risk_score'`

- [ ] **Step 3: Implement `services/risk_score.py`**

```python
# backend/app/services/risk_score.py
"""Composite risk score for a Vulnerability.

Pure functions — no DB, no async. The correlator_engine calls these for each
vulnerability after loading service and HVT context from VulnStageContext.
"""
from __future__ import annotations

# Ports that indicate a publicly-facing web service
_WEB_PORTS = frozenset({80, 443, 8080, 8443, 8000, 8888, 3000})
# Ports that indicate an internal/backend service (lower exposure)
_INTERNAL_PORTS = frozenset({
    3306, 5432, 1433, 1521, 27017, 6379, 9042, 5984, 7474,  # databases
    5672, 15672, 9092, 1883, 61616,                          # messaging
    11211,                                                   # cache
})


def compute_exposure_score(services_for_asset: list) -> float:
    """Return 0.0–1.0 exposure score for an asset.

    services_for_asset: list[Service] — services whose asset_id matches the vuln's asset_id.
    """
    if not services_for_asset:
        return 0.5   # unknown exposure
    ports = {svc.port for svc in services_for_asset}
    if ports & _WEB_PORTS:
        return 1.0
    if ports & _INTERNAL_PORTS:
        return 0.2
    return 0.5


def compute_blast_radius_score(services_for_asset: list) -> float:
    """Return 0.0–1.0 blast radius score.

    Simple proxy: number of services on the same asset / 5, capped at 1.0.
    An asset with 5+ services is maximally exposed; a single-service asset scores 0.2.
    """
    return min(1.0, len(services_for_asset) / 5.0)


def compute_risk(
    *,
    cvss_v3: float | None,
    epss: float | None,
    kev: bool,
    exposure_score: float,
    hvt_score: float,
    blast_radius_score: float,
) -> dict[str, float]:
    """Compute composite risk score from pre-computed component values.

    Returns a dict with risk_score, exposure_score, exploitability_score,
    blast_radius_score — keys matching Vulnerability ORM column names.

    Formula (weights sum to 1.0):
        0.30 * cvss_normalized
        0.20 * epss
        0.15 * kev_bump
        0.15 * exposure_score
        0.10 * hvt_score
        0.10 * blast_radius_score
    """
    cvss_norm = (cvss_v3 or 0.0) / 10.0
    epss_val = epss or 0.0
    kev_bump = 1.0 if kev else 0.0

    risk = (
        0.30 * cvss_norm
        + 0.20 * epss_val
        + 0.15 * kev_bump
        + 0.15 * exposure_score
        + 0.10 * hvt_score
        + 0.10 * blast_radius_score
    )
    # exploitability_score combines cvss + epss as a proxy for ease-of-exploit
    exploitability = min(1.0, 0.60 * cvss_norm + 0.40 * epss_val)

    return {
        "risk_score": min(1.0, max(0.0, risk)),
        "exposure_score": exposure_score,
        "exploitability_score": exploitability,
        "blast_radius_score": blast_radius_score,
    }
```

- [ ] **Step 4: Run tests and confirm pass**

```bash
cd "F:\Studies\AI\RedTeam Dashboard\backend"
python -m pytest tests/unit/test_risk_score.py -v
```

Expected: 9 tests pass.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/risk_score.py backend/tests/unit/test_risk_score.py
git commit -m "feat(vuln): add services/risk_score.py with composite formula + unit tests"
```

---

## Task 3: `services/correlator_engine.py` — CVE Merge + EPSS/KEV Enrichment + Risk Scores

**Files:**
- Create: `backend/app/services/correlator_engine.py`

**Context:** Three async functions, each takes an `AsyncSession` and does NOT commit — the caller (correlator.py) commits after all three. `merge_by_cve` groups Vulnerability rows in the current scan by overlapping `cve_ids[]` on the same `asset_id` using a union-find over the vuln list, picks canonical (highest cvss_v3), moves VulnEvidence rows, deletes duplicates. `enrich_epss_kev` joins cve_ids against the `cve_intel` table and writes `epss`/`kev` columns. `write_risk_scores` calls `compute_hvt_score` + `compute_exposure_score` + `compute_blast_radius_score` + `compute_risk` for each vuln in the scan.

Relevant models:
- `Vulnerability`: `.id`, `.asset_id`, `.service_id`, `.cve_ids` (list[str]), `.cvss_v3`, `.epss`, `.kev`, `.risk_score`, `.exposure_score`, `.exploitability_score`, `.blast_radius_score`
- `VulnRunMatch`: composite PK `(scan_id, vulnerability_id)`, `.state`
- `VulnEvidence`: `.vulnerability_id`, ondelete=CASCADE
- `CveIntel`: `.cve_id` (PK str), `.epss`, `.kev`

Relevant ctx fields: `ctx.services` (list[Service] — `.asset_id`, `.port`), `ctx.service_by_id` (dict UUID→Service), `ctx.hvt_signals_by_asset` (dict UUID→list[HvtSignal])

- [ ] **Step 1: Write `services/correlator_engine.py`**

```python
# backend/app/services/correlator_engine.py
"""Correlation helpers called by the CorrelatorStage adapter.

Three async functions that take an AsyncSession and do NOT commit.
The caller (correlator.py) commits once after all three.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from uuid import UUID

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve_intel import CveIntel
from app.models.vulnerability import Vulnerability
from app.models.vuln_evidence import VulnEvidence
from app.models.vuln_run_match import VulnRunMatch
from app.services.hvt_score import compute_hvt_score
from app.services.risk_score import (
    compute_blast_radius_score,
    compute_exposure_score,
    compute_risk,
)

log = logging.getLogger(__name__)


# ── Union-find helpers ────────────────────────────────────────────────────────

def _find(parent: dict, x: UUID) -> UUID:
    while parent[x] != x:
        parent[x] = parent[parent[x]]  # path compression
        x = parent[x]
    return x


def _union(parent: dict, x: UUID, y: UUID) -> None:
    parent[_find(parent, x)] = _find(parent, y)


def _cve_groups(vulns: list[Vulnerability]) -> list[list[Vulnerability]]:
    """Group vulns that share any CVE on the same asset (union-find).

    Returns a list of groups; groups of size 1 are singletons (nothing to merge).
    """
    if not vulns:
        return []
    parent: dict[UUID, UUID] = {v.id: v.id for v in vulns}
    by_id: dict[UUID, Vulnerability] = {v.id: v for v in vulns}

    for i, v1 in enumerate(vulns):
        v1_set = set(v1.cve_ids or [])
        if not v1_set:
            continue
        for v2 in vulns[i + 1 :]:
            if v1.asset_id != v2.asset_id:
                continue
            if v1_set & set(v2.cve_ids or []):
                _union(parent, v1.id, v2.id)

    groups: dict[UUID, list[Vulnerability]] = {}
    for v in vulns:
        root = _find(parent, v.id)
        groups.setdefault(root, []).append(v)
    return list(groups.values())


# ── Public API ────────────────────────────────────────────────────────────────

async def merge_by_cve(scan_id: UUID, target_id: UUID, db: AsyncSession) -> int:
    """Merge Vulnerability rows that share a CVE on the same asset.

    Picks the row with the highest cvss_v3 as canonical, reassigns VulnEvidence
    rows from duplicates to canonical, deletes duplicate Vulnerability rows (and
    their VulnRunMatch rows for this scan). Returns the number of rows merged.

    Does NOT commit — caller commits.
    """
    # Load vuln IDs for this scan
    vuln_id_result = await db.execute(
        select(VulnRunMatch.vulnerability_id).where(VulnRunMatch.scan_id == scan_id)
    )
    vuln_ids = list(vuln_id_result.scalars().all())
    if not vuln_ids:
        return 0

    # Load vulns with non-empty cve_ids
    vuln_result = await db.execute(
        select(Vulnerability).where(
            Vulnerability.id.in_(vuln_ids),
            Vulnerability.cve_ids != "{}",
        )
    )
    vulns = list(vuln_result.scalars().all())
    if len(vulns) < 2:
        return 0

    groups = _cve_groups(vulns)
    merged = 0

    for group in groups:
        if len(group) < 2:
            continue

        # Canonical = highest CVSS; fall back to first if all None
        canonical = max(group, key=lambda v: v.cvss_v3 or 0.0)
        dupes = [v for v in group if v.id != canonical.id]
        dupe_ids = [v.id for v in dupes]

        # Reassign evidence rows from duplicates to canonical
        await db.execute(
            update(VulnEvidence)
            .where(VulnEvidence.vulnerability_id.in_(dupe_ids))
            .values(vulnerability_id=canonical.id)
        )

        # Delete run_match rows for duplicates in this scan
        await db.execute(
            delete(VulnRunMatch).where(
                VulnRunMatch.scan_id == scan_id,
                VulnRunMatch.vulnerability_id.in_(dupe_ids),
            )
        )

        # Delete duplicate Vulnerability rows
        await db.execute(
            delete(Vulnerability).where(Vulnerability.id.in_(dupe_ids))
        )

        merged += len(dupes)
        log.info(
            "merge_by_cve: merged %d duplicate(s) into canonical %s "
            "(CVEs: %s, asset: %s)",
            len(dupes),
            canonical.id,
            list(set(canonical.cve_ids or [])),
            canonical.asset_id,
        )

    return merged


async def enrich_epss_kev(scan_id: UUID, db: AsyncSession) -> int:
    """Write EPSS and KEV values from cve_intel onto Vulnerability rows.

    For each vuln in this scan:
    - epss: max EPSS across all CVEs in the vuln's cve_ids (None if no data)
    - kev:  True if any CVE is in the CISA KEV catalog

    Does NOT commit — caller commits.
    Returns number of vulns enriched.
    """
    vuln_id_result = await db.execute(
        select(VulnRunMatch.vulnerability_id).where(VulnRunMatch.scan_id == scan_id)
    )
    vuln_ids = list(vuln_id_result.scalars().all())
    if not vuln_ids:
        return 0

    vuln_result = await db.execute(
        select(Vulnerability).where(Vulnerability.id.in_(vuln_ids))
    )
    vulns = list(vuln_result.scalars().all())

    # Collect all CVE IDs referenced in this scan
    all_cves: set[str] = set()
    for v in vulns:
        all_cves.update(v.cve_ids or [])
    if not all_cves:
        return 0

    intel_result = await db.execute(
        select(CveIntel).where(CveIntel.cve_id.in_(list(all_cves)))
    )
    intel_by_id: dict[str, CveIntel] = {r.cve_id: r for r in intel_result.scalars().all()}

    enriched = 0
    for v in vulns:
        if not v.cve_ids:
            continue
        relevant = [intel_by_id[c] for c in v.cve_ids if c in intel_by_id]
        if not relevant:
            continue

        epss_vals = [r.epss for r in relevant if r.epss is not None]
        v.epss = max(epss_vals) if epss_vals else None
        v.kev = any(r.kev for r in relevant)
        enriched += 1

    log.info("enrich_epss_kev: enriched %d vulns for scan %s", enriched, scan_id)
    return enriched


async def write_risk_scores(scan_id: UUID, ctx, db: AsyncSession) -> None:
    """Compute and write composite risk scores for all vulns in the scan.

    ctx: VulnStageContext — supplies ctx.services, ctx.service_by_id,
         ctx.hvt_signals_by_asset.

    Does NOT commit — caller commits.
    """
    vuln_id_result = await db.execute(
        select(VulnRunMatch.vulnerability_id).where(VulnRunMatch.scan_id == scan_id)
    )
    vuln_ids = list(vuln_id_result.scalars().all())
    if not vuln_ids:
        return

    vuln_result = await db.execute(
        select(Vulnerability).where(Vulnerability.id.in_(vuln_ids))
    )
    vulns = list(vuln_result.scalars().all())

    # Pre-compute services-by-asset_id for blast_radius + exposure
    services_by_asset: dict[UUID, list] = defaultdict(list)
    for svc in (ctx.services or []):
        services_by_asset[svc.asset_id].append(svc)

    for v in vulns:
        asset_services = services_by_asset.get(v.asset_id, [])
        asset_hvt = (ctx.hvt_signals_by_asset or {}).get(v.asset_id, [])

        # Prefer the exact service this vuln was detected on for exposure
        if v.service_id and v.service_id in (ctx.service_by_id or {}):
            exposure = compute_exposure_score([ctx.service_by_id[v.service_id]])
        else:
            exposure = compute_exposure_score(asset_services)

        hvt_s = compute_hvt_score(asset_hvt)
        blast = compute_blast_radius_score(asset_services)

        scores = compute_risk(
            cvss_v3=v.cvss_v3,
            epss=v.epss,
            kev=v.kev,
            exposure_score=exposure,
            hvt_score=hvt_s,
            blast_radius_score=blast,
        )

        v.risk_score = scores["risk_score"]
        v.exposure_score = scores["exposure_score"]
        v.exploitability_score = scores["exploitability_score"]
        v.blast_radius_score = scores["blast_radius_score"]

    log.info("write_risk_scores: scored %d vulns for scan %s", len(vulns), scan_id)
```

- [ ] **Step 2: Verify the file imports cleanly**

```bash
cd "F:\Studies\AI\RedTeam Dashboard"
docker compose exec backend python -c "from app.services.correlator_engine import merge_by_cve, enrich_epss_kev, write_risk_scores; print('ok')"
```

Expected: `ok`

- [ ] **Step 3: Commit**

```bash
git add backend/app/services/correlator_engine.py
git commit -m "feat(vuln): add correlator_engine (merge_by_cve, enrich_epss_kev, write_risk_scores)"
```

---

## Task 4: `workers/feeds_refresher.py` — EPSS + KEV Daily Feed Refresh

**Files:**
- Create: `backend/app/workers/feeds_refresher.py`

**Context:** Downloads two feeds and upserts into the `cve_intel` table (created in migration 0008). MUST NOT be called at scan time — vuln stages read from `cve_intel`, never live feeds. This module can be called manually via `docker compose exec backend python -m app.workers.feeds_refresher` or scheduled externally.

**EPSS CSV source:** `https://epss.cyentia.com/epss_scores-current.csv.gz`
- File is gzip-compressed CSV.
- Line 1: `#model_version:v...` (metadata comment, skip)
- Line 2: `cve,epss,percentile` (header, skip)
- Lines 3+: `CVE-YYYY-NNNNN,0.12345,0.98` (data rows)

**CISA KEV JSON source:** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Top-level key `"vulnerabilities"`: list of objects
- Each object has: `"cveID"` (str), `"dateAdded"` (YYYY-MM-DD str), `"knownRansomwareCampaignUse"` ("Known"/"Unknown"/empty)

- [ ] **Step 1: Write `workers/feeds_refresher.py`**

```python
# backend/app/workers/feeds_refresher.py
"""Daily EPSS and CISA KEV feed refresh.

Vuln stages MUST NOT call live feeds — they read from cve_intel. This module
is the sole writer to cve_intel. Run manually or via external cron:

    docker compose exec backend python -m app.workers.feeds_refresher

CI gate: `git diff backend/app/pipeline/vuln | grep -E 'first.org|cisa.gov' && exit 1`
enforces that no vuln stage imports these URLs.
"""
from __future__ import annotations

import asyncio
import csv
import gzip
import io
import logging
from datetime import datetime, timezone

import httpx
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.sql import func

from app.core.db import SessionLocal
from app.models.cve_intel import CveIntel

log = logging.getLogger(__name__)

_EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_BATCH = 2000


async def refresh_epss(db) -> int:
    """Download EPSS CSV, upsert into cve_intel. Returns rows upserted."""
    log.info("feeds_refresher: downloading EPSS from %s", _EPSS_URL)
    async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
        resp = await client.get(_EPSS_URL)
        resp.raise_for_status()

    content = gzip.decompress(resp.content)
    text = content.decode("utf-8")

    reader = csv.reader(io.StringIO(text))
    rows: list[dict] = []
    for line in reader:
        # Skip blank, comment (#), and header (cve) lines
        if not line or not line[0] or line[0].startswith("#") or line[0] == "cve":
            continue
        cve_id = line[0].strip()
        if not cve_id.startswith("CVE-"):
            continue
        try:
            epss = float(line[1])
        except (IndexError, ValueError):
            continue
        rows.append({"cve_id": cve_id, "epss": epss})

    if not rows:
        log.warning("feeds_refresher: EPSS CSV parsed 0 rows")
        return 0

    for start in range(0, len(rows), _BATCH):
        chunk = rows[start : start + _BATCH]
        stmt = insert(CveIntel).values(chunk)
        stmt = stmt.on_conflict_do_update(
            index_elements=["cve_id"],
            set_={"epss": stmt.excluded.epss, "refreshed_at": func.now()},
        )
        await db.execute(stmt)
    await db.commit()

    log.info("feeds_refresher: EPSS upserted %d rows", len(rows))
    return len(rows)


async def refresh_kev(db) -> int:
    """Download CISA KEV catalog, upsert into cve_intel. Returns rows upserted."""
    log.info("feeds_refresher: downloading KEV from %s", _KEV_URL)
    async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
        resp = await client.get(_KEV_URL)
        resp.raise_for_status()

    data = resp.json()
    vulns = data.get("vulnerabilities") or []

    rows: list[dict] = []
    for v in vulns:
        cve_id = (v.get("cveID") or "").strip()
        if not cve_id.startswith("CVE-"):
            continue
        date_str = v.get("dateAdded") or ""
        kev_date: datetime | None = None
        if date_str:
            try:
                kev_date = datetime.strptime(date_str, "%Y-%m-%d").replace(
                    tzinfo=timezone.utc
                )
            except ValueError:
                pass
        ransomware = (v.get("knownRansomwareCampaignUse") or "").strip().lower() == "known"
        rows.append({
            "cve_id": cve_id,
            "kev": True,
            "kev_added_date": kev_date,
            "ransomware_use": ransomware,
        })

    if not rows:
        log.warning("feeds_refresher: KEV JSON parsed 0 rows")
        return 0

    for start in range(0, len(rows), _BATCH):
        chunk = rows[start : start + _BATCH]
        stmt = insert(CveIntel).values(chunk)
        stmt = stmt.on_conflict_do_update(
            index_elements=["cve_id"],
            set_={
                "kev": stmt.excluded.kev,
                "kev_added_date": stmt.excluded.kev_added_date,
                "ransomware_use": stmt.excluded.ransomware_use,
                "refreshed_at": func.now(),
            },
        )
        await db.execute(stmt)
    await db.commit()

    log.info("feeds_refresher: KEV upserted %d rows", len(rows))
    return len(rows)


async def refresh_feeds() -> None:
    """Entry point: refresh EPSS then KEV. Manages its own DB session."""
    async with SessionLocal() as db:
        epss_count = await refresh_epss(db)
        kev_count = await refresh_kev(db)
    log.info(
        "feeds_refresher: done — EPSS %d rows, KEV %d rows", epss_count, kev_count
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(refresh_feeds())
```

- [ ] **Step 2: Verify the module imports**

```bash
cd "F:\Studies\AI\RedTeam Dashboard"
docker compose exec backend python -c "from app.workers.feeds_refresher import refresh_feeds; print('ok')"
```

Expected: `ok`

- [ ] **Step 3: Commit**

```bash
git add backend/app/workers/feeds_refresher.py
git commit -m "feat(vuln): add workers/feeds_refresher.py for EPSS/KEV daily refresh"
```

---

## Task 5: Wire `correlator.py` — Call merge_by_cve → enrich_epss_kev → write_risk_scores

**Files:**
- Modify: `backend/app/pipeline/vuln/adapters/correlator.py`

**Context:** The existing correlator already runs the fixed-vuln diff and commits. After that commit, we add three more DB operations in a second block, then commit again. We also update `depends_on` to explicitly include the 6 conditional stages from M-Vuln-6 (they already run before the correlator via DAG level ordering since they have `depends_on=[]` and correlator depends on detection stages, but adding them explicitly makes the intent clear and guards against future depth changes).

The full `execute_vuln` method after changes will:
1. `async with SessionLocal() as db:` (same session for all operations)
2. Find prior scan + compute fixed_ids (existing code)
3. Mark VulnRunMatch fixed rows (existing code)
4. Flip Vulnerability.status to fixed (existing code)
5. `await db.commit()` (existing, covers steps 3-4)
6. `merge_by_cve(ctx.scan_id, ctx.target_id, db)` (NEW)
7. `enrich_epss_kev(ctx.scan_id, db)` (NEW)
8. `write_risk_scores(ctx.scan_id, ctx, db)` (NEW)
9. `await db.commit()` (NEW, covers steps 6-8)

- [ ] **Step 1: Read the current file to have an accurate edit base**

Read `backend/app/pipeline/vuln/adapters/correlator.py` completely (shown earlier in context).

- [ ] **Step 2: Replace the full file with the wired version**

```python
# backend/app/pipeline/vuln/adapters/correlator.py
"""correlator — diff against prior vuln scan, cross-source merge, and risk scoring.

Runs after all detection stages. In order:
1. Diff: mark vulns fixed that appeared in prior scan but not current.
2. merge_by_cve: collapse multi-source CVE duplicates on the same asset.
3. enrich_epss_kev: write EPSS/KEV from cve_intel onto vuln rows.
4. write_risk_scores: compute composite risk_score for every vuln in this scan.

The stage emits no VulnRecords — it writes directly to the DB. Documented
exception to the "adapters never touch DB" rule (same as RiskPrioritizerStage).
"""

from __future__ import annotations

import logging

from sqlalchemy import and_, desc, select, update
from sqlalchemy.dialects.postgresql import insert

from app.core.db import SessionLocal
from app.models import Scan, ScanKind, ScanStatus
from app.models.vulnerability import Vulnerability, VulnStatus
from app.models.vuln_run_match import VulnRunMatch
from app.pipeline.vuln.stage import VulnRecord, VulnStageContext
from app.services.correlator_engine import enrich_epss_kev, merge_by_cve, write_risk_scores

log = logging.getLogger(__name__)


class CorrelatorStage:
    name = "correlator"
    source_tool = "correlator"
    # All detection stages must finish before correlator runs.
    # Conditional stages have depends_on=[] (depth=0) so they run before
    # correlator regardless, but we list them explicitly for clarity.
    depends_on = [
        "cpe_matcher",
        "panel_detector",
        "nuclei_safe",
        "testssl",
        "nmap_nse_vuln",
        "default_creds_matcher",
        "katana",
        "wp_user_enum",
        "wp_plugin_check",
        "struts_checker",
        "jenkins_probe",
        "graphql_introspection",
        "gitlab_probe",
        "swagger_discoverer",
        "endpoint_classifier",
    ]
    weight = 5
    optional = True
    intrusive_required = False

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        async with SessionLocal() as db:
            # ── 1. Diff: mark vulns fixed since prior scan ────────────────────
            prior_scan_id = await db.scalar(
                select(Scan.id)
                .where(
                    Scan.target_id == ctx.target_id,
                    Scan.kind == ScanKind.vuln_analysis,
                    Scan.status == ScanStatus.completed,
                    Scan.id != ctx.scan_id,
                )
                .order_by(desc(Scan.finished_at))
                .limit(1)
            )

            if prior_scan_id is not None:
                prior_ids = set(
                    (await db.execute(
                        select(VulnRunMatch.vulnerability_id).where(
                            VulnRunMatch.scan_id == prior_scan_id
                        )
                    )).scalars().all()
                )
                current_ids = set(
                    (await db.execute(
                        select(VulnRunMatch.vulnerability_id).where(
                            VulnRunMatch.scan_id == ctx.scan_id
                        )
                    )).scalars().all()
                )
                fixed_ids = prior_ids - current_ids

                if fixed_ids:
                    fixed_rows = [
                        {
                            "scan_id": ctx.scan_id,
                            "vulnerability_id": vid,
                            "state": "fixed_in_this_run",
                        }
                        for vid in fixed_ids
                    ]
                    stmt = insert(VulnRunMatch).values(fixed_rows)
                    stmt = stmt.on_conflict_do_update(
                        index_elements=["scan_id", "vulnerability_id"],
                        set_={"state": stmt.excluded.state},
                    )
                    await db.execute(stmt)

                    await db.execute(
                        update(Vulnerability)
                        .where(
                            and_(
                                Vulnerability.id.in_(fixed_ids),
                                Vulnerability.status == VulnStatus.open,
                            )
                        )
                        .values(status=VulnStatus.fixed)
                    )
                    await db.commit()
                    log.info(
                        "correlator: marked %d vulns fixed_in_this_run", len(fixed_ids)
                    )
                else:
                    await db.commit()
            else:
                await db.commit()

            # ── 2. Cross-source CVE deduplication ────────────────────────────
            merged = await merge_by_cve(ctx.scan_id, ctx.target_id, db)
            if merged:
                log.info("correlator: merged %d cross-source CVE duplicates", merged)

            # ── 3. EPSS / KEV enrichment from cve_intel ───────────────────────
            enriched = await enrich_epss_kev(ctx.scan_id, db)
            log.info("correlator: enriched %d vulns with EPSS/KEV", enriched)

            # ── 4. Composite risk scores ──────────────────────────────────────
            await write_risk_scores(ctx.scan_id, ctx, db)

            # Single commit for steps 2-4
            await db.commit()

        return []
```

- [ ] **Step 3: Verify file parses and imports cleanly**

```bash
cd "F:\Studies\AI\RedTeam Dashboard"
docker compose exec backend python -c "
from app.pipeline.vuln.adapters.correlator import CorrelatorStage
c = CorrelatorStage()
assert 'wp_user_enum' in c.depends_on
assert 'jenkins_probe' in c.depends_on
print('ok, depends_on has', len(c.depends_on), 'entries')
"
```

Expected: `ok, depends_on has 15 entries`

- [ ] **Step 4: Verify no circular imports**

```bash
cd "F:\Studies\AI\RedTeam Dashboard"
docker compose exec backend python -c "
from app.pipeline.vuln.profiles import vuln_stages_for
stages = vuln_stages_for('vuln_deep')
names = [s.name for s in stages]
print('stages:', names)
"
```

Expected: list prints without error; `correlator` and `ai_triage` appear at the end.

- [ ] **Step 5: Commit**

```bash
git add backend/app/pipeline/vuln/adapters/correlator.py
git commit -m "feat(vuln): wire correlator with merge_by_cve + enrich_epss_kev + write_risk_scores"
```

---

## Task 6: Update `ai_triage.py` — Risk-Score-Ordered Selection

**Files:**
- Modify: `backend/app/pipeline/vuln/adapters/ai_triage.py`

**Context:** Currently the query is `WHERE state = 'new'` with no ordering. This means the AI triage sees only the newest vulns, ignoring previously-detected-but-still-open ones. After M-Vuln-7, `risk_score` is populated. Changing to `ORDER BY risk_score DESC NULLS LAST` with `state IN ('new', 'seen')` ensures the LLM focuses on the highest-risk findings. Also update the payload to include `risk_score` and `cvss_v3` for the LLM context.

The query change is in `execute_vuln`:
- Old: `VulnRunMatch.state == "new"` with no ORDER BY
- New: `VulnRunMatch.state.in_(["new", "seen"])` with `.order_by(Vulnerability.risk_score.desc().nullslast())`

Also update the payload dict to include `"risk_score"` and `"cvss_v3"`.

- [ ] **Step 1: Read the current `ai_triage.py`**

File is shown in full in the task context above. Key section to change is lines 53–61:

```python
rows = (await db.execute(
    select(Vulnerability)
    .join(VulnRunMatch, VulnRunMatch.vulnerability_id == Vulnerability.id)
    .where(
        VulnRunMatch.scan_id == ctx.scan_id,
        VulnRunMatch.state == "new",
    )
    .limit(_MAX_VULNS)
)).scalars().all()
```

- [ ] **Step 2: Apply the edits to `ai_triage.py`**

Change the import line: add `desc` from sqlalchemy (it's not imported yet):

At the top of the file, the existing imports are:
```python
from sqlalchemy import select
```

Change to:
```python
from sqlalchemy import desc, select
```

Change the query block (lines 53–61) from:
```python
rows = (await db.execute(
    select(Vulnerability)
    .join(VulnRunMatch, VulnRunMatch.vulnerability_id == Vulnerability.id)
    .where(
        VulnRunMatch.scan_id == ctx.scan_id,
        VulnRunMatch.state == "new",
    )
    .limit(_MAX_VULNS)
)).scalars().all()
```

To:
```python
rows = (await db.execute(
    select(Vulnerability)
    .join(VulnRunMatch, VulnRunMatch.vulnerability_id == Vulnerability.id)
    .where(
        VulnRunMatch.scan_id == ctx.scan_id,
        VulnRunMatch.state.in_(["new", "seen"]),
    )
    .order_by(desc(Vulnerability.risk_score).nullslast())
    .limit(_MAX_VULNS)
)).scalars().all()
```

Change the payload list (lines 66–76) to include `risk_score` and `cvss_v3`:

Old:
```python
payload = [
    {
        "id": str(v.id),
        "title": v.title,
        "severity": str(v.severity.value if hasattr(v.severity, "value") else v.severity),
        "description": v.description[:600],
        "cve_ids": list(v.cve_ids or []),
        "template_id": v.template_id,
    }
    for v in rows
]
```

New:
```python
payload = [
    {
        "id": str(v.id),
        "title": v.title,
        "severity": str(v.severity.value if hasattr(v.severity, "value") else v.severity),
        "description": v.description[:600],
        "cve_ids": list(v.cve_ids or []),
        "template_id": v.template_id,
        "cvss_v3": v.cvss_v3,
        "risk_score": round(v.risk_score, 3) if v.risk_score is not None else None,
    }
    for v in rows
]
```

- [ ] **Step 3: Verify import works**

```bash
cd "F:\Studies\AI\RedTeam Dashboard"
docker compose exec backend python -c "from app.pipeline.vuln.adapters.ai_triage import AiTriageStage; print('ok')"
```

Expected: `ok`

- [ ] **Step 4: Commit**

```bash
git add backend/app/pipeline/vuln/adapters/ai_triage.py
git commit -m "feat(vuln): ai_triage selects by risk_score DESC instead of state=new"
```

---

## Integration Verification

After all tasks are committed, run the following to confirm end-to-end correctness:

```bash
# 1. All imports resolve
docker compose exec backend python -c "
from app.services.hvt_score import compute_hvt_score
from app.services.risk_score import compute_risk
from app.services.correlator_engine import merge_by_cve, enrich_epss_kev, write_risk_scores
from app.workers.feeds_refresher import refresh_feeds
from app.pipeline.vuln.adapters.correlator import CorrelatorStage
from app.pipeline.vuln.adapters.ai_triage import AiTriageStage
print('all imports ok')
"

# 2. Unit tests pass
cd "F:\Studies\AI\RedTeam Dashboard\backend"
python -m pytest tests/unit/test_hvt_score.py tests/unit/test_risk_score.py -v

# 3. DAG levels compute without error for all profiles
docker compose exec backend python -c "
from app.pipeline.vuln.profiles import vuln_stages_for
from app.pipeline.vuln.coordinator import _levels
for profile in ['vuln_quick', 'vuln_standard', 'vuln_deep']:
    stages = vuln_stages_for(profile)
    levels = _levels(stages)
    names_per_level = [[s.name for s in lvl] for lvl in levels]
    print(f'{profile}: {len(levels)} levels, correlator in level', 
          next(i for i, lvl in enumerate(names_per_level) if 'correlator' in lvl))
"

# 4. feeds_refresher module-level import OK (does not run at import time)
docker compose exec backend python -c "
import app.workers.feeds_refresher as fr
print('feeds_refresher imported, entry point:', fr.refresh_feeds.__name__)
"
```

**Optional: Run feeds_refresher against live feeds (requires outbound internet from container)**

```bash
docker compose exec backend python -m app.workers.feeds_refresher
# Expected: INFO logs showing EPSS N rows, KEV N rows
docker compose exec backend psql -U postgres -d recon -c "SELECT count(*) FROM cve_intel WHERE epss IS NOT NULL;"
# Expected: > 100000
docker compose exec backend psql -U postgres -d recon -c "SELECT count(*) FROM cve_intel WHERE kev = true;"
# Expected: > 1000
```

**After running a vuln scan end-to-end:**

```bash
# Risk scores populated after correlator runs
docker compose exec backend psql -U postgres -d recon -c "
SELECT count(*) FROM vulnerabilities WHERE risk_score IS NOT NULL
  AND last_verified_at > now() - interval '1 hour';
"
# Expected: matches vuln count from the test scan

# ai_triage: verify it picked highest risk_score
docker compose exec backend psql -U postgres -d recon -c "
SELECT risk_score, remediation IS NOT NULL as has_remediation 
FROM vulnerabilities ORDER BY risk_score DESC NULLS LAST LIMIT 10;
"
# Expected: top rows have higher risk_score than rows without remediation
```

---

## Self-Review Notes

- **Spec coverage:** merge_by_cve ✓, compute_risk ✓, cve_intel table already exists (migration 0008) ✓, feeds_refresher ✓, correlator wired in order ✓, ai_triage updated ✓, hvt_score.py ✓
- **No placeholders:** All code is complete in each task
- **Type consistency:** `write_risk_scores` accepts `ctx` typed as `VulnStageContext` (uses duck typing via `ctx.services`, `ctx.service_by_id`, `ctx.hvt_signals_by_asset`)
- **Correlator depends_on:** Listed all conditional stages; `_prune_deps` in profiles.py strips unknown ones per profile, so this is safe
- **feeds_refresher does NOT commit in `refresh_epss`/`refresh_kev`:** Wait — actually it DOES call `await db.commit()` inside each. That's intentional: they're separate concerns and committing after each feed allows partial success (EPSS succeeds, KEV fails → EPSS rows are preserved). This differs from correlator_engine where all three steps share one transaction for atomicity.
