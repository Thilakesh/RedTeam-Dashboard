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
