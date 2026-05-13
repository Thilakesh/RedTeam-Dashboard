from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import func

from app.models.vulnerability import Vulnerability, VulnSeverity
from app.models.vuln_evidence import VulnEvidence
from app.models.vuln_run_match import VulnRunMatch

_BATCH_ROWS = 2000


async def upsert_vulns(
    db: AsyncSession,
    *,
    target_id: UUID,
    scan_id: UUID,
    stage_id: UUID,
    records: list,  # list[VulnRecord]
) -> int:
    """Upsert vulnerabilities for a target and write evidence + run-match rows.

    Returns the number of records processed.
    """
    if not records:
        return 0

    for start in range(0, len(records), _BATCH_ROWS):
        chunk = records[start : start + _BATCH_ROWS]
        rows = [
            {
                "target_id": target_id,
                "asset_id": r.asset_id,
                "service_id": r.service_id,
                "technology_id": r.technology_id,
                "canonical_key": r.canonical_key,
                "template_id": r.template_id,
                "cve_ids": r.cve_ids,
                "cwe_ids": r.cwe_ids,
                "title": r.title,
                "severity": VulnSeverity(r.severity),
                "cvss_v3": r.cvss_v3,
                "description": r.description,
                "remediation": r.remediation,
            }
            for r in chunk
        ]
        stmt = insert(Vulnerability).values(rows)
        update_set: dict = {
            "last_seen": func.now(),
            "last_verified_at": func.now(),
        }
        # Only overwrite remediation when the incoming value is non-null
        update_set["remediation"] = func.coalesce(
            stmt.excluded.remediation, Vulnerability.remediation
        )
        stmt = stmt.on_conflict_do_update(
            constraint="uq_vuln_identity",
            set_=update_set,
        )
        await db.execute(stmt)

    # Fetch vuln IDs for inserted/updated rows
    canonical_keys = [r.canonical_key for r in records]
    by_key: dict[str, UUID] = {}
    for start in range(0, len(canonical_keys), _BATCH_ROWS):
        chunk_keys = canonical_keys[start : start + _BATCH_ROWS]
        existing = await db.execute(
            select(Vulnerability.id, Vulnerability.canonical_key).where(
                Vulnerability.target_id == target_id,
                Vulnerability.canonical_key.in_(chunk_keys),
            )
        )
        for vid, ckey in existing.all():
            by_key[ckey] = vid

    # Append-only evidence rows
    evidence_rows = [
        VulnEvidence(
            vulnerability_id=by_key[r.canonical_key],
            scan_id=scan_id,
            stage_id=stage_id,
            source_tool=r.evidence.source_tool,
            request=r.evidence.request,
            response_excerpt=r.evidence.response_excerpt,
            matcher_name=r.evidence.matcher_name,
            extracted=r.evidence.extracted,
            confidence=r.evidence.confidence,
        )
        for r in records
        if r.canonical_key in by_key
    ]
    db.add_all(evidence_rows)
    await db.flush()

    # Upsert VulnRunMatch — determine new vs seen
    vuln_ids = [by_key[r.canonical_key] for r in records if r.canonical_key in by_key]
    if not vuln_ids:
        return 0

    # Find which vuln_ids have been seen in prior scans
    prior = await db.execute(
        select(VulnRunMatch.vulnerability_id).where(
            VulnRunMatch.vulnerability_id.in_(vuln_ids),
            VulnRunMatch.scan_id != scan_id,
        )
    )
    seen_before: set[UUID] = {row[0] for row in prior.all()}

    run_match_rows = [
        {
            "scan_id": scan_id,
            "vulnerability_id": vid,
            "state": "seen" if vid in seen_before else "new",
        }
        for vid in vuln_ids
    ]
    for start in range(0, len(run_match_rows), _BATCH_ROWS):
        chunk = run_match_rows[start : start + _BATCH_ROWS]
        stmt = insert(VulnRunMatch).values(chunk)
        stmt = stmt.on_conflict_do_update(
            index_elements=["scan_id", "vulnerability_id"],
            set_={"state": stmt.excluded.state},
        )
        await db.execute(stmt)

    return len(records)
