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
