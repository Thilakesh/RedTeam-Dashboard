"""correlator — diff against prior vuln scan and mark fixed vulns.

Runs after all detection stages complete. Looks up the previous completed
vuln scan against the same target. Any vulnerability that had a run-match
row in the prior scan but not in the current scan is treated as
"fixed_in_this_run":

  - inserts a VulnRunMatch(current_scan_id, vuln_id, state="fixed_in_this_run")
  - sets Vulnerability.status = "fixed"

The stage emits no VulnRecords; it writes directly to the DB. This is a
documented exception to the "adapters never touch DB" rule, same pattern as
RiskPrioritizerStage in recon.
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

log = logging.getLogger(__name__)


class CorrelatorStage:
    name = "correlator"
    source_tool = "correlator"
    depends_on = [
        "cpe_matcher",
        "panel_detector",
        "nuclei_safe",
        "testssl",
        "nmap_nse_vuln",
        "default_creds_matcher",
        "katana",
    ]
    weight = 5
    optional = True
    intrusive_required = False

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        async with SessionLocal() as db:
            # Prior completed vuln scan against the same target, before this one.
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
            if prior_scan_id is None:
                return []

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
            if not fixed_ids:
                return []

            # Mark VulnRunMatch rows for the current scan
            rows = [
                {"scan_id": ctx.scan_id, "vulnerability_id": vid, "state": "fixed_in_this_run"}
                for vid in fixed_ids
            ]
            stmt = insert(VulnRunMatch).values(rows)
            stmt = stmt.on_conflict_do_update(
                index_elements=["scan_id", "vulnerability_id"],
                set_={"state": stmt.excluded.state},
            )
            await db.execute(stmt)

            # Flip Vulnerability.status to fixed for currently-open ones.
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
            log.info("correlator: marked %d vulns fixed_in_this_run", len(fixed_ids))
        return []
