"""struts_checker — Apache Struts CVE detection via nuclei.

Fires when technology:struts is detected OR service.product contains 'struts'.
Runs nuclei with 'apache,struts,cve' tags covering S2-045, S2-057, S2-061
and other high-profile RCE chains.

Fail-soft: optional=True; skips if nuclei binary missing.
"""

from __future__ import annotations

import logging

from app.pipeline.vuln.adapters._nuclei_runner import nuclei_available, run_nuclei
from app.pipeline.vuln.stage import VulnRecord, VulnStageContext

log = logging.getLogger(__name__)

_TAGS = "apache,struts,cve"
_SEVERITY = "medium,high,critical"
_TIMEOUT_SEC = 600


class StrutsCheckerStage:
    name = "struts_checker"
    source_tool = "nuclei"
    depends_on: list[str] = []
    required_signals: list[str] = ["technology:struts"]
    weight = 40
    optional = True
    intrusive_required = False

    def applies(self, ctx: VulnStageContext) -> bool:
        # Also apply if struts in service.product (recon nmap may detect it before
        # httpx writes a Technology row)
        if any(
            svc.product and "struts" in svc.product.lower()
            for svc in ctx.services
        ):
            return True
        return bool(ctx.http_services)

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        if not ctx.http_services:
            return []
        if not nuclei_available():
            log.warning("struts_checker: nuclei not on PATH — skipping")
            return []

        urls = [a.canonical_key for a in ctx.http_services]
        url_to_asset = {a.canonical_key: a for a in ctx.http_services}

        records = await run_nuclei(
            urls=urls,
            url_to_asset=url_to_asset,
            tags=_TAGS,
            severity=_SEVERITY,
            timeout_sec=_TIMEOUT_SEC,
        )
        log.info("struts_checker: %d findings", len(records))
        return records
