"""wp_plugin_check — WordPress plugin CVE scanner.

Fires when technology:wordpress is detected. Runs nuclei with 'wordpress,cve'
tags so only WordPress-specific CVE templates fire. Complements wp_user_enum
(which is a custom HTTP check) by catching plugin/theme CVEs and misconfigs.

Fail-soft: optional=True; skips if nuclei binary missing.
"""

from __future__ import annotations

import logging

from app.pipeline.vuln.adapters._nuclei_runner import nuclei_available, run_nuclei
from app.pipeline.vuln.stage import VulnRecord, VulnStageContext

log = logging.getLogger(__name__)

_TAGS = "wordpress,cve"
_SEVERITY = "low,medium,high,critical"
_TIMEOUT_SEC = 600


class WpPluginCheckStage:
    name = "wp_plugin_check"
    source_tool = "nuclei"
    depends_on: list[str] = []
    required_signals: list[str] = ["technology:wordpress"]
    weight = 40
    optional = True
    intrusive_required = False

    def applies(self, ctx: VulnStageContext) -> bool:
        return bool(ctx.http_services)

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        if not ctx.http_services:
            return []
        if not nuclei_available():
            log.warning("wp_plugin_check: nuclei not on PATH — skipping")
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
        log.info("wp_plugin_check: %d findings", len(records))
        return records
