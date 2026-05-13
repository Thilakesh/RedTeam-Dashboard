"""nuclei_safe — real nuclei subprocess, safe templates only.

Runs nuclei against http_service URLs from the recon asset graph. Restricted to
non-intrusive tags (cve, exposure, misconfig, tech) and severity <= medium so it
never sends payloads that could trip a WAF or break a service.

Templates dir is mounted read-only into the container at /nuclei-templates.
We intentionally do NOT call `-update-templates` at scan time — version-pinned
and refreshed by an out-of-band job.

Fail-soft: stage is `optional=True`; if the binary is missing or the run fails,
the coordinator logs and continues.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from pathlib import Path

from app.pipeline.vuln.stage import VulnEvidenceRecord, VulnRecord, VulnStageContext

log = logging.getLogger(__name__)

_BINARY = "nuclei"
_TEMPLATES_DIR = os.environ.get("NUCLEI_TEMPLATES_DIR", "/nuclei-templates")
_RATE_LIMIT = "150"
_BULK_SIZE = "25"
_TIMEOUT_SEC = 600
_TAGS = "cve,exposure,misconfig,tech"
_SEVERITY = "low,medium"

_SEV_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MED",
    "low": "LOW",
    "info": "INFO",
    "unknown": "INFO",
}


def _binary_available() -> bool:
    return shutil.which(_BINARY) is not None


def _templates_available() -> bool:
    return Path(_TEMPLATES_DIR).is_dir()


class NucleiSafeStage:
    name = "nuclei_safe"
    source_tool = "nuclei"
    depends_on: list[str] = []
    weight = 60
    optional = True
    intrusive_required = False

    def applies(self, ctx: VulnStageContext) -> bool:
        return bool(ctx.http_services)

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        if not ctx.http_services:
            return []
        if not _binary_available():
            log.warning("nuclei_safe: binary %r not found on PATH — skipping", _BINARY)
            return []

        url_to_asset = {a.canonical_key: a for a in ctx.http_services}
        targets = "\n".join(url_to_asset.keys())

        cmd = [
            _BINARY,
            "-jsonl",
            "-silent",
            "-disable-update-check",
            "-no-color",
            "-tags", _TAGS,
            "-severity", _SEVERITY,
            "-rate-limit", _RATE_LIMIT,
            "-bulk-size", _BULK_SIZE,
        ]
        if _templates_available():
            cmd += ["-templates-directory", _TEMPLATES_DIR]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            log.warning("nuclei_safe: failed to spawn %r", _BINARY)
            return []

        try:
            stdout, _stderr = await asyncio.wait_for(
                proc.communicate(input=targets.encode()), timeout=_TIMEOUT_SEC
            )
        except asyncio.TimeoutError:
            proc.kill()
            try:
                await proc.communicate()
            except Exception:
                pass
            log.warning("nuclei_safe: timed out after %ss", _TIMEOUT_SEC)
            return []

        records: list[VulnRecord] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue

            tmpl_id = row.get("template-id") or row.get("templateID") or "unknown"
            matched_at = row.get("matched-at") or row.get("matched_at") or row.get("host") or ""
            info = row.get("info") or {}
            sev_raw = str(info.get("severity") or "info").lower()
            severity = _SEV_MAP.get(sev_raw, "INFO")
            title = info.get("name") or tmpl_id
            description = info.get("description") or title
            classification = info.get("classification") or {}
            cve_ids = classification.get("cve-id") or []
            cwe_ids = classification.get("cwe-id") or []
            cvss = classification.get("cvss-score")

            # Map matched-at URL back to an asset; fallback to first asset.
            asset = None
            for url, a in url_to_asset.items():
                if matched_at.startswith(url):
                    asset = a
                    break
            if asset is None:
                continue

            canonical_key = f"nuclei:{tmpl_id}:{asset.id}:{matched_at}"
            records.append(
                VulnRecord(
                    asset_id=asset.id,
                    canonical_key=canonical_key,
                    title=title,
                    severity=severity,
                    description=description,
                    template_id=tmpl_id,
                    cve_ids=list(cve_ids) if isinstance(cve_ids, list) else [str(cve_ids)],
                    cwe_ids=list(cwe_ids) if isinstance(cwe_ids, list) else [str(cwe_ids)],
                    cvss_v3=float(cvss) if cvss is not None else None,
                    remediation=info.get("remediation"),
                    evidence=VulnEvidenceRecord(
                        source_tool="nuclei",
                        request=row.get("request"),
                        response_excerpt=(row.get("response") or "")[:1000] or None,
                        matcher_name=row.get("matcher-name") or row.get("matcher_name"),
                        extracted={
                            "matched_at": matched_at,
                            "type": row.get("type"),
                            "tags": info.get("tags"),
                        },
                        confidence=85,
                    ),
                )
            )
        return records
