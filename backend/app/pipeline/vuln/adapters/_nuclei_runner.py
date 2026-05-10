"""_nuclei_runner — shared nuclei subprocess for tag-targeted stages.

Runs nuclei against a given list of URLs with a custom tag + severity filter.
Returns list[VulnRecord]. Caller supplies the asset lookup dict so matched-at
URLs resolve to the correct asset.

Used by wp_plugin_check, struts_checker, and any future tech-specific nuclei
wrapper that needs tag filtering beyond NucleiSafeStage's defaults.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from pathlib import Path

from app.pipeline.vuln.stage import VulnEvidenceRecord, VulnRecord

log = logging.getLogger(__name__)

_BINARY = "nuclei"
_TEMPLATES_DIR = os.environ.get("NUCLEI_TEMPLATES_DIR", "/nuclei-templates")
_RATE_LIMIT = "100"
_BULK_SIZE = "20"

_SEV_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MED",
    "low": "LOW",
    "info": "INFO",
    "unknown": "INFO",
}


def nuclei_available() -> bool:
    return shutil.which(_BINARY) is not None


def templates_available() -> bool:
    return Path(_TEMPLATES_DIR).is_dir()


async def run_nuclei(
    *,
    urls: list[str],
    url_to_asset: dict,
    tags: str,
    severity: str = "low,medium,high,critical",
    timeout_sec: int = 600,
    extra_args: list[str] | None = None,
) -> list[VulnRecord]:
    """Run nuclei against urls with given tags/severity.

    Args:
        urls: target URLs (piped via stdin)
        url_to_asset: canonical URL -> Asset object (for asset_id resolution)
        tags: comma-separated nuclei tags (e.g. "wordpress,cve")
        severity: comma-separated severity filter
        timeout_sec: asyncio.wait_for timeout
        extra_args: additional CLI flags to append

    Returns list[VulnRecord], empty on binary-missing or timeout.
    """
    if not nuclei_available():
        log.warning("_nuclei_runner: %r not on PATH", _BINARY)
        return []

    targets = "\n".join(urls)
    cmd = [
        _BINARY,
        "-jsonl",
        "-silent",
        "-disable-update-check",
        "-no-color",
        "-tags", tags,
        "-severity", severity,
        "-rate-limit", _RATE_LIMIT,
        "-bulk-size", _BULK_SIZE,
    ]
    if templates_available():
        cmd += ["-templates-directory", _TEMPLATES_DIR]
    if extra_args:
        cmd.extend(extra_args)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return []

    try:
        stdout, _ = await asyncio.wait_for(
            proc.communicate(input=targets.encode()), timeout=timeout_sec
        )
    except asyncio.TimeoutError:
        proc.kill()
        try:
            await proc.communicate()
        except Exception:
            pass
        log.warning("_nuclei_runner: timed out after %ss (tags=%s)", timeout_sec, tags)
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
        severity_out = _SEV_MAP.get(sev_raw, "INFO")
        title = info.get("name") or tmpl_id
        description = info.get("description") or title
        classification = info.get("classification") or {}
        cve_ids = classification.get("cve-id") or []
        cwe_ids = classification.get("cwe-id") or []
        cvss = classification.get("cvss-score")

        asset = None
        for url, a in url_to_asset.items():
            if matched_at.startswith(url):
                asset = a
                break
        if asset is None:
            continue

        records.append(VulnRecord(
            asset_id=asset.id,
            canonical_key=f"nuclei:{tmpl_id}:{asset.id}:{matched_at}",
            title=title,
            severity=severity_out,
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
        ))

    return records
