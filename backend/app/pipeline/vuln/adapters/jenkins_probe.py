"""jenkins_probe — Jenkins Script Console + unauth API detection.

Fires when hvt_signal:jenkins is present (panel_detector detected a Jenkins
instance). Checks:
  1. /script — Script Console accessible unauthenticated -> CRITICAL
  2. /whoAmI/api/json -> anonymous = true -> HIGH (anonymous read enabled)

Non-intrusive: read-only GETs. optional=True.
"""

from __future__ import annotations

import asyncio
import json
import logging
from urllib.parse import urlparse, urlunparse

import httpx as _httpx

from app.pipeline.vuln.stage import VulnEvidenceRecord, VulnRecord, VulnStageContext

log = logging.getLogger(__name__)

_TIMEOUT = 8.0

_CHECKS = [
    {
        "path": "/script",
        "indicators": ["script console", "groovy script", "run script"],
        "title": "Jenkins Script Console Accessible Unauthenticated",
        "severity": "CRITICAL",
        "description": (
            "The Jenkins Script Console (/script) is accessible without authentication. "
            "This allows arbitrary Groovy code execution on the Jenkins server, "
            "leading to full remote code execution and server compromise."
        ),
        "remediation": (
            "Enable authentication in Jenkins. Navigate to Manage Jenkins -> "
            "Configure Global Security -> Enable security. Restrict Script Console "
            "access to administrators only."
        ),
        "canonical_suffix": "script_console_unauth",
        "confidence": 95,
    },
    {
        "path": "/whoAmI/api/json",
        "json_key": "anonymous",
        "json_value": True,
        "title": "Jenkins Anonymous Read Access Enabled",
        "severity": "HIGH",
        "description": (
            "Jenkins is configured to allow anonymous read access. Unauthenticated "
            "users can view build history, job configurations, and potentially sensitive "
            "CI/CD configuration including secrets passed as build parameters."
        ),
        "remediation": (
            "In Jenkins: Manage Jenkins -> Configure Global Security -> "
            "uncheck 'Allow users to sign up' and set Authorization to "
            "'Matrix-based security' with no permissions for Anonymous."
        ),
        "canonical_suffix": "anonymous_read",
        "confidence": 90,
    },
]


def _build_url(base_url: str, path: str) -> str:
    parsed = urlparse(base_url)
    return urlunparse(parsed._replace(path=path, query="", fragment=""))


class JenkinsProbeStage:
    name = "jenkins_probe"
    source_tool = "jenkins_probe"
    depends_on: list[str] = []
    required_signals: list[str] = ["hvt_signal:jenkins"]
    weight = 15
    optional = True
    intrusive_required = False

    def applies(self, ctx: VulnStageContext) -> bool:
        return bool(ctx.http_services)

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        if not ctx.http_services:
            return []

        records: list[VulnRecord] = []

        async def check_asset(asset) -> list[VulnRecord]:
            asset_records = []
            for chk in _CHECKS:
                url = _build_url(asset.canonical_key, chk["path"])
                try:
                    async with _httpx.AsyncClient(
                        timeout=_TIMEOUT, follow_redirects=True, verify=False
                    ) as client:
                        resp = await client.get(url)
                except Exception:
                    continue

                if resp.status_code != 200:
                    continue

                # Keyword check for HTML-based probe
                if "indicators" in chk:
                    body_lower = resp.text.lower() if resp.text else ""
                    if not any(ind in body_lower for ind in chk["indicators"]):
                        continue

                # JSON key/value check
                if "json_key" in chk:
                    try:
                        data = json.loads(resp.text)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if data.get(chk["json_key"]) != chk["json_value"]:
                        continue

                asset_records.append(VulnRecord(
                    asset_id=asset.id,
                    canonical_key=f"jenkins:{chk['canonical_suffix']}:{asset.id}",
                    title=chk["title"],
                    severity=chk["severity"],
                    description=chk["description"],
                    remediation=chk["remediation"],
                    evidence=VulnEvidenceRecord(
                        source_tool="jenkins_probe",
                        request=f"GET {url}",
                        response_excerpt=resp.text[:500] if resp.text else None,
                        matcher_name=chk["canonical_suffix"],
                        extracted={"url": url, "status_code": resp.status_code},
                        confidence=chk["confidence"],
                    ),
                ))
            return asset_records

        results = await asyncio.gather(*(check_asset(a) for a in ctx.http_services))
        for batch in results:
            records.extend(batch)

        return records
