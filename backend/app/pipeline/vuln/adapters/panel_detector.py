"""Admin/login panel detector.

For each http_service URL in the VulnStageContext, probes known admin panel paths
using httpx. Emits a VulnRecord when a panel is reachable (HTTP 200) and the
response text matches configured keywords.

Non-intrusive: read-only GET requests only.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse, urlunparse

import httpx as _httpx

from app.pipeline.vuln.stage import VulnEvidenceRecord, VulnRecord, VulnStageContext

PANEL_SIGNATURES = [
    {"path_suffix": "/wp-admin/", "title_keywords": ["wordpress", "wp admin"], "name": "WordPress Admin Panel", "severity": "MED"},
    {"path_suffix": "/wp-login.php", "title_keywords": ["wordpress", "log in"], "name": "WordPress Login", "severity": "LOW"},
    {"path_suffix": "/phpmyadmin/", "title_keywords": ["phpmyadmin"], "name": "phpMyAdmin", "severity": "HIGH"},
    {"path_suffix": "/admin/", "title_keywords": ["admin", "dashboard", "login"], "name": "Admin Panel", "severity": "MED"},
    {"path_suffix": "/administrator/", "title_keywords": ["joomla", "administrator"], "name": "Joomla Admin", "severity": "MED"},
    {"path_suffix": "/manager/html", "title_keywords": ["tomcat", "manager"], "name": "Tomcat Manager", "severity": "HIGH"},
    {"path_suffix": "/console/", "title_keywords": ["weblogic", "console"], "name": "WebLogic Console", "severity": "HIGH"},
    {"path_suffix": "/.git/HEAD", "title_keywords": [], "name": "Exposed Git Repository", "severity": "HIGH"},
    {"path_suffix": "/.env", "title_keywords": [], "name": "Exposed .env File", "severity": "HIGH"},
    {"path_suffix": "/api/", "title_keywords": ["swagger", "api docs", "api explorer"], "name": "API Documentation Exposed", "severity": "LOW"},
]

_SEMAPHORE_LIMIT = 10
_REQUEST_TIMEOUT = 5.0


def _build_check_url(base_url: str, path_suffix: str) -> str:
    parsed = urlparse(base_url)
    return urlunparse(parsed._replace(path=path_suffix, query="", fragment=""))


class PanelDetectorStage:
    name = "panel_detector"
    source_tool = "panel_detector"
    depends_on: list[str] = []
    weight = 15
    optional = True
    intrusive_required = False

    def applies(self, ctx: VulnStageContext) -> bool:
        return bool(ctx.http_services)

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        if not ctx.http_services:
            return []

        sem = asyncio.Semaphore(_SEMAPHORE_LIMIT)
        records: list[VulnRecord] = []

        # Build (asset, url, sig) triples for all checks
        checks = []
        for asset in ctx.http_services:
            base_url = asset.canonical_key
            for sig in PANEL_SIGNATURES:
                checks.append((asset, base_url, sig))

        async def probe(asset, base_url: str, sig: dict) -> VulnRecord | None:
            check_url = _build_check_url(base_url, sig["path_suffix"])
            async with sem:
                try:
                    async with _httpx.AsyncClient(
                        follow_redirects=True,
                        verify=False,
                        timeout=_REQUEST_TIMEOUT,
                    ) as client:
                        resp = await client.get(check_url)
                except Exception:
                    return None

            if resp.status_code != 200:
                return None

            keywords = sig.get("title_keywords", [])
            if keywords:
                body_lower = resp.text.lower()
                if not any(kw in body_lower for kw in keywords):
                    return None

            canonical_key = f"panel:{sig['name'].lower().replace(' ', '_')}:{asset.id}"
            excerpt = resp.text[:500] if resp.text else None
            return VulnRecord(
                asset_id=asset.id,
                canonical_key=canonical_key,
                title=f"Exposed Panel: {sig['name']}",
                severity=sig["severity"],
                description=f"Detected exposed {sig['name']} at {check_url}",
                evidence=VulnEvidenceRecord(
                    source_tool="panel_detector",
                    request=f"GET {check_url}",
                    response_excerpt=excerpt,
                    matcher_name="http_200_keyword",
                    extracted={"url": check_url, "status_code": resp.status_code},
                    confidence=80,
                ),
            )

        results = await asyncio.gather(*(probe(a, u, s) for a, u, s in checks))
        for r in results:
            if r is not None:
                records.append(r)

        return records
