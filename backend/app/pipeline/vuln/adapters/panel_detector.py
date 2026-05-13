"""Admin/login panel detector — M-Vuln-6 rewrite.

Probes known panel/sensitive paths via httpx. Confirmed hits emit HvtSignal
rows (not VulnRecords). Returns []. A Joomla admin panel and a Heartbleed CVE
should not share a table or lifecycle.

Non-intrusive: read-only GET requests. optional=True.
"""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlparse, urlunparse

import httpx as _httpx

from app.core.db import SessionLocal
from app.models.hvt_signal import HvtSignalType
from app.pipeline.vuln.stage import VulnRecord, VulnStageContext
from app.services.hvt_signals import HvtSignalRecord, upsert_hvt_signals

log = logging.getLogger(__name__)

# (path_suffix, title_keywords, signal_type, score, extra_signal_type_if_keyword)
# platform_keywords: optional (keyword_list, HvtSignalType) to emit a second
# platform-specific signal when response body contains those keywords.
PANEL_SIGNATURES = [
    {
        "path_suffix": "/wp-admin/",
        "title_keywords": ["wordpress", "wp admin"],
        "signal_type": HvtSignalType.admin_panel,
        "score": 0.85,
        "confidence": 85,
        "platform_keywords": (["wordpress", "wp-admin"], HvtSignalType.wordpress),
    },
    {
        "path_suffix": "/wp-login.php",
        "title_keywords": ["wordpress", "log in"],
        "signal_type": HvtSignalType.login_form,
        "score": 0.4,
        "confidence": 80,
        "platform_keywords": (["wordpress"], HvtSignalType.wordpress),
    },
    {
        "path_suffix": "/phpmyadmin/",
        "title_keywords": ["phpmyadmin"],
        "signal_type": HvtSignalType.admin_panel,
        "score": 0.9,
        "confidence": 90,
        "platform_keywords": None,
    },
    {
        "path_suffix": "/admin/",
        "title_keywords": ["admin", "dashboard", "login"],
        "signal_type": HvtSignalType.admin_panel,
        "score": 0.7,
        "confidence": 70,
        "platform_keywords": None,
    },
    {
        "path_suffix": "/administrator/",
        "title_keywords": ["joomla", "administrator"],
        "signal_type": HvtSignalType.admin_panel,
        "score": 0.8,
        "confidence": 80,
        "platform_keywords": None,
    },
    {
        "path_suffix": "/manager/html",
        "title_keywords": ["tomcat", "manager"],
        "signal_type": HvtSignalType.admin_panel,
        "score": 0.85,
        "confidence": 85,
        "platform_keywords": None,
    },
    {
        "path_suffix": "/console/",
        "title_keywords": ["weblogic", "console"],
        "signal_type": HvtSignalType.admin_panel,
        "score": 0.85,
        "confidence": 85,
        "platform_keywords": None,
    },
    {
        "path_suffix": "/.git/HEAD",
        "title_keywords": [],          # presence (200 + "ref:") is enough
        "title_contains": "ref:",       # raw response must contain this
        "signal_type": HvtSignalType.git_repo,
        "score": 0.95,
        "confidence": 95,
        "platform_keywords": None,
    },
    {
        "path_suffix": "/.env",
        "title_keywords": [],
        "signal_type": HvtSignalType.env_file,
        "score": 0.95,
        "confidence": 95,
        "platform_keywords": None,
    },
    {
        "path_suffix": "/api/",
        "title_keywords": ["swagger", "api docs", "api explorer"],
        "signal_type": HvtSignalType.api_doc,
        "score": 0.55,
        "confidence": 65,
        "platform_keywords": None,
    },
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
    required_signals: list[str] = []   # no preconditions — fires whenever http_services exist
    weight = 15
    optional = True
    intrusive_required = False

    def applies(self, ctx: VulnStageContext) -> bool:
        return bool(ctx.http_services)

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        if not ctx.http_services:
            return []

        sem = asyncio.Semaphore(_SEMAPHORE_LIMIT)
        signal_records: list[HvtSignalRecord] = []

        checks = [
            (asset, asset.canonical_key, sig)
            for asset in ctx.http_services
            for sig in PANEL_SIGNATURES
        ]

        async def probe(asset, base_url: str, sig: dict) -> list[HvtSignalRecord]:
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
                    return []

            if resp.status_code != 200:
                return []

            body_lower = resp.text.lower() if resp.text else ""

            # Hard-contains check (for .git/HEAD)
            title_contains = sig.get("title_contains")
            if title_contains and title_contains not in body_lower:
                return []

            # Keyword match (if keywords specified, at least one must be present)
            keywords = sig.get("title_keywords", [])
            if keywords and not any(kw in body_lower for kw in keywords):
                return []

            results = []
            primary = HvtSignalRecord(
                asset_id=asset.id,
                signal_type=sig["signal_type"],
                score=sig["score"],
                confidence=sig["confidence"],
                evidence={
                    "url": check_url,
                    "status_code": resp.status_code,
                    "path_suffix": sig["path_suffix"],
                    "response_excerpt": resp.text[:300] if resp.text else "",
                },
            )
            results.append(primary)

            # Optional platform-specific second signal
            pk = sig.get("platform_keywords")
            if pk:
                pk_keywords, pk_type = pk
                if any(kw in body_lower for kw in pk_keywords):
                    results.append(HvtSignalRecord(
                        asset_id=asset.id,
                        signal_type=pk_type,
                        score=sig["score"] * 0.9,
                        confidence=75,
                        evidence={"url": check_url, "detected_via": "panel_detector"},
                    ))

            return results

        gathered = await asyncio.gather(*(probe(a, u, s) for a, u, s in checks))
        for batch in gathered:
            signal_records.extend(batch)

        if not signal_records:
            return []

        async with SessionLocal() as db:
            count = await upsert_hvt_signals(
                db,
                target_id=ctx.target_id,
                source_tool="panel_detector",
                records=signal_records,
            )
            await db.commit()

        log.info("panel_detector: wrote %d HvtSignal rows", count)
        return []  # No VulnRecords — panel detection is surface classification, not weakness finding
