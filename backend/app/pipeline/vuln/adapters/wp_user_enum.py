"""wp_user_enum — WordPress REST API username enumeration.

Fires when technology:wordpress is detected. Checks /wp-json/wp/v2/users —
WordPress exposes user slugs/names to unauthenticated requests by default. A
non-empty response is a HIGH finding: an attacker learns valid usernames for
brute-force attacks.

Non-intrusive: single GET request per http_service.
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
_ENDPOINT = "/wp-json/wp/v2/users"


def _build_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    return urlunparse(parsed._replace(path=_ENDPOINT, query="", fragment=""))


class WpUserEnumStage:
    name = "wp_user_enum"
    source_tool = "wp_user_enum"
    depends_on: list[str] = []
    required_signals: list[str] = ["technology:wordpress"]
    weight = 10
    optional = True
    intrusive_required = False

    def applies(self, ctx: VulnStageContext) -> bool:
        return bool(ctx.http_services)

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        if not ctx.http_services:
            return []

        records: list[VulnRecord] = []

        async def check(asset) -> VulnRecord | None:
            url = _build_url(asset.canonical_key)
            try:
                async with _httpx.AsyncClient(
                    timeout=_TIMEOUT, follow_redirects=True, verify=False
                ) as client:
                    resp = await client.get(url)
            except Exception:
                return None

            if resp.status_code != 200:
                return None

            try:
                data = json.loads(resp.text)
            except (json.JSONDecodeError, ValueError):
                return None

            if not isinstance(data, list) or not data:
                return None

            # Must look like a users array (have slug or name fields)
            first = data[0] if data else {}
            if not isinstance(first, dict) or not (first.get("slug") or first.get("name")):
                return None

            usernames = [u.get("slug") or u.get("name") or "" for u in data[:10]]
            usernames = [u for u in usernames if u]

            return VulnRecord(
                asset_id=asset.id,
                canonical_key=f"wp_user_enum:{asset.id}",
                title="WordPress REST API Exposes User Enumeration",
                severity="HIGH",
                description=(
                    f"The WordPress REST API at {url} returns user account information "
                    f"without authentication. Found {len(data)} user(s). "
                    f"Sample usernames: {', '.join(usernames[:5])}. "
                    "Attackers can use these for targeted brute-force attacks."
                ),
                remediation=(
                    "Disable unauthenticated access to /wp-json/wp/v2/users by adding "
                    "`add_filter('rest_endpoints', function($e){ unset($e['/wp/v2/users']); "
                    "return $e; });` to functions.php, or using a security plugin like "
                    "Wordfence. Alternatively, add authentication requirements to the endpoint."
                ),
                evidence=VulnEvidenceRecord(
                    source_tool="wp_user_enum",
                    request=f"GET {url}",
                    response_excerpt=resp.text[:500],
                    matcher_name="wp_users_endpoint_200",
                    extracted={
                        "url": url,
                        "user_count": len(data),
                        "usernames": usernames,
                        "status_code": resp.status_code,
                    },
                    confidence=90,
                ),
            )

        results = await asyncio.gather(*(check(a) for a in ctx.http_services))
        for r in results:
            if r is not None:
                records.append(r)

        return records
