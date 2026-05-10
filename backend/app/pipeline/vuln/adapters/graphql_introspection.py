"""graphql_introspection — GraphQL introspection enabled detection.

Fires when is_api endpoints exist. Probes known GraphQL paths with an
introspection query. A successful introspection response exposes the full
API schema to unauthenticated clients, aiding attackers in mapping the API
surface and finding injection points.

Non-intrusive: single POST per candidate endpoint.
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
_INTROSPECTION_QUERY = {
    "query": "{ __schema { queryType { name } types { name kind } } }"
}
_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"]


def _build_url(base_url: str, path: str) -> str:
    parsed = urlparse(base_url)
    return urlunparse(parsed._replace(path=path, query="", fragment=""))


def _looks_like_graphql_response(text: str) -> bool:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return False
    return isinstance(data, dict) and "data" in data and "__schema" in (data.get("data") or {})


class GraphqlIntrospectionStage:
    name = "graphql_introspection"
    source_tool = "graphql_introspection"
    depends_on: list[str] = []
    required_signals: list[str] = ["endpoint:is_api"]
    weight = 15
    optional = True
    intrusive_required = False

    def applies(self, ctx: VulnStageContext) -> bool:
        return bool(ctx.http_services)

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        if not ctx.http_services:
            return []

        # Collect candidate GraphQL endpoints: known paths + any flagged endpoint
        candidates: list[tuple] = []  # (asset, url)
        for asset in ctx.http_services:
            # Add well-known paths
            for path in _GRAPHQL_PATHS:
                candidates.append((asset, _build_url(asset.canonical_key, path)))
            # Add endpoints already discovered that look like graphql
            for ep in ctx.endpoints_by_asset.get(asset.id, []):
                if ep.path and "graphql" in ep.path.lower():
                    candidates.append((asset, ep.url))

        # Deduplicate by URL
        seen_urls: set[str] = set()
        unique_candidates = []
        for asset, url in candidates:
            if url not in seen_urls:
                seen_urls.add(url)
                unique_candidates.append((asset, url))

        records: list[VulnRecord] = []

        async def probe(asset, url: str) -> VulnRecord | None:
            try:
                async with _httpx.AsyncClient(
                    timeout=_TIMEOUT, follow_redirects=True, verify=False
                ) as client:
                    resp = await client.post(
                        url,
                        json=_INTROSPECTION_QUERY,
                        headers={"Content-Type": "application/json"},
                    )
            except Exception:
                return None

            if resp.status_code not in (200, 201):
                return None

            if not _looks_like_graphql_response(resp.text):
                return None

            return VulnRecord(
                asset_id=asset.id,
                canonical_key=f"graphql:introspection:{asset.id}:{url}",
                title="GraphQL Introspection Enabled",
                severity="MED",
                description=(
                    f"GraphQL introspection is enabled at {url}. "
                    "Introspection allows unauthenticated clients to query the full API schema, "
                    "including all types, queries, mutations, and field names. "
                    "This significantly reduces the effort required to map and attack the API."
                ),
                remediation=(
                    "Disable introspection in production. In Apollo Server: "
                    "`introspection: process.env.NODE_ENV !== 'production'`. "
                    "In other frameworks, consult the GraphQL security hardening guide at "
                    "https://owasp.org/www-project-top-ten/. "
                    "Consider adding depth-limiting and query complexity analysis."
                ),
                evidence=VulnEvidenceRecord(
                    source_tool="graphql_introspection",
                    request=f"POST {url}\n{json.dumps(_INTROSPECTION_QUERY)}",
                    response_excerpt=resp.text[:500] if resp.text else None,
                    matcher_name="graphql_schema_response",
                    extracted={"url": url, "status_code": resp.status_code},
                    confidence=90,
                ),
            )

        results = await asyncio.gather(*(probe(a, u) for a, u in unique_candidates))
        for r in results:
            if r is not None:
                records.append(r)

        return records
