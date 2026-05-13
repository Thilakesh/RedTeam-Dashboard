"""swagger_discoverer — probe for OpenAPI / Swagger / API-docs surfaces.

For each http_service, GET a fixed list of well-known spec paths. When a JSON
or YAML spec responds 200, two outputs:

  1. An HvtSignal of type=`api_doc` (or `swagger`) on the host asset.
  2. Endpoints expanded from the spec's "paths" section into the endpoints
     table (each path × each declared HTTP method). is_api=True on every row.

Non-intrusive: read-only GETs to standard paths, capped concurrency. No fuzzing.
"""

from __future__ import annotations

import asyncio
import json
import logging
from urllib.parse import urlparse, urlunparse

import httpx as _httpx

from app.core.db import SessionLocal
from app.models.hvt_signal import HvtSignalType
from app.pipeline.vuln.stage import VulnRecord, VulnStageContext
from app.services.endpoints import EndpointRecord
from app.services.hvt_signals import HvtSignalRecord, upsert_hvt_signals

log = logging.getLogger(__name__)

_SPEC_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/api/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/api/v1/openapi.json",
]
_TIMEOUT = 5.0
_SEM = 8


def _replace_path(base_url: str, new_path: str) -> str:
    parsed = urlparse(base_url)
    return urlunparse(parsed._replace(path=new_path, query="", fragment=""))


async def _probe_one(client: _httpx.AsyncClient, asset, base_url: str):
    """Probe one http_service for spec paths. Returns (asset, hits) where hits
    is a list of (spec_path, parsed_spec_dict)."""
    hits = []
    for sp in _SPEC_PATHS:
        url = _replace_path(base_url, sp)
        try:
            resp = await client.get(url)
        except Exception:
            continue
        if resp.status_code != 200:
            continue
        ctype = (resp.headers.get("content-type") or "").lower()
        if "json" not in ctype and not (resp.text or "").lstrip().startswith("{"):
            continue
        try:
            spec = json.loads(resp.text)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(spec, dict) or "paths" not in spec:
            continue
        hits.append((url, spec))
    return asset, hits


def _expand_paths(base_url: str, spec: dict) -> list[str]:
    """Return absolute URLs for every (path, method) declared in the spec."""
    out = []
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return out
    for path, ops in paths.items():
        if not isinstance(path, str) or not path.startswith("/"):
            continue
        if not isinstance(ops, dict):
            continue
        # Just track paths — methods stored on Endpoint.method but for the
        # write below we use GET as the primary method since most APIs accept
        # GET on listing routes; deeper expansion would explode the table.
        out.append(_replace_path(base_url, path))
    return out


class SwaggerDiscovererStage:
    name = "swagger_discoverer"
    source_tool = "swagger_discoverer"
    depends_on: list[str] = []
    weight = 10
    optional = True
    intrusive_required = False

    def applies(self, ctx: VulnStageContext) -> bool:
        return bool(ctx.http_services)

    async def execute_vuln(self, ctx: VulnStageContext) -> list[VulnRecord]:
        if not ctx.http_services:
            return []
        sem = asyncio.Semaphore(_SEM)

        async def run(asset):
            base = asset.canonical_key
            async with sem:
                async with _httpx.AsyncClient(
                    timeout=_TIMEOUT, follow_redirects=True, verify=False,
                ) as client:
                    return await _probe_one(client, asset, base)

        results = await asyncio.gather(*(run(a) for a in ctx.http_services))

        endpoint_records: list[EndpointRecord] = []
        signal_records: list[HvtSignalRecord] = []

        for asset, hits in results:
            for spec_url, spec in hits:
                # Emit HvtSignal: api_doc on the host asset
                signal_records.append(
                    HvtSignalRecord(
                        asset_id=asset.id,
                        signal_type=HvtSignalType.api_doc,
                        score=0.55,
                        confidence=90,
                        evidence={"spec_url": spec_url, "title": (spec.get("info") or {}).get("title")},
                    )
                )
                # Expand spec paths into endpoints
                for url in _expand_paths(asset.canonical_key, spec):
                    endpoint_records.append(
                        EndpointRecord(
                            asset_id=asset.id,
                            url=url,
                            method="GET",
                            is_api=True,
                        )
                    )

        if not endpoint_records and not signal_records:
            return []

        # Persist directly. Same rationale as katana: stage_id plumbing comes in
        # M-Vuln-6; for now we batch-write without observations.
        from sqlalchemy.dialects.postgresql import insert as _insert
        from sqlalchemy.sql import func as _func
        from urllib.parse import urlparse as _urlparse
        from app.models.endpoint import Endpoint

        async with SessionLocal() as db:
            if endpoint_records:
                for start in range(0, len(endpoint_records), 2000):
                    chunk = endpoint_records[start : start + 2000]
                    rows = [
                        {
                            "target_id": ctx.target_id,
                            "asset_id": r.asset_id,
                            "url": r.url,
                            "path": _urlparse(r.url).path or "/",
                            "method": r.method,
                            "is_api": r.is_api,
                            "source_tool": "swagger_discoverer",
                        }
                        for r in chunk
                    ]
                    stmt = _insert(Endpoint).values(rows)
                    stmt = stmt.on_conflict_do_update(
                        constraint="uq_endpoint_identity",
                        set_={
                            "last_seen": _func.now(),
                            "is_api": Endpoint.is_api.op("OR")(stmt.excluded.is_api),
                        },
                    )
                    await db.execute(stmt)
            if signal_records:
                await upsert_hvt_signals(
                    db,
                    target_id=ctx.target_id,
                    source_tool="swagger_discoverer",
                    records=signal_records,
                )
            await db.commit()

        log.info(
            "swagger_discoverer: %d HvtSignals, %d endpoints",
            len(signal_records), len(endpoint_records),
        )
        return []
