"""DAG executor for vulnerability stages.

Mirrors the recon coordinator pattern but operates on VulnStageContext rather than
StageContext. Stages declare `depends_on` (stage names). The coordinator computes
execution levels, runs each level in parallel, and respects intrusive/applies gates.

Callbacks on_start/on_fail/on_skip match the signatures in pipeline/coordinator.py
exactly so the same worker callback functions can be reused.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.endpoint import Endpoint
from app.models.hvt_signal import HvtSignal
from app.models.service import Service
from app.models.technology import Technology
from app.pipeline.vuln.stage import VulnRecord, VulnStage, VulnStageContext

log = logging.getLogger(__name__)

OnStart = Callable[[Any], Awaitable[Any]]
OnDone = Callable[[Any, list[VulnRecord], Any], Awaitable[None]]
OnFail = Callable[[Any, Exception, Any], Awaitable[None]]
OnSkip = Callable[[Any, str], Awaitable[None]]


def _levels(stages: list) -> list[list]:
    by_name = {s.name: s for s in stages}
    for s in stages:
        for dep in s.depends_on:
            if dep not in by_name:
                raise ValueError(f"stage {s.name!r} depends on unknown stage {dep!r}")

    depth: dict[str, int] = {}

    def compute(name: str, seen: frozenset[str]) -> int:
        if name in depth:
            return depth[name]
        if name in seen:
            raise ValueError(f"cycle detected involving stage {name!r}")
        deps = by_name[name].depends_on
        d = 0 if not deps else 1 + max(compute(dep, seen | {name}) for dep in deps)
        depth[name] = d
        return d

    for s in stages:
        compute(s.name, frozenset())

    levels: dict[int, list] = {}
    for s in stages:
        levels.setdefault(depth[s.name], []).append(s)
    return [levels[k] for k in sorted(levels)]


async def load_vuln_context(
    db: AsyncSession,
    scan_id,
    parent_scan_id,
    target_id,
    domain: str,
    intrusive: bool,
) -> VulnStageContext:
    """Query Service, Technology, and Asset(type=http_service) for the target
    and return a populated VulnStageContext.
    """
    services_result = await db.scalars(
        select(Service).where(Service.target_id == target_id)
    )
    services = list(services_result.all())

    technologies_result = await db.scalars(
        select(Technology).where(Technology.target_id == target_id)
    )
    technologies = list(technologies_result.all())

    http_services_result = await db.scalars(
        select(Asset).where(
            Asset.target_id == target_id,
            Asset.type == "http_service",
        )
    )
    http_services = list(http_services_result.all())

    service_by_id = {svc.id: svc for svc in services}

    tech_by_asset_id: dict = {}
    for tech in technologies:
        tech_by_asset_id.setdefault(tech.asset_id, []).append(tech)

    http_service_urls = [asset.canonical_key for asset in http_services]

    # M-Vuln-5: pre-load endpoints + HVT signals discovered in prior scans against
    # this target. Stages can self-skip via applies(ctx) when their preconditions
    # are absent ("no_matching_signals" reason). Endpoints from the *current* scan
    # are written in real-time but won't appear in this snapshot — that's correct,
    # the snapshot is what existed BEFORE this run.
    endpoints_result = await db.scalars(
        select(Endpoint).where(Endpoint.target_id == target_id)
    )
    endpoints = list(endpoints_result.all())

    hvt_result = await db.scalars(
        select(HvtSignal).where(HvtSignal.target_id == target_id)
    )
    hvt_signals = list(hvt_result.all())

    endpoints_by_asset: dict = {}
    for ep in endpoints:
        endpoints_by_asset.setdefault(ep.asset_id, []).append(ep)

    hvt_signals_by_asset: dict = {}
    for sig in hvt_signals:
        hvt_signals_by_asset.setdefault(sig.asset_id, []).append(sig)

    return VulnStageContext(
        scan_id=scan_id,
        target_id=target_id,
        parent_scan_id=parent_scan_id,
        domain=domain,
        intrusive=intrusive,
        services=services,
        technologies=technologies,
        http_services=http_services,
        service_by_id=service_by_id,
        tech_by_asset_id=tech_by_asset_id,
        http_service_urls=http_service_urls,
        endpoints=endpoints,
        hvt_signals=hvt_signals,
        endpoints_by_asset=endpoints_by_asset,
        hvt_signals_by_asset=hvt_signals_by_asset,
    )


def total_weight(stages: list) -> int:
    return sum(max(s.weight, 1) for s in stages)


async def run_vuln_dag(
    stages: list,
    ctx: VulnStageContext,
    *,
    on_start: OnStart,
    on_done: OnDone,
    on_fail: OnFail,
    on_skip: OnSkip,
) -> None:
    """Run the vuln DAG. Optional stages log and continue on failure; required
    stages abort the run by re-raising.
    """
    for level in _levels(stages):
        async def run_one(stage) -> None:
            # Intrusive gate: skip stages that require active/intrusive scanning.
            if getattr(stage, "intrusive_required", False) and not ctx.intrusive:
                await on_skip(stage, "intrusive not enabled")
                return

            # Conditional gate: stages may declare applies(ctx) to self-skip.
            applies_fn = getattr(stage, "applies", None)
            if applies_fn is not None and not applies_fn(ctx):
                await on_skip(stage, "no_matching_inputs")
                return

            stage_handle = await on_start(stage)
            try:
                records = await stage.execute_vuln(ctx)
                await on_done(stage, records, stage_handle)
            except Exception as exc:
                await on_fail(stage, exc, stage_handle)
                optional = getattr(stage, "optional", False)
                if optional:
                    log.warning("optional vuln stage %r failed, continuing: %s", stage.name, exc)
                    return
                raise

        await asyncio.gather(*(run_one(s) for s in level), return_exceptions=False)
