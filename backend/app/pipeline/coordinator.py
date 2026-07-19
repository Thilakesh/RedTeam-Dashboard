"""DAG executor for recon stages.

Stages declare `depends_on` (stage names). The coordinator computes execution levels
from those dependencies, runs each level in parallel, and feeds each stage the
deduplicated set of upstream `outputs` matching its declared `inputs`.

The coordinator is pure orchestration — it never touches the DB. The worker passes in
`on_stage_start` / `on_stage_done` / `on_stage_failed` callbacks so persistence,
pub/sub, and progress accounting all live in one place (`workers/runner.py`).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from app.pipeline.stage import AssetRecord, Stage, StageContext

log = logging.getLogger(__name__)


@dataclass
class StageResult:
    stage: Stage
    records: list[AssetRecord]


OnStart = Callable[[Stage], Awaitable[Any]]
OnDone = Callable[[Stage, list[AssetRecord], Any], Awaitable[None]]
OnFail = Callable[[Stage, Exception, Any], Awaitable[None]]
OnSkip = Callable[[Stage, str], Awaitable[None]]


def _levels(stages: list[Stage]) -> list[list[Stage]]:
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

    levels: dict[int, list[Stage]] = {}
    for s in stages:
        levels.setdefault(depth[s.name], []).append(s)
    return [levels[k] for k in sorted(levels)]


def total_weight(stages: list[Stage]) -> int:
    return sum(max(s.weight, 1) for s in stages)


async def execute_dag(
    stages: list[Stage],
    domain: str,
    target_id,
    scan_id,
    *,
    on_start: OnStart,
    on_done: OnDone,
    on_fail: OnFail,
    on_skip: OnSkip,
) -> None:
    """Run the DAG. Required stages abort the scan on failure; optional stages log the
    error and continue so enrichment tools (amass, geoip) don't kill the pipeline.
    """
    produced: dict[str, set[str]] = {}

    for level in _levels(stages):
        async def run_one(stage: Stage) -> StageResult | None:
            ctx = StageContext(
                scan_id=scan_id,
                target_id=target_id,
                domain=domain,
                inputs={t: sorted(produced.get(t, set())) for t in stage.inputs},
            )
            # Conditional gate: stages may declare an applies(ctx) predicate to skip
            # themselves when their required inputs are absent (e.g. no WordPress tech).
            applies_fn = getattr(stage, "applies", None)
            if applies_fn is not None and not applies_fn(ctx):
                await on_skip(stage, "no_matching_inputs")
                return None
            stage_handle = await on_start(stage)
            try:
                records = await stage.execute(ctx)
                await on_done(stage, records, stage_handle)
                return StageResult(stage=stage, records=records)
            except asyncio.CancelledError:
                # Job-level cancellation (arq's job_timeout, or an explicit
                # stop) — CancelledError is a BaseException, not Exception, so
                # it would otherwise skip on_fail entirely and leave this
                # stage's row stuck at "running" forever. Always record it as
                # failed and always re-raise: a cancellation is never a soft,
                # optional-stage failure to swallow and continue past.
                await on_fail(
                    stage,
                    RuntimeError("stage cancelled (job timeout or scan stopped)"),
                    stage_handle,
                )
                raise
            except Exception as exc:
                await on_fail(stage, exc, stage_handle)
                optional = getattr(stage, "optional", False)
                if optional:
                    log.warning("optional stage %r failed, continuing: %s", stage.name, exc)
                    return None
                raise

        raw = await asyncio.gather(*(run_one(s) for s in level), return_exceptions=False)
        for r in raw:
            if r is None:
                continue
            for rec in r.records:
                produced.setdefault(rec.type, set()).add(rec.canonical_key)
