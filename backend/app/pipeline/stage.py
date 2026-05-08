from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID


@dataclass
class AssetRecord:
    """A single asset emitted by a stage. Stage code never touches the DB directly —
    the coordinator translates these into Asset + AssetObservation rows.
    """

    type: str
    canonical_key: str
    payload: dict = field(default_factory=dict)
    confidence: int = 80


@dataclass
class StageContext:
    scan_id: UUID
    target_id: UUID
    domain: str
    # canonical_keys produced by upstream stages, keyed by asset type. Stages with no
    # `inputs` declared get an empty dict; stages that declare inputs get the
    # deduplicated union of every upstream stage's matching outputs.
    inputs: dict[str, list[str]] = field(default_factory=dict)


class Stage(Protocol):
    name: str
    source_tool: str
    # Asset types this stage consumes from upstream stages. Empty = root stage that
    # operates on ctx.domain only.
    inputs: list[str]
    # Asset types this stage emits. Used by the coordinator to wire downstream inputs.
    outputs: list[str]
    # Stage names this stage depends on. The coordinator verifies the names exist and
    # uses them to compute execution levels.
    depends_on: list[str]
    # Relative cost for weighted progress. Roughly the p50 wall-clock seconds we
    # expect on a typical target — recompute from real data later.
    weight: int
    # If True, a failure or timeout is logged and skipped rather than aborting the scan.
    # Use for enrichment/backup stages (amass, geoip) where partial results are acceptable.
    optional: bool
    # If True, this stage requires the target to be authorization-verified before it will
    # run. The coordinator skips it (with an on_skip callback) when the target is unverified.
    authz_required: bool

    async def execute(self, ctx: StageContext) -> list[AssetRecord]: ...
