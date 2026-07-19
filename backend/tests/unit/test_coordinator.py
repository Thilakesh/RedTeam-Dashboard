"""Unit tests for the DAG coordinator — specifically the CancelledError fix.

CancelledError is a BaseException (not Exception) since Python 3.8, so a plain
`except Exception` around stage execution silently skips on_fail entirely when
a job_timeout cancels a stage mid-run, leaving its ScanStage row stuck at
"running" forever. These tests lock in that on_fail is always called and the
cancellation always propagates, regardless of the stage's optional flag.
"""
from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from app.pipeline.coordinator import execute_dag
from app.pipeline.stage import AssetRecord, StageContext


class _CancellingStage:
    """A stage whose execute() raises CancelledError, as if arq's job_timeout
    fired mid-run."""

    def __init__(self, name: str, optional: bool):
        self.name = name
        self.source_tool = name
        self.inputs: list[str] = []
        self.outputs: list[str] = []
        self.depends_on: list[str] = []
        self.weight = 10
        self.optional = optional

    async def execute(self, ctx: StageContext) -> list[AssetRecord]:
        raise asyncio.CancelledError()


def _make_ctx_args():
    return dict(domain="example.com", target_id=uuid4(), scan_id=uuid4())


async def _noop_on_start(stage):
    return uuid4()


async def _noop_on_done(stage, records, handle):
    pass


async def _noop_on_skip(stage, reason):
    pass


async def _noop_on_fail(stage, exc, handle):
    pass


@pytest.mark.asyncio
async def test_cancelled_stage_calls_on_fail_even_when_optional():
    """A cancelled optional stage must still get on_fail — otherwise its row
    is stuck at 'running' forever, which is exactly the reported bug."""
    fail_calls = []

    async def on_fail(stage, exc, handle):
        fail_calls.append((stage.name, exc))

    stage = _CancellingStage("nmap", optional=True)

    with pytest.raises(asyncio.CancelledError):
        await execute_dag(
            [stage],
            **_make_ctx_args(),
            on_start=_noop_on_start,
            on_done=_noop_on_done,
            on_fail=on_fail,
            on_skip=_noop_on_skip,
        )

    assert len(fail_calls) == 1
    assert fail_calls[0][0] == "nmap"


@pytest.mark.asyncio
async def test_cancelled_stage_always_propagates_regardless_of_optional():
    """Unlike a regular Exception, optional=True must NOT swallow a
    cancellation — the whole job is being torn down, not just this stage."""
    stage = _CancellingStage("amass", optional=True)

    with pytest.raises(asyncio.CancelledError):
        await execute_dag(
            [stage],
            **_make_ctx_args(),
            on_start=_noop_on_start,
            on_done=_noop_on_done,
            on_fail=_noop_on_fail,
            on_skip=_noop_on_skip,
        )
