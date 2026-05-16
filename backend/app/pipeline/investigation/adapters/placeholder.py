"""Placeholder adapter — proves the worker plumbing end-to-end before real
tool adapters land. Returns one INFO finding and an `ok` raw output.

Wired only when the chosen tool has no real adapter yet. Remove from the
registry once all four tools (nmap_deep, ffuf, dirsearch, testssl) are real.
"""
from __future__ import annotations

import asyncio

from app.pipeline.investigation.stage import (
    FindingRecord,
    InvestigationResult,
    TaskContext,
)


class PlaceholderAdapter:
    def __init__(self, tool: str) -> None:
        self.tool = tool

    async def execute(self, ctx: TaskContext) -> InvestigationResult:
        # Simulate ~1s work so the UI progress bar visibly moves.
        await asyncio.sleep(1)
        return InvestigationResult(
            findings=[
                FindingRecord(
                    kind="placeholder",
                    severity="info",
                    title=f"{self.tool} placeholder run on {ctx.asset_canonical_key}",
                    description=(
                        "Placeholder adapter executed successfully. Replace with "
                        "real tool adapter."
                    ),
                    evidence={"tool": self.tool, "asset": ctx.asset_canonical_key},
                )
            ],
            raw_output=f"[placeholder] ran {self.tool} on {ctx.asset_canonical_key}\nok\n",
        )
