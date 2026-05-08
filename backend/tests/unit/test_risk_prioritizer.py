"""Unit tests for RiskPrioritizerStage — all DB and LLM calls are mocked."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_subdomain_row(subdomain: str) -> MagicMock:
    """Build a fake SubdomainRow with the actual attribute names from scan_view.py."""
    row = MagicMock()
    row.subdomain = subdomain          # the FQDN field on SubdomainRow
    row.asset_id = uuid4()
    row.http_status = 200
    row.waf = None
    row.waf_conf = None
    row.cdn = False
    row.cdn_name = None
    row.tech = ["nginx"]
    row.server = "nginx/1.18.0"
    row.screenshot_url = None
    row.first_seen = datetime(2025, 1, 1, tzinfo=timezone.utc)
    return row


FAKE_FQDNS = [
    "admin.example.com",
    "api.example.com",
    "staging.example.com",
    "dev.example.com",
    "mail.example.com",
]

FAKE_ROWS = [_make_subdomain_row(fqdn) for fqdn in FAKE_FQDNS]


def _llm_findings(fqdns: list[str]) -> dict:
    """Build a fake LLM response for the given list of FQDNs."""
    findings = []
    for i, fqdn in enumerate(fqdns):
        findings.append({
            "fqdn": fqdn,
            "severity": "HIGH" if i == 0 else ("MED" if i == 1 else "LOW"),
            "risk_score": round(1.0 - i * 0.15, 2),
            "priority_rank": i + 1,
            "rationale": f"Risk rationale for {fqdn}",
            "signals": ["no_waf", "open_admin_port"] if i == 0 else ["no_waf"],
            "recommended_action": f"Remediate {fqdn} immediately.",
        })
    return {"findings": findings}


def _llm_findings_scrambled(fqdns: list[str]) -> dict:
    """Like _llm_findings but with all priority_rank values set to 99 (wrong).
    The stage must re-rank them to [1..N] based on risk_score ordering."""
    findings = []
    for i, fqdn in enumerate(fqdns):
        findings.append({
            "fqdn": fqdn,
            "severity": "HIGH" if i == 0 else ("MED" if i == 1 else "LOW"),
            "risk_score": round(1.0 - i * 0.15, 2),
            "priority_rank": 99,  # Wrong — stage must fix this.
            "rationale": f"Risk rationale for {fqdn}",
            "signals": ["no_waf", "open_admin_port"] if i == 0 else ["no_waf"],
            "recommended_action": f"Remediate {fqdn} immediately.",
        })
    return {"findings": findings}


def _make_session_mock(added: list) -> MagicMock:
    """Return an async context-manager mock for SessionLocal that tracks db.add() calls."""
    mock_session = AsyncMock()
    mock_session.add = MagicMock(side_effect=added.append)
    mock_session.commit = AsyncMock()
    mock_session.execute = AsyncMock()

    # Make it work as `async with SessionLocal() as db:`
    cm = AsyncMock()
    cm.__aenter__ = AsyncMock(return_value=mock_session)
    cm.__aexit__ = AsyncMock(return_value=None)
    return cm


def _make_session_local(added: list) -> MagicMock:
    """Return a callable mock that returns the async context manager."""
    session_cm = _make_session_mock(added)
    session_local = MagicMock(return_value=session_cm)
    return session_local


def _make_ctx() -> object:
    """Build a minimal StageContext-like object."""
    from app.pipeline.stage import StageContext
    return StageContext(
        scan_id=uuid4(),
        target_id=uuid4(),
        domain="example.com",
    )


from app.agents.bounded_completion import CompletionResult


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_returns_empty_list():
    """Stage.execute() must always return []."""
    from app.agents.risk_prioritizer import RiskPrioritizerStage

    added: list = []
    session_local = _make_session_local(added)
    completion_result = CompletionResult(
        content=_llm_findings(FAKE_FQDNS),
        prompt_tokens=100,
        completion_tokens=50,
    )

    with (
        patch("app.agents.risk_prioritizer.SessionLocal", session_local),
        patch("app.agents.risk_prioritizer.build_subdomain_rows", AsyncMock(return_value=FAKE_ROWS)),
        patch("app.agents.risk_prioritizer.build_port_rows", AsyncMock(return_value=[])),
        patch("app.agents.risk_prioritizer.bounded_completion", AsyncMock(return_value=completion_result)),
    ):
        stage = RiskPrioritizerStage()
        result = await stage.execute(_make_ctx())

    assert result == []


@pytest.mark.asyncio
async def test_every_asset_gets_a_finding():
    """With 5 input assets and a matching LLM response, exactly 5 Finding objects are written."""
    from app.agents.risk_prioritizer import RiskPrioritizerStage
    from app.models.finding import Finding

    added: list = []
    session_local = _make_session_local(added)
    completion_result = CompletionResult(
        content=_llm_findings(FAKE_FQDNS),
        prompt_tokens=200,
        completion_tokens=80,
    )

    with (
        patch("app.agents.risk_prioritizer.SessionLocal", session_local),
        patch("app.agents.risk_prioritizer.build_subdomain_rows", AsyncMock(return_value=FAKE_ROWS)),
        patch("app.agents.risk_prioritizer.build_port_rows", AsyncMock(return_value=[])),
        patch("app.agents.risk_prioritizer.bounded_completion", AsyncMock(return_value=completion_result)),
    ):
        stage = RiskPrioritizerStage()
        await stage.execute(_make_ctx())

    # added list should contain 5 Finding objects + 1 AiUsage object
    finding_objects = [obj for obj in added if isinstance(obj, Finding)]
    assert len(finding_objects) == 5


@pytest.mark.asyncio
async def test_ranks_are_contiguous():
    """Stage re-assigns priority_rank [1,2,3,4,5] even when LLM returns wrong ranks (all 99)."""
    from app.agents.risk_prioritizer import RiskPrioritizerStage
    from app.models.finding import Finding

    added: list = []
    session_local = _make_session_local(added)
    # Use scrambled ranks (all 99) so re-ranking code must actually do work
    completion_result = CompletionResult(
        content=_llm_findings_scrambled(FAKE_FQDNS),
        prompt_tokens=150,
        completion_tokens=60,
    )

    with (
        patch("app.agents.risk_prioritizer.SessionLocal", session_local),
        patch("app.agents.risk_prioritizer.build_subdomain_rows", AsyncMock(return_value=FAKE_ROWS)),
        patch("app.agents.risk_prioritizer.build_port_rows", AsyncMock(return_value=[])),
        patch("app.agents.risk_prioritizer.bounded_completion", AsyncMock(return_value=completion_result)),
    ):
        stage = RiskPrioritizerStage()
        await stage.execute(_make_ctx())

    finding_objects = [obj for obj in added if isinstance(obj, Finding)]
    ranks = sorted(f.priority_rank for f in finding_objects)
    assert ranks == [1, 2, 3, 4, 5]


@pytest.mark.asyncio
async def test_hallucinated_fqdn_dropped():
    """LLM returns 6 items (5 real + 1 fake FQDN not in scan) → only 5 findings written."""
    from app.agents.risk_prioritizer import RiskPrioritizerStage
    from app.models.finding import Finding

    added: list = []
    session_local = _make_session_local(added)

    # Build response with 5 real FQDNs + 1 hallucinated FQDN
    hallucinated = FAKE_FQDNS + ["hallucinated.notreal.example.com"]
    llm_content = _llm_findings(hallucinated)
    completion_result = CompletionResult(
        content=llm_content,
        prompt_tokens=120,
        completion_tokens=55,
    )

    with (
        patch("app.agents.risk_prioritizer.SessionLocal", session_local),
        patch("app.agents.risk_prioritizer.build_subdomain_rows", AsyncMock(return_value=FAKE_ROWS)),
        patch("app.agents.risk_prioritizer.build_port_rows", AsyncMock(return_value=[])),
        patch("app.agents.risk_prioritizer.bounded_completion", AsyncMock(return_value=completion_result)),
    ):
        stage = RiskPrioritizerStage()
        await stage.execute(_make_ctx())

    finding_objects = [obj for obj in added if isinstance(obj, Finding)]
    # Only 5 real FQDNs should produce findings — hallucinated one dropped
    assert len(finding_objects) == 5

    # Verify the hallucinated FQDN's asset_id is not in any finding.
    # The hallucinated row has no entry in FAKE_ROWS so its asset_id can never appear.
    real_asset_ids = {row.asset_id for row in FAKE_ROWS}
    finding_asset_ids = {f.asset_id for f in finding_objects}
    assert finding_asset_ids.issubset(real_asset_ids), "Hallucinated finding leaked through"


@pytest.mark.asyncio
async def test_llm_failure_propagates():
    """When bounded_completion raises BoundedCompletionError, it propagates out of execute()."""
    from app.agents.risk_prioritizer import RiskPrioritizerStage
    from app.agents.bounded_completion import BoundedCompletionError

    added: list = []
    session_local = _make_session_local(added)

    async def raise_bounded_completion_error(**kwargs):
        raise BoundedCompletionError("OpenRouter is down")

    with (
        patch("app.agents.risk_prioritizer.SessionLocal", session_local),
        patch("app.agents.risk_prioritizer.build_subdomain_rows", AsyncMock(return_value=FAKE_ROWS)),
        patch("app.agents.risk_prioritizer.build_port_rows", AsyncMock(return_value=[])),
        patch("app.agents.risk_prioritizer.bounded_completion", raise_bounded_completion_error),
    ):
        stage = RiskPrioritizerStage()
        with pytest.raises(BoundedCompletionError):
            await stage.execute(_make_ctx())
