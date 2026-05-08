# M3 Risk Prioritizer — Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add AI-powered risk prioritization to deep scans, writing ranked `Finding` rows via a `RiskPrioritizerStage` that calls `openai/gpt-oss-20b:free` via OpenRouter as the final DAG stage.

**Architecture:** `RiskPrioritizerStage` runs at L7 in the deep profile, after `GoWitnessStage`. It opens its own DB sessions, reads the asset graph via existing `scan_view` helpers, calls `bounded_completion()` (OpenRouter wrapper with JSON mode), writes `Finding` rows to a new `findings` table, and returns `[]`. `optional=True` means the scan completes even if the LLM call fails.

**Tech Stack:** SQLAlchemy 2.0 async, Pydantic v2, httpx, FastAPI, Alembic, pytest + pytest-asyncio, `unittest.mock`.

---

## File Map

**Create:**
- `backend/app/models/finding.py`
- `backend/app/models/ai_usage.py`
- `backend/app/agents/__init__.py`
- `backend/app/agents/bounded_completion.py`
- `backend/app/agents/risk_prioritizer.py`
- `backend/app/schemas/findings.py`
- `backend/tests/__init__.py`
- `backend/tests/unit/__init__.py`
- `backend/tests/unit/test_bounded_completion.py`
- `backend/tests/unit/test_risk_prioritizer.py`

**Modify:**
- `backend/app/models/__init__.py`
- `backend/app/core/config.py`
- `backend/app/services/scan_view.py`
- `backend/app/api/scans.py`
- `backend/app/pipeline/profiles.py`
- `infra/docker-compose.yml`
- `.env` (not committed)

---

## Task 1: ORM Models

**Files:**
- Create: `backend/app/models/finding.py`
- Create: `backend/app/models/ai_usage.py`
- Modify: `backend/app/models/__init__.py`

- [ ] **Step 1: Create `backend/app/models/finding.py`**

```python
from __future__ import annotations

import enum
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class FindingSeverity(str, enum.Enum):
    HIGH = "HIGH"
    MED = "MED"
    LOW = "LOW"
    INFO = "INFO"


class Finding(Base):
    """One risk-prioritization row per (scan, asset). Written by RiskPrioritizerStage.

    This is NOT an Asset — it lives in findings, not assets/asset_observations.
    The ENUM type 'finding_severity' is created explicitly in the migration
    (see CLAUDE.md ENUM gotcha — do not use sa.Enum with create_type=False in columns).
    """

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("scan_id", "asset_id", name="uq_finding_scan_asset"),
        UniqueConstraint("scan_id", "priority_rank", name="uq_finding_scan_rank"),
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=True
    )
    severity: Mapped[FindingSeverity] = mapped_column(
        Enum(FindingSeverity, name="finding_severity"), nullable=False
    )
    priority_rank: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    signals: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    recommended_action: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(20), nullable=False, default="llm")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
```

- [ ] **Step 2: Create `backend/app/models/ai_usage.py`**

```python
from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class AiUsage(Base):
    """One row per LLM call — tracks token consumption for cost visibility."""

    __tablename__ = "ai_usage"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
```

- [ ] **Step 3: Register models in `backend/app/models/__init__.py`**

Replace the entire file with:

```python
from app.models.asset import Asset, AssetObservation
from app.models.ai_usage import AiUsage
from app.models.finding import Finding, FindingSeverity
from app.models.org import Organization, Project, Target
from app.models.scan import Scan, ScanStage, ScanStatus, StageStatus
from app.models.user import User

__all__ = [
    "AiUsage",
    "Asset",
    "AssetObservation",
    "Finding",
    "FindingSeverity",
    "Organization",
    "Project",
    "Scan",
    "ScanStage",
    "ScanStatus",
    "StageStatus",
    "Target",
    "User",
]
```

---

## Task 2: Database Migration

**Files:**
- Create: `backend/migrations/versions/<rev>_add_findings_and_ai_usage.py`

- [ ] **Step 1: Generate a blank migration**

```bash
docker compose exec backend alembic revision -m "add findings and ai_usage tables"
```

Note the generated filename in `backend/migrations/versions/`. Open it.

- [ ] **Step 2: Replace the generated `upgrade()` and `downgrade()` with the exact code below**

Find the generated file (e.g. `backend/migrations/versions/xxxx_add_findings_and_ai_usage_tables.py`) and replace its body:

```python
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


def upgrade() -> None:
    # CLAUDE.md ENUM pattern: single postgresql.ENUM instance, create_type=False,
    # explicit .create() call, same instance referenced from the column.
    finding_severity = postgresql.ENUM(
        "HIGH", "MED", "LOW", "INFO",
        name="finding_severity",
        create_type=False,
    )
    finding_severity.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=True),
        sa.Column("severity", finding_severity, nullable=False),
        sa.Column("priority_rank", sa.Integer(), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("signals", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'[]'::jsonb")),
        sa.Column("recommended_action", sa.Text(), nullable=False),
        sa.Column("source", sa.String(20), nullable=False, server_default="llm"),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()")),
        sa.UniqueConstraint("scan_id", "asset_id", name="uq_finding_scan_asset"),
        sa.UniqueConstraint("scan_id", "priority_rank", name="uq_finding_scan_rank"),
    )
    op.create_index("ix_findings_scan_rank", "findings", ["scan_id", "priority_rank"])
    op.create_index("ix_findings_scan_severity", "findings", ["scan_id", "severity"])

    op.create_table(
        "ai_usage",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("model", sa.String(100), nullable=False),
        sa.Column("prompt_tokens", sa.Integer(), nullable=True),
        sa.Column("completion_tokens", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()")),
    )
    op.create_index("ix_ai_usage_scan_id", "ai_usage", ["scan_id"])


def downgrade() -> None:
    op.drop_table("ai_usage")
    op.drop_index("ix_findings_scan_severity", table_name="findings")
    op.drop_index("ix_findings_scan_rank", table_name="findings")
    op.drop_table("findings")
    postgresql.ENUM(name="finding_severity", create_type=False).drop(
        op.get_bind(), checkfirst=True
    )
```

- [ ] **Step 3: Apply the migration**

```bash
docker compose exec backend alembic upgrade head
```

Expected output ends with: `Running upgrade <prev> -> <new>, add findings and ai_usage tables`

- [ ] **Step 4: Verify tables exist**

```bash
docker compose exec postgres psql -U recon -d recon -c "\dt findings ai_usage"
```

Expected: both tables listed.

---

## Task 3: Config + Environment

**Files:**
- Modify: `backend/app/core/config.py`
- Modify: `infra/docker-compose.yml`
- Modify: `.env` (create if absent, never commit)

- [ ] **Step 1: Add `openrouter_api_key` to `backend/app/core/config.py`**

Add one line after `minio_bucket`:

```python
    minio_bucket: str = "recon"
    openrouter_api_key: str = ""          # required for deep scans; set via OPENROUTER_API_KEY env
```

- [ ] **Step 2: Add `OPENROUTER_API_KEY` to the worker service in `infra/docker-compose.yml`**

In the `worker:` → `environment:` block, add after `MINIO_BUCKET`:

```yaml
      OPENROUTER_API_KEY: ${OPENROUTER_API_KEY:-}
```

- [ ] **Step 3: Set the key in `.env`**

Create or edit `infra/.env` (or the root `.env` if you run compose from the project root):

```
OPENROUTER_API_KEY=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
```

Verify `.env` is in `.gitignore` — do not commit the key.

---

## Task 4: Pydantic Schemas

**Files:**
- Create: `backend/app/schemas/findings.py`

- [ ] **Step 1: Create `backend/app/schemas/findings.py`**

```python
"""Response schemas for GET /scans/{id}/findings."""
from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel


class FindingRow(BaseModel):
    finding_id: UUID
    asset_id: UUID | None
    fqdn: str
    severity: str           # HIGH | MED | LOW | INFO
    priority_rank: int      # 1 = highest risk
    risk_score: float       # 0.0–1.0
    rationale: str
    signals: list[str]
    recommended_action: str
    source: str             # "llm" | "fallback"


class FindingsPage(BaseModel):
    total: int
    items: list[FindingRow]
```

---

## Task 5: `bounded_completion.py` (TDD)

**Files:**
- Create: `backend/app/agents/__init__.py`
- Create: `backend/tests/__init__.py`
- Create: `backend/tests/unit/__init__.py`
- Create: `backend/tests/unit/test_bounded_completion.py`
- Create: `backend/app/agents/bounded_completion.py`

- [ ] **Step 1: Create empty `__init__.py` files**

Create three empty files:
- `backend/app/agents/__init__.py`
- `backend/tests/__init__.py`
- `backend/tests/unit/__init__.py`

All are empty (just a blank file).

- [ ] **Step 2: Write the failing tests**

Create `backend/tests/unit/test_bounded_completion.py`:

```python
"""Unit tests for bounded_completion — all OpenRouter calls are mocked."""
import json
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.config import get_settings


@pytest.fixture(autouse=True)
def api_key_env():
    """Inject a fake API key and clear the lru_cache so Settings re-reads env."""
    os.environ["OPENROUTER_API_KEY"] = "test-key-abc"
    get_settings.cache_clear()
    yield
    os.environ.pop("OPENROUTER_API_KEY", None)
    get_settings.cache_clear()


def _mock_client(status: int = 200, body: dict | None = None):
    """Build a mock httpx.AsyncClient that returns the given status and body."""
    if body is None:
        body = {
            "choices": [{"message": {"content": json.dumps({"findings": []})}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50},
        }
    mock_resp = MagicMock()
    if status >= 400:
        import httpx
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            f"HTTP {status}",
            request=MagicMock(),
            response=MagicMock(status_code=status),
        )
    else:
        mock_resp.raise_for_status = MagicMock()
    mock_resp.json = MagicMock(return_value=body)

    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    client.post = AsyncMock(return_value=mock_resp)
    return client


@pytest.mark.asyncio
async def test_happy_path_returns_completion_result():
    from app.agents.bounded_completion import bounded_completion, CompletionResult

    with patch("app.agents.bounded_completion.httpx.AsyncClient", return_value=_mock_client()):
        result = await bounded_completion(system="sys", user="user")

    assert isinstance(result, CompletionResult)
    assert result.content == {"findings": []}
    assert result.prompt_tokens == 100
    assert result.completion_tokens == 50


@pytest.mark.asyncio
async def test_http_429_raises_bounded_completion_error():
    from app.agents.bounded_completion import bounded_completion, BoundedCompletionError

    with patch("app.agents.bounded_completion.httpx.AsyncClient", return_value=_mock_client(status=429)):
        with pytest.raises(BoundedCompletionError, match="HTTP error"):
            await bounded_completion(system="sys", user="user")


@pytest.mark.asyncio
async def test_http_500_raises_bounded_completion_error():
    from app.agents.bounded_completion import bounded_completion, BoundedCompletionError

    with patch("app.agents.bounded_completion.httpx.AsyncClient", return_value=_mock_client(status=500)):
        with pytest.raises(BoundedCompletionError, match="HTTP error"):
            await bounded_completion(system="sys", user="user")


@pytest.mark.asyncio
async def test_input_truncated_when_over_limit():
    """Payload sent to OpenRouter must be ≤ max_input_chars; truncation marker appended."""
    from app.agents.bounded_completion import bounded_completion

    captured: dict = {}

    async def fake_post(url, json=None, headers=None):
        captured["payload"] = json
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={
            "choices": [{"message": {"content": "{\"findings\":[]}"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        })
        return mock_resp

    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    client.post = AsyncMock(side_effect=fake_post)

    long_user = "x" * 50_000
    with patch("app.agents.bounded_completion.httpx.AsyncClient", return_value=client):
        await bounded_completion(system="sys", user=long_user, max_input_chars=40_000)

    sent_user = captured["payload"]["messages"][1]["content"]
    assert len(sent_user) <= 40_100  # 40_000 + small truncation marker
    assert "[truncated" in sent_user


@pytest.mark.asyncio
async def test_missing_api_key_raises():
    os.environ.pop("OPENROUTER_API_KEY", None)
    get_settings.cache_clear()

    from app.agents.bounded_completion import bounded_completion, BoundedCompletionError

    with pytest.raises(BoundedCompletionError, match="OPENROUTER_API_KEY"):
        await bounded_completion(system="sys", user="user")
```

- [ ] **Step 3: Run tests — confirm they all FAIL (module not found)**

```bash
docker compose exec backend python -m pytest tests/unit/test_bounded_completion.py -v 2>&1 | tail -20
```

Expected: `ModuleNotFoundError: No module named 'app.agents.bounded_completion'`

- [ ] **Step 4: Implement `backend/app/agents/bounded_completion.py`**

```python
"""Async wrapper around OpenRouter's OpenAI-compatible API with JSON mode enforced.

Uses OPENROUTER_API_KEY from settings. Raises BoundedCompletionError on any failure
so callers can treat it as optional (scan stage is optional=True).
"""
from __future__ import annotations

import json
from typing import NamedTuple

import httpx

from app.core.config import get_settings

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


class BoundedCompletionError(RuntimeError):
    """Raised when the OpenRouter call fails for any reason."""


class CompletionResult(NamedTuple):
    content: dict           # parsed JSON from model response
    prompt_tokens: int
    completion_tokens: int


async def bounded_completion(
    *,
    system: str,
    user: str,
    model: str = "openai/gpt-oss-20b:free",
    max_input_chars: int = 40_000,
    timeout: float = 120.0,
) -> CompletionResult:
    """Call OpenRouter with JSON mode and a hard input character cap.

    If len(user) > max_input_chars, the user string is truncated and a
    '[truncated: input exceeded limit]' marker is appended so the model
    knows the list is incomplete.

    Returns CompletionResult on success.
    Raises BoundedCompletionError on HTTP error, timeout, or empty API key.
    """
    api_key = get_settings().openrouter_api_key
    if not api_key:
        raise BoundedCompletionError(
            "OPENROUTER_API_KEY is not set — cannot call risk prioritizer"
        )

    if len(user) > max_input_chars:
        user = user[:max_input_chars] + "\n[truncated: input exceeded limit]"

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "response_format": {"type": "json_object"},
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                OPENROUTER_URL,
                json=payload,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
            )
            resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise BoundedCompletionError(
            f"OpenRouter HTTP error: {exc.response.status_code}"
        ) from exc
    except httpx.TimeoutException as exc:
        raise BoundedCompletionError("OpenRouter request timed out") from exc

    data = resp.json()
    try:
        raw = data["choices"][0]["message"]["content"]
        content = json.loads(raw)
    except (KeyError, IndexError, json.JSONDecodeError) as exc:
        raise BoundedCompletionError(
            f"Failed to parse OpenRouter response: {exc}"
        ) from exc

    usage = data.get("usage") or {}
    return CompletionResult(
        content=content,
        prompt_tokens=int(usage.get("prompt_tokens") or 0),
        completion_tokens=int(usage.get("completion_tokens") or 0),
    )
```

- [ ] **Step 5: Run tests — confirm they all PASS**

```bash
docker compose exec backend python -m pytest tests/unit/test_bounded_completion.py -v
```

Expected: `5 passed`

---

## Task 6: `RiskPrioritizerStage` (TDD)

**Files:**
- Create: `backend/tests/unit/test_risk_prioritizer.py`
- Create: `backend/app/agents/risk_prioritizer.py`

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/unit/test_risk_prioritizer.py`:

```python
"""Unit tests for RiskPrioritizerStage.

bounded_completion, SessionLocal, build_subdomain_rows, and build_port_rows
are all mocked. No DB or network calls happen.
"""
from __future__ import annotations

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from app.agents.bounded_completion import BoundedCompletionError, CompletionResult
from app.pipeline.stage import StageContext

SCAN_ID = uuid4()
TARGET_ID = uuid4()


def _row(subdomain: str, *, waf: str | None = None, status: int | None = 200) -> MagicMock:
    r = MagicMock()
    r.subdomain = subdomain
    r.asset_id = uuid4()
    r.http_status = status
    r.waf = waf
    r.waf_conf = None
    r.cdn = False
    r.cdn_name = None
    r.tech = []
    r.server = "nginx/1.18"
    r.screenshot_url = None
    r.first_seen = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return r


FAKE_ROWS = [
    _row("admin.example.com"),
    _row("api.example.com"),
    _row("www.example.com", waf="Cloudflare WAF"),
    _row("staging.example.com"),
    _row("dev.example.com", status=None),
]


def _llm_findings(rows: list) -> dict:
    return {
        "findings": [
            {
                "fqdn": r.subdomain,
                "severity": "HIGH" if i == 0 else ("MED" if i < 3 else "LOW"),
                "risk_score": round(0.9 - i * 0.15, 2),
                "priority_rank": i + 1,
                "rationale": f"Risk assessment for {r.subdomain}",
                "signals": ["no_waf"] if not r.waf else [],
                "recommended_action": "Review" if i == 0 else "Monitor",
            }
            for i, r in enumerate(rows)
        ]
    }


@pytest.fixture
def mock_env():
    """Mock DB sessions, build helpers, and return the write-session mock."""
    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    mock_session.execute = AsyncMock()
    mock_session.add = MagicMock()
    mock_session.commit = AsyncMock()

    with patch("app.agents.risk_prioritizer.SessionLocal", return_value=mock_session):
        with patch(
            "app.agents.risk_prioritizer.build_subdomain_rows",
            new_callable=AsyncMock,
            return_value=FAKE_ROWS,
        ):
            with patch(
                "app.agents.risk_prioritizer.build_port_rows",
                new_callable=AsyncMock,
                return_value=[],
            ):
                yield mock_session


@pytest.mark.asyncio
async def test_returns_empty_list(mock_env):
    from app.agents.risk_prioritizer import RiskPrioritizerStage

    llm = CompletionResult(content=_llm_findings(FAKE_ROWS), prompt_tokens=500, completion_tokens=200)
    with patch("app.agents.risk_prioritizer.bounded_completion", new_callable=AsyncMock, return_value=llm):
        result = await RiskPrioritizerStage().execute(
            StageContext(scan_id=SCAN_ID, target_id=TARGET_ID, domain="example.com")
        )
    assert result == []


@pytest.mark.asyncio
async def test_every_asset_gets_a_finding(mock_env):
    from app.agents.risk_prioritizer import RiskPrioritizerStage
    from app.models.finding import Finding

    added: list = []
    mock_env.add = MagicMock(side_effect=added.append)

    llm = CompletionResult(content=_llm_findings(FAKE_ROWS), prompt_tokens=500, completion_tokens=200)
    with patch("app.agents.risk_prioritizer.bounded_completion", new_callable=AsyncMock, return_value=llm):
        await RiskPrioritizerStage().execute(
            StageContext(scan_id=SCAN_ID, target_id=TARGET_ID, domain="example.com")
        )

    findings = [a for a in added if isinstance(a, Finding)]
    assert len(findings) == 5


@pytest.mark.asyncio
async def test_ranks_are_contiguous(mock_env):
    from app.agents.risk_prioritizer import RiskPrioritizerStage
    from app.models.finding import Finding

    added: list = []
    mock_env.add = MagicMock(side_effect=added.append)

    llm = CompletionResult(content=_llm_findings(FAKE_ROWS), prompt_tokens=500, completion_tokens=200)
    with patch("app.agents.risk_prioritizer.bounded_completion", new_callable=AsyncMock, return_value=llm):
        await RiskPrioritizerStage().execute(
            StageContext(scan_id=SCAN_ID, target_id=TARGET_ID, domain="example.com")
        )

    findings = [a for a in added if isinstance(a, Finding)]
    ranks = sorted(f.priority_rank for f in findings)
    assert ranks == list(range(1, 6))


@pytest.mark.asyncio
async def test_hallucinated_fqdn_dropped(mock_env):
    from app.agents.risk_prioritizer import RiskPrioritizerStage
    from app.models.finding import Finding

    added: list = []
    mock_env.add = MagicMock(side_effect=added.append)

    bad = _llm_findings(FAKE_ROWS)
    bad["findings"].append({
        "fqdn": "notreal.example.com",
        "severity": "HIGH",
        "risk_score": 0.99,
        "priority_rank": 1,
        "rationale": "Hallucinated",
        "signals": [],
        "recommended_action": "Ignore",
    })
    llm = CompletionResult(content=bad, prompt_tokens=500, completion_tokens=200)
    with patch("app.agents.risk_prioritizer.bounded_completion", new_callable=AsyncMock, return_value=llm):
        await RiskPrioritizerStage().execute(
            StageContext(scan_id=SCAN_ID, target_id=TARGET_ID, domain="example.com")
        )

    findings = [a for a in added if isinstance(a, Finding)]
    assert len(findings) == 5  # 6 from LLM, 1 hallucinated → 5 written


@pytest.mark.asyncio
async def test_llm_failure_propagates(mock_env):
    from app.agents.risk_prioritizer import RiskPrioritizerStage

    with patch(
        "app.agents.risk_prioritizer.bounded_completion",
        new_callable=AsyncMock,
        side_effect=BoundedCompletionError("API down"),
    ):
        with pytest.raises(BoundedCompletionError):
            await RiskPrioritizerStage().execute(
                StageContext(scan_id=SCAN_ID, target_id=TARGET_ID, domain="example.com")
            )
```

- [ ] **Step 2: Run tests — confirm FAIL (module not found)**

```bash
docker compose exec backend python -m pytest tests/unit/test_risk_prioritizer.py -v 2>&1 | tail -10
```

Expected: `ModuleNotFoundError: No module named 'app.agents.risk_prioritizer'`

- [ ] **Step 3: Implement `backend/app/agents/risk_prioritizer.py`**

```python
"""RiskPrioritizerStage — AI analysis stage (DAG L7, deep profile only).

This stage is an intentional exception to the 'adapters never touch DB' rule that
applies to tool adapter stages. Tool adapters write assets (handled by upsert_assets);
this stage reads the asset graph and writes to the findings table. It is the only
stage in this category for M3.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import delete

from app.agents.bounded_completion import BoundedCompletionError, bounded_completion
from app.core.db import SessionLocal
from app.models.ai_usage import AiUsage
from app.models.finding import Finding, FindingSeverity
from app.pipeline.stage import AssetRecord, StageContext
from app.services.scan_view import build_port_rows, build_subdomain_rows

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are a security analyst ranking reconnaissance findings by attack-surface risk.

Given a JSON list of assets from a deep scan, return a JSON object with key
"findings" containing ALL assets ranked from highest to lowest risk.

For each asset output exactly these fields:
  fqdn              string   (copy from input, unchanged)
  severity          string   HIGH | MED | LOW | INFO
  risk_score        float    0.0-1.0 (higher = more critical)
  priority_rank     integer  1=highest risk, contiguous integers, no gaps or duplicates
  rationale         string   1-2 sentences explaining the specific risk
  signals           array    short snake_case tags e.g. ["no_waf","open_admin_port"]
  recommended_action string  one imperative sentence

Ranking criteria (highest weight first):
  - Exposed admin or login interfaces (path or subdomain contains admin, login, dashboard)
  - Missing WAF on a live HTTP service (waf field is null or empty)
  - Outdated or known-vulnerable server software (server field contains version numbers)
  - Open non-standard ports (ports other than 80, 443)
  - Recently appeared assets (first_seen_days_ago < 7)
  - No CDN fronting on a direct-IP asset (cdn is false and no cdn_name)

Every asset in the input MUST appear in the output exactly once.
Severity should reflect genuine risk: not everything is HIGH or MED.
"""


class RiskPrioritizerStage:
    """Final stage in the deep profile DAG — ranks all assets by risk using an LLM.

    Opens its own DB sessions (exception to the adapter no-DB rule — see module docstring).
    Returns [] always; writes to findings + ai_usage tables directly.
    """

    name = "risk_prioritizer"
    source_tool = "risk_prioritizer"
    depends_on = ["gowitness"]
    inputs: list[str] = []
    outputs: list[str] = []
    weight = 15
    optional = True
    authz_required = False

    async def execute(self, ctx: StageContext) -> list[AssetRecord]:
        # --- Session 1: read asset graph ---
        async with SessionLocal() as db:
            subdomain_rows = await build_subdomain_rows(db, ctx.scan_id)
            port_rows = await build_port_rows(db, ctx.scan_id)

        if not subdomain_rows:
            logger.info("risk_prioritizer: no subdomain assets for scan %s — skipping", ctx.scan_id)
            return []

        # FQDN → SubdomainRow (hallucination guard index)
        asset_index = {row.subdomain: row for row in subdomain_rows}

        # FQDN → ["80/tcp", "443/tcp", ...]
        port_lookup: dict[str, list[str]] = {}
        for pr in port_rows:
            port_lookup.setdefault(pr.host, []).append(f"{pr.port}/{pr.proto}")

        # Serialize to compact JSON for LLM
        now = datetime.now(timezone.utc)
        asset_list = []
        for row in subdomain_rows:
            first_seen = row.first_seen
            if first_seen is not None and first_seen.tzinfo is None:
                first_seen = first_seen.replace(tzinfo=timezone.utc)
            days_ago = (now - first_seen).days if first_seen else None
            asset_list.append({
                "fqdn": row.subdomain,
                "http_status": row.http_status,
                "waf": row.waf,
                "waf_conf": row.waf_conf,
                "cdn": row.cdn,
                "cdn_name": row.cdn_name,
                "ports": port_lookup.get(row.subdomain, []),
                "tech": list(row.tech or []),
                "server": row.server,
                "screenshot": row.screenshot_url is not None,
                "first_seen_days_ago": days_ago,
            })

        # --- LLM call (raises BoundedCompletionError on failure) ---
        result = await bounded_completion(
            system=SYSTEM_PROMPT,
            user=json.dumps(asset_list),
        )

        raw = result.content.get("findings") or []

        # Hallucination guard: drop FQDNs not in this scan
        valid = []
        for item in raw:
            fqdn = item.get("fqdn", "")
            if fqdn not in asset_index:
                logger.warning("risk_prioritizer: dropping hallucinated FQDN %r", fqdn)
                continue
            valid.append(item)

        # Re-rank by risk_score DESC — normalises gaps/duplicates the model may emit
        valid.sort(key=lambda x: float(x.get("risk_score") or 0.0), reverse=True)
        for i, item in enumerate(valid, 1):
            if item.get("priority_rank") != i:
                logger.warning(
                    "risk_prioritizer: re-numbering %r: %s → %s",
                    item.get("fqdn"), item.get("priority_rank"), i,
                )
            item["priority_rank"] = i

        # --- Session 2: write findings ---
        async with SessionLocal() as db:
            # Delete existing rows first — idempotent if stage is re-run
            await db.execute(delete(Finding).where(Finding.scan_id == ctx.scan_id))

            for item in valid:
                fqdn = item["fqdn"]
                row = asset_index[fqdn]
                severity_str = (item.get("severity") or "INFO").upper()
                try:
                    severity = FindingSeverity[severity_str]
                except KeyError:
                    severity = FindingSeverity.INFO

                db.add(Finding(
                    scan_id=ctx.scan_id,
                    asset_id=row.asset_id,
                    severity=severity,
                    priority_rank=item["priority_rank"],
                    risk_score=float(item.get("risk_score") or 0.0),
                    rationale=str(item.get("rationale") or ""),
                    signals=list(item.get("signals") or []),
                    recommended_action=str(item.get("recommended_action") or ""),
                    source="llm",
                ))

            db.add(AiUsage(
                scan_id=ctx.scan_id,
                model="openai/gpt-oss-20b:free",
                prompt_tokens=result.prompt_tokens,
                completion_tokens=result.completion_tokens,
            ))
            await db.commit()

        logger.info(
            "risk_prioritizer: wrote %d findings for scan %s (%d prompt + %d completion tokens)",
            len(valid), ctx.scan_id, result.prompt_tokens, result.completion_tokens,
        )
        return []
```

- [ ] **Step 4: Run tests — confirm all PASS**

```bash
docker compose exec backend python -m pytest tests/unit/test_risk_prioritizer.py -v
```

Expected: `5 passed`

---

## Task 7: DAG Integration

**Files:**
- Modify: `backend/app/pipeline/profiles.py`

- [ ] **Step 1: Add `RiskPrioritizerStage` to the deep profile**

In `backend/app/pipeline/profiles.py`, add the import at the top:

```python
from app.agents.risk_prioritizer import RiskPrioritizerStage
```

Then update the `"deep"` profile list — add `RiskPrioritizerStage()` as the last entry:

```python
    "deep": [
        SubfinderStage(),
        AssetfinderStage(),
        AmassStage(),
        DnsxStage(),
        HttpxStage(),
        AsnmapStage(),
        GeoipStage(),
        Wafw00fStage(),
        NaabuStage(),
        NmapStage(),
        GoWitnessStage(),
        RiskPrioritizerStage(),   # L7 — AI analysis, runs after all enrichment
    ],
```

- [ ] **Step 2: Verify the DAG resolves without import errors**

```bash
docker compose exec backend python -c "from app.pipeline.profiles import stages_for; print([s.name for s in stages_for('deep')])"
```

Expected output (last item must be `risk_prioritizer`):
```
['subfinder', 'assetfinder', 'amass', 'dnsx', 'httpx', 'asnmap', 'geoip', 'wafw00f', 'naabu', 'nmap', 'gowitness', 'risk_prioritizer']
```

---

## Task 8: API Endpoint

**Files:**
- Modify: `backend/app/services/scan_view.py`
- Modify: `backend/app/api/scans.py`

- [ ] **Step 1: Add `build_findings()` to `backend/app/services/scan_view.py`**

Add these imports at the top of `scan_view.py` (after the existing imports):

```python
from sqlalchemy import func

from app.models.finding import Finding
from app.schemas.findings import FindingRow
```

Then add this function at the end of the file:

```python
async def build_findings(
    db: AsyncSession,
    scan_id: UUID,
    severity: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> tuple[int, list[FindingRow]]:
    """Return paginated findings ordered by priority_rank ASC (1 = highest risk)."""
    # Asset is already imported at the top of this file

    count_q = select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
    if severity:
        count_q = count_q.where(Finding.severity == severity)
    total: int = await db.scalar(count_q) or 0

    data_q = (
        select(Finding, Asset.canonical_key)
        .join(Asset, Asset.id == Finding.asset_id, isouter=True)
        .where(Finding.scan_id == scan_id)
    )
    if severity:
        data_q = data_q.where(Finding.severity == severity)
    data_q = data_q.order_by(Finding.priority_rank).offset(offset).limit(limit)

    rows = (await db.execute(data_q)).all()
    items = [
        FindingRow(
            finding_id=finding.id,
            asset_id=finding.asset_id,
            fqdn=fqdn or "",
            severity=finding.severity.value,
            priority_rank=finding.priority_rank,
            risk_score=finding.risk_score,
            rationale=finding.rationale,
            signals=list(finding.signals or []),
            recommended_action=finding.recommended_action,
            source=finding.source,
        )
        for finding, fqdn in rows
    ]
    return total, items
```

- [ ] **Step 2: Add `GET /scans/{id}/findings` route to `backend/app/api/scans.py`**

Add these imports at the top of `scans.py` (after existing imports):

```python
from app.schemas.findings import FindingsPage
```

Then add this route at the end of the file (before the `/stream` route is fine, or after — order doesn't matter):

```python
@router.get("/{scan_id}/findings", response_model=FindingsPage)
async def get_scan_findings(
    scan_id: UUID,
    severity: str | None = Query(None, pattern="^(HIGH|MED|LOW|INFO)$"),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> FindingsPage:
    """Prioritized risk findings for a deep scan, ordered by priority_rank ASC."""
    await _ensure_scan_visible(db, scan_id, user)
    offset = (page - 1) * limit
    total, items = await scan_view.build_findings(db, scan_id, severity=severity, offset=offset, limit=limit)
    return FindingsPage(total=total, items=items)
```

- [ ] **Step 3: Restart the backend and verify the route appears in API docs**

```bash
docker compose restart backend
```

Then open `http://localhost:8000/docs` and confirm `GET /scans/{scan_id}/findings` appears under the **scans** tag.

---

## Task 9: End-to-End Smoke Verification

- [ ] **Step 1: Run all unit tests**

```bash
docker compose exec backend python -m pytest tests/unit/ -v
```

Expected: `9 passed` (5 bounded_completion + 4... wait, let me re-count: 5 bounded_completion + 5 risk_prioritizer = 10... actually looking at the tests: 5 + 5 = 10 total)

Expected: `10 passed`

- [ ] **Step 2: Trigger a deep scan against a verified target**

Using the existing API (swap `<TOKEN>` and `<DOMAIN>` for your values):

```bash
curl -s -X POST http://localhost:8000/scans \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"domain": "<DOMAIN>", "profile": "deep"}' | python -m json.tool
```

Note the returned `id` as `SCAN_ID`.

- [ ] **Step 3: Watch the worker logs for risk_prioritizer stage**

```bash
docker compose logs -f worker | grep -E "(risk_prioritizer|findings|BoundedCompletion)"
```

Expected lines (in order):
```
stage.started stage=risk_prioritizer
risk_prioritizer: wrote N findings for scan ... (X prompt + Y completion tokens)
stage.completed stage=risk_prioritizer
```

- [ ] **Step 4: Query the findings endpoint**

```bash
curl -s "http://localhost:8000/scans/<SCAN_ID>/findings?limit=5" \
  -H "Authorization: Bearer <TOKEN>" | python -m json.tool
```

Expected shape:
```json
{
  "total": 16,
  "items": [
    {
      "finding_id": "...",
      "asset_id": "...",
      "fqdn": "admin.example.com",
      "severity": "HIGH",
      "priority_rank": 1,
      "risk_score": 0.9,
      "rationale": "...",
      "signals": ["no_waf"],
      "recommended_action": "...",
      "source": "llm"
    }
  ]
}
```

Verify:
- `total` equals the number of subdomains found in the scan
- `items[0].priority_rank == 1`
- `items` are ordered by `priority_rank` ASC
- `severity` values are one of `HIGH`, `MED`, `LOW`, `INFO`

- [ ] **Step 5: Verify severity filter works**

```bash
curl -s "http://localhost:8000/scans/<SCAN_ID>/findings?severity=HIGH" \
  -H "Authorization: Bearer <TOKEN>" | python -m json.tool | grep severity
```

Expected: every `"severity"` line says `"HIGH"`.

- [ ] **Step 6: Verify `ai_usage` row was written**

```bash
docker compose exec postgres psql -U recon -d recon \
  -c "SELECT model, prompt_tokens, completion_tokens FROM ai_usage ORDER BY created_at DESC LIMIT 1;"
```

Expected: one row with `model = openai/gpt-oss-20b:free` and non-zero token counts.
