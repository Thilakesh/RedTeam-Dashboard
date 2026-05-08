# M3 Risk Prioritizer — Backend Design Spec

**Date:** 2026-05-07
**Scope:** Backend only — `findings` data model, AI analysis stage, DAG integration, API endpoint.
**Profile:** Deep scans only.
**Model:** `openai/gpt-oss-20b:free` via OpenRouter (JSON mode, no parse retries needed).
**Approach:** Approach B — `RiskPrioritizerStage` as a full DAG stage (AI analysis stage category, documented exception to "no DB" adapter rule).

---

## 1. Data Model

### New table: `findings`

```sql
CREATE TABLE findings (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id            UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id           UUID REFERENCES assets(id) ON DELETE CASCADE,  -- nullable (future scan-level findings)
    severity           finding_severity NOT NULL,   -- HIGH | MED | LOW | INFO
    priority_rank      INTEGER NOT NULL,            -- 1 = highest risk, contiguous 1..N per scan
    risk_score         FLOAT NOT NULL,              -- 0.0–1.0
    rationale          TEXT NOT NULL,
    signals            JSONB NOT NULL DEFAULT '[]', -- ["no_waf", "open_admin_port", ...]
    recommended_action TEXT NOT NULL,
    source             VARCHAR(20) NOT NULL DEFAULT 'llm',  -- 'llm' | 'fallback'
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (scan_id, asset_id),       -- one finding per asset per scan
    UNIQUE (scan_id, priority_rank)   -- ranks are unique within a scan
);

CREATE INDEX ix_findings_scan_rank     ON findings (scan_id, priority_rank);
CREATE INDEX ix_findings_scan_severity ON findings (scan_id, severity);
```

### New table: `ai_usage`

```sql
CREATE TABLE ai_usage (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id           UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    model             VARCHAR(100) NOT NULL,
    prompt_tokens     INTEGER,
    completion_tokens INTEGER,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### Notes

- `severity` is a new Postgres ENUM `finding_severity`. Follow the pattern in `migrations/versions/0001_initial.py`: create one `postgresql.ENUM` instance, call `.create(checkfirst=True)`, reference the same instance from the column — do not use `sa.Enum(create_type=False)` in the column definition.
- `asset_id` is nullable to reserve space for future scan-level findings (e.g. attack-path rows spanning multiple assets). Every M3 row will have a non-null `asset_id`.
- Migration: `alembic revision --autogenerate -m "add findings and ai_usage tables"`.
- Register both models in `backend/app/models/__init__.py`.

### New files

- `backend/app/models/finding.py` — `Finding` ORM model
- `backend/app/models/ai_usage.py` — `AiUsage` ORM model

---

## 2. Agent Architecture

### `backend/app/agents/bounded_completion.py`

Thin async wrapper around OpenRouter's OpenAI-compatible API.

```python
class BoundedCompletionError(RuntimeError): ...

async def bounded_completion(
    *,
    system: str,
    user: str,
    model: str = "openai/gpt-oss-20b:free",
    max_input_chars: int = 40_000,
    timeout: float = 120.0,
) -> dict:
    """
    Call OpenRouter with JSON mode enforced.

    If len(user) > max_input_chars, truncates the user string to max_input_chars
    and appends '[truncated: input exceeded limit]' so the model knows.

    Returns parsed dict on success.
    Raises BoundedCompletionError on HTTP error, timeout, or non-JSON response body.
    """
```

**Implementation details:**
- Uses `httpx.AsyncClient` (already a project dependency).
- `Authorization: Bearer {OPENROUTER_API_KEY}` header.
- `response_format={"type": "json_object"}` in request body — JSON mode guaranteed.
- Reads `OPENROUTER_API_KEY` from `get_settings()`. Raises `BoundedCompletionError` at call time if key is empty.
- Returns `response.json()["choices"][0]["message"]["content"]` parsed as JSON.
- Extracts `usage.prompt_tokens` and `usage.completion_tokens` from response.
- Returns a `CompletionResult(content: dict, prompt_tokens: int, completion_tokens: int)` NamedTuple so callers can write `ai_usage` rows without a second API call.

### `backend/app/agents/risk_prioritizer.py`

`RiskPrioritizerStage` — an **AI analysis stage**. Reads from DB, writes to `findings`, returns `[]`.

This stage is an intentional exception to the "adapters never touch DB" rule that applies to tool adapter stages. The distinction: tool adapters write assets (handled by `upsert_assets`); AI analysis stages read the full asset graph and write to domain-specific tables (`findings`). This is the only such stage in M3.

#### Stage attributes

```python
name           = "risk_prioritizer"
source_tool    = "risk_prioritizer"
depends_on     = ["gowitness"]   # last deep stage — ensures all enrichment is present
inputs         = []              # reads from DB directly, not from coordinator inputs
outputs        = []
weight         = 15              # ~15s expected wall-clock
optional       = True            # scan completes even if LLM call fails
authz_required = False
```

#### `execute()` flow

```
1. Open SessionLocal session
   → call build_subdomain_rows(db, scan_id)   [from services/scan_view.py]
   → call build_port_rows(db, scan_id)         [from services/scan_view.py]

2. Build asset_index: {fqdn → SubdomainRow} for hallucination guard

3. Serialize asset list to compact JSON:
   [{
     fqdn, http_status, waf, waf_conf, cdn, cdn_name,
     ports: ["80/tcp", "443/tcp"],
     tech: ["nginx", "React"],
     server,
     screenshot: bool,
     first_seen_days_ago: int
   }]

4. Call bounded_completion(system=SYSTEM_PROMPT, user=json.dumps(asset_list))
   → raises BoundedCompletionError on failure → stage marked failed (optional=True)

5. Parse response["findings"] list
   → for each item: look up asset_id via asset_index[item["fqdn"]]
   → drop items whose fqdn is not in asset_index (hallucination guard, log warning)
   → sort surviving items by risk_score DESC, re-assign priority_rank=1..N in that order
     (normalises gaps or duplicates the model may emit; logs a warning if re-numbering occurs)

6. Open SessionLocal session
   → INSERT INTO findings (...) ON CONFLICT (scan_id, asset_id) DO UPDATE
   → INSERT INTO ai_usage (scan_id, model, prompt_tokens, completion_tokens)

7. Return []
```

#### System prompt (static, not user-controllable)

```
You are a security analyst ranking reconnaissance findings by attack-surface risk.

Given a JSON list of assets from a deep scan, return a JSON object with key
"findings" containing ALL assets ranked from highest to lowest risk.

For each asset output exactly these fields:
  fqdn              string   (copy from input)
  severity          string   HIGH | MED | LOW | INFO
  risk_score        float    0.0–1.0
  priority_rank     integer  1=highest risk, contiguous, no gaps
  rationale         string   1-2 sentences explaining the risk
  signals           array    short tags, e.g. ["no_waf","open_admin_port","outdated_software"]
  recommended_action string  one imperative sentence

Ranking criteria (highest weight first):
  - Exposed admin or login interfaces (path contains /admin, /login, /dashboard)
  - Missing WAF on a live HTTP service (waf is null/empty)
  - Outdated or known-vulnerable server software (server header contains version)
  - Open non-standard ports (ports other than 80, 443)
  - Recently appeared assets (first_seen_days_ago < 7)
  - No CDN fronting on a direct-IP asset

Every asset in the input MUST appear in the output exactly once.
Severity distribution should reflect genuine risk: not everything is HIGH.
```

---

## 3. DAG Integration

### `profiles.py`

```python
from app.agents.risk_prioritizer import RiskPrioritizerStage

PROFILES = {
    "quick":    [...],
    "standard": [...],
    "deep": [
        SubfinderStage(), AssetfinderStage(), AmassStage(),
        DnsxStage(), HttpxStage(), AsnmapStage(), GeoipStage(),
        Wafw00fStage(), NaabuStage(), NmapStage(), GoWitnessStage(),
        RiskPrioritizerStage(),   # L7 — runs after all enrichment complete
    ],
}
```

### `core/config.py`

```python
openrouter_api_key: str = ""  # required for deep scans; BoundedCompletionError if empty at call time
```

### `infra/docker-compose.yml` — worker env

```yaml
OPENROUTER_API_KEY: ${OPENROUTER_API_KEY}
```

### `.env` (not committed, add to `.gitignore` if not already)

```
OPENROUTER_API_KEY=sk-or-v1-...
```

### Execution flow

```
execute_dag() levels (deep profile):
  L0: subfinder + assetfinder
  L1: amass + dnsx
  L2: httpx + asnmap + geoip
  L3: wafw00f
  L4: naabu
  L5: nmap
  L6: gowitness
  L7: risk_prioritizer          ← new
        ↓
  runner: on_done(records=[])
    → upsert_assets() no-ops (empty list)
    → scan_stage marked completed
    → "stage.completed" pub/sub fires (assets_found=0)
        ↓
  scan marked completed, progress_pct=100
```

### Error path

If `bounded_completion()` raises for any reason:
- Coordinator calls `on_fail()` → `scan_stages` row marked `failed`, error stored
- Because `optional=True`, DAG does **not** abort
- `scan.completed` fires normally
- Risks tab shows empty state: *"Risk analysis unavailable for this scan."*

---

## 4. API Endpoint

### `GET /scans/{id}/findings`

**Location:** `backend/app/api/scan_view.py` (alongside all other per-scan read endpoints)

**Query parameters:**

| Param    | Type   | Default | Description                          |
|----------|--------|---------|--------------------------------------|
| severity | string | —       | Filter: `HIGH`, `MED`, `LOW`, `INFO` |
| page     | int    | 1       |                                      |
| limit    | int    | 50      | Max 200                              |

**Response: `FindingsPage`**

```python
class FindingRow(BaseModel):
    finding_id:         UUID
    asset_id:           UUID
    fqdn:               str
    severity:           str        # HIGH | MED | LOW | INFO
    priority_rank:      int        # 1 = highest risk
    risk_score:         float
    rationale:          str
    signals:            list[str]
    recommended_action: str
    source:             str        # "llm" | "fallback"

class FindingsPage(BaseModel):
    total: int
    items: list[FindingRow]
```

**Tenant scoping:** `findings → scans.org_id == current_user.org_id`. Returns 404 if scan not found or belongs to different org.

**Empty state:** `{"total": 0, "items": []}` — not 404. Frontend uses `scan.profile` (already in `GET /scans/{id}`) to distinguish "deep scan with failed prioritizer" from "standard/quick scan where prioritizer never ran."

### New schema file

`backend/app/schemas/findings.py` — `FindingRow`, `FindingsPage`

### `scan_view.py` helper

```python
async def build_findings(
    db: AsyncSession,
    scan_id: UUID,
    severity: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> tuple[int, list[FindingRow]]:
    q = (
        select(Finding, Asset.canonical_key)
        .join(Asset, Asset.id == Finding.asset_id)
        .where(Finding.scan_id == scan_id)
    )
    if severity:
        q = q.where(Finding.severity == severity)
    total = await db.scalar(select(func.count()).select_from(q.subquery()))
    rows = (await db.execute(
        q.order_by(Finding.priority_rank).offset(offset).limit(limit)
    )).all()
    return total, [FindingRow(...) for finding, fqdn in rows]
```

---

## 5. Testing Strategy

### Layer 1 — Unit: `bounded_completion`

**File:** `tests/unit/test_bounded_completion.py`
**Mock:** `respx` to intercept `httpx` calls

| Test | Assertion |
|------|-----------|
| Happy path | Valid JSON response → parsed dict returned |
| HTTP 429 | `BoundedCompletionError` raised |
| HTTP 500 | `BoundedCompletionError` raised |
| Input truncation | Payload sent to OpenRouter ≤ `max_input_chars`; body contains `[truncated` marker |
| Missing API key | `BoundedCompletionError` raised before HTTP call |

### Layer 2 — Unit: `RiskPrioritizerStage`

**File:** `tests/unit/test_risk_prioritizer.py`
**Mocks:** `bounded_completion`, `SessionLocal` (fixture injects 5 known assets)

| Test | Assertion |
|------|-----------|
| Coverage | `len(findings_written) == 5` — every input asset has exactly one Finding |
| Rank contiguity | `sorted([f.priority_rank for f in findings]) == [1, 2, 3, 4, 5]` |
| Severity ordering | All HIGH rows have lower `priority_rank` than all MED rows, etc. |
| Hallucination guard | LLM returns extra FQDN not in scan → that row dropped; all 5 real assets still written |
| Stage optional | `bounded_completion` raises → `BoundedCompletionError` propagates; scan_stage marked failed |

### Layer 3 — Integration: findings endpoint

**File:** `tests/integration/test_findings_api.py`
**Infrastructure:** `testcontainers` (Postgres + Redis)

| Test | Assertion |
|------|-----------|
| Ordered results | 3 findings inserted → response items sorted by `priority_rank` |
| Severity filter | `?severity=HIGH` returns only HIGH rows |
| Tenant isolation | Request from different org → 404 |
| Wrong profile | Standard-profile scan → `{"total": 0, "items": []}` |
| Pagination | `?page=2&limit=2` with 5 findings → 2 items, correct offset |

### Explicitly out of scope

- Real OpenRouter API calls in tests (flaky, consumes quota — all mocked)
- Load testing the LLM call
- Frontend Playwright tests for the Risks tab (separate spec, M3 frontend)

---

## 6. New Files Summary

```
backend/
  app/
    agents/
      __init__.py
      bounded_completion.py
      risk_prioritizer.py
    models/
      finding.py
      ai_usage.py
    schemas/
      findings.py
  tests/
    unit/
      test_bounded_completion.py
      test_risk_prioritizer.py
    integration/
      test_findings_api.py

migrations/
  versions/XXXX_add_findings_and_ai_usage_tables.py
```

### Modified files

| File | Change |
|------|--------|
| `backend/app/models/__init__.py` | Register `Finding`, `AiUsage` |
| `backend/app/pipeline/profiles.py` | Add `RiskPrioritizerStage()` to deep profile |
| `backend/app/core/config.py` | Add `openrouter_api_key: str = ""` |
| `backend/app/services/scan_view.py` | Add `build_findings()` helper |
| `backend/app/api/scan_view.py` | Add `GET /scans/{id}/findings` route |
| `backend/app/schemas/__init__.py` | Export findings schemas |
| `infra/docker-compose.yml` | Add `OPENROUTER_API_KEY` to worker env |
| `.env` (not committed) | `OPENROUTER_API_KEY=sk-or-v1-...` |
