# M5 — Enrichment (Censys + Shodan + BBOT) Design Spec

**Date:** 2026-05-08
**Scope:** Backend only — two new adapter groups, heavy-worker infra, queue routing.
**Approach:** Parallel agent execution in two git worktrees; merge after both complete.
**OpenSearch:** Deferred to future update. No search infra in this milestone.

---

## 1. Overview

M5 adds three passive enrichment sources to the recon pipeline:

| Source | Profile | Queue | Stage level |
|--------|---------|-------|-------------|
| Censys | standard + deep | default / heavy | L0 (parallel with subfinder) |
| Shodan | standard + deep | default / heavy | L0 (parallel with subfinder) |
| BBOT   | deep only | heavy | L0 (parallel with subfinder) |

All three are `optional=True` and `authz_required=False` — passive data sources, no active probing, scan completes even if they fail or are unconfigured.

---

## 2. Parallel Agent Split

### Agent 1 — Censys + Shodan

**New files:**
- `backend/app/pipeline/adapters/censys.py`
- `backend/app/pipeline/adapters/shodan.py`

**Modified files:**
- `backend/app/pipeline/profiles.py` — add `CensysStage()`, `ShodanStage()` to standard + deep at L0
- `backend/app/core/config.py` — add `censys_api_id`, `censys_api_secret`, `shodan_api_key`
- `infra/docker-compose.yml` — add `CENSYS_API_ID`, `CENSYS_API_SECRET`, `SHODAN_API_KEY` to worker env
- `infra/Dockerfile.worker` — add `censys shodan` to pip install

### Agent 2 — BBOT + Heavy Worker

**New files:**
- `backend/app/pipeline/adapters/bbot.py`
- `infra/Dockerfile.heavy-worker`

**Modified files:**
- `backend/app/pipeline/profiles.py` — add `BBOTStage()` to deep at L0
- `backend/app/core/config.py` — add `bbot_timeout: int = 1800`
- `infra/docker-compose.yml` — add `heavy-worker` service block
- `backend/app/services/queue.py` — add queue routing by profile

### Merge strategy

After both agents complete, merge their worktrees. All conflicts are additive:

| File | Agent 1 change | Agent 2 change | Conflict risk |
|------|---------------|---------------|---------------|
| `profiles.py` | Adds CensysStage/ShodanStage to L0 lists | Adds BBOTStage to deep L0 list | Low — different list positions |
| `config.py` | Adds 3 API key fields | Adds bbot_timeout field | Low — different fields |
| `docker-compose.yml` | Adds env vars to `worker` service | Adds new `heavy-worker` service block | Low — different sections |

---

## 3. Censys + Shodan Adapters

### 3.1 Daily Redis Cache

Both adapters share the same caching pattern to avoid burning API quota on repeated same-day scans.

```python
cache_key = f"{tool_name}:cache:{ctx.target_id}:{date.today().isoformat()}"
cached = await redis.get(cache_key)
if cached:
    return json.loads(cached)  # list of dicts → rebuild AssetRecords
# ... make API call ...
await redis.setex(cache_key, 86400, json.dumps(records_as_dicts))
```

The worker's Redis client is obtained from `arq.connections.RedisSettings` already available in the worker context.

### 3.2 CensysStage

```python
class CensysStage:
    name           = "censys"
    source_tool    = "censys"
    depends_on     = []
    inputs         = []
    outputs        = ["subdomain", "ipv4"]
    weight         = 8
    optional       = True
    authz_required = False
```

**API call** (Censys Search API v2, uses `censys` Python SDK):
```python
from censys.search import CensysHosts

h = CensysHosts(api_id=settings.censys_api_id, api_secret=settings.censys_api_secret)
results = h.search(f"parsed.names: {ctx.domain}", pages=2, fields=["ip", "parsed.names"])
```

**Output:** One `AssetRecord(type="ipv4", canonical_key=ip)` per unique IP. One `AssetRecord(type="subdomain", canonical_key=fqdn.lower())` per FQDN that ends with `.{ctx.domain}` (safety filter — prevents cross-tenant asset pollution from Censys responses).

**Error handling:** If `censys_api_id` is empty, log info and return `[]`. HTTP 401/403/429/5xx → log warning, return `[]`. SDK `CensysRateLimitExceededException` → same.

### 3.3 ShodanStage

```python
class ShodanStage:
    name           = "shodan"
    source_tool    = "shodan"
    depends_on     = []
    inputs         = []
    outputs        = ["subdomain", "ipv4"]
    weight         = 5
    optional       = True
    authz_required = False
```

**API call** (Shodan Python SDK):
```python
import shodan

api = shodan.Shodan(settings.shodan_api_key)
result = api.dns.domain(ctx.domain, history=False, type="A", page=1)
```

**Output:** `result["subdomains"]` contains bare labels (e.g., `["www", "api", "mail"]`). Construct FQDNs as `f"{label}.{ctx.domain}"`. Return `AssetRecord(type="subdomain", canonical_key=fqdn.lower())` per entry. Also parse `result["data"]` for IPs → `AssetRecord(type="ipv4", ...)`.

**Error handling:** Empty `shodan_api_key` → return `[]`. `shodan.exception.APIError` (includes rate limit and auth errors) → log warning, return `[]`.

### 3.4 Config additions (`config.py`)

```python
censys_api_id: str = ""
censys_api_secret: str = ""
shodan_api_key: str = ""
```

All default to empty — stages check at call time and skip gracefully if unset.

### 3.5 docker-compose.yml additions (worker env section)

```yaml
CENSYS_API_ID: ${CENSYS_API_ID:-}
CENSYS_API_SECRET: ${CENSYS_API_SECRET:-}
SHODAN_API_KEY: ${SHODAN_API_KEY:-}
```

### 3.6 Dockerfile.worker addition

```dockerfile
RUN pip install censys shodan
```

Added alongside existing Python package installs.

---

## 4. BBOT + Heavy Worker

### 4.1 BBOTStage

```python
class BBOTStage:
    name           = "bbot"
    source_tool    = "bbot"
    depends_on     = []
    inputs         = []
    outputs        = ["subdomain", "ipv4"]
    weight         = 120
    optional       = True
    authz_required = False
```

**Invocation:**
```python
import tempfile, asyncio, json

async def execute(self, ctx: StageContext) -> list[AssetRecord]:
    with tempfile.TemporaryDirectory() as tmpdir:
        proc = await asyncio.create_subprocess_exec(
            "bbot", "-t", ctx.domain,
            "-p", "subdomain-enum",
            "--json", "--yes", "--silent",
            "-o", tmpdir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=settings.bbot_timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return []
    return _parse_bbot_output(stdout, ctx.domain)
```

**Output parsing** (`_parse_bbot_output`): iterate JSON lines from stdout. Events with `type="DNS_NAME"` and `data` ending in `.{domain}` → `subdomain` AssetRecords. Events with `type="IP_ADDRESS"` → `ipv4` AssetRecords. Malformed lines skipped silently.

**Domain safety filter:** same as Censys — only accept FQDNs that end with `.{ctx.domain}` or equal `ctx.domain`. Prevents BBOT's recursive discovery from leaking unrelated domains into the tenant's asset graph.

### 4.2 Queue Routing (`services/queue.py`)

Current `enqueue_scan(scan_id)` opens a Redis connection and pushes to the default queue. Updated signature:

```python
async def enqueue_scan(scan_id: str, profile: str = "quick") -> None:
    queue_name = "heavy" if profile == "deep" else "default"
    redis = await create_pool(RedisSettings.from_dsn(settings.redis_url))
    await redis.enqueue_job("run_scan", scan_id, _queue_name=queue_name)
    await redis.close()
```

`POST /scans` in `api/scans.py` already has `scan.profile` at enqueue time — pass it through:
```python
await enqueue_scan(str(scan.id), profile=scan.profile)
```

Same change in `POST /scans/{id}/start`.

### 4.3 `Dockerfile.heavy-worker`

```dockerfile
FROM python:3.11-slim AS base

# System deps — same as Dockerfile.worker
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python deps — same as backend
COPY backend/pyproject.toml backend/
RUN pip install --no-cache-dir -e backend/[worker]

# Install same recon binaries as Dockerfile.worker.
# Agent 2: copy the full binary install section verbatim from infra/Dockerfile.worker
# (subfinder, assetfinder, amass, dnsx, httpx, wafw00f, asnmap, naabu, nmap, gowitness).
# Do not abbreviate — heavy-worker runs the full deep DAG including all active stages.

# BBOT — heavy worker specific
RUN pip install --no-cache-dir bbot

COPY backend/ /app/

CMD ["python", "-m", "app.workers.runner"]
```

The heavy worker runs the same `runner.py` — it just listens to the `heavy` queue and has BBOT available.

### 4.4 `heavy-worker` service in docker-compose

```yaml
heavy-worker:
  build:
    context: ..
    dockerfile: infra/Dockerfile.heavy-worker
  environment:
    DATABASE_URL: ${DATABASE_URL}
    REDIS_URL: ${REDIS_URL}
    MINIO_URL: ${MINIO_URL}
    MINIO_PUBLIC_URL: ${MINIO_PUBLIC_URL}
    MINIO_ACCESS_KEY: ${MINIO_ACCESS_KEY}
    MINIO_SECRET_KEY: ${MINIO_SECRET_KEY}
    OPENROUTER_API_KEY: ${OPENROUTER_API_KEY:-}
    CENSYS_API_ID: ${CENSYS_API_ID:-}
    CENSYS_API_SECRET: ${CENSYS_API_SECRET:-}
    SHODAN_API_KEY: ${SHODAN_API_KEY:-}
    ARQ_QUEUE_NAME: heavy
  depends_on:
    - postgres
    - redis
    - minio
  restart: unless-stopped
```

### 4.5 Runner reads queue name from env

`backend/app/workers/runner.py` — `WorkerSettings` picks up queue from env:

```python
class WorkerSettings:
    functions = [run_scan]
    queue_name = os.getenv("ARQ_QUEUE_NAME", "default")
```

Existing `worker` service has no `ARQ_QUEUE_NAME` set → defaults to `"default"`. `heavy-worker` sets `ARQ_QUEUE_NAME=heavy`.

### 4.6 Config addition (`config.py`)

```python
bbot_timeout: int = 1800  # 30 min hard cap on BBOT subprocess
```

---

## 5. profiles.py final state (after merge)

```python
"standard": [
    SubfinderStage(),
    AssetfinderStage(),
    AmassStage(),
    CensysStage(),    # M5 — Agent 1
    ShodanStage(),    # M5 — Agent 1
    DnsxStage(),
    HttpxStage(),
    AsnmapStage(),
    GeoipStage(),
    Wafw00fStage(),
],
"deep": [
    SubfinderStage(),
    AssetfinderStage(),
    AmassStage(),
    CensysStage(),    # M5 — Agent 1
    ShodanStage(),    # M5 — Agent 1
    BBOTStage(),      # M5 — Agent 2
    DnsxStage(),
    HttpxStage(),
    AsnmapStage(),
    GeoipStage(),
    Wafw00fStage(),
    NaabuStage(),
    NmapStage(),
    GoWitnessStage(),
    RiskPrioritizerStage(),
],
```

`CensysStage`, `ShodanStage`, `BBOTStage` all have `depends_on=[]` so they run at L0 alongside `subfinder`/`assetfinder`.

---

## 6. .env additions (not committed)

```
CENSYS_API_ID=
CENSYS_API_SECRET=
SHODAN_API_KEY=<your-key>
```

---

## 7. Testing Strategy

### Agent 1 — Censys + Shodan

| Test | File | What it asserts |
|------|------|----------------|
| CensysStage — empty key skips | `tests/unit/test_censys.py` | `censys_api_id=""` → returns `[]`, no HTTP call |
| CensysStage — happy path | same | Mock SDK response → correct AssetRecords returned |
| CensysStage — domain filter | same | FQDN not ending in `.{domain}` is excluded |
| CensysStage — cache hit | same | Second call with same target+date → no SDK call, same records |
| CensysStage — 429 | same | SDK rate-limit exception → returns `[]`, stage not failed |
| ShodanStage — empty key skips | `tests/unit/test_shodan.py` | `shodan_api_key=""` → returns `[]` |
| ShodanStage — happy path | same | Mock SDK response → FQDNs constructed correctly |
| ShodanStage — APIError | same | Returns `[]`, stage not failed |

### Agent 2 — BBOT

| Test | File | What it asserts |
|------|------|----------------|
| BBOTStage — happy path | `tests/unit/test_bbot.py` | Mock subprocess output → correct AssetRecords |
| BBOTStage — domain filter | same | Events outside target domain excluded |
| BBOTStage — timeout | same | `asyncio.TimeoutError` → returns `[]`, process killed |
| BBOTStage — malformed JSON | same | Non-JSON lines skipped, valid lines still parsed |
| Queue routing — deep → heavy | `tests/unit/test_queue.py` | `enqueue_scan(id, profile="deep")` uses `_queue_name="heavy"` |
| Queue routing — quick → default | same | `enqueue_scan(id, profile="quick")` uses `_queue_name="default"` |

### Explicitly out of scope

- Real Censys/Shodan API calls in tests (mock the SDK)
- BBOT binary in CI (mock subprocess)
- Integration test requiring `heavy-worker` container (E2E manual only)

---

## 8. New Files Summary

```
backend/
  app/
    pipeline/
      adapters/
        censys.py         ← Agent 1
        shodan.py         ← Agent 1
        bbot.py           ← Agent 2
  tests/
    unit/
      test_censys.py      ← Agent 1
      test_shodan.py      ← Agent 1
      test_bbot.py        ← Agent 2
      test_queue.py       ← Agent 2

infra/
  Dockerfile.heavy-worker ← Agent 2
```

### Modified Files

| File | Agent | Change |
|------|-------|--------|
| `backend/app/pipeline/profiles.py` | 1 + 2 | Add stages to L0 lists |
| `backend/app/core/config.py` | 1 + 2 | Add env var fields |
| `backend/app/services/queue.py` | 2 | Profile-based queue routing |
| `backend/app/workers/runner.py` | 2 | `WorkerSettings.queue_name` from env |
| `infra/docker-compose.yml` | 1 + 2 | Env vars (1) + heavy-worker service (2) |
| `infra/Dockerfile.worker` | 1 | `pip install censys shodan` |
