# M5 BBOT + Heavy Worker — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add BBOT passive subdomain enumeration to the deep scan profile, routing deep scans to an isolated `heavy` Arq queue consumed by a dedicated `heavy-worker` Docker service that has BBOT installed.

**Architecture:** `POST /scans` with `profile=deep` enqueues to `heavy` queue instead of `default`. A new `heavy-worker` compose service runs the same `runner.py` but reads `ARQ_QUEUE_NAME=heavy` from env, drains only the `heavy` queue, and has BBOT available. `BBOTStage` is `optional=True` — timeout or parse failure returns `[]` without aborting the scan.

**Tech Stack:** Arq queue routing, BBOT Python CLI tool, `asyncio.create_subprocess_exec`, `pytest-asyncio` + `unittest.mock` for tests.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `backend/app/services/queue.py` | Modify | Add `profile` param; route deep → `heavy`, others → `default` |
| `backend/app/workers/runner.py` | Modify | `WorkerSettings.queue_name` reads `ARQ_QUEUE_NAME` env var |
| `backend/app/api/scans.py` | Modify | Pass `scan.profile` to `enqueue_scan` at both call sites |
| `backend/app/core/config.py` | Modify | Add `bbot_timeout: int = 1800` |
| `backend/app/pipeline/adapters/bbot.py` | Create | BBOTStage — subprocess invocation + JSON parsing |
| `backend/app/pipeline/profiles.py` | Modify | Register `BBOTStage` in deep profile at L0 |
| `infra/Dockerfile.heavy-worker` | Create | Worker image + all recon binaries + BBOT |
| `infra/docker-compose.yml` | Modify | Add `heavy-worker` service |
| `backend/tests/unit/test_queue.py` | Create | Unit tests for queue routing |
| `backend/tests/unit/test_bbot.py` | Create | Unit tests for BBOTStage |

---

## Task 1: Queue routing (TDD)

**Files:**
- Modify: `backend/app/services/queue.py`
- Modify: `backend/app/workers/runner.py`
- Modify: `backend/app/api/scans.py`
- Create: `backend/tests/unit/test_queue.py`

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/unit/test_queue.py`:

```python
import pytest
from unittest.mock import AsyncMock, patch


@pytest.mark.asyncio
async def test_deep_scan_enqueues_to_heavy_queue():
    mock_pool = AsyncMock()
    with patch("app.services.queue.create_pool", new=AsyncMock(return_value=mock_pool)):
        from app.services.queue import enqueue_scan
        await enqueue_scan("scan-abc", profile="deep")
    mock_pool.enqueue_job.assert_called_once_with("run_scan", "scan-abc", _queue_name="heavy")


@pytest.mark.asyncio
async def test_standard_scan_enqueues_to_default_queue():
    mock_pool = AsyncMock()
    with patch("app.services.queue.create_pool", new=AsyncMock(return_value=mock_pool)):
        from app.services.queue import enqueue_scan
        await enqueue_scan("scan-def", profile="standard")
    mock_pool.enqueue_job.assert_called_once_with("run_scan", "scan-def", _queue_name="default")


@pytest.mark.asyncio
async def test_quick_scan_enqueues_to_default_queue():
    mock_pool = AsyncMock()
    with patch("app.services.queue.create_pool", new=AsyncMock(return_value=mock_pool)):
        from app.services.queue import enqueue_scan
        await enqueue_scan("scan-ghi", profile="quick")
    mock_pool.enqueue_job.assert_called_once_with("run_scan", "scan-ghi", _queue_name="default")


@pytest.mark.asyncio
async def test_default_profile_enqueues_to_default_queue():
    """profile defaults to 'quick' when not provided."""
    mock_pool = AsyncMock()
    with patch("app.services.queue.create_pool", new=AsyncMock(return_value=mock_pool)):
        from app.services.queue import enqueue_scan
        await enqueue_scan("scan-jkl")
    mock_pool.enqueue_job.assert_called_once_with("run_scan", "scan-jkl", _queue_name="default")
```

- [ ] **Step 2: Run tests — expect failures**

```bash
docker compose exec backend python -m pytest backend/tests/unit/test_queue.py -v 2>&1 | head -20
```

Expected: tests fail because `enqueue_scan` doesn't accept a `profile` parameter yet.

- [ ] **Step 3: Update `backend/app/services/queue.py`**

Replace the entire file content:

```python
from arq import create_pool
from arq.connections import RedisSettings

from app.core.config import get_settings


def _redis_settings() -> RedisSettings:
    return RedisSettings.from_dsn(get_settings().redis_url)


async def enqueue_scan(scan_id: str, profile: str = "quick") -> None:
    queue_name = "heavy" if profile == "deep" else "default"
    pool = await create_pool(_redis_settings())
    try:
        await pool.enqueue_job("run_scan", scan_id, _queue_name=queue_name)
    finally:
        await pool.close()
```

- [ ] **Step 4: Run tests — all should pass**

```bash
docker compose exec backend python -m pytest backend/tests/unit/test_queue.py -v
```

Expected:
```
PASSED test_deep_scan_enqueues_to_heavy_queue
PASSED test_standard_scan_enqueues_to_default_queue
PASSED test_quick_scan_enqueues_to_default_queue
PASSED test_default_profile_enqueues_to_default_queue
4 passed
```

- [ ] **Step 5: Update `backend/app/api/scans.py` — pass profile at both enqueue_scan call sites**

Find line 98 (in `create_scan`):
```python
        await enqueue_scan(str(scan.id))
```
Change to:
```python
        await enqueue_scan(str(scan.id), profile=scan.profile)
```

Find line 131 (in `start_scan`):
```python
    await enqueue_scan(str(scan.id))
```
Change to:
```python
    await enqueue_scan(str(scan.id), profile=scan.profile)
```

- [ ] **Step 6: Update `backend/app/workers/runner.py` — WorkerSettings reads queue from env**

Find the `WorkerSettings` class at the bottom of the file:
```python
class WorkerSettings:
    functions = [run_scan]
    on_startup = startup
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)
    job_timeout = 60 * 30
    max_jobs = 4
```

Replace with:
```python
import os

class WorkerSettings:
    functions = [run_scan]
    on_startup = startup
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)
    queue_name = os.getenv("ARQ_QUEUE_NAME", "default")
    job_timeout = 60 * 30
    max_jobs = 4
```

The `import os` line goes at the top of `runner.py` with the existing stdlib imports. The file already has `import json` — add `import os` on the line immediately after it.

- [ ] **Step 7: Commit**

```bash
git add backend/app/services/queue.py backend/app/workers/runner.py backend/app/api/scans.py backend/tests/unit/test_queue.py
git commit -m "feat(m5): route deep scans to heavy queue, WorkerSettings reads ARQ_QUEUE_NAME from env"
```

---

## Task 2: Add bbot_timeout config field

**Files:**
- Modify: `backend/app/core/config.py`

- [ ] **Step 1: Add field**

In `backend/app/core/config.py`, add after `shodan_api_key` (or after `openrouter_api_key` if Agent 1 changes aren't merged yet):

```python
    bbot_timeout: int = 1800          # seconds — hard cap on BBOT subprocess runtime
```

- [ ] **Step 2: Commit**

```bash
git add backend/app/core/config.py
git commit -m "feat(m5): add bbot_timeout config field"
```

---

## Task 3: BBOTStage adapter (TDD)

**Files:**
- Create: `backend/tests/unit/test_bbot.py`
- Create: `backend/app/pipeline/adapters/bbot.py`

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/unit/test_bbot.py`:

```python
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from app.pipeline.stage import StageContext

# Simulated BBOT JSON-lines stdout — mix of valid events, cross-domain, duplicate, and junk
BBOT_OUTPUT = b"""\
{"type": "DNS_NAME", "data": "www.example.com"}
{"type": "DNS_NAME", "data": "api.example.com"}
{"type": "DNS_NAME", "data": "evil.com"}
{"type": "IP_ADDRESS", "data": "1.2.3.4"}
not-valid-json-line
{"type": "DNS_NAME", "data": "www.example.com"}
{"type": "UNKNOWN_TYPE", "data": "ignored.example.com"}
"""


@pytest.fixture
def ctx():
    return StageContext(scan_id=uuid4(), target_id=uuid4(), domain="example.com")


def _make_proc(stdout: bytes = BBOT_OUTPUT) -> MagicMock:
    proc = MagicMock()
    proc.communicate = AsyncMock(return_value=(stdout, b""))
    proc.kill = MagicMock()
    return proc


@pytest.mark.asyncio
async def test_happy_path_returns_subdomains_and_ips(ctx):
    proc = _make_proc()
    with patch("asyncio.create_subprocess_exec", return_value=proc), \
         patch("app.pipeline.adapters.bbot.get_settings") as mock_s:
        mock_s.return_value.bbot_timeout = 1800
        from app.pipeline.adapters.bbot import BBOTStage
        records = await BBOTStage().execute(ctx)

    keys = {r.canonical_key for r in records}
    assert "www.example.com" in keys
    assert "api.example.com" in keys
    assert "1.2.3.4" in keys


@pytest.mark.asyncio
async def test_domain_filter_excludes_cross_domain(ctx):
    proc = _make_proc()
    with patch("asyncio.create_subprocess_exec", return_value=proc), \
         patch("app.pipeline.adapters.bbot.get_settings") as mock_s:
        mock_s.return_value.bbot_timeout = 1800
        from app.pipeline.adapters.bbot import BBOTStage
        records = await BBOTStage().execute(ctx)

    keys = {r.canonical_key for r in records}
    assert "evil.com" not in keys
    assert "ignored.example.com" not in keys  # UNKNOWN_TYPE not parsed


@pytest.mark.asyncio
async def test_deduplication(ctx):
    proc = _make_proc()
    with patch("asyncio.create_subprocess_exec", return_value=proc), \
         patch("app.pipeline.adapters.bbot.get_settings") as mock_s:
        mock_s.return_value.bbot_timeout = 1800
        from app.pipeline.adapters.bbot import BBOTStage
        records = await BBOTStage().execute(ctx)

    subdomain_keys = [r.canonical_key for r in records if r.type == "subdomain"]
    assert subdomain_keys.count("www.example.com") == 1


@pytest.mark.asyncio
async def test_malformed_json_lines_skipped(ctx):
    proc = _make_proc()
    with patch("asyncio.create_subprocess_exec", return_value=proc), \
         patch("app.pipeline.adapters.bbot.get_settings") as mock_s:
        mock_s.return_value.bbot_timeout = 1800
        from app.pipeline.adapters.bbot import BBOTStage
        records = await BBOTStage().execute(ctx)

    # Despite "not-valid-json-line" in output, other records still parsed
    assert len(records) > 0


@pytest.mark.asyncio
async def test_timeout_returns_empty_and_kills_process(ctx):
    proc = MagicMock()
    proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
    proc.kill = MagicMock()

    with patch("asyncio.create_subprocess_exec", return_value=proc), \
         patch("app.pipeline.adapters.bbot.get_settings") as mock_s:
        mock_s.return_value.bbot_timeout = 1
        from app.pipeline.adapters.bbot import BBOTStage
        records = await BBOTStage().execute(ctx)

    proc.kill.assert_called_once()
    assert records == []
```

- [ ] **Step 2: Run tests — expect ImportError**

```bash
docker compose exec backend python -m pytest backend/tests/unit/test_bbot.py -v 2>&1 | head -10
```

Expected: `ModuleNotFoundError: No module named 'app.pipeline.adapters.bbot'`

- [ ] **Step 3: Create `backend/app/pipeline/adapters/bbot.py`**

```python
import asyncio
import json
import logging
import tempfile

from app.core.config import get_settings
from app.pipeline.stage import AssetRecord, StageContext

log = logging.getLogger(__name__)


class BBOTStage:
    name = "bbot"
    source_tool = "bbot"
    inputs: list[str] = []
    outputs = ["subdomain", "ipv4"]
    depends_on: list[str] = []
    weight = 120
    optional = True
    authz_required = False

    async def execute(self, ctx: StageContext) -> list[AssetRecord]:
        settings = get_settings()
        proc = await asyncio.create_subprocess_exec(
            "bbot",
            "-t", ctx.domain,
            "-p", "subdomain-enum",
            "--json", "--yes",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=settings.bbot_timeout
            )
        except asyncio.TimeoutError:
            log.warning("bbot: timed out after %ds for %s", settings.bbot_timeout, ctx.domain)
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return []

        return self._parse(stdout, ctx.domain)

    def _parse(self, stdout: bytes, domain: str) -> list[AssetRecord]:
        seen: set[str] = set()
        records: list[AssetRecord] = []
        for raw_line in stdout.decode(errors="replace").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            event_type = event.get("type", "")
            data = event.get("data", "")
            if not isinstance(data, str):
                continue

            if event_type == "DNS_NAME":
                fqdn = data.lower()
                if fqdn not in seen and (fqdn == domain or fqdn.endswith(f".{domain}")):
                    seen.add(fqdn)
                    records.append(
                        AssetRecord(
                            type="subdomain",
                            canonical_key=fqdn,
                            payload={"source": "bbot"},
                            confidence=85,
                        )
                    )
            elif event_type == "IP_ADDRESS":
                ip = data.strip()
                if ip and ip not in seen:
                    seen.add(ip)
                    records.append(
                        AssetRecord(
                            type="ipv4",
                            canonical_key=ip,
                            payload={"source": "bbot"},
                            confidence=80,
                        )
                    )
        return records
```

- [ ] **Step 4: Run tests — all should pass**

```bash
docker compose exec backend python -m pytest backend/tests/unit/test_bbot.py -v
```

Expected:
```
PASSED test_happy_path_returns_subdomains_and_ips
PASSED test_domain_filter_excludes_cross_domain
PASSED test_deduplication
PASSED test_malformed_json_lines_skipped
PASSED test_timeout_returns_empty_and_kills_process
5 passed
```

- [ ] **Step 5: Commit**

```bash
git add backend/app/pipeline/adapters/bbot.py backend/tests/unit/test_bbot.py
git commit -m "feat(m5): add BBOTStage adapter with timeout and domain filter"
```

---

## Task 4: Register BBOTStage in deep profile

**Files:**
- Modify: `backend/app/pipeline/profiles.py`

- [ ] **Step 1: Add import and register stage**

In `backend/app/pipeline/profiles.py`, add import alongside existing ones:

```python
from app.pipeline.adapters.bbot import BBOTStage
```

Then update `PROFILES["deep"]` to insert `BBOTStage()` at L0 (after `AmassStage()`, before `DnsxStage()`):

```python
    "deep": [
        SubfinderStage(),
        AssetfinderStage(),
        AmassStage(),
        BBOTStage(),
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

Note: if `CensysStage` and `ShodanStage` are already in this list from Agent 1's merge, keep them — add `BBOTStage()` after `AmassStage()` in the same L0 group.

- [ ] **Step 2: Verify import and profile**

```bash
docker compose exec backend python -c "from app.pipeline.profiles import PROFILES; print([s.name for s in PROFILES['deep']])"
```

Expected output includes `"bbot"` in the list.

- [ ] **Step 3: Commit**

```bash
git add backend/app/pipeline/profiles.py
git commit -m "feat(m5): register BBOTStage in deep profile at L0"
```

---

## Task 5: Create Dockerfile.heavy-worker

**Files:**
- Create: `infra/Dockerfile.heavy-worker`

- [ ] **Step 1: Create `infra/Dockerfile.heavy-worker`**

This Dockerfile contains the full content of `infra/Dockerfile.worker` with BBOT added at the end before the COPY/CMD section. Copy the entire content of `infra/Dockerfile.worker` verbatim, then append the BBOT install block before the final `COPY backend/ ./` line:

```dockerfile
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libpq-dev curl ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

# subfinder (ProjectDiscovery) — pinned binary release
ARG SUBFINDER_VERSION=2.6.6
RUN curl -fsSL -o /tmp/subfinder.zip \
        "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" \
    && unzip -o /tmp/subfinder.zip -d /usr/local/bin/ \
    && rm /tmp/subfinder.zip \
    && chmod +x /usr/local/bin/subfinder \
    && subfinder -version

# assetfinder (tomnomnom)
ARG ASSETFINDER_VERSION=0.1.1
RUN curl -fsSL -o /tmp/assetfinder.tgz \
        "https://github.com/tomnomnom/assetfinder/releases/download/v${ASSETFINDER_VERSION}/assetfinder-linux-amd64-${ASSETFINDER_VERSION}.tgz" \
    && tar -xzf /tmp/assetfinder.tgz -C /usr/local/bin/ \
    && rm /tmp/assetfinder.tgz \
    && chmod +x /usr/local/bin/assetfinder \
    && assetfinder --help >/dev/null

# dnsx (ProjectDiscovery)
ARG DNSX_VERSION=1.2.0
RUN curl -fsSL -o /tmp/dnsx.zip \
        "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_amd64.zip" \
    && unzip -o /tmp/dnsx.zip -d /usr/local/bin/ \
    && rm /tmp/dnsx.zip \
    && chmod +x /usr/local/bin/dnsx \
    && dnsx -version

# httpx (ProjectDiscovery) — renamed to pdhttpx to avoid shadowing Python httpx CLI
ARG HTTPX_VERSION=1.6.0
RUN curl -fsSL -o /tmp/httpx.zip \
        "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip" \
    && unzip -o /tmp/httpx.zip -d /tmp/httpx-extract/ \
    && mv /tmp/httpx-extract/httpx /usr/local/bin/pdhttpx \
    && rm -rf /tmp/httpx.zip /tmp/httpx-extract \
    && chmod +x /usr/local/bin/pdhttpx \
    && pdhttpx -version

# OWASP Amass
ARG AMASS_VERSION=5.1.1
RUN curl -fsSL -o /tmp/amass.tgz \
        "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/amass_linux_amd64.tar.gz" \
    && tar -xzf /tmp/amass.tgz -C /tmp/ \
    && find /tmp -maxdepth 3 -name amass -type f -executable -exec mv {} /usr/local/bin/amass \; \
    && rm -rf /tmp/amass.tgz /tmp/amass_linux_amd64 \
    && chmod +x /usr/local/bin/amass \
    && amass -version 2>&1 | head -3 || true

# asnmap (ProjectDiscovery)
ARG ASNMAP_VERSION=1.1.1
RUN curl -fsSL -o /tmp/asnmap.zip \
        "https://github.com/projectdiscovery/asnmap/releases/download/v${ASNMAP_VERSION}/asnmap_${ASNMAP_VERSION}_linux_amd64.zip" \
    && unzip -o /tmp/asnmap.zip -d /usr/local/bin/ \
    && rm /tmp/asnmap.zip \
    && chmod +x /usr/local/bin/asnmap \
    && asnmap -version

# wafw00f
RUN pip install --no-cache-dir wafw00f==2.3.0 \
    && wafw00f --help >/dev/null

# dbip-city-lite — local IP geo database
ARG DBIP_MONTH=2026-05
RUN mkdir -p /opt/geoip \
    && curl -fsSL -o /opt/geoip/dbip-city-lite.mmdb.gz \
        "https://download.db-ip.com/free/dbip-city-lite-${DBIP_MONTH}.mmdb.gz" \
    && gunzip /opt/geoip/dbip-city-lite.mmdb.gz \
    && ls -lh /opt/geoip/dbip-city-lite.mmdb

# naabu (ProjectDiscovery) — active port scanner
ARG NAABU_VERSION=2.3.3
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL -o /tmp/naabu.zip \
            "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_amd64.zip" \
    && unzip -o /tmp/naabu.zip naabu -d /usr/local/bin/ \
    && rm /tmp/naabu.zip \
    && chmod +x /usr/local/bin/naabu \
    && naabu -version

# nmap
RUN apt-get update && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/* \
    && nmap --version | head -1

# Chromium + gowitness
RUN apt-get update && apt-get install -y --no-install-recommends \
        chromium chromium-driver \
        fonts-liberation fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

ARG GOWITNESS_VERSION=2.4.2
RUN curl -fsSL -o /usr/local/bin/gowitness \
        "https://github.com/sensepost/gowitness/releases/download/${GOWITNESS_VERSION}/gowitness-${GOWITNESS_VERSION}-linux-amd64" \
    && chmod +x /usr/local/bin/gowitness \
    && gowitness version || true

# Python deps (same as Dockerfile.worker)
COPY backend/pyproject.toml ./pyproject.toml
RUN pip install --upgrade pip && pip install .

# BBOT — heavy-worker specific passive recon tool
RUN pip install --no-cache-dir bbot \
    && bbot --version

COPY backend/ ./

CMD ["arq", "app.workers.runner.WorkerSettings"]
```

- [ ] **Step 2: Commit**

```bash
git add infra/Dockerfile.heavy-worker
git commit -m "feat(m5): add Dockerfile.heavy-worker with BBOT installed"
```

---

## Task 6: Add heavy-worker service to docker-compose

**Files:**
- Modify: `infra/docker-compose.yml`

- [ ] **Step 1: Add heavy-worker service**

In `infra/docker-compose.yml`, add a new `heavy-worker` service block after the existing `worker` service block (before `frontend`):

```yaml
  heavy-worker:
    build:
      context: ..
      dockerfile: infra/Dockerfile.heavy-worker
    environment:
      DATABASE_URL: postgresql+asyncpg://recon:recon@postgres:5432/recon
      REDIS_URL: redis://redis:6379/0
      PDCP_API_KEY: ${PDCP_API_KEY:-}  # redacted 2026-07-11 — see security audit H5; rotate in ProjectDiscovery console
      MINIO_URL: http://minio:9000
      MINIO_PUBLIC_URL: http://localhost:9000
      MINIO_ACCESS_KEY: minioadmin
      MINIO_SECRET_KEY: minioadmin
      MINIO_BUCKET: recon
      OPENROUTER_API_KEY: ${OPENROUTER_API_KEY:-}
      CENSYS_API_ID: ${CENSYS_API_ID:-}
      CENSYS_API_SECRET: ${CENSYS_API_SECRET:-}
      SHODAN_API_KEY: ${SHODAN_API_KEY:-}
      ARQ_QUEUE_NAME: heavy
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      minio:
        condition: service_healthy
    volumes:
      - ../backend:/app
```

- [ ] **Step 2: Commit**

```bash
git add infra/docker-compose.yml
git commit -m "feat(m5): add heavy-worker compose service for deep scans"
```

---

## Task 7: Build and smoke test

- [ ] **Step 1: Build heavy-worker image**

```bash
cd infra
docker compose build heavy-worker
```

Expected: build completes, final layer runs `bbot --version` successfully.

- [ ] **Step 2: Start all services**

```bash
docker compose up -d
```

- [ ] **Step 3: Verify heavy-worker drains heavy queue only**

```bash
docker compose logs heavy-worker --tail=20
```

Expected: worker started, no errors, listening on `heavy` queue.

- [ ] **Step 4: Verify regular worker still drains default queue**

```bash
docker compose logs worker --tail=20
```

Expected: worker started, listening on `default` queue (no `ARQ_QUEUE_NAME` log difference, but it processes quick/standard scans normally).

- [ ] **Step 5: Run full unit test suite**

```bash
docker compose exec backend python -m pytest backend/tests/unit/ -v
```

Expected: all tests pass (including test_queue.py and test_bbot.py).

- [ ] **Step 6: Smoke test — deep scan routes to heavy queue**

Submit a queued deep scan and verify it lands in the heavy queue:

```bash
# Get a JWT first — replace credentials as needed
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"your@email.com","password":"yourpassword"}' | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Create a queued deep scan (autostart=false so we can inspect before it runs)
curl -s -X POST http://localhost:8000/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","profile":"deep","autostart":false}' | python -m json.tool
```

Expected: `{"status": "queued", "profile": "deep", ...}`

```bash
# Inspect Redis to confirm job is in heavy queue (not default)
docker compose exec redis redis-cli LLEN arq:queue:heavy
docker compose exec redis redis-cli LLEN arq:queue:default
```

Expected: `arq:queue:heavy` has 1 job; `arq:queue:default` has 0.

---

## Verification Checklist

1. `python -m pytest backend/tests/unit/test_queue.py -v` → 4 tests pass
2. `python -m pytest backend/tests/unit/test_bbot.py -v` → 5 tests pass
3. `[s.name for s in PROFILES['deep']]` includes `"bbot"`
4. `docker compose logs heavy-worker` — worker starts without errors
5. Deep scan (`profile=deep`) → job lands in `arq:queue:heavy`, not `arq:queue:default`
6. Quick/standard scan → job lands in `arq:queue:default`
7. `BBOTStage` with BBOT not on PATH → `optional=True` means scan completes, stage marked failed
