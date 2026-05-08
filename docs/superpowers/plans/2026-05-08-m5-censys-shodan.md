# M5 Censys + Shodan Adapters — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Censys and Shodan passive enrichment adapters to the standard and deep scan profiles, with Redis-based daily caching to avoid burning API quota on repeated scans.

**Architecture:** Two new `Stage`-protocol adapters follow the existing pattern in `backend/app/pipeline/adapters/`. A shared `_cache.py` helper handles Redis read/write so both adapters stay DRY. The adapters are `optional=True` — if credentials are absent or the API returns an error, the stage returns `[]` and the scan continues normally.

**Tech Stack:** FastAPI + Arq workers, `censys` Python SDK, `shodan` Python SDK, `redis.asyncio` for daily cache. Tests use `pytest-asyncio` + `unittest.mock`.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `backend/app/pipeline/adapters/_cache.py` | Create | Shared Redis daily-cache helpers |
| `backend/app/pipeline/adapters/censys.py` | Create | CensysStage adapter |
| `backend/app/pipeline/adapters/shodan.py` | Create | ShodanStage adapter |
| `backend/app/core/config.py` | Modify | Add `censys_api_id`, `censys_api_secret`, `shodan_api_key` fields |
| `backend/app/pipeline/profiles.py` | Modify | Register both stages in standard + deep at L0 |
| `backend/pyproject.toml` | Modify | Add `censys` and `shodan` to dependencies |
| `infra/Dockerfile.worker` | Modify | `pip install censys shodan` (covered by pyproject.toml, but Dockerfile install must rebuild) |
| `infra/docker-compose.yml` | Modify | Add `CENSYS_API_ID`, `CENSYS_API_SECRET`, `SHODAN_API_KEY` to worker env |
| `backend/tests/unit/test_censys.py` | Create | Unit tests for CensysStage |
| `backend/tests/unit/test_shodan.py` | Create | Unit tests for ShodanStage |

---

## Task 1: Add dependencies and config fields

**Files:**
- Modify: `backend/pyproject.toml`
- Modify: `backend/app/core/config.py`

- [ ] **Step 1: Add SDK dependencies to pyproject.toml**

In `backend/pyproject.toml`, add to the `dependencies` list (after `minio>=7.2`):
```toml
    "censys>=2.2",
    "shodan>=1.31",
```

- [ ] **Step 2: Add config fields to Settings**

In `backend/app/core/config.py`, add three fields after `openrouter_api_key`:
```python
    openrouter_api_key: str = ""          # required for deep scans; set via OPENROUTER_API_KEY env
    censys_api_id: str = ""               # Censys Search API v2 — optional; skipped if empty
    censys_api_secret: str = ""
    shodan_api_key: str = ""              # Shodan DNS API — optional; skipped if empty
```

- [ ] **Step 3: Commit**

```bash
git add backend/pyproject.toml backend/app/core/config.py
git commit -m "feat(m5): add censys/shodan deps and config fields"
```

---

## Task 2: Shared Redis cache helper

**Files:**
- Create: `backend/app/pipeline/adapters/_cache.py`

- [ ] **Step 1: Write the failing test (inline in Task 3 — skip standalone test for this helper, it is tested implicitly via adapter tests)**

- [ ] **Step 2: Create `backend/app/pipeline/adapters/_cache.py`**

```python
import json
import logging

from redis.asyncio import Redis

log = logging.getLogger(__name__)


async def cache_get(key: str, redis_url: str) -> list[dict] | None:
    """Return cached list of AssetRecord dicts, or None on miss/error."""
    try:
        async with Redis.from_url(redis_url, decode_responses=True) as r:
            raw = await r.get(key)
        return json.loads(raw) if raw else None
    except Exception as exc:
        log.debug("cache_get failed (non-fatal): %s", exc)
        return None


async def cache_set(key: str, redis_url: str, data: list[dict]) -> None:
    """Store list of AssetRecord dicts for 24 hours. Failure is silent."""
    try:
        async with Redis.from_url(redis_url, decode_responses=True) as r:
            await r.setex(key, 86400, json.dumps(data))
    except Exception as exc:
        log.debug("cache_set failed (non-fatal): %s", exc)
```

- [ ] **Step 3: Commit**

```bash
git add backend/app/pipeline/adapters/_cache.py
git commit -m "feat(m5): add shared Redis daily-cache helper for enrichment adapters"
```

---

## Task 3: CensysStage adapter (TDD)

**Files:**
- Create: `backend/tests/unit/test_censys.py`
- Create: `backend/app/pipeline/adapters/censys.py`

- [ ] **Step 1: Create test directory if needed**

```bash
mkdir -p backend/tests/unit
touch backend/tests/__init__.py backend/tests/unit/__init__.py
```

- [ ] **Step 2: Write the failing tests**

Create `backend/tests/unit/test_censys.py`:

```python
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from app.pipeline.stage import StageContext


@pytest.fixture
def ctx():
    return StageContext(scan_id=uuid4(), target_id=uuid4(), domain="example.com")


@pytest.mark.asyncio
async def test_no_credentials_returns_empty(ctx):
    with patch("app.pipeline.adapters.censys.get_settings") as mock_s:
        mock_s.return_value.censys_api_id = ""
        mock_s.return_value.censys_api_secret = ""
        from app.pipeline.adapters.censys import CensysStage
        records = await CensysStage().execute(ctx)
    assert records == []


@pytest.mark.asyncio
async def test_cache_hit_skips_api_call(ctx):
    cached = [
        {"type": "subdomain", "canonical_key": "www.example.com",
         "payload": {"source": "censys"}, "confidence": 90}
    ]
    with patch("app.pipeline.adapters.censys.get_settings") as mock_s, \
         patch("app.pipeline.adapters.censys.cache_get", new=AsyncMock(return_value=cached)), \
         patch("app.pipeline.adapters.censys.cache_set", new=AsyncMock()) as mock_set, \
         patch("app.pipeline.adapters.censys.CensysHosts") as mock_hosts:
        mock_s.return_value.censys_api_id = "id"
        mock_s.return_value.censys_api_secret = "secret"
        mock_s.return_value.redis_url = "redis://localhost:6379/0"
        from app.pipeline.adapters.censys import CensysStage
        records = await CensysStage().execute(ctx)
    mock_hosts.assert_not_called()
    mock_set.assert_not_called()
    assert len(records) == 1
    assert records[0].canonical_key == "www.example.com"


@pytest.mark.asyncio
async def test_happy_path_returns_subdomains_and_ips(ctx):
    fake_hosts = [
        {
            "ip": "1.2.3.4",
            "parsed": {"names": ["www.example.com", "api.example.com", "other.evil.com"]},
        }
    ]
    with patch("app.pipeline.adapters.censys.get_settings") as mock_s, \
         patch("app.pipeline.adapters.censys.cache_get", new=AsyncMock(return_value=None)), \
         patch("app.pipeline.adapters.censys.cache_set", new=AsyncMock()), \
         patch("app.pipeline.adapters.censys.CensysHosts") as mock_hosts:
        mock_s.return_value.censys_api_id = "id"
        mock_s.return_value.censys_api_secret = "secret"
        mock_s.return_value.redis_url = "redis://localhost:6379/0"
        mock_hosts.return_value.search.return_value = iter(fake_hosts)
        from app.pipeline.adapters.censys import CensysStage
        records = await CensysStage().execute(ctx)

    keys = {r.canonical_key for r in records}
    assert "1.2.3.4" in keys
    assert "www.example.com" in keys
    assert "api.example.com" in keys
    assert "other.evil.com" not in keys  # domain filter rejects cross-domain names


@pytest.mark.asyncio
async def test_api_error_returns_empty(ctx):
    with patch("app.pipeline.adapters.censys.get_settings") as mock_s, \
         patch("app.pipeline.adapters.censys.cache_get", new=AsyncMock(return_value=None)), \
         patch("app.pipeline.adapters.censys.CensysHosts") as mock_hosts:
        mock_s.return_value.censys_api_id = "id"
        mock_s.return_value.censys_api_secret = "secret"
        mock_s.return_value.redis_url = "redis://localhost:6379/0"
        mock_hosts.return_value.search.side_effect = Exception("401 Unauthorized")
        from app.pipeline.adapters.censys import CensysStage
        records = await CensysStage().execute(ctx)
    assert records == []
```

- [ ] **Step 3: Run tests — expect ImportError (module doesn't exist yet)**

```bash
docker compose exec backend python -m pytest backend/tests/unit/test_censys.py -v 2>&1 | head -30
```

Expected: `ModuleNotFoundError: No module named 'app.pipeline.adapters.censys'`

- [ ] **Step 4: Create `backend/app/pipeline/adapters/censys.py`**

```python
import logging
from dataclasses import asdict
from datetime import date

from censys.search import CensysHosts

from app.core.config import get_settings
from app.pipeline.adapters._cache import cache_get, cache_set
from app.pipeline.stage import AssetRecord, StageContext

log = logging.getLogger(__name__)


class CensysStage:
    name = "censys"
    source_tool = "censys"
    inputs: list[str] = []
    outputs = ["subdomain", "ipv4"]
    depends_on: list[str] = []
    weight = 8
    optional = True
    authz_required = False

    async def execute(self, ctx: StageContext) -> list[AssetRecord]:
        settings = get_settings()
        if not settings.censys_api_id or not settings.censys_api_secret:
            log.info("censys: no credentials configured, skipping")
            return []

        cache_key = f"censys:cache:{ctx.target_id}:{date.today().isoformat()}"
        cached = await cache_get(cache_key, settings.redis_url)
        if cached is not None:
            log.info("censys: cache hit for %s, skipping API call", ctx.domain)
            return [AssetRecord(**r) for r in cached]

        try:
            h = CensysHosts(api_id=settings.censys_api_id, api_secret=settings.censys_api_secret)
            results = h.search(f"parsed.names: {ctx.domain}", pages=2)
            records = self._parse(results, ctx.domain)
        except Exception as exc:
            log.warning("censys: API error for %s, skipping: %s", ctx.domain, exc)
            return []

        await cache_set(cache_key, settings.redis_url, [asdict(r) for r in records])
        return records

    def _parse(self, results, domain: str) -> list[AssetRecord]:
        seen: set[str] = set()
        records: list[AssetRecord] = []
        for host in results:
            ip = host.get("ip", "")
            if ip and ip not in seen:
                seen.add(ip)
                records.append(
                    AssetRecord(type="ipv4", canonical_key=ip,
                                payload={"source": "censys"}, confidence=90)
                )
            for name in host.get("parsed", {}).get("names", []):
                fqdn = name.lower()
                if fqdn not in seen and (fqdn == domain or fqdn.endswith(f".{domain}")):
                    seen.add(fqdn)
                    records.append(
                        AssetRecord(type="subdomain", canonical_key=fqdn,
                                    payload={"source": "censys"}, confidence=90)
                    )
        return records
```

- [ ] **Step 5: Run tests — all should pass**

```bash
docker compose exec backend python -m pytest backend/tests/unit/test_censys.py -v
```

Expected output:
```
PASSED test_no_credentials_returns_empty
PASSED test_cache_hit_skips_api_call
PASSED test_happy_path_returns_subdomains_and_ips
PASSED test_api_error_returns_empty
4 passed
```

- [ ] **Step 6: Commit**

```bash
git add backend/app/pipeline/adapters/censys.py backend/tests/unit/test_censys.py
git commit -m "feat(m5): add CensysStage adapter with daily Redis cache"
```

---

## Task 4: ShodanStage adapter (TDD)

**Files:**
- Create: `backend/tests/unit/test_shodan.py`
- Create: `backend/app/pipeline/adapters/shodan.py`

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/unit/test_shodan.py`:

```python
import pytest
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from app.pipeline.stage import StageContext


@pytest.fixture
def ctx():
    return StageContext(scan_id=uuid4(), target_id=uuid4(), domain="example.com")


@pytest.mark.asyncio
async def test_no_api_key_returns_empty(ctx):
    with patch("app.pipeline.adapters.shodan.get_settings") as mock_s:
        mock_s.return_value.shodan_api_key = ""
        from app.pipeline.adapters.shodan import ShodanStage
        records = await ShodanStage().execute(ctx)
    assert records == []


@pytest.mark.asyncio
async def test_cache_hit_skips_api_call(ctx):
    cached = [
        {"type": "subdomain", "canonical_key": "www.example.com",
         "payload": {"source": "shodan"}, "confidence": 85}
    ]
    with patch("app.pipeline.adapters.shodan.get_settings") as mock_s, \
         patch("app.pipeline.adapters.shodan.cache_get", new=AsyncMock(return_value=cached)), \
         patch("app.pipeline.adapters.shodan.cache_set", new=AsyncMock()) as mock_set, \
         patch("app.pipeline.adapters.shodan.shodan_lib") as mock_lib:
        mock_s.return_value.shodan_api_key = "key"
        mock_s.return_value.redis_url = "redis://localhost:6379/0"
        from app.pipeline.adapters.shodan import ShodanStage
        records = await ShodanStage().execute(ctx)
    mock_lib.Shodan.assert_not_called()
    mock_set.assert_not_called()
    assert len(records) == 1


@pytest.mark.asyncio
async def test_happy_path_constructs_fqdns(ctx):
    fake_result = {
        "subdomains": ["www", "api", "mail"],
        "data": [{"type": "A", "value": "1.2.3.4"}, {"type": "MX", "value": "5.6.7.8"}],
    }
    with patch("app.pipeline.adapters.shodan.get_settings") as mock_s, \
         patch("app.pipeline.adapters.shodan.cache_get", new=AsyncMock(return_value=None)), \
         patch("app.pipeline.adapters.shodan.cache_set", new=AsyncMock()), \
         patch("app.pipeline.adapters.shodan.shodan_lib") as mock_lib:
        mock_s.return_value.shodan_api_key = "key"
        mock_s.return_value.redis_url = "redis://localhost:6379/0"
        mock_lib.Shodan.return_value.dns.domain.return_value = fake_result
        from app.pipeline.adapters.shodan import ShodanStage
        records = await ShodanStage().execute(ctx)

    keys = {r.canonical_key for r in records}
    assert "www.example.com" in keys
    assert "api.example.com" in keys
    assert "mail.example.com" in keys
    assert "1.2.3.4" in keys
    assert "5.6.7.8" not in keys  # only A records produce ipv4 assets


@pytest.mark.asyncio
async def test_api_error_returns_empty(ctx):
    with patch("app.pipeline.adapters.shodan.get_settings") as mock_s, \
         patch("app.pipeline.adapters.shodan.cache_get", new=AsyncMock(return_value=None)), \
         patch("app.pipeline.adapters.shodan.shodan_lib") as mock_lib:
        mock_s.return_value.shodan_api_key = "key"
        mock_s.return_value.redis_url = "redis://localhost:6379/0"
        mock_lib.Shodan.return_value.dns.domain.side_effect = Exception("APIError")
        from app.pipeline.adapters.shodan import ShodanStage
        records = await ShodanStage().execute(ctx)
    assert records == []
```

- [ ] **Step 2: Run tests — expect ImportError**

```bash
docker compose exec backend python -m pytest backend/tests/unit/test_shodan.py -v 2>&1 | head -10
```

Expected: `ModuleNotFoundError: No module named 'app.pipeline.adapters.shodan'`

- [ ] **Step 3: Create `backend/app/pipeline/adapters/shodan.py`**

```python
import logging
import shodan as shodan_lib
from dataclasses import asdict
from datetime import date

from app.core.config import get_settings
from app.pipeline.adapters._cache import cache_get, cache_set
from app.pipeline.stage import AssetRecord, StageContext

log = logging.getLogger(__name__)


class ShodanStage:
    name = "shodan"
    source_tool = "shodan"
    inputs: list[str] = []
    outputs = ["subdomain", "ipv4"]
    depends_on: list[str] = []
    weight = 5
    optional = True
    authz_required = False

    async def execute(self, ctx: StageContext) -> list[AssetRecord]:
        settings = get_settings()
        if not settings.shodan_api_key:
            log.info("shodan: no API key configured, skipping")
            return []

        cache_key = f"shodan:cache:{ctx.target_id}:{date.today().isoformat()}"
        cached = await cache_get(cache_key, settings.redis_url)
        if cached is not None:
            log.info("shodan: cache hit for %s, skipping API call", ctx.domain)
            return [AssetRecord(**r) for r in cached]

        try:
            api = shodan_lib.Shodan(settings.shodan_api_key)
            result = api.dns.domain(ctx.domain, history=False, type="A", page=1)
            records = self._parse(result, ctx.domain)
        except Exception as exc:
            log.warning("shodan: API error for %s, skipping: %s", ctx.domain, exc)
            return []

        await cache_set(cache_key, settings.redis_url, [asdict(r) for r in records])
        return records

    def _parse(self, result: dict, domain: str) -> list[AssetRecord]:
        seen: set[str] = set()
        records: list[AssetRecord] = []
        for label in result.get("subdomains", []):
            fqdn = f"{label}.{domain}".lower()
            if fqdn not in seen:
                seen.add(fqdn)
                records.append(
                    AssetRecord(type="subdomain", canonical_key=fqdn,
                                payload={"source": "shodan"}, confidence=85)
                )
        for entry in result.get("data", []):
            if entry.get("type") == "A":
                ip = entry.get("value", "")
                if ip and ip not in seen:
                    seen.add(ip)
                    records.append(
                        AssetRecord(type="ipv4", canonical_key=ip,
                                    payload={"source": "shodan"}, confidence=85)
                    )
        return records
```

- [ ] **Step 4: Run tests — all should pass**

```bash
docker compose exec backend python -m pytest backend/tests/unit/test_shodan.py -v
```

Expected:
```
PASSED test_no_api_key_returns_empty
PASSED test_cache_hit_skips_api_call
PASSED test_happy_path_constructs_fqdns
PASSED test_api_error_returns_empty
4 passed
```

- [ ] **Step 5: Commit**

```bash
git add backend/app/pipeline/adapters/shodan.py backend/tests/unit/test_shodan.py
git commit -m "feat(m5): add ShodanStage adapter with daily Redis cache"
```

---

## Task 5: Register stages in profiles.py

**Files:**
- Modify: `backend/app/pipeline/profiles.py`

- [ ] **Step 1: Add imports and register stages**

In `backend/app/pipeline/profiles.py`, add two imports at the top alongside the existing ones:

```python
from app.pipeline.adapters.censys import CensysStage
from app.pipeline.adapters.shodan import ShodanStage
```

Then update `PROFILES` to insert both at L0 (after `AmassStage()`, before `DnsxStage()`):

```python
PROFILES: dict[str, list[Stage]] = {
    "quick": [SubfinderStage()],
    "standard": [
        SubfinderStage(),
        AssetfinderStage(),
        AmassStage(),
        CensysStage(),
        ShodanStage(),
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
        CensysStage(),
        ShodanStage(),
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
}
```

- [ ] **Step 2: Verify import succeeds**

```bash
docker compose exec backend python -c "from app.pipeline.profiles import PROFILES; print([s.name for s in PROFILES['standard']])"
```

Expected output includes `censys` and `shodan` in the list.

- [ ] **Step 3: Commit**

```bash
git add backend/app/pipeline/profiles.py
git commit -m "feat(m5): register CensysStage and ShodanStage in standard + deep profiles"
```

---

## Task 6: Infra — docker-compose env vars and Dockerfile

**Files:**
- Modify: `infra/docker-compose.yml`
- Modify: `infra/Dockerfile.worker`

- [ ] **Step 1: Add env vars to worker service in docker-compose.yml**

In `infra/docker-compose.yml`, in the `worker` service's `environment` block, add after `OPENROUTER_API_KEY`:

```yaml
      CENSYS_API_ID: ${CENSYS_API_ID:-}
      CENSYS_API_SECRET: ${CENSYS_API_SECRET:-}
      SHODAN_API_KEY: ${SHODAN_API_KEY:-}
```

- [ ] **Step 2: Add pip install to Dockerfile.worker**

In `infra/Dockerfile.worker`, add after the `wafw00f` install line (line 74):

```dockerfile
# censys + shodan — passive enrichment API clients (M5)
RUN pip install --no-cache-dir "censys>=2.2" "shodan>=1.31"
```

- [ ] **Step 3: Add API keys to local .env (not committed)**

If `.env` doesn't exist yet at the repo root, create it:
```
CENSYS_API_ID=
CENSYS_API_SECRET=
SHODAN_API_KEY=<your-shodan-key>
```

- [ ] **Step 4: Rebuild worker and verify imports**

```bash
docker compose up --build -d worker
docker compose exec worker python -c "import censys; import shodan; print('OK')"
```

Expected: `OK`

- [ ] **Step 5: Run full test suite to catch regressions**

```bash
docker compose exec backend python -m pytest backend/tests/unit/ -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add infra/docker-compose.yml infra/Dockerfile.worker
git commit -m "feat(m5): add Censys/Shodan env vars to worker and rebuild deps"
```

---

## Verification Checklist

1. `python -m pytest backend/tests/unit/test_censys.py backend/tests/unit/test_shodan.py -v` → 8 tests pass
2. `from app.pipeline.profiles import PROFILES; [s.name for s in PROFILES['standard']]` includes `"censys"` and `"shodan"`
3. Worker container: `import censys; import shodan` → no ImportError
4. Standard scan with `CENSYS_API_ID` empty → stages complete with 0 assets, scan does not fail
5. Second standard scan of same domain same day → Redis cache hit logged, no API call made
