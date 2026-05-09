# Active Tasks

## Completed This Session (2026-05-09) — Censys/Shodan Removal + Pipeline Verification

### Censys + Shodan Removal
- [x] Deleted `backend/app/pipeline/adapters/censys.py`
- [x] Deleted `backend/app/pipeline/adapters/shodan.py`
- [x] Deleted `backend/app/pipeline/adapters/_cache.py` (was only used by censys/shodan)
- [x] Deleted `backend/tests/unit/test_censys.py`
- [x] Deleted `backend/tests/unit/test_shodan.py`
- [x] `backend/app/pipeline/profiles.py` — removed CensysStage/ShodanStage from standard+deep
- [x] `backend/app/core/config.py` — removed censys_api_id, censys_api_secret, shodan_api_key
- [x] `backend/pyproject.toml` — removed censys>=2.2, shodan>=1.31 deps
- [x] `infra/Dockerfile.worker` — removed `pip install censys shodan` line
- [x] `infra/docker-compose.yml` — removed CENSYS_API_ID, CENSYS_API_SECRET, SHODAN_API_KEY from worker + heavy-worker

### Pipeline Verification (Systematic Debugging)
- [x] **Quick profile** — subfinder only, completed 22s ✅
- [x] **Standard profile** — 8 stages (subfinder, assetfinder, amass, dnsx, httpx, asnmap, geoip, wafw00f), 213s ✅
- [x] **Deep profile** — launched on heavy-worker, clean stages (no censys/shodan), bbot running ✅

### Bug Found + Fixed: heavy-worker missing bind mount
- [x] Root cause: heavy-worker had no `volumes:` in docker-compose.yml → used baked image with old profiles
- [x] Fix: added `volumes: - ../backend:/app` to heavy-worker service in `infra/docker-compose.yml`
- [x] Verified: `docker compose exec heavy-worker python -c "from app.pipeline.profiles import ..."` → clean profiles

### Bug Found: arq workers must be restarted after Python module changes
- [x] Documented: arq loads modules at startup, bind mount alone doesn't hot-reload process
- [x] Verified: after `docker compose restart worker heavy-worker`, profiles loaded cleanly

## In Progress

### Deep scan 4b692230 (boman.ai, deep profile, smoke@test.io)
- Started: 2026-05-09 06:11 UTC
- Stage status at last check: authz_verifier✅ subfinder✅ assetfinder✅ amass✅ bbot🔄
- BBOT timeout: 1800s (30 min). After BBOT: dnsx → httpx/asnmap/geoip → wafw00f → naabu → nmap → gowitness → risk_prioritizer
- Check via UI: http://localhost:3000

## Pending / Needs User Action

### PR not created (gh CLI missing)
- Create PR manually: https://github.com/Thilakesh/RedTeam-Dashboard/compare/main...dev_BlackPie
- Branch: `dev_BlackPie`, base: `main`
- Latest commits include: M5 features, M5 bug fixes, Censys/Shodan removal

## One-time Ops (before demo)
- [ ] Fix existing screenshot URLs stored with wrong hostname (pre-M2-fix scans):
  ```sql
  UPDATE asset_observations
  SET payload = jsonb_set(
    payload,
    '{screenshot_url}',
    to_jsonb(replace(payload->>'screenshot_url', 'http://minio:9000', 'http://localhost:9000'))
  )
  WHERE payload ? 'screenshot_url'
    AND payload->>'screenshot_url' LIKE 'http://minio:9000%';
  ```
- [ ] Set `MINIO_USE_SIGNED_URLS=true` in production compose only (dev: keep public URLs)

## Next Milestone: Vulnerability Analysis (TBD)
- Start with brainstorming skill to define scope
- User confirmed: pipeline clean, proceed to Vulnerability Analysis feature
