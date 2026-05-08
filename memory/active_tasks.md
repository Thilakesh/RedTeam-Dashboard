# Active Tasks

## Completed This Session (2026-05-08) — M4 UI Polish + Bug Fixes

### Bug: Screenshots not showing in Subdomains tab
- [x] **Root cause**: `_resolve_screenshot_url()` in `scan_view.py` called `storage.screenshot_url()` from backend API context; backend container has NO MINIO env vars → returns `None` → old code returned `None` without fallback
- [x] **Fix**: `backend/app/services/scan_view.py` — added `if url: return url` guard; falls back to stored `screenshot_url` (written by worker with correct `MINIO_PUBLIC_URL` at upload time)

### Feature: Technologies tab shows source subdomains
- [x] `backend/app/schemas/subdomain_view.py` — added `TechBucket(label, count, subdomains: list[str])`
- [x] `backend/app/services/scan_view.py` — `build_technologies()` uses `defaultdict(list)` to collect FQDNs per tech
- [x] `backend/app/api/scans.py` — `/technologies` endpoint response_model changed to `list[TechBucket]`
- [x] `frontend/lib/api.ts` — `TechBucket` type exported
- [x] `frontend/components/tabs/TechnologiesTab.tsx` — expandable `TechRow` with subdomain list

### UI: Dashboard nav item + breadcrumb fixes
- [x] `frontend/components/AppShell.tsx` — Dashboard nav item at `/home` with `LayoutDashboard` icon
- [x] `frontend/app/home/page.tsx` — new empty Dashboard placeholder page
- [x] Breadcrumbs fixed: `/home` → "Dashboard"; `/scans/*` → "Scan Detail" (removed "Basic Recon" prefix)

### UI: Dashboard layout restructuring
- [x] `frontend/app/dashboard/layout.tsx` — stripped to bare `<AppShell>{children}</AppShell>`
- [x] `frontend/app/dashboard/page.tsx` — "Add Scan" title + description heading above scan form
- [x] `frontend/app/dashboard/recon-jobs/page.tsx` — "Recon Jobs" title + 4-column stats grid (Total/Running/Completed/Failed)

## One-time Ops Needed (before demo)
- [ ] Fix existing screenshot URLs stored with wrong hostname (pre-MinIO-fix scans):
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

## Next: M5 — Enrichment + Search (not started)
- Censys + Shodan integrations (rate-limited, cached per-target-per-day)
- BBOT integration (deep profile only, isolated worker pool, separate `heavy` queue)
- OpenSearch full-text asset search (`GET /search?q=...`)
