# Next Steps

## M0–M4 — DONE (2026-05-08)

All backend + frontend complete. Key fixes this final session:
- Screenshot URL fallback fix (backend has no MinIO env vars; use stored URL)
- Technologies tab now shows which subdomains each tech came from (expandable rows)
- Dashboard UI polish: new `/home` Dashboard page, nav restructured, breadcrumbs corrected, Add Scan / Recon Jobs layout cleaned up

## Next Milestone: M5 — Enrichment + Search

### Censys / Shodan integrations
- Rate-limited, cached per-target-per-day
- New adapters: `backend/app/pipeline/adapters/censys.py`, `shodan.py`
- Requires API key env vars: `CENSYS_API_ID`, `CENSYS_API_SECRET`, `SHODAN_API_KEY`

### BBOT integration
- Deep profile only, isolated worker pool
- Recursive passive + active recon
- Heavy resource consumer — needs separate `heavy` queue in Arq

### OpenSearch full-text asset search
- Index assets by `canonical_key + type + attributes`
- `GET /search?q=...` endpoint
- New service: `backend/app/services/search.py`

## One-time Ops (do before demo)
- Run screenshot URL fix SQL (see active_tasks.md) — fixes pre-M2-fix scans with `minio:9000` internal URLs
- Set `MINIO_USE_SIGNED_URLS=true` in production compose only (dev: keep public URLs)

## Architecture Notes (stable)
- `AuthzVerifierStage` and `RiskPrioritizerStage` are documented exceptions to "adapters never touch DB" rule
- `authz_state: list[bool]` pattern: mutable singleton threaded through runner → coordinator → stage
- `screenshot_object_name` in gowitness payload enables URL regeneration at query time (presigned URLs)
- Quick/standard profiles unchanged — AuthzVerifierStage only in deep profile
- **RLIMIT_AS must never be used for Go-based tools** — Go reserves virtual GBs at startup even with low actual usage
- **Backend API has no MinIO env vars** — `_resolve_screenshot_url()` must always fall back to stored `screenshot_url`
- **`layout.tsx` is bare wrapper** — child pages own their title/stats headers, not the layout
