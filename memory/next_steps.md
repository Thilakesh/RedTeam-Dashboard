# Next Steps

## M0–M4 — DONE (2026-05-08)

All backend + frontend complete. Key fixes this final session:
- Screenshot URL fallback fix (backend has no MinIO env vars; use stored URL)
- Technologies tab now shows which subdomains each tech came from (expandable rows)
- Dashboard UI polish: new `/home` Dashboard page, nav restructured, breadcrumbs corrected, Add Scan / Recon Jobs layout cleaned up

## M5 — COMPLETE (2026-05-09)

Censys, Shodan, BBOT adapters + heavy-worker infra done. 17 unit tests passing.
To activate: rebuild worker + heavy-worker images, set `CENSYS_API_ID`, `CENSYS_API_SECRET`, `SHODAN_API_KEY` in env.

OpenSearch deferred to future update.

## Next Milestone: M6 — (TBD)

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
