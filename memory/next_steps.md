# Next Steps

## M0–M5 — DONE (2026-05-09)

All backend + frontend complete through M5. Final state:
- Censys + Shodan removed (user decision — keep pipeline lean)
- BBOT adapter + heavy-worker queue routing intact
- naabu connect scan fix (-s c flag)
- Source attribution column in SubdomainsTable
- Pipeline verified: quick ✅ standard ✅ deep ✅ (all 3 profiles confirmed clean)
- heavy-worker now has bind mount (was missing, caused stale baked image issues)

## Immediate Actions (User)

1. **Create PR**: `gh` not installed. Open manually:
   https://github.com/Thilakesh/RedTeam-Dashboard/compare/main...dev_BlackPie

2. **Watch deep scan**: scan `4b692230` running on heavy-worker for boman.ai. Check UI at http://localhost:3000.

## Pre-Demo SQL Fix (still pending)
Fix screenshots stored with `minio:9000` internal hostname:
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

## Next Milestone: Vulnerability Analysis

User confirmed this is the next feature. Start by invoking `superpowers:brainstorming` skill.

Likely scope (to be refined via brainstorm):
- Run nuclei/other vuln scanners against discovered subdomains/ports
- Vulnerability findings stored as a new asset type or new findings table
- Severity-ranked vuln list in UI (separate from AI risk findings)
- Only on verified targets (authz_required=True)

## Architecture Notes (stable, carry forward)
- `AuthzVerifierStage` and `RiskPrioritizerStage` are documented exceptions to "adapters never touch DB" rule
- **RLIMIT_AS must never be used for Go binaries** — causes SIGABRT at startup
- **Backend API has no MinIO env vars** — `_resolve_screenshot_url()` must always fall back to stored URL
- **`layout.tsx` is bare wrapper** — child pages own their title/stats headers
- **naabu must use `-s c`** — connect scan; SYN is silently blocked by Cloudflare
- **`infra/.env` is the source of truth for secrets** — docker-compose reads it; `${VAR:-}` overrides Pydantic `.env`
- **arq reload rule**: must `docker compose restart worker heavy-worker` after Python module changes — bind mount alone doesn't reload the process
- **Both worker services need bind mount**: `volumes: - ../backend:/app` on both `worker` and `heavy-worker` in docker-compose.yml
