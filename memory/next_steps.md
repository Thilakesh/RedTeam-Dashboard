# Next Steps

## M0–M5 + M-Vuln-1 + M-Vuln-2 — DONE (2026-05-09)
## UI/Bug Fixes — DONE (2026-05-10)

Backend + frontend complete through M-Vuln-2. Three uncommitted local changes from 2026-05-10 session.

## Immediate Actions (User)

1. **Commit + push UI fixes** (3 files modified locally):
   ```bash
   git add frontend/components/AppShell.tsx \
           frontend/app/dashboard/recon-jobs/page.tsx \
           backend/app/api/scans.py
   git commit -m "fix: filter recon-only scans in list API; add vuln nav + run-vuln button in recon jobs"
   git push origin dev_vuln_dash
   ```

2. **Create PR** (gh CLI not installed):
   https://github.com/Thilakesh/RedTeam-Dashboard/compare/main...dev_vuln_dash
   Includes M-Vuln-1 schema + M-Vuln-2 pipeline/worker/API/UI + subfinder fix + nav/UX fixes.

## Next Milestone: M-Vuln-3 — Real Nuclei + Safe Stages

Goal: replace nuclei_safe stub with real binary, add safe-tier vuln stages, ship Diff tab.

**Stages to add:**
- `nuclei_safe.py`: real `nuclei` subprocess; rate-limit `-rate-limit 150 -bulk-size 25`; templates dir mounted read-only from host volume (version-pinned, do NOT call `-update-templates` at scan time)
- `testssl.py`: TLS misconfig (weak ciphers, expired certs, deprecated protocols)
- `nmap_nse_vuln.py`: safe NSE category (`vuln-cve*`, `http-enum`, `ssl-cert`)
- `default_creds_matcher.py`: matches services to known default-cred CPEs (NO auth attempts)
- `katana.py`: passive endpoint discovery
- `correlator.py`: dedup, evidence merge, exploitability scoring (`risk = w1·CVSS + w2·EPSS + w3·KEV + w4·exposure + ...`)
- `ai_triage.py`: LLM rationale + remediation, reuses `bounded_completion` + writes `ai_usage` rows

**Frontend additions:**
- Diff tab on `/vuln-scans/[id]`: query `VulnRunMatch.state` (new vs seen vs fixed_in_this_run vs regressed)
- Per-tab grouping: By Service tab, By Technology tab, TLS tab, Endpoints tab (M-Vuln-3.5 if scope creeps)

**Infra:**
- Update `Dockerfile.vuln_worker` to bake testssl.sh + katana
- Mount nuclei templates dir read-only from host volume (don't bake into image)

## M-Vuln-4 (later) — Intrusive Stages
- `ffuf` (dir/path fuzz), `nikto`, `nuclei_intrusive` (severity high+, tagged rce/sqli/fuzz)
- Rate limiter: Redis SETNX with TTL on `vuln:rate:{target_id}`, per-org token bucket on `vuln:rate:{org_id}:intrusive` (default 1 per 10min)
- Per-target consent UX: explicit intrusive opt-in checkbox + warning modal
- Tighter ulimit on vuln-worker: `RLIMIT_NOFILE=8192`, `RLIMIT_NPROC=512`

## Architecture Notes (carry forward)
- Vuln adapters NEVER write to `assets`/`services`/`technologies` — consume frozen `VulnStageContext` only (CI grep check recommended in M-Vuln-3)
- Vuln dedup identity: `(target_id, canonical_key)`; `canonical_key` formula:
  - cpe_matcher: `cve:{cve_id}:{asset_id_or_service_id_or_tech_id}`
  - nuclei: `nuclei:{template_id}:{asset_id}:{matched_at}`
  - nmap NSE: `nse:{script_name}:{service_id}`
- VulnStageContext is detached SQLAlchemy objects (column attrs loaded, no lazy relationships); built once inside SessionLocal, then session closed
- VulnRunMatch state set per scan: `new` | `seen` | `fixed_in_this_run` (correlator stage marks `fixed` when prior scan had vuln but current doesn't)
- Vuln scans require parent recon `status=completed` (enforced at API + can defense-in-depth at coordinator)
- `RLIMIT_AS` still banned for Go binaries
- arq reload: `docker compose restart worker heavy-worker vuln-worker` after Python module changes
- All worker services need `volumes: - ../backend:/app` bind mount for dev hot-swap
- `GET /scans` filters `kind=recon` only — vuln_analysis scans accessed only via `GET /vuln-scans`
