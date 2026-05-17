# Next Steps

## M-TW-1 — Target Workspace scaffold IN PROGRESS (2026-05-17)

**Step 7 done (Nmap Deep adapter, 2026-05-17):**
- `pipeline/investigation/adapters/nmap_deep.py`: real adapter. Cmd `nmap -sV -sC --script vuln,banner --open -Pn {port_args} -oX {tmp} {host}`. Port args: `-p {params.port}` if explicit, else `--top-ports 1000`. Timeout 600s. Parses XML, emits `ServiceUpdateRecord` per open port (service_name/product/version/banner/cpes) + `FindingRecord` per NSE hit. Script classifier: `vuln`-category → `nse_vuln_<sid>` with severity from VULNERABLE / LIKELY VULNERABLE / NOT VULNERABLE markers (skip on "not vulnerable"); `banner` → `service_banner_leak` low; other scripts → `nse_<sid>` low. Host-level scripts (smb-vuln-*) also captured.
- `services/service_enrichment.py::upsert_service_enrichment`: new helper. Upserts Service by (target_id, canonical_key="{host}:{port}/{proto}"). On conflict: coalesce non-null fields (preserves prior values when nmap_deep omits). `cpes` uses case+cardinality check to avoid wiping existing CPEs with empty list. Sets `asset_id=NULL` on insert (investigation enrichment doesn't carry Asset row).
- `workers/investigation_runner._persist_result`: now dispatches `result.services` → `upsert_service_enrichment`. Endpoint dispatch still TODO (Steps 8-9).
- `pipeline/investigation/registry.py`: `nmap_deep` → `NmapDeepAdapter()` (real); ffuf/dirsearch still placeholder.

**Completed prior session (Steps 1-6 + mid-sprint UI changes):**
- DB schema (3 tables + 2 enums, migration 0012)
- Models + service layer + API (8 endpoints) + schemas
- Frontend shell: list page, detail page (Overview/Subdomains/Tasks tabs), CTA buttons, AppShell nav
- Worker scaffold with placeholder adapter — end-to-end testable
- TestSSL adapter (`pipeline/investigation/adapters/testssl.py`): JSON parse, classify into `weak_cipher`/`insecure_protocol`/`expired_cert`/`self_signed_cert`/`tls_vuln`/`tls_misconfig` kinds. Emits `TlsObservationRecord` (cert metadata + protocol matrix + weak ciphers + grade). `services/tls.py::insert_tls_observation` persists rows (skips silently if no matching Service for (target, host, port)). Registered in `registry.py` — testssl real, others still placeholder.
- **Mid-sprint UI changes (2026-05-16, user-driven):**
  - All 4 tools shown unconditionally; capability gating removed from `available_tools_for_asset` and `validate_tool_for_asset`. Subdomain row no longer hides tools for unknown/unenriched assets.
  - `build_workspace_subdomain_rows` returns primary IP only per subdomain (from dnsx observation `primary_ip`). IPs column added; `tools_run` aggregates own + primary IP tasks.
  - Subdomain rows expandable: chevron reveals `ScanTargetPanel` per FQDN + per IP. Each panel has its own HTTP/HTTPS toggle and Tool dropdown. Task params now carry `{protocol, port}`.
  - Sort dropdown replaced with column-header sort icons (lucide ArrowUpDown / ArrowUp / ArrowDown). Sortable columns: Subdomain, Status, Ports, IPs, Tools Run. Click same header to flip direction.

**Next session (Steps 7-12 of plan at `C:\Users\Admin\.claude\plans\target-workspace-gleaming-clarke.md`):**

Adapters must honor new task params: `params.protocol ∈ {http, https}` + `params.port`. The asset passed in may now be type `subdomain` OR `ipv4` (per primary IP scanning support). Build URL as `{protocol}://{asset_canonical_key}[:{port}]/`.

1. **Step 8 — FFUF adapter**. Cmd `ffuf -u {protocol}://{host}/FUZZ -w $INVESTIGATION_WORDLIST -mc 200,204,301,302,307,401,403 -of json`. Parse JSON; emit `EndpointRecord`s + classify via `pipeline/vuln/adapters/endpoint_classifier._classify` for admin/login/api/upload finding kinds. Worker `_persist_result` needs Endpoint upsert dispatch.
2. **Step 9 — Dirsearch adapter**. Cmd `dirsearch -u {protocol}://{host} -w $INVESTIGATION_WORDLIST --format=json`. Parse; emit Endpoint records + `directory_indexing`/`exposed_dotgit`/`exposed_dotenv`/`backup_file`/`swagger_exposed` findings.
3. **Step 10 — Per-task result page** `/targets/[id]/workspace/tasks/[task_id]/page.tsx` + 4 `components/workspace/tool-results/{Nmap,Ffuf,Dirsearch,TestSsl}Result.tsx` + `RawOutputCollapsible.tsx`.
4. **Step 11 — SSE verification + query invalidation polish** with real adapters.
5. **Step 12 — Dynamic "View X Scan" deep links** on Subdomains tab — query most-recent task per (asset, tool) and link to its detail page.

**Known sharp edges:**
- Worker `_persist_result` writes findings + tls_observations + service enrichment. Step 8/9 require adding Endpoint upsert dispatch.
- testssl on bare IP without SNI may fail handshake on multi-tenant hosts; accept failure as a finding.
- Asset type `ipv4` cannot use FQDN-dependent tools cleanly; nmap_deep is the primary IP-friendly tool. Document or grey-out as we learn from real use.
- nmap_deep with `--top-ports 1000` + NSE scripts on a slow host may exhaust 600s timeout. Analyst can pass `params.port=N` for a single-port scan.

**Verification gate** (after Step 10): full smoke test in plan §Verification (steps 1-11). Key checks: idempotent workspace creation, conditional dropdown logic, authz negative test, tenant isolation, raw_output collapsible.

---

## M-Vuln-1 through M-Vuln-8 — DONE (2026-05-13)

Backend + frontend complete through M-Vuln-8. 14 commits from this session on `dev_vuln_dash`, not yet pushed.

## Immediate Actions (User)

1. **Push branch**:
   ```bash
   git push origin dev_vuln_dash
   ```

2. **UI smoke test** — start `docker compose up` in `infra/`, then:
   - `/vuln-scans/<id>` — all 9 tabs render (empty states OK for TLS/HVTs if no data)
   - Vulnerabilities tab — KEV-only + HVT-only toggles, Risk column
   - Overview tab — HVT/public-service cards when data present
   - `/vuln-scans/<id>/endpoints/<ep_id>` — endpoint detail page
   - `/targets/<id>/risk` — severity cards + top-risk table

3. **Create PR** (gh CLI not installed):
   https://github.com/Thilakesh/RedTeam-Dashboard/compare/main...dev_vuln_dash
   This PR covers M-Vuln-1 through M-Vuln-8.

## Next Milestone: M-Vuln-4 — Intrusive Stages

Goal: Add ffuf/nikto/nuclei_intrusive, per-target rate limiting, explicit opt-in UX.

**Backend:**
- `ffuf.py` adapter: directory fuzz (NOT enabled by default, intrusive_required=True)
- `nikto.py` adapter: web server misconfig scan
- `nuclei_intrusive.py`: high+ severity, tagged rce/sqli/fuzz templates
- Rate limiter: Redis SETNX `vuln:rate:{target_id}` (per-scan) + `vuln:rate:{org_id}:intrusive` token bucket (default 1 per 10min)
- `Dockerfile.vuln_worker`: add ffuf + nikto binaries

**Frontend:**
- Per-target consent UX on `/vuln-scans` create form: explicit `intrusive` checkbox + warning modal ("These scans send attack traffic")
- Rate limit feedback: show "intrusive rate limit reached, next scan available in Xm" on 429

## Future: Branch Cleanup Options

After M-Vuln-4, consider:
- Merge `dev_vuln_dash` → main
- Start `dev_vuln_m4` branch (or continue on `dev_vuln_dash`)

## Architecture Notes (carry forward)
- Vuln adapters NEVER write to `assets`/`services`/`technologies`
- VulnStageContext is detached SQLAlchemy objects (no lazy relationships)
- Risk score: 0.30·CVSS + 0.20·EPSS + 0.15·KEV + 0.15·exposure + 0.10·hvt + 0.10·blast_radius
- `GET /scans` filters `kind=recon` only — vuln scans via `GET /vuln-scans`
- Endpoint detail scoped by `scan.target_id` — tenant isolation preserved
- `/targets/{id}/risk` endpoint does full cross-scan rollup (no VulnRunMatch join — reads Vulnerability.target_id directly)
- Tab state: `?tab=` URL param + VALID_TABS allowlist (now 9 tabs)
