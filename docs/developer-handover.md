# Developer Handover Notes

---

## How the Application Works (Executive Summary)

The Red Team Recon Dashboard is a multi-tenant Attack Surface Management platform where admins invite analysts, analysts submit domains for reconnaissance, background workers run a directed-acyclic-graph of security tools against those domains, and normalized findings stream back to the browser in real time. A separate vulnerability analysis pipeline runs tool-specific checks (nuclei, nmap NSE, testssl) against the discovered services and scores each finding with a composite risk formula (CVSS + EPSS + KEV + exposure + HVT signals). Analysts can also open a Target Workspace and run deep per-asset investigations (intensive nmap, directory brute-force, TLS audit) against specific subdomains or IPs. All state is persisted in PostgreSQL, real-time updates flow through Redis pub/sub → Server-Sent Events, and screenshots land in MinIO object storage.

---

## Critical Files

| File | Purpose |
|---|---|
| `backend/app/core/config.py` | All configuration via Pydantic Settings; loaded once via `@lru_cache` |
| `backend/app/main.py` | FastAPI app factory; all router registrations; startup hooks (keypair + admin bootstrap) |
| `backend/app/api/deps.py` | `get_current_user`, `require_role()`, `require_feature()` — used on every authenticated route |
| `backend/app/core/tokens.py` | `create_access_token()` (RS256 sign) + `decode_access_token()` (RS256 verify) |
| `backend/app/core/security.py` | `hash_password()` / `verify_password()` — bcrypt direct, 72-byte truncation |
| `backend/app/pipeline/stage.py` | `Stage` protocol + `StageContext` — the contract every recon adapter must implement |
| `backend/app/pipeline/coordinator.py` | Recon DAG executor: topo sort → parallel execution levels |
| `backend/app/pipeline/profiles.py` | Recon profile → stage list mapping (quick / standard / deep) |
| `backend/app/pipeline/vuln/stage.py` | `VulnStage` protocol + `VulnStageContext` |
| `backend/app/pipeline/vuln/coordinator.py` | Vuln DAG executor with `applies()` + `intrusive_required` gates |
| `backend/app/pipeline/investigation/stage.py` | `InvestigationAdapter` protocol + result record types |
| `backend/app/pipeline/investigation/registry.py` | Maps tool name → adapter instance |
| `backend/app/services/scan_profiles.py` | Per-tool investigation scan profiles (PROFILES dict + resolve_args) |
| `backend/app/services/assets.py` | `upsert_assets()` — deduplication core for the recon asset graph |
| `backend/app/services/vulns.py` | `upsert_vulns()` — deduplication core for the vuln lifecycle |
| `backend/app/services/correlator_engine.py` | CVE merge + EPSS/KEV enrichment + risk score computation |
| `backend/app/workers/runner.py` | Recon scan lifecycle (load → DAG → commit → pub/sub) |
| `backend/app/workers/vuln_runner.py` | Vuln scan lifecycle |
| `backend/app/workers/investigation_runner.py` | Per-task investigation lifecycle + enrichment dispatch |
| `backend/app/agents/bounded_completion.py` | OpenRouter LLM wrapper with null-content guard |
| `backend/app/agents/risk_prioritizer.py` | AI risk scoring stage: reads asset graph → LLM → writes findings |
| `backend/migrations/versions/` | All schema changes; read newest migration for current DB state |
| `frontend/lib/api.ts` | Typed fetch wrapper, all API helper functions, all TypeScript types |
| `frontend/lib/auth-context.tsx` | React auth context — `useAuth()` hook for current user |
| `frontend/components/AppShell.tsx` | Sidebar nav + breadcrumbs + theme toggle — wraps every authenticated page |
| `frontend/components/workspace/ScanConfigurationCard.tsx` | Investigation task launcher with profile select + command preview |
| `infra/docker-compose.yml` | All service definitions, env vars, volumes, health checks |

---

## Important Implementation Details

### Do not reintroduce these mistakes

| Issue | Rule |
|---|---|
| passlib + bcrypt | Use `bcrypt` directly. passlib probes a long password at init and raises `ValueError` with `bcrypt>=4.1`. `app/core/security.py` handles 72-byte truncation. |
| `RLIMIT_AS` on workers | Never set address-space limits for Go binaries (naabu, nmap, gowitness). Go reserves multi-GB virtual address space at startup. `SIGABRT` in <300ms, 0 results, no DB error. Use `RLIMIT_NOFILE` only. |
| naabu SYN scan | Always `-s c` (connect scan). SYN scan is silently blocked by Cloudflare CDN → 0–4 ports returned. |
| subfinder `proc.communicate()` | Use `asyncio.wait_for(_collect(), 300s)` with streaming async iteration. `communicate()` buffers all stdout in memory and blocks. |
| `shell=True` in subprocesses | Never. All subprocess calls use `asyncio.create_subprocess_exec` with args as a list. |
| vuln adapters touching asset graph | Vuln adapters must ONLY read from the frozen `VulnStageContext`. Writing to `assets`, `services`, or `technologies` from vuln adapters corrupts the recon graph. |
| `recon_token` in localStorage | This is stale. Auth uses HttpOnly cookies (`rt_access`, `rt_refresh`, `rt_csrf`) since the auth overhaul commit `d05ba3e`. |
| Public signup | Removed. Invite-only since auth overhaul. Bootstrap admin via `ADMIN_EMAIL`/`ADMIN_PASSWORD` env. |

### Arq worker restart required after Python changes
Arq pre-imports all modules. File edits hot-reload only in the API container (uvicorn --reload). For workers:
```bash
docker compose restart worker heavy-worker vuln-worker investigation-worker
```

### MinIO env split (intentional)
The backend API container has **no** MinIO env vars. All MinIO operations happen in workers. `_resolve_screenshot_url()` in the API falls back to the URL stored in `asset_observations.payload["screenshot_url"]` (written correctly by the worker using `MINIO_PUBLIC_URL`). Adding MinIO env to the backend would break this pattern.

### SSE `withCredentials` (critical for cross-origin)
EventSource does not send cookies by default on cross-origin requests. Frontend (`:3000`) → API (`:8000`) is cross-origin. All three SSE clients must pass `{ withCredentials: true }`. This was fixed in commit `843499c`.

---

## Current Route Structure

| URL | Page | Auth | Notes |
|---|---|---|---|
| `/` | redirect → `/dashboard` | — | |
| `/login` | Login form | None | Cookie auth, no signup link |
| `/accept-invite` | Set password from invite token | Token param | |
| `/dashboard` | Add Scan form | Any | queued or immediate start |
| `/dashboard/recon-jobs` | Recon Jobs table | Any | lifecycle actions per row |
| `/scans/[id]` | Recon scan detail | Any | 8 tabs: Overview, Subdomains, IPs, CDN/WAF, Tech, Ports, Risks, History |
| `/vuln-scans` | Vuln scan list | Any | 4s polling while running |
| `/vuln-scans/[id]` | Vuln scan detail | Any | 9 tabs |
| `/vuln-scans/[id]/endpoints/[ep_id]` | Endpoint detail | Any | Back link to ?tab=endpoints |
| `/targets` | Target list | Any | links to workspace |
| `/targets/[id]/workspace` | Target workspace | Any | 3 tabs: Overview, Subdomains, Tasks |
| `/targets/[id]/workspace/tasks/[task_id]` | Per-task result | Any | dispatches to tool renderer |
| `/targets/[id]/risk` | Cross-scan risk rollup | Any | severity cards + top-10 vulns |
| `/home` | Dashboard placeholder | Any | future widgets |
| `/settings/profile` | User profile | Any | |
| `/settings/sessions` | Active sessions | Any | revoke sessions |
| `/admin/users` | User management | Admin | invite, disable, promote |
| `/admin/users/[id]` | User detail | Admin | |
| `/admin/sessions` | All sessions | Admin | |
| `/admin/audit` | Audit log | Admin | |
| `/admin/features` | Feature flags | Admin | per-user feature toggles |
| `/admin/settings` | App settings | Admin | |

**Note:** The Operations Console route structure (`/targets/[id]`, `/targets/[id]/launch-operation`, `/targets/[id]/operations`, `/targets/[id]/operations/[operation_id]`) from the temporal-marble plan was **not implemented**. The workspace still uses the tab-based structure at `/targets/[id]/workspace`.

---

## API Endpoint Inventory

### Auth (`/auth`)
| Method | Path | Description |
|---|---|---|
| POST | `/auth/login` | Email + password → set 3 cookies |
| POST | `/auth/refresh` | Rotate refresh token → new cookies |
| POST | `/auth/logout` | Revoke session + clear cookies |
| GET | `/auth/me` | Current user info + enabled features |
| POST | `/auth/invite/accept` | Set password from invite token |

### Scans (`/scans`) — recon only
| Method | Path | Description |
|---|---|---|
| GET | `/scans` | List recon scans (kind=recon, tenant-scoped) |
| POST | `/scans` | Create scan (autostart optional) |
| GET | `/scans/{id}` | Scan detail |
| PATCH | `/scans/{id}` | Update profile (queued only) |
| DELETE | `/scans/{id}` | Delete (not running) |
| POST | `/scans/{id}/start` | Start queued scan |
| POST | `/scans/{id}/stop` | Stop running scan |
| GET | `/scans/{id}/stream` | SSE progress stream |
| GET | `/scans/{id}/subdomains` | Subdomain rows (joined enrichment) |
| GET | `/scans/{id}/overview` | Counts + distributions |
| GET | `/scans/{id}/ips` | IP rows |
| GET | `/scans/{id}/cdn-waf` | CDN/WAF summary |
| GET | `/scans/{id}/technologies` | Tech buckets |
| GET | `/scans/{id}/ports` | Port rows |
| GET | `/scans/{id}/findings` | AI risk findings (paginated, severity filter) |

### Vulnerability Scans (`/vuln-scans`)
| Method | Path | Description |
|---|---|---|
| GET | `/vuln-scans` | List vuln scans |
| POST | `/vuln-scans` | Create + enqueue vuln scan |
| GET | `/vuln-scans/{id}` | Detail |
| DELETE | `/vuln-scans/{id}` | Delete (not running) |
| GET | `/vuln-scans/{id}/stream` | SSE stream |
| GET | `/vuln-scans/{id}/overview` | Severity counts + top risks |
| GET | `/vuln-scans/{id}/vulnerabilities` | Paginated vuln rows |
| GET | `/vuln-scans/{id}/by-service` | Vulns grouped by service |
| GET | `/vuln-scans/{id}/by-technology` | Vulns grouped by tech |
| GET | `/vuln-scans/{id}/endpoints` | Endpoint list |
| GET | `/vuln-scans/{id}/endpoints/{ep_id}` | Endpoint detail |
| GET | `/vuln-scans/{id}/tls` | TLS observations |
| GET | `/vuln-scans/{id}/hvts` | HVT signals |
| GET | `/vuln-scans/{id}/triage` | Top-20 by risk_score |

### Vulnerabilities (`/vulns`)
| Method | Path | Description |
|---|---|---|
| PATCH | `/vulns/{id}` | Update vuln status (tenant-scoped via target→project→org) |

### Targets (`/targets`)
| Method | Path | Description |
|---|---|---|
| GET | `/targets` | List targets |
| POST | `/targets` | Create target |
| GET | `/targets/{id}` | Target detail |
| GET | `/targets/{id}/risk` | Cross-scan risk rollup (open vulns, HVTs, endpoints, top-10) |

### Target Workspaces (`/target-workspaces`)
| Method | Path | Description |
|---|---|---|
| POST | `/target-workspaces` | Create/get workspace (idempotent) |
| GET | `/target-workspaces` | List workspaces for user |
| DELETE | `/target-workspaces/{ws}` | Delete workspace (refuses if tasks running) |
| GET | `/target-workspaces/{ws}/overview` | Overview stats |
| GET | `/target-workspaces/{ws}/subdomains` | Subdomain rows with IPs + tools_run |
| GET | `/target-workspaces/{ws}/tasks` | All investigation tasks |
| GET | `/target-workspaces/{ws}/tasks/{id}` | Task detail + findings |
| POST | `/target-workspaces/{ws}/tasks` | Create + enqueue task (requires asset_id) |
| DELETE | `/target-workspaces/{ws}/tasks/{id}` | Delete task (not running) |
| GET | `/target-workspaces/{ws}/stream` | SSE stream |
| POST | `/target-workspaces/{ws}/operations/preview` | Server-side command preview |
| GET | `/target-workspaces/scan-profiles` | All tool profile bundles |

---

## Migration History

| File | Change | Milestone |
|---|---|---|
| `0001_initial.py` | Base schema: org, project, target, user, scan, asset, asset_observation | M0 |
| `0002_m2_auth.py` | Auth tables: refresh_session, blacklisted_jti, audit_log | M2 |
| `0005_promote_services_tech.py` | Service + Technology first-class tables | M-Vuln-1 |
| `0006_vuln_tables.py` | Vulnerability + VulnEvidence + VulnRunMatch | M-Vuln-1 |
| `0007_scan_kind_and_parent.py` | Scan.kind, Scan.parent_scan_id, Scan.intrusive | M-Vuln-2 |
| `0008_endpoints_and_hvt_signals.py` | Endpoint + HvtSignal | M-Vuln-5 |
| `0009_vuln_risk_columns.py` | Vulnerability.epss_score, risk_score, kev | M-Vuln-7 |
| `0010_service_classification.py` | Service.classification enum | M-Vuln-6 |
| `0011_panel_detector_cleanup.py` | Panel detector findings cleanup | M-Vuln-6 |
| `0012_target_workspace.py` | TargetWorkspace + InvestigationTask + InvestigationFinding (3 tables + 2 enums) | M-TW-1 |
| `0013_auth_overhaul.py` | UserFeature, user names, super_admin_email | Auth overhaul |
| `0014_target_verified.py` | targets.is_verified + verified_by + verified_at | Auth overhaul |
| `0015_user_names.py` | User.first_name, User.last_name | Auth overhaul |
| `0017_drop_target_verification.py` | Drop all verification columns (is_verified, authorization_token, etc.) | elegant-yeti |
| `ba7455c...py` | ScanStatus: queued + stopped | M4 |
| `c358f6f...py` | Finding + AiUsage tables | M3 |

**Next migration to add:** `0019_operation_manual_target.py` — make `investigation_tasks.asset_id` and `investigation_findings.asset_id` nullable, add `target VARCHAR(255)` and `target_type VARCHAR(16)` to `investigation_tasks`.

---

## Risk Areas

### 1. CLAUDE.md is partially stale
`CLAUDE.md` references self-signup (`Users sign up`), `recon_token` in localStorage, and the old auth architecture. These were replaced by invite-only auth + HttpOnly cookies in commit `d05ba3e`. Do not edit CLAUDE.md for now, but treat any code guidance in it with the caveat that the auth section is outdated.

### 2. Investigation task `asset_id` blocks logical-otter
`InvestigationTask.asset_id` is `NOT NULL` in the current model and migration `0012`. The logical-otter plan requires this to be nullable before any manual-target operations can be stored. Until migration `0019` runs, the `create_manual_operation()` service function cannot insert a row.

### 3. Frontend route restructure (temporal-marble) was not completed
The temporal-marble plan described replacing `/targets/[id]/workspace/` tabs with nested Next.js routes: `/targets/[id]` (Assets), `/targets/[id]/launch-operation`, `/targets/[id]/operations`, `/targets/[id]/operations/[operation_id]`. **This was not implemented.** The current code still uses the old tab-based workspace route.

The logical-otter plan's frontend steps reference files in `app/targets/[id]/(workspace)/` — a route group that **does not exist**. Before implementing logical-otter, decide one of:
- **Option A**: Implement temporal-marble route restructure first (per the plan), then logical-otter on top. This is the "clean" path but touches many files.
- **Option B**: Adapt logical-otter to the current workspace tab structure — add a "Launch Operation (Manual)" sub-panel within the existing workspace tabs, keeping the current route tree intact.

### 4. gpt-oss-20b:free null-content failures unhandled at UI level
When the free LLM rate-limits or is unavailable, `bounded_completion` raises `BoundedCompletionError`. The `risk_prioritizer` stage is `optional=True` so the scan still completes, but the Risks tab will be empty. The UI shows no error indicator for this case — the analyst sees an empty Risks tab with no explanation. A toast or empty-state with "AI analysis unavailable" would improve UX.

### 5. MinIO public URLs are unsigned
Screenshot URLs in `asset_observations.payload["screenshot_url"]` are unsigned, publicly accessible, and never expire. In production, switch to presigned URLs with a short TTL before exposing the service.

### 6. `memory/architecture.md` was empty
Fixed by this documentation session. The SessionStart hook script (`session-start.sh`) does not yet `cat` this file — consider adding it for future sessions.

---

## Claude-Assisted Implementation Plans

All plans live in `C:\Users\Admin\.claude\plans\`. Claude Code was used to plan and implement each milestone.

| Plan file | Focus | Status |
|---|---|---|
| `you-are-a-senior-shiny-hearth.md` | Full architecture plan M0–M6, AI council design | Reference document — not a task plan |
| `red-team-recon-delightful-codd.md` | Vulnerability Analysis module architecture (M-Vuln-1 to M-Vuln-8) | Deployed |
| `target-workspace-gleaming-clarke.md` | Target Workspace M-TW-1 (4 adapters, per-task UI, SSE) | Deployed |
| `authentication-session-management-elegant-yeti.md` | Remove scan authorization gating + verified targets subsystem | Deployed |
| `you-are-a-principal-temporal-marble.md` | Operations Console (M-TW-2): scan profiles, ScanConfigurationCard, nested routes | Backend partial (scan_profiles, ScanConfigurationCard); frontend routes NOT done |
| `you-are-a-principal-logical-otter.md` | Manual standalone operations (no recon asset required) | **Pending** |

---

## Pending Implementation: logical-otter

**Goal:** Allow analysts to launch investigation tools against a manually typed domain or IP, without requiring a pre-existing recon Asset row.

**What changes:**
1. **Migration `0019`** — `investigation_tasks.asset_id` → nullable; add `target VARCHAR(255)`, `target_type VARCHAR(16)`; `investigation_findings.asset_id` → nullable
2. **Model** — `InvestigationTask.asset_id: Mapped[UUID | None]`; add `target` + `target_type`; `InvestigationFinding.asset_id: Mapped[UUID | None]`
3. **Worker** — load Asset only if `task.asset_id is not None`; host = `asset.canonical_key or task.target`; guard enrichment dispatch (service/endpoint/TLS enrichment only when `asset_id` is set — manual ops must not pollute the recon asset graph)
4. **Service** — `validate_target(target_type, target) -> str` (FQDN allowlist regex + IPv4 validation — prevents argument injection); `create_manual_operation()`; `build_manual_command_preview()`; `list_tasks_for_workspace` INNER JOIN → LEFT JOIN
5. **API** — new `POST /{ws}/operations`; extend `POST /{ws}/operations/preview` to accept `target`+`target_type` OR `asset_id`; fix `cancel` + `retry` endpoints (LEFT JOIN so they work on manual tasks)
6. **Schema** — `InvestigationTaskOut.asset_id: UUID | None`; add `target`, `target_type`; new `OperationCreateRequest`; update `CommandPreviewRequest`
7. **Frontend** — new `ManualOperationForm.tsx` component; update `launch-operation/page.tsx` (replace asset picker with `ManualOperationForm`); update operations list (Target column uses `asset_label ?? task.target`)

**Security critical:** `validate_target()` must run at BOTH preview and create, before any host string reaches the command builder. An unvalidated host like `-oN` passed to nmap as a bare argv token is argument injection (not shell injection, but equally dangerous).

**Route dependency:** The logical-otter plan references `app/targets/[id]/(workspace)/launch-operation/page.tsx`. This `(workspace)` route group does not exist in current code (see Risk Area 3). Resolve this first.

**Verification checklist (from plan):**
1. Alembic reaches migration `0019`
2. Manual launch: Domain + testssl → completes, result renders
3. Manual IP: IP + nmap_deep → completes
4. Argument injection blocked: target=`-oN` → 422 on preview and create
5. Custom-args denylist: profile=custom, args=`-o /tmp/x` → 422
6. No asset pollution: Assets tab shows no new rows after manual op
7. Cancel/Retry work on manual ops (LEFT JOIN fix)
8. Assets tab unchanged: still uses `asset_id`-based path via POST `/tasks`
9. Operations list: Target column shows typed host for manual + asset key for asset-linked ops
10. Tenant isolation: another org's workspace → 404

---

## Locked Architecture Decisions

These decisions are set in `you-are-a-senior-shiny-hearth.md` and must not be reversed without team alignment:

| Decision | Rationale |
|---|---|
| SaaS-first multi-tenant (one Postgres, shared infra) | Simpler ops; per-tenant namespace is Org + org_id on every row |
| Layered monolith, no microservices | Deferred until load justifies the operational cost |
| Asset graph, not result rows | `canonical_key` dedup enables diff scans (M3 future) as a DB query |
| Stage protocol — adapters never touch DB | Clean boundary between tool execution and persistence |
| Vuln adapters never touch asset graph | Vuln pipeline is read-only on the recon data; prevents cross-contamination |
| Invite-only auth, no public signup | Trusted-operator model; analysts are known identities |
| Admin/analyst RBAC + feature flags | Fine-grained access without per-route hardcoding |
| No target authorization gating | Removed in elegant-yeti; access control is RBAC only |
| AI focus = risk prioritization, not summaries | LLM ranks findings; it does not narrate or explain |

---

## Future Improvements

| Area | Description | Notes |
|---|---|---|
| M-Vuln-4: Intrusive stages | ffuf, nikto, nuclei_intrusive; per-target consent UX; rate limiter (Redis token bucket) | Design in `next_steps.md` |
| M6: Scheduling + alerts | Recurring scans (cron per target), email/webhook alerts, per-tenant rate limits | Not started |
| Full-text search | OpenSearch index for asset search across all org scans | Not started |
| Test suite | pytest + pytest-asyncio + testcontainers (real Postgres+Redis); prefer integration over mocks | No tests currently except unit tests for risk_score, hvt_score, bounded_completion |
| SSE vs polling | Vuln scans list uses 4s polling; switch to SSE with TanStack invalidation | Pattern already established in recon scans |
| MinIO signed URLs | Replace unsigned public URLs with presigned URLs (30-min TTL) | Security improvement for production |
| Redis connection pool | `services/queue.py` opens/closes per enqueue; pool when scan frequency justifies | Low priority |
| `memory/architecture.md` in hook | Add `cat memory/architecture.md` to `.claude/hooks/session-start.sh` | Trivial change, high value |
| Fix hook filename typo | `.claude/settiings.local.json` has a double `i` — rename to `settings.local.json` | Minor, but may confuse new developers |

---

## Codebase Intelligence Summary

### Reusable utilities
| Name | Location | Purpose |
|---|---|---|
| `api<T>()` | `frontend/lib/api.ts` | Typed fetch with CSRF, auto-refresh, error parsing — use for ALL HTTP calls |
| `sseUrl()` | `frontend/lib/api.ts` | Constructs full SSE URL (use with EventSource + withCredentials) |
| `cn()` | `frontend/lib/cn.ts` | `clsx` + `tailwind-merge` — use for conditional class composition |
| `get_current_user` | `backend/app/api/deps.py` | FastAPI dependency for authenticated routes |
| `require_role()` | `backend/app/api/deps.py` | FastAPI dependency factory for RBAC gating |
| `require_feature()` | `backend/app/api/deps.py` | FastAPI dependency for feature-flag gating |
| `audit.log()` | `backend/app/services/audit.py` | Write structured audit event — call on any sensitive action |
| `upsert_assets()` | `backend/app/services/assets.py` | Dedup-aware asset persistence — only way to write assets |
| `upsert_vulns()` | `backend/app/services/vulns.py` | Dedup-aware vuln persistence |
| `sandbox.get_preexec_fn()` | `backend/app/workers/sandbox.py` | `preexec_fn` for subprocess resource limits (Unix only) |
| `resolve_args()` | `backend/app/services/scan_profiles.py` | Merge profile args + custom_args into final subprocess arg list |

### Shared UI components
| Component | Location | Purpose |
|---|---|---|
| `AppShell` | `components/AppShell.tsx` | Sidebar + breadcrumbs — wrap every authenticated page |
| `StatusBadge` | `components/StatusBadge.tsx` | Color-coded scan status chip |
| `ScanRow` | `components/ScanRow.tsx` | Recon job table row with lifecycle actions |
| `ScanConfigurationCard` | `components/workspace/ScanConfigurationCard.tsx` | Investigation task launcher with profile select + preview |
| `RawOutputCollapsible` | `components/workspace/tool-results/RawOutputCollapsible.tsx` | Universal `<details>` + copy button for raw tool output |
| `shared.tsx` | `components/workspace/tool-results/shared.tsx` | `SeverityBadge`, `statusVariant` — used by all 4 tool result components |
| `Badge`, `Button`, `Card`, `Tabs`, `Select` | `components/ui/` | Radix-based primitives (shadcn pattern) |

### Potential refactoring opportunities
- `frontend/app/targets/[id]/workspace/page.tsx` — 600+ line single-file component; split tab content into separate components (matches pattern used in `scans/[id]/page.tsx` with `components/tabs/`)
- `services/scan_view.py` and `services/vuln_view.py` — read-model builders could be extracted to a query layer as the number of views grows
- `frontend/lib/api.ts` — all types and helpers in one 600+ line file; no split needed yet but worth monitoring
- `services/queue.py` — add Redis connection pooling when scan submission frequency increases
- The `docs/superpowers/plans/` directory holds additional implementation plans from earlier sessions — review for any unrealized specs before adding features in those areas
