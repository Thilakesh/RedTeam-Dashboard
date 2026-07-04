# Red Team Recon Dashboard — Application Guide

A single, practical reference for what the application does, how it works, and
how to use it. Covers analyst workflows (scan, investigate, launch, delete),
admin workflows (users, sessions, settings), and developer workflows (run,
migrate, extend). Written to the current state of the codebase after the
Vulnerability Scans feature was removed (migration `0020`).

---

## 1. What the application is

Multi-tenant Attack Surface Management (ASM) platform for a red team analyst.
Given a domain, an analyst can:

1. **Basic Recon** — enumerate subdomains, resolve IPs, detect services / ports
   / technologies / WAF/CDN, capture screenshots, and get an LLM risk ranking.
2. **Target Workspace (Assets)** — take a completed recon scan and open a
   per-asset investigation console (Nmap Deep, FFUF, Dirsearch, TestSSL)
   against each subdomain / IP, with a scan-configuration UI + result pages.
3. **Operations Console** — launch a standalone one-off scan against a
   manually-typed domain or IP (no recon linkage), track it in a global
   history, view a structured result page.
4. **Administration** — manage users, sessions, feature flags, system settings
   (bbot timeout, OpenRouter API key + default model), and view an audit log.

Everything is scoped by tenant (`org_id`) and by user role (admin / analyst).

---

## 2. Runtime layout

Everything runs from `infra/` via Docker Compose. Containers:

| Service                | Purpose                                                       |
|------------------------|---------------------------------------------------------------|
| `postgres`             | Primary data store (Postgres 16). Bind-mounted `postgres_data`. |
| `redis`                | Queue broker + pub/sub for live progress events.               |
| `minio`                | Object store for screenshots (used by `gowitness`).            |
| `backend`              | FastAPI + Uvicorn on port `8000`. Runs `alembic upgrade head` on boot. |
| `frontend`             | Next.js 14 dev server on port `3000`.                          |
| `worker`               | Arq worker on the `default` queue — recon (quick/standard profiles). |
| `heavy-worker`         | Arq worker on the `heavy` queue — deep recon + BBOT enrichment. |
| `investigation-worker` | Arq worker on the `investigation` queue — per-asset investigations AND standalone operations. |

Boot: `cd infra && docker compose up --build` (first run) or `docker compose up`.

URLs:
- Frontend: <http://localhost:3000>
- API docs (OpenAPI Swagger): <http://localhost:8000/docs>
- MinIO console: <http://localhost:9001>

---

## 3. High-level architecture

```
Presentation  (Next.js App Router)                     frontend/
     │
     │ JSON + CSRF-guarded fetch (frontend/lib/api.ts::api())
     ▼
API           (FastAPI routers)                        backend/app/api/
     │
     ▼
Services      (business logic; auth, tenant scoping)   backend/app/services/
     │
     ▼  enqueue via Arq                          backend/app/services/queue.py
Queue         (Redis)
     │
     ▼
Workers       (Arq)                                     backend/app/workers/
     │
     ▼
Pipeline      (stages / adapters / DAG)                 backend/app/pipeline/
     │
     ▼
Data          (Postgres asset graph + observations)     backend/app/models/
```

Pub/sub: workers publish scan/task/operation progress to Redis; the API relays
via SSE (recon scans, investigation tasks) or the UI polls (operations).

---

## 4. Feature areas

### 4.1 Basic Recon

**UI:** `Basic Recon → Add Scan` (`/dashboard`) and `Recon Jobs` (`/dashboard/recon-jobs`).
Scan detail: `/scans/{id}` with tabs Overview / Subdomains / Ports / Findings /
CDN & WAF / Risks.

**Profiles** (`services/scan_profiles.py`):
- `quick` — subfinder → assetfinder → dnsx → httpx (light).
- `standard` — quick + naabu + nmap-lite + wafw00f + gowitness screenshots.
- `deep` — standard + BBOT enrichment (runs on `heavy-worker`).

**How to launch:**
- POST `/scans` with `{target: "example.com", profile: "quick"|"standard"|"deep"}`.
- Backend creates a `Scan` row, then `services/queue.py::enqueue_scan()` pushes
  the job to `default` or `heavy` queue.
- The worker runs the DAG in `pipeline/coordinator.py`, streaming stage events
  to Redis channel `scan:{scan_id}`. The UI subscribes via SSE
  `GET /scans/{id}/stream` and refreshes tabs as data lands.

**AI risk ranking:** `agents/risk_prioritizer.py` runs late in the DAG and calls
OpenRouter through `agents/bounded_completion.py`. It reads the API key and
model from the admin-controlled `system_settings` table (falls back to
`OPENROUTER_API_KEY` env + `openai/gpt-oss-20b:free`). Results appear on the
`Risks` tab.

**Deleting a scan:** each scan card in `/dashboard/recon-jobs` and the scan
detail page have a `Delete` button. Backend: `DELETE /scans/{id}` cascades
stages + observations + findings.

### 4.2 Target Workspace (Assets)

**Purpose:** analyst per-asset investigation on top of a completed recon scan.

**UI:** `Target Workspace → Assets` (`/targets`) → workspace detail at
`/targets/{target_id}/workspace` with tabs Overview / Subdomains / Run Scan Details.
Per-task result at `/targets/{target_id}/workspace/tasks/{task_id}`.

**Creating a workspace:** on the scan detail page for a completed scan, click
`Open Investigation Workspace`. Backend: `POST /target-workspaces` with
`{parent_scan_id}` is idempotent — repeat clicks return the existing workspace.

**Running a per-asset investigation task:** in the Subdomains tab, expand a
row to reveal `ScanConfigurationCard` (protocol, tool, profile, server-side
command preview, custom args, Run). Pick one of 4 tools:

| Tool         | Docker image                           | What it does                                 |
|--------------|----------------------------------------|----------------------------------------------|
| `nmap_deep`  | `investigation-worker`                 | Full nmap incl. NSE (`vuln`, `banner`).      |
| `ffuf`       | `investigation-worker`                 | Content-discovery fuzz (URL/FUZZ).           |
| `dirsearch`  | `investigation-worker`                 | Directory bruteforce.                        |
| `testssl`    | `investigation-worker`                 | TLS posture + weak-cipher checks.            |

Flow:
1. `POST /target-workspaces/{ws}/tasks` with `{asset_id, tool, params}`
   validates via `services/investigation_tasks.py`, stores `InvestigationTask`,
   and enqueues to the `investigation` Arq queue.
2. `workers/investigation_runner.py::run_investigation_task` loads the asset
   and adapter, executes it, publishes progress to
   `investigation:{task_id}`, and persists `InvestigationFinding` rows +
   `raw_output` + enrichment into shared `endpoints` / `tls_observations` /
   `services` / `technologies`.
3. UI polls the task detail every 3s or listens on the workspace SSE stream
   (`GET /target-workspaces/{ws}/stream`).

**Result pages** render structured per-tool views (services + NSE, endpoints
table with classifier flags, TLS protocols + cipher strength, plus a
collapsible raw-output panel) — never a raw terminal dump.

**Deleting a task:** the Run Scan Details tab has a delete icon per row.
`DELETE /target-workspaces/{ws}/tasks/{id}` cascades findings.

**Deleting the workspace:** `/targets` list has a delete action.
`DELETE /target-workspaces/{ws}` refuses to run while any task is in flight.

### 4.3 Operations Console

**Purpose:** run one-off manual scans against a hand-typed domain / IP with no
recon prerequisite. Standalone; **not** connected to Assets.

**UI:** top-level `Operations → Launch Operation` (`/operations/launch`) and
`Operations → Operation History` (`/operations`). Result at
`/operations/{operation_id}`.

**Launch Operation form fields**: Target Type (Domain / IP), Target (typed),
Tool (nmap / ffuf / dirsearch / testssl), Scan Profile (built-in + Custom…),
Protocol (http / https), Command Preview (server-authoritative, debounced),
Custom Args (editable in Custom profile), Start Operation.

Flow:
1. `POST /operations/preview` with `{target_type, target, tool, profile,
   protocol, custom_args}` returns `{generated_command}`. Validation:
   `services/operations_command.py::validate_target` (strict FQDN / IPv4
   allowlist — rejects leading `-`, whitespace, shell metacharacters →
   argument-injection safe). `validate_custom_args` denies per-tool
   output/file flags.
2. `POST /operations` inserts an `Operation` row (owned by
   `org_id`+`created_by`) and enqueues `run_operation` on the `investigation`
   Arq queue.
3. Worker reuses the four investigation adapters with a synthesized
   `TaskContext` (host = typed target, no asset), persists only
   `operation_findings` + `raw_output` (no recon graph enrichment), and
   publishes to `operation:{id}`.
4. The Operation History table polls every 4s while any op is queued/running.

**Available actions on an operation**: `View Results`, `Retry` (creates a new
operation copying target/tool/profile/params — original untouched), `Cancel`
(only while queued/running).

Delete is not exposed in the UI (the row is retained for audit); prune via SQL
if truly needed.

### 4.4 Administration

Nav: `Administration` (admin role required) — Users / Sessions / Feature
Controls / System Settings / Change Logs.

- **Users** (`/admin/users`) — list, create (invite email), toggle role,
  activate/deactivate.
- **Sessions** (`/admin/sessions`) — list all live sessions per user; revoke.
- **Feature Controls** (`/admin/features`) — per-user toggles for features
  listed in `backend/app/core/features.py::FEATURES` (deep_scan, ffuf,
  dirsearch, nmap, naabu, target_workspace, investigations, export_reports,
  gowitness). Missing row = enabled. Setting `enabled=false` disables.
- **System Settings** (`/admin/settings`):
  - **bbot timeout** — patches the in-memory setting (`PATCH /settings/system`).
  - **OpenRouter Configuration** — persistent card (`GET/POST
    /admin/settings/openrouter`). Fields: masked API key with show/hide
    toggle, model select (3 presets + Custom…), Test Connection (returns
    Connected / Invalid Key / Connection Failed), Save. The key is stored
    plaintext in `system_settings` (admin-gated table), never returned by the
    API (only `api_key_set` + last-4 hint), and never written to logs / audit
    meta. Saved values become the source of truth for the AI pipeline (DB-first,
    env fallback).
- **Change Logs** (`/admin/audit`) — every privileged action rows out of
  `app/services/audit.py::log()` (login, role changes, settings patches,
  user CRUD, session revokes).

---

## 5. Auth & tenant model

- **Auth**: RS256 JWT. Access token in `rt_access` HTTP-only cookie; refresh
  token in `rt_refresh`. CSRF via double-submit `rt_csrf` cookie + custom
  header (frontend `lib/api.ts` handles it automatically for POST/PATCH/DELETE).
- **Bootstrap**: on first boot the backend creates one Organization + one
  Project + one admin user from `ADMIN_EMAIL` / `ADMIN_PASSWORD` env vars.
- **Roles**: `admin` sees all rows across the org; `analyst` sees only their
  own (`Scan.created_by == user.id`). Enforced via
  `CurrentUser.scan_filter()`.
- **Tenant isolation**: every scan-relevant row is denormalized with
  `org_id`. Every query filters `where(org_id == user.org_id)`. Operations
  reuse this pattern; investigation tasks scope through the workspace's
  target.

---

## 6. Data model — what tables exist

Kept after the vuln-removal migration `0020`:

| Group          | Tables                                                             |
|----------------|--------------------------------------------------------------------|
| Identity       | `organizations`, `projects`, `users`, `refresh_sessions`, `user_features`, `blacklisted_jti`, `audit_logs` |
| Targets        | `targets`, `assets`, `asset_observations`                          |
| Recon scans    | `scans`, `scan_stages`, `services`, `technologies`, `findings`, `ai_usage` |
| Investigation  | `target_workspaces`, `investigation_tasks`, `investigation_findings` |
| Shared enrich  | `endpoints`, `endpoint_observations`, `tls_observations`           |
| Operations     | `operations`, `operation_findings`                                 |
| Settings       | `system_settings`                                                   |

Dropped in `0020`: `vulnerabilities`, `vuln_evidence`, `vuln_run_matches`,
`cve_intel`, `hvt_signals` + Scan columns `kind` / `parent_scan_id` /
`intrusive` + 4 enums (`scan_kind`, `vuln_severity`, `vuln_status`,
`hvt_signal_type`).

---

## 7. Selected API surface

Grouped by prefix. Every route requires auth; admin-only routes marked ★.

| Prefix                  | Highlights                                                       |
|-------------------------|------------------------------------------------------------------|
| `/auth`                 | `POST /login`, `POST /refresh`, `POST /logout`, `GET /me`, `POST /accept-invite` |
| `/scans`                | `GET /` (list), `POST /` (create), `GET /{id}`, `PATCH /{id}`, `DELETE /{id}`, `POST /{id}/stop`, `GET /{id}/stream` (SSE), `GET /{id}/overview\|/subdomains\|/ports\|/findings` |
| `/targets`              | `GET /` (list)                                                    |
| `/target-workspaces`    | `GET /`, `POST /`, `GET /{id}`, `DELETE /{id}`, `GET /{id}/overview\|/subdomains\|/tasks\|/stream`, `POST /{id}/tasks`, `GET/DELETE /{id}/tasks/{tid}`, `POST /{id}/operations/preview`, `POST /{id}/tasks/{tid}/cancel\|/retry` |
| `/operations`           | `POST /preview`, `POST /`, `GET /`, `GET /{id}`, `POST /{id}/cancel`, `POST /{id}/retry` |
| `/settings`             | `GET/PATCH /profile`, ★ `GET/PATCH /system`                       |
| `/admin/settings/openrouter` ★ | `GET`, `POST`, `POST /test` (masked; key never returned)  |
| `/admin/audit` ★        | `GET /` (filters: actor, action, from, to, limit)                 |
| `/users` ★              | invite / list / patch / revoke                                    |
| `/sessions`             | `GET /` (own), ★ list-all / revoke                                |
| `/health`               | Public — `{status: "ok"}`                                          |

OpenAPI is always canonical: <http://localhost:8000/docs>.

---

## 8. How to scan and how to delete (recipes)

Curl-style examples assume you've logged in and are carrying the cookies +
`X-CSRF-Token` header (any HTTPie / Postman equivalent works; the frontend
does it automatically).

### Start a recon scan
```
POST /scans
{ "target": "example.com", "profile": "quick" }
```

### Poll or stream progress
```
GET /scans/{id}/overview      # snapshot
GET /scans/{id}/stream        # SSE — emits scan.started / stage.* / scan.completed / scan.failed
```

### Open a Target Workspace on a completed scan
```
POST /target-workspaces
{ "parent_scan_id": "<completed scan uuid>" }
```

### Run a per-asset investigation task
```
POST /target-workspaces/{ws}/tasks
{ "asset_id": "<subdomain-asset-uuid>",
  "tool":     "nmap_deep",
  "params":   { "profile": "aggressive", "protocol": "https" } }
```

### Preview + start a standalone operation
```
POST /operations/preview
{ "target_type": "domain", "target": "example.com",
  "tool": "testssl", "profile": "full", "protocol": "https" }
# → { "generated_command": "testssl.sh --quiet --color 0 --jsonfile <tmp> --protocols --server-defaults --vulnerable -E example.com:443" }

POST /operations           # same body → returns the OperationOut row (queued)
POST /operations/{id}/cancel
POST /operations/{id}/retry
```

### Configure OpenRouter
```
POST /admin/settings/openrouter          { "api_key": "sk-or-...", "default_model": "openai/gpt-4o" }
POST /admin/settings/openrouter/test     { }   # tests the stored/env key against openrouter.ai/api/v1/models
GET  /admin/settings/openrouter          # { api_key_set: true, api_key_hint: "…abcd", default_model: "openai/gpt-4o" }
```

### Delete recipes
| Thing              | Path                                                | Cascades / rules                          |
|--------------------|-----------------------------------------------------|-------------------------------------------|
| Scan               | `DELETE /scans/{id}`                                 | Stages + observations + findings          |
| Investigation task | `DELETE /target-workspaces/{ws}/tasks/{tid}`         | Findings                                  |
| Workspace          | `DELETE /target-workspaces/{ws}`                     | 409 if any task is queued/running; otherwise cascades tasks + findings |
| User               | `DELETE /users/{id}` ★                               | Marks inactive + revokes sessions         |
| Session            | `DELETE /sessions/{id}` (own) or ★ `/admin/sessions/{id}` | Refresh token invalidated              |
| Operation          | Not exposed via UI — manual SQL if truly needed. Cancel + Retry cover the analyst flow. |

---

## 9. Adding a new investigation tool (developer)

1. Write an adapter under
   `backend/app/pipeline/investigation/adapters/mytool.py` — implement the
   `InvestigationAdapter` protocol (`tool: str`, `async def execute(ctx:
   TaskContext) -> InvestigationResult`). Reuse: `scan_profiles.resolve_args`
   for arg templating, `workers/sandbox.get_preexec_fn` for RLIMIT sandbox,
   `asyncio.create_subprocess_exec` (never `shell=True`).
2. Register it in
   `backend/app/pipeline/investigation/registry.py::ADAPTERS`.
3. If it's a new CLI binary, install it in
   `infra/Dockerfile.investigation_worker` (pin the version; verify with
   `--version` at build time). Then rebuild:
   `docker compose up --build investigation-worker`.
4. Add a profile bundle for it in `backend/app/services/scan_profiles.py`
   (`PROFILES[tool] = {binary, default, profiles: [...]}`) so the frontend
   dropdown surfaces it automatically.
5. If Operations should support it, add it to the `TOOLS` set +
   `_DEFAULT_ARGS` shape in `backend/app/services/operations_command.py`.
6. Wire a result renderer:
   `frontend/components/workspace/tool-results/MyToolResult.tsx`, and dispatch
   it from `frontend/app/targets/[id]/workspace/tasks/[task_id]/page.tsx` and
   `frontend/app/operations/[operation_id]/page.tsx` on `tool === "mytool"`.

---

## 10. Migrations & schema changes

Location: `backend/migrations/versions/`. Current head: `0020` (see any file
prefix).

```
# generate
docker compose exec backend alembic revision --autogenerate -m "describe change"
# apply
docker compose exec backend alembic upgrade head
# roll back one
docker compose exec backend alembic downgrade -1
```

Rules:
- Every new ORM class **must** be added to `backend/app/models/__init__.py`
  or autogenerate won't diff it.
- For a fresh Postgres ENUM, follow the `postgresql.ENUM(..., create_type=False)`
  + `.create(op.get_bind(), checkfirst=True)` pattern in
  `migrations/versions/0001_initial.py`. Don't let SQLAlchemy re-emit `CREATE
  TYPE` from a column — that's the "ENUM gotcha" that kept biting us.
- Prefer plain `VARCHAR(N)` for new status columns (see `operations.status`
  or `system_settings.key`) — cleaner migrations.

---

## 11. Frontend conventions

- **Nav** is centralized in `frontend/components/AppShell.tsx`
  (`NAV_MAIN` + `NAV_ADMIN`). Breadcrumbs are pattern-matched in
  `buildBreadcrumb`.
- **API client**: everything routes through `frontend/lib/api.ts::api<T>()`.
  It auto-attaches CSRF, refreshes on 401 once, and formats Pydantic error
  arrays.
- **State**: TanStack Query for reads (with `refetchInterval` where a task /
  scan / operation may be active). `useState` for form drafts.
- **Result renderers** live under `frontend/components/workspace/tool-results/`
  and are shared between the Investigation task page and the Operation result
  page.
- **Path alias**: `@/*` maps to `frontend/*` (see `tsconfig.json`).
- Type-check before shipping: `cd frontend && npx tsc --noEmit`.

---

## 12. Troubleshooting

| Symptom                                                     | Likely cause / fix                                    |
|-------------------------------------------------------------|-------------------------------------------------------|
| `backend` container exits right after boot                  | Alembic failure — `docker compose logs backend --tail=80`. Usually a stale `alembic_version` referencing a missing migration file. Fix: stamp to the correct rev in psql, then re-boot. |
| Frontend `/*` returns 500 (Next.js)                         | `.next` cache stale/missing after a bind-mounted file was removed on host. Fix: `docker compose restart frontend` — the dev server rebuilds. |
| "OPENROUTER_API_KEY is not set — cannot call risk prioritizer" | Admin has neither saved a key in `/admin/settings` nor set the env var. |
| Investigation task stuck in `queued`                         | `investigation-worker` container isn't running or wasn't restarted after Python changes. `docker compose restart investigation-worker`. |
| CORS / `ERR_CONNECTION_REFUSED` from the browser             | Backend container exited silently (see above). If actually reachable but returning no `Access-Control-Allow-Origin`, the origin isn't matched by `cors_origin_regex` — check `backend/app/core/config.py`. |
| Preview command in Launch Operation doesn't match execution  | Adapter argv drift. Preview is server-side in `operations_command.render_command` — must mirror the adapter's inline argv. |

---

## 13. What is *not* in the codebase (removed)

- **Vulnerability Analysis** (M-Vuln-1 … M-Vuln-8): the CVE-tagged
  Vulnerability entity, nuclei / correlator / AI-triage stages, HVT signal
  scoring, EPSS/KEV feeds refresher, `/vuln-scans` UI, `/targets/{id}/risk`
  rollup — all deleted in the migration behind `0020_drop_vuln_feature`. The
  `endpoints` / `tls_observations` tables stayed because Investigation
  adapters write to them.
- The old scan-authorization gate (verified-target-only). Access is now
  role-based only (admin/analyst) with per-user feature flags.

---

## 14. Where to look for what

| Topic                     | File                                                        |
|---------------------------|-------------------------------------------------------------|
| Nav + breadcrumbs         | `frontend/components/AppShell.tsx`                          |
| API client + types        | `frontend/lib/api.ts`                                       |
| Scan submit + list        | `backend/app/api/scans.py` + `frontend/app/dashboard/**`    |
| Recon DAG                 | `backend/app/pipeline/coordinator.py` + `pipeline/adapters/`|
| Investigation adapters    | `backend/app/pipeline/investigation/adapters/`              |
| Operations command builder| `backend/app/services/operations_command.py`                |
| System settings (DB)      | `backend/app/services/system_settings.py`                   |
| Auth deps + roles         | `backend/app/api/deps.py`                                   |
| Queue names + enqueues    | `backend/app/services/queue.py`                             |
| Migrations                | `backend/migrations/versions/`                              |
| Dev instructions          | `CLAUDE.md`, this file (`APPLICATION_GUIDE.md`)             |
