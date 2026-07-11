# Technical Documentation

Developer reference for the current codebase. For architecture, see
[`architecture.md`](architecture.md). For onboarding, see
[`developer-handover.md`](developer-handover.md). For end-user recipes, see
[`../APPLICATION_GUIDE.md`](../APPLICATION_GUIDE.md).

---

## 1. Backend layout

```
backend/
├── app/
│   ├── main.py                # FastAPI app, router registration, startup bootstrap
│   ├── agents/                # LLM wrappers (OpenRouter). bounded_completion + risk_prioritizer
│   ├── api/                   # FastAPI routers grouped by prefix
│   │   ├── admin/             # /admin/audit, /admin/settings/openrouter (admin-gated)
│   │   ├── auth.py            # /auth (login, refresh, logout, invites, me)
│   │   ├── scans.py           # /scans (recon submit + list + streams + tabs)
│   │   ├── targets.py         # /targets (list only)
│   │   ├── target_workspaces.py # /target-workspaces (investigation)
│   │   ├── operations.py      # /operations (standalone manual scans)
│   │   ├── settings.py        # /settings (profile + admin system settings)
│   │   ├── users.py           # /users (admin CRUD)
│   │   └── sessions.py        # /sessions (self + admin listing/revoke)
│   ├── core/
│   │   ├── config.py          # Pydantic Settings (env-backed)
│   │   ├── db.py              # SQLAlchemy async engine + SessionLocal + Base
│   │   ├── security.py        # bcrypt hash/verify (no passlib)
│   │   ├── keys.py            # RS256 keypair bootstrap
│   │   └── features.py        # Per-user feature flag store + cache
│   ├── models/                # SQLAlchemy 2.0 async ORM classes
│   ├── pipeline/
│   │   ├── stage.py           # Recon Stage protocol + StageContext + AssetRecord
│   │   ├── coordinator.py     # Recon DAG executor
│   │   ├── profiles.py        # quick/standard/deep stage lists
│   │   ├── adapters/          # Recon adapters (subfinder, dnsx, httpx, naabu, nmap, wafw00f, gowitness, bbot, ...)
│   │   └── investigation/
│   │       ├── stage.py       # InvestigationAdapter + TaskContext + records
│   │       ├── registry.py    # tool → adapter mapping
│   │       └── adapters/      # nmap_deep, ffuf, dirsearch, testssl
│   ├── schemas/               # Pydantic v2 request/response models
│   ├── services/              # Business logic (asset upsert, scan_view, queue, ...)
│   └── workers/               # Arq worker entrypoints + sandbox helper
├── migrations/                # Alembic
│   └── versions/              # 0001 … 0020 (head)
└── pyproject.toml             # ruff config; deps include arq, sqlalchemy[asyncio], httpx, ...
```

---

## 2. Frontend layout

```
frontend/
├── app/                       # Next.js App Router
│   ├── (auth)/login/          # public
│   ├── accept-invite/         # public (invited user first login)
│   ├── home/                  # landing dashboard
│   ├── dashboard/             # Basic Recon: Add Scan + Recon Jobs
│   ├── scans/[id]/            # Scan detail (tabs)
│   ├── targets/               # Target Workspace list + detail
│   ├── operations/            # Operations Console (list, launch, result)
│   ├── settings/              # own profile + sessions
│   └── admin/                 # admin panels
├── components/
│   ├── AppShell.tsx           # nav, breadcrumbs, top bar
│   ├── ui/                    # buttons, cards, selects, badges
│   ├── tabs/                  # recon tabs (Overview, Subdomains, Ports, ...)
│   ├── workspace/             # investigation UI (ScanConfigurationCard, ScansDropdown, tool-results/*)
│   └── operations/            # (form components live inline in launch page currently)
├── lib/
│   ├── api.ts                 # single source of truth for HTTP + types
│   └── auth-context.tsx       # useAuth (SWR-like context around /auth/me)
└── middleware.ts              # edge auth gate on protected paths
```

Path alias: `@/*` → `frontend/*`. TypeScript strict.

---

## 3. API surface (by prefix)

All routes require auth unless marked public. Admin-only routes marked ★.

### `/auth` (public + authenticated)
| Method | Path                    | Purpose                                         |
|--------|-------------------------|-------------------------------------------------|
| POST   | `/auth/login`           | Set `rt_access` + `rt_refresh` + `rt_csrf`      |
| POST   | `/auth/refresh`         | Rotate refresh + reissue access                  |
| POST   | `/auth/logout`          | Revoke session + clear cookies                   |
| POST   | `/auth/accept-invite`   | First-login flow for invited users               |
| GET    | `/auth/me`              | Current-user profile                             |

### `/scans` (recon)
| Method | Path                          | Purpose                                                  |
|--------|-------------------------------|----------------------------------------------------------|
| GET    | `/scans`                      | List (org-scoped, `scan_filter` on `created_by`)         |
| POST   | `/scans`                      | Create (`{target, profile}`). Enqueues via `enqueue_scan`.|
| GET    | `/scans/{id}`                 | Detail (`ScanDetail`: scan + stages + assets)            |
| PATCH  | `/scans/{id}`                 | Update profile (only while queued)                       |
| DELETE | `/scans/{id}`                 | Cascade stages + observations + findings                 |
| POST   | `/scans/{id}/stop`            | Set status=stopped, cancel running stages                |
| GET    | `/scans/{id}/stream`          | **SSE** — live stage / progress events                   |
| GET    | `/scans/{id}/overview\|/subdomains\|/ports\|/findings\|/cdn-waf` | Per-tab data           |

### `/targets`
| Method | Path      | Purpose                              |
|--------|-----------|--------------------------------------|
| GET    | `/targets`| List targets in the org              |

### `/target-workspaces` (investigation)
| Method | Path                                                    | Purpose                                                 |
|--------|---------------------------------------------------------|---------------------------------------------------------|
| GET    | `/target-workspaces`                                    | List workspaces                                          |
| POST   | `/target-workspaces`                                    | Create/get by `parent_scan_id` (idempotent)              |
| GET    | `/target-workspaces/{id}`                               | Detail                                                    |
| DELETE | `/target-workspaces/{id}`                               | 409 if a task is queued/running; else cascade            |
| GET    | `/target-workspaces/{id}/overview\|/subdomains\|/tasks` | Tab data (`hvt_count` returns `0`, `hvt_signal_summary` is empty since vuln removal) |
| GET    | `/target-workspaces/{id}/stream`                        | **SSE** — task events                                     |
| POST   | `/target-workspaces/{id}/tasks`                         | Create investigation task (`{asset_id, tool, params}`)   |
| GET/DELETE | `/target-workspaces/{id}/tasks/{tid}`               | Detail / delete                                           |
| POST   | `/target-workspaces/{id}/tasks/{tid}/cancel\|/retry`    | Lifecycle actions                                         |
| POST   | `/target-workspaces/{id}/operations/preview`            | Server-authoritative command preview for a task          |
| GET    | `/target-workspaces/scan-profiles`                      | `PROFILES` catalog (used by Scan Configuration UI)       |

### `/operations` (standalone manual)
| Method | Path                              | Purpose                                                                 |
|--------|-----------------------------------|-------------------------------------------------------------------------|
| POST   | `/operations/preview`             | Validate + render `generated_command` (never touches DB)               |
| POST   | `/operations`                     | Create + enqueue (`org_id`+`created_by` scoped)                          |
| GET    | `/operations`                     | List (org-scoped)                                                       |
| GET    | `/operations/{id}`                | `{operation, findings, raw_output}`                                     |
| POST   | `/operations/{id}/cancel`         | Only while queued/running (409 else); publishes `operation.cancelled`   |
| POST   | `/operations/{id}/retry`          | Copy target/tool/profile/params into new operation                      |

### `/settings`
| Method | Path                | Purpose                                                    |
|--------|---------------------|------------------------------------------------------------|
| GET    | `/settings/profile` | Own profile                                                 |
| PATCH  | `/settings/profile` | Update email / name / password (audit-logged)              |
| GET    | `/settings/system` ★| bbot timeout + JWT TTLs                                     |
| PATCH  | `/settings/system` ★| Patch bbot_timeout (in-memory only)                         |

### `/admin/settings/openrouter` ★
| Method | Path                                | Purpose                                                             |
|--------|-------------------------------------|---------------------------------------------------------------------|
| GET    | `/admin/settings/openrouter`        | `{api_key_set, api_key_hint, default_model}` (raw key never returned)|
| POST   | `/admin/settings/openrouter`        | Save (empty `api_key` = keep existing)                              |
| POST   | `/admin/settings/openrouter/test`   | `connected` / `invalid_key` / `connection_failed`                    |

### `/admin/audit` ★
| Method | Path            | Purpose                                              |
|--------|-----------------|------------------------------------------------------|
| GET    | `/admin/audit`  | Query with `actor`, `action`, `from`, `to`, `limit` |

### `/users` ★ and `/sessions`
Standard admin CRUD + self session listing / revoke.

### `/health` (public)
`GET /health` → `{status: "ok"}`.

Canonical spec: `GET /openapi.json` and Swagger UI at `/docs`.

---

## 4. Data model (models → tables)

Every ORM class **must** be exported from `backend/app/models/__init__.py` or
alembic autogenerate won't diff it.

| Model                             | Table                     | Key columns / notes                                          |
|-----------------------------------|---------------------------|--------------------------------------------------------------|
| `Organization`, `Project`         | `organizations`, `projects` | Tenant hierarchy. One default org is bootstrapped on boot. |
| `User`, `UserFeature`, `UserRole` | `users`, `user_features`  | RS256 JWT sub is `users.id`. `role` = admin \| analyst.      |
| `RefreshSession`, `BlacklistedJti`| `refresh_sessions`, `blacklisted_jti` | Rotating refresh + JTI blacklist for CSRF/rotation. |
| `AuditLog`                        | `audit_logs`              | Append-only. `audit.log(...)`.                                |
| `Target`                          | `targets`                 | One row per submitted domain (per project).                   |
| `Asset`, `AssetObservation`       | `assets`, `asset_observations` | Deduped asset graph + per-scan history.                 |
| `Scan`, `ScanStage`, `ScanStatus`, `StageStatus` | `scans`, `scan_stages` | Recon scan lifecycle. `parent_scan_id` and `kind` removed in `0020`. |
| `Service`, `ServiceClassification`| `services`                | Recon writes; distinct from Asset for host:port granularity.  |
| `Technology`                      | `technologies`            | Recon writes (name/version/CPE per asset).                    |
| `Finding`, `FindingSeverity`      | `findings`                | Recon-tier signals ranked by `RiskPrioritizerStage`.          |
| `Endpoint`, `EndpointObservation` | `endpoints`, `endpoint_observations` | Shared. Written by investigation adapters (ffuf/dirsearch).|
| `TlsObservation`                  | `tls_observations`        | Shared. Written by investigation `testssl`.                   |
| `TargetWorkspace`, `WorkspaceStatus` | `target_workspaces`     | One workspace per (target, parent_scan) — idempotent.         |
| `InvestigationTask`, `InvestigationTaskStatus`, `InvestigationFinding` | `investigation_tasks`, `investigation_findings` | Per-task rows; findings drive result renderers. |
| `Operation`, `OperationStatus`, `OperationFinding` | `operations`, `operation_findings` | Standalone operations; VARCHAR(16) status (no ENUM). |
| `AiUsage`                          | `ai_usage`                | LLM token accounting (per scan).                              |
| `SystemSetting`                    | `system_settings`         | Generic key-value (openrouter_api_key, openrouter_default_model). |

---

## 5. Queues and worker functions

`backend/app/services/queue.py`:

| Fn                                | Redis queue     | Arq job              | Handler                                                |
|-----------------------------------|-----------------|----------------------|--------------------------------------------------------|
| `enqueue_scan(scan_id, profile)`  | `default`/`heavy` | `run_scan`         | `backend/app/workers/runner.py::run_scan`              |
| `enqueue_investigation_task(id)`  | `investigation` | `run_investigation_task` | `backend/app/workers/investigation_runner.py::run_investigation_task` |
| `enqueue_operation(id)`           | `investigation` | `run_operation`      | `backend/app/workers/investigation_runner.py::run_operation` |

`InvestigationWorkerSettings.functions = [run_investigation_task, run_operation]`
so a single container serves both entry points.

---

## 6. Migrations workflow

Migrations live in `backend/migrations/versions/`. Current head: `0020`.

```
# generate from ORM diff
docker compose exec backend alembic revision --autogenerate -m "describe change"

# apply
docker compose exec backend alembic upgrade head

# roll back one
docker compose exec backend alembic downgrade -1

# stamp DB to a specific rev (fix out-of-sync alembic_version)
docker compose exec backend alembic stamp <revision>
```

### Rules

- Every new ORM class must be added to `backend/app/models/__init__.py` (both
  the `import` line and the `__all__` list) — otherwise autogenerate won't see
  it.
- For a fresh Postgres ENUM: build the `postgresql.ENUM(..., name="...",
  create_type=False)` **once**, call `.create(op.get_bind(), checkfirst=True)`,
  and reuse the same instance in every column. Never let SQLAlchemy re-emit
  `CREATE TYPE` from a column — that's the "ENUM gotcha" that repeatedly bit
  us. See `0001_initial.py` and the removed `0006_vuln_tables.py` for
  reference.
- Prefer `VARCHAR(N)` over Postgres ENUM for new status columns (see
  `operations.status` = `VARCHAR(16)` — no ENUM to migrate later).
- Forward-only removals are allowed. See `0020_drop_vuln_feature.py` for the
  pattern.

---

## 7. Config (`backend/app/core/config.py`)

Pydantic `Settings` (env-backed via `.env` in `infra/`). Key fields:

| Field                          | Env var (implicit)          | Default            |
|--------------------------------|-----------------------------|--------------------|
| `database_url`                 | `DATABASE_URL`              | postgres async DSN |
| `redis_url`                    | `REDIS_URL`                 |                     |
| `openrouter_api_key`           | `OPENROUTER_API_KEY`        | ``                  |
| `bbot_timeout`                 | `BBOT_TIMEOUT`              | `1800`              |
| `jwt_access_expire_minutes`    | ...                         | `15`                |
| `jwt_refresh_expire_days`      | ...                         | `30`                |
| `admin_email`, `admin_password`| ...                         | bootstrap admin     |
| `default_org_name`             | ...                         | bootstrap org       |
| `cors_origins`, `cors_origin_regex` | ...                    | localhost defaults  |

`get_settings()` is `@lru_cache`d — env changes need a container restart. DB
settings that must be hot-swappable go through `services/system_settings.py`
instead (see OpenRouter).

---

## 8. Conventions

- Python 3.11. `ruff` config in `backend/pyproject.toml`, line length 100.
- SQLAlchemy 2.0 async: `await db.scalar(select(...))` / `db.execute(...)`.
  Never the legacy `Query` API.
- Pydantic v2. Response schemas use `model_config = ConfigDict(from_attributes=True)`
  where they mirror ORM shapes.
- Passwords use `bcrypt` directly, not `passlib` (see `core/security.py`
  comment for the gotcha).
- CORS allows any `localhost` / `127.0.0.1` port via `cors_origin_regex`.
  Explicit prod origins go in `cors_origins`.
- Frontend fetch always goes through `frontend/lib/api.ts::api()` — it
  attaches CSRF, refreshes on 401 once, and formats Pydantic 422 arrays.

---

## 9. Testing (current state)

No formal test suite in-tree yet. Verification is:
- **`ruff check app/`** for lint.
- **Import check**: `docker compose exec backend python -c "import app.main"`.
- **`tsc --noEmit`** for the frontend.
- **Manual e2e** via browser (see the verification steps in each PR).

When tests land, prefer `pytest` + `pytest-asyncio` (already declared as
optional deps) and integration-style tests against real Postgres + Redis via
`testcontainers`.
