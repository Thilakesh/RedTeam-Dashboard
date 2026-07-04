# Red Team Recon Dashboard

Multi-tenant Attack Surface Management (ASM) platform. Submit a domain, run a recon pipeline, discover services, investigate assets, and launch standalone operations — all scoped per tenant with a full audit trail.

**Architecture and detailed roadmap:** [`you-are-a-senior-shiny-hearth.md`](you-are-a-senior-shiny-hearth.md)
**Technical documentation:** [`docs/technical-documentation.md`](docs/technical-documentation.md)
**Architecture diagrams:** [`docs/architecture.md`](docs/architecture.md)
**Developer handover:** [`docs/developer-handover.md`](docs/developer-handover.md)

---

## Feature Matrix

| Feature | Milestone | Status |
|---|---|---|
| FastAPI + Next.js scaffold, Postgres, Redis, Arq | M0 | Deployed |
| Subfinder recon, asset graph (Asset + AssetObservation) | M0 | Deployed |
| DAG executor (parallel levels), Stage protocol | M1 | Deployed |
| Adapters: subfinder, assetfinder, amass, dnsx, httpx, wafw00f, asnmap, geoip | M1 / M1.5 | Deployed |
| Subdomain-centric UI (TanStack Table, all tabs) | M1.5 | Deployed |
| Active scanning: naabu, nmap, gowitness + MinIO screenshots | M2 | Deployed |
| AI risk prioritization (OpenRouter, Risks tab) | M3 | Deployed |
| Workflow dashboard: Add Scan / Recon Jobs, queued/stopped lifecycle | M4 | Deployed |
| BBOT enrichment (heavy-worker, deep profile) | M5 | Deployed |
| Vulnerability analysis pipeline (M-Vuln-1..M-Vuln-8) | — | **Removed** |
| Target Workspace: 4 investigation adapters (TestSSL/Nmap/FFUF/Dirsearch) | M-TW-1 | Deployed |
| Scan profiles, ScanConfigurationCard with command preview | M-TW-2 (partial) | Deployed |
| RS256 JWT + rotating-refresh cookies + CSRF + RBAC (admin/analyst) | Auth overhaul | Deployed |
| Admin panel: users, sessions, audit log, feature flags | Auth overhaul | Deployed |
| Invite-only onboarding (no public signup) | Auth overhaul | Deployed |
| Delete functionality (scans, workspaces, tasks) | Auth overhaul | Deployed |
| Scan authorization gating removed (trusted-operator model) | elegant-yeti | Deployed |
| Manual standalone operations (no recon asset required) | logical-otter | **Pending** |

---

## Tech Stack

| Layer | Technology | Version |
|---|---|---|
| Frontend | Next.js App Router | 14.x |
| UI components | Radix UI primitives + Tailwind CSS | latest |
| Data fetching | TanStack Query (React Query) | 5.x |
| Backend API | FastAPI + Uvicorn | 0.110+ |
| ORM | SQLAlchemy 2.0 async | 2.x |
| Migrations | Alembic | 1.13+ |
| Task queue | Arq (asyncio-first, Redis-backed) | 0.25+ |
| Database | PostgreSQL | 16 |
| Cache / pub-sub | Redis | 7 |
| Object storage | MinIO | 2024-01 |
| Auth | RS256 JWT (python-jose) + bcrypt | 3.3 / 4.1+ |
| AI | OpenRouter → openai/gpt-oss-20b:free | — |
| Recon tools | subfinder, assetfinder, amass, dnsx, httpx, naabu, nmap, gowitness, wafw00f, bbot | pinned in Dockerfiles |
| Investigation tools | nmap, ffuf 2.1.0, dirsearch 0.4.3, testssl 3.2 | pinned in Dockerfile.investigation_worker |
| Language | Python 3.11+ / TypeScript 5.x | — |

---

## Quick Start

Requires Docker Desktop.

```bash
cd infra
docker compose up --build   # first run (pulls images, installs recon tools)
docker compose up           # subsequent runs
docker compose down         # stop
```

The backend runs `alembic upgrade head` on startup — migrations apply automatically.

| Service | URL |
|---|---|
| Frontend | http://localhost:3000 |
| API + Swagger | http://localhost:8000/docs |
| MinIO console | http://localhost:9001 |

**First login:** An admin account is bootstrapped on first startup using `ADMIN_EMAIL` / `ADMIN_PASSWORD` env vars (defaults: `alpha@gmail.com` / `Testing123@`). There is no public signup — all users are invited by an admin.

**Hot reload:** backend and frontend source directories are bind-mounted. Edit files freely; no rebuild needed. Rebuild only when changing `pyproject.toml`, `package.json`, or a worker Dockerfile.

**After Python module changes to workers:** restart the affected worker:
```bash
docker compose restart worker heavy-worker investigation-worker
```

---

## Environment Variables

### Required for production

| Variable | Description |
|---|---|
| `JWT_SECRET` / keypair | RS256 keys auto-generated into `jwt_secrets` volume on first boot |
| `ADMIN_EMAIL` | Bootstrap admin email (default: `alpha@gmail.com`) |
| `ADMIN_PASSWORD` | Bootstrap admin password (default: `Testing123@`) |
| `OPENROUTER_API_KEY` | Required for deep recon scans (AI risk prioritization) |

### Service URLs (Docker internal, override only if not using Compose)

| Variable | Default | Used by |
|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://recon:recon@postgres:5432/recon` | backend, workers |
| `REDIS_URL` | `redis://redis:6379/0` | backend, workers |
| `MINIO_URL` | `http://minio:9000` | worker (SDK connections) |
| `MINIO_PUBLIC_URL` | `http://localhost:9000` | worker (browser-accessible URLs) |
| `MINIO_ACCESS_KEY` | `minioadmin` | worker |
| `MINIO_SECRET_KEY` | `minioadmin` | worker |
| `MINIO_BUCKET` | `recon` | worker |

### Auth tuning (optional)

| Variable | Default | Description |
|---|---|---|
| `JWT_ACCESS_EXPIRE_MINUTES` | `10` | Access token TTL |
| `JWT_REFRESH_EXPIRE_DAYS` | `14` | Refresh token TTL |
| `COOKIE_SECURE` | `false` | Set `true` in production (HTTPS only) |
| `SUPER_ADMIN_EMAIL` | Same as `ADMIN_EMAIL` | Cannot be disabled/demoted |

### Other

| Variable | Default | Description |
|---|---|---|
| `PDCP_API_KEY` | hardcoded dev key | ProjectDiscovery Cloud Platform (asnmap) |
| `BBOT_TIMEOUT` | `1800` | Max seconds for BBOT enrichment |
| `CORS_ORIGINS` | `["http://localhost:3000"]` | Explicit non-localhost origins for production |

Secret source of truth: `infra/.env` (gitignored). `backend/.env` is only for running the backend directly outside Docker.

---

## Database Migrations

```bash
# create a new migration (run inside the backend container)
docker compose exec backend alembic revision --autogenerate -m "describe change"

# apply pending migrations
docker compose exec backend alembic upgrade head

# roll back one step
docker compose exec backend alembic downgrade -1
```

**ENUM gotcha:** build a single `postgresql.ENUM(...)` instance, call `.create(op.get_bind(), checkfirst=True)` once, then reference **that same instance** in every column. See `migrations/versions/0001_initial.py` for the working pattern.

**New model registration:** add every new ORM class to `backend/app/models/__init__.py` or autogenerate will not see it.

---

## Folder Structure

```
.
├── backend/
│   ├── app/
│   │   ├── api/              # FastAPI routers (auth, scans, targets, vuln-scans, workspaces…)
│   │   │   ├── admin/        # Admin-only: audit log
│   │   │   └── middleware/   # CSRF middleware
│   │   ├── core/             # config, db, redis, security, tokens, keys, features
│   │   ├── models/           # SQLAlchemy ORM (22 models, all exported from __init__.py)
│   │   ├── schemas/          # Pydantic v2 request/response models
│   │   ├── pipeline/
│   │   │   ├── adapters/     # Recon tool adapters (subfinder, nmap, bbot…)
│   │   │   ├── vuln/         # Vulnerability pipeline (coordinator, adapters, profiles)
│   │   │   └── investigation/# Investigation pipeline (adapters, registry, stage protocol)
│   │   ├── services/         # Business logic (assets, vulns, scan_view, queue, scan_profiles…)
│   │   ├── agents/           # LLM wrappers (risk_prioritizer, bounded_completion)
│   │   └── workers/          # Arq worker entrypoints (runner, vuln_runner, investigation_runner…)
│   ├── migrations/versions/  # Alembic migration files (0001→0017 + named)
│   └── pyproject.toml
├── frontend/
│   ├── app/
│   │   ├── (auth)/           # Login + accept-invite (no AppShell)
│   │   ├── admin/            # Admin pages (users, sessions, audit, settings, features)
│   │   ├── dashboard/        # Add Scan + Recon Jobs table
│   │   ├── scans/[id]/       # Recon scan detail (8 tabs)
│   │   ├── vuln-scans/       # Vuln scan list + detail (9 tabs) + endpoint detail
│   │   ├── targets/          # Target list + workspace + risk rollup
│   │   └── settings/         # User profile + sessions
│   ├── components/
│   │   ├── ui/               # Radix-based primitives (shadcn-style)
│   │   ├── tabs/             # Recon scan tab components (Overview, IPs, CDN/WAF…)
│   │   └── workspace/        # Target workspace: ScanConfigurationCard, tool-result renderers
│   └── lib/
│       ├── api.ts            # Typed fetch wrapper + all API helpers + TypeScript types
│       └── auth-context.tsx  # React auth context (current user, login/logout)
├── infra/
│   ├── docker-compose.yml
│   ├── Dockerfile.app        # Backend API
│   ├── Dockerfile.worker     # Default recon worker
│   ├── Dockerfile.heavy-worker # Deep recon + BBOT
│   ├── Dockerfile.vuln_worker  # Vulnerability analysis
│   └── Dockerfile.investigation_worker # Target workspace (nmap, ffuf, dirsearch, testssl)
├── memory/                   # Claude Code session memory (read at session start)
│   ├── project_state.md      # Milestone completion status
│   ├── active_tasks.md       # In-progress and pending tasks
│   ├── next_steps.md         # Next actions per milestone
│   ├── application_flow.md   # Scan lifecycle, data flows, routing
│   └── architecture.md       # Architecture snapshot (this session)
├── docs/
│   ├── technical-documentation.md
│   ├── architecture.md
│   ├── developer-handover.md
│   └── diagrams.md
├── .claude/
│   ├── hooks/session-start.sh  # Injects memory into Claude context at session start
│   ├── commands/handoff.md     # /handoff slash command definition
│   └── settiings.local.json    # Hook registration (SessionStart)
├── CLAUDE.md                 # Claude Code instructions (partially stale — see handover)
└── you-are-a-senior-shiny-hearth.md  # Full architectural plan + milestone definitions
```

---

## Memory System Overview

This project uses a file-based memory system at `memory/` to maintain continuity across Claude Code sessions.

**Read (automatic):** A `SessionStart` hook defined in `.claude/settiings.local.json` runs `.claude/hooks/session-start.sh` every time a session opens. The script cats `project_state.md`, `active_tasks.md`, `next_steps.md`, and `application_flow.md` into the console, loading them into Claude's context automatically. `memory/architecture.md` exists but is not yet wired into the hook script.

**Write (manual):** Run `/handoff` at the end of each session. The slash command (defined in `.claude/commands/handoff.md`) instructs Claude to analyze the session's work and update all four memory files with completed tasks, decisions made, modified files, blockers, and next recommended actions.

---

## Screenshots

No screenshots are committed to the repository. Add them to `docs/screenshots/` and reference them below.

| View | File | Description |
|---|---|---|
| Dashboard | `docs/screenshots/dashboard.png` | Add Scan + Recon Jobs |
| Scan detail | `docs/screenshots/scan-detail.png` | 8-tab recon scan view |
| Vuln scan | `docs/screenshots/vuln-scan.png` | 9-tab vulnerability analysis |
| Target workspace | `docs/screenshots/workspace.png` | Subdomains + investigation tools |
| Target risk | `docs/screenshots/target-risk.png` | Cross-scan risk rollup |
| Admin panel | `docs/screenshots/admin.png` | User/session management |

---

## Troubleshooting

**Backend exits silently on startup**
Alembic migration failure is the most common cause. Check:
```bash
docker compose logs backend --tail=80
```
Fix the migration error, then `docker compose up` again.

**Frontend shows "no response body" or `ERR_CONNECTION_REFUSED`**
Backend container likely exited. Run `docker compose ps` first. If the backend is down, fix it and restart.

**CORS error — request succeeds but no `Access-Control-Allow-Origin` header**
Your browser origin is not in `cors_origins` and doesn't match `cors_origin_regex`. For non-localhost origins (staging, prod), add the origin to `CORS_ORIGINS` env var.

**SSE progress bar stuck / events not arriving**
EventSource requires `withCredentials: true` for cross-origin cookie auth. All three SSE clients (scan detail, vuln-scan detail, workspace) already set this. If events stop, check `docker compose logs worker` for the scan's progress.

**MinIO screenshot URLs broken (`minio:9000` in the URL)**
Worker used the internal Docker URL instead of the public URL. Run the SQL fix:
```sql
UPDATE asset_observations
SET payload = jsonb_set(
  payload, '{screenshot_url}',
  to_jsonb(replace(payload->>'screenshot_url', 'http://minio:9000', 'http://localhost:9000'))
)
WHERE payload ? 'screenshot_url'
  AND payload->>'screenshot_url' LIKE 'http://minio:9000%';
```

**Worker subprocess crashes immediately with 0 results (naabu, nmap, gowitness)**
Never set `RLIMIT_AS` for Go binaries. The Go runtime reserves several GB of virtual address space at startup; an address-space limit causes `SIGABRT` in under 300ms with no error in the DB. Use `RLIMIT_NOFILE` only.

**naabu finds 0 ports on public hosts**
naabu must use `-s c` (connect scan). The default SYN scan is silently blocked by Cloudflare and similar CDNs. The `NaabuStage` adapter already sets this flag.

**Subfinder hangs on slow passive sources**
`SubfinderStage` uses `asyncio.wait_for(300s)` with `-timeout 30` per source. On timeout it kills the process and returns partial results. This is expected behavior.

---

## Contributing

### Branch naming
```
dev_<FeatureName>_<slug>   # e.g. dev_Tar_workspace
```

### Before any non-trivial change
Read `you-are-a-senior-shiny-hearth.md` for locked architectural decisions, then read `memory/project_state.md` + `memory/next_steps.md` for current focus.

### Adding a recon adapter
1. Implement `Stage` protocol in `backend/app/pipeline/adapters/your_tool.py`
2. Install the binary in `infra/Dockerfile.worker` (pin version, verify with `--version`)
3. Register in `backend/app/pipeline/profiles.py`
4. Add to `backend/app/models/__init__.py` if any new models

### Adding a vuln adapter
1. Implement `VulnStage` protocol in `backend/app/pipeline/vuln/adapters/`
2. Adapters **must not** touch `assets`, `services`, or `technologies` tables
3. Register in `backend/app/pipeline/vuln/profiles.py`

### Migration ENUM gotcha
Build one `postgresql.ENUM(...)` instance, call `.create(checkfirst=True)` once, reference the **same object** from every column. Never use `sa.Enum(name=..., create_type=False)` in column definitions.

### Code style
- Python: `ruff`, line length 100, no `from __future__ import annotations` unless needed
- TypeScript: strict mode, path alias `@/*` → `frontend/*`
- No comments unless the WHY is non-obvious. No multi-paragraph docstrings.
- Async everywhere in Python. Never use the legacy SQLAlchemy `Query` API.
