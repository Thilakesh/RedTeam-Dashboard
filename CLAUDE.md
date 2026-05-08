# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project context

Multi-tenant Attack Surface Management (ASM) dashboard. Users sign up, submit a domain, a worker runs a recon DAG against it, and normalized assets stream back to the UI. **M0 is complete and verified end-to-end** (signup → JWT → scan → subfinder → asset graph → UI). Only `subfinder` is wired in and the "DAG" is a linear loop — replacing the loop with a real DAG executor and adding `assetfinder`/`dnsx`/`httpx` adapters is M1. The full architectural plan, including milestones M0–M6 and the multi-agent AI council, is in [`you-are-a-senior-shiny-hearth.md`](you-are-a-senior-shiny-hearth.md). **Read that file before any non-trivial change** — it defines the locked decisions (SaaS-first multi-tenant, hard authz gate on active scanning, AI focus = risk prioritization not summaries) that subsequent code must respect.

`project_spec.md` is the original learning-grade spec; the architecture plan supersedes it. Do not implement against `project_spec.md`.

## Run / develop

Everything runs via Docker Compose from `infra/`:

```bash
cd infra
docker compose up --build      # first run + after dependency changes
docker compose up              # subsequent runs
docker compose down            # stop
docker compose logs -f worker  # tail worker output (where stage execution happens)
```

The backend container runs `alembic upgrade head` on boot; you don't run migrations manually unless you're authoring one. Backend (`backend/`) and frontend (`frontend/`) are bind-mounted, so file edits hot-reload — no rebuild needed for code changes. Rebuild only when dependencies change (`pyproject.toml`, `package.json`) or when modifying the worker Dockerfile to add a new recon binary.

URLs after boot: frontend `http://localhost:3000`, API docs `http://localhost:8000/docs`.

If the frontend can't reach the API (browser shows `ERR_CONNECTION_REFUSED` or "no response body"), check `docker compose ps` first — the backend container exits silently when alembic fails, and Compose stops retrying after a few attempts. `docker compose logs backend --tail=80` is where the actual exception lives.

### Database migrations

```bash
docker compose exec backend alembic revision --autogenerate -m "describe change"
docker compose exec backend alembic upgrade head
docker compose exec backend alembic downgrade -1
```

Autogenerate works because `migrations/env.py` imports `app.models` (which re-exports every ORM class) — any new model **must** be added to `backend/app/models/__init__.py` or it won't appear in autogenerate diffs.

**Postgres ENUM gotcha** (we hit this in M0): if your migration declares an ENUM, build it as a single `postgresql.ENUM(values..., name=..., create_type=False)` instance, call `.create(op.get_bind(), checkfirst=True)` on it once, then **reference that same instance** from every column. Do not use `sa.Enum(name="...", create_type=False)` in columns — SQLAlchemy treats it as a separate ENUM with `create_type=True` defaulted-on, fires a second `CREATE TYPE ... AS ENUM ()` during table create, and the migration crashes. See `migrations/versions/0001_initial.py` for the working pattern.

### Tests (none yet)

Test infra is on the M1+ checklist. When adding tests, use `pytest` with `pytest-asyncio` (already in optional deps) and prefer integration tests against a real Postgres+Redis via `testcontainers` over mocks — see locked decision in the architecture plan.

## Architecture you must internalize

### Five-plane layered monolith

`Presentation (Next.js) → API (FastAPI) → Orchestration (Scan Coordinator) → Execution (Arq workers) → Data (Postgres + Redis)`. These are module boundaries within one repo, not separate services. Do not split into microservices — that decision is explicitly deferred in the plan.

### Tenant scoping is non-negotiable

Every scan-related query **must** filter by `Scan.org_id == user.org_id` (see `backend/app/api/scans.py` for the pattern). The `org_id` on `Scan` is denormalized from `Target → Project → Organization` specifically so list/detail queries can scope without a 3-table join. New tables that hold tenant data should follow the same denormalization pattern or join through `Project`.

### The recon pipeline is a stage protocol, not an ad-hoc function

Adding a new recon tool means writing a new adapter that satisfies `Stage` in `backend/app/pipeline/stage.py`:

```python
class Stage(Protocol):
    name: str           # used in scan_stages.stage_name
    source_tool: str    # used in asset_observations.source_tool
    async def execute(self, ctx: StageContext) -> list[AssetRecord]: ...
```

The adapter is responsible for invoking the tool (subprocess for CLI, httpx for API), parsing output, and returning `AssetRecord`s. **Adapters never touch the DB directly** — the worker calls `services.assets.upsert_assets` to persist. This is the anti-coupling boundary; preserve it.

To register a new adapter: add it to the relevant profile list in `backend/app/pipeline/profiles.py`. If the tool is a CLI binary, install it in `infra/Dockerfile.worker` (see the subfinder block as a template — pin the version, verify with `--version` at build time).

### Asset graph, not result rows

Recon output is modeled as deduplicated `Asset`s plus per-scan `AssetObservation`s. The same `(target_id, type, canonical_key)` upserts to a single `Asset` row across scans (`first_seen`/`last_seen` track history); each scan run writes a fresh observation. This makes diff scans (M3) a database query rather than a comparison job. **Do not** add a results table that duplicates data per-scan — extend `attributes` JSONB or add an asset type instead.

`canonical_key` is the dedup identity. For `subdomain` it's the lowercased FQDN; for `ipv4` it'll be the dotted-quad; for `service` it'll be `host:port/proto`. Pick canonical keys carefully — changing them later requires a migration.

### Worker pub/sub for live updates

Workers publish stage events to Redis pub/sub channel `scan:{scan_id}`. The API exposes these via SSE at `/scans/{id}/stream`. Currently the frontend uses polling (TanStack Query `refetchInterval`) — switching to SSE is an M1 task. When publishing new event types, follow the existing `{event, scan_id, ...fields}` JSON shape and emit `scan.completed` or `scan.failed` as the terminal event so the SSE generator closes cleanly.

### Frontend API client

All HTTP goes through `frontend/lib/api.ts::api()` which auto-attaches the JWT and parses errors (including Pydantic 422 validation arrays). Don't bypass it with raw `fetch`. The token lives in `localStorage` under `recon_token`; `AppShell` redirects to `/login` if it's missing, so any authenticated page should wrap its content in `<AppShell>`.

## Conventions worth knowing

- Python: `ruff` config in `backend/pyproject.toml`, line length 100. Use `from __future__ import annotations` only when needed (Python 3.11+).
- SQLAlchemy 2.0 async style throughout: `await db.scalar(select(...))`, never the legacy `Query` API.
- Pydantic v2 schemas live in `backend/app/schemas/`. ORM-derived response models use `Config.from_attributes = True`.
- TypeScript strict mode. Path alias `@/*` maps to `frontend/*`.
- The default JWT secret `dev-secret-change-me` is fine for local dev; it must be set via `JWT_SECRET` env for any non-local deploy.
- **Password hashing uses `bcrypt` directly, not `passlib`.** Passlib breaks against `bcrypt>=4.1` (its init-time probe raises `ValueError` on long passwords). `app/core/security.py` truncates inputs to bcrypt's 72-byte limit explicitly. Don't reintroduce passlib.
- **CORS allows any `localhost`/`127.0.0.1` port** via `cors_origin_regex` in `app/core/config.py`. The `cors_origins` list is for explicit non-localhost origins (prod). When the browser's origin doesn't match either, the API returns 200 to the preflight but no `Access-Control-Allow-Origin` header — the request fails with no body. The frontend `(auth)` pages distinguish this `TypeError` case from `ApiError` and surface a real "cannot reach API" message; copy that pattern in any new page that hits the API directly.

## Known gaps to expect (do not "fix" these without intent)

- Stage execution is sequential, not a real DAG (M1).
- No worker subprocess sandboxing yet (M2 — required before adding naabu/nmap/active tools).
- No authorization-proof verification on targets (M2 — same milestone as active tools).
- No AI agents wired in (M4).
- `services/queue.py` opens and closes a Redis connection per enqueue. Fine for current load; pool it when scan submission frequency justifies the change.

## Rules
- Never break module boundaries
- Keep workers stateless
- Use async wherever possible
- Persist scan states in DB

## Memory System
Before starting work:
- Read memory/project_state.md
- Read memory/next_steps.md
- Read memory/active_tasks.md

Before ending session:
- Run /handoff

## Karpathy Skills — Coding Behavior Principles

Behavioral guidelines to reduce common LLM coding mistakes.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

### 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

### 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

### 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

### 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.