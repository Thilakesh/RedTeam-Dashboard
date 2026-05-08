# Red Team Recon Dashboard

Modular attack surface management dashboard. Submit a domain, run a recon pipeline, see normalized assets in the UI.

Architecture and roadmap live in `you-are-a-senior-shiny-hearth.md` (saved plan). This README only covers running M0.

## M0 — what works

- Email/password signup with auto-created Org + default Project
- JWT auth, tenant-scoped scan API
- Submit a domain → background worker runs `subfinder` → results appear in the UI
- Live progress polling on dashboard + scan detail
- Asset graph (Asset + AssetObservation) populated on every scan

## Run it

Requires Docker Desktop.

```bash
cd infra
docker compose up --build
```

First boot pulls images, builds backend/worker, and downloads the `subfinder` binary into the worker image. The backend container runs `alembic upgrade head` before uvicorn starts, so migrations apply automatically.

Then open:

- Frontend → http://localhost:3000
- API docs → http://localhost:8000/docs

Sign up with any email + password (≥8 chars), submit `example.com` or any domain you own / are authorized to scan, watch results stream in.

## Layout

```
backend/
  app/
    api/           # FastAPI routers (auth, scans)
    core/          # config, db, security
    models/        # SQLAlchemy ORM
    schemas/       # Pydantic request/response
    pipeline/      # Stage protocol + tool adapters
      adapters/subfinder.py
    services/      # asset upsert, queue helpers
    workers/       # Arq worker entrypoint
  migrations/      # Alembic
frontend/
  app/             # Next.js App Router
    (auth)/login, (auth)/signup
    dashboard/
    scans/[id]/
  components/
  lib/api.ts
infra/
  docker-compose.yml
  Dockerfile.app, Dockerfile.worker
```

## What's next (M1)

DAG executor + 3 more stage adapters (assetfinder, dnsx, httpx) + SSE wiring on the scan detail page. The current SSE endpoint exists at `/scans/{id}/stream` but the UI uses polling — switching it on is one component change.

## Notes

- The default JWT secret is `dev-secret-change-me` — fine for local, change for anything else.
- Docker volumes mount the backend/frontend source for hot reload.
- Active-scanning tools (naabu/nmap/etc.) are deliberately not wired in M0. The authorization-gate work in M2 lands before them.
