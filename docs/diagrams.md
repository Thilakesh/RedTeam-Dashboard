# Architecture Diagrams — Quick Reference

All diagrams are also embedded inline in [`docs/architecture.md`](architecture.md) with surrounding prose.

---

## 1. High-Level System Architecture

> See [`docs/architecture.md § High-Level System Architecture`](architecture.md#1-high-level-system-architecture)

```mermaid
graph TB
    subgraph Browser
        FE["Next.js 14\n:3000"]
    end

    subgraph "API Container :8000"
        API["FastAPI\n(Uvicorn)"]
        CSRF["CSRF Middleware"]
        AUTH["Auth: RS256 cookies\n+ rotating refresh"]
    end

    subgraph "Data Layer"
        PG[("PostgreSQL 16\n:5432")]
        RD[("Redis 7\n:6379")]
        MN[("MinIO\n:9000")]
    end

    subgraph "Worker Containers"
        W1["worker\n(default queue)\nquick/standard recon"]
        W2["heavy-worker\n(heavy queue)\ndeep recon + BBOT"]
        W3["vuln-worker\n(vuln queue)\nvuln analysis"]
        W4["investigation-worker\n(investigation queue)\nnmap/ffuf/dirsearch/testssl"]
    end

    FE -- "cookie auth\nX-CSRF-Token\ncredentials:include" --> API
    API --> PG
    API -- "pub/sub\nsession cache\nblacklist" --> RD
    API -- "enqueue jobs" --> RD
    W1 & W2 & W3 & W4 -- "dequeue" --> RD
    W1 & W2 & W3 & W4 --> PG
    W2 -- "screenshots" --> MN
    FE -- "screenshot URLs" --> MN
    W1 & W2 -- "publish events\nscan:{id}" --> RD
    W3 -- "publish events\nscan:{id}" --> RD
    W4 -- "publish events\ninvestigation:{id}" --> RD
    API -- "SSE stream\n/scans/{id}/stream" --> FE
```

---

## 2. Frontend Component Architecture

> See [`docs/architecture.md § Frontend Component Architecture`](architecture.md#3-frontend-component-architecture)

```mermaid
flowchart TD
    ROOT["app/layout.tsx\n(Providers: QueryClient, ThemeProvider, AuthContext)"]

    ROOT --> AUTH_LAYOUT["(auth)/layout.tsx\n(no AppShell)"]
    ROOT --> APP_PAGES["All other pages\n(wrap in AppShell)"]

    AUTH_LAYOUT --> LOGIN["login/page.tsx"]
    AUTH_LAYOUT --> INVITE["accept-invite/page.tsx"]

    APP_PAGES --> APPSHELL["AppShell.tsx\n(sidebar nav + breadcrumbs + theme toggle)"]
    APPSHELL --> DASHBOARD["dashboard/\nAdd Scan + Recon Jobs"]
    APPSHELL --> SCANS["scans/[id]/page.tsx\n8-tab recon detail"]
    APPSHELL --> VULN["vuln-scans/[id]/page.tsx\n9-tab vuln detail"]
    APPSHELL --> TARGETS["targets/[id]/workspace/\n3-tab investigation"]
    APPSHELL --> ADMIN["admin/ (admin role required)"]

    SCANS --> TABS1["Overview | Subdomains\nIPs | CDN/WAF | Tech\nPorts | Risks | History"]
    VULN --> TABS2["Overview | Vulns | By Service\nBy Tech | Endpoints | TLS\nHVTs | Triage | Diff"]
    TARGETS --> TABS3["Overview | Subdomains\n(ScanConfigurationCard)\nTasks"]

    SCANS & VULN & TARGETS --> APILIB["lib/api.ts\n(typed fetch + auto-refresh + CSRF)"]
    APILIB --> BE["FastAPI :8000"]
```

---

## 3. Database Entity Relationships

> See [`docs/architecture.md § Database Entity Relationships`](architecture.md#4-database-entity-relationships)

```mermaid
erDiagram
    Organization ||--o{ Project : "has"
    Organization ||--o{ User : "has"
    Project ||--o{ Target : "has"
    Target ||--o{ Scan : "has"
    Target ||--o{ TargetWorkspace : "has"
    Target ||--o{ Asset : "has"
    Target ||--o{ Vulnerability : "has"

    Scan ||--o{ ScanStage : "has"
    Scan ||--o{ AssetObservation : "produces"
    Scan ||--o{ Finding : "has"
    Scan ||--o{ AiUsage : "logs"
    Scan }o--o| Scan : "parent_scan_id (vuln→recon)"

    Asset ||--o{ AssetObservation : "has"
    Asset ||--o{ InvestigationTask : "linked via"

    TargetWorkspace ||--o{ InvestigationTask : "contains"
    InvestigationTask ||--o{ InvestigationFinding : "produces"

    Vulnerability ||--o{ VulnEvidence : "has"
    Vulnerability ||--o{ VulnRunMatch : "tracked by"
    Vulnerability }o--o| CveIntel : "enriched by"

    Service ||--o{ HvtSignal : "signals"
    Service ||--o{ TlsObservation : "has"
    Service ||--o{ Endpoint : "has"

    User ||--o{ RefreshSession : "has"
    User ||--o{ AuditLog : "actor"
    User ||--o{ UserFeature : "has"
    RefreshSession }o--|| BlacklistedJti : "revoked via"
```

---

## 4. Authentication Flow

> See [`docs/architecture.md § Authentication Flow`](architecture.md#5-authentication-flow)

```mermaid
sequenceDiagram
    participant B as Browser
    participant API as FastAPI
    participant DB as PostgreSQL
    participant RD as Redis

    Note over B,API: Login
    B->>API: POST /auth/login {email, password}
    API->>DB: lookup User, verify bcrypt hash
    API->>DB: INSERT RefreshSession (opaque token hash)
    API->>RD: HSET session:{id} + SADD session:user:{uid}
    API-->>B: Set-Cookie: rt_access (HttpOnly, 10min)<br/>rt_refresh (HttpOnly, path=/auth, 14d)<br/>rt_csrf (JS-readable)
    API-->>B: 200 {csrf_token, user}

    Note over B,API: Authenticated Request
    B->>API: GET /scans (Cookie: rt_access; X-CSRF-Token: ...)
    API->>RD: EXISTS blacklist:jti:{jti}?
    API->>DB: get User by id
    API-->>B: 200 [scans]

    Note over B,API: Token Refresh (transparent)
    B->>API: GET /scans → 401
    B->>API: POST /auth/refresh (Cookie: rt_refresh)
    API->>DB: find RefreshSession by token hash
    API->>DB: mark old session revoked (rotation)
    API->>DB: INSERT new RefreshSession
    API-->>B: Set-Cookie: new rt_access, rt_refresh, rt_csrf
    B->>API: GET /scans (retry with new rt_access)
    API-->>B: 200 [scans]

    Note over B,API: Logout
    B->>API: POST /auth/logout
    API->>DB: revoke RefreshSession
    API->>RD: DEL session:{id}
    API-->>B: Clear all 3 cookies
```

---

## 5. Recon Pipeline Flow

> See [`docs/architecture.md § Recon Pipeline Flow`](architecture.md#6-recon-pipeline-flow)

```mermaid
flowchart TD
    UI["User: POST /scans\n(domain, profile)"] --> API
    API["API: create Scan row\nstatus=queued"] --> Q{autostart?}
    Q -- yes --> ENQ["enqueue job\nservices/queue.py"]
    Q -- no --> WAIT["status=queued\n(user starts later)"]
    ENQ --> RD[("Redis queue\n(default or heavy)")]
    RD --> WORKER["Worker picks up\nworkers/runner.py"]
    WORKER --> DAG["execute_dag()\npipeline/coordinator.py\n\nL0: subfinder + assetfinder (parallel)\nL1: amass, dnsx\nL2: httpx + asnmap + geoip (parallel)\nL3: wafw00f\n[deep] L4: naabu\n[deep] L5: nmap\n[deep] L6: gowitness\n[deep] L7: risk_prioritizer"]
    DAG --> EACH["each stage:\non_start → execute → on_done/on_fail/on_skip"]
    EACH --> UPSERT["services/assets.py\nupsert_assets()\nAsset + AssetObservation"]
    EACH --> PUB["Redis pub/sub\nscan:{scan_id}\n{event, stage_name, ...}"]
    PUB --> SSE["GET /scans/{id}/stream\nSSE endpoint"]
    SSE --> TQ["TanStack Query\ninvalidateQueries on each event"]
    UPSERT --> PG[("PostgreSQL")]
```

---

## 6. Vulnerability Scan Flow

> See [`docs/technical-documentation.md § Vulnerability Scan Flow`](technical-documentation.md#vulnerability-scan-flow)

```mermaid
sequenceDiagram
    participant U as Analyst
    participant FE as Next.js
    participant API as FastAPI
    participant RD as Redis
    participant VW as vuln-worker

    U->>FE: "Run Vulnerability Analysis"
    FE->>API: POST /vuln-scans {parent_scan_id, profile}
    API->>API: validate parent status=completed, same org
    API->>API: INSERT Scan(kind=vuln_analysis)
    API->>RD: enqueue to "vuln" queue
    API-->>FE: 201 {id}
    FE->>FE: navigate to /vuln-scans/{id}

    VW->>RD: dequeue job
    VW->>VW: load_vuln_context() → frozen VulnStageContext
    VW->>RD: publish scan.started
    loop For each stage (topo order)
        VW->>VW: applies(ctx)? intrusive_required?
        VW->>VW: stage.execute_vuln(ctx) → VulnRecord[]
        VW->>VW: upsert_vulns()
        VW->>RD: publish stage.completed
    end
    VW->>VW: correlator: merge_by_cve + EPSS/KEV + risk_scores
    VW->>VW: ai_triage (top-20 by risk_score)
    VW->>RD: publish scan.completed
    FE->>API: GET /vuln-scans/{id}/overview
    FE->>FE: render 9-tab UI
```

---

## 7. Memory and Hooks Flow

> See [`docs/architecture.md § Memory and Hooks Flow`](architecture.md#7-memory-and-hooks-flow)

```mermaid
flowchart LR
    subgraph "Session Start (automatic)"
        HOOK["SessionStart hook\n.claude/settiings.local.json"]
        SH[".claude/hooks/session-start.sh"]
        M1["memory/project_state.md"]
        M2["memory/active_tasks.md"]
        M3["memory/next_steps.md"]
        M4["memory/application_flow.md"]
        CTX["Claude context window"]

        HOOK --> SH
        SH -- "cat" --> M1 & M2 & M3 & M4
        M1 & M2 & M3 & M4 --> CTX
    end

    subgraph "Session End (manual)"
        CMD["/handoff command\n.claude/commands/handoff.md"]
        CLAUDE["Claude analyzes\nsession work"]
        W1["writes project_state.md\n(milestone status)"]
        W2["writes active_tasks.md\n(completed + pending)"]
        W3["writes next_steps.md\n(next actions)"]
        W4["writes application_flow.md\n(flow changes)"]

        CMD --> CLAUDE
        CLAUDE --> W1 & W2 & W3 & W4
    end

    NOTE["memory/architecture.md\nexists but NOT in hook script yet\n(added this session)"]
```

---

## 8. Deployment Architecture

> See [`docs/architecture.md § Deployment Architecture`](architecture.md#8-deployment-architecture)

```mermaid
graph TB
    subgraph "Docker Compose (infra/)"
        direction TB

        PG[("postgres:16-alpine\n:5432\nvolume: postgres_data")]
        RD[("redis:7-alpine\n:6379")]
        MN[("minio/minio\n:9000 API\n:9001 console\nvolume: minio_data")]

        subgraph "backend :8000"
            BE["Dockerfile.app\nuvicorn + alembic upgrade head\nbind-mount: ../backend:/app\nvolume: jwt_secrets:/secrets/jwt"]
        end

        subgraph "worker (default queue)"
            W1["Dockerfile.worker\nsubfinder, assetfinder, amass\ndnsx, httpx, naabu, nmap\ngowitness, wafw00f\nbind-mount: ../backend:/app"]
        end

        subgraph "heavy-worker (heavy queue)"
            W2["Dockerfile.heavy-worker\nARQ_QUEUE_NAME=heavy\nbbot + all standard tools\nbind-mount: ../backend:/app"]
        end

        subgraph "vuln-worker (vuln queue)"
            W3["Dockerfile.vuln_worker\nnuclei + testssl\nbind-mount: ../backend:/app"]
        end

        subgraph "investigation-worker"
            W4["Dockerfile.investigation_worker\nnmap + ffuf 2.1.0\ndirsearch 0.4.3 + testssl 3.2\nSecLists wordlist\nbind-mount: ../backend:/app"]
        end

        subgraph "frontend :3000"
            FE["node:20-alpine\nnpm run dev\nbind-mount: ../frontend:/app"]
        end

        BE & W1 & W2 & W3 & W4 -- "healthcheck wait" --> PG & RD
        W1 & W2 & W3 & W4 -- "healthcheck wait" --> MN
        BE -- "migrations on startup" --> PG
    end

    BROWSER["Browser"] --> FE
    BROWSER --> BE
    BROWSER --> MN
```
