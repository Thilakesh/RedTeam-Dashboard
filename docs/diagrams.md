# Diagrams

Mermaid diagrams of the current runtime. Renders on GitHub. For prose, see
[`architecture.md`](architecture.md).

---

## 1. Container layout

```mermaid
flowchart LR
    subgraph browser[Browser]
        UI[Next.js SPA]
    end

    subgraph docker[Docker Compose]
        FE[frontend<br/>Next.js dev :3000]
        BE[backend<br/>FastAPI :8000]
        W1[worker<br/>queue: default]
        W2[heavy-worker<br/>queue: heavy]
        W3[investigation-worker<br/>queue: investigation]
        PG[(postgres<br/>:5432)]
        RD[(redis<br/>:6379)]
        MO[(minio<br/>:9000)]
    end

    UI -->|HTTPS| FE
    UI -->|JSON + CSRF| BE
    FE -->|SSR / dev fetch| BE
    BE --> PG
    BE --> RD
    W1 --> PG
    W1 --> RD
    W2 --> PG
    W2 --> RD
    W3 --> PG
    W3 --> RD
    W1 --> MO
    W2 --> MO
```

---

## 2. Feature nav (App Router)

```mermaid
flowchart TD
    APP[AppShell]

    APP --> HOME[/home/]
    APP --> RECON[Basic Recon]
    APP --> TW[Target Workspace]
    APP --> OPS[Operations]
    APP --> ADMIN[Administration]

    RECON --> ADD[/dashboard/]
    RECON --> JOBS[/dashboard/recon-jobs/]
    JOBS --> SCAN[/scans/:id/]

    TW --> ASSETS[/targets/]
    ASSETS --> WS[/targets/:id/workspace/]
    WS --> TASK[/targets/:id/workspace/tasks/:task_id/]

    OPS --> LAUNCH[/operations/launch/]
    OPS --> HIST[/operations/]
    HIST --> OPRES[/operations/:operation_id/]

    ADMIN --> USERS[/admin/users/]
    ADMIN --> SESS[/admin/sessions/]
    ADMIN --> FEAT[/admin/features/]
    ADMIN --> SYS[/admin/settings/]
    ADMIN --> AUD[/admin/audit/]
```

---

## 3. Recon scan lifecycle

```mermaid
sequenceDiagram
    autonumber
    participant U as Analyst
    participant FE as Frontend
    participant API as backend /scans
    participant Q as Redis (default/heavy)
    participant W as worker / heavy-worker
    participant DB as Postgres

    U->>FE: Submit target + profile
    FE->>API: POST /scans
    API->>DB: INSERT scan (status=created)
    API->>Q: enqueue_scan(scan_id, profile)
    API-->>FE: 201 Scan
    FE->>API: GET /scans/{id}/stream (SSE)

    Q->>W: run_scan(scan_id)
    W->>DB: mark running
    W->>W: coordinator.execute(DAG)
    loop per stage
        W->>DB: upsert_assets + observations
        W-->>Redis: publish scan:{id} stage.started/completed
    end
    W->>DB: mark completed
    W-->>Redis: publish scan:{id} scan.completed
    Redis-->>FE: SSE event
    FE-->>U: Overview / Subdomains / Ports refresh
```

---

## 4. Investigation task lifecycle

```mermaid
sequenceDiagram
    autonumber
    participant U as Analyst
    participant FE as Frontend
    participant API as backend /target-workspaces
    participant Q as Redis (investigation)
    participant W as investigation-worker
    participant DB as Postgres

    U->>FE: Pick asset + tool + profile
    FE->>API: POST /operations/preview
    API-->>FE: {generated_command}
    U->>FE: Run
    FE->>API: POST /{ws}/tasks
    API->>DB: INSERT investigation_task (queued)
    API->>Q: enqueue_investigation_task
    API-->>FE: 201

    Q->>W: run_investigation_task
    W->>DB: load workspace / asset / target
    W->>W: adapter.execute(TaskContext)
    W->>DB: insert investigation_findings + upsert endpoints/tls_observations
    W-->>Redis: publish investigation:{id} task.completed
    Redis-->>FE: SSE via /{ws}/stream
    FE-->>U: Task result page renders findings
```

---

## 5. Operation lifecycle (standalone)

```mermaid
sequenceDiagram
    autonumber
    participant U as Analyst
    participant FE as Frontend
    participant API as backend /operations
    participant Q as Redis (investigation)
    participant W as investigation-worker
    participant DB as Postgres

    U->>FE: Type target + tool
    FE->>API: POST /operations/preview
    API->>API: validate_target + validate_custom_args
    API-->>FE: {generated_command}

    U->>FE: Start Operation
    FE->>API: POST /operations
    API->>DB: INSERT operations (queued) org_id + created_by
    API->>Q: enqueue_operation
    API-->>FE: 201 Operation

    Q->>W: run_operation
    W->>DB: mark started
    W->>W: adapter.execute(TaskContext with host=typed target)
    W->>DB: insert operation_findings, save raw_output
    W-->>Redis: publish operation:{id} operation.completed
    FE->>API: GET /operations/{id} (poll every 4s)
    API-->>FE: {operation, findings, raw_output}
    FE-->>U: Structured per-tool result page
```

---

## 6. Data model (ER, current)

```mermaid
erDiagram
    Organization ||--o{ Project : "has"
    Project ||--o{ Target : "has"
    Organization ||--o{ User : "has"
    Target ||--o{ Scan : "has"
    Target ||--o{ Asset : "owns"
    Target ||--o{ TargetWorkspace : "has"
    Scan ||--o{ ScanStage : "has"
    Scan ||--o{ AssetObservation : "produces"
    Asset ||--o{ AssetObservation : "observed via"
    Asset ||--o{ Service : "hosts"
    Asset ||--o{ Technology : "runs"
    Scan ||--o{ Finding : "yields"
    Scan ||--o{ AiUsage : "tokens"

    TargetWorkspace ||--o{ InvestigationTask : "contains"
    InvestigationTask ||--o{ InvestigationFinding : "yields"
    Asset ||--o{ InvestigationTask : "targeted by"
    Asset ||--o{ InvestigationFinding : "about"

    Organization ||--o{ Operation : "owns"
    User ||--o{ Operation : "created"
    Operation ||--o{ OperationFinding : "yields"

    Service ||--o{ TlsObservation : "measured"
    Asset ||--o{ Endpoint : "exposes"
    Endpoint ||--o{ EndpointObservation : "seen"

    User ||--o{ RefreshSession : "has"
    User ||--o{ UserFeature : "flags"
    User ||--o{ AuditLog : "actor"
```

Notes:
- `Vulnerability` / `VulnEvidence` / `VulnRunMatch` / `CveIntel` /
  `HvtSignal` all removed by migration `0020`.
- `Operation` is **not** linked to `Target` / `Asset` — that isolation is the
  whole point of the Operations Console.

---

## 7. Auth flow

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant FE as Next.js
    participant API as /auth
    participant DB as Postgres

    U->>FE: POST /auth/login {email, password}
    FE->>API: proxy request
    API->>DB: verify bcrypt hash
    API->>DB: INSERT refresh_session
    API-->>FE: Set-Cookie rt_access, rt_refresh, rt_csrf
    FE-->>U: {csrf_token, user}

    Note over FE,API: authenticated request
    FE->>API: GET /... (rt_access cookie + X-CSRF-Token header)
    alt 401
        FE->>API: POST /auth/refresh
        API->>DB: rotate refresh_session + issue new access
        API-->>FE: new cookies
        FE->>API: retry original request
    end
```

---

## 8. OpenRouter config resolution

```mermaid
flowchart LR
    APP[Any AI caller<br/>e.g. risk_prioritizer]
    APP -->|get_openrouter_config(db)| SVC[services/system_settings.py]
    SVC -->|SELECT| DB[(system_settings)]
    DB -.->|miss| ENV[Env OPENROUTER_API_KEY]
    SVC --> APP
    APP -->|bounded_completion(model, api_key)| OR[OpenRouter HTTPS]
```

- DB miss falls back to env.
- Model miss falls back to `openai/gpt-oss-20b:free`.
- Raw key never returned by any API; the admin card exposes only
  `api_key_set` + last-4 hint.
