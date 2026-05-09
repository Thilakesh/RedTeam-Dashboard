# Vulnerability Analysis Module — Architecture Finalization

## Context

The platform already ships a working multi-tenant ASM recon pipeline: a real DAG executor (`backend/app/pipeline/coordinator.py`), 13 adapters across 7 levels, an asset graph with deduped `Asset` + immutable `AssetObservation` rows, MinIO screenshot storage, an LLM-based risk prioritizer, and an intelligence-tiered UI (Subdomains / IPs / CDN-WAF / Tech / Ports / Risks).

The module being designed answers a fundamentally different question than recon. Recon answers **"what attack surface exists?"** Vulnerability Analysis must answer **"what concrete weaknesses exist on that surface, with evidence, and how dangerous are they in this specific environment?"** That is not the same job — it has different inputs (the recon asset graph, not the raw target), different tools (matchers, fuzzers, NSE scripts, nuclei templates — not enumerators), different outputs (CVE/CWE-tagged vulnerabilities with reproducible evidence — not deduped assets), different lifecycles (open → triaged → fixed → reopened — not first_seen/last_seen), and different authorization risk profile (intrusive checks can trip WAFs, fill error logs, and break things).

The locked-in decisions from this session's brainstorm:

1. **Vuln Analysis is a separate `Scan.kind`**, referencing a parent recon scan. Distinct lifecycle, queue, profile, and UI. No coupling of recon-rerun to vuln-rerun.
2. **Promote Services and Technologies to first-class tables.** JSONB-only worked for display-tier recon; CPE→CVE matching, version-targeted vuln stages, and finding correlation all need real columns/indexes.
3. **New `vulnerabilities` table; keep existing `findings` table unchanged.** Findings = LLM-prioritized attack-surface signals (a *ranking* artifact). Vulnerabilities = concrete weaknesses with CVE/CVSS/evidence and a status workflow. They have different lifecycles → different tables. A unified read model can compose them later.
4. **Authorization: reuse target `authz_required` gate + add `intrusive` flag** on stages. Default vuln-analysis is non-intrusive (matchers + safe nuclei templates). Intrusive stages (nikto, aggressive ffuf, exploit-tier nuclei) are opt-in per scan, rate-limited per target+org.

The rest of this document is the architecture that follows from those four choices. Read it as a finalization, not an exploration.

---

## 1. High-Level Architecture

### Module separation and data ownership

```
┌────────────────────────────────────────────────────────────────────┐
│ RECON MODULE                                                       │
│   Owns:  Asset, AssetObservation, Service, Technology              │
│   Job:   Discover and normalize attack surface                     │
│   Tools: passive enum, DNS, HTTP probe, WAF/CDN, port scan, nmap,  │
│          screenshots, ASN/geo                                      │
│   Sink:  asset graph (services + tech are now first-class)         │
└────────────────────────────────────────────────────────────────────┘
                              │ reads (read-only)
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│ VULNERABILITY ANALYSIS MODULE                                      │
│   Owns:  Vulnerability, VulnEvidence, VulnRunMatch                 │
│   Job:   Find, dedup, score, and track concrete weaknesses         │
│   Tools: nuclei (template-routed), nmap NSE (vuln cat), trivy/cpe  │
│          matcher, ffuf (gated), katana (gated), testssl, nikto     │
│          (gated), custom rule engine, AI triage agent              │
│   Sink:  vulnerabilities + evidence (per-target dedup)             │
└────────────────────────────────────────────────────────────────────┘
                              │ feeds
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│ INTELLIGENCE LAYER (cross-cutting)                                 │
│   Owns:  RiskScore composition, Findings (kept), AI triage output  │
│   Job:   Rank, correlate, produce remediation guidance             │
└────────────────────────────────────────────────────────────────────┘
```

### Hard ownership rules (enforce at code review)

- **Recon never writes to `vulnerabilities` / `vuln_evidence`.** Period.
- **Vuln stages never write to `assets` / `asset_observations` / `services` / `technologies`.** They consume them. If a vuln check discovers a new endpoint, it goes into a vuln-scoped `endpoints` table — not into the asset graph (recon owns that).
- **Findings stays a read-only sink for the LLM prioritizer.** It is not extended to hold CVE matches.
- **Tools belong to exactly one module.** No tool runs in both. If a tool produces both surface and weakness data (e.g., wafw00f could be argued either way), it lives where its primary output is consumed.

### Why a layered monolith still fits

The CLAUDE.md decision to stay a layered monolith is correct here. The vuln module is two new schema tables, one new Arq queue (`vuln`), a new adapter directory, a new coordinator entrypoint, a new API router, and new UI tabs. Splitting into a microservice would buy nothing and break the asset-graph read path that is the entire point of reusing recon.

---

## 2. Execution Architecture

### Scan model evolution

Add to `Scan`:

```python
class Scan(Base):
    kind: Mapped[ScanKind]                      # NEW: "recon" | "vuln_analysis"
    parent_scan_id: Mapped[UUID | None] = ...   # NEW: vuln scans point to a recon scan
    intrusive: Mapped[bool] = ...               # NEW: opt-in for aggressive stages (vuln only)
```

Migration: backfill `kind="recon"` for existing rows. New unique partial index: `(target_id, status)` filtered to `kind='vuln_analysis' AND status IN ('queued','running')` to prevent two concurrent vuln scans for the same target.

### Two coordinators, one Stage protocol

`Stage` (`backend/app/pipeline/stage.py`) does not change. It is the right abstraction. What changes is that there are now two coordinator entry points and two profile registries:

```
backend/app/pipeline/
  stage.py                        # unchanged
  coordinator.py                  # unchanged (recon)
  profiles.py                     # unchanged (recon profiles)
  vuln/
    coordinator.py                # NEW — same DAG executor, different StageContext
    profiles.py                   # NEW — vuln_quick / vuln_standard / vuln_deep
    adapters/
      nuclei_safe.py
      nuclei_intrusive.py         # gated by intrusive=True
      nmap_nse_vuln.py
      cpe_matcher.py
      testssl.py
      ffuf.py                     # gated by intrusive=True
      katana.py                   # gated by intrusive=True
      nikto.py                    # gated by intrusive=True
      ai_triage.py                # LLM, runs last
```

The vuln coordinator is a thin specialization. It calls the same `execute_dag()` from `coordinator.py` but builds a `VulnStageContext` that pre-loads the **parent recon scan's asset graph** (services, technologies, http_services, screenshots) into memory so adapters never re-query the DB mid-run. This is the core anti-duplication mechanism — vuln stages cannot accidentally re-port-scan because they get a frozen view of recon results, not a live target.

### DAG levels — vuln_deep profile

```
L0 (cheap, fan-out wide):
   cpe_matcher              # services + technologies → CVE candidates (offline NVD/OSV)
   tls_matcher              # http_services → testssl-lite (config flaws, no negotiation abuse)
   panel_detector           # http_services → known admin/login fingerprints
   default_creds_matcher    # services → known default-cred CPE matches (no auth attempts)

L1 (template-routed, parallel by service type):
   nuclei_safe              # severity ≤ medium, tagged "cve,exposure,misconfig,tech"
   nmap_nse_vuln            # safe NSE scripts only (vuln-cve*, http-enum, ssl-cert)

L2 (requires L0/L1 evidence; correlates):
   endpoint_discovery       # katana (passive only by default)
   directory_fuzzing        # ffuf — INTRUSIVE, gated
   nikto_scan               # INTRUSIVE, gated
   nuclei_intrusive         # severity high+, tagged "rce,sqli,fuzz,intrusive" — gated

L3 (correlation + triage):
   correlator               # dedup, evidence-merge, exploitability scoring
   ai_triage                # LLM: per-vuln rationale, exploit chain hints, remediation
```

Conditional execution is enforced two ways:

1. **`Stage.applies(ctx)` predicate** (new, optional method): returns False if no input services/tech match. e.g., `nuclei_intrusive_wordpress` skips if `technology.name='wordpress'` is absent. Coordinator records `skipped_reason="no_matching_inputs"` instead of running the stage. This is what "service-centric analysis" means in code.
2. **`intrusive=True` gate** on the stage class. Coordinator skips with `skipped_reason="intrusive_not_opted_in"` if `Scan.intrusive=False`.

Both reuse the existing `on_skip` callback path, so SSE events surface the skip reason to the UI for free.

### Profiles

| Profile | Stages | Use case |
|---|---|---|
| `vuln_quick` | cpe_matcher, panel_detector, nuclei_safe (filtered: cve,exposure) | sub-2-min triage of newly added target |
| `vuln_standard` | + tls_matcher, nmap_nse_vuln, default_creds_matcher, ai_triage | nightly continuous monitoring |
| `vuln_deep` | all of standard + endpoint_discovery + correlator (no intrusive unless opted) | scheduled deep-dive |
| `vuln_deep + intrusive=True` | adds ffuf, nikto, nuclei_intrusive | pentest engagement, with target authz |

### Queue routing

Add `vuln` queue alongside `default` and `heavy`:

- `vuln_quick` → `default` queue (light, low timeout)
- `vuln_standard` / `vuln_deep` → `vuln` queue (dedicated worker, ulimit-controlled, longer timeouts)
- `intrusive=True` runs → `vuln` queue with **per-target rate limiter** (Redis SETNX with TTL on `vuln:rate:{target_id}`). This is the operational-stability net.

Update `backend/app/services/queue.py::enqueue_scan` to route by `(kind, profile, intrusive)`. Update `infra/docker-compose.yml` and `infra/Dockerfile.worker` (or fork into `Dockerfile.vuln_worker` if binary set diverges meaningfully — likely yes once nuclei templates and NSE scripts are added).

---

## 3. Asset Model — first-class promotion

### Migration `0005_promote_services_tech.py`

Two new tables, both target-scoped (tenant inherited via target → project → org), with `(target_id, canonical_key)` unique indexes mirroring the existing pattern.

```python
class Service(Base):
    __tablename__ = "services"
    id: Mapped[UUID]
    target_id: Mapped[UUID]                     # FK targets, indexed
    asset_id: Mapped[UUID]                      # FK assets (the host: subdomain or ipv4)
    host: Mapped[str]                           # canonical host
    port: Mapped[int]
    proto: Mapped[str]                          # tcp/udp
    canonical_key: Mapped[str]                  # f"{host}:{port}/{proto}"  -- unique per target
    state: Mapped[str]                          # open/closed/filtered
    service_name: Mapped[str | None]            # http, ssh, smb, ...
    product: Mapped[str | None]                 # nginx, OpenSSH, ...
    version: Mapped[str | None]
    banner: Mapped[str | None]
    cpes: Mapped[list[str]]                     # ARRAY(TEXT) — fuels CPE→CVE matching
    tls: Mapped[dict | None]                    # JSONB: cert chain, ciphers, protocols
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
    UniqueConstraint(target_id, canonical_key, name="uq_service_identity")

class Technology(Base):
    __tablename__ = "technologies"
    id: Mapped[UUID]
    target_id: Mapped[UUID]                     # FK targets, indexed
    asset_id: Mapped[UUID]                      # FK assets (subdomain or service)
    name: Mapped[str]                           # "wordpress", "nginx", "react"
    version: Mapped[str | None]
    cpe: Mapped[str | None]
    category: Mapped[str | None]                # cms, framework, server, ...
    confidence: Mapped[int]
    source_tool: Mapped[str]                    # httpx, nuclei-tech, manual
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
    UniqueConstraint(target_id, asset_id, name, version, name="uq_tech_identity")
```

### Backfill

Migration must backfill from existing JSONB:

- For each `Asset.type='service'` row, parse `canonical_key` (`host:port/proto`) and existing `attributes` (port_state, naabu/nmap fields) into a `services` row.
- For each `Asset.type='subdomain'` with `attributes.tech` (list), explode into `technologies` rows linked to that subdomain asset.

Keep `Asset.type='service'` rows for one release window for safety, then a follow-up migration (`0006_drop_service_assets.py`) drops them once `scan_view.build_port_rows` reads from `services`.

### Read-model rewrite

`backend/app/services/scan_view.py::build_port_rows` switches from JSONB-walking to a `select(Service).join(Asset).where(...)` query. It will be ~40% shorter and ~100x faster on deep scans. `build_technologies` similarly.

### Why this isn't premature

- Vuln stages need `WHERE cpe = ANY(:vulnerable_cpes)` queries. JSONB array containment works but blocks indexes and forces query rewrites every time a matcher is added.
- Service-centric DAG routing (run `nuclei_wordpress` only if a wordpress tech row exists) needs a real `EXISTS` query. JSONB makes that a sequential scan.
- The current `service` canonical_key is already correct (`host:port/proto`); the migration is renormalization, not redesign. Cost is bounded.

---

## 4. Vulnerability Analysis Design

### `vulnerabilities` table

```python
class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[UUID]
    target_id: Mapped[UUID]                     # FK targets, indexed (tenant scope)
    asset_id: Mapped[UUID]                      # FK to subdomain | ipv4 | service asset
    service_id: Mapped[UUID | None]             # FK services (null for tech-level vulns)
    technology_id: Mapped[UUID | None]          # FK technologies
    canonical_key: Mapped[str]                  # f"{template_id_or_cve}:{asset_id}:{port}"
    template_id: Mapped[str | None]             # nuclei template id, NSE script name, custom-rule id
    cve_ids: Mapped[list[str]]                  # ARRAY(TEXT)
    cwe_ids: Mapped[list[str]]                  # ARRAY(TEXT)
    title: Mapped[str]
    severity: Mapped[Severity]                  # CRITICAL/HIGH/MED/LOW/INFO (extend existing enum)
    cvss_v3: Mapped[float | None]
    cvss_vector: Mapped[str | None]
    epss: Mapped[float | None]                  # Exploit Prediction Scoring System
    kev: Mapped[bool]                            # CISA Known Exploited Vulnerability
    description: Mapped[str]
    remediation: Mapped[str | None]
    status: Mapped[VulnStatus]                  # open/triaged/false_positive/fixed/wont_fix/reopened
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
    last_verified_at: Mapped[datetime]
    UniqueConstraint(target_id, canonical_key, name="uq_vuln_identity")

class VulnEvidence(Base):
    __tablename__ = "vuln_evidence"
    id: Mapped[UUID]
    vulnerability_id: Mapped[UUID]              # FK vulnerabilities, indexed
    scan_id: Mapped[UUID]                       # FK scans (the vuln scan that produced this)
    stage_id: Mapped[UUID]                      # FK scan_stages
    source_tool: Mapped[str]
    request: Mapped[str | None]                 # raw HTTP request that triggered detection
    response_excerpt: Mapped[str | None]        # bounded slice of response
    matcher_name: Mapped[str | None]            # which matcher fired
    extracted: Mapped[dict]                     # JSONB: extracted strings, banners, versions
    confidence: Mapped[int]
    observed_at: Mapped[datetime]

class VulnRunMatch(Base):                       # per-scan join table
    __tablename__ = "vuln_run_matches"
    scan_id: Mapped[UUID]                       # composite PK with vulnerability_id
    vulnerability_id: Mapped[UUID]
    state: Mapped[str]                          # "new" | "seen" | "fixed_in_this_run"
```

The `(target_id, canonical_key)` uniqueness gives per-target dedup across runs (the asset graph pattern, applied to weaknesses). `VulnRunMatch` answers "what's new vs the last vuln scan?" without scanning the whole vulns table — this is your diff/regression view.

---

## Implementation Milestones

**Strongly suggest splitting this into four PRs**, in order. Do not attempt as one branch.

1. **M-Vuln-1: Schema + scan-kind plumbing.** Migrations 0005/0006/0007. Promote Services/Technologies. Backfill. Rewrite `scan_view.build_port_rows` + `build_technologies`. Add `Scan.kind/parent_scan_id/intrusive`. No vuln stages yet. Verifies the asset model evolution under load.
2. **M-Vuln-2: Vuln coordinator + first 3 stages (cpe_matcher, panel_detector, nuclei_safe).** New queue, new worker image, new API router, minimal UI (list + detail Overview + Vulnerabilities tabs). End-to-end signup → recon → vuln scan → vulnerabilities table populated → UI shows them.
3. **M-Vuln-3: Remaining safe stages + AI triage + diff/run-match.** testssl, nmap_nse_vuln, default_creds_matcher, katana (passive), correlator, ai_triage. Diff tab.
4. **M-Vuln-4: Intrusive stages + rate limits + per-target consent UX.** ffuf, nikto, nuclei_intrusive. Rate-limiter middleware. Intrusive-opt-in flow.

Each PR is independently deployable and revertable.
