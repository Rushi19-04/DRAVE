# DRAVE — Architecture Reference

**Purpose:** single source-of-truth diagram set for DRAVE's system architecture, data model, lifecycle, and trust boundaries. Give this file to an AI coding agent alongside `AGENTS.md` and `DRAVE-Approval-Policy.md` — it's the "shape of the system" doc; those are the "rules of engagement" docs.

Companion docs: `DRAVE-Knowledge-Base.md` (concepts), `DRAVE-Build-Blueprint.md` (build order/tech stack), `DRAVE-Tech-Stack-Decisions.md` (detailed rationale), `AGENTS.md` + `DRAVE-Approval-Policy.md` (agent behavior rules).

---

## 1. System Architecture (Component View)

```mermaid
flowchart TB
    subgraph Users["Detection Engineers"]
        GH[GitHub / GitLab]
        WEB[Web Dashboard (Vercel)]
    end

    subgraph Auth["Identity"]
        CLERK[Clerk Auth]
    end

    WEB -->|JWT| API
    CLERK -.->|JWKS Validation| API
    WEB -.->|Login| CLERK

    subgraph GitHubActions["CI/CD Automation"]
        CI[DRAVE CI]
        SYNC[API Sync Workflow]
    end
    
    GH -->|Push/PR| CI
    CI -->|Score/Validation| SYNC
    SYNC -->|X-API-Key| API

    subgraph CloudHosting["Render Cloud"]
        API["DRAVE API (FastAPI)"]
        ORCH[Pipeline Orchestrator]
        
        API --> ORCH
        
        subgraph Orchestration
            ORCH --> RM[Rule Management]
            ORCH --> TE[Test Engine]
            ORCH --> DEP[Deployment]
        end
    end

    subgraph Database["Neon Serverless DB"]
        NEON[(PostgreSQL)]
    end
    
    API -->|SQLModel| NEON
    RM -->|Save Rules| NEON

    subgraph TestEngine["Test Engine"]
        TE --> UNIT[Unit Tests]
        TE --> REPLAY[Attack Replay]
        TE --> REGR[Regression]
    end

    UNIT --> EVID[Evidence Engine]
    REPLAY --> EVID
    REGR --> EVID
    RM --> EVID

    EVID --> HEALTH[Health Engine]
    HEALTH --> GATE{Hard Gates}
    GATE -->|PASS| DEP
    GATE -->|WARN| DEP
    GATE -->|FAIL| BLOCK[Block / Fix Rule]

    DEP --> ADAPT[SIEM Adapters]
    ADAPT --> SPLUNK[Splunk]
    ADAPT --> SENTINEL[Sentinel]

    ORCH --> RUNNER[Customer Runner]
    RUNNER --> TELEM[Customer Telemetry]
    RUNNER --> SIEM[Customer SIEM]

    style GATE fill:#f9d,stroke:#900
    style BLOCK fill:#f99,stroke:#900
    style RUNNER fill:#dfd,stroke:#090
    style NEON fill:#bbf,stroke:#33f
    style CLERK fill:#fbf,stroke:#f3f
```

**Key boundary:** everything inside `RUNNER` down runs inside **customer infrastructure**. Only results (not raw telemetry) cross back to DRAVE Cloud.

---

## 2. DRAVE Core — Three Pillars, One Object

```mermaid
flowchart LR
    subgraph Core["DRAVE Core"]
        direction TB
        A[ANALYSIS<br/>Does it work?]
        V[VERSIONING<br/>What changed?]
        E[EVALUATION<br/>How broadly does it work?]
    end

    A -->|Validation, Schema, Telemetry| Detection
    V -->|Git, Diff, History, Rollback| Detection
    E -->|Unit, Regression, Attack Replay,<br/>Variations, Noise, Performance, ATT&CK| Detection

    Detection[("Detection<br/>(rich object, not just a query)")]
```

---

## 3. Real End-to-End Lifecycle Sequence

This sequence diagram illustrates the entire flow of data across the real production systems (Vercel, Clerk, Render, Neon, GitHub Actions) from user signup through rule creation, CI validation, API sync, and deployment.

```mermaid
sequenceDiagram
    participant User as Detection Engineer
    participant Frontend as Dashboard (Vercel)
    participant Clerk as Clerk Auth
    participant API as SaaS API (Render)
    participant DB as Postgres (Neon)
    participant Git as GitHub
    participant CI as GitHub Actions
    participant SIEM as SIEM (Splunk)

    %% Authentication
    User->>Frontend: Sign up / Log in
    Frontend->>Clerk: Authenticate
    Clerk-->>Frontend: Return Session JWT
    
    %% API Key Generation (One-time setup)
    User->>Frontend: Request CI API Key
    Frontend->>API: POST /api/v1/ci-keys (Bearer JWT)
    API->>API: Validate JWT via Clerk JWKS
    API->>API: Generate Key & Hash (SHA-256)
    API->>DB: Store Hash + Tenant ID
    API-->>Frontend: Return Raw Key (Once)
    User->>Git: Store Key as Repository Secret
    
    %% Rule Authoring & Sync (Via CI/CD)
    User->>Git: Commit new rule YAML to `main`
    Git->>CI: Trigger `drave-sync.yml` on push
    CI->>CI: Parse YAML, Run Core Engine (Syntax, Schema, Tests, Attack Replay)
    CI->>CI: Generate Evidence Score & EvidenceReport JSON
    CI->>API: POST /api/v1/rules (X-API-Key)
    API->>DB: Hash Key, Verify in DB -> Map to Tenant ID
    API->>DB: Upsert RuleEntity (with Evidence JSON) & HealthRecord
    API-->>CI: 200 OK
    
    %% Rule Authoring (Via Dashboard UI)
    User->>Frontend: Click "New Rule" and submit form
    Frontend->>API: POST /api/v1/rules (Bearer JWT)
    API->>API: Validate JWT via Clerk JWKS
    API->>DB: Insert RuleEntity (Empty Evidence JSON)
    API-->>Frontend: 200 OK
    
    %% Viewing & Deployment
    User->>Frontend: View Active Detections
    Frontend->>API: GET /api/v1/rules (Bearer JWT)
    API->>DB: SELECT WHERE tenant_id = user
    DB-->>API: Rules + Health Scores
    API-->>Frontend: Render Dashboard
    
    User->>Frontend: Click "Deploy to Splunk"
    Frontend->>API: POST /api/v1/deployments (Bearer JWT)
    API->>DB: Verify rule exists & belongs to tenant
    API->>API: Evaluate Hard Gates (Tier 3)
    API->>SIEM: Adapter pushes query to Splunk
    SIEM-->>API: Confirm success
    API->>DB: Log DeploymentManifest
    API-->>Frontend: Status: Success
```

---

## 4. Trust Boundary — Customer Telemetry

```mermaid
flowchart LR
    subgraph Cloud["DRAVE Cloud (Render)"]
        JOB[Test/Replay Job Definition]
        RESULTS[(Results Only)]
    end

    subgraph CustomerInfra["Customer VPC / On-Prem / K8s"]
        RUNNER[Customer Runner<br/>least-privilege creds]
        TELEM[(Raw Telemetry — never leaves)]
        CSIEM[Customer SIEM]
    end

    JOB -->|job spec| RUNNER
    RUNNER -->|read-only query| TELEM
    RUNNER -->|read-only query| CSIEM
    RUNNER -->|TestResult / AttackResult objects only| RESULTS

    style TELEM fill:#fdd,stroke:#900
    style RESULTS fill:#dfd,stroke:#090
```

**Rule for any agent building this:** if a code path would send raw telemetry (not a `TestResult`/`AttackResult` object) from `runner/` back to `api/`, that is a Tier 3 action under the Approval Policy — stop and ask.

---

## 5. Data Model (Core Objects)

```mermaid
classDiagram
    class DetectionRule {
        +id: str
        +name: str
        +language: str
        +platform: str
        +query: str
        +severity: str
        +attack_mappings: list~str~
    }

    class CIApiKey {
        +id: str
        +tenant_id: str
        +key_hash: str
        +label: str
        +revoked: bool
    }

    class DeploymentLog {
        +deployment_id: str
        +tenant_id: str
        +status: str
        +target_siem: str
    }

    class EvidenceReport {
        +syntax: bool
        +schema: bool
        +unit: str
        +regression: str
        +attack: str
        +variation_pct: float
        +volume_per_day: int
        +attack_coverage: dict
        +performance: bool
    }

    DetectionRule "1" --> "many" DeploymentLog
    DetectionRule --> EvidenceReport
```

---

## 6. Build-Order Overlay (which layer to build when)

```mermaid
flowchart TD
    S1["1. Repo scaffold + CLI stub"] --> S2["2. DetectionRule + TestCase models"]
    S2 --> S3["3. In-memory Sigma adapter"]
    S3 --> S4["4. Test Runner + drave test CLI"]
    S4 --> S5["5. Syntax + Schema validation"]
    S5 --> S6["6. Result storage + starter corpus"]
    S6 --> S7["7. Git as source of truth + PR reporting"]
    S7 --> S8["8. Deployment manifests + rollback bookkeeping"]
    S8 --> S9["9. Regression engine"]
    S9 --> S10["10. Customer Runner (stub)"]
    S10 --> S11["11. Attack replay"]
    S11 --> S12["12. Robustness / variations"]
    S12 --> S13["13. Noise / volume"]
    S13 --> S14["14. Performance + ATT&CK metadata"]
    S14 --> S15["15. Evidence + Health engine"]
    S15 --> S16["16. Real CI/CD (GitHub Action)"]
    S16 --> S17["17. Real SIEM adapters + deploy"]
    S17 --> S18["18. SaaS platform (Vercel/Render/Clerk/Neon/API Keys)"]

    style S1 fill:#dfd
    style S4 fill:#dfd
    style S17 fill:#fdd
    style S18 fill:#fdd
```
Green = safe to build/run entirely locally. Red = touches real production systems — governed by `DRAVE-Approval-Policy.md` Tier 3.
