# DRAVE — Architecture Reference

**Purpose:** single source-of-truth diagram set for DRAVE's system architecture, data model, lifecycle, and trust boundaries. Give this file to an AI coding agent alongside `AGENTS.md` and `DRAVE-Approval-Policy.md` — it's the "shape of the system" doc; those are the "rules of engagement" docs.

Companion docs: `DRAVE-Knowledge-Base.md` (concepts), `DRAVE-Build-Blueprint.md` (build order/tech stack), `AGENTS.md` + `DRAVE-Approval-Policy.md` (agent behavior rules).

---

## 1. System Architecture (Component View)

```mermaid
flowchart TB
    subgraph Engineers["Detection Engineers"]
        GH[GitHub / GitLab]
        CLI[DRAVE CLI]
        WEB[Web Dashboard]
    end

    GH --> API
    CLI --> API
    WEB --> API

    API["DRAVE API (FastAPI)"] --> ORCH[Pipeline Orchestrator]

    subgraph Orchestration
        ORCH --> RM[Rule Management]
        ORCH --> TE[Test Engine]
        ORCH --> DEP[Deployment]
    end

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
    ADAPT --> ELASTIC[Elastic]

    ORCH --> RUNNER[Customer Runner]
    RUNNER --> TELEM[Customer Telemetry]
    RUNNER --> SIEM[Customer SIEM]
    RUNNER --> TESTDATA[Test/Attack Data]

    style GATE fill:#f9d,stroke:#900
    style BLOCK fill:#f99,stroke:#900
    style RUNNER fill:#dfd,stroke:#090
```

**Key boundary:** everything inside `RUNNER` down runs inside **customer infrastructure**. Only results (not raw telemetry) cross back to DRAVE Cloud — see Section 4.

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

This maps directly to `core/` in the repo:

```
core/
├── detection/     ─┐
├── validation/     ├─ ANALYSIS
├── telemetry/      ┘
├── regression/     ─┐
├── replay/          ├─ EVALUATION
├── robustness/       │
├── volume/           │
├── performance/     ┘
└── scoring/          ─ EVIDENCE + HEALTH (aggregates all three)
```
*(Git/versioning logic lives outside `core/detection`, directly against the repo — see Section 3.)*

---

## 3. Detection Lifecycle (End-to-End)

```mermaid
sequenceDiagram
    participant Eng as Engineer
    participant Git as Git/GitHub
    participant CI as DRAVE CI
    participant Eval as Evidence/Health Engine
    participant Human as Approver
    participant SIEM as Production SIEM

    Eng->>Git: Write/modify rule, open PR
    Git->>CI: Trigger DRAVE CI
    CI->>CI: Syntax, Schema checks
    CI->>CI: Unit, Regression tests
    CI->>CI: Attack Replay, Variations
    CI->>CI: Noise/Volume, Performance, ATT&CK
    CI->>Eval: Aggregate results
    Eval->>Eval: Evaluate hard gates

    alt Gate failed
        Eval-->>Git: Post FAIL report, block merge
        Git-->>Eng: Fix rule
    else Gate passed
        Eval-->>Git: Post PASS evidence report
        Git->>Human: Request approval
        Human->>Git: Approve + merge
        Git->>SIEM: Deploy (via adapter)
        SIEM-->>Git: Verify deployment
        SIEM->>Eval: Continuous evaluation (ongoing)
        Eval-->>Human: Alert on degradation
        Human->>SIEM: Rollback (if needed, audited)
    end
```

---

## 4. Trust Boundary — Customer Telemetry

```mermaid
flowchart LR
    subgraph Cloud["DRAVE Cloud"]
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

    class TestCase {
        +test_id: str
        +detection_id: str
        +type: TestType
        +input_telemetry: dict
        +expected: dict
    }

    class TestResult {
        +status: PASS|FAIL|ERROR|SKIPPED
        +diagnostics: dict
    }

    class AttackScenario {
        +id: str
        +technique: str
        +telemetry: str
        +expected_detections: list~str~
    }

    class DeploymentManifest {
        +detection_id: str
        +git_commit: str
        +version: int
        +target: str
        +siem: str
        +requested_by: str
        +approved_by: str
        +reason: str
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

    DetectionRule "1" --> "many" TestCase
    TestCase --> TestResult
    DetectionRule "1" --> "many" AttackScenario
    DetectionRule "1" --> "many" DeploymentManifest
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
    S17 --> S18["18. SaaS platform (API/DB/dashboard)"]

    style S1 fill:#dfd
    style S4 fill:#dfd
    style S17 fill:#fdd
    style S18 fill:#fdd
```
Green = safe to build/run entirely locally. Red = touches real production systems — governed by `DRAVE-Approval-Policy.md` Tier 3.

---

## 7. How to Use This File With an AI Agent

Give the agent, in this order:
1. `AGENTS.md` — how to behave, setup commands, code style
2. `DRAVE-Approval-Policy.md` — what it may/may not do without asking
3. `ARCHITECTURE.md` (this file) — the shape of the system it's building
4. `DRAVE-Build-Blueprint.md` — step-by-step build instructions with tools/libraries
5. `DRAVE-Knowledge-Base.md` — full conceptual reference if it needs "why" context

The diagrams here are Mermaid (plain text) specifically so an agent can read the file directly without image parsing — but they also render as visuals on GitHub, GitLab, and most markdown viewers.
