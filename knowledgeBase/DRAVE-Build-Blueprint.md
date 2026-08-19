# DRAVE — Build Blueprint
### How to Build DRAVE From Scratch (Python Stack)

**Companion document to `DRAVE-Knowledge-Base.md`.** That document defines *what* DRAVE is and *what* the 70 steps are. This document defines *how* to actually build each of them — tech stack, libraries, folder scaffolding, and build order.

---

## 1. Tech Stack Decision

| Concern | Choice | Why |
|---|---|---|
| Language | **Python 3.11+** | Sigma ecosystem (`pySigma`), fast prototyping, dominant language in detection engineering |
| Package/env manager | **uv** | Fast, single binary, replaces pip+venv+poetry |
| CLI framework | **Typer** | Type-hint driven, built on Click, gives you `drave test` etc. almost for free |
| Data models/validation | **Pydantic v2** | Used for `DetectionRule`, `TestCase`, assertions, API schemas — one model layer everywhere |
| Sigma parsing/conversion | **pySigma** + `pySigma-backend-splunk` (later `-elasticsearch`, `-microsoft365defender`) | Official Sigma library; gives you rule parsing + SIEM query compilation without rebuilding Sigma |
| In-memory rule evaluation (MVP) | Custom pySigma backend that evaluates parsed rule trees directly against JSON telemetry (no live SIEM needed) | Lets Phase A/B run entirely offline against fixtures |
| YAML | **ruamel.yaml** | Preserves comments/formatting — useful since rules/tests are YAML and get diffed in PRs |
| Schema validation | **Pydantic v2** + `jsonschema` for telemetry schema comparisons | Reuse the same validation layer |
| Git operations | **GitPython** (or shell out via `subprocess` for speed-critical paths) | Diff, commit, branch, PR metadata extraction |
| Web API | **FastAPI** + `uvicorn` | Pairs natively with Pydantic; auto OpenAPI docs |
| Database | **PostgreSQL** via **SQLModel** (SQLAlchemy + Pydantic combined) | One model class serves both DB table and API schema |
| Migrations | **Alembic** | Standard for SQLAlchemy/SQLModel |
| Job queue | **Arq** (async, Redis-backed) — simpler than Celery for this scale | Runs test jobs, replay jobs, customer-runner jobs asynchronously |
| Object storage | **MinIO** (dev) / **S3** (prod) via `boto3` | Stores telemetry fixtures, evidence reports, large results |
| Customer Runner transport | **Redis Streams** or **NATS** between DRAVE Cloud and Customer Runner | Lightweight, no telemetry ever leaves customer infra — only results |
| Dashboard (frontend) | **React + TypeScript + Tailwind** (separate repo/package, consumes DRAVE API) | Not Python, but noted here since it's Phase M — kept fully decoupled via REST/OpenAPI |
| CI/CD | **GitHub Actions** | Matches "Build the DRAVE GitHub Action" (Step 61) directly |
| Containerized local dev | **Docker + docker-compose** (Postgres, Redis, MinIO) | One command spins up the whole dev environment |
| Testing DRAVE itself | **pytest** + `coverage.py` | For DRAVE's own codebase (distinct from the DetectionRule test runner it builds) |
| Lint/format/type-check | **ruff** (lint+format) + **mypy** | Fast, single tool for lint+format |

> **Rule of thumb throughout:** DRAVE's own test suite (pytest) tests *DRAVE's code*. The `TestRunner` DRAVE builds in Phase A tests *detection rules*. Keep these mentally separate — they look similar but are different systems.

---

## 2. The Leaner Build Order (Macro Blueprint)

Build in this order. Each stage should be shippable/demoable before moving to the next — don't parallelize early stages.

| # | Stage | Maps to | What "done" looks like |
|---|---|---|---|
| 1 | **Repo + environment scaffolding** | pre-Phase A | `drave test` runs (even if it does nothing yet) |
| 2 | **Core data models** | Steps 2–3, 7 | `DetectionRule` and `TestCase` Pydantic models exist and validate YAML |
| 3 | **Sigma adapter (in-memory)** | Steps 9–10 | A Sigma rule can be parsed and evaluated against a JSON event in Python, no SIEM needed |
| 4 | **Test Runner + CLI** | Steps 4–6, 8, 12 | `drave test` runs positive/negative/edge tests from local fixtures and prints PASS/FAIL |
| 5 | **Syntax + Schema validation** | Steps 13–16 | Invalid rules fail fast; schema compatibility % is reported |
| 6 | **Result storage + corpus** | Steps 17–20 | A small starter detection corpus exists with stored, structured results |
| 7 | **Git as source of truth + PR reporting** | Steps 21–27 | Rule changes go through branches/PRs; DRAVE posts a results comment |
| 8 | **Deployment manifests + rollback bookkeeping** | Steps 28–32 | Last-known-good is tracked; rollback is a scripted, audited action (no real SIEM yet) |
| 9 | **Regression engine** | Steps 33–36 | Old tests automatically re-run against new rule versions; regressions are flagged |
| 10 | **Customer Runner (local stub first)** | Steps 37–41 | A "runner" process can execute tests against a separate telemetry source and report schema drift |
| 11 | **Attack replay** | Steps 42–45 | Attack fixtures + `AttackScenario` YAML drive replay and report missed/expected detections |
| 12 | **Robustness / variation testing** | Steps 46–49 | Coverage % and a robustness matrix are generated from attack variations |
| 13 | **Noise/volume measurement** | Steps 50–53 | Estimated production alert volume is computed and checked against policy |
| 14 | **Performance + ATT&CK metadata** | Steps 54–57 | Query cost is measured (where adapter supports it); declared vs. tested ATT&CK coverage is tracked |
| 15 | **Evidence + Health engine** | Steps 58–60 | A single Evidence Report aggregates everything; hard gates block bad deployments |
| 16 | **Real CI/CD (GitHub Action)** | Steps 61–64 | DRAVE runs as a GitHub Action on every PR and blocks unsafe merges |
| 17 | **Real SIEM adapters + deployment** | Steps 65–67 | Rules actually deploy to a real SIEM (start with Splunk) with verification and automated rollback |
| 18 | **SaaS platform (API, DB, dashboard)** | Steps 68–70 | Multi-tenant API + Postgres + React dashboard, full lifecycle visible end-to-end |

This is the same order as the Version Roadmap (v0.1 → v1.5) in the knowledge base — the table above just adds the "what tool, what done looks like" layer.

---

## 3. Initial Repo Scaffolding (run this first)

```bash
# 1. Project init
mkdir drave && cd drave
git init
uv init --package drave
uv python pin 3.11

# 2. Core dependencies
uv add pydantic typer ruamel.yaml pysigma jsonschema gitpython

# 3. Dev dependencies
uv add --dev pytest coverage ruff mypy

# 4. Folder structure matching the Knowledge Base's Section 10
mkdir -p core/{detection,testing,validation,telemetry,replay,robustness,regression,volume,performance,scoring}
mkdir -p adapters/{sigma,splunk,sentinel,eql,esql}
mkdir -p cli runner api dashboard tests
mkdir -p fixtures/{powershell,brute_force}
mkdir -p detections/{rules,tests,scenarios}
touch detections/drave.yml

# 5. Python packaging stubs
find core adapters cli runner api -type d -exec touch {}/__init__.py \;

# 6. First CLI entrypoint
cat > cli/main.py << 'EOF'
import typer
app = typer.Typer()

@app.command()
def test(detection_id: str = typer.Argument(None)):
    """Run tests for a detection (or all detections)."""
    typer.echo("DRAVE test runner not yet implemented.")

if __name__ == "__main__":
    app()
EOF

# 7. Verify
uv run python cli/main.py test
```

---

## 4. Detailed 70-Step Build Notes

Each step below states: **what to build → with what → scaffolding/commands.**

### PHASE A — Core Detection Engine

**1. MVP question** — no code; write it down as `docs/mvp_question.md`. This is the acceptance test for everything in Phase A/B.

**2. `DetectionRule` model**
- Build with: Pydantic v2
- `core/detection/models.py`:
```python
from pydantic import BaseModel
from datetime import datetime


class DetectionRule(BaseModel):
    id: str
    name: str
    description: str
    language: str  # "sigma" for MVP
    platform: str
    query: str
    severity: str
    author: str
    created_at: datetime
    updated_at: datetime
    attack_mappings: list[str] = []
```

**3. `TestCase` model** — same file, `core/testing/models.py`:
```python
from enum import Enum
from typing import Any
from pydantic import BaseModel


class TestType(str, Enum):
    positive = "positive"
    negative = "negative"
    edge = "edge"
    regression = "regression"
    attack = "attack"


class TestCase(BaseModel):
    test_id: str
    detection_id: str
    type: TestType
    input_telemetry: dict[str, Any]
    expected: dict[str, Any]
```

**4–6. Positive/negative/edge tests** — no new code; these are *YAML fixtures* under `detections/tests/`, loaded by the model above. Build 3–5 of each per detection.

**7. Assertions** — extend `expected` schema in `TestCase` with typed fields (`alert: bool`, `min_matches`, `max_matches`, `severity`). Validate with Pydantic field validators, not raw dict checks.

**8. Test Runner** — `core/testing/runner.py`. Build with: pure Python, no framework. Pipeline:
```python
def run_test(
    rule: DetectionRule, test: TestCase, adapter: DetectionAdapter
) -> TestResult:
    compiled = adapter.compile(rule)
    actual = adapter.execute(compiled, test.input_telemetry)
    normalized = adapter.normalize_result(actual)
    return compare(test.expected, normalized)
```

**9. Adapter interface** — `core/detection/adapter.py`, an `ABC`:
```python
from abc import ABC, abstractmethod


class DetectionAdapter(ABC):
    @abstractmethod
    def validate(self, rule: DetectionRule) -> bool: ...
    @abstractmethod
    def compile(self, rule: DetectionRule): ...
    @abstractmethod
    def execute(self, compiled, telemetry: dict): ...
    @abstractmethod
    def normalize_result(self, raw_result) -> dict: ...
```

**10. First adapter (Sigma, in-memory)** — `adapters/sigma/inmemory.py`. Build with: **pySigma**.
- `pip`/`uv add pysigma`
- Use `pySigma`'s `SigmaCollection` + `SigmaRule` to parse the rule.
- Write a minimal custom backend (subclass `pySigma`'s `Backend`) that evaluates the parsed condition tree directly against a Python dict (the telemetry event) instead of compiling to a query string — this is what lets Phase A/B run with zero SIEM dependency.
- Real SIEM query compilation (`pySigma-backend-splunk`, etc.) is deferred to Phase L (Step 65).

### PHASE B — Validation

**11. Local telemetry fixtures** — plain JSON files under `fixtures/powershell/attack.json` and `benign.json`. No library needed; hand-author 5–10 events per fixture initially.

**12. First CLI (`drave test`)** — build with: **Typer**, extend `cli/main.py` to load a `DetectionRule` + its `TestCase`s from `detections/`, run them through `core/testing/runner.py`, print a formatted PASS/FAIL table (use `rich` for the table — `uv add rich`).

**13. Syntax validation** — call `adapter.validate()` before compiling; for Sigma, this is `pySigma`'s own parser raising on malformed YAML/rule syntax. Fail fast with a clear CLI error.

**14. Rule dependency extraction** — `core/validation/dependencies.py`: walk the parsed Sigma rule's field references (pySigma exposes the detection field names) and return the set of required fields/log sources.

**15. Schema validation** — `core/validation/schema.py`: compare the field set from Step 14 against a telemetry schema definition (a simple JSON Schema file per log source, validated with `jsonschema`).

**16. Schema compatibility reporting** — `core/validation/report.py`: `matched_fields / required_fields` → percentage, plus a `missing` list and a `risk` bucket (`LOW/MEDIUM/HIGH` based on whether missing fields are required by the rule's core condition vs. optional filters).

**17. Initial detection corpus** — author 4 real detections (PowerShell, Brute Force, Credential Access, Suspicious Admin Activity) as Sigma YAML under `detections/rules/`, each with a matching set of tests under `detections/tests/`.

**18. Deterministic tests** — enforce via CI convention: no wall-clock/network calls inside adapters during test execution; freeze any timestamps in fixtures (`freezegun` optional: `uv add --dev freezegun`).

**19. Store test results** — start simple: write结果 as JSON lines to `results/` locally (`core/testing/storage.py`); this gets replaced by Postgres in Phase M — keep the storage interface abstract from day one so that swap is a one-file change.

**20. Result model** — `core/testing/models.py`: `TestResult` Pydantic model with `status: Literal["PASS","FAIL","ERROR","SKIPPED"]` + `diagnostics: dict`.

### PHASE C — Git and Versioning

**21. Git as source of truth** — no new library; enforce the `detections/{rules,tests,scenarios}` + `drave.yml` layout from the scaffolding above. `drave.yml` holds project-level config (adapter target, volume policy defaults, etc.).

**22–23. Branches + PRs** — process convention, not code (standard `main` + feature branches, PR-based workflow). Enforce via GitHub branch protection rules (Step 25).

**24. Report DRAVE results in the PR** — build with: **GitHub Actions** + GitHub's REST API (`PyGithub` or plain `requests`) to post a formatted comment; this is a light version of Step 61's full Action.

**25. Protect production branches** — GitHub repo settings (branch protection rule requiring PR + 1 review + the DRAVE CI status check) — no DRAVE code needed, just configuration.

**26. Capture the rule diff** — `core/versioning/diff.py`, build with **GitPython**: `repo.git.diff(commit_before, commit_after, rule_path)`; store author/timestamp/commit/PR from the Git commit + GitHub PR API.

**27. Record change reason** — add a required `reason` field (enum: `bug_fix, false_positive_reduction, new_attack, schema_change, performance, tuning`) to the PR template (`.github/PULL_REQUEST_TEMPLATE.md`) and parse it in the CI job.

**28. Deployment manifests** — `core/versioning/manifest.py`, a Pydantic model matching the YAML shape in the knowledge base (`detection_id, git_commit, version, target, siem`), written to `deployments/` per deploy.

**29. Deployment history** — extend the result-storage abstraction from Step 19 to also persist deployment manifests (same storage backend, different table/collection).

**30. Last-known-good tracking** — `core/versioning/lkg.py`: a simple pointer file/DB row per detection (`current_version`, `last_deployed_version`, `last_known_good_version`), updated after every successful deployment + test run.

**31. Rollback implementation** — `core/versioning/rollback.py`: orchestrates "find LKG artifact → re-run required tests via Test Runner → require approval flag → call adapter's deploy → verify" — this is a coordinator function, not a new library.

**32. Rollback audit info** — extend the deployment manifest model with `requested_by, approved_by, reason, from_version, to_version, timestamp, test_results_ref`.

### PHASE D — Regression

**33. Run old tests against new versions** — `core/regression/runner.py`: reuse the Phase A Test Runner, but load the *full historical test set* for a detection_id (not just the new tests added in this PR) and run them all against the new rule version.

**34. Show exact regressions** — diff the `TestResult` sets between the last passing version and the current one; output a table of `test_id, before_status, after_status` where they differ.

**35. Regression baseline** — store a "baseline" pointer (which version's test results count as the baseline) per detection, similar to Step 30's LKG pointer.

**36. Convert failures into permanent tests** — CLI command `drave capture-failure <detection_id> <telemetry_file>` that wraps the failing event as a new `TestCase` YAML file and commits it to `detections/tests/` — a small Typer subcommand, no new library.

### PHASE E — Customer Telemetry

**37. DRAVE Customer Runner** — a separate deployable Python package (`runner/`), packaged as a Docker image, run inside customer's VPC/K8s/VM. Build with: same `core/` library (import it as a dependency), plus a lightweight job-consumer loop.

**38. Keep telemetry inside customer infra** — architecture constraint enforced by design: the Runner pulls *job definitions* from DRAVE Cloud (via **Arq**/Redis or a signed HTTPS poll) and pushes back only `TestResult`/`AttackResult` objects — never raw telemetry.

**39. Least-privilege permissions** — Runner's SIEM/telemetry credentials are scoped read-only (query only); deployment credentials (Step 65+) are a separate, more privileged credential set never given to the same process.

**40. Test against representative telemetry** — Runner command `drave-runner sample-test <detection_id> --sample-size 10000`, using the existing Test Runner but pointed at a live telemetry query instead of a local fixture.

**41. Schema drift detection** — `core/telemetry/drift.py`: store the schema snapshot from the last successful run (Step 15/16) and diff field names against the current snapshot on each Runner execution; emit `⚠ Schema drift detected` with the specific field rename/removal.

### PHASE F — Attack Replay

**42. Attack fixtures** — JSON telemetry files under `fixtures/<technique>/attack.json`, same shape as Phase B fixtures but tagged with ATT&CK technique.

**43. `AttackScenario` model** — `core/replay/models.py`, Pydantic model matching the YAML shape (`id, name, technique, telemetry, expected_detections`).

**44. Replay engine** — `core/replay/engine.py`: loads an `AttackScenario`, sends its telemetry through the Customer Runner (or local adapter for dev), collects which detections fired, compares against `expected_detections`.

**45. Measure attack results** — extend `TestResult`-style output with `expected_detections, actual_detections, missed_detections, detection_latency_ms` (latency = event timestamp → alert timestamp, computed from telemetry/result timestamps).

### PHASE G — Detection Robustness

**46. Attack variations** — author variation fixtures per technique (`fixtures/<technique>/variation_01.json` … `variation_N.json`), each perturbing one dimension (tool, encoding, parent process, etc.). Optionally script simple mutators (`core/robustness/mutators.py`) for cheap dimensions like casing/encoding.

**47. Variation coverage** — `core/robustness/coverage.py`: `detected_count / total_variations`, run through the same Replay Engine from Step 44.

**48. Robustness matrix** — `core/robustness/matrix.py`, builds a `detection × variation → PASS/FAIL` grid; render as a table with `rich` in the CLI, and as JSON for the dashboard later.

**49. Historical bypasses** — same flow as Step 36 (`drave capture-failure`), but tagged `type: attack` and added to the variation set permanently.

### PHASE H — Noise and Operational Safety

**50–51. Alert volume measurement/estimation** — `core/volume/estimator.py`: run the detection over a representative sample (via the Customer Runner), compute `matches / sample_events * production_daily_events` to estimate daily alert volume.

**52. Volume policies** — extend `drave.yml` / per-detection metadata with a `volume_policy: {warning, failure}` block; check estimated volume against it in CI (hard gate candidate, see Step 60).

**53. Separate volume from false positives** — extend `TestResult`/replay output with `true_positive`, `false_positive`, `unknown` counters, only populated when a human/labeled fixture marks ground truth — never auto-inferred.

### PHASE I — Performance and ATT&CK

**54. Performance measurement** — adapter-specific: for the Splunk adapter (Step 65), use Splunk's job inspector API (`run_duration`, `scan_count`) via `splunk-sdk`; store in `core/performance/models.py`.

**55. Detect expensive rules** — `core/performance/thresholds.py`: compare measured runtime/cost against configurable thresholds; flag "logically correct, operationally expensive."

**56–57. ATT&CK metadata + declared vs tested coverage** — extend `DetectionRule.attack_mappings` (already in the Step 2 model) and cross-reference against which techniques actually have: a unit test, an attack replay scenario, and a variation set — `core/scoring/attack_coverage.py` outputs the Declared/Unit/Attack/Variation/Validated table.

### PHASE J — Evidence and Health

**58. Evidence Report** — `core/scoring/evidence.py`: aggregates outputs from every prior phase into one Pydantic model; render as CLI table (`rich`) and Markdown (for PR comments, Step 24) and JSON (for dashboard/API, Phase M).

**59. Health model** — `core/scoring/health.py`: weighted/dimensioned score across Logic correctness, Attack validation, Robustness, Telemetry compatibility, Regression stability, Noise, Performance, ATT&CK validation — pure Python scoring function, no ML needed for MVP.

**60. Hard gates** — `core/scoring/gates.py`: a list of boolean checks (`syntax_valid, all_required_tests_pass, no_known_attack_missed, schema_compatibility_ok, volume_within_policy`) evaluated *before* the health score is even computed; any `False` = automatic block regardless of score.

### PHASE K — CI/CD

**61. DRAVE GitHub Action** — `.github/workflows/drave-ci.yml`, calls `uv run drave ci-check` (a new Typer command that runs the full pipeline: syntax → schema → unit → regression → attack → robustness → volume → ATT&CK → evidence/gates) and exits non-zero on gate failure.

**62. PR checks** — the Action posts the Evidence Report (Step 58's Markdown output) as a PR comment via the GitHub API (reuse Step 24's posting code).

**63. Block unsafe merges** — set the `drave-ci` job as a required status check in GitHub branch protection (configuration, from Step 25).

**64. Deployment approvals** — GitHub Environments with required reviewers for `production`; high-risk detections (flagged via a `risk: high` field on the manifest) require an additional named approver group.

### PHASE L — Deployment

**65. SIEM adapters** — start with **Splunk**: `adapters/splunk/adapter.py` implementing the Step 9 `DetectionAdapter` interface, using `pySigma-backend-splunk` to compile the rule to SPL and the official `splunk-sdk` to deploy/query. Sentinel/Elastic/Chronicle follow the same interface later.

**66. Deployment verification** — `core/deployment/verify.py`: after deploy, query the SIEM adapter for the live rule version, compare to expected, run one smoke-test telemetry event through it, record PASS/FAIL.

**67. Automated rollback** — `core/deployment/auto_rollback.py`: wraps Step 31's rollback logic, triggered automatically when Step 66 verification fails or a policy-defined critical check fails post-deploy.

### PHASE M — SaaS Platform

**68. DRAVE API + database** — build with: **FastAPI** + **SQLModel** + **PostgreSQL** + **Alembic**. Reuse the exact Pydantic models from `core/` as the SQLModel table definitions (`class DetectionRule(SQLModel, table=True): ...`) — no duplicate schema layer. `api/main.py` exposes REST endpoints wrapping every `core/` function built so far.

```bash
uv add fastapi uvicorn sqlmodel alembic asyncpg
mkdir -p api/{routers,db}
```

**69. DRAVE dashboard** — separate package (`dashboard/`), **React + TypeScript + Tailwind**, calls the FastAPI OpenAPI-generated client. Core pages map 1:1 to the API routers: Overview, Rules, Pipelines, Test Results, Attack Coverage, Robustness, Noise, Regression, Deployments, Rollback, Audit.

**70. Complete lifecycle** — no new component; this is integration/E2E testing across everything built above (`tests/e2e/`), verifying the full `WRITE → VERSION → ANALYZE → TEST → ATTACK-TEST → EVALUATE → REVIEW → DEPLOY → MONITOR → ROLLBACK/IMPROVE → RE-TEST` loop actually runs end-to-end through the real API + real GitHub Action + a real (or sandbox) Splunk instance.

---

## 5. What To Build First — Summary

1. Run the **Section 3 scaffolding commands** to create the repo.
2. Build `DetectionRule` + `TestCase` Pydantic models (Steps 2–3).
3. Build the in-memory Sigma adapter (Step 10) — this is the hardest/most important early piece; everything else depends on it.
4. Build the Test Runner + `drave test` CLI (Steps 4–8, 12).
5. Get **one detection with 3+ passing tests** running end-to-end locally before touching Git integration, customer telemetry, or any SIEM.

Do not start Phase C (Git/PR automation), Phase E (Customer Runner), or Phase M (SaaS/dashboard) until Phase A/B run cleanly on your machine with local fixtures. This mirrors the Knowledge Base's explicit guidance: **"Do not start with the website."**
