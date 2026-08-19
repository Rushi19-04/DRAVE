# DRAVE
### Detection Rule Analysis, Versioning, and Evaluation

**Internal Knowledge Base — Full Reference**

---

## 1. Product Definition

DRAVE is a detection engineering platform that brings software-engineering practices to security detection rules: version control, automated testing, attack replay, robustness evaluation, telemetry validation, regression detection, safe deployment, and rollback.

> **Core promise:** Don't just deploy a detection. Prove it.

---

## 2. The Three Problems DRAVE Solves

### Problem 1 — Detection Decay

A detection worked when it was created:

```
Detection → Tested → Worked → Deployed
```

Later, the environment changes underneath it:

- SIEM changes
- Parser changes
- Field changes
- Windows/cloud changes
- Telemetry changes

The rule still exists, but **rule exists ≠ rule works**.

The dangerous situation:

```
Attack → Telemetry → Detection doesn't match → No alert
```

**DRAVE continuously evaluates whether the detection still works.**

### Problem 2 — Detection Changes and Rollback

An engineer changes a detection: `v1 → v2`. That new version might generate 100,000 alerts/day, or it might generate 0 alerts.

DRAVE provides: Git version history + Diff + Author + Timestamp + Reason + Pull Request + Review + Test Results + Deployment History + Rollback.

**Example:**
```
DET-001
v12 → PASS
v13 → PASS
v14 → FAIL

Last Known Good: v13
```

**Rollback flow:**
```
v14 → Validate v13 → Deploy v13 → Production
```

**Audit trail example:**
```
Rollback: v14 → v13
Requested by: Alice
Approved by: Bob
Reason: Attack coverage regression
Time: 15:02
Deployment: SUCCESS
```

Git handles the source history; **DRAVE connects that history to actual deployment state.**

### Problem 3 — Detection Does Not Automatically Generalize

An engineer observes Attack Situation A, creates Detection A, and it catches A. That does **not** prove it catches B, C, D … 100.

Attackers can vary: command, process, parent process, tool, encoding, obfuscation, execution method, user, host, telemetry source, sequence.

**Therefore: one successful test does not prove broad detection coverage.**

DRAVE tests multiple known manifestations:
```
50 attack variations
Detected: 46
Missed: 4
Validated variation coverage: 92%
```

This is **evidence-based coverage**, not a guarantee against every future attack.

---

## 3. DRAVE's Three Pillars

```
                    DRAVE
                      │
       ┌──────────────┼──────────────┐
       ▼              ▼              ▼
   ANALYSIS       VERSIONING      EVALUATION
       │              │              │
 Does it work?    What changed?   How broadly
                                   does it work?
```

These map directly to the three problems above (decay → analysis/evaluation, change/rollback → versioning, generalization → evaluation).

---

## 4. What DRAVE Actually Is

DRAVE is **not** another SIEM. It sits around existing security detection infrastructure:

```
GitHub / GitLab
       │
       ▼
      DRAVE
       │
 ┌─────┼──────────────┐
 ▼     ▼              ▼
Test  Evaluate      Deploy
 │     │              │
 ▼     ▼              ▼
SIEM / Customer Environment
```

Supported detection languages can eventually include: **Sigma, SPL, KQL, EQL, ES|QL, YARA-L**, etc.

> **MVP scope decision:** start with one language/platform combination rather than trying to support everything.

---

## 5. Detection Is More Than a Query

**Traditional detection:** just a `Rule`.

**DRAVE detection** is a rich object:

```
Detection
│
├── Rule
├── Metadata
├── Platform
├── Language
├── Expected behavior
├── Positive tests
├── Negative tests
├── Edge tests
├── Attack scenarios
├── Attack variations
├── Telemetry requirements
├── Volume policy
├── ATT&CK mapping
├── Regression history
└── Deployment policy
```

---

## 6. Complete Detection Lifecycle

```
Threat / Incident
      ↓
Detection hypothesis
      ↓
Engineer writes rule
      ↓
Git
      ↓
Pull Request
      ↓
DRAVE CI
      ↓
Rule Validation
      ↓
Schema Validation
      ↓
Unit Tests
      ↓
Customer Telemetry
      ↓
Attack Replay
      ↓
Variation Testing
      ↓
Noise / Volume
      ↓
Regression
      ↓
Performance
      ↓
ATT&CK Validation
      ↓
Human Review
      ↓
Merge
      ↓
Deploy
      ↓
Continuous Evaluation
      ↓
New failure / attack
      ↓
New regression test
      ↓
Detection improvement  (loops back)
```

---

## 7. The 70-Step DRAVE Build Plan

### PHASE A — Core Detection Engine

**1. Define the first MVP question**
> Given a detection, telemetry, and expected behavior, did the detection behave correctly?
`Rule + Telemetry + Expected result = PASS / FAIL`

**2. Define `DetectionRule`** — internal model contains: `id, name, description, language, platform, query, severity, author, created_at, updated_at, ATT&CK mappings`

**3. Define `TestCase`** — fields: `test_id, detection_id, type, input telemetry, expected result, assertions`. Types: `positive, negative, edge, regression, attack`

**4. Build positive tests** — behavior SHOULD trigger the detection (`Attack event → Expected: Alert`)

**5. Build negative tests** — benign behavior SHOULD NOT trigger the detection (`Benign event → Expected: No Alert`). Catches overly broad detections.

**6. Build edge tests** — missing field, different casing, different parser, unexpected value, partial telemetry

**7. Define assertions** — go beyond `true/false`. Support: `alert, match count, rule ID, severity, required fields, result fields`
```yaml
expected:
  alert: true
  min_matches: 1
  max_matches: 5
  severity: high
```

**8. Build the Test Runner**
```
Load rule → Load test → Load telemetry → Execute detection
→ Normalize result → Compare expected vs actual → PASS / FAIL
```
This is the first important piece of DRAVE code.

**9. Build the adapter interface** — test engine should not contain SIEM-specific logic. Common interface: `DetectionAdapter { validate(), compile(), execute(), normalize_result() }`

**10. Build the first adapter** — for MVP, choose one path: `Sigma → Target SIEM`. Use existing Sigma tooling/backends instead of rebuilding the Sigma ecosystem.

### PHASE B — Validation

**11. Build local telemetry fixtures** — avoid customer infrastructure initially:
```
fixtures/
├── powershell/{attack.json, benign.json}
└── brute_force/{attack.json, benign.json}
```

**12. Build the first CLI** — e.g. `drave test`:
```
Detection: DET-001
✓ TC-001 positive
✓ TC-002 negative
✓ TC-003 edge
3/3 PASS
```

**13. Add syntax validation** — `Rule → Syntax validation → Tests`. Invalid rules fail immediately.

**14. Extract rule dependencies** — analyze: fields, tables, indexes, log sources, data types

**15. Build schema validation** — compare rule requirements against telemetry schema
```
Required: ✓ Image  ✓ User  ✗ CommandLine
```

**16. Create schema compatibility reporting**
```
Detection: DET-001
Compatibility: 75%
Missing: CommandLine
Risk: HIGH
```

**17. Create the initial detection corpus** — small starter set: PowerShell, Brute Force, Credential Access, Suspicious Admin Activity — each with Positive/Negative/Edge tests

**18. Make tests deterministic** — repeatable, fast, deterministic, versioned

**19. Store test results** — `test_id, rule_version, timestamp, expected, actual, status, execution_time, adapter_version`

**20. Build the result model** — structured result types: `PASS, FAIL, ERROR, SKIPPED` + diagnostic information

### PHASE C — Git and Versioning

**21. Make Git the source of truth**
```
detections/
├── rules/
├── tests/
├── scenarios/
└── drave.yml
```

**22. Support branches** — `main`, `feature/new-detection`, `fix/powershell`, `tuning/false-positive`

**23. Support Pull Requests** — `Engineer → Branch → Change rule → PR → DRAVE CI`

**24. Report DRAVE results in the PR**
```
DRAVE CI
Syntax       ✓
Schema       ✓
Unit         24/24
Regression   72/72
Attack       8/8
Robustness   94%
Volume       32/day
PASS
```

**25. Protect production branches** — require PR + Review + DRAVE CI before merge

**26. Capture the rule diff** — for every change: Before, After, Diff, Author, Timestamp, Commit, PR, Reviewer

**27. Record change reason** — categories: `bug_fix, false_positive_reduction, new_attack, schema_change, performance, tuning`

**28. Create deployment manifests**
```yaml
deployment:
  detection_id: DET-001
  git_commit: abc123
  version: 14
  target: production
  siem: splunk
```

**29. Create deployment history** — store: Detection, Version, Commit, Environment, SIEM, Deployer, Time, Result

**30. Implement last-known-good** — track Current version, Last deployed version, Last known-good version (e.g. `Current: v14`, `Last known good: v13`)

**31. Implement rollback**
```
Find known-good artifact → Run required validation → Approve → Deploy → Verify
```

**32. Record rollback audit information** — Who requested? Who approved? Why? From/To version? When? Tests? Deployment result?

> This gives DRAVE the complete versioning + rollback capability.

### PHASE D — Regression

**33. Run old tests against new versions** — e.g. `v12 → 30/30 PASS`, `v13 → 27/30 PASS` → DRAVE identifies **3 regressions**

**34. Show exact regressions**
```
TC-014  Before: PASS  After: FAIL
TC-021  Before: PASS  After: FAIL
```

**35. Maintain a regression baseline** — every production detection has a known-good test baseline; new versions are compared against it.

**36. Convert real failures into permanent tests**
```
Failure → Capture relevant telemetry → Create test → Fix rule
→ Verify → Keep test permanently
```
This continuously improves the detection.

### PHASE E — Customer Telemetry

**37. Build the DRAVE Customer Runner** — runs inside Customer VPC, on-prem, Kubernetes, or VM

**38. Keep sensitive telemetry inside customer infrastructure**
```
DRAVE Cloud → Test job → Customer Runner → Customer telemetry
→ Detection → Results only → DRAVE Cloud
```

**39. Use least-privilege permissions** — runner gets only: Read telemetry, Query SIEM, Execute tests. Deployment permissions are separately controlled.

**40. Test against representative customer telemetry** — e.g. `10,000 representative events → Detection → 0 matches` → DRAVE flags potential issues if matching behavior should have been present.

**41. Detect schema drift** — compare previous vs current schema (e.g. `CommandLine` → `ProcessCommandLine`) → `⚠ Schema drift detected`. This directly addresses **Problem #1**.

### PHASE F — Attack Replay

**42. Create attack fixtures** — start small: PowerShell, Credential Dumping, Brute Force, Suspicious Admin

**43. Define `AttackScenario`**
```yaml
scenario:
  id: PS-001
  name: Encoded PowerShell
technique: T1059.001
telemetry: attack.json
expected_detections:
  - DET-001
```

**44. Build the replay engine**
```
Attack fixture → Customer Runner → Telemetry → Detection
→ Alerts → Compare expected
```

**45. Measure attack results** — Expected detections, Actual detections, Missed detections, Detection latency

### PHASE G — Detection Robustness

**46. Build attack variations** — for each behavior: Variation 1, 2, 3… across dimensions: tool, command, encoding, process, parent process, user, host, execution method, telemetry source

**47. Measure validated variation coverage** — e.g. `100 variations, 92 detected → Coverage: 92%` (evidence, not future guarantee)

**48. Build a robustness matrix**
```
                 V1 V2 V3 V4 V5
Detection A       ✓  ✓  ✓  ✗  ✓
Detection B       ✓  ✗  ✓  ✓  ✓
```
Shows where a detection is weak.

**49. Add historical bypasses**
```
Bypass → Telemetry → Regression fixture → Rule improvement → Permanent test
```

### PHASE H — Noise and Operational Safety

**50. Measure alert volume** — run the detection over representative data; calculate events processed, matches, sample time, estimated production volume

**51. Estimate production alerts** — e.g. `1M sample events, 350 matches` → production `100M events/day` → estimated `35,000 alerts/day`

**52. Create volume policies**
```yaml
volume_policy:
  warning: 100
  failure: 1000
```
Results: `42/day → PASS`, `400/day → WARN`, `8,000/day → FAIL`

**53. Separate volume from false positives** — track Total matches, Known true positives, Known false positives, Unknown. Don't call all matches false positives unless actually labeled.

### PHASE I — Performance and ATT&CK

**54. Measure detection performance** — where supported: Query runtime, Events processed, Bytes scanned, Resource usage, Query cost

**55. Detect expensive rules** — a detection may be logically correct ✓ but operationally expensive ✗. DRAVE should expose this before deployment where possible.

**56. Define ATT&CK metadata**
```yaml
attack:
  - T1059.001
```

**57. Separate declared vs tested coverage** — track Declared, Tested, Validated
```
T1059.001
Declared: ✓
Unit: ✓
Attack replay: ✓
Variation: ✓
Validated: ✓
```

### PHASE J — Evidence and Health

**58. Build the Detection Evidence Report**
```
DET-001 — Encoded PowerShell
Version: v14
Syntax: PASS
Schema: PASS
Unit: 18/18
Regression: 32/32
Attack: 7/7
Variation: 93%
Volume: 42/day
ATT&CK: T1059.001
Performance: PASS
```

**59. Build the Detection Health model** — dimensions: Logic correctness, Attack validation, Robustness, Telemetry compatibility, Regression stability, Noise, Performance, ATT&CK validation

**60. Use hard gates** — automatically block deployment on: Syntax invalid, Required test failed, Known attack missed, Critical schema incompatibility, Volume exceeds policy. **A high numerical score must never hide a critical failure.**

### PHASE K — CI/CD

**61. Build the DRAVE GitHub Action** — `GitHub → Pull Request → DRAVE CI → Tests → Result`

**62. Add PR checks**
```
DRAVE
✓ Syntax
✓ Schema
✓ Unit
✓ Regression
✓ Attack Replay
✓ Robustness
✓ Volume
✓ ATT&CK
PASS
```

**63. Block unsafe merges** — `Attack test FAIL → PR → DRAVE FAIL → Merge blocked`

**64. Support deployment approvals** — `DRAVE PASS → Human approval → Merge → Deploy`. High-risk detections require additional approval.

### PHASE L — Deployment

**65. Build SIEM adapters** — eventually: Splunk, Sentinel, Elastic, Chronicle… Each adapter knows: Compile, Validate, Deploy, Read deployment state, Rollback

**66. Build deployment verification**
```
Deploy → Verify → Confirm expected version → Run smoke test → Record result
```
```
Expected: DET-001 v14
Actual production: DET-001 v14
Deployment: SUCCESS
```

**67. Build automated rollback**
```
v14 → FAIL → Last known good = v13 → Approval / policy → Deploy v13 → Verify
```

### PHASE M — SaaS Platform

**68. Build DRAVE API + database**
```
DRAVE API
    │
    ├── PostgreSQL
    ├── Object Storage
    └── Job Queue
```
Stores: Organizations, Users, Projects, Detections, Pipelines, Tests, Results, Attack runs, Deployments, Audit events

**69. Build the DRAVE dashboard** — core pages: Overview, Rules, Pipelines, Test Results, Attack Coverage, Robustness, Noise, Regression, Deployments, Rollback, Audit. A detection page shows: Current version, Last known good, Who changed it, What changed, Why, Tests, Attack coverage, Robustness, Alert volume, Deployment state, Rollback history.

**70. Build the complete DRAVE lifecycle** — the finished product (see Section 9 for the full diagram).

---

## 8. Version Roadmap

| Version | Milestone |
|---|---|
| v0.1 | DRAVE Core (Rule → Test → Telemetry → Adapter → PASS/FAIL) |
| v0.2 | Syntax + Schema validation |
| v0.3 | Git + Regression |
| v0.4 | Customer Telemetry |
| v0.5 | Attack Replay |
| v0.6 | Attack Variations / Robustness |
| v0.7 | Noise / Volume |
| v0.8 | Performance |
| v0.9 | ATT&CK Validation |
| v1.0 | Detection Health |
| v1.1 | GitHub Action |
| v1.2 | Customer Runner |
| v1.3 | Deployment + Rollback |
| v1.4 | SaaS Dashboard |
| v1.5 | Multi-SIEM / Multi-language |

**First milestone (do not start with the website):**
```
Detection Rule → Test Case → Telemetry → Detection Adapter
→ Execute → Expected vs Actual → PASS / FAIL
```

---

## 9. DRAVE's Final Architecture

```
                         DETECTION ENGINEERS
                                  │
                    ┌─────────────┼─────────────┐
                    ▼             ▼             ▼
                 GitHub          CLI          Web UI
                    │             │             │
                    └─────────────┼─────────────┘
                                  ▼
                            DRAVE API
                                  │
                                  ▼
                       PIPELINE ORCHESTRATOR
                                  │
              ┌───────────────────┼──────────────────┐
              ▼                   ▼                  ▼
       RULE MANAGEMENT       TEST ENGINE        DEPLOYMENT
              │                   │                  │
              │             ┌─────┼─────┐            │
              │             ▼     ▼     ▼            │
              │            Unit Replay Regression    │
              │             │     │     │            │
              └─────────────┼─────┼─────┘            │
                            ▼     ▼                  ▼
                       EVIDENCE ENGINE          SIEM ADAPTERS
                            │              ┌──────┼──────┐
                            │              ▼      ▼      ▼
                            │           Splunk Sentinel Elastic
                            │
                            ▼
                       HEALTH ENGINE
                            │
                   ┌────────┼────────┐
                   ▼        ▼        ▼
                 PASS      WARN     FAIL
                            │
                            ▼
                      CUSTOMER RUNNER
                            │
                  ┌─────────┼─────────┐
                  ▼         ▼         ▼
              Telemetry    SIEM    Test Data
```

### DRAVE's Technical Core

```
                    DRAVE CORE
                        │
       ┌────────────────┼─────────────────┐
       ▼                ▼                 ▼
     ANALYSIS       VERSIONING        EVALUATION
       │                │                 │
       ▼                ▼                 ▼
   Validation         Git           Unit Tests
   Schema             Diff          Regression
   Telemetry          History       Attack Replay
                                     Variations
                                     Noise
                                     Performance
                                     ATT&CK
```

### Complete Lifecycle Diagram (End-to-End)

```
                         DRAVE
                           │
                           ▼
                   WRITE DETECTION
                           │
                           ▼
                          GIT
                           │
                           ▼
                         PR
                           │
                           ▼
                    DRAVE CI/CD
                           │
       ┌───────────────────┼───────────────────┐
       ▼                   ▼                   ▼
   ANALYSIS           VERSIONING          EVALUATION
       │                   │                   │
   Syntax              Diff               Unit Tests
   Schema              Author             Attack Replay
   Telemetry           Timestamp          Variations
                       Reason             Robustness
                       Review             Noise
                       Version            Performance
                                           ATT&CK
       │                   │                   │
       └───────────────────┼───────────────────┘
                           ▼
                     EVIDENCE ENGINE
                           │
                    ┌──────┴──────┐
                    ▼             ▼
                   FAIL          PASS
                    │             │
                    ▼             ▼
                Fix Rule       Approval
                                  │
                                  ▼
                                Merge
                                  │
                                  ▼
                               Deploy
                                  │
                 ┌────────────────┼────────────────┐
                 ▼                ▼                ▼
              Splunk           Sentinel          Elastic
                 │                │                │
                 └────────────────┼────────────────┘
                                  ▼
                             PRODUCTION
                                  │
                                  ▼
                       CONTINUOUS EVALUATION
                                  │
                       ┌──────────┴──────────┐
                       ▼                     ▼
                    HEALTHY              DEGRADATION
                                             │
                                             ▼
                                        INVESTIGATE
                                             │
                                             ▼
                                        NEW TEST
                                             │
                                             ▼
                                        NEW VERSION
                                             │
                                             ▼
                                         RE-TEST
```

---

## 10. Repository Structure

```
drave/
│
├── core/
│   ├── detection/
│   ├── testing/
│   ├── validation/
│   ├── telemetry/
│   ├── replay/
│   ├── robustness/
│   ├── regression/
│   ├── volume/
│   ├── performance/
│   └── scoring/
│
├── adapters/
│   ├── sigma/
│   ├── splunk/
│   ├── sentinel/
│   ├── eql/
│   └── esql/
│
├── cli/
├── runner/
├── api/
├── dashboard/
└── tests/
```

---

## 11. The Final DRAVE Concept

The entire startup reduces to three questions, which map directly to the product name:

**1. Analysis — Does this detection actually work?**
Syntax · Schema · Unit Tests · Telemetry · Attack Replay

**2. Versioning — What changed, who changed it, why, when, what is deployed, and can we safely go back?**
Git · Diff · PR · Review · Deployment Manifest · Audit · Last Known Good · Rollback

**3. Evaluation — How well and how broadly does this detection work?**
Attack Variations · Robustness · Regression · Alert Volume · Performance · ATT&CK Coverage

> **DRAVE** = **D**etection **R**ule **A**nalysis, **V**ersioning, and **E**valuation

### Product Statement

DRAVE is a detection engineering platform that analyzes security detection rules, versions and audits every change, evaluates them against telemetry and attack variations, and safely moves validated detections through CI/CD into production.

### Simplest Mental Model

```
WRITE → VERSION → ANALYZE → TEST → ATTACK-TEST → EVALUATE
→ REVIEW → DEPLOY → MONITOR → ROLLBACK / IMPROVE → RE-TEST
```

That's DRAVE.
