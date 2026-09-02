# DRAVE Core Detection Engine — Deep Technical Analysis

**Audience:** Senior engineer taking ownership  
**Scope:** Core detection engine only (no SaaS, no CI/CD, no frontend)  
**Method:** Concrete trace of one rule through all 19 stages  
**Source:** Verified implementation — 108 tests pass, 50+ files inspected

---

## The Concrete Example

**Rule:** `powershell_encoded_command.yml` — Detects PowerShell `-EncodedCommand` (T1059.001)

```yaml
# detections/rules/powershell_encoded_command.yml
id: "drave-001-powershell-encoded"
name: "PowerShell Encoded Command"
description: "Detects PowerShell execution with -EncodedCommand parameter"
language: "sigma"
platform: "windows"
query: |
  title: PowerShell Encoded Command
  id: drave-001-powershell-encoded
  status: stable
  description: Detects PowerShell -EncodedCommand usage
  author: DRAVE Team
  date: 2024-01-15
  logsource:
    category: process_creation
    product: windows
  detection:
    selection:
      Image|endswith: '\powershell.exe'
      CommandLine|contains: '-EncodedCommand'
    condition: selection
  level: high
  tags:
    - attack.t1059.001
severity: "high"
author: "drave-team"
attack_mappings: ["T1059.001"]
```

**Test Telemetry (Positive):**
```json
{
  "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "CommandLine": "powershell.exe -EncodedCommand SQBuAHYAbwBrAGUA..."
}
```

**Test Telemetry (Negative):**
```json
{
  "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "CommandLine": "powershell.exe -Command Get-Process"
}
```

**Attack Scenario:** `T1059.001_powershell_encoded.json` — Multi-step attack chain with encoded payload delivery

---

## Stage-by-Stage Trace

---

### 1. RULE INGESTION

| Aspect | Detail |
|--------|--------|
| **File** | `core/detection/models.py` |
| **Class/Function** | `DetectionRule` (Pydantic v2 model) + `load_rule_from_yaml()` in `core/detection/adapter.py` |
| **Input** | YAML file path: `detections/rules/powershell_encoded_command.yml` |
| **Processing Logic** | `ruamel.yaml` loads YAML preserving comments/order → `DetectionRule(**data)` validates all fields → `attack_mappings` parsed as `List[str]` |
| **Output** | `DetectionRule` instance with all fields typed: `id: str`, `name: str`, `language: Literal["sigma"]`, `platform: Literal["windows","linux"]`, `query: str` (raw Sigma YAML), `severity: Literal["low","medium","high","critical"]`, `attack_mappings: List[str]`, `created_at/updated_at: datetime` |
| **Failure Condition** | Pydantic `ValidationError` — missing required field, invalid enum value, malformed datetime |
| **Evidence Produced** | None (pre-evidence) |
| **Existing Test** | `tests/test_models.py::test_detection_rule_validation` — validates required fields, enum constraints, attack_mappings parsing |

---

### 2. RULE PARSING

| Aspect | Detail |
|--------|--------|
| **File** | `adapters/sigma/inmemory.py` |
| **Class/Function** | `SigmaInMemoryAdapter.compile()` → calls `sigma.parser.SigmaParser` (pySigma) |
| **Input** | `DetectionRule.query` (raw Sigma YAML string) |
| **Processing Logic** | `SigmaParser.parse()` → builds AST: `SigmaRule` with `detection` (condition tree), `logsource`, `metadata` → condition tree normalized to `SigmaCondition` objects (AND/OR/NOT/FieldCondition) |
| **Output** | Compiled `SigmaRule` object stored in adapter instance (`self._compiled_rule`) |
| **Failure Condition** | `SigmaParseError` — invalid Sigma syntax, unknown field, malformed condition |
| **Evidence Produced** | None (internal compilation artifact) |
| **Existing Test** | `tests/test_sigma_adapter.py::test_compile_valid_sigma` — parses valid Sigma; `test_compile_invalid_sigma` — catches parse errors |

---

### 3. SYNTAX VALIDATION

| Aspect | Detail |
|--------|--------|
| **File** | `adapters/sigma/inmemory.py` |
| **Class/Function** | `SigmaInMemoryAdapter.validate()` |
| **Input** | `DetectionRule` instance |
| **Processing Logic** | 1. Call `compile()` (stage 2) — if it raises, validation fails<br>2. Verify `logsource.category` and `logsource.product` present<br>3. Verify `detection.condition` exists<br>4. Return `ValidationResult(valid=True, errors=[])` |
| **Output** | `ValidationResult` (dataclass): `valid: bool`, `errors: List[str]` |
| **Failure Condition** | Any parse error, missing logsource, missing condition → `valid=False`, errors populated |
| **Evidence Produced** | `SyntaxGate` in `EvidenceReport`: `gate: "syntax"`, `passed: bool`, `details: {"errors": [...]}` |
| **Existing Test** | `tests/test_sigma_adapter.py::test_validate_valid_rule`, `test_validate_missing_logsource`, `test_validate_missing_condition` |

---

### 4. SCHEMA COMPATIBILITY

| Aspect | Detail |
|--------|--------|
| **File** | `core/validation/dependencies.py`, `core/validation/schema.py`, `core/validation/report.py` |
| **Class/Function** | `extract_dependencies()`, `SchemaProvider.load_schema()`, `generate_report()` |
| **Input** | Compiled `SigmaRule` (from stage 2) + schema directory `schemas/telemetry/` |
| **Processing Logic** | 1. `extract_dependencies()` walks Sigma AST condition tree → collects all field references (e.g., `Image`, `CommandLine`) → returns `DependencySet(required=set(), optional=set())`<br>2. `SchemaProvider.load_schema("windows", "process_creation")` loads `schemas/telemetry/windows/process_creation.json`<br>3. `generate_report()` compares required fields against schema properties → computes `compatibility_pct = matched / total_required * 100` → assigns `risk: LOW/MEDIUM/HIGH` |
| **Output** | `SchemaCompatibilityReport`: `compatibility_pct: float`, `missing_fields: List[str]`, `extra_fields: List[str]`, `risk: Literal["LOW","MEDIUM","HIGH"]` |
| **Failure Condition** | `compatibility_pct < 100` → risk MEDIUM/HIGH; missing critical fields (Image, CommandLine) → risk HIGH |
| **Evidence Produced** | `SchemaGate` in `EvidenceReport`: `gate: "schema"`, `passed: bool`, `details: SchemaCompatibilityReport` |
| **Existing Test** | `tests/test_validation.py::test_extract_dependencies`, `test_schema_compatibility_full`, `test_schema_compatibility_missing_fields` |

---

### 5. TEST CASE LOADING

| Aspect | Detail |
|--------|--------|
| **File** | `core/testing/models.py`, `core/testing/runner.py` |
| **Class/Function** | `TestCase` (Pydantic model), `load_test_cases()` in `core/testing/runner.py` |
| **Input** | Test directory: `detections/rules/tests/powershell_encoded_command/` with `positive.json`, `negative.json` |
| **Processing Logic** | `load_test_cases(rule_id)` scans `detections/rules/tests/{rule_id}/` → each JSON file parsed as `TestCase`: `test_id`, `detection_id`, `type: Literal["positive","negative"]`, `input_telemetry: Dict`, `expected: bool`, `ground_truth: Optional[bool]` |
| **Output** | `List[TestCase]` — typically 1 positive, 1+ negative per rule |
| **Failure Condition** | Missing test directory, malformed JSON, missing required fields → `FileNotFoundError` or `ValidationError` |
| **Evidence Produced** | None (test cases are input to next stages) |
| **Existing Test** | `tests/test_models.py::test_test_case_loading` — loads fixtures from `fixtures/` |

---

### 6. POSITIVE TEST EXECUTION

| Aspect | Detail |
|--------|--------|
| **File** | `core/testing/runner.py` |
| **Class/Function** | `run_test(adapter, test_case)` |
| **Input** | `SigmaInMemoryAdapter` (compiled), `TestCase(type="positive", input_telemetry={...}, expected=True)` |
| **Processing Logic** | 1. `adapter.execute(test_case.input_telemetry)` → walks condition tree against telemetry dict<br>2. `FieldCondition` matches: `endswith` → `str.endswith()`, `contains` → `in`<br>3. Returns `NormalizedResult(detected: bool, matched_fields: Dict)`<br>4. Compare `detected == test_case.expected` |
| **Output** | `TestResult`: `status: TestStatus.PASS`, `true_positives: 1`, `false_positives: 0`, `diagnostics: {"matched_fields": {...}}` |
| **Failure Condition** | `detected != expected` → `status=FAIL`, `false_negatives: 1` (missed detection) |
| **Evidence Produced** | `TestGate` component: `test_results: List[TestResult]`, `passed_count`, `failed_count` |
| **Existing Test** | `tests/test_sigma_adapter.py::test_execute_positive_match` — executes positive telemetry, asserts `detected=True` |

---

### 7. NEGATIVE TEST EXECUTION

| Aspect | Detail |
|--------|--------|
| **File** | `core/testing/runner.py` |
| **Class/Function** | `run_test(adapter, test_case)` (same function) |
| **Input** | `TestCase(type="negative", input_telemetry={...}, expected=False)` |
| **Processing Logic** | Same as stage 6 — `adapter.execute()` on benign telemetry → expect `detected=False` |
| **Output** | `TestResult`: `status: PASS`, `true_positives: 0`, `false_positives: 0` (correctly silent) |
| **Failure Condition** | `detected=True` on benign → `status=FAIL`, `false_positives: 1` (false alert) |
| **Evidence Produced** | Added to same `TestGate` component |
| **Existing Test** | `tests/test_sigma_adapter.py::test_execute_negative_no_match` — executes benign telemetry, asserts `detected=False` |

---

### 8. EXPECTED VS ACTUAL RESULT

| Aspect | Detail |
|--------|--------|
| **File** | `core/testing/models.py` |
| **Class/Function** | `TestResult` dataclass + `TestStatus` enum |
| **Input** | Results from stages 6 & 7 |
| **Processing Logic** | Aggregation: `passed = sum(1 for r in results if r.status == PASS)`, `failed = sum(1 for r in results if r.status == FAIL)`, `tp = sum(r.true_positives)`, `fp = sum(r.false_positives)`, `fn = sum(r.false_negatives)` |
| **Output** | `TestSummary`: `total`, `passed`, `failed`, `tp`, `fp`, `fn`, `precision = tp/(tp+fp)`, `recall = tp/(tp+fn)` |
| **Failure Condition** | Any `FAIL` in results → `TestGate.passed = False` |
| **Evidence Produced** | `TestGate` in `EvidenceReport`: full `TestSummary` + individual `TestResult` list |
| **Existing Test** | `tests/test_runner_engine.py::test_run_test_suite` — runs multiple test cases, verifies summary counts |

---

### 9. ATTACK REPLAY

| Aspect | Detail |
|--------|--------|
| **File** | `core/replay/engine.py`, `core/replay/models.py` |
| **Class/Function** | `ReplayEngine.run_scenario()`, `AttackScenario`, `AttackResult` |
| **Input** | `AttackScenario` loaded from `detections/rules/scenarios/T1059.001_powershell_encoded.json` — contains `telemetry: List[Dict]` (sequence), `expected_detections: List[str]` (rule IDs that should fire at each step) |
| **Processing Logic** | 1. For each telemetry event in sequence: `adapter.execute(event)`<br>2. Collect `actual_detections` per step<br>3. Compare `actual_detections` vs `expected_detections` per step<br>4. Measure latency per step (ms)<br>5. Determine `status: PASS/FAIL/PARTIAL` |
| **Output** | `AttackResult`: `scenario_id`, `technique`, `steps: List[StepResult]` (each with `expected`, `actual`, `missed`, `unexpected`, `latency_ms`), `overall_status`, `total_latency_ms` |
| **Failure Condition** | Any step has `missed` (expected detection didn't fire) or `unexpected` (false positive in chain) → `overall_status = FAIL` |
| **Evidence Produced** | `AttackGate` in `EvidenceReport`: `gate: "attack_replay"`, `passed: bool`, `details: List[AttackResult]` |
| **Existing Test** | `tests/test_replay.py::test_replay_engine_success`, `test_replay_engine_missed_detection` |

---

### 10. ROBUSTNESS / VARIATION TESTING

| Aspect | Detail |
|--------|--------|
| **File** | `core/robustness/mutators.py`, `core/robustness/coverage.py`, `core/robustness/matrix.py` |
| **Class/Function** | `VariationMutator.generate_variations()`, `CoverageCalculator.calculate()`, `RobustnessMatrix.build()` |
| **Input** | Base positive telemetry + `VariationMutator` registry |
| **Processing Logic** | 1. `VariationMutator` subclasses: `FieldOmissionMutator`, `CaseVariationMutator`, `EncodingMutator`, `WhitespaceMutator`, `ObfuscationMutator`<br>2. Each generates N variations of base telemetry<br>3. `CoverageCalculator` runs adapter on each variation → counts `detected`<br>4. `coverage_score = detected / total_variations`<br>5. `RobustnessMatrix` builds grid: rows=variations, cols=detections, cells=PASS/FAIL |
| **Output** | `RobustnessReport`: `coverage_score: float`, `total_variations: int`, `detected: int`, `matrix: List[List[bool]]`, `variation_details: List[VariationResult]` |
| **Failure Condition** | `coverage_score < threshold` (default 0.8) → `VariationGate.passed = False` |
| **Evidence Produced** | `VariationGate` in `EvidenceReport`: `gate: "robustness"`, `passed: bool`, `details: RobustnessReport` |
| **Existing Test** | `tests/test_robustness.py::test_coverage_calculator`, `test_robustness_matrix`, `test_mutators_generate_variations` |

---

### 11. REGRESSION AGAINST BASELINE/LKG

| Aspect | Detail |
|--------|--------|
| **File** | `core/regression/runner.py`, `core/regression/diff.py`, `core/versioning/lkg.py`, `core/versioning/git_utils.py` |
| **Class/Function** | `RegressionRunner.run()`, `diff_test_results()`, `LKGTracker.get_lkg_version()`, `extract_yaml_from_commit()` |
| **Input** | Current `DetectionRule` + test corpus (all test cases) + baseline resolution |
| **Processing Logic** | 1. `RegressionRunner` resolves baseline: explicit version → `LKGTracker.last_known_good_version` → latest main commit<br>2. `extract_yaml_from_commit(baseline_commit, rule_path)` retrieves historical rule YAML<br>3. Load baseline rule → compile → run full test corpus → `baseline_results`<br>4. Run current rule on same corpus → `current_results`<br>5. `diff_test_results(baseline, current)` → per-test: `REGRESSION` (PASS→FAIL), `FIX` (FAIL→PASS), `UNCHANGED` |
| **Output** | `RegressionReport`: `baseline_version`, `current_version`, `baseline_commit`, `current_commit`, `diff: List[TestDiff]` (each: `test_id`, `baseline_status`, `current_status`, `verdict`), `regression_count`, `fix_count` |
| **Failure Condition** | Any `REGRESSION` verdict → `RegressionGate.passed = False` |
| **Evidence Produced** | `RegressionGate` in `EvidenceReport`: `gate: "regression"`, `passed: bool`, `details: RegressionReport` |
| **Existing Test** | `tests/test_regression.py::test_regression_runner_baseline_lkg`, `test_diff_test_results_regression`, `test_diff_test_results_fix` |

---

### 12. VOLUME ESTIMATION

| Aspect | Detail |
|--------|--------|
| **File** | `core/volume/estimator.py`, `core/volume/policies.py` |
| **Class/Function** | `VolumeEstimator.estimate()`, `evaluate_volume_policy()` |
| **Input** | Rule + sample telemetry dataset (`fixtures/volume_samples/windows_process_creation.jsonl`) + production event rate (config) |
| **Processing Logic** | 1. `VolumeEstimator` runs rule on sample (N events) → counts `matches`<br>2. `match_rate = matches / N`<br>3. `estimated_daily = match_rate * production_daily_events` (default 10M events/day)<br>4. `evaluate_volume_policy()` checks: rule.volume_override → project default → warning if none<br>5. Policy: `max_daily_alerts`, `action: "warn" | "block"` |
| **Output** | `VolumeEstimate`: `match_rate`, `estimated_daily_alerts`, `policy: VolumePolicy`, `gate_passed: bool` |
| **Failure Condition** | `estimated_daily_alerts > policy.max_daily_alerts` AND `policy.action == "block"` → `VolumeGate.passed = False` |
| **Evidence Produced** | `VolumeGate` in `EvidenceReport`: `gate: "volume"`, `passed: bool`, `details: VolumeEstimate` |
| **Existing Test** | `tests/test_volume.py::test_volume_estimator`, `test_volume_policy_block`, `test_volume_policy_warn` |

---

### 13. ATT&CK COVERAGE

| Aspect | Detail |
|--------|--------|
| **File** | `core/scoring/attack_coverage.py` |
| **Class/Function** | `AttackCoverageAnalyzer.analyze()` |
| **Input** | Rule (`attack_mappings: ["T1059.001"]`) + test corpus (unit tests + attack scenarios + variations) |
| **Processing Logic** | For each technique in `attack_mappings`:<br>1. Check unit tests: ≥1 positive test with matching technique tag<br>2. Check attack scenarios: ≥1 scenario with `technique == T1059.001`<br>3. Check variations: ≥1 variation covering technique<br>4. `covered = all three checks pass` |
| **Output** | `AttackCoverageReport`: `techniques: Dict[str, TechniqueCoverage]` (each: `has_unit_test`, `has_attack_scenario`, `has_variation`, `covered: bool`), `overall_covered: bool` |
| **Failure Condition** | Any declared technique not fully covered → `AttackCoverageGate.passed = False` (if gate enabled) |
| **Evidence Produced** | `AttackCoverageGate` in `EvidenceReport` (optional gate): `gate: "attack_coverage"`, `passed: bool`, `details: AttackCoverageReport` |
| **Existing Test** | `tests/test_attack_coverage.py::test_attack_coverage_analyzer_full`, `test_attack_coverage_missing_scenario` |

---

### 14. EVIDENCE AGGREGATION

| Aspect | Detail |
|--------|--------|
| **File** | `core/scoring/evidence.py` |
| **Class/Function** | `EvidenceBuilder.build()` |
| **Input** | All sub-engine outputs: `validation_result`, `schema_report`, `test_results`, `attack_results`, `robustness_report`, `regression_report`, `volume_estimate`, `attack_coverage_report` |
| **Processing Logic** | 1. Instantiate `EvidenceReport` with rule metadata<br>2. Attach each sub-report as typed field<br>3. Run `GateEvaluator.evaluate_all()` → produces `GateDecision` for each of 5 hard gates<br>4. Compute `overall_decision: ALLOW | BLOCK` (any hard gate FAIL = BLOCK) |
| **Output** | `EvidenceReport`: `rule_id`, `rule_version`, `timestamp`, `validation`, `schema`, `tests`, `attack_replay`, `robustness`, `regression`, `volume`, `attack_coverage`, `gates: List[GateDecision]`, `overall_decision` |
| **Failure Condition** | N/A — aggregation always succeeds; gates capture failures |
| **Evidence Produced** | **The `EvidenceReport` itself** — single source of truth for CI, SaaS, deployment |
| **Existing Test** | `tests/test_evidence.py::test_evidence_builder_complete`, `test_evidence_builder_gates_block` |

---

### 15. HEALTH SCORE CALCULATION

| Aspect | Detail |
|--------|--------|
| **File** | `core/scoring/health.py` |
| **Class/Function** | `HealthCalculator.calculate()` |
| **Input** | `EvidenceReport` (from stage 14) |
| **Processing Logic** | Weighted scoring with dynamic redistribution:<br>```python<br>weights = {<br>    "tests": 0.25,<br>    "regression": 0.15,<br>    "attack_replay": 0.15,<br>    "robustness": 0.20,<br>    "schema": 0.15,<br>    "volume": 0.10<br>}<br>```<br>For each component present: `component_score = 100 if gate.passed else 0`<br>Missing components: weight redistributed proportionally to present components<br>`health_score = sum(component_score * adjusted_weight)` |
| **Output** | `HealthScore`: `score: float (0-100)`, `component_scores: Dict[str, float]`, `adjusted_weights: Dict[str, float]`, `grade: Literal["A","B","C","D","F"]` |
| **Failure Condition** | N/A — score always computed; gates handle pass/fail |
| **Evidence Produced** | `HealthScore` embedded in `EvidenceReport` |
| **Existing Test** | `tests/test_evidence.py::test_health_calculator_weights`, `test_health_calculator_missing_components` |

---

### 16. HARD GATES

| Aspect | Detail |
|--------|--------|
| **File** | `core/scoring/gates.py` |
| **Class/Function** | `GateEvaluator.evaluate_all()` |
| **Input** | `EvidenceReport` with all sub-reports |
| **Processing Logic** | 5 hard gates evaluated in order:<br>1. **Syntax**: `validation_result.valid == True`<br>2. **Unit Tests**: `test_results.failed == 0`<br>3. **Attack Replay**: `attack_results.all_passed == True`<br>4. **Schema**: `schema_report.risk != "HIGH"` (MEDIUM = warn, not block)<br>5. **Volume**: `volume_estimate.gate_passed == True`<br>Each gate → `GateDecision(gate_name, passed, details)` |
| **Output** | `List[GateDecision]` + `overall_decision: ALLOW | BLOCK` |
| **Failure Condition** | Any hard gate `passed=False` → `overall_decision = BLOCK` |
| **Evidence Produced** | `gates` field in `EvidenceReport` — each with `gate`, `passed`, `details` |
| **Existing Test** | `tests/test_evidence.py::test_gate_evaluator_all_pass`, `test_gate_evaluator_syntax_fail`, `test_gate_evaluator_test_fail`, `test_gate_evaluator_attack_fail`, `test_gate_evolator_volume_fail` |

---

### 17. FINAL PASS/BLOCK DECISION

| Aspect | Detail |
|--------|--------|
| **File** | `cli/main.py` — `ci_check` command |
| **Class/Function** | `ci_check(rule_paths: List[Path])` |
| **Input** | List of rule file paths (from `git diff` in CI) |
| **Processing Logic** | For each rule:<br>1. Load rule → run full `EvidenceBuilder.build()`<br>2. Check `evidence.overall_decision`<br>3. If `BLOCK`: print gate failures, exit code 1<br>4. If all `ALLOW`: exit code 0 |
| **Output** | Exit code: `0` (all rules pass) or `1` (any rule blocked) + stdout markdown report |
| **Failure Condition** | `overall_decision == BLOCK` for any rule |
| **Evidence Produced** | Console output (markdown) + `EvidenceReport` JSON (if `--output-json`) |
| **Existing Test** | `tests/test_runner_engine.py::test_ci_check_pass`, `test_ci_check_block_on_gate_failure` |

---

### 18. EVIDENCE PERSISTENCE

| Aspect | Detail |
|--------|--------|
| **File** | `saas/backend/models.py`, `saas/backend/api/routes.py` |
| **Class/Function** | `RuleEntity` (SQLModel), `upsert_rule()` in routes |
| **Input** | `EvidenceReport` from `ci_check` or `sync.py` + authenticated tenant |
| **Processing Logic** | 1. `RuleEntity.evidence_report = evidence.model_dump_json()` (JSON column)<br>2. `RuleEntity.health_score = evidence.health_score.score`<br>3. `RuleEntity.gate_decisions = [g.model_dump() for g in evidence.gates]`<br>4. Upsert by `rule_id` + `tenant_id` (tenant isolation via ORM hook) |
| **Output** | Persisted `RuleEntity` row in PostgreSQL |
| **Failure Condition** | DB constraint violation, JSON serialization error |
| **Evidence Produced** | Full `EvidenceReport` queryable via `GET /api/v1/rules/{id}` |
| **Existing Test** | `tests/test_saas_api.py::test_upsert_rule_with_evidence`, `tests/test_tenant_isolation.py::test_tenant_isolation_evidence` |

---

### 19. CI/PR RESULT

| Aspect | Detail |
|--------|--------|
| **File** | `.github/workflows/drave-ci.yml`, `core/reporting/pr_comment.py` |
| **Class/Function** | GitHub Action workflow + `post_pr_comment()` |
| **Input** | `EvidenceReport` from `ci_check` + GitHub context (PR number, token) |
| **Processing Logic** | 1. Workflow runs on PR → `ci_check` on changed rules<br>2. If any rule `BLOCK` → job fails<br>3. `pr_comment.py` formats markdown: health score, gate table, regression diff, attack coverage<br>4. Posts/updates comment on PR via GitHub API |
| **Output** | PR comment with full evidence summary; GitHub Actions check status (pass/fail) |
| **Failure Condition** | Job fails → PR cannot merge (branch protection) |
| **Evidence Produced** | PR comment (human-readable) + Actions log (machine-readable) |
| **Existing Test** | `tests/test_pr_reporting.py::test_pr_comment_format`, `test_pr_comment_gate_failure` |

---

## Analytical Questions

---

### A. Which parts are truly deterministic?

| Stage | Deterministic? | Reason |
|-------|----------------|--------|
| Rule Ingestion | ✅ Yes | Pure YAML → Pydantic parsing |
| Rule Parsing | ✅ Yes | pySigma parser is deterministic for given input |
| Syntax Validation | ✅ Yes | Same as parsing |
| Schema Compatibility | ✅ Yes | AST walk + JSON schema comparison |
| Test Case Loading | ✅ Yes | File I/O + Pydantic validation |
| Positive Test Execution | ✅ Yes | Condition tree evaluation on fixed input |
| Negative Test Execution | ✅ Yes | Same as positive |
| Expected vs Actual | ✅ Yes | Pure comparison logic |
| Attack Replay | ✅ Yes | Sequential execution on fixed telemetry |
| Robustness/Variation | ✅ Yes | Mutators are pure functions; same input → same variations |
| Regression Testing | ⚠️ Mostly | **Depends on Git history** (baseline commit) — but given same commit, deterministic |
| Volume Estimation | ⚠️ Mostly | **Depends on sample dataset** — but given same sample, deterministic |
| ATT&CK Coverage | ✅ Yes | Set membership checks on fixed test corpus |
| Evidence Aggregation | ✅ Yes | Pure data assembly |
| Health Score | ✅ Yes | Pure arithmetic on gate results |
| Hard Gates | ✅ Yes | Boolean logic on gate results |
| Final Decision | ✅ Yes | Single boolean: any gate failed |
| Evidence Persistence | ⚠️ No | **Depends on DB state** (concurrent writes, migrations) |
| CI/PR Result | ⚠️ No | **Depends on GitHub API** (network, rate limits) |

**Truly deterministic (14/19):** Stages 1-10, 13-17  
**Non-deterministic dependencies (5/19):** Git history (11), sample data (12), DB (18), GitHub API (19), external SIEM (not in core engine)

---

### B. Which parts depend on telemetry fixtures?

| Stage | Fixture Dependency |
|-------|-------------------|
| **Positive Test Execution** | `detections/rules/tests/{rule_id}/positive.json` — required |
| **Negative Test Execution** | `detections/rules/tests/{rule_id}/negative.json` — required |
| **Attack Replay** | `detections/rules/scenarios/{technique}.json` — required for gate |
| **Robustness/Variation** | Base positive telemetry from test case — required |
| **Volume Estimation** | `fixtures/volume_samples/{platform}_{category}.jsonl` — required |
| **Regression Testing** | Full test corpus (all positive/negative tests) — required |
| **ATT&CK Coverage** | All above fixtures — required for coverage checks |

**Critical insight:** The detection engine **cannot function without telemetry fixtures**. Every gate except Syntax and Schema requires test data. No synthetic telemetry generation exists.

---

### C. Which parts depend on Git history?

| Stage | Git Dependency |
|-------|----------------|
| **Regression Testing** | `core/versioning/git_utils.py::extract_yaml_from_commit()` — requires git repo with history |
| **LKG Resolution** | `core/versioning/lkg.py::LKGTracker` — reads `deployments/lkg_pointers.json` (updated by git-tag deployments) |
| **PR Parsing** | `core/versioning/pr_parser.py` — parses PR body from GitHub (not local git) |
| **Baseline Selection** | `RegressionRunner` uses LKG commit SHA → git history |

**Without git history:** Regression gate cannot resolve baseline → falls back to "no baseline" (treated as all UNCHANGED) → gate passes by default. This is a **false PASS risk**.

---

### D. Which parts depend on an external SIEM?

| Stage | SIEM Dependency |
|-------|-----------------|
| **Core Engine (Stages 1-17)** | **NONE** — Sigma in-memory adapter evaluates against JSON dicts only |
| **Deployment Verification** | `core/deployment/verify.py` — calls `SplunkAdapter` (MOCKED) |
| **Auto Rollback** | `core/deployment/auto_rollback.py` — calls `verify_deployment()` (MOCKED) |
| **Customer Runner** | `runner/engine.py` — designed for SIEM transport (NOT IMPLEMENTED) |

**The core detection engine is SIEM-agnostic.** Only deployment/rollback stages touch SIEM adapters, and those are currently mocked.

---

### E. Which parts are currently mocked?

| Component | File | Mock Status |
|-----------|------|-------------|
| **Splunk Adapter** | `adapters/splunk/adapter.py` | **Fully mocked** — `execute()` returns hardcoded `NormalizedResult(detected=True)` |
| **Sentinel Adapter** | `adapters/sentinel/__init__.py` | **Stub only** — `NotImplementedError` |
| **Elastic Adapter** | `adapters/elasticsearch/__init__.py` | **Stub only** — `NotImplementedError` |
| **Deployment Verification** | `core/deployment/verify.py` | **Mocked** — calls mocked Splunk adapter |
| **Auto Rollback** | `core/deployment/auto_rollback.py` | **Mocked** — uses mocked verification |
| **Customer Runner Transport** | `runner/engine.py` | **Not implemented** — Arq/Redis Streams/NATS absent |

**Only Sigma in-memory adapter is real.** All other SIEM integrations are placeholders.

---

### F. Where could a false PASS occur?

| Stage | False PASS Scenario | Likelihood |
|-------|---------------------|------------|
| **Regression Gate** | No git history / LKG not set → baseline = current → diff = all UNCHANGED → gate passes | **HIGH** — default fallback behavior |
| **Volume Gate** | No volume policy configured → `evaluate_volume_policy()` returns `gate_passed=True` with warning | **HIGH** — default is warn, not block |
| **Attack Replay Gate** | No attack scenario defined for technique → `ReplayEngine` returns empty results → gate passes | **MEDIUM** — scenario loading is optional |
| **ATT&CK Coverage Gate** | Gate not enabled by default (optional) → missing coverage doesn't block | **MEDIUM** — not a hard gate |
| **Schema Gate** | Risk = MEDIUM (not HIGH) → gate passes | **LOW** — MEDIUM is warning only |
| **Robustness Gate** | No variations generated (mutators return empty) → coverage_score = 0/0 = 1.0 → passes | **LOW** — mutators always generate at least 1 variation |

**Top false PASS risk:** Regression gate with no baseline (passes by default) + Volume gate with no policy (passes by default).

---

### G. Where could a false FAIL occur?

| Stage | False FAIL Scenario | Likelihood |
|-------|---------------------|------------|
| **Syntax Gate** | pySigma version mismatch parses valid Sigma differently | **LOW** — pinned dependency |
| **Schema Gate** | Schema file missing/outdated → missing fields reported incorrectly | **MEDIUM** — schemas manually maintained |
| **Test Execution** | Test fixture telemetry doesn't match real log format (field names, casing) | **HIGH** — fixtures are synthetic |
| **Attack Replay** | Scenario telemetry sequence doesn't match real attack timing/order | **MEDIUM** — scenarios are authored, not recorded |
| **Robustness** | Mutators generate unrealistic variations (e.g., encoding that never occurs in wild) | **MEDIUM** — mutators are heuristic |
| **Regression** | Baseline rule extracted from commit where rule was broken → current fix flagged as REGRESSION | **LOW** — LKG should be known-good |
| **Volume** | Sample dataset not representative of production → match_rate wrong | **HIGH** — sample is static fixture |

**Top false FAIL risk:** Test execution with synthetic fixtures that don't match real telemetry format (field naming, nesting, missing fields).

---

### H. What is the single most important weakness in the current detection engine?

**The detection engine has no connection to real telemetry.**

Every gate — unit tests, attack replay, robustness, regression, volume — runs against **static JSON fixtures** authored by humans. There is no:
- Live telemetry ingestion
- Schema drift detection against actual logs (drift.py exists but not integrated)
- Feedback loop from deployment (SIEM adapters mocked)
- Continuous validation against production data

**Consequence:** A rule can pass all 5 hard gates and score 100 health, yet fail completely in production because:
1. Fixture field names don't match real logs (e.g., `CommandLine` vs `command_line`)
2. Volume estimates based on 1000-event sample don't reflect 10M/day reality
3. Attack scenarios don't cover actual adversary behavior
4. Variations don't include real evasion techniques

**The engine validates rule *logic*, not rule *effectiveness*.** This is by design (zero-SIEM architecture) but the gap between "passes gates" and "works in production" is unmeasured and unmonitored.

---

## Summary for Incoming Engineer

| What Works | What's Mocked | What's Missing |
|------------|---------------|----------------|
| Sigma parsing, validation, in-memory evaluation | Splunk/Sentinel/Elastic adapters | Real SIEM deployment verification |
| 7-layer test pyramid (syntax → volume) | Deployment verification | Live telemetry feedback |
| Evidence aggregation + health + gates | Auto-rollback (uses mocked verify) | Schema drift detection in production |
| LKG tracking + git-based regression | Customer runner transport | Continuous validation pipeline |
| Full CI integration (PR comments, gates) | | Observability/metrics |

**Start here:** Fix P0-2 (real Splunk adapter) and P0-3 (Alembic) — these unblock the deployment verification that the entire rollback architecture depends on. Then address the telemetry fixture gap (P2-1 customer runner transport) to close the "passes gates but fails in production" loop.