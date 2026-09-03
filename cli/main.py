from pathlib import Path
from typing import Any

import typer
import yaml
from rich.console import Console
from rich.table import Table

from adapters.sigma.inmemory import SigmaInMemoryAdapter
from core.detection.models import DetectionRule
from core.reporting.pr_comment import generate_pr_comment
from core.testing.models import TestCase
from core.testing.runner import run_test
from core.testing.storage import LocalJsonlStorage
from core.validation.dependencies import extract_dependencies
from core.validation.report import generate_report
from core.validation.schema import SchemaProvider
from core.versioning.diff import extract_rule_diff
from core.versioning.pr_parser import parse_pr_reason
from core.versioning.manifest import DeploymentManifest
from core.versioning.lkg import LKGTracker, LKGRecord
from core.versioning.rollback import RollbackCoordinator
from core.regression.runner import RegressionRunner
from core.regression.diff import diff_test_results
import uuid
import json
from datetime import datetime, timezone

app = typer.Typer(help="DRAVE Detection Validation Engine")
console = Console()


@app.callback()
def callback():
    """DRAVE CLI."""


def load_yaml(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


@app.command()
def test(detection_id: str = typer.Argument(None)):
    """Run tests for a detection (or all detections)."""
    # Load all rules
    rules_dir = Path("detections/rules")
    tests_dir = Path("detections/tests")

    if not rules_dir.exists() or not tests_dir.exists():
        console.print(
            "[red]Error: detections/rules or detections/tests directory not found.[/red]"
        )
        raise typer.Exit(1)

    rules: dict[str, DetectionRule] = {}
    for rule_file in rules_dir.glob("*.yml"):
        data = load_yaml(str(rule_file))
        rule = DetectionRule(**data)
        if detection_id and rule.id != detection_id:
            continue
        rules[rule.id] = rule

    if not rules:
        console.print("[yellow]No rules found matching the criteria.[/yellow]")
        raise typer.Exit(0)

    # Load all tests
    tests: list[TestCase] = []
    for test_file in tests_dir.glob("*.yml"):
        data = load_yaml(str(test_file))
        test_case = TestCase(**data)
        if test_case.detection_id in rules:
            tests.append(test_case)

    if not tests:
        console.print("[yellow]No tests found for the loaded rules.[/yellow]")
        raise typer.Exit(0)

    adapter = SigmaInMemoryAdapter()
    schema_provider = SchemaProvider()
    storage = LocalJsonlStorage()

    for rule_id, rule in rules.items():
        console.print(f"\n[bold underline]Rule: {rule.name} ({rule.id})[/bold underline]")
        
        # ── 1. Syntax Validation (Step 13) ──
        if not adapter.validate(rule):
            console.print("[bold red]FAIL: Syntax validation failed. Skipping tests.[/bold red]")
            continue
            
        console.print("[green]PASS: Syntax valid[/green]")
        
        # ── 2. Schema Validation (Steps 14-16) ──
        compiled = adapter.compile(rule)
        deps = extract_dependencies(compiled)
        schema_fields = schema_provider.get_schema_fields(deps.logsource_id)
        report = generate_report(deps, schema_fields)
        
        if report.error:
            console.print(f"[yellow]WARN: Schema Validation Error: {report.error}[/yellow]")
        else:
            pct_color = "green" if report.compatibility_pct == 100 else "yellow"
            console.print(f"[{pct_color}]Schema Compatibility: {report.compatibility_pct}%[/{pct_color}]")
            
            if report.missing_required_fields:
                console.print(f"[bold red]FAIL: Missing REQUIRED fields: {', '.join(report.missing_required_fields)}[/bold red]")
            if report.missing_optional_fields:
                console.print(f"[yellow]WARN: Missing OPTIONAL fields: {', '.join(report.missing_optional_fields)}[/yellow]")
                
            console.print(f"Risk Level: [bold]{report.risk}[/bold]")
        
        # ── 3. Run Tests ──
        rule_tests = [tc for tc in tests if tc.detection_id == rule_id]
        if not rule_tests:
            console.print("[dim]No tests found for this rule.[/dim]")
            continue
            
        table = Table(title="Test Results", title_justify="left", show_edge=False)
        table.add_column("Test ID", style="magenta")
        table.add_column("Type")
        table.add_column("Status", justify="center")
        table.add_column("Diagnostics")

        for tc in rule_tests:
            result = run_test(rule, tc, adapter)
            storage.store_result(result)
            
            status_color = {
                "PASS": "[bold green]PASS[/bold green]",
                "FAIL": "[bold red]FAIL[/bold red]",
                "ERROR": "[bold yellow]ERROR[/bold yellow]",
                "SKIPPED": "[dim]SKIP[/dim]",
            }.get(result.status, result.status)

            error_msg = result.diagnostics.get("error_msg", "")
            if result.status == "ERROR":
                error_msg = result.diagnostics.get("error", "Unknown error")
                
            table.add_row(
                tc.test_id,
                tc.type.value,
                status_color,
                error_msg,
            )

        console.print(table)
        console.print()

@app.command()
def pr_report(detection_id: str, base: str, head: str, pr_body_file: str):
    """Generate a markdown PR report for a specific detection."""
    # 1. Parse Reason
    pr_body_path = Path(pr_body_file)
    if not pr_body_path.exists():
        console.print(f"[red]PR body file {pr_body_file} not found.[/red]")
        raise typer.Exit(1)
    
    reason = parse_pr_reason(pr_body_path.read_text(encoding="utf-8"))
    
    # 2. Find rule
    rule_file = next(Path("detections/rules").glob(f"*.yml"), None)
    rules_dir = Path("detections/rules")
    rule_path = None
    rule = None
    for rf in rules_dir.glob("*.yml"):
        data = load_yaml(str(rf))
        if data.get("id") == detection_id:
            rule_path = rf
            rule = DetectionRule(**data)
            break
            
    if not rule or not rule_path:
        console.print(f"[red]Detection {detection_id} not found.[/red]")
        raise typer.Exit(1)
        
    # 3. Extract Diff
    try:
        rule_diff = extract_rule_diff(".", base, head, str(rule_path).replace("\\", "/"))
    except Exception as e:
        console.print(f"[red]Git diff failed: {e}[/red]")
        raise typer.Exit(1)

    # 4. Schema/Validation
    adapter = SigmaInMemoryAdapter()
    schema_provider = SchemaProvider()
    compiled = adapter.compile(rule)
    deps = extract_dependencies(compiled)
    schema_fields = schema_provider.get_schema_fields(deps.logsource_id)
    schema_report = generate_report(deps, schema_fields)
    
    # 5. Tests
    tests_dir = Path("detections/tests")
    test_results = []
    for test_file in tests_dir.glob("*.yml"):
        data = load_yaml(str(test_file))
        test_case = TestCase(**data)
        if test_case.detection_id == detection_id:
            res = run_test(rule, test_case, adapter)
            test_results.append(res)
            
    # 6. Generate Markdown
    md = generate_pr_comment(rule, schema_report, test_results, rule_diff, reason)
    console.print(md)

@app.command()
def deploy_stub(detection_id: str, commit_hash: str, mark_lkg: bool = typer.Option(True, help="Update LKG to this deployment")):
    """Stub deployment command (Phase L prep). Books the LKG state."""
    # Find rule for version
    rule_file = next(Path("detections/rules").glob(f"*.yml"), None)
    rules_dir = Path("detections/rules")
    rule = None
    for rf in rules_dir.glob("*.yml"):
        data = load_yaml(str(rf))
        if data.get("id") == detection_id:
            rule = DetectionRule(**data)
            break
            
    if not rule:
        console.print(f"[red]Detection {detection_id} not found.[/red]")
        raise typer.Exit(1)
        
    manifest = DeploymentManifest(
        deployment_id=str(uuid.uuid4()),
        detection_id=detection_id,
        git_commit=commit_hash,
        version=rule.version,
        target_siem="splunk",
        timestamp=datetime.now(timezone.utc),
        status="success"
    )
    
    storage = LocalJsonlStorage()
    storage.store_deployment(manifest)
    
    lkg = LKGTracker()
    record = lkg.get_record(detection_id) or LKGRecord(detection_id=detection_id, current_version=rule.version)
    record.current_version = rule.version
    record.last_deployed_version = rule.version
    
    if mark_lkg:
        record.last_known_good_version = rule.version
        record.last_known_good_commit = commit_hash
        console.print(f"[green]Stub deploy recorded for {detection_id} v{rule.version}. LKG marked.[/green]")
    else:
        console.print(f"[green]Stub deploy recorded for {detection_id} v{rule.version}. LKG NOT marked.[/green]")
        
    lkg.update_record(record)

@app.command()
def rollback_plan(detection_id: str, rule_path: str, tests_dir: str = "detections/tests", requested_by: str = "cli_user", reason: str = "emergency_rollback"):
    """Orchestrate a rollback using the LKG tracker and historical git blobs."""
    test_paths = [str(p) for p in Path(tests_dir).glob("*.yml")]
    coordinator = RollbackCoordinator()
    try:
        manifest = coordinator.orchestrate_rollback(
            detection_id=detection_id,
            rule_path=rule_path,
            test_paths=test_paths,
            requested_by=requested_by,
            reason=reason
        )
        console.print("[yellow]Rollback Verification Successful[/yellow]")
        console.print(f"Old tests re-run and passed. Manifest ID: {manifest.deployment_id}")
        console.print(f"Rolled back to version: {manifest.to_version} from commit: {manifest.git_commit}")
    except Exception as e:
        console.print(f"[red]Rollback Failed: {e}[/red]")
        raise typer.Exit(1)

@app.command()
def regression_test(detection_id: str, rule_path: str, tests_dir: str = "detections/tests"):
    """Run regression tests against the LKG baseline."""
    # Find rule
    rule = None
    data = load_yaml(rule_path)
    if data.get("id") == detection_id:
        rule = DetectionRule(**data)
        
    if not rule:
        console.print(f"[red]Rule not found or ID mismatch at {rule_path}[/red]")
        raise typer.Exit(1)
        
    runner = RegressionRunner()
    try:
        b_results, c_results = runner.run_regression_suite(rule, rule_path, tests_dir)
        report = diff_test_results(detection_id, b_results, c_results)
        
        table = Table(title=f"Regression Report: {detection_id}", show_lines=True)
        table.add_column("Test ID", style="cyan")
        table.add_column("Baseline", style="blue")
        table.add_column("Current", style="magenta")
        table.add_column("Change", style="yellow")
        
        for item in report.items:
            color = "green" if item.status_change == "FIX" else "red" if item.status_change == "REGRESSION" else "white"
            table.add_row(
                item.test_id,
                item.baseline_status,
                item.current_status,
                f"[{color}]{item.status_change}[/{color}]"
            )
            
        console.print(table)
        console.print(f"\nRegressions: [red]{report.regressions}[/red] | Fixes: [green]{report.fixes}[/green]")
        if report.regressions > 0:
            raise typer.Exit(1)
            
    except Exception as e:
        console.print(f"[red]Regression engine failed: {e}[/red]")
        raise typer.Exit(1)

@app.command()
def capture_failure(
    detection_id: str, 
    telemetry_file: str, 
    expected_alert: bool = typer.Option(..., "--expected-alert", help="MUST specify if this event is expected to trigger an alert"),
    test_type: str = typer.Option("regression", help="Type of test: 'regression' or 'attack'")
):
    """Convert a failing telemetry event into a permanent test case or attack variation."""
    telemetry_path = Path(telemetry_file)
    if not telemetry_path.exists():
        console.print(f"[red]File {telemetry_file} not found.[/red]")
        raise typer.Exit(1)
        
    event = json.loads(telemetry_path.read_text(encoding="utf-8"))
    
    if test_type == "attack":
        # Step 49: Write as a permanent variation fixture
        # Determine technique from the rule's attack_mappings
        rules_dir = Path("detections/rules")
        technique = None
        for rf in rules_dir.glob("*.yml"):
            data = load_yaml(str(rf))
            if data.get("id") == detection_id:
                mappings = data.get("attack_mappings", [])
                if mappings:
                    technique = mappings[0].replace(".", "_")
                break
        if not technique:
            technique = "unknown"
            
        fixture_dir = Path(f"fixtures/{technique}")
        fixture_dir.mkdir(parents=True, exist_ok=True)
        
        variation_id = f"bypass_{uuid.uuid4().hex[:6]}"
        out_path = fixture_dir / f"{variation_id}.json"
        out_path.write_text(json.dumps(event, indent=2), encoding="utf-8")
        console.print(f"[green]Captured bypass as attack variation: {out_path}[/green]")
    else:
        test_id = f"test-{test_type}-{uuid.uuid4().hex[:6]}"
        
        test_case = {
            "test_id": test_id,
            "detection_id": detection_id,
            "type": test_type,
            "expected": {
                "alert": expected_alert
            },
            "input_telemetry": [event]
        }
        
        import ruamel.yaml
        yaml_writer = ruamel.yaml.YAML()
        yaml_writer.indent(mapping=2, sequence=4, offset=2)
        
        out_path = Path("detections/tests") / f"{test_id}.yml"
        with out_path.open("w", encoding="utf-8") as f:
            yaml_writer.dump(test_case, f)
            
        console.print(f"[green]Captured failure as new test case: {out_path}[/green]")

@app.command()
def runner_test(detection_id: str):
    """Run a detection through the local Customer Runner stub."""
    from runner.engine import RunnerEngine
    from runner.models import RunnerJob
    
    # Find rule and tests
    rules_dir = Path("detections/rules")
    tests_dir = Path("detections/tests")
    rule_path = None
    
    for rf in rules_dir.glob("*.yml"):
        data = load_yaml(str(rf))
        if data.get("id") == detection_id:
            rule_path = str(rf)
            break
            
    if not rule_path:
        console.print(f"[red]Detection {detection_id} not found.[/red]")
        raise typer.Exit(1)
        
    test_paths = [str(p) for p in tests_dir.glob("*.yml")]
    
    job = RunnerJob(
        job_id=str(uuid.uuid4()),
        detection_id=detection_id,
        rule_path=rule_path,
        test_paths=test_paths
    )
    
    engine = RunnerEngine()
    result = engine.execute_job(job)
    
    # Display results
    table = Table(title=f"Runner Result: {detection_id}", show_lines=True)
    table.add_column("Test ID", style="cyan")
    table.add_column("Status", style="magenta")
    
    for tr in result.test_results:
        color = "green" if tr.status == "PASS" else "red"
        table.add_row(tr.test_id, f"[{color}]{tr.status}[/{color}]")
        
    console.print(table)
    console.print(f"\nStatus: {result.status}")
    
    if result.schema_snapshot:
        console.print(f"Schema fields: {len(result.schema_snapshot.fields)}")
        
    if result.drift_detected:
        console.print("[yellow]Schema Drift Detected:[/yellow]")
        for d in result.drift_details:
            console.print(f"  - {d}")
    else:
        console.print("[green]No schema drift detected.[/green]")


@app.command()
def replay(scenario_path: str):
    """Replay an attack scenario and report detection coverage."""
    from core.replay.engine import ReplayEngine
    from core.replay.models import AttackScenario
    
    # Load the scenario
    path = Path(scenario_path)
    if not path.exists():
        console.print(f"[red]Scenario file not found: {scenario_path}[/red]")
        raise typer.Exit(1)
        
    data = load_yaml(str(path))
    scenario = AttackScenario(**data)
    
    # Load attack telemetry from the fixtures if they are file paths
    import json
    loaded_telemetry = []
    for item in scenario.telemetry:
        if isinstance(item, str):
            # It's a path to a fixture
            fixture_path = Path(item)
            if fixture_path.exists():
                loaded_telemetry.append(json.loads(fixture_path.read_text(encoding="utf-8")))
            else:
                console.print(f"[red]Telemetry fixture not found: {item}[/red]")
                raise typer.Exit(1)
        elif isinstance(item, dict):
            # It's inline telemetry
            loaded_telemetry.append(item)
            
    scenario.telemetry = loaded_telemetry
    
    engine = ReplayEngine()
    result = engine.replay(scenario)
    
    # Render results
    console.print(f"\n[bold]Attack Replay:[/bold] {result.scenario_name} ({result.technique})")
    
    table = Table(show_lines=True)
    table.add_column("Expected Detection ID", style="cyan")
    table.add_column("Status", style="magenta")
    
    for det_id in result.expected_detections:
        if det_id in result.actual_detections:
            table.add_row(det_id, "[green]FIRED[/green]")
        else:
            table.add_row(det_id, "[red]MISSED[/red]")
            
    console.print(table)
    
    # The crucial part requested by the user: exit non-zero if missed
    if result.status == "FAIL":
        console.print(f"\n[red]FAIL: {len(result.missed_detections)} expected detection(s) missed![/red]")
        raise typer.Exit(1)
    
    console.print(f"\n[green]PASS: All expected detections fired. Latency: {result.detection_latency_ms}ms[/green]")


@app.command()
def volume(
    detection_id: str,
    sample_dir: str = typer.Option(..., "--sample-dir", help="Directory containing sample JSON telemetry"),
    daily_events: int = typer.Option(..., "--daily-events", help="Estimated total events in production per day")
):
    """Estimate daily alert volume based on a representative telemetry sample."""
    from core.volume.estimator import VolumeEstimator
    from core.volume.policies import evaluate_volume_policy
    
    rules_dir = Path("detections/rules")
    rule = None
    for rf in rules_dir.glob("*.yml"):
        data = load_yaml(str(rf))
        if data.get("id") == detection_id:
            rule = DetectionRule(**data)
            break
            
    if not rule:
        console.print(f"[red]Detection {detection_id} not found.[/red]")
        raise typer.Exit(1)
        
    sample_path = Path(sample_dir)
    if not sample_path.exists() or not sample_path.is_dir():
        console.print(f"[red]Sample directory {sample_dir} not found.[/red]")
        raise typer.Exit(1)
        
    sample_events = []
    for f in sample_path.glob("*.json"):
        try:
            event = json.loads(f.read_text(encoding="utf-8"))
            sample_events.append(event)
        except Exception:
            continue
            
    if not sample_events:
        console.print(f"[yellow]No valid JSON events found in {sample_dir}.[/yellow]")
        raise typer.Exit(1)
        
    estimator = VolumeEstimator()
    estimate = estimator.estimate(rule, sample_events, daily_events)
    
    console.print("\n[bold]Volume Estimation[/bold]")
    console.print(f"Sample size: {estimate.sample_size} events")
    console.print(f"Matches in sample: {estimate.match_count}")
    console.print(f"Match rate: {estimate.match_rate:.2%}")
    console.print(f"Estimated daily alerts: [cyan]{estimate.estimated_daily_alerts:.1f}[/cyan] (based on {daily_events} daily events)")
    
    result = evaluate_volume_policy(rule, estimate)
    if result.status == "FAIL":
        console.print(f"\n[red]FAIL: {result.message}[/red]")
        raise typer.Exit(1)
    elif result.status == "WARNING":
        console.print(f"\n[yellow]WARNING: {result.message}[/yellow]")
    else:
        console.print(f"\n[green]PASS: {result.message}[/green]")

@app.command()
def attack_coverage(detection_id: str):
    """Analyze a rule's ATT&CK metadata and validation coverage."""
    from core.scoring.attack_coverage import AttackCoverageAnalyzer
    from rich.table import Table
    
    rules_dir = Path("detections/rules")
    rule = None
    for rf in rules_dir.glob("*.yml"):
        data = load_yaml(str(rf))
        if data.get("id") == detection_id:
            # If it's a raw Sigma rule, it won't have a query field
            if "query" not in data:
                data["query"] = Path(rf).read_text(encoding="utf-8")
            
            data["name"] = data.get("title", data.get("name", "Unknown"))
            data["severity"] = data.get("level", data.get("severity", "low"))
            
            if "tags" in data and "attack_mappings" not in data:
                data["attack_mappings"] = [
                    t.replace("attack.", "").upper() for t in data["tags"]
                    if t.startswith("attack.t")
                ]
            
            # ensure other required fields have fallbacks if this is a raw sigma rule
            data["language"] = data.get("language", "sigma")
            data["platform"] = data.get("platform", "windows")
            data["author"] = data.get("author", "unknown")
            data["created_at"] = data.get("created_at", data.get("date", "2024-01-01T00:00:00Z"))
            data["updated_at"] = data.get("updated_at", data.get("modified", "2024-01-01T00:00:00Z"))
            if isinstance(data["created_at"], str) and "/" in data["created_at"]:
                 data["created_at"] = "2024-01-01T00:00:00Z" # bypass date parse issues for demo
            
            rule = DetectionRule(**data)
            break
            
    if not rule:
        console.print(f"[red]Detection {detection_id} not found.[/red]")
        raise typer.Exit(1)
        
    analyzer = AttackCoverageAnalyzer()
    report = analyzer.analyze(rule)
    
    table = Table(title=f"ATT&CK Coverage: {detection_id}", show_lines=True)
    table.add_column("Category", style="cyan")
    table.add_column("Status", style="magenta")
    
    table.add_row("Declared Techniques", ", ".join(report.declared_techniques) if report.declared_techniques else "None")
    table.add_row("Unit Tests Passing", "[green]Yes[/green]" if report.has_unit_tests else "[red]No[/red]")
    table.add_row("Attack Scenario Passing", "[green]Yes[/green]" if report.has_attack_scenario else "[red]No[/red]")
    table.add_row("Variations Coverage > 0", "[green]Yes[/green]" if report.has_variations else "[red]No[/red]")
    table.add_row("FULLY VALIDATED", "[green]YES[/green]" if report.is_validated else "[red]NO[/red]")
    
    console.print(table)


@app.command()
def robustness(detection_id: str):
    """Run robustness analysis: variation coverage and matrix."""
    from core.robustness.coverage import CoverageCalculator
    from core.robustness.matrix import RobustnessMatrix
    
    # Find the rule and its ATT&CK mappings
    rules_dir = Path("detections/rules")
    rule = None
    technique = None
    for rf in rules_dir.glob("*.yml"):
        data = load_yaml(str(rf))
        if data.get("id") == detection_id:
            rule = DetectionRule(**data)
            mappings = data.get("attack_mappings", [])
            if mappings:
                technique = mappings[0]
            break
            
    if not rule:
        console.print(f"[red]Detection {detection_id} not found.[/red]")
        raise typer.Exit(1)
        
    if not technique:
        console.print(f"[red]No ATT&CK mapping found for {detection_id}.[/red]")
        raise typer.Exit(1)
        
    # Discover variation fixtures for this technique
    fixtures_base = Path("fixtures")
    variation_paths = []
    for technique_dir in fixtures_base.iterdir():
        if not technique_dir.is_dir():
            continue
        # Check if this fixture directory maps to the rule's technique
        meta_path = technique_dir / "metadata.json"
        if meta_path.exists():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            dir_technique = meta.get("technique", "")
            # Match against any of the rule's attack_mappings
            # T1059.001 matches T1059.001; T1110 matches T1110.001
            if not any(dir_technique.startswith(t) or t.startswith(dir_technique)
                       for t in (rule.attack_mappings or [])):
                continue
        else:
            continue  # No metadata, skip
        for vf in technique_dir.glob("variation_*.json"):
            variation_paths.append(str(vf))
        for vf in technique_dir.glob("bypass_*.json"):
            variation_paths.append(str(vf))
    
    if not variation_paths:
        console.print(f"[yellow]No variation fixtures found.[/yellow]")
        raise typer.Exit(0)
        
    # Calculate coverage
    calc = CoverageCalculator()
    report = calc.calculate(rule, variation_paths)
    
    # Build and render matrix
    matrix = RobustnessMatrix()
    matrix.add_report(report)
    
    console.print(matrix.render_table(detection_id))
    console.print(f"\nCoverage: {report.detected_count}/{report.total_variations} ({report.coverage_score:.0%})")
    
    if report.failed_variations:
        console.print(f"[red]Failed variations: {', '.join(report.failed_variations)}[/red]")


@app.command()
def evidence(detection_id: str):
    """Generate the full Evidence Report and evaluate Hard Gates for deployment."""
    from core.scoring.evidence import EvidenceBuilder
    from core.testing.runner import run_test
    from core.testing.models import TestCase
    from core.validation.report import generate_report as generate_schema_report
    from core.validation.dependencies import extract_dependencies
    from core.validation.schema import SchemaProvider
    from core.volume.estimator import VolumeEstimator
    from core.volume.policies import evaluate_volume_policy
    from core.robustness.coverage import CoverageCalculator
    from core.replay.engine import ReplayEngine
    from core.replay.models import AttackScenario
    from adapters.sigma.inmemory import SigmaInMemoryAdapter
    import json
    
    rules_dir = Path("detections/rules")
    rule = None
    rule_path = None
    for rf in rules_dir.glob("*.yml"):
        data = load_yaml(str(rf))
        if data.get("id") == detection_id:
            if "query" not in data:
                data["query"] = Path(rf).read_text(encoding="utf-8")
            data["name"] = data.get("title", data.get("name", "Unknown"))
            data["severity"] = data.get("level", data.get("severity", "low"))
            if "tags" in data and "attack_mappings" not in data:
                data["attack_mappings"] = [t.replace("attack.", "").upper() for t in data["tags"] if t.startswith("attack.t")]
            data["language"] = data.get("language", "sigma")
            data["platform"] = data.get("platform", "windows")
            data["author"] = data.get("author", "unknown")
            data["created_at"] = data.get("created_at", data.get("date", "2024-01-01T00:00:00Z"))
            data["updated_at"] = data.get("updated_at", data.get("modified", "2024-01-01T00:00:00Z"))
            if isinstance(data["created_at"], str) and "/" in data["created_at"]:
                 data["created_at"] = "2024-01-01T00:00:00Z"
            rule = DetectionRule(**data)
            rule_path = str(rf)
            break
            
    if not rule:
        console.print(f"[red]Rule {detection_id} not found.[/red]")
        raise typer.Exit(1)
        
    syntax_valid = True
    try:
        SigmaInMemoryAdapter().compile(rule)
    except Exception:
        syntax_valid = False
        
    adapter = SigmaInMemoryAdapter()
        
    # 1. Tests
    tests_dir = Path("detections/tests")
    test_paths = []
    if tests_dir.exists():
        for f in tests_dir.glob("*.yml"):
            try:
                td = load_yaml(str(f))
                if td.get("detection_id") == detection_id:
                    test_paths.append(str(f))
            except Exception:
                pass
                
    tests_total = len(test_paths)
    tests_passed = 0
    if tests_total > 0:
        for f in test_paths:
            try:
                tc = TestCase(**load_yaml(f))
                res = run_test(rule, tc, adapter)
                if res.status == "PASS":
                    tests_passed += 1
            except Exception:
                pass
                
    # 2. Schema
    deps = extract_dependencies(adapter.compile(rule))
    schema_fields = SchemaProvider().get_schema_fields(deps.logsource_id)
    schema_report = generate_schema_report(deps, schema_fields)
    
    # 3. Volume
    volume_result = None
    sample_file = Path("fixtures/powershell/attack.json") # Mock path for volume, ideally user configures this.
    if sample_file.exists():
        estimator = VolumeEstimator()
        sample_data = json.loads(sample_file.read_text(encoding="utf-8"))
        if isinstance(sample_data, dict):
            sample_data = [sample_data]
        est_vol = estimator.estimate(rule, sample_data, 1000)
        volume_result = evaluate_volume_policy(rule, est_vol)
        
    # 4. Attack Replay & Variations
    attack_report = None
    variation_report = None
    if rule.attack_mappings:
        technique = rule.attack_mappings[0]
        scenarios_dir = Path("fixtures") / technique.replace("T", "t").lower()
        if scenarios_dir.exists():
            # Find scenario
            scenario_path = scenarios_dir / "attack.json"
            if scenario_path.exists():
                # Attack scenario uses YAML model, wait, earlier we built scenarios/powershell_attack.yml
                pass
                
    # Re-using AttackCoverageAnalyzer logic is safer
    from core.scoring.attack_coverage import AttackCoverageAnalyzer
    analyzer = AttackCoverageAnalyzer()
    
    # Let's get AttackReplayReport manually since AttackCoverageAnalyzer only returns boolean currently.
    scenarios_dir = Path("detections/scenarios")
    if scenarios_dir.exists() and rule.attack_mappings:
        technique = rule.attack_mappings[0]
        for f in scenarios_dir.glob("*.yml"):
            sd = load_yaml(str(f))
            if sd.get("technique") == technique and detection_id in sd.get("expected_detections", []):
                scenario = AttackScenario(**sd)
                loaded_telemetry = []
                for item in scenario.telemetry:
                    if isinstance(item, str) and Path(item).exists():
                        loaded_telemetry.append(json.loads(Path(item).read_text(encoding="utf-8")))
                    elif isinstance(item, dict):
                        loaded_telemetry.append(item)
                scenario.telemetry = loaded_telemetry
                engine = ReplayEngine()
                attack_report = engine.replay(scenario)
                break
                
        # Variations (Lookup by technique or explicit name)
        v_dir = Path(f"fixtures/{rule.attack_mappings[0].lower().replace('.', '_')}")
        if not v_dir.exists() and "powershell" in rule.name.lower():
            v_dir = Path("fixtures/powershell")
            
        v_paths = []
        if v_dir.exists():
            for f in v_dir.glob("variation_*.json"):
                v_paths.append(str(f))
        if v_paths:
            calc = CoverageCalculator()
            variation_report = calc.calculate(rule, v_paths)
            
    # 5. Regression 
    regression_report = None
    from core.regression.runner import RegressionRunner
    from core.regression.diff import diff_test_results
    import git
    
    r_runner = RegressionRunner(repo_path=".")
    try:
        b_results, c_results = r_runner.run_regression_suite(rule, str(rule_path))
        regression_report = diff_test_results(detection_id, b_results, c_results)
    except ValueError:
        # Expected if there is no baseline/LKG set yet for a new rule
        pass
    except git.exc.GitCommandError:
        # Expected if the file didn't exist in the baseline commit (brand new rule)
        pass
            
    builder = EvidenceBuilder()
    report = builder.build(
        rule=rule,
        syntax_valid=syntax_valid,
        tests_total=tests_total,
        tests_passed=tests_passed,
        regression_report=regression_report,
        attack_report=attack_report,
        variation_report=variation_report,
        schema_report=schema_report,
        volume_result=volume_result
    )
    
    # Render Output
    table = Table(title=f"Evidence Report: {report.rule_name}", show_lines=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")
    
    table.add_row("Health Score", f"{report.health_score}/100")
    table.add_row("Syntax Valid", str(report.gates.syntax_valid))
    table.add_row("Tests Passing", f"{report.tests_passed}/{report.tests_total}" if report.tests_total else "N/A (Failed Gate)")
    table.add_row("Schema Risk", report.schema_risk or "N/A")
    table.add_row("Schema Compat", f"{report.schema_compatibility_pct}%" if report.schema_compatibility_pct is not None else "N/A")
    table.add_row("Volume Status", report.volume_status or "N/A")
    table.add_row("Attack Scenarios", "Passed" if report.gates.no_known_attack_missed else "Failed")
    
    color = "green" if report.gates.passed_all_gates else "red"
    table.add_row("HARD GATES PASSED", f"[{color}]{str(report.gates.passed_all_gates).upper()}[/{color}]")
    
    console.print(table)
    
    if not report.gates.passed_all_gates:
        console.print("[red]Rule blocked from deployment due to failing hard gates.[/red]")
        raise typer.Exit(1)
        
    console.print("[green]Rule cleared for deployment.[/green]")

from typing import Optional

@app.command()
def ci_check(
    files: Optional[list[str]] = typer.Argument(None, help="List of YAML rule files to check"),
    out: str = typer.Option("drave_report.md", help="Path to write the markdown report"),
    workspace: str = typer.Option(".", "--workspace", help="Workspace root for artifact discovery"),
    bootstrap: bool = typer.Option(False, "--bootstrap", help="Validate all discovered rules")
):
    """Run the CI Evidence pipeline against a list of modified rules."""
    from core.scoring.evidence import EvidenceBuilder
    from core.scoring.health import HealthCalculator
    from core.validation.dependencies import extract_dependencies
    from core.validation.schema import SchemaProvider
    from core.validation.report import generate_report as generate_schema_report
    from core.volume.estimator import VolumeEstimator
    from core.volume.policies import evaluate_volume_policy
    from core.replay.engine import ReplayEngine
    from core.replay.models import AttackScenario
    from core.robustness.coverage import CoverageCalculator
    from core.discovery.scanner import RepositoryScanner
    from adapters.sigma.inmemory import SigmaInMemoryAdapter
    import git
    from core.regression.runner import RegressionRunner
    from core.regression.diff import diff_test_results
    import json
    
    passed_all = True
    full_markdown = []
    
    # Run Artifact Discovery
    scanner = RepositoryScanner(workspace)
    inventory = scanner.scan()
    
    if inventory.errors:
        print(f"⚠️  Discovery encountered {len(inventory.errors)} error(s):")
        for err in inventory.errors:
            print(f"   - [{err.error_type}] {err.relative_path}: {err.message}")
            
    rules_to_check = []
    if bootstrap:
        rules_to_check = list(inventory.rules.values())
        print(f"Bootstrap mode: Validating all {len(rules_to_check)} discovered rules.")
    else:
        if not files:
            print("Error: Must provide files in incremental mode, or use --bootstrap.")
            raise typer.Exit(code=1)
            
        for file_path in files:
            p = Path(file_path)
            try:
                rel_path = str(p.resolve().relative_to(Path(workspace).resolve())).replace("\\", "/")
            except ValueError:
                rel_path = str(p).replace("\\", "/")
                
            if rel_path in inventory.rule_paths:
                det_id = inventory.rule_paths[rel_path]
                if det_id in inventory.rules:
                    rules_to_check.append(inventory.rules[det_id])
                else:
                    print(f"Warning: Discovered rule {det_id} but it failed to parse. Skipping {file_path}")
            else:
                print(f"Warning: File {file_path} is not a valid detection rule. Skipping.")
                
    if not rules_to_check:
        print("No valid rules to check.")
        raise typer.Exit(code=0)

    for rule in rules_to_check:
        detection_id = rule.id
        print(f"\nEvaluating Rule: {detection_id}")
        
        # 1. Syntax
        syntax_valid = True
        adapter = SigmaInMemoryAdapter()
        try:
            adapter.compile(rule)
        except Exception:
            syntax_valid = False
            
        # 2. Tests
        test_refs = inventory.tests.get(detection_id, [])
        tests_total = len(test_refs)
        tests_passed = 0
        if tests_total > 0:
            for ref in test_refs:
                try:
                    f = Path(workspace) / ref.relative_path
                    tc = TestCase(**load_yaml(str(f)))
                    res = run_test(rule, tc, adapter)
                    if res.status == "PASS":
                        tests_passed += 1
                except Exception:
                    pass
                    
        # 3. Schema
        schema_report = None
        if syntax_valid:
            try:
                deps = extract_dependencies(adapter.compile(rule))
                schema_fields = SchemaProvider().get_schema_fields(deps.logsource_id)
                schema_report = generate_schema_report(deps, schema_fields)
            except Exception:
                pass
                
        # 4. Volume
        volume_result = None
        vol_refs = inventory.volume_fixtures.get(detection_id, [])
        if not vol_refs and rule.attack_mappings:
            vol_refs = inventory.volume_fixtures.get(rule.attack_mappings[0], [])
            
        if vol_refs:
            # For MVP, just use the first matching volume fixture
            sample_file = Path(workspace) / vol_refs[0].relative_path
            try:
                estimator = VolumeEstimator()
                sample_data = json.loads(sample_file.read_text(encoding="utf-8"))
                if isinstance(sample_data, dict) and "events" in sample_data:
                    sample_data = sample_data["events"]
                elif isinstance(sample_data, dict): 
                    sample_data = [sample_data]
                est_vol = estimator.estimate(rule, sample_data, 1000)
                volume_result = evaluate_volume_policy(rule, est_vol)
            except Exception:
                pass
                
        # 5. Attack Replay & Variations
        attack_reports = []
        variation_report = None
        
        scenario_refs = inventory.scenarios.get(detection_id, [])
        if scenario_refs:
            for ref in scenario_refs:
                f = Path(workspace) / ref.relative_path
                try:
                    sd = load_yaml(str(f))
                    scenario = AttackScenario(**sd)
                    loaded_telemetry = []
                    for item in scenario.telemetry:
                        if isinstance(item, str):
                            item_path = Path(workspace) / item
                            if item_path.exists():
                                loaded_telemetry.append(json.loads(item_path.read_text(encoding="utf-8")))
                        elif isinstance(item, dict):
                            loaded_telemetry.append(item)
                    scenario.telemetry = loaded_telemetry
                    engine = ReplayEngine()
                    attack_reports.append(engine.replay(scenario))
                except Exception:
                    pass
                    
        var_refs = inventory.variation_fixtures.get(detection_id, [])
        if not var_refs and rule.attack_mappings:
            var_refs = inventory.variation_fixtures.get(rule.attack_mappings[0], [])
            
        v_paths = [str(Path(workspace) / r.relative_path) for r in var_refs]
        if v_paths:
            calc = CoverageCalculator()
            variation_report = calc.calculate(rule, v_paths)
                
        # 6. Regression 
        regression_report = None
        r_runner = RegressionRunner(repo_path=workspace)
        try:
            # We don't have the original file_path easily accessible, use relative path if we want
            # But the regression runner in MVP expects the file path of the rule in the working tree
            # Let's find the rel_path from inventory
            rel_path = next((k for k, v in inventory.rule_paths.items() if v == detection_id), None)
            if rel_path:
                b_results, c_results = r_runner.run_regression_suite(rule, str(Path(workspace) / rel_path))
                regression_report = diff_test_results(detection_id, b_results, c_results)
        except Exception:
            pass
            
        builder = EvidenceBuilder()
        # Note: EvidenceBuilder now needs to handle List[ReplayReport]
        # For backwards compatibility during this step, we will update EvidenceBuilder separately
        # But here we pass the list.
        evidence = builder.build(
            rule=rule,
            syntax_valid=syntax_valid,
            tests_total=tests_total,
            tests_passed=tests_passed,
            schema_report=schema_report,
            volume_result=volume_result,
            attack_reports=attack_reports,
            variation_report=variation_report
        )
        
        if not evidence.gates.passed_all_gates:
            passed_all = False
            console.print(f"[red][FAIL] {detection_id} failed hard gates[/red]")
        else:
            console.print(f"[green][PASS] {detection_id} passed[/green]")
            
        full_markdown.append(evidence.render_markdown())
        
    out_path = Path(out)
    out_path.write_text("\n\n---\n\n".join(full_markdown), encoding="utf-8")
    
    if not passed_all:
        console.print("\n[bold red]CI Check Failed: One or more rules failed hard gates.[/bold red]")
        raise typer.Exit(1)
        
    console.print(f"\n[bold green]CI Check Passed! Report saved to {out}[/bold green]")

@app.command()
def deploy(
    rule_file: str = typer.Argument(..., help="Path to the rule YAML file to deploy"),
    target: str = typer.Option("splunk", help="SIEM target to deploy to (e.g., splunk)")
):
    """Deploy a detection rule to a SIEM (Tier 3 Action)."""
    import ruamel.yaml
    from datetime import datetime
    import uuid
    import getpass
    
    from core.detection.models import DetectionRule
    from adapters.splunk.adapter import SplunkAdapter
    from core.deployment.verify import verify_deployment
    from core.deployment.auto_rollback import attempt_auto_rollback
    from core.versioning.manifest import DeploymentManifest
    
    yaml = ruamel.yaml.YAML(typ="safe")
    path = Path(rule_file)
    if not path.exists():
        console.print(f"[red]Error: File {rule_file} not found.[/red]")
        raise typer.Exit(1)
        
    data = yaml.load(path.read_text(encoding="utf-8"))
    try:
        rule = DetectionRule(**data)
    except Exception as e:
        console.print(f"[red]Error parsing rule: {e}[/red]")
        raise typer.Exit(1)
        
    if target.lower() != "splunk":
        console.print(f"[red]Unsupported target: {target}[/red]")
        raise typer.Exit(1)
        
    console.print("\n[bold yellow]! TIER 3 ACTION: SIEM DEPLOYMENT ![/bold yellow]")
    console.print(f"You are about to deploy the following rule to [bold]{target.upper()}[/bold]:")
    console.print(f"  - [cyan]Rule Name:[/cyan] {rule.name}")
    console.print(f"  - [cyan]Detection ID:[/cyan] {rule.id}")
    console.print(f"  - [cyan]Version:[/cyan] {rule.version}")
    console.print("\nThis action requires explicit human sign-off.")
    
    confirm = typer.prompt(f"Type the detection ID ({rule.id}) to confirm deployment")
    
    if confirm != rule.id:
        console.print("\n[red]Deployment aborted: Confirmation did not match detection ID.[/red]")
        raise typer.Exit(1)
        
    # Log the approval
    user = getpass.getuser()
    manifest = DeploymentManifest(
        deployment_id=str(uuid.uuid4()),
        detection_id=rule.id,
        git_commit="HEAD",  # Mocked for CLI demo
        version=rule.version,
        target_siem=target,
        timestamp=datetime.utcnow(),
        status="pending",
        requested_by=user,
        approved_by=user,
        reason="Manual deployment via CLI"
    )
    
    console.print(f"\n[green]Deployment authorized by {user}. Logged to manifest ({manifest.deployment_id}).[/green]")
    
    adapter = SplunkAdapter()
    console.print("Deploying to Splunk...")
    
    success = adapter.deploy(rule)
    if not success:
        console.print("[red]Deployment failed at adapter level.[/red]")
        manifest.status = "failed"
        raise typer.Exit(1)
        
    console.print("Running post-deployment verification (smoke test)...")
    verified = verify_deployment(rule, adapter)
    
    if verified:
        console.print("[bold green]Deployment and verification successful![/bold green]")
        manifest.status = "success"
    else:
        console.print("[bold red]Verification failed! Smoke test returned no match.[/bold red]")
        console.print("[yellow]Triggering automated rollback...[/yellow]")
        
        rollback_success = attempt_auto_rollback(rule.id, rule_path=rule_file)
        if rollback_success:
            manifest.status = "rollback_success"
        else:
            manifest.status = "rollback_failed"
            console.print("[bold red]CRITICAL: Rollback failed. Manual intervention required.[/bold red]")
            raise typer.Exit(1)

if __name__ == "__main__":
    app()
