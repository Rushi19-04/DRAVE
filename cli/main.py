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
import uuid
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
def deploy_stub(detection_id: str, commit_hash: str):
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
    record.last_deployed_version = rule.version
    record.last_known_good_version = rule.version
    record.last_known_good_commit = commit_hash
    lkg.update_record(record)
    
    console.print(f"[green]Stub deploy recorded for {detection_id} v{rule.version}[/green]")

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


if __name__ == "__main__":
    app()
