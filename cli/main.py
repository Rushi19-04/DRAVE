from pathlib import Path
from typing import Any

import typer
import yaml
from rich.console import Console
from rich.table import Table

from adapters.sigma.inmemory import SigmaInMemoryAdapter
from core.detection.models import DetectionRule
from core.testing.models import TestCase
from core.testing.runner import run_test
from core.testing.storage import LocalJsonlStorage
from core.validation.dependencies import extract_dependencies
from core.validation.report import generate_report
from core.validation.schema import SchemaProvider

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


if __name__ == "__main__":
    app()
