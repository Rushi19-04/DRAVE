"""Unit tests for Stage 5 Validation logic."""

from pathlib import Path

from sigma.rule import SigmaRule

from core.validation.dependencies import extract_dependencies
from core.validation.report import generate_report
from core.validation.schema import SchemaProvider


def test_dependency_extraction():
    """Test extracting required and optional fields from a Sigma rule."""
    yaml = r"""
    title: Test Rule
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Image|endswith: '\powershell.exe'
            CommandLine|contains: '-enc'
        filter:
            User: 'SYSTEM'
        condition: sel and not filter
    """
    rule = SigmaRule.from_yaml(yaml)
    deps = extract_dependencies(rule)

    assert deps.logsource_id == "windows_process_creation"
    assert "Image" in deps.required_fields
    assert "CommandLine" in deps.required_fields
    assert "User" in deps.optional_fields
    assert "User" not in deps.required_fields


def test_schema_provider_loads_fields(tmp_path: Path):
    """Test that SchemaProvider correctly parses a JSON schema for its fields."""
    import json
    
    schema_dir = tmp_path / "schemas"
    schema_dir.mkdir()
    schema_file = schema_dir / "test_logsource.json"
    
    schema_data = {
        "properties": {
            "FieldA": {"type": "string"},
            "FieldB": {"type": "integer"}
        }
    }
    with open(schema_file, "w") as f:
        json.dump(schema_data, f)
        
    provider = SchemaProvider(schemas_dir=str(schema_dir))
    fields = provider.get_schema_fields("test_logsource")
    
    assert fields == {"FieldA", "FieldB"}


def test_schema_provider_missing_file(tmp_path: Path):
    provider = SchemaProvider(schemas_dir=str(tmp_path))
    fields = provider.get_schema_fields("does_not_exist")
    assert fields == set()


def test_generate_report_100_percent():
    from core.validation.dependencies import RuleDependencies
    
    deps = RuleDependencies(
        logsource_id="test",
        required_fields={"Image", "CommandLine"},
        optional_fields={"User"}
    )
    schema_fields = {"Image", "CommandLine", "User", "OtherField"}
    
    report = generate_report(deps, schema_fields)
    assert report.compatibility_pct == 100.0
    assert report.risk == "LOW"
    assert not report.missing_required_fields
    assert not report.missing_optional_fields


def test_generate_report_missing_optional():
    from core.validation.dependencies import RuleDependencies
    
    deps = RuleDependencies(
        logsource_id="test",
        required_fields={"Image"},
        optional_fields={"User"}
    )
    schema_fields = {"Image"}
    
    report = generate_report(deps, schema_fields)
    assert report.compatibility_pct == 100.0
    assert report.risk == "MEDIUM"
    assert not report.missing_required_fields
    assert report.missing_optional_fields == ["User"]


def test_generate_report_missing_required():
    from core.validation.dependencies import RuleDependencies
    
    deps = RuleDependencies(
        logsource_id="test",
        required_fields={"Image", "FakeField"},
        optional_fields=set()
    )
    schema_fields = {"Image"}
    
    report = generate_report(deps, schema_fields)
    assert report.compatibility_pct == 50.0
    assert report.risk == "HIGH"
    assert report.missing_required_fields == ["FakeField"]
