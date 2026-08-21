"""Unit tests for robustness engine (Steps 46-49)."""

import json
import copy
from pathlib import Path

from core.robustness.mutators import mutate_casing, mutate_encoding_flag, mutate_parent_process
from core.robustness.coverage import CoverageCalculator, CoverageReport
from core.robustness.matrix import RobustnessMatrix
from core.detection.models import DetectionRule


# --- Step 46: Mutators ---

def test_mutate_casing():
    event = {"CommandLine": "powershell.exe -enc ABC"}
    result = mutate_casing(event, "CommandLine")
    # Original unchanged
    assert event["CommandLine"] == "powershell.exe -enc ABC"
    # Mutated version has same chars, possibly different casing
    assert result["CommandLine"].lower() == event["CommandLine"].lower()

def test_mutate_parent_process():
    event = {"ParentImage": "C:\\Windows\\explorer.exe"}
    result = mutate_parent_process(event, "C:\\Windows\\System32\\cmd.exe")
    assert result["ParentImage"] == "C:\\Windows\\System32\\cmd.exe"
    # Original unchanged
    assert event["ParentImage"] == "C:\\Windows\\explorer.exe"

def test_mutate_encoding_flag():
    event = {"CommandLine": "powershell.exe -enc SGVsbG8="}
    result = mutate_encoding_flag(event)
    # Should have swapped the -enc flag with some variant
    assert "-enc" in result["CommandLine"] or "-EncodedCommand" in result["CommandLine"] or \
           "-ec " in result["CommandLine"] or "-e " in result["CommandLine"] or "-eNc" in result["CommandLine"]


# --- Step 47: Coverage with exact numeric assertions ---

def _make_rule():
    """Create a minimal DetectionRule for testing."""
    return DetectionRule(
        id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        name="Test Rule",
        description="Test",
        language="sigma",
        platform="windows",
        severity="high",
        author="test",
        created_at="2024-01-01T00:00:00Z",
        updated_at="2024-01-01T00:00:00Z",
        query="""
title: Test Rule
id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\\\powershell.exe'
            - '\\\\pwsh.exe'
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'
            - '-ec '
    condition: selection
level: high
"""
    )


def test_coverage_exact_score(tmp_path):
    """4 variations: 3 should match, 1 should evade.
    
    Expected coverage = 3/4 = 0.75 exactly.
    The evading variation (variation_04) uses '-e ' which the rule does NOT cover.
    """
    rule = _make_rule()
    
    # variation_01: pwsh.exe with -enc → PASS
    v1 = tmp_path / "variation_01.json"
    v1.write_text(json.dumps({
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\pwsh.exe",
        "CommandLine": "pwsh.exe -enc SGVsbG8="
    }))
    
    # variation_02: powershell.exe with -EncodedCommand → PASS
    v2 = tmp_path / "variation_02.json"
    v2.write_text(json.dumps({
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -EncodedCommand SGVsbG8="
    }))
    
    # variation_03: powershell.exe with -ec → PASS
    v3 = tmp_path / "variation_03.json"
    v3.write_text(json.dumps({
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -ec SGVsbG8="
    }))
    
    # variation_04: powershell.exe with -e → FAIL (rule doesn't cover '-e ')
    v4 = tmp_path / "variation_04.json"
    v4.write_text(json.dumps({
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -e SGVsbG8="
    }))
    
    calc = CoverageCalculator()
    report = calc.calculate(rule, [str(v1), str(v2), str(v3), str(v4)])
    
    # Exact assertions
    assert report.total_variations == 4
    assert report.detected_count == 3
    assert report.coverage_score == 0.75
    assert report.failed_variations == ["variation_04"]


def test_coverage_all_pass(tmp_path):
    """2 variations that both match. Coverage = 2/2 = 1.0 exactly."""
    rule = _make_rule()
    
    v1 = tmp_path / "variation_01.json"
    v1.write_text(json.dumps({
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -enc SGVsbG8="
    }))
    
    v2 = tmp_path / "variation_02.json"
    v2.write_text(json.dumps({
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\pwsh.exe",
        "CommandLine": "pwsh.exe -EncodedCommand SGVsbG8="
    }))
    
    calc = CoverageCalculator()
    report = calc.calculate(rule, [str(v1), str(v2)])
    
    assert report.total_variations == 2
    assert report.detected_count == 2
    assert report.coverage_score == 1.0
    assert report.failed_variations == []


# --- Step 48: Robustness Matrix ---

def test_robustness_matrix_render():
    report = CoverageReport(
        detection_id="det-1",
        total_variations=3,
        detected_count=2,
        coverage_score=2/3
    )
    from core.robustness.coverage import VariationResult
    report.results = [
        VariationResult("v1", "path/v1.json", True),
        VariationResult("v2", "path/v2.json", True),
        VariationResult("v3", "path/v3.json", False),
    ]
    
    matrix = RobustnessMatrix()
    matrix.add_report(report)
    
    # Check entries
    assert len(matrix.entries) == 3
    pass_entries = [e for e in matrix.entries if e.result == "PASS"]
    fail_entries = [e for e in matrix.entries if e.result == "FAIL"]
    assert len(pass_entries) == 2
    assert len(fail_entries) == 1
    assert fail_entries[0].variation_id == "v3"


def test_robustness_matrix_json():
    report = CoverageReport(
        detection_id="det-1",
        total_variations=2,
        detected_count=1,
        coverage_score=0.5
    )
    from core.robustness.coverage import VariationResult
    report.results = [
        VariationResult("v1", "path/v1.json", True),
        VariationResult("v2", "path/v2.json", False),
    ]
    
    matrix = RobustnessMatrix()
    matrix.add_report(report)
    
    json_str = matrix.to_json()
    data = json.loads(json_str)
    assert len(data) == 2
    assert data[0]["result"] == "PASS"
    assert data[1]["result"] == "FAIL"
