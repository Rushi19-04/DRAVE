"""Unit tests for ATT&CK coverage analyzer (Steps 56-57)."""

import pytest
from core.detection.models import DetectionRule
from core.scoring.attack_coverage import AttackCoverageAnalyzer, AttackCoverageReport


def _make_rule(rule_id="11111111-2222-3333-4444-555555555555", technique="T1059.001"):
    return DetectionRule(
        id=rule_id,
        name="Coverage Test Rule",
        description="Test",
        language="sigma",
        platform="windows",
        severity="high",
        author="test",
        created_at="2024-01-01T00:00:00Z",
        updated_at="2024-01-01T00:00:00Z",
        attack_mappings=[technique] if technique else [],
        query=f"""
title: Coverage Test Rule
id: {rule_id}
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\cmd.exe'
    condition: selection
level: high
"""
    )


def test_coverage_analyzer_no_mappings():
    analyzer = AttackCoverageAnalyzer()
    rule = _make_rule(technique=None)
    
    report = analyzer.analyze(rule)
    assert not report.is_validated
    assert report.has_unit_tests is False
    assert report.has_attack_scenario is False
    assert report.has_variations is False


def test_coverage_analyzer_actually_checks_execution(monkeypatch):
    """Prove that validation requires tests to ACTUALLY pass, not just files existing."""
    analyzer = AttackCoverageAnalyzer()
    rule = _make_rule()
    
    # Mock the internal check methods directly to simulate:
    # 1. Unit tests run and PASS
    monkeypatch.setattr(analyzer, "_check_unit_tests", lambda r_id, r: True)
    # 2. Variations run and coverage > 0
    monkeypatch.setattr(analyzer, "_check_variations", lambda r, t: True)
    
    # 3. Attack scenario file exists but execution FAILS (returns False)
    monkeypatch.setattr(analyzer, "_check_attack_scenario", lambda r_id, t: False)
    
    report = analyzer.analyze(rule)
    
    # Even though it has unit tests and variations, the failing attack scenario 
    # must prevent Validated from being True.
    assert report.has_unit_tests is True
    assert report.has_variations is True
    assert report.has_attack_scenario is False
    assert report.is_validated is False
