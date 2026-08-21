"""Tests for the Evidence and Health Engine (Stage 15)."""

import pytest
from core.detection.models import DetectionRule
from core.scoring.gates import GateEvaluator
from core.scoring.health import HealthCalculator
from core.scoring.evidence import EvidenceBuilder
from core.validation.report import SchemaCompatibilityReport
from core.volume.policies import VolumePolicyResult
from core.replay.models import AttackResult
from core.robustness.coverage import CoverageReport
from core.regression.diff import RegressionReport


def test_health_calculator():
    calc = HealthCalculator()
    
    # Perfect score scenario
    score = calc.calculate(
        tests_total=10,
        tests_passed=10,
        regression_report=RegressionReport(detection_id="test", total_tests=5, regressions=0, fixes=0, items=[]),
        attack_report=AttackResult(
            scenario_id="s1", 
            scenario_name="Test",
            technique="T1", 
            expected_detections=["d1", "d2"], 
            actual_detections=["d1", "d2"], 
            missed_detections=[], 
            detection_latency_ms=10.0, 
            status="PASS"
        ),
        variation_report=CoverageReport(detection_id="r1", total_variations=4, detected_count=4, coverage_score=1.0),
        schema_report=SchemaCompatibilityReport(compatibility_pct=100.0, missing_required_fields=[], missing_optional_fields=[], risk="LOW"),
        volume_result=VolumePolicyResult(status="PASS", message="OK")
    )
    
    assert score == 100.0
    
    # Partial score scenario (e.g., volume is WARNING, so 5/10 for volume)
    score_partial = calc.calculate(
        tests_total=10,
        tests_passed=5,  # 50% pass rate -> 12.5 points
        regression_report=RegressionReport(detection_id="test", total_tests=5, regressions=1, fixes=0, items=[]), # 80% stability -> 12 points
        attack_report=AttackResult(
            scenario_id="s1", 
            scenario_name="Test",
            technique="T1",
            expected_detections=["d1", "d2"], 
            actual_detections=["d1"], 
            missed_detections=["d2"], 
            detection_latency_ms=10.0, 
            status="FAIL"
        ), # 50% attack pass -> 7.5 points
        variation_report=CoverageReport(detection_id="r1", total_variations=4, detected_count=2, coverage_score=0.5), # 50% coverage -> 10 points
        schema_report=SchemaCompatibilityReport(compatibility_pct=50.0, missing_required_fields=[], missing_optional_fields=[], risk="MEDIUM"), # 50% -> 7.5 points
        volume_result=VolumePolicyResult(status="WARNING", message="WARN") # WARNING -> 5 points
    )
    # Total = 12.5 + 12 + 7.5 + 10 + 7.5 + 5 = 54.5
    assert score_partial == 54.5
    
def test_dynamic_weight_redistribution():
    calc = HealthCalculator()
    
    # Missing Regression (15% weight) -> Max applicable is 85
    # Let's say: 
    # Tests: 25/25
    # Attack: 15/15
    # Variation: 20/20
    # Schema: 7.5/15 (50%)
    # Volume: 5/10 (WARNING)
    # Score = 25 + 15 + 20 + 7.5 + 5 = 72.5
    # Applicable = 85.0
    # Expected scaled = (72.5 / 85.0) * 100 = 85.29
    
    score = calc.calculate(
        tests_total=10,
        tests_passed=10,
        regression_report=None,  # MISSING
        attack_report=AttackResult(
            scenario_id="s1", 
            scenario_name="Test",
            technique="T1", 
            expected_detections=["d1"], 
            actual_detections=["d1"], 
            missed_detections=[], 
            detection_latency_ms=10.0, 
            status="PASS"
        ),
        variation_report=CoverageReport(detection_id="r1", total_variations=4, detected_count=4, coverage_score=1.0),
        schema_report=SchemaCompatibilityReport(compatibility_pct=50.0, missing_required_fields=[], missing_optional_fields=[], risk="MEDIUM"),
        volume_result=VolumePolicyResult(status="WARNING", message="WARN")
    )
    
    assert score == 85.29


def test_gates_and_evidence():
    rule = DetectionRule(
        id="test-rule",
        name="Test",
        description="Test",
        language="sigma",
        platform="windows",
        severity="low",
        author="test",
        created_at="2024-01-01T00:00:00Z",
        updated_at="2024-01-01T00:00:00Z",
        query="test"
    )
    
    builder = EvidenceBuilder()
    
    # Scenario: High health score (Volume WARNING, 50% variation coverage) but FAILS schema hard gate
    report = builder.build(
        rule=rule,
        syntax_valid=True,
        tests_total=10,
        tests_passed=10,
        regression_report=RegressionReport(detection_id="test", total_tests=5, regressions=0, fixes=0, items=[]),
        attack_report=AttackResult(
            scenario_id="s1", 
            scenario_name="Test",
            technique="T1", 
            expected_detections=["d1", "d2"], 
            actual_detections=["d1", "d2"], 
            missed_detections=[], 
            detection_latency_ms=10.0, 
            status="PASS"
        ),
        variation_report=CoverageReport(detection_id="r1", total_variations=4, detected_count=4, coverage_score=1.0),
        schema_report=SchemaCompatibilityReport(compatibility_pct=0.0, missing_required_fields=["Image"], missing_optional_fields=[], risk="HIGH"), # HIGH RISK -> FAILS GATE
        volume_result=VolumePolicyResult(status="WARNING", message="WARN")
    )
    
    # Score should be high (Schema is 0 points, Volume is 5 points, everything else is perfect)
    # Tests=25, Regression=15, Attack=15, Variation=20, Schema=0, Volume=5  => Total 80
    assert report.health_score == 80.0
    
    # BUT gates_passed MUST BE FALSE because Schema Risk is HIGH
    assert report.gates.no_critical_schema_incompatibility is False
    assert report.gates.passed_all_gates is False
