"""Unit tests for volume estimation and policies (Steps 50-53)."""

import json
from pathlib import Path

from core.detection.models import DetectionRule
from core.testing.models import TestCase, TestResult, ExpectedResult
from core.volume.models import VolumeEstimate, VolumePolicy
from core.volume.estimator import VolumeEstimator
from core.volume.policies import evaluate_volume_policy


def _make_rule(volume_policy=None):
    return DetectionRule(
        id="bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
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
id: bbbbbbbb-cccc-dddd-eeee-ffffffffffff
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\\\cmd.exe'
    condition: selection
level: high
""",
        volume_policy=volume_policy
    )


# --- Estimator Tests ---

def test_estimator_exact_rate():
    rule = _make_rule()
    # 4 events, 1 matches cmd.exe
    sample_events = [
        {"Image": "C:\\Windows\\System32\\explorer.exe"},
        {"Image": "C:\\Windows\\System32\\cmd.exe"},
        {"Image": "C:\\Windows\\System32\\powershell.exe"},
        {"Image": "C:\\Windows\\System32\\notepad.exe"},
    ]
    
    estimator = VolumeEstimator()
    estimate = estimator.estimate(rule, sample_events, production_daily_events=10000)
    
    assert estimate.sample_size == 4
    assert estimate.match_count == 1
    assert estimate.match_rate == 0.25
    assert estimate.production_daily_events == 10000
    assert estimate.estimated_daily_alerts == 2500.0


def test_estimator_empty_sample():
    rule = _make_rule()
    estimator = VolumeEstimator()
    estimate = estimator.estimate(rule, [], production_daily_events=10000)
    
    assert estimate.sample_size == 0
    assert estimate.match_count == 0
    assert estimate.match_rate == 0.0
    assert estimate.estimated_daily_alerts == 0.0


# --- Policy Precedence Tests ---

def test_policy_precedence_rule_override(monkeypatch):
    """Rule override should take precedence over global drave.yml."""
    # Mock global config loading to return a policy
    def mock_load():
        return VolumePolicy(warning_threshold=500, failure_threshold=5000)
    import core.volume.policies
    monkeypatch.setattr(core.volume.policies, "load_project_volume_policy", mock_load)
    
    # Rule with tighter override
    rule = _make_rule(volume_policy={"warning_threshold": 10, "failure_threshold": 50})
    estimate = VolumeEstimate(
        detection_id="bbbbbbbb-cccc-dddd-eeee-ffffffffffff", sample_size=10, match_count=1, match_rate=0.1,
        production_daily_events=1000, estimated_daily_alerts=100.0
    )
    
    # 100 > 50 (rule failure), but 100 < 5000 (global failure)
    # Result should be FAIL due to rule override
    result = evaluate_volume_policy(rule, estimate)
    assert result.status == "FAIL"
    assert "rule override" in result.message


def test_policy_precedence_global_default(monkeypatch):
    """Global default should apply when rule has no policy."""
    def mock_load():
        return VolumePolicy(warning_threshold=500, failure_threshold=5000)
    import core.volume.policies
    monkeypatch.setattr(core.volume.policies, "load_project_volume_policy", mock_load)
    
    rule = _make_rule(volume_policy=None)
    estimate = VolumeEstimate(
        detection_id="bbbbbbbb-cccc-dddd-eeee-ffffffffffff", sample_size=10, match_count=1, match_rate=0.1,
        production_daily_events=10000, estimated_daily_alerts=1000.0
    )
    
    # 1000 > 500 (global warning), 1000 < 5000
    result = evaluate_volume_policy(rule, estimate)
    assert result.status == "WARNING"
    assert "project default" in result.message


def test_policy_precedence_no_policy(monkeypatch):
    """Should issue an explicit warning if NO policy exists anywhere."""
    def mock_load():
        return None
    import core.volume.policies
    monkeypatch.setattr(core.volume.policies, "load_project_volume_policy", mock_load)
    
    rule = _make_rule(volume_policy=None)
    estimate = VolumeEstimate(
        detection_id="bbbbbbbb-cccc-dddd-eeee-ffffffffffff", sample_size=10, match_count=1, match_rate=0.1,
        production_daily_events=1000, estimated_daily_alerts=100.0
    )
    
    result = evaluate_volume_policy(rule, estimate)
    assert result.status == "WARNING"
    assert "zero volume gate coverage" in result.message


# --- Ground Truth Counters Tests ---

def test_ground_truth_defaults_unknown():
    tc = TestCase(
        test_id="t1", detection_id="bbbbbbbb-cccc-dddd-eeee-ffffffffffff", type="positive",
        input_telemetry=[], expected=ExpectedResult(alert=True)
    )
    # Default is None
    assert tc.ground_truth is None
    
    res = TestResult(
        rule_id="det-1", test_id="t1", timestamp="now", status="PASS"
    )
    assert res.true_positive == 0
    assert res.false_positive == 0
    assert res.unknown == 0


def test_ground_truth_explicit_labels():
    tc = TestCase(
        test_id="t1", detection_id="det-1", type="positive",
        input_telemetry=[], expected=ExpectedResult(alert=True),
        ground_truth="true_positive"
    )
    assert tc.ground_truth == "true_positive"
    
    res = TestResult(
        rule_id="det-1", test_id="t1", timestamp="now", status="PASS",
        true_positive=1
    )
    assert res.true_positive == 1
    assert res.false_positive == 0
