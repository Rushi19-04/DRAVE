"""Unit tests for attack replay engine (Steps 43-45)."""

import pytest
from core.replay.models import AttackScenario, AttackResult
from core.replay.engine import ReplayEngine
from core.detection.models import DetectionRule


def test_attack_scenario_model():
    scenario = AttackScenario(
        id="s1",
        name="Test Scenario",
        technique="T1059.001",
        telemetry=[{"EventID": 1, "CommandLine": "powershell"}],
        expected_detections=["det-1", "det-2"]
    )
    assert scenario.technique == "T1059.001"
    assert len(scenario.expected_detections) == 2


def test_attack_result_pass():
    result = AttackResult(
        scenario_id="s1",
        scenario_name="Test",
        technique="T1",
        expected_detections=["det-1"],
        actual_detections=["det-1"],
        missed_detections=[],
        detection_latency_ms=0.5,
        status="PASS"
    )
    assert result.status == "PASS"


def test_attack_result_fail_on_missed():
    result = AttackResult(
        scenario_id="s1",
        scenario_name="Test",
        technique="T1",
        expected_detections=["det-1", "det-2"],
        actual_detections=["det-1"],
        missed_detections=["det-2"],
        detection_latency_ms=0.5,
        status="FAIL"
    )
    assert result.status == "FAIL"


class MockAdapter:
    def compile(self, rule):
        return rule
        
    def execute(self, compiled_rule, event):
        # Dummy logic: if rule name matches event data
        is_match = compiled_rule.name in event.get("trigger", "")
        return {"match": is_match}


def test_replay_engine_all_fire(tmp_path):
    """Test happy path where all expected detections fire."""
    engine = ReplayEngine(rules_dir=str(tmp_path))
    engine.adapter = MockAdapter()
    
    # Create dummy rule
    rule_path = tmp_path / "rule1.yml"
    rule_path.write_text('''
id: det-1
name: rule1
author: test
date: 2024-01-01
description: test
language: sigma
platform: windows
query: test
severity: high
created_at: "2024-01-01T00:00:00Z"
updated_at: "2024-01-01T00:00:00Z"
logsource: {category: process_creation}
detection: {condition: all of them}
''')

    scenario = AttackScenario(
        id="s1", name="Test", technique="T1",
        telemetry=[{"trigger": "rule1"}],
        expected_detections=["det-1"]
    )
    
    result = engine.replay(scenario)
    assert result.status == "PASS"
    assert "det-1" in result.actual_detections
    assert not result.missed_detections


def test_replay_engine_missed_detection(tmp_path):
    """Test failure path where a detection is missed."""
    engine = ReplayEngine(rules_dir=str(tmp_path))
    engine.adapter = MockAdapter()
    
    # Create two dummy rules
    rule1_path = tmp_path / "rule1.yml"
    rule1_path.write_text('''
id: det-1
name: rule1
author: test
date: 2024-01-01
description: test
language: sigma
platform: windows
query: test
severity: high
created_at: "2024-01-01T00:00:00Z"
updated_at: "2024-01-01T00:00:00Z"
logsource: {category: process_creation}
detection: {condition: all of them}
''')
    
    rule2_path = tmp_path / "rule2.yml"
    rule2_path.write_text('''
id: det-2
name: rule2
author: test
date: 2024-01-01
description: test
language: sigma
platform: windows
query: test
severity: high
created_at: "2024-01-01T00:00:00Z"
updated_at: "2024-01-01T00:00:00Z"
logsource: {category: process_creation}
detection: {condition: all of them}
''')

    # Telemetry only triggers rule1, but we expect both
    scenario = AttackScenario(
        id="s1", name="Test", technique="T1",
        telemetry=[{"trigger": "rule1"}],
        expected_detections=["det-1", "det-2"]
    )
    
    result = engine.replay(scenario)
    
    # Assert failure path
    assert result.status == "FAIL"
    assert "det-1" in result.actual_detections
    assert "det-2" in result.missed_detections
    assert len(result.missed_detections) == 1
