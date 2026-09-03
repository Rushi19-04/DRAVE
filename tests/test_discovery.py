import tempfile
import yaml
import json
from pathlib import Path
from core.discovery.scanner import RepositoryScanner
from core.discovery.models import RuleInventory, ArtifactReference
from core.scoring.gates import GateEvaluator, GateResult
from core.replay.models import AttackResult

def test_discovery_scanner_full():
    with tempfile.TemporaryDirectory() as temp_dir:
        workspace = Path(temp_dir)
        
        # 1. Valid Rules
        r1 = workspace / "rules/rule1.yml"
        r1.parent.mkdir(parents=True, exist_ok=True)
        yaml.dump({
            "id": "det-1", "name": "Rule 1", "logsource": {"category": "test"}, 
            "detection": {"condition": "selection"}, "attack_mappings": ["T1059"]
        }, open(r1, "w"))
        
        r2 = workspace / "other_dir/rule2.yml"
        r2.parent.mkdir(parents=True, exist_ok=True)
        yaml.dump({
            "id": "det-2", "name": "Rule 2", "logsource": {"category": "test"}, 
            "detection": {"condition": "selection"}
        }, open(r2, "w"))

        # 2. Invalid Rules (Schema error)
        r_invalid = workspace / "rules/invalid.yml"
        # attack_mappings expects a list, giving an int will fail Pydantic validation
        yaml.dump({"id": "det-3", "logsource": {}, "detection": {}, "attack_mappings": 123}, open(r_invalid, "w"))
        
        # Unreadable file
        r_unreadable = workspace / "rules/bad.json"
        with open(r_unreadable, "w") as f:
            f.write('{ "id": "det-3", bad json ')

        # 3. Test Cases
        t1 = workspace / "tests/test1.yml"
        t1.parent.mkdir(parents=True, exist_ok=True)
        yaml.dump({"test_id": "test-1", "detection_id": "det-1", "input_telemetry": []}, open(t1, "w"))

        # 4. Attack Scenarios (Multiple)
        s1 = workspace / "scenarios/scen1.yaml"
        s1.parent.mkdir(parents=True, exist_ok=True)
        yaml.dump({"name": "scen-1", "technique": "T1059", "expected_detections": ["det-1"], "telemetry": []}, open(s1, "w"))
        
        s2 = workspace / "scenarios/scen2.yaml"
        yaml.dump({"name": "scen-2", "technique": "T1059", "expected_detections": ["det-1"], "telemetry": []}, open(s2, "w"))

        # 5. Schema-Aware Fixtures
        # Volume fixture explicit detection_id
        v1 = workspace / "weird/vol1.json"
        v1.parent.mkdir(parents=True, exist_ok=True)
        json.dump({"fixture_type": "volume", "detection_id": "det-1", "events": []}, open(v1, "w"))
        
        # Variation fixture by technique
        v2 = workspace / "weird/var1.json"
        json.dump({"fixture_type": "variation", "technique": "T1059", "events": []}, open(v2, "w"))
        
        # Unsupported fixture (missing both detection_id and technique)
        v3 = workspace / "weird/bad_fix.json"
        json.dump({"fixture_type": "volume", "events": []}, open(v3, "w"))

        # Initialize Scanner
        scanner = RepositoryScanner(workspace_path=str(workspace))
        inventory = scanner.scan()
        
        # Verify Bootstrap/Rule Discovery
        assert "det-1" in inventory.rules
        assert "det-2" in inventory.rules
        assert len(inventory.rules) == 2
        
        # Verify Incremental Mapping
        r1_rel = str(r1.relative_to(workspace)).replace("\\", "/")
        r2_rel = str(r2.relative_to(workspace)).replace("\\", "/")
        assert inventory.rule_paths[r1_rel] == "det-1"
        assert inventory.rule_paths[r2_rel] == "det-2"
        
        # Verify Fixture Classification
        assert "det-1" in inventory.volume_fixtures
        assert len(inventory.volume_fixtures["det-1"]) == 1
        assert inventory.volume_fixtures["det-1"][0].relative_path == "weird/vol1.json"
        
        assert "T1059" in inventory.variation_fixtures
        assert len(inventory.variation_fixtures["T1059"]) == 1
        assert inventory.variation_fixtures["T1059"][0].relative_path == "weird/var1.json"
        
        # Verify Multiple Scenarios
        assert len(inventory.scenarios["det-1"]) == 2
        
        # Verify Errors
        err_paths = [e.relative_path for e in inventory.errors]
        assert "rules/invalid.yml" in err_paths  # schema failure
        assert "rules/bad.json" in err_paths    # unreadable
        assert "weird/bad_fix.json" in err_paths # unsupported fixture

def test_scenario_aggregation_gates():
    evaluator = GateEvaluator()
    
    # 1. Both scenarios pass
    report1 = AttackResult(
        scenario_id="scen-1", scenario_name="Scen 1", technique="T1059",
        expected_detections=["det-1"], actual_detections=["det-1"], missed_detections=[],
        detection_latency_ms=100.0, status="PASS"
    )
    report2 = AttackResult(
        scenario_id="scen-2", scenario_name="Scen 2", technique="T1059",
        expected_detections=["det-1"], actual_detections=["det-1"], missed_detections=[],
        detection_latency_ms=100.0, status="PASS"
    )
    
    res_pass = evaluator.evaluate(
        syntax_valid=True, tests_passed=True, attack_reports=[report1, report2],
        schema_report=None, volume_result=None
    )
    assert res_pass.no_known_attack_missed is True
    assert res_pass.passed_all_gates is True
    
    # 2. One scenario fails
    report3 = AttackResult(
        scenario_id="scen-3", scenario_name="Scen 3", technique="T1059",
        expected_detections=["det-1"], actual_detections=[], missed_detections=["det-1"],
        detection_latency_ms=0.0, status="FAIL"
    )
    res_fail = evaluator.evaluate(
        syntax_valid=True, tests_passed=True, attack_reports=[report1, report3],
        schema_report=None, volume_result=None
    )
    assert res_fail.no_known_attack_missed is False
    assert res_fail.passed_all_gates is False

def test_incremental_resolver():
    from core.discovery.incremental import IncrementalResolver
    from core.discovery.diff import ChangedFile, DiffRange
    from core.detection.models import DetectionRule
    
    inventory = RuleInventory()
    inventory.rules["rule-1"] = DetectionRule.model_construct(id="rule-1", name="R1", attack_mappings=[])
    inventory.rules["rule-2"] = DetectionRule.model_construct(id="rule-2", name="R2", attack_mappings=[])
    inventory.rule_paths["rules/rule1.yml"] = "rule-1"
    inventory.rule_paths["rules/rule2.yml"] = "rule-2"
    
    inventory.tests["rule-1"] = [ArtifactReference(id="t1", relative_path="tests/t1.yml")]
    inventory.scenarios["rule-2"] = [ArtifactReference(id="s1", relative_path="scenarios/s1.yml")]
    inventory.volume_fixtures["rule-1"] = [ArtifactReference(id="v1", relative_path="fixtures/v1.json")]
    
    # Mock diff provider that only returns content for a deleted test
    class MockDiffProvider:
        def get_file_content_at_commit(self, path, commit):
            if path == "tests/deleted_test.yml":
                return '{"test_id": "t2", "detection_id": "rule-2"}'
            return None
            
    resolver = IncrementalResolver(inventory, MockDiffProvider())
    diff_range = DiffRange(before="123", after="456")
    
    # 1. Rule changed -> 1 rule
    res = resolver.resolve(diff_range, [ChangedFile(path="rules/rule1.yml", status="M")])
    assert res == {"rule-1"}
    
    # 2. Test changed -> associated rule
    res = resolver.resolve(diff_range, [ChangedFile(path="tests/t1.yml", status="A")])
    assert res == {"rule-1"}
    
    # 3. Scenario changed -> all expected rules
    res = resolver.resolve(diff_range, [ChangedFile(path="scenarios/s1.yml", status="M")])
    assert res == {"rule-2"}
    
    # 4. Fixture changed -> associated rule
    res = resolver.resolve(diff_range, [ChangedFile(path="fixtures/v1.json", status="M")])
    assert res == {"rule-1"}
    
    # 5. README modified -> 0 rules
    res = resolver.resolve(diff_range, [ChangedFile(path="README.md", status="M")])
    assert res == set()
    
    # 6. Two rules modified -> 2 rules
    res = resolver.resolve(diff_range, [
        ChangedFile(path="rules/rule1.yml", status="M"),
        ChangedFile(path="rules/rule2.yml", status="M")
    ])
    assert res == {"rule-1", "rule-2"}
    
    # 7. Deleted test -> associated rule still resolved
    res = resolver.resolve(diff_range, [ChangedFile(path="tests/deleted_test.yml", status="D")])
    assert res == {"rule-2"}
