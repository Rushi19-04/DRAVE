import tempfile
import yaml
import json
from pathlib import Path
from core.discovery.scanner import RepositoryScanner
from core.discovery.models import RuleInventory, ArtifactReference

def test_discovery_scanner():
    with tempfile.TemporaryDirectory() as temp_dir:
        workspace = Path(temp_dir)
        
        # 1. Create a Detection Rule
        rule_path = workspace / "detections" / "rule1.yml"
        rule_path.parent.mkdir(parents=True, exist_ok=True)
        rule_content = {
            "id": "det-1",
            "name": "Test Rule",
            "logsource": {"category": "test"},
            "detection": {"condition": "selection"},
            "severity": "high",
            "author": "DRAVE",
            "platform": "windows"
        }
        with open(rule_path, "w") as f:
            yaml.dump(rule_content, f)
            
        # 2. Create a Test Case in a weird directory
        test_path = workspace / "weird_customer_dir" / "test1.yml"
        test_path.parent.mkdir(parents=True, exist_ok=True)
        test_content = {
            "test_id": "test-1",
            "detection_id": "det-1",
            "input_telemetry": []
        }
        with open(test_path, "w") as f:
            yaml.dump(test_content, f)
            
        # 3. Create an Attack Scenario
        scenario_path = workspace / "scenarios" / "scen1.yaml"
        scenario_path.parent.mkdir(parents=True, exist_ok=True)
        scenario_content = {
            "name": "scen-1",
            "technique": "T1033",
            "expected_detections": ["det-1"],
            "telemetry": []
        }
        with open(scenario_path, "w") as f:
            yaml.dump(scenario_content, f)
            
        # Initialize Scanner
        scanner = RepositoryScanner(workspace_path=str(workspace))
        inventory = scanner.scan()
        
        assert "det-1" in inventory.rules
        assert inventory.rules["det-1"].name == "Test Rule"
        
        assert "det-1" in inventory.tests
        assert len(inventory.tests["det-1"]) == 1
        test_ref = inventory.tests["det-1"][0]
        assert test_ref.id == "test-1"
        assert test_ref.relative_path == "weird_customer_dir/test1.yml"
        
        assert "det-1" in inventory.scenarios
        assert len(inventory.scenarios["det-1"]) == 1
        scen_ref = inventory.scenarios["det-1"][0]
        assert scen_ref.id == "scen-1"
        assert scen_ref.relative_path == "scenarios/scen1.yaml"
        
        print("Discovery tests passed!")
