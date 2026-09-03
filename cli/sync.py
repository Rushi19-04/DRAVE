import os
import sys
import json
import yaml
import requests
from pathlib import Path
from core.detection.models import DetectionRule
from core.testing.runner import run_test
from core.testing.models import TestCase
from core.validation.report import generate_report as generate_schema_report
from core.validation.dependencies import extract_dependencies
from core.validation.schema import SchemaProvider
from core.volume.estimator import VolumeEstimator
from core.volume.policies import evaluate_volume_policy
from adapters.sigma.inmemory import SigmaInMemoryAdapter
from core.scoring.evidence import EvidenceBuilder
from core.replay.engine import ReplayEngine
from core.replay.models import AttackScenario
from core.robustness.coverage import CoverageCalculator
from core.discovery.scanner import RepositoryScanner

def generate_evidence(rule: DetectionRule, workspace: str = "."):
    # Run Artifact Discovery
    scanner = RepositoryScanner(workspace)
    inventory = scanner.scan()

    # Syntax & Schema
    adapter = SigmaInMemoryAdapter()
    syntax_valid = True
    schema_report = None
    try:
        compiled = adapter.compile(rule)
        deps = extract_dependencies(compiled)
        schema_fields = SchemaProvider().get_schema_fields(deps.logsource_id)
        schema_report = generate_schema_report(deps, schema_fields)
    except Exception:
        syntax_valid = False

    # Tests
    test_refs = inventory.tests.get(rule.id, [])
    tests_total = len(test_refs)
    tests_passed = 0
    if tests_total > 0 and syntax_valid:
        for ref in test_refs:
            try:
                f = Path(workspace) / ref.relative_path
                tc = TestCase(**load_yaml(str(f)))
                res = run_test(rule, tc, adapter)
                if res.status == "PASS":
                    tests_passed += 1
            except Exception:
                pass

    # Volume
    volume_result = None
    sample_file = Path(workspace) / "fixtures/powershell/attack.json"
    if sample_file.exists():
        try:
            estimator = VolumeEstimator()
            sample_data = json.loads(sample_file.read_text(encoding="utf-8"))
            if isinstance(sample_data, dict): sample_data = [sample_data]
            est_vol = estimator.estimate(rule, sample_data, 1000)
            volume_result = evaluate_volume_policy(rule, est_vol)
        except Exception:
            pass

    # Attack & Variations
    attack_report = None
    variation_report = None
    
    scenario_refs = inventory.scenarios.get(rule.id, [])
    if scenario_refs:
        for ref in scenario_refs:
            try:
                f = Path(workspace) / ref.relative_path
                sd = load_yaml(str(f))
                scenario = AttackScenario(**sd)
                loaded_telemetry = []
                for item in scenario.telemetry:
                    if isinstance(item, str):
                        item_path = Path(workspace) / item
                        if item_path.exists():
                            loaded_telemetry.append(json.loads(item_path.read_text(encoding="utf-8")))
                    elif isinstance(item, dict):
                        loaded_telemetry.append(item)
                scenario.telemetry = loaded_telemetry
                engine = ReplayEngine()
                attack_report = engine.replay(scenario)
                break
            except Exception:
                pass
                
    if rule.attack_mappings:
        technique = rule.attack_mappings[0]
        v_dir = Path(workspace) / f"fixtures/{technique.lower().replace('.', '_')}"
        if not v_dir.exists() and "powershell" in rule.name.lower():
            v_dir = Path(workspace) / "fixtures/powershell"
        if v_dir.exists():
            variation_paths = [str(f) for f in v_dir.glob("*.json")]
            if variation_paths:
                calc = CoverageCalculator()
                try:
                    variation_report = calc.calculate(rule, variation_paths)
                except Exception:
                    pass

    builder = EvidenceBuilder()
    return builder.build(
        rule=rule,
        syntax_valid=syntax_valid,
        tests_total=tests_total,
        tests_passed=tests_passed,
        schema_report=schema_report,
        volume_result=volume_result,
        attack_report=attack_report,
        variation_report=variation_report
    )

def load_yaml(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def sync_rule(rule_path: str):
    api_key = os.environ.get("DRAVE_API_KEY")
    if not api_key:
        print("Error: DRAVE_API_KEY environment variable is not set.")
        sys.exit(1)

    api_base_url = os.environ.get("API_BASE_URL", "http://127.0.0.1:8000")
    
    path = Path(rule_path)
    if not path.exists():
        print(f"Error: Rule file {rule_path} not found.")
        sys.exit(1)

    data = load_yaml(str(path))
    # Ensure missing fields have defaults for MVP parsing
    data["name"] = data.get("title", data.get("name", "Unknown"))
    data["severity"] = data.get("level", data.get("severity", "low"))
    if "tags" in data and "attack_mappings" not in data:
        data["attack_mappings"] = [t.replace("attack.", "").upper() for t in data["tags"] if t.startswith("attack.t")]
    data["language"] = data.get("language", "sigma")
    data["platform"] = data.get("platform", "windows")
    data["author"] = data.get("author", "unknown")
    data["created_at"] = data.get("created_at", data.get("date", "2024-01-01T00:00:00Z"))
    data["updated_at"] = data.get("updated_at", data.get("modified", "2024-01-01T00:00:00Z"))
    if isinstance(data["created_at"], str) and "/" in data["created_at"]:
        data["created_at"] = "2024-01-01T00:00:00Z"

    if "query" not in data:
        data["query"] = path.read_text(encoding="utf-8")

    try:
        rule = DetectionRule(**data)
    except Exception as e:
        print(f"Failed to parse DetectionRule from {rule_path}: {e}")
        sys.exit(1)

    print(f"Generating real Evidence Report for {rule.id}...")
    workspace = os.environ.get("DRAVE_WORKSPACE", ".")
    evidence = generate_evidence(rule, workspace)

    payload = {
        "rule": json.loads(rule.model_dump_json()),
        "score": evidence.health_score,
        "evidence": json.loads(evidence.model_dump_json())
    }

    url = f"{api_base_url}/api/v1/rules"
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json"
    }

    print(f"Syncing {rule.id} to {url}...")
    try:
        resp = requests.post(url, json=payload, headers=headers)
        if resp.status_code in (200, 201):
            print(f"Successfully synced {rule.id}")
            print(resp.json())
        else:
            print(f"Failed to sync {rule.id}. Status {resp.status_code}")
            print(resp.text)
            sys.exit(1)
    except Exception as e:
        print(f"Request failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python cli/sync.py <path_to_rule.yml>")
        sys.exit(1)
    
    rule_path = sys.argv[1]
    sync_rule(rule_path)
