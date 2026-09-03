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
    vol_refs = inventory.volume_fixtures.get(rule.id, [])
    if not vol_refs and rule.attack_mappings:
        vol_refs = inventory.volume_fixtures.get(rule.attack_mappings[0], [])
        
    if vol_refs:
        sample_file = Path(workspace) / vol_refs[0].relative_path
        if sample_file.exists():
            try:
                estimator = VolumeEstimator()
                sample_data = json.loads(sample_file.read_text(encoding="utf-8"))
                if isinstance(sample_data, dict) and "events" in sample_data:
                    sample_data = sample_data["events"]
                elif isinstance(sample_data, dict): 
                    sample_data = [sample_data]
                est_vol = estimator.estimate(rule, sample_data, 1000)
                volume_result = evaluate_volume_policy(rule, est_vol)
            except Exception:
                pass

    # Attack & Variations
    attack_reports = []
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
                attack_reports.append(engine.replay(scenario))
            except Exception:
                pass
                
    var_refs = inventory.variation_fixtures.get(rule.id, [])
    if not var_refs and rule.attack_mappings:
        var_refs = inventory.variation_fixtures.get(rule.attack_mappings[0], [])
        
    v_paths = [str(Path(workspace) / r.relative_path) for r in var_refs]
    if v_paths:
        calc = CoverageCalculator()
        try:
            variation_report = calc.calculate(rule, v_paths)
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
        attack_reports=attack_reports,
        variation_report=variation_report
    )

def load_yaml(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Sync validation results to DRAVE API")
    parser.add_argument("files", nargs="*", help="List of rule files to sync")
    parser.add_argument("--bootstrap", action="store_true", help="Sync all discovered rules")
    args = parser.parse_args()
    
    workspace = os.environ.get("DRAVE_WORKSPACE", ".")
    scanner = RepositoryScanner(workspace)
    inventory = scanner.scan()
    
    rules_to_sync = []
    
    if args.bootstrap:
        rules_to_sync = list(inventory.rules.values())
        print(f"Bootstrap Mode: Syncing all {len(rules_to_sync)} discovered rules...")
    else:
        if not args.files:
            print("Usage: python -m cli.sync <rule_file_path> OR --bootstrap")
            sys.exit(1)
            
        for file_path in args.files:
            p = Path(file_path)
            try:
                rel_path = str(p.resolve().relative_to(Path(workspace).resolve())).replace("\\", "/")
            except ValueError:
                rel_path = str(p).replace("\\", "/")
                
            if rel_path in inventory.rule_paths:
                det_id = inventory.rule_paths[rel_path]
                if det_id in inventory.rules:
                    rules_to_sync.append(inventory.rules[det_id])
            else:
                print(f"Warning: {file_path} is not a valid discovered rule. Skipping sync.")
                
    if not rules_to_sync:
        print("No rules to sync.")
        sys.exit(0)

    for rule in rules_to_sync:
        print(f"Generating real Evidence Report for {rule.id}...")
        evidence = generate_evidence(rule, workspace)

        payload = {
            "rule": json.loads(rule.model_dump_json()),
            "evidence": json.loads(evidence.model_dump_json())
        }
        
        # We wrap the payload matching the backend schema
        api_payload = {
            "rule": payload["rule"],
            "score": evidence.health_score
        }

        api_url = os.environ.get("API_BASE_URL", "http://localhost:8000")
        api_key = os.environ.get("DRAVE_API_KEY")

        if not api_key:
            print(f"DRAVE_API_KEY not set. Would have synced {rule.id}")
            continue

        headers = {
            "X-API-Key": api_key,
            "Content-Type": "application/json"
        }

        try:
            resp = requests.post(f"{api_url}/api/v1/rules", json=api_payload, headers=headers)
            resp.raise_for_status()
            print(f"Successfully synced {rule.id} to DRAVE API.")
        except requests.exceptions.RequestException as e:
            print(f"Failed to sync {rule.id}. Error: {e}")
            if e.response is not None:
                print(f"Response: {e.response.text}")
            sys.exit(1)
