"""ATT&CK Coverage Analyzer (Steps 56-57)."""

from pathlib import Path
from pydantic import BaseModel

from core.detection.models import DetectionRule
from core.replay.engine import ReplayEngine
from core.replay.models import AttackScenario
from core.robustness.coverage import CoverageCalculator
import yaml


class AttackCoverageReport(BaseModel):
    """ATT&CK validation metadata for a rule."""
    
    detection_id: str
    declared_techniques: list[str]
    has_unit_tests: bool
    has_attack_scenario: bool
    has_variations: bool
    is_validated: bool


class AttackCoverageAnalyzer:
    """Cross-references declared ATT&CK mappings against verified coverage."""
    
    def analyze(self, rule: DetectionRule) -> AttackCoverageReport:
        if not rule.attack_mappings:
            return AttackCoverageReport(
                detection_id=rule.id,
                declared_techniques=[],
                has_unit_tests=False,
                has_attack_scenario=False,
                has_variations=False,
                is_validated=False
            )
            
        technique = rule.attack_mappings[0]
        
        # 1. Unit Tests
        has_unit = self._check_unit_tests(rule.id, rule)
        
        # 2. Attack Scenario
        has_attack = self._check_attack_scenario(rule.id, technique)
        
        # 3. Variations
        has_variations = self._check_variations(rule, technique)
        
        # Validated = all three checks pass
        is_validated = has_unit and has_attack and has_variations
        
        return AttackCoverageReport(
            detection_id=rule.id,
            declared_techniques=rule.attack_mappings,
            has_unit_tests=has_unit,
            has_attack_scenario=has_attack,
            has_variations=has_variations,
            is_validated=is_validated
        )

    def _check_unit_tests(self, rule_id: str, rule: DetectionRule) -> bool:
        """Find unit tests for this rule and execute them. Must all pass."""
        tests_dir = Path("detections/tests")
        if not tests_dir.exists():
            return False
            
        test_paths = []
        for f in tests_dir.glob("*.yml"):
            try:
                data = yaml.safe_load(Path(f).read_text(encoding="utf-8"))
                if data.get("detection_id") == rule_id:
                    test_paths.append(str(f))
            except Exception:
                pass
                
        if not test_paths:
            return False
            
        from core.testing.runner import run_test
        from core.testing.models import TestCase
        from adapters.sigma.inmemory import SigmaInMemoryAdapter
        
        adapter = SigmaInMemoryAdapter()
        all_pass = True
        
        # Execute them
        for f in test_paths:
            data = yaml.safe_load(Path(f).read_text(encoding="utf-8"))
            test_case = TestCase(**data)
            result = run_test(rule, test_case, adapter)
            if result.status != "PASS":
                all_pass = False
                break
                
        return all_pass

    def _check_attack_scenario(self, rule_id: str, technique: str) -> bool:
        """Find the scenario for this technique and run it. Must PASS."""
        scenarios_dir = Path("detections/scenarios")
        if not scenarios_dir.exists():
            return False
            
        scenario = None
        for f in scenarios_dir.glob("*.yml"):
            try:
                data = yaml.safe_load(Path(f).read_text(encoding="utf-8"))
                if data.get("technique") == technique:
                    # Check if this rule is in expected_detections
                    if rule_id in data.get("expected_detections", []):
                        scenario = AttackScenario(**data)
                        break
            except Exception:
                pass
                
        if not scenario:
            return False
            
        # Load telemetry files into dicts
        import json
        loaded_telemetry = []
        for item in scenario.telemetry:
            if isinstance(item, str):
                path = Path(item)
                if path.exists():
                    loaded_telemetry.append(json.loads(path.read_text(encoding="utf-8")))
            elif isinstance(item, dict):
                loaded_telemetry.append(item)
        scenario.telemetry = loaded_telemetry
            
        engine = ReplayEngine()
        result = engine.replay(scenario)
        return result.status == "PASS"

    def _check_variations(self, rule: DetectionRule, technique: str) -> bool:
        """Find variations for this technique and compute coverage. Must be > 0%."""
        fixtures_base = Path("fixtures")
        if not fixtures_base.exists():
            return False
            
        variation_paths = []
        for tech_dir in fixtures_base.iterdir():
            if not tech_dir.is_dir():
                continue
            meta_path = tech_dir / "metadata.json"
            if meta_path.exists():
                import json
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                    dir_tech = meta.get("technique", "")
                    if dir_tech.startswith(technique) or technique.startswith(dir_tech):
                        for vf in tech_dir.glob("variation_*.json"):
                            variation_paths.append(str(vf))
                        for vf in tech_dir.glob("bypass_*.json"):
                            variation_paths.append(str(vf))
                except Exception:
                    pass
                    
        if not variation_paths:
            return False
            
        calc = CoverageCalculator()
        report = calc.calculate(rule, variation_paths)
        return report.coverage_score > 0.0
