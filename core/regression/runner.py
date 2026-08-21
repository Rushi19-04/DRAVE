"""Regression test runner (Step 33)."""

from pathlib import Path
from core.detection.models import DetectionRule
from core.testing.models import TestCase, TestResult
from core.testing.runner import run_test
from core.versioning.git_utils import extract_yaml_from_commit
from core.versioning.lkg import LKGTracker
from core.regression.baseline import BaselineTracker
from adapters.sigma.inmemory import SigmaInMemoryAdapter


class RegressionRunner:
    """Dynamically evaluates current and baseline rules against the current test corpus."""
    
    def __init__(self, repo_path: str = "."):
        self.repo_path = repo_path
        self.baseline_tracker = BaselineTracker()
        self.lkg_tracker = LKGTracker()
        self.adapter = SigmaInMemoryAdapter()
        
    def resolve_baseline_commit(self, detection_id: str) -> str:
        """Determine which commit to use as the regression baseline.
        
        Prefers an explicit regression baseline; falls back to LKG.
        Raises ValueError if neither is available.
        """
        baseline_rec = self.baseline_tracker.get_baseline(detection_id)
        if baseline_rec:
            return baseline_rec.baseline_commit
        
        lkg_rec = self.lkg_tracker.get_record(detection_id)
        if not lkg_rec or not lkg_rec.last_known_good_commit:
            raise ValueError(f"No regression baseline or LKG commit found for {detection_id}.")
        return lkg_rec.last_known_good_commit
        
    def run_regression_suite(self, rule: DetectionRule, rule_path: str, tests_dir: str = "detections/tests") -> tuple[list[TestResult], list[TestResult]]:
        """Run the test corpus against the baseline rule and the current rule.
        
        Uses the regression baseline commit if one is set; otherwise falls back
        to the LKG commit. This distinction matters: a regression baseline can
        advance on a feature branch before anything is deployed (LKG unchanged).
        """
        
        baseline_commit = self.resolve_baseline_commit(rule.id)
        
        # 1. Extract Baseline Rule
        baseline_rule_data = extract_yaml_from_commit(self.repo_path, baseline_commit, rule_path)
        baseline_rule = DetectionRule(**baseline_rule_data)
        
        baseline_results = []
        current_results = []
        
        import ruamel.yaml
        yaml = ruamel.yaml.YAML(typ="safe")
        
        # 2. Iterate all CURRENT tests for this detection
        for test_file in Path(tests_dir).glob("*.yml"):
            data = yaml.load(test_file.read_text(encoding="utf-8"))
            test_case = TestCase(**data)
            
            if test_case.detection_id != rule.id:
                continue
                
            # Evaluate against Baseline Rule
            b_res = run_test(baseline_rule, test_case, self.adapter)
            baseline_results.append(b_res)
            
            # Evaluate against Current Rule
            c_res = run_test(rule, test_case, self.adapter)
            current_results.append(c_res)
            
        return baseline_results, current_results
