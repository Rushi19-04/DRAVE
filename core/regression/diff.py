"""Diffing logic for TestResults (Step 34)."""

from typing import Literal
from pydantic import BaseModel
from core.testing.models import TestResult

class RegressionItem(BaseModel):
    test_id: str
    status_change: Literal["REGRESSION", "FIX", "UNCHANGED"]
    baseline_status: str
    current_status: str

class RegressionReport(BaseModel):
    detection_id: str
    total_tests: int
    regressions: int
    fixes: int
    items: list[RegressionItem]

def diff_test_results(detection_id: str, baseline_results: list[TestResult], current_results: list[TestResult]) -> RegressionReport:
    """Compare two sets of test results to identify regressions."""
    baseline_map = {r.test_id: r.status for r in baseline_results}
    current_map = {r.test_id: r.status for r in current_results}
    
    items = []
    regressions = 0
    fixes = 0
    
    # Check all current tests (new tests won't have a baseline, treat baseline as SKIPPED/None)
    all_test_ids = set(baseline_map.keys()) | set(current_map.keys())
    
    for tid in all_test_ids:
        b_status = baseline_map.get(tid, "UNKNOWN")
        c_status = current_map.get(tid, "UNKNOWN")
        
        status_change = "UNCHANGED"
        if b_status == "PASS" and c_status == "FAIL":
            status_change = "REGRESSION"
            regressions += 1
        elif b_status == "FAIL" and c_status == "PASS":
            status_change = "FIX"
            fixes += 1
            
        items.append(RegressionItem(
            test_id=tid,
            status_change=status_change, # type: ignore
            baseline_status=b_status,
            current_status=c_status
        ))
        
    return RegressionReport(
        detection_id=detection_id,
        total_tests=len(all_test_ids),
        regressions=regressions,
        fixes=fixes,
        items=items
    )
