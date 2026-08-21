"""Unit tests for regression engine."""

from core.regression.diff import diff_test_results
from core.testing.models import TestResult

def test_diff_test_results_regression():
    b_results = [
        TestResult(rule_id="r1", test_id="t1", timestamp="ts", status="PASS", diagnostics={}),
        TestResult(rule_id="r1", test_id="t2", timestamp="ts", status="FAIL", diagnostics={}),
    ]
    c_results = [
        TestResult(rule_id="r1", test_id="t1", timestamp="ts", status="FAIL", diagnostics={}), # REGRESSION
        TestResult(rule_id="r1", test_id="t2", timestamp="ts", status="PASS", diagnostics={}), # FIX
    ]
    
    report = diff_test_results("r1", b_results, c_results)
    assert report.total_tests == 2
    assert report.regressions == 1
    assert report.fixes == 1
    
    t1_item = next(i for i in report.items if i.test_id == "t1")
    assert t1_item.status_change == "REGRESSION"
    
    t2_item = next(i for i in report.items if i.test_id == "t2")
    assert t2_item.status_change == "FIX"

def test_diff_test_results_new_test():
    b_results = [
        TestResult(rule_id="r1", test_id="t1", timestamp="ts", status="PASS", diagnostics={}),
    ]
    c_results = [
        TestResult(rule_id="r1", test_id="t1", timestamp="ts", status="PASS", diagnostics={}),
        TestResult(rule_id="r1", test_id="t_new", timestamp="ts", status="PASS", diagnostics={}),
    ]
    
    report = diff_test_results("r1", b_results, c_results)
    assert report.total_tests == 2
    assert report.regressions == 0
    t_new = next(i for i in report.items if i.test_id == "t_new")
    assert t_new.status_change == "UNCHANGED"
    assert t_new.baseline_status == "UNKNOWN"

def test_baseline_tracker_crud(tmp_path):
    from core.regression.baseline import BaselineTracker, BaselineRecord
    tracker = BaselineTracker(storage_path=str(tmp_path / "baselines.json"))
    
    record = BaselineRecord(
        detection_id="det-123",
        baseline_version=1,
        baseline_commit="abc123"
    )
    tracker.update_baseline(record)
    
    loaded = tracker.get_baseline("det-123")
    assert loaded is not None
    assert loaded.baseline_commit == "abc123"
    assert loaded.baseline_version == 1

def test_baseline_tracker_missing(tmp_path):
    from core.regression.baseline import BaselineTracker
    tracker = BaselineTracker(storage_path=str(tmp_path / "baselines.json"))
    assert tracker.get_baseline("missing") is None


def test_resolve_baseline_commit_uses_baseline_when_set(tmp_path):
    """When an explicit regression baseline exists, resolve_baseline_commit returns it."""
    from core.regression.runner import RegressionRunner
    from core.regression.baseline import BaselineTracker, BaselineRecord
    from core.versioning.lkg import LKGTracker, LKGRecord

    runner = RegressionRunner()
    runner.baseline_tracker = BaselineTracker(storage_path=str(tmp_path / "baselines.json"))
    runner.lkg_tracker = LKGTracker(storage_path=str(tmp_path / "lkg.json"))

    # Set both baseline AND LKG
    runner.baseline_tracker.update_baseline(BaselineRecord(
        detection_id="det-1", baseline_version=3, baseline_commit="baseline_commit_abc"
    ))
    runner.lkg_tracker.update_record(LKGRecord(
        detection_id="det-1", current_version=2,
        last_known_good_version=2, last_known_good_commit="lkg_commit_xyz"
    ))

    # Should prefer the explicit baseline, not the LKG
    result = runner.resolve_baseline_commit("det-1")
    assert result == "baseline_commit_abc"


def test_resolve_baseline_commit_falls_back_to_lkg(tmp_path):
    """When no explicit regression baseline exists, resolve_baseline_commit falls back to LKG."""
    from core.regression.runner import RegressionRunner
    from core.regression.baseline import BaselineTracker
    from core.versioning.lkg import LKGTracker, LKGRecord

    runner = RegressionRunner()
    runner.baseline_tracker = BaselineTracker(storage_path=str(tmp_path / "baselines.json"))
    runner.lkg_tracker = LKGTracker(storage_path=str(tmp_path / "lkg.json"))

    # Set LKG only — no baseline
    runner.lkg_tracker.update_record(LKGRecord(
        detection_id="det-1", current_version=2,
        last_known_good_version=2, last_known_good_commit="lkg_commit_xyz"
    ))

    result = runner.resolve_baseline_commit("det-1")
    assert result == "lkg_commit_xyz"


def test_resolve_baseline_commit_raises_when_neither_set(tmp_path):
    """When neither baseline nor LKG exists, resolve_baseline_commit raises ValueError."""
    import pytest
    from core.regression.runner import RegressionRunner
    from core.regression.baseline import BaselineTracker
    from core.versioning.lkg import LKGTracker

    runner = RegressionRunner()
    runner.baseline_tracker = BaselineTracker(storage_path=str(tmp_path / "baselines.json"))
    runner.lkg_tracker = LKGTracker(storage_path=str(tmp_path / "lkg.json"))

    with pytest.raises(ValueError, match="No regression baseline or LKG commit found"):
        runner.resolve_baseline_commit("det-missing")
