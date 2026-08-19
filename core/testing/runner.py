"""DRAVE Test Runner — Step 8 of the Build Blueprint.

Orchestrates the evaluation of a single TestCase against a DetectionRule
using a specific DetectionAdapter, and compares actual vs. expected results.
"""

from datetime import datetime, timezone

from core.detection.adapter import DetectionAdapter
from core.detection.models import DetectionRule
from core.testing.models import TestCase, TestResult


def run_test(
    rule: DetectionRule, test: TestCase, adapter: DetectionAdapter
) -> TestResult:
    """Run a single test case and return the structured result."""
    now = datetime.now(timezone.utc).isoformat()
    try:
        compiled = adapter.compile(rule)
    except Exception as e:  # noqa: BLE001
        return TestResult(
            rule_id=rule.id,
            test_id=test.test_id,
            timestamp=now,
            status="ERROR",
            diagnostics={"error": f"Failed to compile rule: {e}"},
        )

    try:
        events = test.input_telemetry if isinstance(test.input_telemetry, list) else [test.input_telemetry]
        match_count = 0
        for event in events:
            raw_actual = adapter.execute(compiled, event)
            normalized = adapter.normalize_result(raw_actual)
            if normalized.get("match", False):
                match_count += 1
    except Exception as e:  # noqa: BLE001
        return TestResult(
            rule_id=rule.id,
            test_id=test.test_id,
            timestamp=now,
            status="ERROR",
            diagnostics={"error": f"Failed to execute test: {e}"},
        )

    expected_alert = test.expected.alert
    is_match = match_count > 0

    diagnostics = {
        "expected": test.expected.model_dump(exclude_none=True),
        "actual": {"alert": is_match, "match_count": match_count},
    }

    status = "PASS"
    error_msgs = []

    if is_match != expected_alert:
        status = "FAIL"
        error_msgs.append(f"Expected alert={expected_alert}, but got {is_match}")
    
    if test.expected.min_matches is not None and match_count < test.expected.min_matches:
        status = "FAIL"
        error_msgs.append(f"Expected min_matches={test.expected.min_matches}, got {match_count}")

    if test.expected.max_matches is not None and match_count > test.expected.max_matches:
        status = "FAIL"
        error_msgs.append(f"Expected max_matches={test.expected.max_matches}, got {match_count}")

    if error_msgs:
        diagnostics["error_msg"] = "; ".join(error_msgs)
        
    return TestResult(
        rule_id=rule.id,
        test_id=test.test_id,
        timestamp=now,
        status=status,
        diagnostics=diagnostics
    )
