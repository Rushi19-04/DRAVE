"""Tests for DRAVE core data models (DetectionRule, TestCase, TestResult)."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from core.detection.models import DetectionRule
from core.testing.models import TestCase, TestResult, TestType


class TestDetectionRuleModel:
    """Verify DetectionRule Pydantic model validation."""

    def test_valid_detection_rule(self) -> None:
        rule = DetectionRule(
            id="DET-001",
            name="Encoded PowerShell",
            description="Detects base64-encoded PowerShell execution",
            language="sigma",
            platform="windows",
            query="title: Encoded PowerShell",
            severity="high",
            author="alice",
            created_at=datetime(2025, 1, 1, tzinfo=UTC),
            updated_at=datetime(2025, 6, 1, tzinfo=UTC),
            attack_mappings=["T1059.001"],
        )
        assert rule.id == "DET-001"
        assert rule.language == "sigma"
        assert rule.attack_mappings == ["T1059.001"]

    def test_attack_mappings_defaults_empty(self) -> None:
        rule = DetectionRule(
            id="DET-002",
            name="Test Rule",
            description="Desc",
            language="sigma",
            platform="windows",
            query="title: Test",
            severity="medium",
            author="bob",
            created_at=datetime(2025, 1, 1, tzinfo=UTC),
            updated_at=datetime(2025, 1, 1, tzinfo=UTC),
        )
        assert rule.attack_mappings == []

    def test_missing_required_field_raises(self) -> None:
        with pytest.raises(ValidationError):
            DetectionRule(
                id="DET-003",
                name="Incomplete",
                # missing description, language, platform, query, severity, author, timestamps
            )


class TestTestCaseModel:
    """Verify TestCase Pydantic model validation."""

    def test_valid_positive_test(self) -> None:
        tc = TestCase(
            test_id="TC-001",
            detection_id="DET-001",
            type=TestType.positive,
            input_telemetry={"Image": "powershell.exe", "CommandLine": "-enc abc"},
            expected={"alert": True, "min_matches": 1},
        )
        assert tc.type == TestType.positive
        assert tc.expected.alert is True

    def test_valid_negative_test(self) -> None:
        tc = TestCase(
            test_id="TC-002",
            detection_id="DET-001",
            type=TestType.negative,
            input_telemetry={"Image": "notepad.exe"},
            expected={"alert": False},
        )
        assert tc.type == TestType.negative

    def test_all_test_types(self) -> None:
        for tt in TestType:
            tc = TestCase(
                test_id=f"TC-{tt.value}",
                detection_id="DET-001",
                type=tt,
                input_telemetry={},
                expected={"alert": False},
            )
            assert tc.type == tt

    def test_invalid_test_type_raises(self) -> None:
        with pytest.raises(ValidationError):
            TestCase(
                test_id="TC-BAD",
                detection_id="DET-001",
                type="invalid_type",
                input_telemetry={},
                expected={},
            )


class TestTestResultModel:
    """Verify TestResult Pydantic model validation."""

    def test_pass_result(self) -> None:
        tr = TestResult(
            rule_id="r1", test_id="t1", timestamp="2025-01-01T00:00:00Z", status="PASS"
        )
        assert tr.status == "PASS"
        assert tr.diagnostics == {}

    def test_fail_result_with_diagnostics(self) -> None:
        tr = TestResult(
            rule_id="r1",
            test_id="t1",
            timestamp="2025-01-01T00:00:00Z",
            status="FAIL",
            diagnostics={
                "expected": {"alert": True},
                "actual": {"alert": False},
                "message": "Detection did not fire",
            },
        )
        assert tr.status == "FAIL"
        assert tr.diagnostics["expected"]["alert"] is True
        assert tr.diagnostics["message"] == "Detection did not fire"

    def test_all_valid_statuses(self) -> None:
        for status in ("PASS", "FAIL", "ERROR", "SKIPPED"):
            tr = TestResult(
                rule_id="r1", test_id="t1", timestamp="2025-01-01T00:00:00Z", status=status
            )
            assert tr.status == status

    def test_invalid_status_raises(self) -> None:
        with pytest.raises(ValidationError):
            TestResult(
                rule_id="r1", test_id="t1", timestamp="2025-01-01T00:00:00Z", status="INVALID"
            )
