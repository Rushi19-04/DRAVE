"""DRAVE Test Case and Test Result models — Steps 3 and 20 of the Build Blueprint."""

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel


class TestType(str, Enum):
    """Types of tests DRAVE can run against a detection rule."""

    positive = "positive"
    negative = "negative"
    edge = "edge"
    regression = "regression"
    attack = "attack"


class ExpectedResult(BaseModel):
    """Assertions for a test case — Step 7."""

    alert: bool
    min_matches: int | None = None
    max_matches: int | None = None
    severity: str | None = None


class TestCase(BaseModel):
    """A single test case for a detection rule.

    Fields match the blueprint Step 3 specification:
    test_id, detection_id, type, input_telemetry, expected.
    """

    test_id: str
    detection_id: str
    type: TestType
    input_telemetry: dict[str, Any] | list[dict[str, Any]]
    expected: ExpectedResult
    ground_truth: Literal["true_positive", "false_positive"] | None = None


class TestResult(BaseModel):
    """Structured result of running a test case — Step 20.

    Status is one of PASS, FAIL, ERROR, SKIPPED plus
    diagnostic information for debugging.
    """

    rule_id: str
    test_id: str
    timestamp: str
    status: Literal["PASS", "FAIL", "ERROR", "SKIPPED"]
    diagnostics: dict[str, Any] = {}
    true_positive: int = 0
    false_positive: int = 0
    unknown: int = 0
