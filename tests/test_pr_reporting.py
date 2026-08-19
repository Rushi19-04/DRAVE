"""Unit tests for PR reporting generation."""

from datetime import datetime, timezone
from core.detection.models import DetectionRule
from core.testing.models import TestResult, TestCase, ExpectedResult
from core.validation.report import SchemaCompatibilityReport
from core.versioning.diff import RuleDiff
from core.reporting.pr_comment import generate_pr_comment


def test_generate_pr_comment_full_pass():
    """Verify PR comment generation formats correctly for a passing rule."""
    rule = DetectionRule(
        id="123",
        name="Test Rule",
        description="Desc",
        language="sigma",
        platform="windows",
        query="test",
        severity="low",
        author="test",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    
    schema_report = SchemaCompatibilityReport(
        compatibility_pct=100.0,
        missing_required_fields=[],
        missing_optional_fields=[],
        risk="LOW",
        error=None
    )
    
    test_results = [
        TestResult(
            rule_id="123",
            test_id="t1",
            timestamp="2025-01-01T00:00:00Z",
            status="PASS",
            diagnostics={}
        )
    ]
    
    rule_diff = RuleDiff(
        file_path="rule.yml",
        diff_text="+ new content",
        author="user",
        timestamp=datetime.now(timezone.utc),
        commit_head="123456789",
        commit_base="abcdef123"
    )
    
    md = generate_pr_comment(
        rule=rule,
        schema_report=schema_report,
        test_results=test_results,
        rule_diff=rule_diff,
        reason="bug_fix"
    )
    
    assert "Test Rule" in md
    assert ":white_check_mark: PASS" in md
    assert "+ new content" in md
    assert "`bug_fix`" in md
