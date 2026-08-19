"""Unit tests for versioning parsing and diffing."""

from core.versioning.pr_parser import parse_pr_reason

def test_parse_pr_reason_bug_fix():
    body = "- [x] `bug_fix`: Fixing something"
    assert parse_pr_reason(body) == "bug_fix"

def test_parse_pr_reason_unknown():
    body = "- [ ] `bug_fix`: empty"
    assert parse_pr_reason(body) == "unknown"

def test_parse_pr_reason_different_casing():
    body = "* [X] `performance`: Better"
    assert parse_pr_reason(body) == "performance"
