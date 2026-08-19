"""Unit tests for storage."""

import json
from pathlib import Path

from core.testing.models import TestResult
from core.testing.storage import LocalJsonlStorage


def test_local_jsonl_storage_stores_results(tmp_path: Path):
    """Verify that TestResult objects are written as JSON lines."""
    storage = LocalJsonlStorage(directory=str(tmp_path), filename="results.jsonl")

    res1 = TestResult(
        rule_id="rule1",
        test_id="test1",
        timestamp="2025-01-01T00:00:00Z",
        status="PASS"
    )
    res2 = TestResult(
        rule_id="rule1",
        test_id="test2",
        timestamp="2025-01-01T00:00:00Z",
        status="FAIL",
        diagnostics={"error_msg": "Boom"}
    )

    storage.store_result(res1)
    storage.store_result(res2)

    lines = (tmp_path / "results.jsonl").read_text().splitlines()
    assert len(lines) == 2
    
    data1 = json.loads(lines[0])
    assert data1["rule_id"] == "rule1"
    assert data1["test_id"] == "test1"
    assert data1["status"] == "PASS"

    data2 = json.loads(lines[1])
    assert data2["test_id"] == "test2"
    assert data2["status"] == "FAIL"
    assert data2["diagnostics"] == {"error_msg": "Boom"}
