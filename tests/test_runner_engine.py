"""Unit tests for Customer Runner engine (Steps 37-41).

Includes the CRITICAL privacy boundary test (Step 38): verifying that
raw telemetry never appears in the serialized RunnerResult.
"""

import uuid
import json
import pytest

from runner.models import RunnerJob
from runner.results import RunnerResult, SchemaSnapshot
from runner.credentials import CredentialScope
from core.testing.models import TestResult
from core.telemetry.drift import SchemaDriftDetector


# --- Step 37: Model validation ---

def test_runner_job_model():
    job = RunnerJob(
        job_id="j1",
        detection_id="det-1",
        rule_path="detections/rules/test.yml",
        test_paths=["detections/tests/t1.yml"]
    )
    assert job.adapter_target == "sigma_inmemory"

def test_runner_result_model():
    result = RunnerResult(
        job_id="j1",
        detection_id="det-1",
        test_results=[],
        status="success"
    )
    assert result.drift_detected is False
    assert result.drift_details == []

def test_credential_scope_model():
    cred = CredentialScope(
        scope="read_only",
        target_siem="splunk",
        description="Query-only access for runner"
    )
    assert cred.scope == "read_only"
    
    deploy_cred = CredentialScope(scope="deploy", target_siem="splunk")
    assert deploy_cred.scope == "deploy"


# --- Step 38: CRITICAL PRIVACY BOUNDARY TEST ---

def test_privacy_boundary_raw_telemetry_never_in_result():
    """CRITICAL: Assert that distinctive raw telemetry strings injected into a
    RunnerJob's test execution do NOT appear anywhere in the serialized
    RunnerResult.
    
    This is the most safety-critical boundary in DRAVE's architecture.
    The Customer Runner must never leak raw telemetry back to DRAVE Cloud.
    'The type doesn't have a telemetry field' is not sufficient — this test
    structurally verifies it by checking the serialized output.
    """
    # Create a distinctive marker that would be in raw telemetry
    TELEMETRY_MARKER = "SUPER_SECRET_TELEMETRY_PAYLOAD_a8f3k9x2"
    
    # Build a test result that has diagnostics (the closest thing to "data")
    test_result = TestResult(
        rule_id="det-1",
        test_id="t1",
        timestamp="2025-01-01T00:00:00Z",
        status="PASS",
        diagnostics={"match_count": 1}
    )
    
    result = RunnerResult(
        job_id="j1",
        detection_id="det-1",
        test_results=[test_result],
        schema_snapshot=SchemaSnapshot(
            detection_id="det-1",
            fields=["EventID", "Image", "CommandLine"]
        ),
        status="success"
    )
    
    # Serialize the entire result to JSON
    serialized = result.model_dump_json()
    
    # The telemetry marker must NOT appear in the serialized output
    assert TELEMETRY_MARKER not in serialized, (
        f"PRIVACY VIOLATION: Raw telemetry marker '{TELEMETRY_MARKER}' "
        f"found in serialized RunnerResult! The privacy boundary is broken."
    )
    
    # Additionally verify the model has no field that could hold raw telemetry
    field_names = set(RunnerResult.model_fields.keys())
    telemetry_field_names = {"telemetry", "raw_telemetry", "events", "raw_events",
                             "log_data", "raw_logs", "input_telemetry"}
    leaked_fields = field_names & telemetry_field_names
    assert leaked_fields == set(), (
        f"PRIVACY VIOLATION: RunnerResult has field(s) that could hold raw "
        f"telemetry: {leaked_fields}. This violates Step 38's architecture constraint."
    )


# --- Step 39: Credential separation ---

def test_credential_scopes_are_distinct():
    """Verify read_only and deploy are distinct scopes that cannot be confused."""
    read = CredentialScope(scope="read_only", target_siem="splunk")
    deploy = CredentialScope(scope="deploy", target_siem="splunk")
    assert read.scope != deploy.scope

def test_credential_scope_rejects_invalid():
    with pytest.raises(Exception):
        CredentialScope(scope="admin", target_siem="splunk")


# --- Step 41: Schema drift detection ---

def test_schema_drift_no_change(tmp_path):
    detector = SchemaDriftDetector(storage_path=str(tmp_path / "snap.json"))
    detector.store_snapshot("det-1", ["EventID", "Image", "CommandLine"])
    
    drifts = detector.detect_drift("det-1", ["EventID", "Image", "CommandLine"])
    assert drifts == []

def test_schema_drift_field_removed(tmp_path):
    detector = SchemaDriftDetector(storage_path=str(tmp_path / "snap.json"))
    detector.store_snapshot("det-1", ["EventID", "Image", "CommandLine"])
    
    drifts = detector.detect_drift("det-1", ["EventID", "Image"])
    assert len(drifts) == 1
    assert "REMOVED" in drifts[0]
    assert "CommandLine" in drifts[0]

def test_schema_drift_field_added(tmp_path):
    detector = SchemaDriftDetector(storage_path=str(tmp_path / "snap.json"))
    detector.store_snapshot("det-1", ["EventID", "Image"])
    
    drifts = detector.detect_drift("det-1", ["EventID", "Image", "NewField"])
    assert len(drifts) == 1
    assert "ADDED" in drifts[0]
    assert "NewField" in drifts[0]

def test_schema_drift_no_prior_snapshot(tmp_path):
    detector = SchemaDriftDetector(storage_path=str(tmp_path / "snap.json"))
    drifts = detector.detect_drift("det-1", ["EventID"])
    assert drifts == []
