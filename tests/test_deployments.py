"""Unit tests for deployment and rollback logic."""

import uuid
from datetime import datetime, timezone
import pytest

from core.versioning.manifest import DeploymentManifest
from core.versioning.lkg import LKGRecord, LKGTracker

def test_deployment_manifest_validation():
    manifest = DeploymentManifest(
        deployment_id=str(uuid.uuid4()),
        detection_id="det-123",
        git_commit="abc1234",
        version=2,
        target_siem="splunk",
        timestamp=datetime.now(timezone.utc),
        status="success"
    )
    assert manifest.version == 2
    assert manifest.status == "success"

def test_lkg_tracker_crud(tmp_path):
    lkg_file = tmp_path / "lkg.json"
    tracker = LKGTracker(storage_path=str(lkg_file))
    
    record = LKGRecord(
        detection_id="det-123",
        current_version=1,
        last_known_good_version=1,
        last_known_good_commit="commit1"
    )
    tracker.update_record(record)
    
    loaded = tracker.get_record("det-123")
    assert loaded is not None
    assert loaded.last_known_good_commit == "commit1"
    
def test_lkg_tracker_missing(tmp_path):
    lkg_file = tmp_path / "lkg.json"
    tracker = LKGTracker(storage_path=str(lkg_file))
    assert tracker.get_record("missing") is None
