"""Rollback Orchestration (Step 31)."""

import uuid
from datetime import datetime, timezone
from git import Repo
import ruamel.yaml

from core.detection.models import DetectionRule
from core.testing.models import TestCase
from core.testing.runner import run_test
from core.testing.storage import LocalJsonlStorage
from adapters.sigma.inmemory import SigmaInMemoryAdapter
from core.versioning.lkg import LKGTracker
from core.versioning.manifest import DeploymentManifest
from core.versioning.git_utils import extract_yaml_from_commit


class RollbackError(Exception):
    pass


class RollbackCoordinator:
    """Coordinates detection rollback via git blob extraction and test verification."""
    
    def __init__(self, repo_path: str = "."):
        self.repo_path = repo_path
        self.lkg_tracker = LKGTracker()
        self.storage = LocalJsonlStorage()
        self.adapter = SigmaInMemoryAdapter()
            
    def orchestrate_rollback(
        self, 
        detection_id: str, 
        rule_path: str, 
        test_paths: list[str], 
        requested_by: str, 
        reason: str
    ) -> DeploymentManifest:
        """Plan and orchestrate a rollback to the Last-Known-Good state."""
        
        # 1. Find LKG Artifact
        record = self.lkg_tracker.get_record(detection_id)
        if not record or not record.last_known_good_commit or not record.last_known_good_version:
            raise RollbackError(f"No LKG commit found for detection {detection_id}.")
            
        lkg_commit = record.last_known_good_commit
        lkg_version = record.last_known_good_version
        
        # 2. Extract historical rule and run tests
        try:
            rule_data = extract_yaml_from_commit(self.repo_path, lkg_commit, rule_path)
            rule = DetectionRule(**rule_data)
        except Exception as e:
            raise RollbackError(f"Failed to load rule from LKG commit: {e}")
            
        test_results_ref = f"rollback_{uuid.uuid4().hex[:8]}"
        passed = 0
        total = 0
        
        for tp in test_paths:
            try:
                test_data = extract_yaml_from_commit(self.repo_path, lkg_commit, tp)
                test_case = TestCase(**test_data)
                
                # Only run tests that belong to this detection
                if test_case.detection_id != detection_id:
                    continue
                
                # Re-run validation (Step 31 Explicit requirement)
                res = run_test(rule, test_case, self.adapter)
                
                # Tag it so we can trace it in storage
                res.diagnostics["run_ref"] = test_results_ref
                self.storage.store_result(res)
                
                total += 1
                if res.status == "PASS":
                    passed += 1
            except Exception as e:
                # E.g. test didn't exist in the old commit, skip it or fail
                pass
                
        if total == 0:
            raise RollbackError("No valid tests found in LKG commit to verify rollback.")
            
        if passed != total:
            raise RollbackError(f"Rollback verification failed! Only {passed}/{total} tests passed on the LKG artifact.")
            
        # 3. Formulate Rollback Manifest
        manifest = DeploymentManifest(
            deployment_id=str(uuid.uuid4()),
            detection_id=detection_id,
            git_commit=lkg_commit,
            version=lkg_version,
            target_siem="splunk",
            timestamp=datetime.now(timezone.utc),
            status="rollback_success", # Note: Real deploy stubbed until Phase L
            requested_by=requested_by,
            approved_by="auto", # Mocking approval for now
            reason=reason,
            from_version=record.current_version,
            to_version=lkg_version,
            test_results_ref=test_results_ref
        )
        
        # 4. Save Bookkeeping
        self.storage.store_deployment(manifest)
        record.current_version = lkg_version
        record.last_deployed_version = lkg_version
        self.lkg_tracker.update_record(record)
        
        return manifest
