"""Deployment manifest model (Steps 28, 32)."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

DeploymentStatus = Literal[
    "pending",
    "success",
    "failed",
    "rollback_success",
    "rollback_failed"
]

class DeploymentManifest(BaseModel):
    """Manifest tracking a single deployment event."""
    deployment_id: str
    detection_id: str
    git_commit: str
    version: int
    target_siem: str
    timestamp: datetime
    status: DeploymentStatus
    
    # Audit fields for rollback/compliance (Step 32)
    requested_by: str | None = None
    approved_by: str | None = None
    reason: str | None = None
    from_version: int | None = None
    to_version: int | None = None
    test_results_ref: str | None = None
