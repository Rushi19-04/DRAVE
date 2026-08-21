"""Runner result definitions (Steps 37, 38).

CRITICAL PRIVACY BOUNDARY: RunnerResult must NEVER contain raw telemetry.
Only structured test results and schema metadata flow back to DRAVE Cloud.
This is enforced by the model's field definitions and tested explicitly.
"""

from pydantic import BaseModel
from core.testing.models import TestResult


class SchemaSnapshot(BaseModel):
    """Schema field snapshot captured during a runner execution."""
    detection_id: str
    fields: list[str]


class RunnerResult(BaseModel):
    """Structured output sent from Customer Runner back to DRAVE Cloud.
    
    PRIVACY CONTRACT: This model intentionally has no field for raw telemetry,
    event data, or log content. Only test pass/fail results and schema metadata
    are transmitted. Any attempt to add a telemetry field here must be rejected
    in code review.
    """
    job_id: str
    detection_id: str
    test_results: list[TestResult]
    schema_snapshot: SchemaSnapshot | None = None
    drift_detected: bool = False
    drift_details: list[str] = []
    status: str  # "success", "error"
    error_message: str | None = None
