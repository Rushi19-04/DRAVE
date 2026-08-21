"""Volume estimation and policy models (Steps 50-52)."""

from typing import Literal
from pydantic import BaseModel


class VolumeEstimate(BaseModel):
    """Result of volume estimation for a detection rule."""
    
    detection_id: str
    sample_size: int
    match_count: int
    match_rate: float
    production_daily_events: int
    estimated_daily_alerts: float


class VolumePolicy(BaseModel):
    """Thresholds for acceptable daily alert volume."""
    
    warning_threshold: int
    failure_threshold: int


class VolumePolicyResult(BaseModel):
    """Result of evaluating a VolumeEstimate against a VolumePolicy."""
    
    status: Literal["PASS", "WARNING", "FAIL", "NO_POLICY"]
    message: str
