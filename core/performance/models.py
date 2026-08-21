"""Performance metrics and thresholds (Steps 54-55)."""

from pydantic import BaseModel


class PerformanceMetrics(BaseModel):
    """Execution performance metrics for a detection rule."""
    
    detection_id: str
    run_duration_ms: float
    scan_count: int | None = None


class PerformanceThresholds(BaseModel):
    """Configurable thresholds for acceptable performance.
    
    Note: Real performance gating requires Phase L's Splunk adapter and its 
    actual query-cost metrics (scan_count, bytes_scanned). The in-memory 
    adapter timing measures Python dict traversal, not real query cost, so 
    these thresholds are placeholders and currently unenforced.
    """
    
    max_run_duration_ms: float
