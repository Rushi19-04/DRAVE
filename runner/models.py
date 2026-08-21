"""Runner job definitions (Step 37)."""

from pydantic import BaseModel


class RunnerJob(BaseModel):
    """Job definition sent from DRAVE Cloud to the Customer Runner.
    
    Contains only metadata and pointers — never raw telemetry.
    The runner loads telemetry locally from its own infrastructure.
    """
    job_id: str
    detection_id: str
    rule_path: str
    test_paths: list[str]
    adapter_target: str = "sigma_inmemory"
