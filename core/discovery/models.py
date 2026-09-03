"""Discovery models for decoupled artifact resolution."""

from pydantic import BaseModel
from typing import Dict, List, Any

from core.detection.models import DetectionRule

class ArtifactReference(BaseModel):
    """A portable reference to an artifact inside the customer repository."""
    id: str
    relative_path: str

class DiscoveryError(BaseModel):
    """Represents an error encountered during artifact discovery."""
    relative_path: str
    error_type: str  # e.g., "invalid_schema", "unreadable", "unsupported"
    message: str

class RuleInventory(BaseModel):
    """The structured state of the repository."""
    rules: Dict[str, DetectionRule] = {}
    rule_paths: Dict[str, str] = {}  # relative_path -> detection_id
    tests: Dict[str, List[ArtifactReference]] = {}
    scenarios: Dict[str, List[ArtifactReference]] = {}
    volume_fixtures: Dict[str, List[ArtifactReference]] = {}  # detection_id or technique -> list
    variation_fixtures: Dict[str, List[ArtifactReference]] = {} # detection_id or technique -> list
    errors: List[DiscoveryError] = []
