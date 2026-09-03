"""Discovery models for decoupled artifact resolution."""

from pydantic import BaseModel
from typing import Dict, List, Any

from core.detection.models import DetectionRule

class ArtifactReference(BaseModel):
    """A portable reference to a supporting artifact, relative to the workspace."""
    id: str
    relative_path: str

class RuleInventory(BaseModel):
    """The structured state of the repository."""
    rules: Dict[str, DetectionRule] = {}
    tests: Dict[str, List[ArtifactReference]] = {}
    scenarios: Dict[str, List[ArtifactReference]] = {}
    fixtures: Dict[str, List[ArtifactReference]] = {}
