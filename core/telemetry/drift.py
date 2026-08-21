"""Schema drift detection (Step 41)."""

import json
from pathlib import Path


class SchemaDriftDetector:
    """Detects schema field changes between runner executions."""
    
    def __init__(self, storage_path: str = "deployments/schema_snapshots.json"):
        self.path = Path(storage_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("{}")
            
    def _load(self) -> dict[str, list[str]]:
        return json.loads(self.path.read_text(encoding="utf-8"))
        
    def _save(self, data: dict[str, list[str]]) -> None:
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    
    def store_snapshot(self, detection_id: str, fields: list[str]) -> None:
        """Save the current schema field set for a detection."""
        data = self._load()
        data[detection_id] = sorted(fields)
        self._save(data)
        
    def detect_drift(self, detection_id: str, current_fields: list[str]) -> list[str]:
        """Compare current fields against the stored snapshot.
        
        Returns a list of drift descriptions. Empty list means no drift.
        """
        data = self._load()
        if detection_id not in data:
            return []
            
        stored = set(data[detection_id])
        current = set(current_fields)
        
        drifts = []
        removed = stored - current
        added = current - stored
        
        for f in sorted(removed):
            drifts.append(f"REMOVED: field '{f}' no longer present")
        for f in sorted(added):
            drifts.append(f"ADDED: new field '{f}' detected")
            
        return drifts
