"""Last-Known-Good tracking (Step 30)."""

import json
from pathlib import Path
from pydantic import BaseModel

class LKGRecord(BaseModel):
    """Tracks version history pointers for a single detection."""
    detection_id: str
    current_version: int
    last_deployed_version: int | None = None
    last_known_good_version: int | None = None
    last_known_good_commit: str | None = None

class LKGTracker:
    """Manages LKG records in a JSON file."""
    
    def __init__(self, storage_path: str = "deployments/lkg_pointers.json"):
        self.path = Path(storage_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("{}")
            
    def _load(self) -> dict[str, dict]:
        return json.loads(self.path.read_text(encoding="utf-8"))
        
    def _save(self, data: dict[str, dict]) -> None:
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        
    def get_record(self, detection_id: str) -> LKGRecord | None:
        data = self._load()
        if detection_id in data:
            return LKGRecord(**data[detection_id])
        return None
        
    def update_record(self, record: LKGRecord) -> None:
        data = self._load()
        data[record.detection_id] = record.model_dump()
        self._save(data)
