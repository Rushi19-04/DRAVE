"""Regression baseline management (Step 35).

Separate from LKG tracking: LKG tracks the last successfully *deployed* version.
The regression baseline tracks which version's test results are the comparison
target for regression detection. These can diverge — a rule can pass all tests
on a feature branch (updating the regression baseline) without having been
deployed yet (LKG unchanged).
"""

import json
from pathlib import Path
from pydantic import BaseModel


class BaselineRecord(BaseModel):
    """Tracks the regression baseline for a single detection."""
    detection_id: str
    baseline_version: int
    baseline_commit: str


class BaselineTracker:
    """Manages regression baseline pointers in a JSON file."""

    def __init__(self, storage_path: str = "deployments/regression_baselines.json"):
        self.path = Path(storage_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("{}")

    def _load(self) -> dict[str, dict]:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _save(self, data: dict[str, dict]) -> None:
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def get_baseline(self, detection_id: str) -> BaselineRecord | None:
        data = self._load()
        if detection_id in data:
            return BaselineRecord(**data[detection_id])
        return None

    def update_baseline(self, record: BaselineRecord) -> None:
        data = self._load()
        data[record.detection_id] = record.model_dump()
        self._save(data)
