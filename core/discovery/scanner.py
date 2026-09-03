"""Scanner for recursive, path-agnostic artifact discovery."""

from pathlib import Path
from typing import List
import yaml

from core.discovery.models import RuleInventory, ArtifactReference
from core.detection.models import DetectionRule

class RepositoryScanner:
    """Recursively discovers and classifies DRAVE artifacts."""

    def __init__(self, workspace_path: str, exclusions: List[str] = None):
        self.workspace = Path(workspace_path).resolve()
        self.exclusions = exclusions or [".git", ".venv", "__pycache__", "node_modules", "saas"]

    def _should_exclude(self, path: Path) -> bool:
        """Check if a path should be excluded."""
        for part in path.parts:
            if part in self.exclusions:
                return True
        return False

    def scan(self) -> RuleInventory:
        """Scan the workspace and build the inventory."""
        inventory = RuleInventory()

        for file_path in self.workspace.rglob("*"):
            if not file_path.is_file() or self._should_exclude(file_path):
                continue

            if file_path.suffix not in [".yml", ".yaml", ".json"]:
                continue

            try:
                # Basic check before full parse
                content = file_path.read_text(encoding="utf-8")
                
                # Simple heuristic to avoid parsing massive unrelated JSON files
                if '"id"' not in content and "id:" not in content and "detection_id" not in content and "technique" not in content:
                    continue

                if file_path.suffix == ".json":
                    import json
                    data = json.loads(content)
                else:
                    data = yaml.safe_load(content)

                if not isinstance(data, dict):
                    continue

                rel_path = str(file_path.relative_to(self.workspace)).replace("\\", "/")

                # Classify Artifact
                if "logsource" in data and "detection" in data and "id" in data:
                    # Detection Rule
                    data["query"] = content # The engine expects query to be the yaml text
                    data["name"] = data.get("title", data.get("name", "Unknown"))
                    data["description"] = data.get("description", "No description provided")
                    data["severity"] = data.get("level", data.get("severity", "low"))
                    if "tags" in data and "attack_mappings" not in data:
                        data["attack_mappings"] = [t.replace("attack.", "").upper() for t in data["tags"] if t.startswith("attack.t")]
                    data["language"] = data.get("language", "sigma")
                    data["platform"] = data.get("platform", "windows")
                    data["author"] = data.get("author", "unknown")
                    data["created_at"] = data.get("created_at", data.get("date", "2024-01-01T00:00:00Z"))
                    data["updated_at"] = data.get("updated_at", data.get("modified", "2024-01-01T00:00:00Z"))
                    # Make sure they are strings if they are date objects from yaml
                    if not isinstance(data["created_at"], str):
                        data["created_at"] = str(data["created_at"]) + "T00:00:00Z"
                    if not isinstance(data["updated_at"], str):
                        data["updated_at"] = str(data["updated_at"]) + "T00:00:00Z"
                    if isinstance(data["created_at"], str) and "/" in data["created_at"]:
                        data["created_at"] = "2024-01-01T00:00:00Z"
                        
                    try:
                        rule = DetectionRule(**data)
                        inventory.rules[rule.id] = rule
                    except Exception as e:
                        pass # Ignore invalid rules

                elif "test_id" in data and "input_telemetry" in data and "detection_id" in data:
                    # Test Case
                    det_id = data["detection_id"]
                    ref = ArtifactReference(id=data["test_id"], relative_path=rel_path)
                    if det_id not in inventory.tests:
                        inventory.tests[det_id] = []
                    inventory.tests[det_id].append(ref)

                elif "technique" in data and "expected_detections" in data:
                    # Attack Scenario
                    ref = ArtifactReference(id=data.get("name", "scenario"), relative_path=rel_path)
                    for det_id in data["expected_detections"]:
                        if det_id not in inventory.scenarios:
                            inventory.scenarios[det_id] = []
                        inventory.scenarios[det_id].append(ref)

            except Exception:
                # Silently skip unparseable or irrelevant files
                continue

        return inventory
