import os
import sys
import json
import yaml
import requests
from pathlib import Path
from core.detection.models import DetectionRule

def load_yaml(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def sync_rule(rule_path: str):
    api_key = os.environ.get("DRAVE_API_KEY")
    if not api_key:
        print("Error: DRAVE_API_KEY environment variable is not set.")
        sys.exit(1)

    api_base_url = os.environ.get("API_BASE_URL", "http://127.0.0.1:8000")
    
    path = Path(rule_path)
    if not path.exists():
        print(f"Error: Rule file {rule_path} not found.")
        sys.exit(1)

    data = load_yaml(str(path))
    # Ensure missing fields have defaults for MVP parsing
    data["name"] = data.get("title", data.get("name", "Unknown"))
    data["severity"] = data.get("level", data.get("severity", "low"))
    if "tags" in data and "attack_mappings" not in data:
        data["attack_mappings"] = [t.replace("attack.", "").upper() for t in data["tags"] if t.startswith("attack.t")]
    data["language"] = data.get("language", "sigma")
    data["platform"] = data.get("platform", "windows")
    data["author"] = data.get("author", "unknown")
    data["created_at"] = data.get("created_at", data.get("date", "2024-01-01T00:00:00Z"))
    data["updated_at"] = data.get("updated_at", data.get("modified", "2024-01-01T00:00:00Z"))
    if isinstance(data["created_at"], str) and "/" in data["created_at"]:
        data["created_at"] = "2024-01-01T00:00:00Z"

    if "query" not in data:
        data["query"] = path.read_text(encoding="utf-8")

    try:
        rule = DetectionRule(**data)
    except Exception as e:
        print(f"Failed to parse DetectionRule from {rule_path}: {e}")
        sys.exit(1)

    # Note: In a full implementation, we would extract the real Evidence score here.
    # For this prototype, we assign a perfect score if CI passes.
    score = 1.0

    payload = {
        "rule": json.loads(rule.model_dump_json()),
        "score": score
    }

    url = f"{api_base_url}/api/v1/rules"
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json"
    }

    print(f"Syncing {rule.id} to {url}...")
    try:
        resp = requests.post(url, json=payload, headers=headers)
        if resp.status_code in (200, 201):
            print(f"Successfully synced {rule.id}")
            print(resp.json())
        else:
            print(f"Failed to sync {rule.id}. Status {resp.status_code}")
            print(resp.text)
            sys.exit(1)
    except Exception as e:
        print(f"Request failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python cli/sync.py <path_to_rule.yml>")
        sys.exit(1)
    
    rule_path = sys.argv[1]
    sync_rule(rule_path)
