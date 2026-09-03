import yaml
import json
from pathlib import Path
from typing import Set, List
from core.discovery.models import RuleInventory
from core.discovery.diff import ChangedFile, GitDiffProvider, DiffRange

class IncrementalResolver:
    def __init__(self, inventory: RuleInventory, diff_provider: GitDiffProvider):
        self.inventory = inventory
        self.diff_provider = diff_provider

    def resolve(self, diff_range: DiffRange, changed_files: List[ChangedFile]) -> Set[str]:
        affected_ids = set()

        for f in changed_files:
            rel_path = f.path.replace("\\", "/")
            
            # If renamed, also consider the old path just in case
            paths_to_check = [rel_path]
            if f.previous_path:
                paths_to_check.append(f.previous_path.replace("\\", "/"))
                
            for path in paths_to_check:
                # 1. Rule changed
                if path in self.inventory.rule_paths:
                    affected_ids.add(self.inventory.rule_paths[path])
                    continue
                    
                # 2. Test changed
                for det_id, refs in self.inventory.tests.items():
                    if any(ref.relative_path == path for ref in refs):
                        affected_ids.add(det_id)
                        
                # 3. Scenario changed
                for det_id, refs in self.inventory.scenarios.items():
                    if any(ref.relative_path == path for ref in refs):
                        affected_ids.add(det_id)
                        
                # 4. Volume Fixture changed
                for key, refs in self.inventory.volume_fixtures.items():
                    if any(ref.relative_path == path for ref in refs):
                        self._add_fixture_affected(key, affected_ids)
                        
                # 5. Variation Fixture changed
                for key, refs in self.inventory.variation_fixtures.items():
                    if any(ref.relative_path == path for ref in refs):
                        self._add_fixture_affected(key, affected_ids)

                # 6. Deletion handling (if D and not found in current inventory)
                if f.status == 'D' or f.status == 'R':
                    self._resolve_deleted(diff_range.before, path, affected_ids)

        # Deduplicate and ensure the rules still exist in the current inventory
        return {id for id in affected_ids if id in self.inventory.rules}
        
    def _add_fixture_affected(self, key: str, affected_ids: Set[str]):
        """Key could be a detection_id or a technique."""
        if key in self.inventory.rules:
            affected_ids.add(key)
        else:
            # It's a technique, find all rules with this technique
            for rule in self.inventory.rules.values():
                if rule.attack_mappings:
                    for t in rule.attack_mappings:
                        if key.startswith(t) or t.startswith(key):
                            affected_ids.add(rule.id)
                            break

    def _resolve_deleted(self, before_sha: str, path: str, affected_ids: Set[str]):
        """Parse the old content to see what it was attached to."""
        content = self.diff_provider.get_file_content_at_commit(path, before_sha)
        if not content:
            return
            
        try:
            if path.endswith(".json"):
                data = json.loads(content)
            else:
                data = yaml.safe_load(content)
                
            if not isinstance(data, dict):
                return
                
            # Is it a rule? (If rule is deleted, we handled it above by intersecting with current inventory)
            
            # Is it a test?
            if "test_id" in data and "detection_id" in data:
                affected_ids.add(data["detection_id"])
                
            # Is it a scenario?
            if "technique" in data and "expected_detections" in data:
                for det_id in data["expected_detections"]:
                    affected_ids.add(det_id)
                    
            # Is it a fixture?
            if "fixture_type" in data:
                det_id = data.get("detection_id")
                tech = data.get("technique")
                if det_id:
                    self._add_fixture_affected(det_id, affected_ids)
                elif tech:
                    self._add_fixture_affected(tech, affected_ids)
                    
        except Exception:
            pass
