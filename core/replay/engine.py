"""Attack Replay engine (Step 44).

Loads an AttackScenario, runs its telemetry through each expected detection's
rule via the in-memory adapter, and reports which detections fired and which
were missed.
"""

import time
from pathlib import Path
import ruamel.yaml

from core.detection.models import DetectionRule
from core.replay.models import AttackScenario, AttackResult
from adapters.sigma.inmemory import SigmaInMemoryAdapter


class ReplayEngine:
    """Replays attack scenarios against detection rules."""
    
    def __init__(self, rules_dir: str = "detections/rules"):
        self.rules_dir = Path(rules_dir)
        self.adapter = SigmaInMemoryAdapter()
        self.yaml = ruamel.yaml.YAML(typ="safe")
        
    def _load_rule_by_id(self, detection_id: str) -> DetectionRule | None:
        """Find and load a detection rule by its ID."""
        for rf in self.rules_dir.glob("*.yml"):
            data = self.yaml.load(rf.read_text(encoding="utf-8"))
            if data and data.get("id") == detection_id:
                return DetectionRule(**data)
        return None
        
    def replay(self, scenario: AttackScenario) -> AttackResult:
        """Replay an attack scenario and determine which detections fire."""
        
        actual_detections = []
        
        start_time = time.perf_counter()
        
        for det_id in scenario.expected_detections:
            rule = self._load_rule_by_id(det_id)
            if not rule:
                # Detection doesn't exist — it's missed by definition
                continue
                
            # Compile the rule and test each telemetry event
            compiled = self.adapter.compile(rule)
            fired = False
            
            for event in scenario.telemetry:
                exec_result = self.adapter.execute(compiled, event)
                if isinstance(exec_result, dict) and exec_result.get("match") is True:
                    fired = True
                    break
                    
            if fired:
                actual_detections.append(det_id)
                
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        
        missed = [d for d in scenario.expected_detections if d not in actual_detections]
        
        # PASS/FAIL: any missed detection = FAIL, period.
        status = "FAIL" if missed else "PASS"
        
        return AttackResult(
            scenario_id=scenario.id,
            scenario_name=scenario.name,
            technique=scenario.technique,
            expected_detections=scenario.expected_detections,
            actual_detections=actual_detections,
            missed_detections=missed,
            detection_latency_ms=round(elapsed_ms, 2),
            status=status
        )
