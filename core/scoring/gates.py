"""Hard Gates logic — Step 60 of the Build Blueprint.

Evaluates strict pass/fail gates that block deployment regardless of health score.
"""

from typing import Any
from pydantic import BaseModel

from core.detection.models import DetectionRule
from core.validation.report import SchemaCompatibilityReport
from core.volume.policies import VolumePolicyResult
from core.replay.models import AttackResult


class GateResult(BaseModel):
    """The result of evaluating a single rule against the deployment hard gates."""
    
    syntax_valid: bool
    all_required_tests_pass: bool
    no_known_attack_missed: bool
    no_critical_schema_incompatibility: bool
    volume_within_policy: bool
    
    passed_all_gates: bool
    

class GateEvaluator:
    """Evaluates hard gates for a rule based on sub-engine outputs."""

    def evaluate(
        self,
        syntax_valid: bool,
        tests_passed: bool,  # Simplified input from TestRunner
        attack_reports: list[AttackResult] | None,
        schema_report: SchemaCompatibilityReport | None,
        volume_result: VolumePolicyResult | None
    ) -> GateResult:
        """Evaluate the 5 hard gates."""
        
        # 1. Syntax
        gate_syntax = syntax_valid
        
        # 2. Unit Tests
        gate_tests = tests_passed
        
        # 3. Attack Replay (No known attack missed across ALL scenarios)
        gate_attack = True
        if attack_reports:
            for rep in attack_reports:
                if rep.missed_detections:
                    gate_attack = False
                    break
                
        # 4. Schema Compatibility (No Risk == HIGH)
        gate_schema = True
        if schema_report and schema_report.risk == "HIGH":
            gate_schema = False
            
        # 5. Volume Policy (Not FAIL)
        gate_volume = True
        if volume_result and volume_result.status == "FAIL":
            gate_volume = False
            
        passed_all = (
            gate_syntax and 
            gate_tests and 
            gate_attack and 
            gate_schema and 
            gate_volume
        )
        
        return GateResult(
            syntax_valid=gate_syntax,
            all_required_tests_pass=gate_tests,
            no_known_attack_missed=gate_attack,
            no_critical_schema_incompatibility=gate_schema,
            volume_within_policy=gate_volume,
            passed_all_gates=passed_all
        )
