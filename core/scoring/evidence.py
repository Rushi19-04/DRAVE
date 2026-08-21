"""Evidence Report — Step 58 of the Build Blueprint.

Aggregates outputs from every prior phase into one Pydantic model.
"""

from typing import Any
from pydantic import BaseModel

from core.detection.models import DetectionRule
from core.validation.report import SchemaCompatibilityReport
from core.volume.policies import VolumePolicyResult
from core.replay.models import AttackResult
from core.robustness.coverage import CoverageReport
from core.regression.diff import RegressionReport
from core.scoring.gates import GateResult, GateEvaluator
from core.scoring.health import HealthCalculator


class EvidenceReport(BaseModel):
    """The final aggregated report for a detection rule."""
    
    detection_id: str
    rule_name: str
    
    # Dual-system outputs
    health_score: float
    gates: GateResult
    
    # Sub-engine summaries
    tests_total: int
    tests_passed: int
    
    schema_risk: str | None
    schema_compatibility_pct: float | None
    
    volume_status: str | None
    volume_message: str | None
    
    attack_expected: int | None
    attack_missed: int | None
    
    robustness_score: float | None
    
    regression_total: int | None
    regressions_found: int | None
    
    def render_markdown(self) -> str:
        """Render the evidence report as a Markdown string."""
        color = "🟢" if self.gates.passed_all_gates else "🔴"
        status_text = "CLEARED" if self.gates.passed_all_gates else "BLOCKED"
        
        md = [
            f"## {color} Evidence Report: {self.rule_name} (`{self.detection_id}`)",
            f"**Status:** {status_text} | **Health Score:** {self.health_score}/100",
            "",
            "### Hard Gates",
            f"- **Syntax Valid:** {'✅' if self.gates.syntax_valid else '❌'}",
            f"- **Tests Passing:** {'✅' if self.gates.all_required_tests_pass else '❌'}",
            f"- **No Known Attack Missed:** {'✅' if self.gates.no_known_attack_missed else '❌'}",
            f"- **Schema Risk LOW/MED:** {'✅' if self.gates.no_critical_schema_incompatibility else '❌'}",
            f"- **Volume Within Policy:** {'✅' if self.gates.volume_within_policy else '❌'}",
            "",
            "### Metrics Breakdown",
            f"- **Unit Tests:** {self.tests_passed}/{self.tests_total} passed",
            f"- **Schema Compatibility:** {self.schema_compatibility_pct}% (Risk: {self.schema_risk or 'N/A'})",
        ]
        
        if self.volume_status:
            md.append(f"- **Volume Status:** {self.volume_status} ({self.volume_message})")
        
        if self.attack_expected is not None:
            md.append(f"- **Attack Replay:** Expected {self.attack_expected}, Missed {self.attack_missed}")
            
        if self.robustness_score is not None:
            md.append(f"- **Variation Coverage:** {self.robustness_score * 100}%")
            
        if self.regression_total is not None:
            md.append(f"- **Regressions:** {self.regressions_found} regressions found across {self.regression_total} baseline tests")
            
        return "\n".join(md)


class EvidenceBuilder:
    """Constructs an EvidenceReport from component inputs."""
    
    def build(
        self,
        rule: DetectionRule,
        syntax_valid: bool,
        tests_total: int,
        tests_passed: int,
        regression_report: RegressionReport | None = None,
        attack_report: AttackResult | None = None,
        variation_report: CoverageReport | None = None,
        schema_report: SchemaCompatibilityReport | None = None,
        volume_result: VolumePolicyResult | None = None
    ) -> EvidenceReport:
        """Evaluate gates, calculate health, and construct the report."""
        
        gate_evaluator = GateEvaluator()
        gates = gate_evaluator.evaluate(
            syntax_valid=syntax_valid,
            tests_passed=(tests_passed == tests_total and tests_total > 0),
            attack_report=attack_report,
            schema_report=schema_report,
            volume_result=volume_result
        )
        
        health_calc = HealthCalculator()
        health_score = health_calc.calculate(
            tests_total=tests_total,
            tests_passed=tests_passed,
            regression_report=regression_report,
            attack_report=attack_report,
            variation_report=variation_report,
            schema_report=schema_report,
            volume_result=volume_result
        )
        
        return EvidenceReport(
            detection_id=rule.id,
            rule_name=rule.name,
            health_score=health_score,
            gates=gates,
            tests_total=tests_total,
            tests_passed=tests_passed,
            schema_risk=schema_report.risk if schema_report else None,
            schema_compatibility_pct=schema_report.compatibility_pct if schema_report else None,
            volume_status=volume_result.status if volume_result else None,
            volume_message=volume_result.message if volume_result else None,
            attack_expected=len(attack_report.expected_detections) if attack_report and attack_report.expected_detections else None,
            attack_missed=len(attack_report.missed_detections) if attack_report and attack_report.missed_detections else None,
            robustness_score=variation_report.coverage_score if variation_report else None,
            regression_total=regression_report.total_tests if regression_report else None,
            regressions_found=regression_report.regressions if regression_report else None
        )
