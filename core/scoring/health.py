"""Health Score logic — Step 59 of the Build Blueprint.

Evaluates the overall quality of a rule across 6 dimensions.
"""

from core.validation.report import SchemaCompatibilityReport
from core.volume.policies import VolumePolicyResult
from core.replay.models import AttackResult
from core.robustness.coverage import CoverageReport
from core.regression.diff import RegressionReport


class HealthCalculator:
    """Computes a 0-100 numerical health score based on weighted dimensions."""

    def calculate(
        self,
        tests_total: int,
        tests_passed: int,
        regression_report: RegressionReport | None,
        attack_report: AttackResult | None,
        variation_report: CoverageReport | None,
        schema_report: SchemaCompatibilityReport | None,
        volume_result: VolumePolicyResult | None
    ) -> float:
        """Calculate the overall health score using defined weights.
        
        Weights:
        - Unit Test Pass Rate: 25%
        - Regression Stability: 15%
        - Attack Replay Pass Rate: 15%
        - Variation/Robustness Coverage: 20%
        - Schema Compatibility %: 15%
        - Volume Health: 10%
        """
        score = 0.0
        applicable_weight = 0.0
        
        # 1. Unit Test Pass Rate (25%)
        if tests_total > 0:
            score += (tests_passed / tests_total) * 25.0
            applicable_weight += 25.0
            
        # 2. Regression Stability (15%)
        if regression_report and regression_report.total_tests > 0:
            stability_pct = (regression_report.total_tests - regression_report.regressions) / regression_report.total_tests
            score += stability_pct * 15.0
            applicable_weight += 15.0
            
        # 3. Attack Replay Pass Rate (15%)
        if attack_report and attack_report.expected_detections:
            expected = len(attack_report.expected_detections)
            missed = len(attack_report.missed_detections)
            attack_pct = (expected - missed) / expected
            score += attack_pct * 15.0
            applicable_weight += 15.0
            
        # 4. Variation/Robustness Coverage (20%)
        if variation_report and variation_report.total_variations > 0:
            score += (variation_report.coverage_score) * 20.0
            applicable_weight += 20.0
            
        # 5. Schema Compatibility (15%)
        if schema_report:
            score += (schema_report.compatibility_pct / 100.0) * 15.0
            applicable_weight += 15.0
            
        # 6. Volume Health (10%)
        if volume_result:
            applicable_weight += 10.0
            if volume_result.status == "PASS":
                score += 10.0
            elif volume_result.status == "WARNING":
                score += 5.0
                
        # Scale the score back to 100 based on the applicable weight
        if applicable_weight == 0.0:
            return 0.0
            
        scaled_score = (score / applicable_weight) * 100.0
        return round(scaled_score, 2)
