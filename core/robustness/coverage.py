"""Variation coverage scoring (Step 47)."""

import json
from pathlib import Path
from dataclasses import dataclass, field

from core.detection.models import DetectionRule
from adapters.sigma.inmemory import SigmaInMemoryAdapter


@dataclass
class VariationResult:
    """Result of running a single variation against a rule."""
    variation_id: str
    variation_path: str
    detected: bool


@dataclass
class CoverageReport:
    """Coverage score and per-variation details."""
    detection_id: str
    total_variations: int
    detected_count: int
    coverage_score: float  # detected_count / total_variations
    results: list[VariationResult] = field(default_factory=list)

    @property
    def failed_variations(self) -> list[str]:
        return [r.variation_id for r in self.results if not r.detected]


class CoverageCalculator:
    """Calculates variation coverage for a detection rule."""

    def __init__(self):
        self.adapter = SigmaInMemoryAdapter()

    def calculate(self, rule: DetectionRule, variation_paths: list[str]) -> CoverageReport:
        """Run each variation fixture through the rule and compute coverage."""
        compiled = self.adapter.compile(rule)
        results = []

        for vp in variation_paths:
            path = Path(vp)
            variation_id = path.stem  # e.g. "variation_01"
            event = json.loads(path.read_text(encoding="utf-8"))

            exec_result = self.adapter.execute(compiled, event)
            detected = isinstance(exec_result, dict) and exec_result.get("match") is True

            results.append(VariationResult(
                variation_id=variation_id,
                variation_path=vp,
                detected=detected
            ))

        total = len(results)
        detected_count = sum(1 for r in results if r.detected)
        score = detected_count / total if total > 0 else 0.0

        return CoverageReport(
            detection_id=rule.id,
            total_variations=total,
            detected_count=detected_count,
            coverage_score=score,
            results=results
        )
