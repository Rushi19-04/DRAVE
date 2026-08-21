"""Robustness matrix (Step 48)."""

import json
from dataclasses import dataclass, field
from rich.table import Table

from core.robustness.coverage import CoverageReport


@dataclass
class MatrixEntry:
    detection_id: str
    variation_id: str
    result: str  # "PASS" or "FAIL"


class RobustnessMatrix:
    """Builds a detection × variation → PASS/FAIL grid."""

    def __init__(self):
        self.entries: list[MatrixEntry] = []

    def add_report(self, report: CoverageReport) -> None:
        """Populate matrix entries from a CoverageReport."""
        for vr in report.results:
            self.entries.append(MatrixEntry(
                detection_id=report.detection_id,
                variation_id=vr.variation_id,
                result="PASS" if vr.detected else "FAIL"
            ))

    def render_table(self, detection_id: str) -> Table:
        """Render a rich Table for a single detection's variations."""
        table = Table(title=f"Robustness Matrix: {detection_id}", show_lines=True)
        table.add_column("Variation", style="cyan")
        table.add_column("Result", style="magenta")

        for entry in self.entries:
            if entry.detection_id == detection_id:
                color = "green" if entry.result == "PASS" else "red"
                table.add_row(entry.variation_id, f"[{color}]{entry.result}[/{color}]")

        return table

    def to_json(self) -> str:
        """JSON representation for dashboard consumption."""
        data = [
            {"detection_id": e.detection_id, "variation_id": e.variation_id, "result": e.result}
            for e in self.entries
        ]
        return json.dumps(data, indent=2)
