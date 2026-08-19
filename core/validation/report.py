"""Schema compatibility reporting — Step 16 of the Build Blueprint.

Compares required rule dependencies against available schema fields.
"""

from typing import Literal

from pydantic import BaseModel

from core.validation.dependencies import RuleDependencies


class SchemaCompatibilityReport(BaseModel):
    """The result of comparing a rule's dependencies to a telemetry schema."""

    compatibility_pct: float
    missing_required_fields: list[str]
    missing_optional_fields: list[str]
    risk: Literal["LOW", "MEDIUM", "HIGH"]
    error: str | None = None


def generate_report(
    dependencies: RuleDependencies, available_fields: set[str]
) -> SchemaCompatibilityReport:
    """Calculate compatibility between rule requirements and schema."""

    # If the schema has no fields (maybe missing file), we can't guarantee anything.
    if not available_fields:
        return SchemaCompatibilityReport(
            compatibility_pct=0.0,
            missing_required_fields=list(dependencies.required_fields),
            missing_optional_fields=list(dependencies.optional_fields),
            risk="HIGH",
            error=f"No schema found for log source: {dependencies.logsource_id}",
        )

    # Missing fields
    missing_req = dependencies.required_fields - available_fields
    missing_opt = dependencies.optional_fields - available_fields

    # Compatibility percentage (based strictly on required fields for now)
    total_req = len(dependencies.required_fields)
    if total_req == 0:
        pct = 100.0
    else:
        matched_req = total_req - len(missing_req)
        pct = (matched_req / total_req) * 100.0

    # Risk heuristic:
    # - Missing a required field (in the core condition) -> HIGH risk (blind spot)
    # - Missing an optional field (only in NOT filters) -> MEDIUM risk (will alert, but likely noisy)
    # - 100% match -> LOW risk
    if missing_req:
        risk = "HIGH"
    elif missing_opt:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return SchemaCompatibilityReport(
        compatibility_pct=round(pct, 2),
        missing_required_fields=sorted(list(missing_req)),
        missing_optional_fields=sorted(list(missing_opt)),
        risk=risk,
    )
