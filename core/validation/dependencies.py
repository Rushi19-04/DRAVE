"""Rule dependency extraction — Step 14 of the Build Blueprint.

Extracts the required log source and fields from a parsed SigmaRule.
"""

from dataclasses import dataclass
from typing import Any

from sigma.conditions import ConditionNOT
from sigma.rule import SigmaRule


@dataclass
class RuleDependencies:
    """The telemetry dependencies required by a DetectionRule."""

    logsource_id: str
    required_fields: set[str]
    # Fields that appear only inside a NOT condition, implying they are optional filters
    optional_fields: set[str]


def extract_dependencies(rule: SigmaRule) -> RuleDependencies:
    """Walk a parsed Sigma rule and extract its required fields."""

    # 1. Determine the log source ID (e.g. "windows_process_creation")
    parts = []
    if rule.logsource.product:
        parts.append(rule.logsource.product)
    if rule.logsource.category:
        parts.append(rule.logsource.category)
    if rule.logsource.service:
        parts.append(rule.logsource.service)

    logsource_id = "_".join(parts).lower()

    # 2. Extract fields from the AST
    required_fields: set[str] = set()
    optional_fields: set[str] = set()

    for condition in rule.detection.parsed_condition:
        _extract_fields_from_node(
            condition.parsed,
            is_negated=False,
            required_acc=required_fields,
            optional_acc=optional_fields,
        )

    # A field might appear in both a required and optional context
    # If it's required anywhere, it's not strictly optional
    optional_fields = optional_fields - required_fields

    return RuleDependencies(
        logsource_id=logsource_id,
        required_fields=required_fields,
        optional_fields=optional_fields,
    )


def _extract_fields_from_node(
    node: Any, is_negated: bool, required_acc: set[str], optional_acc: set[str]
) -> None:
    """Recursively walk the pySigma AST to find field references."""

    if isinstance(node, ConditionNOT):
        # Everything underneath this NOT is considered an optional filter
        for arg in node.args:
            _extract_fields_from_node(arg, True, required_acc, optional_acc)
        return

    # If it has args, recurse
    if hasattr(node, "args"):
        for arg in node.args:
            _extract_fields_from_node(arg, is_negated, required_acc, optional_acc)

    # If it's a leaf node with a field, record it
    if hasattr(node, "field") and node.field is not None:
        if is_negated:
            optional_acc.add(node.field)
        else:
            required_acc.add(node.field)
