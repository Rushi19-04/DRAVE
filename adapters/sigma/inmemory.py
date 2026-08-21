"""DRAVE In-Memory Sigma Adapter — Step 10 of the Build Blueprint.

A custom pySigma-based adapter that evaluates parsed Sigma rule condition
trees directly against JSON telemetry dicts in Python — no live SIEM needed.

This is what lets Phase A/B run entirely offline against fixtures.
Real SIEM query compilation (pySigma-backend-splunk, etc.) is deferred
to Phase L (Step 65).
"""

from __future__ import annotations

import re
from typing import Any

import yaml
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule
from sigma.types import SigmaNumber, SigmaString

from core.detection.adapter import DetectionAdapter
from core.detection.models import DetectionRule


class SigmaInMemoryAdapter(DetectionAdapter):
    """Evaluate Sigma rules against telemetry events in pure Python.

    Pipeline:
        1. validate() — parse with pySigma, catch syntax errors
        2. compile() — parse rule YAML into a SigmaRule + parsed condition tree
        3. execute() — walk the condition tree, matching each node against the event dict
        4. normalize_result() — return {"match": bool, "details": ...}
    """

    # ── DetectionAdapter interface ──────────────────────────────────

    def validate(self, rule: DetectionRule) -> bool:
        """Return True if the Sigma YAML parses without errors."""
        try:
            SigmaRule.from_yaml(rule.query)
            return True
        except (SigmaError, yaml.YAMLError):
            return False

    def compile(self, rule: DetectionRule) -> SigmaRule:
        """Parse the Sigma YAML into a ``SigmaRule`` object."""
        return SigmaRule.from_yaml(rule.query)

    def execute(self, compiled: SigmaRule, telemetry: dict[str, Any]) -> dict[str, Any]:
        """Evaluate the compiled Sigma rule against a single event dict.

        Walks the parsed condition tree and checks each leaf node
        against the telemetry values.
        """
        import time
        start = time.perf_counter()
        
        # A Sigma rule can have multiple conditions (rare); we evaluate
        # all of them and return True if *any* condition matches (OR).
        for condition in compiled.detection.parsed_condition:
            tree = condition.parsed
            if self._evaluate_node(tree, telemetry):
                duration = (time.perf_counter() - start) * 1000.0
                return {"match": True, "matched_condition": str(condition.condition), "run_duration_ms": duration}

        duration = (time.perf_counter() - start) * 1000.0
        return {"match": False, "matched_condition": None, "run_duration_ms": duration}

    def normalize_result(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Already normalized — pass through."""
        return raw_result

    # ── Condition-tree evaluator (recursive) ────────────────────────

    def _evaluate_node(self, node: Any, event: dict[str, Any]) -> bool:
        """Recursively evaluate a pySigma condition-tree node."""
        if isinstance(node, ConditionAND):
            return all(self._evaluate_node(arg, event) for arg in node.args)

        if isinstance(node, ConditionOR):
            return any(self._evaluate_node(arg, event) for arg in node.args)

        if isinstance(node, ConditionNOT):
            # ConditionNOT wraps exactly one child
            return not self._evaluate_node(node.args[0], event)

        if isinstance(node, ConditionFieldEqualsValueExpression):
            return self._match_field_value(node.field, node.value, event)

        if isinstance(node, ConditionValueExpression):
            # Keyword search — match against *all* string values in the event
            return self._match_keyword(node.value, event)

        # Fallback: unknown node type — conservatively return False
        return False

    # ── Leaf-node matchers ──────────────────────────────────────────

    def _match_field_value(
        self,
        field: str | None,
        sigma_value: SigmaString | SigmaNumber | Any,
        event: dict[str, Any],
    ) -> bool:
        """Check whether ``event[field]`` matches ``sigma_value``."""
        if field is None:
            return False

        event_value = event.get(field)
        if event_value is None:
            return False

        # ── SigmaNumber: numeric equality ───────────────────────────
        if isinstance(sigma_value, SigmaNumber):
            try:
                return float(event_value) == float(sigma_value.number)
            except (ValueError, TypeError):
                return False

        # ── SigmaString: plain or wildcard match ────────────────────
        if isinstance(sigma_value, SigmaString):
            return self._match_sigma_string(sigma_value, str(event_value))

        # Fallback: string equality
        return str(event_value) == str(sigma_value)

    def _match_sigma_string(self, sigma_str: SigmaString, value: str) -> bool:
        """Match a SigmaString (possibly containing wildcards) against a value.

        Plain strings  → case-insensitive equality.
        Wildcard strings → convert to regex via pySigma and match.
        """
        if not sigma_str.contains_special():
            # No wildcards — plain case-insensitive comparison
            return value.lower() == sigma_str.to_plain().lower()

        # Contains wildcards — use regex
        regex_pattern = self._sigma_string_to_regex(sigma_str)
        return bool(re.match(regex_pattern, value, re.IGNORECASE | re.DOTALL))

    def _sigma_string_to_regex(self, sigma_str: SigmaString) -> str:
        """Convert a SigmaString with wildcards to a Python regex pattern.

        Iterates over the internal ``.s`` list which contains plain strings
        and ``SpecialChars`` enum members, building a regex directly.
        """
        from sigma.types import SpecialChars

        parts: list[str] = []
        for segment in sigma_str.s:
            if segment is SpecialChars.WILDCARD_MULTI:
                parts.append(".*")
            elif segment is SpecialChars.WILDCARD_SINGLE:
                parts.append(".")
            else:
                parts.append(re.escape(str(segment)))

        return "^" + "".join(parts) + "$"

    def _match_keyword(
        self, sigma_value: SigmaString | Any, event: dict[str, Any]
    ) -> bool:
        """Keyword search: match against every string value in the event.

        Sigma keyword searches are substring matches — if the keyword
        appears anywhere in any field value, it's a match.
        """
        for v in event.values():
            if isinstance(v, str):
                if isinstance(sigma_value, SigmaString):
                    if sigma_value.contains_special():
                        # Wildcards present — use regex
                        if self._match_sigma_string(sigma_value, v):
                            return True
                    else:
                        # Plain keyword — case-insensitive substring search
                        if sigma_value.to_plain().lower() in v.lower():
                            return True
                elif str(sigma_value).lower() in v.lower():
                    return True
        return False
