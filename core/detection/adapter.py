"""DRAVE Detection Adapter interface — Step 9 of the Build Blueprint.

The test engine should not contain SIEM-specific logic. Every adapter
(Sigma in-memory, Splunk, Sentinel, Elastic, etc.) implements this
common interface so the Test Runner and all downstream consumers
remain adapter-agnostic.
"""

from abc import ABC, abstractmethod
from typing import Any

from core.detection.models import DetectionRule


class DetectionAdapter(ABC):
    """Abstract base class that every detection adapter must implement.

    Methods
    -------
    validate(rule)
        Syntax-check the rule; return True if valid.
    compile(rule)
        Parse/compile the rule into an adapter-specific representation.
    execute(compiled, telemetry)
        Run the compiled rule against a single telemetry event dict
        and return the raw adapter-specific result.
    normalize_result(raw_result)
        Convert the adapter-specific result into a DRAVE-standard dict
        with at least ``{"match": bool, ...}``.
    """

    @abstractmethod
    def validate(self, rule: DetectionRule) -> bool:
        """Return True if the rule's query is syntactically valid."""
        ...

    @abstractmethod
    def compile(self, rule: DetectionRule) -> Any:
        """Parse the rule into an internal representation for execution."""
        ...

    @abstractmethod
    def execute(self, compiled: Any, telemetry: dict[str, Any]) -> Any:
        """Run the compiled rule against a telemetry event dict."""
        ...

    @abstractmethod
    def normalize_result(self, raw_result: Any) -> dict[str, Any]:
        """Normalize adapter-specific output to a standard DRAVE dict."""
        ...
