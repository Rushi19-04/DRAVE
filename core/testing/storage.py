"""Result storage — Step 19 of the Build Blueprint.

Abstract interface for storing test results and a local JSONL implementation.
"""

import json
from abc import ABC, abstractmethod
from pathlib import Path

from core.testing.models import TestResult


class ResultStorage(ABC):
    """Abstract base class for storing test results."""

    @abstractmethod
    def store_result(self, result: TestResult) -> None:
        """Store a single test result."""
        pass


class LocalJsonlStorage(ResultStorage):
    """Local JSON Lines implementation of ResultStorage."""

    def __init__(self, directory: str = "results", filename: str = "test_results.jsonl"):
        self.path = Path(directory) / filename
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def store_result(self, result: TestResult) -> None:
        """Append the TestResult as a JSON line to the configured file."""
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(result.model_dump_json() + "\n")
