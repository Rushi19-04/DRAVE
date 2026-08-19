"""Result storage — Step 19 of the Build Blueprint.

Abstract interface for storing test results and a local JSONL implementation.
"""

import json
from abc import ABC, abstractmethod
from pathlib import Path

from core.testing.models import TestResult
from core.versioning.manifest import DeploymentManifest


class ResultStorage(ABC):
    """Abstract base class for storing test results."""

    @abstractmethod
    def store_result(self, result: TestResult) -> None:
        """Store a single test result."""
        pass

    @abstractmethod
    def store_deployment(self, manifest: "DeploymentManifest") -> None:
        """Store a deployment manifest."""
        pass


class LocalJsonlStorage(ResultStorage):
    """Local JSON Lines implementation of ResultStorage."""

    def __init__(self, directory: str = "results", filename: str = "test_results.jsonl", deployments_filename: str = "deployments.jsonl"):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.filepath = self.directory / filename
        self.deployments_filepath = self.directory / deployments_filename

    def store_result(self, result: TestResult) -> None:
        """Append the TestResult as a JSON line to the configured file."""
        with self.filepath.open("a", encoding="utf-8") as f:
            f.write(result.model_dump_json() + "\n")

    def store_deployment(self, manifest: "DeploymentManifest") -> None:
        """Append the DeploymentManifest as a JSON line to the configured file."""
        with self.deployments_filepath.open("a", encoding="utf-8") as f:
            f.write(manifest.model_dump_json() + "\n")
