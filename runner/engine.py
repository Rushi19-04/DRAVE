"""Local Customer Runner engine (Steps 37-38, 40-41).

This is the local stub of the DRAVE Customer Runner. In production, this
process runs inside the customer's infrastructure (VPC/K8s/VM) and
communicates with DRAVE Cloud via job definitions and structured results.

PRIVACY INVARIANT: Raw telemetry never leaves this engine. Only TestResult
objects and schema metadata are returned in RunnerResult.
"""

from pathlib import Path
import ruamel.yaml

from core.detection.models import DetectionRule
from core.testing.models import TestCase
from core.testing.runner import run_test
from core.validation.dependencies import extract_dependencies
from core.validation.schema import SchemaProvider
from core.telemetry.drift import SchemaDriftDetector
from adapters.sigma.inmemory import SigmaInMemoryAdapter
from runner.models import RunnerJob
from runner.results import RunnerResult, SchemaSnapshot


class RunnerEngine:
    """Local stub of the DRAVE Customer Runner."""
    
    def __init__(self):
        self.adapter = SigmaInMemoryAdapter()
        self.schema_provider = SchemaProvider()
        self.drift_detector = SchemaDriftDetector()
        self.yaml = ruamel.yaml.YAML(typ="safe")
        
    def execute_job(self, job: RunnerJob) -> RunnerResult:
        """Execute a runner job and return structured results only."""
        
        try:
            # 1. Load Rule
            rule_data = self.yaml.load(Path(job.rule_path).read_text(encoding="utf-8"))
            rule = DetectionRule(**rule_data)
            
            # 2. Run Tests
            test_results = []
            for tp in job.test_paths:
                test_data = self.yaml.load(Path(tp).read_text(encoding="utf-8"))
                test_case = TestCase(**test_data)
                
                if test_case.detection_id != job.detection_id:
                    continue
                    
                result = run_test(rule, test_case, self.adapter)
                test_results.append(result)
                
            # 3. Schema Snapshot & Drift Detection
            compiled = self.adapter.compile(rule)
            deps = extract_dependencies(compiled)
            schema_fields = self.schema_provider.get_schema_fields(deps.logsource_id)
            
            snapshot = SchemaSnapshot(
                detection_id=job.detection_id,
                fields=schema_fields
            )
            
            drift_details = self.drift_detector.detect_drift(job.detection_id, schema_fields)
            
            # Update stored snapshot for next comparison
            self.drift_detector.store_snapshot(job.detection_id, schema_fields)
            
            return RunnerResult(
                job_id=job.job_id,
                detection_id=job.detection_id,
                test_results=test_results,
                schema_snapshot=snapshot,
                drift_detected=len(drift_details) > 0,
                drift_details=drift_details,
                status="success"
            )
            
        except Exception as e:
            return RunnerResult(
                job_id=job.job_id,
                detection_id=job.detection_id,
                test_results=[],
                status="error",
                error_message=str(e)
            )
