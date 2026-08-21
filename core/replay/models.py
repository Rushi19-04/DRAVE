"""Attack Replay models (Steps 43, 45)."""

from typing import Literal
from pydantic import BaseModel


class AttackScenario(BaseModel):
    """Defines an attack replay scenario tied to an ATT&CK technique."""
    id: str
    name: str
    technique: str  # ATT&CK ID, e.g. "T1059.001"
    telemetry: list[dict | str]  # The attack event(s) or path to fixture
    expected_detections: list[str]  # Detection IDs that MUST fire


class AttackResult(BaseModel):
    """Result of replaying an attack scenario through the detection pipeline.
    
    PASS/FAIL semantics: If any expected detection is missed, the result
    is FAIL. A missed attack detection is a critical gap, not informational.
    
    detection_latency_ms: For the in-memory adapter this will be near-zero
    since there's no real SIEM round-trip. Real latency measurement is
    deferred to Phase L when a live SIEM adapter exists.
    """
    scenario_id: str
    scenario_name: str
    technique: str
    expected_detections: list[str]
    actual_detections: list[str]
    missed_detections: list[str]
    detection_latency_ms: float
    status: Literal["PASS", "FAIL"]
