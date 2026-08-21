"""Volume policy evaluation logic with fallback precedence (Step 52)."""

import yaml
from pathlib import Path

from core.detection.models import DetectionRule
from core.volume.models import VolumeEstimate, VolumePolicy, VolumePolicyResult


def load_project_volume_policy() -> VolumePolicy | None:
    """Load the global volume policy from drave.yml, if it exists."""
    config_path = Path("drave.yml")
    if not config_path.exists():
        return None
        
    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        if data and "volume_policy" in data:
            return VolumePolicy(**data["volume_policy"])
    except Exception:
        pass
        
    return None


def evaluate_volume_policy(
    rule: DetectionRule, 
    estimate: VolumeEstimate
) -> VolumePolicyResult:
    """Evaluate an estimate against the applicable policy.
    
    Precedence:
    1. Per-rule policy (from DetectionRule.volume_policy)
    2. Project global policy (from drave.yml)
    3. Warning if no policy exists (zero volume gate coverage).
    """
    policy = None
    source = ""
    
    if rule.volume_policy:
        policy = VolumePolicy(**rule.volume_policy)
        source = "rule override"
    else:
        project_policy = load_project_volume_policy()
        if project_policy:
            policy = project_policy
            source = "project default"
            
    if not policy:
        return VolumePolicyResult(
            status="WARNING",
            message="No volume policy applied. This rule has zero volume gate coverage."
        )
        
    if estimate.estimated_daily_alerts > policy.failure_threshold:
        return VolumePolicyResult(
            status="FAIL",
            message=f"Estimated {estimate.estimated_daily_alerts:.1f} alerts/day exceeds {source} failure threshold ({policy.failure_threshold})"
        )
    elif estimate.estimated_daily_alerts > policy.warning_threshold:
        return VolumePolicyResult(
            status="WARNING",
            message=f"Estimated {estimate.estimated_daily_alerts:.1f} alerts/day exceeds {source} warning threshold ({policy.warning_threshold})"
        )
        
    return VolumePolicyResult(
        status="PASS",
        message=f"Estimated {estimate.estimated_daily_alerts:.1f} alerts/day is within {source} limits"
    )
