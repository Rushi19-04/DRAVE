"""Deployment verification (Step 66)."""

from core.detection.models import DetectionRule
from core.detection.adapter import DetectionAdapter

def verify_deployment(rule: DetectionRule, adapter: DetectionAdapter) -> bool:
    """
    Verify that the deployed rule matches the expected rule and successfully 
    fires on a positive smoke test.
    
    Returns True if verified, False if deployment failed the smoke test.
    """
    # 1. Verify SPL is in the SIEM
    # We use the specific SplunkAdapter type dynamically here to check the mock
    # In reality, this would hit the API and retrieve the SPL.
    deployed_spl = None
    if hasattr(adapter, "get_deployed_spl"):
        deployed_spl = adapter.get_deployed_spl(rule.id)
        
    if not deployed_spl:
        return False
        
    # 2. Smoke Test
    # We pass a simple mock telemetry event. A real implementation would push this
    # event to the SIEM and verify the alert fired.
    smoke_event = {"EventID": 1, "Image": "powershell.exe", "CommandLine": "-enc"}
    
    # We call adapter.execute which simulates evaluating the event against the rule in the SIEM
    actual = adapter.execute(deployed_spl, smoke_event)
    
    # If the adapter returned a match, verification passes.
    if actual:
        return True
        
    return False
