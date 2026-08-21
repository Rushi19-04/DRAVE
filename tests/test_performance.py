"""Performance unit tests (Step 54)."""

import time
from core.detection.models import DetectionRule
from adapters.sigma.inmemory import SigmaInMemoryAdapter


def test_inmemory_adapter_timing():
    rule = DetectionRule(
        id="66666666-7777-8888-9999-aaaaaaaaaaaa",
        name="Perf Test Rule",
        description="Test",
        language="sigma",
        platform="windows",
        severity="high",
        author="test",
        created_at="2024-01-01T00:00:00Z",
        updated_at="2024-01-01T00:00:00Z",
        query="""
title: Perf Test Rule
id: 66666666-7777-8888-9999-aaaaaaaaaaaa
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\cmd.exe'
    condition: selection
level: high
"""
    )
    
    adapter = SigmaInMemoryAdapter()
    compiled = adapter.compile(rule)
    event = {"Image": "C:\\Windows\\System32\\cmd.exe"}
    
    # Run execute
    result = adapter.execute(compiled, event)
    
    assert "match" in result
    assert result["match"] is True
    assert "run_duration_ms" in result
    assert isinstance(result["run_duration_ms"], float)
    assert result["run_duration_ms"] >= 0.0
