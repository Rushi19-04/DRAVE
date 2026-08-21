import pytest
from core.detection.models import DetectionRule
from adapters.splunk.adapter import SplunkAdapter

@pytest.fixture
def sample_rule():
    return DetectionRule(
        id="11111111-1111-1111-1111-111111111111",
        version=1,
        name="Mock Rule",
        description="A mock rule",
        language="sigma",
        platform="windows",
        severity="high",
        author="Test",
        created_at="2025-01-01T00:00:00Z",
        updated_at="2025-01-01T00:00:00Z",
        query='''
title: Mock Rule
id: 11111111-1111-1111-1111-111111111111
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'mock_pattern'
    condition: selection
level: high
'''
    )

def test_splunk_adapter_validate(sample_rule):
    adapter = SplunkAdapter()
    assert adapter.validate(sample_rule) is True

def test_splunk_adapter_compile(sample_rule):
    adapter = SplunkAdapter()
    spl = adapter.compile(sample_rule)
    assert 'CommandLine="*mock_pattern*"' in spl

def test_splunk_adapter_execute(sample_rule):
    adapter = SplunkAdapter()
    # Execute simply returns the telemetry as a mock
    assert adapter.execute("fake_spl", {"foo": "bar"}) == {"foo": "bar"}

def test_splunk_adapter_deploy(sample_rule):
    adapter = SplunkAdapter()
    assert adapter.deploy(sample_rule) is True
    spl = adapter.get_deployed_spl(sample_rule.id)
    assert 'CommandLine="*mock_pattern*"' in spl
