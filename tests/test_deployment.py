import pytest
from unittest.mock import patch, MagicMock

from core.deployment.verify import verify_deployment
from core.deployment.auto_rollback import attempt_auto_rollback
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

def test_verify_deployment_success(sample_rule):
    adapter = SplunkAdapter()
    adapter.deploy(sample_rule)
    assert verify_deployment(sample_rule, adapter) is True

def test_verify_deployment_failure(sample_rule):
    adapter = SplunkAdapter()
    # Do not deploy to ensure verify fails
    assert verify_deployment(sample_rule, adapter) is False

@patch("core.deployment.auto_rollback.LKGTracker")
@patch("core.deployment.auto_rollback.extract_yaml_from_commit")
def test_attempt_auto_rollback_no_lkg(mock_extract, mock_tracker):
    mock_instance = mock_tracker.return_value
    mock_instance.get_record.return_value = None
    assert attempt_auto_rollback("11111111-1111-1111-1111-111111111111", "mock-path") is False

@patch("core.deployment.auto_rollback.LKGTracker")
@patch("core.deployment.auto_rollback.extract_yaml_from_commit")
def test_attempt_auto_rollback_success(mock_extract, mock_tracker, sample_rule):
    mock_instance = mock_tracker.return_value
    mock_record = MagicMock()
    mock_record.last_known_good_commit = "abcd123"
    mock_instance.get_record.return_value = mock_record
    
    mock_extract.return_value = sample_rule.model_dump()
    
    assert attempt_auto_rollback("11111111-1111-1111-1111-111111111111", "mock-path") is True
