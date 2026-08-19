"""Tests for the In-Memory Sigma Adapter (Stage 3, Steps 9-10)."""

from datetime import UTC, datetime
from typing import Any

from adapters.sigma.inmemory import SigmaInMemoryAdapter
from core.detection.adapter import DetectionAdapter
from core.detection.models import DetectionRule

# ── Fixtures ────────────────────────────────────────────────────────

VALID_SIGMA_YAML = r"""
title: Encoded PowerShell
id: af4a3d12-2b5e-4c6d-8e7f-1a2b3c4d5e6f
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_encoded:
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'
    condition: selection_process and selection_encoded
level: high
"""

INVALID_SIGMA_YAML = """
title: Broken Rule
detection:
    condition: missing_identifier
"""

OR_RULE_YAML = r"""
title: Shell Execution
id: bf4a3d12-2b5e-4c6d-8e7f-1a2b3c4d5e6f
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel1:
        Image|endswith: '\powershell.exe'
    sel2:
        Image|endswith: '\cmd.exe'
    condition: sel1 or sel2
level: medium
"""

NOT_RULE_YAML = r"""
title: PowerShell Except SYSTEM
id: cf4a3d12-2b5e-4c6d-8e7f-1a2b3c4d5e6f
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
    filter:
        User: 'SYSTEM'
    condition: selection and not filter
level: medium
"""

KEYWORD_RULE_YAML = """
title: Mimikatz Keyword
id: df4a3d12-2b5e-4c6d-8e7f-1a2b3c4d5e6f
status: test
logsource:
    category: process_creation
    product: windows
detection:
    keywords:
        - 'mimikatz'
        - 'sekurlsa'
    condition: keywords
level: critical
"""

NUMERIC_RULE_YAML = """
title: EventID Match
id: ef4a3d12-2b5e-4c6d-8e7f-1a2b3c4d5e6f
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 4688
    condition: selection
level: low
"""

NOW = datetime(2025, 1, 1, tzinfo=UTC)


def _make_rule(sigma_yaml: str, rule_id: str = "DET-TEST") -> DetectionRule:
    return DetectionRule(
        id=rule_id,
        name="Test Rule",
        description="Test",
        language="sigma",
        platform="windows",
        query=sigma_yaml,
        severity="high",
        author="test",
        created_at=NOW,
        updated_at=NOW,
    )


def _run(
    adapter: SigmaInMemoryAdapter, rule: DetectionRule, event: dict[str, Any]
) -> dict[str, Any]:
    compiled = adapter.compile(rule)
    raw = adapter.execute(compiled, event)
    return adapter.normalize_result(raw)


# ── Tests ───────────────────────────────────────────────────────────


class TestAdapterInterface:
    """Verify SigmaInMemoryAdapter implements the ABC correctly."""

    def test_is_detection_adapter(self) -> None:
        assert issubclass(SigmaInMemoryAdapter, DetectionAdapter)

    def test_instance_is_detection_adapter(self) -> None:
        adapter = SigmaInMemoryAdapter()
        assert isinstance(adapter, DetectionAdapter)


class TestValidate:
    """Test syntax validation via pySigma parsing."""

    def test_valid_rule(self) -> None:
        adapter = SigmaInMemoryAdapter()
        rule = _make_rule(VALID_SIGMA_YAML)
        assert adapter.validate(rule) is True

    def test_invalid_rule(self) -> None:
        adapter = SigmaInMemoryAdapter()
        rule = _make_rule(INVALID_SIGMA_YAML)
        assert adapter.validate(rule) is False

    def test_garbage_yaml(self) -> None:
        adapter = SigmaInMemoryAdapter()
        rule = _make_rule("this is not yaml: [[[")
        assert adapter.validate(rule) is False


class TestCompileAndExecute:
    """Test rule compilation and execution against telemetry events."""

    def test_positive_match(self) -> None:
        adapter = SigmaInMemoryAdapter()
        rule = _make_rule(VALID_SIGMA_YAML)
        event = {
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": "powershell.exe -enc SGVsbG8=",
        }
        result = _run(adapter, rule, event)
        assert result["match"] is True

    def test_negative_no_match_wrong_process(self) -> None:
        adapter = SigmaInMemoryAdapter()
        rule = _make_rule(VALID_SIGMA_YAML)
        event = {
            "Image": r"C:\Windows\notepad.exe",
            "CommandLine": "notepad.exe -enc something",
        }
        result = _run(adapter, rule, event)
        assert result["match"] is False

    def test_negative_no_match_no_encoding(self) -> None:
        adapter = SigmaInMemoryAdapter()
        rule = _make_rule(VALID_SIGMA_YAML)
        event = {
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": "powershell.exe -File script.ps1",
        }
        result = _run(adapter, rule, event)
        assert result["match"] is False

    def test_case_insensitive_match(self) -> None:
        adapter = SigmaInMemoryAdapter()
        rule = _make_rule(VALID_SIGMA_YAML)
        event = {
            "Image": r"C:\WINDOWS\SYSTEM32\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE",
            "CommandLine": "POWERSHELL.EXE -ENC SGVsbG8=",
        }
        result = _run(adapter, rule, event)
        assert result["match"] is True

    def test_pwsh_variant(self) -> None:
        adapter = SigmaInMemoryAdapter()
        rule = _make_rule(VALID_SIGMA_YAML)
        event = {
            "Image": r"C:\Program Files\PowerShell\7\pwsh.exe",
            "CommandLine": "pwsh.exe -EncodedCommand SGVsbG8=",
        }
        result = _run(adapter, rule, event)
        assert result["match"] is True

    def test_missing_field_no_match(self) -> None:
        adapter = SigmaInMemoryAdapter()
        rule = _make_rule(VALID_SIGMA_YAML)
        event = {"Image": r"C:\Windows\powershell.exe"}  # missing CommandLine
        result = _run(adapter, rule, event)
        assert result["match"] is False

    def test_empty_event_no_match(self) -> None:
        adapter = SigmaInMemoryAdapter()
        rule = _make_rule(VALID_SIGMA_YAML)
        result = _run(adapter, rule, {})
        assert result["match"] is False


class TestORLogic:
    """Test OR condition: sel1 or sel2."""

    def test_first_branch(self) -> None:
        adapter = SigmaInMemoryAdapter()
        rule = _make_rule(OR_RULE_YAML)
        event = {"Image": r"C:\Windows\powershell.exe"}
        assert _run(adapter, rule, event)["match"] is True

    def test_second_branch(self) -> None:
        adapter = SigmaInMemoryAdapter()
        rule = _make_rule(OR_RULE_YAML)
        event = {"Image": r"C:\Windows\cmd.exe"}
        assert _run(adapter, rule, event)["match"] is True

    def test_neither_branch(self) -> None:
        adapter = SigmaInMemoryAdapter()
        rule = _make_rule(OR_RULE_YAML)
        event = {"Image": r"C:\Windows\notepad.exe"}
        assert _run(adapter, rule, event)["match"] is False


class TestNOTLogic:
    """Test AND + NOT: selection and not filter."""

    def test_matches_without_filter(self) -> None:
        adapter = SigmaInMemoryAdapter()
        rule = _make_rule(NOT_RULE_YAML)
        event = {
            "Image": r"C:\Windows\powershell.exe",
            "User": "CORP\\jsmith",
        }
        assert _run(adapter, rule, event)["match"] is True

    def test_filtered_out_by_user(self) -> None:
        adapter = SigmaInMemoryAdapter()
        rule = _make_rule(NOT_RULE_YAML)
        event = {
            "Image": r"C:\Windows\powershell.exe",
            "User": "SYSTEM",
        }
        assert _run(adapter, rule, event)["match"] is False


class TestKeywordSearch:
    """Test keyword matching (no field specified)."""

    def test_keyword_in_commandline(self) -> None:
        adapter = SigmaInMemoryAdapter()
        rule = _make_rule(KEYWORD_RULE_YAML)
        event = {
            "Image": r"C:\Windows\cmd.exe",
            "CommandLine": "cmd.exe /c mimikatz.exe",
        }
        assert _run(adapter, rule, event)["match"] is True

    def test_keyword_in_another_field(self) -> None:
        adapter = SigmaInMemoryAdapter()
        rule = _make_rule(KEYWORD_RULE_YAML)
        event = {
            "Image": r"C:\tools\sekurlsa.exe",
            "CommandLine": "normal command",
        }
        assert _run(adapter, rule, event)["match"] is True

    def test_no_keyword_present(self) -> None:
        adapter = SigmaInMemoryAdapter()
        rule = _make_rule(KEYWORD_RULE_YAML)
        event = {
            "Image": r"C:\Windows\notepad.exe",
            "CommandLine": "notepad.exe",
        }
        assert _run(adapter, rule, event)["match"] is False


class TestNumericMatch:
    """Test numeric field matching (SigmaNumber)."""

    def test_matching_event_id(self) -> None:
        adapter = SigmaInMemoryAdapter()
        rule = _make_rule(NUMERIC_RULE_YAML)
        event = {"EventID": 4688}
        assert _run(adapter, rule, event)["match"] is True

    def test_event_id_as_string(self) -> None:
        adapter = SigmaInMemoryAdapter()
        rule = _make_rule(NUMERIC_RULE_YAML)
        event = {"EventID": "4688"}
        assert _run(adapter, rule, event)["match"] is True

    def test_wrong_event_id(self) -> None:
        adapter = SigmaInMemoryAdapter()
        rule = _make_rule(NUMERIC_RULE_YAML)
        event = {"EventID": 1234}
        assert _run(adapter, rule, event)["match"] is False
