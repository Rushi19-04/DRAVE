"""DRAVE Stage 3 Demo — In-Memory Sigma Adapter.

A real Sigma rule detecting encoded PowerShell execution,
evaluated against real-shaped Windows telemetry events.
No SIEM required — runs entirely in Python.
"""

from datetime import UTC, datetime

from adapters.sigma.inmemory import SigmaInMemoryAdapter
from core.detection.models import DetectionRule

# ── 1. A real Sigma rule (encoded PowerShell detection) ─────────────

SIGMA_RULE_YAML = r"""
title: Encoded PowerShell Command Line
id: af4a3d12-2b5e-4c6d-8e7f-1a2b3c4d5e6f
status: test
description: >
    Detects execution of PowerShell with Base64-encoded command line,
    a common technique used by attackers to obfuscate malicious scripts.
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
            - '-ec '
    condition: selection_process and selection_encoded
falsepositives:
    - Legitimate administrative scripts using encoding
level: high
tags:
    - attack.execution
    - attack.t1059.001
"""

# ── 2. Build the DetectionRule model ────────────────────────────────

rule = DetectionRule(
    id="DET-001",
    name="Encoded PowerShell Command Line",
    description="Detects base64-encoded PowerShell execution",
    language="sigma",
    platform="windows",
    query=SIGMA_RULE_YAML,
    severity="high",
    author="drave-demo",
    created_at=datetime(2025, 1, 1, tzinfo=UTC),
    updated_at=datetime(2025, 6, 1, tzinfo=UTC),
    attack_mappings=["T1059.001"],
)

# ── 3. Telemetry events (Windows process creation shape) ────────────

attack_event = {
    "EventID": 4688,
    "TimeCreated": "2025-06-15T14:32:01Z",
    "Computer": "WORKSTATION-01",
    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "CommandLine": "powershell.exe -NoProfile -enc SGVsbG8gV29ybGQ=",
    "User": "CORP\\jsmith",
    "ParentImage": r"C:\Windows\explorer.exe",
    "ParentCommandLine": "explorer.exe",
}

benign_event = {
    "EventID": 4688,
    "TimeCreated": "2025-06-15T14:33:12Z",
    "Computer": "WORKSTATION-01",
    "Image": r"C:\Windows\System32\notepad.exe",
    "CommandLine": "notepad.exe C:\\Users\\jsmith\\notes.txt",
    "User": "CORP\\jsmith",
    "ParentImage": r"C:\Windows\explorer.exe",
    "ParentCommandLine": "explorer.exe",
}

benign_powershell_event = {
    "EventID": 4688,
    "TimeCreated": "2025-06-15T14:34:00Z",
    "Computer": "WORKSTATION-01",
    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "CommandLine": "powershell.exe -File C:\\Scripts\\backup.ps1",
    "User": "CORP\\admin",
    "ParentImage": r"C:\Windows\System32\svchost.exe",
    "ParentCommandLine": "svchost.exe -k netsvcs",
}

# ── 4. Run the adapter ──────────────────────────────────────────────

adapter = SigmaInMemoryAdapter()

print("=" * 65)
print("  DRAVE -- In-Memory Sigma Adapter Demo (Stage 3)")
print("=" * 65)
print()

# Validate
print(f"Rule: {rule.name} ({rule.id})")
is_valid = adapter.validate(rule)
print(f"Syntax valid: {is_valid}")
print()

# Compile
compiled = adapter.compile(rule)
print(f"Compiled SigmaRule: {compiled.title}")
print(f"Level: {compiled.level}")
print()

# Execute against each event
events = [
    ("ATTACK — Encoded PowerShell", attack_event),
    ("BENIGN — Notepad", benign_event),
    ("BENIGN — PowerShell without encoding", benign_powershell_event),
]

print("-" * 65)
for label, event in events:
    raw = adapter.execute(compiled, event)
    result = adapter.normalize_result(raw)
    match_str = ">> MATCH (ALERT)" if result["match"] else "-- no match"
    print(f"  {label}")
    print(f"    Image:       {event['Image'].split(chr(92))[-1]}")
    print(f"    CommandLine: {event['CommandLine'][:60]}")
    print(f"    Result:      {match_str}")
    print()

print("-" * 65)
print("  Expected: MATCH on attack, no match on both benign events.")
print("=" * 65)
