"""PR Markdown parsing (Step 27)."""

import re
from typing import Literal

ReasonType = Literal[
    "bug_fix",
    "false_positive_reduction",
    "new_attack",
    "schema_change",
    "performance",
    "tuning",
    "unknown"
]


def parse_pr_reason(pr_body: str) -> ReasonType:
    """
    Parse the PR body to find the selected change reason.
    Expects markdown checkboxes like:
    - [x] `bug_fix`: Fixing a logic error...
    """
    lines = pr_body.splitlines()
    for line in lines:
        # Match checked boxes: - [x] `reason` or * [X] `reason`
        match = re.match(r"^[\-\*]\s*\[[xX]\]\s*`([^`]+)`", line.strip())
        if match:
            reason = match.group(1)
            # Validate against our known reasons
            if reason in ReasonType.__args__:
                return reason  # type: ignore
                
    return "unknown"
