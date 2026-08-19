"""Rule diffing using GitPython (Step 26)."""

from datetime import datetime
from pathlib import Path
from typing import Any

from git import Repo
from pydantic import BaseModel


class RuleDiff(BaseModel):
    """Metadata and raw text diff for a changed rule."""
    file_path: str
    diff_text: str
    author: str
    timestamp: datetime
    commit_head: str
    commit_base: str


def extract_rule_diff(
    repo_path: str,
    commit_base: str,
    commit_head: str,
    rule_path: str
) -> RuleDiff:
    """Extract diff and metadata for a specific rule file."""
    repo = Repo(repo_path)
    
    # Get the diff text
    diff_text = repo.git.diff(commit_base, commit_head, "--", rule_path)
    
    # Get metadata from the head commit
    head_commit = repo.commit(commit_head)
    
    return RuleDiff(
        file_path=rule_path,
        diff_text=diff_text,
        author=head_commit.author.name,
        timestamp=head_commit.authored_datetime,
        commit_head=commit_head,
        commit_base=commit_base
    )
