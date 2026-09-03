import os
import json
import subprocess
from typing import List, Optional
from pydantic import BaseModel

class DiffRange(BaseModel):
    before: str
    after: str

class ChangedFile(BaseModel):
    path: str
    status: str  # A (Added), M (Modified), D (Deleted), R (Renamed), etc.
    previous_path: Optional[str] = None # For Renames

class GitDiffProvider:
    def __init__(self, workspace: str):
        self.workspace = workspace

    def get_diff_range_from_event(self, event_path: str) -> Optional[DiffRange]:
        """Extract the before and after SHAs from a GitHub Event payload."""
        if not os.path.exists(event_path):
            return None
            
        try:
            with open(event_path, 'r', encoding='utf-8') as f:
                event_data = json.load(f)
                
            # Try push event
            before = event_data.get("before")
            after = event_data.get("after")
            
            # Try pull_request event
            if not before or not after:
                pr = event_data.get("pull_request", {})
                base = pr.get("base", {})
                head = pr.get("head", {})
                before = base.get("sha")
                after = head.get("sha")
                
            if before and after and before != "0000000000000000000000000000000000000000":
                return DiffRange(before=before, after=after)
        except Exception:
            pass
            
        return None

    def get_changed_files(self, diff_range: DiffRange) -> List[ChangedFile]:
        """Execute git diff and parse the status and paths."""
        try:
            result = subprocess.run(
                ["git", "diff", "--name-status", diff_range.before, diff_range.after],
                cwd=self.workspace,
                capture_output=True,
                text=True,
                check=True
            )
            
            changed = []
            for line in result.stdout.splitlines():
                parts = line.strip().split("\t")
                if not parts:
                    continue
                    
                status = parts[0][0].upper() # Get just the first letter (e.g., R from R100)
                if status == 'R' and len(parts) >= 3:
                    changed.append(ChangedFile(status=status, path=parts[2], previous_path=parts[1]))
                elif len(parts) >= 2:
                    changed.append(ChangedFile(status=status, path=parts[1]))
                    
            return changed
        except subprocess.CalledProcessError:
            return []
            
    def get_file_content_at_commit(self, file_path: str, commit_sha: str) -> Optional[str]:
        """Fetch the content of a file at a specific commit (useful for deleted files)."""
        try:
            # Path needs to use forward slashes for git show
            git_path = file_path.replace("\\", "/")
            result = subprocess.run(
                ["git", "show", f"{commit_sha}:{git_path}"],
                cwd=self.workspace,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError:
            return None
