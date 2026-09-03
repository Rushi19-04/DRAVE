import os
import sys
from pathlib import Path
from core.discovery.scanner import RepositoryScanner
from core.discovery.diff import GitDiffProvider, DiffRange
from core.discovery.incremental import IncrementalResolver

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Resolve affected rules from git diff")
    parser.add_argument("--workspace", default=".", help="Workspace path")
    args = parser.parse_args()
    
    workspace = Path(args.workspace).resolve()
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    
    provider = GitDiffProvider(str(workspace))
    
    if not event_path or not os.path.exists(event_path):
        print(f"::warning::GITHUB_EVENT_PATH not found or invalid. Falling back to HEAD~1...", file=sys.stderr)
        diff_range = DiffRange(before="HEAD~1", after="HEAD")
    else:
        diff_range = provider.get_diff_range_from_event(event_path)
        if not diff_range:
            print(f"::warning::Could not extract valid diff range from {event_path}. Falling back to HEAD~1...", file=sys.stderr)
            diff_range = DiffRange(before="HEAD~1", after="HEAD")
            
    print(f"DEBUG: Using Diff Range: {diff_range.before} -> {diff_range.after}", file=sys.stderr)
    
    changed_files = provider.get_changed_files(diff_range)
    
    if not changed_files:
        print("DEBUG: No files changed in this diff range.", file=sys.stderr)
        return
        
    print(f"DEBUG: Found {len(changed_files)} changed file(s).", file=sys.stderr)
    for cf in changed_files:
        print(f"DEBUG:  {cf.status} {cf.path}", file=sys.stderr)
        
    scanner = RepositoryScanner(str(workspace))
    inventory = scanner.scan()
    
    resolver = IncrementalResolver(inventory, provider)
    affected_ids = resolver.resolve(diff_range, changed_files)
    
    if not affected_ids:
        print("DEBUG: 0 affected detection rules found.", file=sys.stderr)
        return
        
    print(f"DEBUG: Resolved {len(affected_ids)} affected detection IDs.", file=sys.stderr)
    
    for det_id in affected_ids:
        rule = inventory.rules.get(det_id)
        if rule:
            # Output the paths to stdout so entrypoint.sh can iterate over them
            for path, r_id in inventory.rule_paths.items():
                if r_id == det_id:
                    print(path)
                    break

if __name__ == "__main__":
    main()
