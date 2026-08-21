"""Git utilities for extracting historical blobs."""

from git import Repo
import ruamel.yaml


def extract_yaml_from_commit(repo_path: str, commit_hash: str, file_path: str) -> dict:
    """Dynamically extract a YAML blob from a historical commit without checking out."""
    repo = Repo(repo_path)
    commit = repo.commit(commit_hash)
    try:
        # Git paths use forward slashes
        tree_path = file_path.replace("\\", "/")
        blob = commit.tree / tree_path
        content = blob.data_stream.read().decode("utf-8")
        yaml = ruamel.yaml.YAML(typ="safe")
        return yaml.load(content)
    except KeyError:
        raise KeyError(f"File {file_path} not found in commit {commit_hash}")
