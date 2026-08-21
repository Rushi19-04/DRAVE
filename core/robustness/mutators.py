"""Automated mutators for cheap perturbation dimensions (Step 46)."""

import copy
import random


def mutate_casing(event: dict, field: str) -> dict:
    """Randomize casing of a string field value."""
    mutated = copy.deepcopy(event)
    if field in mutated and isinstance(mutated[field], str):
        mutated[field] = "".join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in mutated[field]
        )
    return mutated


def mutate_encoding_flag(event: dict) -> dict:
    """Swap the encoding flag in CommandLine to a random variant."""
    mutated = copy.deepcopy(event)
    variants = ["-enc", "-EncodedCommand", "-ec ", "-e ", "-eNc"]
    cmd = mutated.get("CommandLine", "")
    for flag in ["-enc", "-EncodedCommand", "-ec ", "-e ", "-eNc"]:
        if flag in cmd:
            replacement = random.choice(variants)
            mutated["CommandLine"] = cmd.replace(flag, replacement, 1)
            break
    return mutated


def mutate_parent_process(event: dict, parent: str) -> dict:
    """Replace ParentImage with a different process path."""
    mutated = copy.deepcopy(event)
    mutated["ParentImage"] = parent
    return mutated
