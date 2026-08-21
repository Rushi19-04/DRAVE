"""Credential scoping model (Step 39).

Enforces the separation between read-only (query) credentials and
deployment credentials at the type level. Actual credential management
is deferred to Phase L — this model exists so the boundary is established
in the type system from day one.
"""

from typing import Literal
from pydantic import BaseModel


class CredentialScope(BaseModel):
    """Defines the permission scope for a set of credentials."""
    scope: Literal["read_only", "deploy"]
    target_siem: str
    description: str = ""
