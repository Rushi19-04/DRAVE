"""DRAVE Detection Rule model — Step 2 of the Build Blueprint."""

from datetime import datetime

from pydantic import BaseModel


class DetectionRule(BaseModel):
    """A detection rule as a rich object, not just a query.

    Fields match the blueprint Step 2 specification:
    id, name, description, language, platform, query, severity,
    author, created_at, updated_at, ATT&CK mappings.
    """

    id: str
    version: int = 1
    name: str
    description: str
    language: str  # "sigma" for MVP
    platform: str
    query: str
    severity: str
    author: str
    created_at: datetime
    updated_at: datetime
    attack_mappings: list[str] = []
    known_limitations: str | None = None
