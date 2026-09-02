"""SaaS Database Models (Step 68)."""

from datetime import datetime
from typing import Optional, Dict, Any, List
import uuid

from sqlmodel import SQLModel, Field
from sqlalchemy import Column, JSON

from core.detection.models import DetectionRule
from core.versioning.manifest import DeploymentManifest

class Tenant(SQLModel, table=True):
    """Multi-tenant boundary constraint."""
    id: str = Field(primary_key=True)
    name: str

class RuleEntity(DetectionRule, SQLModel, table=True):
    """Core storage for detection rules, reusing the engine's model."""
    id: str = Field(primary_key=True)
    tenant_id: str = Field(index=True)
    
    # We override these fields purely to provide SQLAlchemy JSON columns 
    # since SQLModel doesn't natively map lists/dicts to Postgres types without help.
    tags: List[str] = Field(default=[], sa_column=Column(JSON))
    attack_mappings: List[str] = Field(default=[], sa_column=Column(JSON))
    volume_policy: Optional[Dict[str, int]] = Field(default=None, sa_column=Column(JSON))
    evidence_report: dict = Field(default={}, sa_column=Column(JSON))

class HealthRecord(SQLModel, table=True):
    """Historical tracking of rule scores over time."""
    id: Optional[int] = Field(default=None, primary_key=True)
    rule_id: str = Field(index=True)
    tenant_id: str = Field(index=True)
    score: float
    recorded_at: datetime = Field(default_factory=datetime.utcnow)

class ValidationRun(SQLModel, table=True):
    """Historical validation run logs from CI/CD pipeline."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    tenant_id: str = Field(index=True)
    rule_id: str = Field(index=True)
    rule_name: str
    status: str
    score: float
    evidence_report: dict = Field(default={}, sa_column=Column(JSON))
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class DeploymentLog(DeploymentManifest, SQLModel, table=True):
    """Equivalent to DeploymentManifest for the database."""
    deployment_id: str = Field(primary_key=True)
    tenant_id: str = Field(index=True)
    status: str = Field(index=True)  # Override Literal for SQL compatibility

class CIApiKey(SQLModel, table=True):
    """Database-backed multi-tenant API keys."""
    id: str = Field(primary_key=True)
    tenant_id: str = Field(index=True)
    key_hash: str = Field(index=True)
    label: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_used_at: Optional[datetime] = None
    revoked: bool = Field(default=False)
