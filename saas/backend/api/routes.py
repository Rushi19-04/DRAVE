"""API Routes (Step 69)."""

import uuid
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select
from pydantic import BaseModel

from saas.backend.database import get_session
from saas.backend.models import RuleEntity, HealthRecord, DeploymentLog

# Import existing core modules
from core.detection.models import DetectionRule
from adapters.splunk.adapter import SplunkAdapter
from core.deployment.verify import verify_deployment
from saas.backend.api.auth import get_current_user

router = APIRouter()

def get_tenant_session(
    user: str = Depends(get_current_user),
    session: Session = Depends(get_session)
) -> Session:
    """Provides a database session automatically scoped to the user's tenant (user_id)."""
    # Use user_id as tenant_id (Personal Workspaces)
    session.info["tenant_id"] = user
    return session

class RuleCreate(BaseModel):
    rule: DetectionRule
    score: float

@router.post("/rules", response_model=RuleEntity)
def ingest_rule(
    payload: RuleCreate, 
    session: Session = Depends(get_tenant_session),
    user: str = Depends(get_current_user)
):
    """Ingest a new rule from CI/CD runs."""
    # The session is now automatically scoped to tenant_id=user!
    existing = session.exec(select(RuleEntity).where(RuleEntity.id == payload.rule.id)).first()
    
    if existing:
        # Update
        for k, v in payload.rule.model_dump().items():
            setattr(existing, k, v)
        db_rule = existing
    else:
        # Create - we still need to populate tenant_id explicitly on insert
        db_rule = RuleEntity(**payload.rule.model_dump(), tenant_id=user)
        session.add(db_rule)
        
    # Record health
    health_record = HealthRecord(
        rule_id=db_rule.id,
        tenant_id=user,
        score=payload.score
    )
    session.add(health_record)
    
    try:
        session.commit()
        session.refresh(db_rule)
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=409, detail="Rule ID conflict or other integrity error.")
        
    return db_rule

@router.get("/rules", response_model=List[RuleEntity])
def get_rules(
    session: Session = Depends(get_tenant_session)
):
    """Fetch rules."""
    # NO manual .where(tenant_id) - do_orm_execute handles it globally!
    rules = session.exec(select(RuleEntity)).all()
    return rules

class DeployRequest(BaseModel):
    rule_id: str
    target_siem: str = "splunk"
    confirmation_id: str

@router.post("/deployments", response_model=DeploymentLog)
def trigger_deployment(
    req: DeployRequest,
    session: Session = Depends(get_tenant_session),
    user: str = Depends(get_current_user)
):
    """Trigger SIEM deployments securely (Tier 3)."""
    # 1. Tier 3 Confirmation Check
    if req.confirmation_id != req.rule_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Deployment aborted: Confirmation did not match detection ID."
        )
        
    rule_entity = session.exec(select(RuleEntity).where(RuleEntity.id == req.rule_id)).first()
    if not rule_entity:
        raise HTTPException(status_code=404, detail="Rule not found")
        
    # Create deployment log
    deployment = DeploymentLog(
        deployment_id=str(uuid.uuid4()),
        detection_id=rule_entity.id,
        tenant_id=user,
        git_commit="HEAD",
        version=rule_entity.version,
        target_siem=req.target_siem,
        status="pending",
        requested_by=user,
        approved_by=user,
        reason="API Triggered",
        timestamp=datetime.utcnow()
    )
    session.add(deployment)
    session.commit()
    
    # We convert RuleEntity back to DetectionRule for the adapter
    rule = DetectionRule.model_validate(rule_entity, from_attributes=True)
    
    # Deploy
    adapter = SplunkAdapter()
    success = adapter.deploy(rule)
    
    if not success:
        deployment.status = "failed"
        session.commit()
        raise HTTPException(status_code=500, detail="Adapter deployment failed")
        
    # Verify Smoke Test
    verified = verify_deployment(rule, adapter)
    
    if verified:
        deployment.status = "success"
    else:
        # Automated Rollback would happen here (simplified for API)
        deployment.status = "rollback_failed" # Mocking failure for demonstration
        
    session.add(deployment)
    session.commit()
    session.refresh(deployment)
    
    return deployment

@router.get("/health")
def get_health(
    session: Session = Depends(get_tenant_session)
):
    """Fetch aggregate workspace health metrics."""
    # Simplified aggregate for MVP - queries are automatically scoped
    records = session.exec(select(HealthRecord)).all()
    if not records:
        return {"average_health": 0.0, "total_records": 0}
        
    avg = sum(r.score for r in records) / len(records)
    return {"average_health": round(avg, 2), "total_records": len(records)}
