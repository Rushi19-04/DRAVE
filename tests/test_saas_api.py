import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, Session, create_engine
from typing import Generator

from saas.backend.api.main import app
from saas.backend.api.auth import get_current_user
from saas.backend.database import get_session
from saas.backend.models import RuleEntity, HealthRecord, DeploymentLog, Tenant

from core.detection.models import DetectionRule

# Mock successful Auth for regular tests
def override_get_current_user():
    return "test_user_from_token"

app.dependency_overrides[get_current_user] = override_get_current_user

def test_ingest_rule(client, sample_rule):
    response = client.post("/api/v1/rules", json={"rule": sample_rule, "score": 85.0})
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == sample_rule["id"]
    assert data["tenant_id"] == "test_user_from_token"

def test_get_rules(client, sample_rule):
    client.post("/api/v1/rules", json={"rule": sample_rule, "score": 85.0})
    response = client.get("/api/v1/rules")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["id"] == sample_rule["id"]

def test_get_health(client, sample_rule):
    client.post("/api/v1/rules", json={"rule": sample_rule, "score": 80.0})
    client.post("/api/v1/rules", json={"rule": sample_rule, "score": 90.0}) # Update same rule health
    
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["average_health"] == 85.0
    assert data["total_records"] == 2

def test_deployment_rejects_mismatched_confirmation(client, sample_rule):
    # Ingest the rule first
    client.post("/api/v1/rules", json={"rule": sample_rule, "score": 100.0})
    
    # Try deploying with wrong confirmation
    response = client.post("/api/v1/deployments", json={
        "rule_id": sample_rule["id"],
        "target_siem": "splunk",
        "confirmation_id": "wrong-id"
    })
    
    assert response.status_code == 400
    assert "Confirmation did not match" in response.json()["detail"]

def test_deployment_accepts_correct_confirmation(client, sample_rule):
    client.post("/api/v1/rules", json={"rule": sample_rule, "score": 90.0})
    
    response = client.post("/api/v1/deployments", json={
        "rule_id": sample_rule["id"],
        "target_siem": "splunk",
        "confirmation_id": sample_rule["id"]
    })
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["success", "failed", "rollback_failed"]
    # Check that requested_by was grabbed from our token override!
    assert data["requested_by"] == "test_user_from_token"

def test_missing_token_returns_401(client):
    app.dependency_overrides.pop(get_current_user, None)
    
    # Test all 4 endpoints
    assert client.get("/api/v1/rules").status_code == 401
    assert client.get("/api/v1/health").status_code == 401
    assert client.post("/api/v1/rules", json={"rule": {}, "score": 90.0}).status_code == 401
    assert client.post("/api/v1/deployments", json={"rule_id": "1", "target_siem": "splunk", "confirmation_id": "1"}).status_code == 401

def test_invalid_format_token_returns_401(client):
    app.dependency_overrides.pop(get_current_user, None)
    
    headers = {"Authorization": "Bearer not.a.real.jwt"}
    
    # Test all 4 endpoints
    assert client.get("/api/v1/rules", headers=headers).status_code == 401
    assert client.get("/api/v1/health", headers=headers).status_code == 401
    assert client.post("/api/v1/rules", json={"rule": {}, "score": 90.0}, headers=headers).status_code == 401
    assert client.post("/api/v1/deployments", json={"rule_id": "1", "target_siem": "splunk", "confirmation_id": "1"}, headers=headers).status_code == 401

def test_expired_token_returns_401(client, monkeypatch):
    app.dependency_overrides.pop(get_current_user, None)
    
    # Create a mock expired token using pyjwt directly for testing
    import jwt
    import time
    
    # We can't easily sign a real token that Clerk's JWKS will validate, 
    # but we CAN mock the jwt.decode function just for this test to raise ExpiredSignatureError
    # to guarantee our exception handling catches it and returns 401.
    def mock_decode(*args, **kwargs):
        raise jwt.ExpiredSignatureError("Token has expired")
        
    def mock_get_unverified_header(*args, **kwargs):
        return {"kid": "mock_kid"}
        
    def mock_get_jwks(*args, **kwargs):
        return {"keys": [{"kid": "mock_kid", "kty": "RSA", "use": "sig", "n": "mock", "e": "AQAB"}]}
        
    def mock_get_rsa_public_key(*args, **kwargs):
        return b"mock_key"
        
    monkeypatch.setattr(jwt, "decode", mock_decode)
    monkeypatch.setattr(jwt, "get_unverified_header", mock_get_unverified_header)
    monkeypatch.setattr("saas.backend.api.auth.get_jwks", mock_get_jwks)
    monkeypatch.setattr("saas.backend.api.auth.get_rsa_public_key", mock_get_rsa_public_key)
    
    headers = {"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.mock"}
    
    # Test all 4 endpoints
    assert client.get("/api/v1/rules", headers=headers).status_code == 401
    assert client.get("/api/v1/health", headers=headers).status_code == 401
    assert client.post("/api/v1/rules", json={"rule": {}, "score": 90.0}, headers=headers).status_code == 401
    assert client.post("/api/v1/deployments", json={"rule_id": "1", "target_siem": "splunk", "confirmation_id": "1"}, headers=headers).status_code == 401
    
    # Restore override for future tests
    app.dependency_overrides[get_current_user] = override_get_current_user
