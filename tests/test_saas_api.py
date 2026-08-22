import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, Session, create_engine
from typing import Generator

from saas.backend.api.main import app
from saas.backend.database import get_session
from saas.backend.models import RuleEntity, HealthRecord, DeploymentLog, Tenant
from core.detection.models import DetectionRule

from sqlalchemy.pool import StaticPool

# Create in-memory SQLite for testing to avoid contaminating Postgres
engine = create_engine(
    "sqlite://", 
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)

def get_session_override() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session

app.dependency_overrides[get_session] = get_session_override

@pytest.fixture(autouse=True)
def setup_db():
    SQLModel.metadata.create_all(engine)
    yield
    SQLModel.metadata.drop_all(engine)

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def sample_rule():
    return {
        "id": "11111111-1111-1111-1111-111111111111",
        "version": 1,
        "name": "Test Rule",
        "description": "Desc",
        "language": "sigma",
        "platform": "windows",
        "query": "title: Test Rule\nid: 11111111-1111-1111-1111-111111111111\nstatus: test\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        CommandLine|contains: 'mock_pattern'\n    condition: selection\nlevel: high",
        "severity": "high",
        "author": "Author",
        "created_at": "2025-01-01T00:00:00Z",
        "updated_at": "2025-01-01T00:00:00Z"
    }

def test_ingest_rule(client, sample_rule):
    response = client.post("/api/v1/rules", json={"rule": sample_rule, "score": 85.0})
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == sample_rule["id"]
    assert data["tenant_id"] == "tenant_1"

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
    # Ingest the rule first
    client.post("/api/v1/rules", json={"rule": sample_rule, "score": 100.0})
    
    # Try deploying with correct confirmation
    response = client.post("/api/v1/deployments", json={
        "rule_id": sample_rule["id"],
        "target_siem": "splunk",
        "confirmation_id": sample_rule["id"]
    })
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["success", "rollback_failed"] # Will be rollback_failed since we mocked smoke test to fail in adapters
    assert data["detection_id"] == sample_rule["id"]
    assert data["approved_by"] == "api_user@drave.local"
