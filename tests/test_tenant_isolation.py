import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, Session, create_engine
from sqlalchemy.pool import StaticPool
from typing import Generator

from saas.backend.api.main import app
from saas.backend.api.auth import get_current_user
from saas.backend.database import get_session



def test_cross_tenant_isolation(client, sample_rule):
    """
    Test that data isolation works for all protected endpoints.
    User A's data must be completely invisible to User B.
    """
    # -----------------------------
    # 1. Setup User A's Data
    # -----------------------------
    def override_user_a():
        return "user_A"
    app.dependency_overrides[get_current_user] = override_user_a
    
    # User A creates a rule with a health score of 90.0
    res_a_create = client.post("/api/v1/rules", json={"rule": sample_rule, "score": 90.0})
    assert res_a_create.status_code == 200
    
    # User A verifies health is 90.0
    res_a_health = client.get("/api/v1/health")
    assert res_a_health.status_code == 200
    assert res_a_health.json()["average_health"] == 90.0
    assert res_a_health.json()["total_records"] == 1
    
    # User A verifies their rule exists
    res_a_rules = client.get("/api/v1/rules")
    assert len(res_a_rules.json()) == 1
    assert res_a_rules.json()[0]["id"] == sample_rule["id"]
    
    # -----------------------------
    # 2. Switch to User B
    # -----------------------------
    def override_user_b():
        return "user_B"
    app.dependency_overrides[get_current_user] = override_user_b
    
    # -----------------------------
    # 3. Assert Isolation on Health
    # -----------------------------
    # User B should see 0 health because they have no records, not User A's 90.0!
    res_b_health = client.get("/api/v1/health")
    assert res_b_health.status_code == 200
    assert res_b_health.json()["average_health"] == 0.0
    assert res_b_health.json()["total_records"] == 0
    
    # -----------------------------
    # 4. Assert Isolation on Reads
    # -----------------------------
    # User B should see 0 rules
    res_b_rules = client.get("/api/v1/rules")
    assert len(res_b_rules.json()) == 0
    
    # -----------------------------
    # 5. Assert Isolation on Updates (PUT/POST logic)
    # -----------------------------
    # If User B tries to ingest the exact same rule ID (malicious override),
    # the 'existing' check in ingest_rule will yield None, so it will attempt to CREATE 
    # a new rule rather than overwriting User A's rule.
    # Because 'id' is a global primary key, this correctly triggers an IntegrityError (409 Conflict).
    res_b_malicious = client.post("/api/v1/rules", json={"rule": sample_rule, "score": 10.0})
    assert res_b_malicious.status_code == 409

    import copy
    sample_rule_b = copy.deepcopy(sample_rule)
    sample_rule_b["id"] = "22222222-2222-2222-2222-222222222222"
    
    # User B pushes a different valid rule
    res_b_create = client.post("/api/v1/rules", json={"rule": sample_rule_b, "score": 10.0})
    assert res_b_create.status_code == 200
    
    # Verify User B's health is now exactly 10.0 (not combined with A's 90.0)
    res_b_health2 = client.get("/api/v1/health")
    assert res_b_health2.json()["average_health"] == 10.0
    assert res_b_health2.json()["total_records"] == 1
    
    # -----------------------------
    # 6. Assert Isolation on Deployments
    # -----------------------------
    # Switch to User C (has no rules) and attempt to deploy the rule
    def override_user_c():
        return "user_C"
    app.dependency_overrides[get_current_user] = override_user_c
    
    res_c_deploy = client.post("/api/v1/deployments", json={
        "rule_id": sample_rule["id"],
        "target_siem": "splunk",
        "confirmation_id": sample_rule["id"]
    })
    # Since the global event scopes the query to user_C, the rule will not be found -> 404
    assert res_c_deploy.status_code == 404
    assert "Rule not found" in res_c_deploy.json()["detail"]
    
    # Cleanup overrides
    app.dependency_overrides.pop(get_current_user, None)
