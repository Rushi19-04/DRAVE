import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from saas.backend.api.main import app
from saas.backend.api.main import app
from saas.backend.api.auth import get_current_user
from saas.backend.database import get_session, engine

client = TestClient(app)

def mock_get_unverified_header(token):
    return {"kid": "test-kid"}

def mock_jwt_decode(token, *args, **kwargs):
    if token == "token_a":
        return {"sub": "tenant_a"}
    elif token == "token_b":
        return {"sub": "tenant_b"}
    raise Exception("Invalid token")

@patch("saas.backend.api.auth.jwt.get_unverified_header", side_effect=mock_get_unverified_header)
@patch("saas.backend.api.auth.jwt.decode", side_effect=mock_jwt_decode)
@patch("saas.backend.api.auth.get_jwks", return_value={"keys": [{"kid": "test-kid", "kty": "RSA", "use": "sig", "n": "dummy", "e": "AQAB"}]})
@patch("saas.backend.api.auth.get_rsa_public_key", return_value="dummy_key")
def test_api_key_lifecycle_and_tenant_isolation(mock_pk, mock_jwks, mock_decode, mock_header):
    # Clear any global overrides leaked from other test files
    app.dependency_overrides.pop(get_current_user, None)
    
    # 1. Tenant A generates a key
    resp = client.post("/api/v1/ci-keys", json={"label": "GitHub Actions A"}, headers={"Authorization": "Bearer token_a"})
    assert resp.status_code == 200
    key_data = resp.json()
    assert "raw_key" in key_data
    assert key_data["raw_key"] is not None
    assert key_data["label"] == "GitHub Actions A"
    raw_key = key_data["raw_key"]
    key_id = key_data["id"]

    # 2. Check the key list (raw_key should be None)
    resp = client.get("/api/v1/ci-keys", headers={"Authorization": "Bearer token_a"})
    assert resp.status_code == 200
    keys = resp.json()
    assert len(keys) == 1
    assert keys[0]["id"] == key_id
    assert keys[0]["raw_key"] is None

    # 3. Use the raw key via unauth client to ingest a rule
    rule_payload = {
        "rule": {
            "id": "det-api-key-test",
            "name": "API Key Test Rule",
            "description": "Test",
            "language": "sigma",
            "platform": "windows",
            "query": "title: API Key Test",
            "severity": "low",
            "author": "ci",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
            "tags": [],
            "attack_mappings": []
        },
        "score": 1.0
    }
    resp = client.post(
        "/api/v1/rules", 
        json=rule_payload, 
        headers={"X-API-Key": raw_key}
    )
    assert resp.status_code == 200
    rule_resp = resp.json()
    # It must have been ingested as tenant_a
    assert rule_resp["tenant_id"] == "tenant_a"

    # 4. Verify cross-tenant isolation
    # Tenant A should see it
    resp_a = client.get("/api/v1/rules", headers={"Authorization": "Bearer token_a"})
    assert any(r["id"] == "det-api-key-test" for r in resp_a.json())
    
    # Tenant B should NOT see it
    resp_b = client.get("/api/v1/rules", headers={"Authorization": "Bearer token_b"})
    assert not any(r["id"] == "det-api-key-test" for r in resp_b.json())

    # 5. Revoke the key
    resp = client.delete(f"/api/v1/ci-keys/{key_id}", headers={"Authorization": "Bearer token_a"})
    assert resp.status_code == 200

    # 6. Verify revoked key fails
    resp = client.post(
        "/api/v1/rules", 
        json=rule_payload, 
        headers={"X-API-Key": raw_key}
    )
    assert resp.status_code == 401
    assert "Invalid or revoked API Key" in resp.json()["detail"]

    # 7. Invalid random key fails
    resp = client.post(
        "/api/v1/rules", 
        json=rule_payload, 
        headers={"X-API-Key": "completely_wrong_key"}
    )
    assert resp.status_code == 401
