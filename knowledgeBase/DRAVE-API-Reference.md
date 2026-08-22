# DRAVE API Reference

This document provides a static reference for the DRAVE SaaS backend endpoints. 

**Base URL**: `https://drave-bfsi.onrender.com`
**Authentication**: All endpoints require a valid Clerk JWT passed in the `Authorization: Bearer <token>` header.

---

## Health

### `GET /api/v1/health`
**Purpose**: Fetch aggregate workspace health metrics for the authenticated tenant's dashboard.
**Auth Requirement**: Bearer Token (JWT)

**Request Shape**:
*No body required.*

**Response Shape** (200 OK):
```json
{
  "average_health": 95.5,
  "total_records": 12
}
```

---

## Rules

### `GET /api/v1/rules`
**Purpose**: Fetch all detection rules isolated to the authenticated tenant.
**Auth Requirement**: Bearer Token (JWT)

**Request Shape**:
*No body required.*

**Response Shape** (200 OK):
```json
[
  {
    "id": "uuid-string",
    "tenant_id": "user_id",
    "name": "Suspicious PowerShell Download",
    "description": "Detects usage of Net.WebClient",
    "severity": "high",
    "logic": "...",
    "version": 1
  }
]
```

### `POST /api/v1/rules`
**Purpose**: Ingest a new detection rule or update an existing one (upsert). Usually called by the CI/CD pipeline.
**Auth Requirement**: Bearer Token (JWT)

**Request Shape**:
```json
{
  "rule": {
    "id": "uuid-string",
    "name": "Suspicious PowerShell Download",
    "description": "Detects usage of Net.WebClient",
    "severity": "high",
    "logic": "..."
  },
  "score": 95.0
}
```

**Response Shape** (200 OK):
```json
{
  "id": "uuid-string",
  "tenant_id": "user_id",
  "name": "Suspicious PowerShell Download",
  "description": "Detects usage of Net.WebClient",
  "severity": "high",
  "logic": "...",
  "version": 1
}
```

---

## Deployments

### `POST /api/v1/deployments`
**Purpose**: Trigger a secure deployment of a detection rule to the target SIEM (Tier 3 action).
**Auth Requirement**: Bearer Token (JWT)

**Request Shape**:
```json
{
  "rule_id": "uuid-string",
  "target_siem": "splunk",
  "confirmation_id": "uuid-string" // Must match rule_id
}
```

**Response Shape** (200 OK):
```json
{
  "deployment_id": "uuid-string",
  "detection_id": "uuid-string",
  "tenant_id": "user_id",
  "git_commit": "HEAD",
  "version": 1,
  "target_siem": "splunk",
  "status": "pending | success | failed | rollback_failed",
  "requested_by": "user_id",
  "approved_by": "user_id",
  "reason": "API Triggered",
  "timestamp": "2026-08-22T00:00:00Z"
}
```
