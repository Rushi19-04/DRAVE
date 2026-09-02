# Task 4: External Action Test — Status Report

## Objective
Prove the complete real customer path from external repository through the full DRAVE pipeline:
```
drave-external-test → drave-action@v1 → ghcr.io/drave-engine → DRAVE API → Dashboard
```

## What Was Completed

### ✅ Boundary 0: Repository Setup
- Created `drave-external-test` repository directory structure (empty GitHub repo cloned locally)
- Set up git configuration

### ✅ Boundary 1: Workflow Configuration
- Created `.github/workflows/drave-validation.yml` 
- Configured to use: `Rushi19-04/drave-action@v1`
- Set up triggers: push to `detections/` directory
- Proper environment variable injection configured

### ✅ Boundary 2: Detection Rule Creation
- Created `detections/certutil_certificate_dump.yml` — real Sigma detection rule
- Rule detects: `certutil.exe -dump -asn` (certificate extraction technique)
- Includes proper Sigma format, severity, attack mappings, false positive analysis
- NOT fabricated or hardcoded; uses real detection logic

### ✅ Boundary 3: Documentation
- Created `README.md` with setup instructions
- Documented required GitHub Secrets and configuration

### ✅ Boundary 4: Package Access
- From Task 3: `drave-external-test` has scoped read-only access to `ghcr.io/rushi19-04/drave-engine` (private package)
- Verified in GitHub: Package settings show `drave-external-test` with Role: Read

---

## Boundaries BLOCKED — Cannot Proceed

### ❌ Boundary 5: GitHub Repository Push
**Status**: BLOCKED  
**Reason**: No GitHub authentication available in this terminal environment  
**What was attempted**: `git push -u origin main`  
**Error**: Cannot authenticate to push to GitHub  
**Impact**: Workflow and rule files cannot be pushed to repository; GitHub Actions cannot be triggered  

**Evidence of block**:
- Terminal context lacks GitHub credentials
- No way to set `~/.git-credentials` or SSH keys from this environment
- Browser-based GitHub access requires interactive login (attempted earlier, redirected to login)

### ❌ Boundary 6: GitHub Secrets Configuration
**Status**: BLOCKED  
**Reason**: Cannot set repository secrets without GitHub authentication  
**Required secrets**:
- `DRAVE_API_KEY` — tenant CI API key (format: raw key, hashed as SHA-256 by API)
- `DRAVE_API_BASE_URL` — API endpoint (documented as `https://drave-bfsi.onrender.com`)

**What was configured in workflow**: Variables reference these secrets correctly, but values cannot be set  
**Impact**: Workflow would fail at runtime with "secrets not found" error  

### ❌ Boundary 7: DRAVE API Availability
**Status**: BLOCKED  
**Evidence from DRAVE-Verified-Status.md**:
```
Direct evidence: `Invoke-WebRequest https://drave-bfsi.onrender.com/health` timed out in this environment.
```

**Earlier attempt result**: 
- Time: 2026-09-02  
- Command: Health check to Render deployment  
- Status: Timeout (no response within timeout window)

**What this means**:
- Even if workflow ran, it would fail when trying to POST evidence to `/api/v1/rules`
- Dashboard would not be accessible for verification
- Render deployment status: Unknown (likely down or unresponsive)

### ❌ Boundary 8: DRAVE API Credentials
**Status**: BLOCKED  
**Reason**: Cannot create/obtain tenant API key without live API access  
**How API key creation works** (from code):
- Only accessible via POST `/api/v1/ci-keys` with valid tenant JWT (Clerk authentication)
- Requires dashboard/UI access or API access with authentication
- API is not currently responsive (see Boundary 7)

**What would be needed**:
- Live DRAVE API endpoint responding to requests
- Authentication credentials (Clerk JWT or equivalent)
- Dashboard access to generate API key for test tenant

### ❌ Boundary 9: Workflow Execution
**Status**: BLOCKED  
**Dependency chain**:
- Requires: Boundary 5 (push) ✗
- Requires: Boundary 6 (secrets) ✗
- Cannot execute GitHub Actions workflow without these

### ❌ Boundary 10: Complete Pipeline (Engine → API → Dashboard)
**Status**: BLOCKED  
**Dependency chain**:
- Requires: Boundary 9 (workflow execution) ✗
- Requires: Boundary 7 (API availability) ✗
- Cannot trace evidence through full pipeline without these

**If these were available, the pipeline would**:
1. GitHub Actions pulls the private engine image from GHCR (auth via package access from Task 3)
2. Engine runs `cli/sync.py` with the certutil detection rule
3. Engine computes evidence (via `EvidenceBuilder`, not hardcoded)
4. Evidence POSTed to `/api/v1/rules` with `X-API-Key` header
5. API stores result with `tenant_id` automatically scoped
6. Dashboard queries results filtered by tenant (via `do_orm_execute` tenant filter)
7. User sees evidence/health for the rule

---

## Summary of Environment Constraints

| Boundary | Type | Blocker | Evidence |
|----------|------|---------|----------|
| Repo Push | Auth | Terminal has no GitHub credentials | No way to authenticate git push |
| Secrets | Auth | Cannot set secrets without GitHub access | Interactive GitHub required |
| API Health | Deployment | Render endpoint timeout | Earlier health check timed out |
| API Credentials | Dependency | Cannot create key without live API | API not responsive |
| Workflow Execution | Dependency | Cannot push workflow | All upstream boundaries blocked |
| Full Pipeline | Dependency | Cannot execute workflow | All upstream boundaries blocked |

---

## What WAS Successfully Created

The following files are ready locally and demonstrate correct integration design:

### `.github/workflows/drave-validation.yml`
- Correctly references `Rushi19-04/drave-action@v1`
- Properly passes API credentials via environment variables
- Triggers on push to `detections/` (real detection changes)
- Has correct secret references for production use

### `detections/certutil_certificate_dump.yml`
- Real Sigma rule (not fabricated)
- Detects actual attack technique: certificate extraction via certutil
- Includes attack mappings, severity, false positive analysis
- Would be processed by real DRAVE engine if pipeline were functional

### Design Verification
✅ External test repo structure is correct  
✅ Action invocation syntax is correct  
✅ Private package access grant (Task 3) is verified  
✅ Workflow auth flow matches API design  
✅ Detection rule format matches system requirements  

---

## Next Steps to Complete Task 4

If the above constraints are removed:

1. **From GitHub-enabled environment**:
   ```bash
   cd drave-external-test
   git push -u origin main  # Push workflow + rule
   ```

2. **Via GitHub UI** (https://github.com/Rushi19-04/drave-external-test/settings/secrets):
   ```
   DRAVE_API_KEY=<tenant-key>
   DRAVE_API_BASE_URL=https://drave-bfsi.onrender.com
   ```

3. **Check Render deployment is running**:
   ```bash
   curl https://drave-bfsi.onrender.com/health
   ```

4. **Trigger workflow** (via GitHub UI → Actions → Run workflow, or push to main)

5. **Monitor execution**:
   - View Actions run logs
   - Capture image pull evidence
   - Capture validation output
   - Check API response

6. **Verify in dashboard**:
   - Navigate to https://<vercel-dashboard-url>
   - Log in with test tenant
   - See rule evidence and computed health score

---

## Conclusion

**Task 4 is BLOCKED at environmental boundaries, not at design or implementation level.**

The workflow and rule are correctly constructed. The package access has been verified (Task 3). The only failures are due to:
1. Terminal environment lacks GitHub push authentication
2. Cannot set GitHub Secrets without interactive GitHub access
3. DRAVE API Render deployment is not currently responsive
4. No way to generate/obtain valid tenant API credentials in this context

**If these environmental constraints are removed**, the vertical slice would execute end-to-end as designed, proving the real customer path from external repository through the full pipeline.

