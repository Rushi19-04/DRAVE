# DRAVE — Phase 2 Roadmap
### Hardening the Tech Before Product, Before Clients

**Companion to:** `DRAVE-Knowledge-Base.md`, `DRAVE-Build-Blueprint.md`, `ARCHITECTURE.md`, `AGENTS.md`, `DRAVE-Approval-Policy.md`.

**Where this fits:** The original 70-step blueprint (Stages 1–18) is complete and verified — local core, real GitHub CI, real Splunk-shaped adapter, real Postgres-backed API, real Tier 3 safety gates. Auth was **deliberately mocked** in Stage 18 to keep that phase scoped. Phase 2 is not a continuation of the 70 steps — it's the next deliberate phase: **Tech → Product → Clients**. This document covers **Tech** only. Product (UI redesign, onboarding) and Clients (design partners) are separate future documents, written once Phase 2 is done.

**Guiding principle, unchanged from Phase 1:** every stage here still follows the same discipline that caught real bugs across Stages 1–18 — state a plan, wait for real approval, show real terminal output as proof, flag your own deviations, never let a completion claim substitute for verification. `AGENTS.md` and `DRAVE-Approval-Policy.md` apply exactly as before, with one addition: **this phase touches real user data and real secrets for the first time**, so Tier 2/3 scrutiny should if anything be tighter here than it was in Phase 1.

---

## 1. Why Phase 2 Exists

Stage 18 proved the *mechanism* works: a real deployment request, gated by a real Tier 3 confirmation, hit a real API, and landed a real row in Postgres. But it proved this with **one hardcoded fake user** (`api_user@drave.local`) and **one hardcoded fake tenant** (`tenant_1`) that nothing actually enforces. That's correct for a prototype. It is not correct for a system a second real person will ever log into.

Phase 2 closes exactly these gaps:

| Gap today | Risk if shipped as-is |
|---|---|
| Auth is mocked — no real login | Anyone with API access can act as anyone |
| `tenant_id` is a trusted request field | Any caller can read/write another tenant's data by just changing a field |
| Everything runs on your laptop | No one else can reach it; dies when your machine sleeps |
| Secrets (DB password, future SIEM creds) live in local `.env`/Docker config | Not survivable or auditable once hosted |
| Splunk adapter has only ever talked to a mock | Unknown whether real SPL compiled by `pySigma-backend-splunk` actually deploys/executes correctly against a real Splunk instance |

---

## 2. Phase 2 Stages

### Stage 19 — Real Authentication

**Goal:** Replace the mocked `api_user@drave.local` with real user accounts, with sessions/tokens tied to an actual identity.

**Decision to make first (open question for the agent to present, not decide):** managed auth provider (e.g. Clerk, Auth0, Supabase Auth) vs. rolling your own JWT auth.
- **Recommended default: managed provider.** Rolling your own auth means you own password hashing, session security, token rotation, and account-recovery flows — all high-consequence to get wrong, and all solved problems a managed provider gives you in hours instead of weeks. Revisit only if there's a specific reason (cost at scale, specific compliance requirement) once there are real paying customers.

**Build:**
- Integrate chosen provider into `saas/backend/api/main.py` — replace the mock-auth dependency with real session/token verification.
- Every API endpoint that currently trusts a client-supplied identity must instead derive identity from the verified session/token.
- Frontend: real login/signup screens, replacing the current no-auth dashboard access.

**Verification:**
- A request with no valid session is rejected (401) at every protected endpoint — test this explicitly, not just the happy path.
- A request with a valid session for User A cannot read/act on data belonging to User B (this overlaps with Stage 20's tenant test, but auth-level rejection should be tested independently first).

---

### Stage 20 — Real Tenant Isolation

**Goal:** `tenant_id` must be derived from the authenticated user, never trusted from request input, and every database query must be scoped by it automatically.

**Build:**
- Remove `tenant_id` as a client-writable field on any request body (rules ingestion, deployments, health queries).
- Derive it server-side from the authenticated session (e.g. user → tenant mapping in the DB).
- Add a query-scoping layer (e.g. a dependency/middleware in FastAPI) so every SQLModel query is automatically filtered by the caller's tenant — not left to each route handler to remember to add a `WHERE tenant_id = ...` clause by hand, which is exactly the kind of thing that gets silently forgotten in one endpoint later.

**Verification — this is the most important test in this entire phase:**
- Create two real accounts, two real tenants, seed each with a distinct rule.
- Log in as Tenant A. Attempt to read, modify, and deploy Tenant B's rule (via the API directly, not just the UI, since the UI hides options the API might still allow).
- **Every one of those attempts must fail.** Show the real HTTP responses proving it. This test needs to exist permanently in the automated suite, not just be run once by hand — tenant isolation is the kind of thing that silently breaks when someone adds a new endpoint later and forgets the scoping.

---

### Stage 21 — Secrets Management

**Goal:** No real secret (DB password, future SIEM API keys/tokens, auth provider keys) lives in a local `.env` file or committed config once this is meant to run somewhere real.

**Build:**
- Move secrets to a proper secrets manager appropriate to the eventual hosting choice (e.g. environment variables injected by the hosting platform, or a dedicated secrets service — decide alongside Stage 22's hosting choice, don't decide in isolation).
- Confirm `.gitignore` already excludes `.env` (check now — this should already be true, but verify explicitly rather than assuming).
- Rotate the current local Postgres password before this goes anywhere beyond your machine, since it's been sitting in a local file this whole build.

**Verification:**
- `git log` and `git grep` across the full repo history for anything that looks like a real secret ever having been committed. If Stage 1–18's history has one, it needs rotation regardless of whether the file was later removed — git history keeps it.

---

### Stage 22 — Real Hosting

**Goal:** The API, database, and dashboard run somewhere reachable on the internet, not on your laptop.

**Open questions for the agent to present, not decide:**
- Hosting target (a simple VPS like DigitalOcean/Hetzner vs. a managed platform like Railway/Render vs. full cloud like AWS/GCP) — recommend starting simple; this doesn't need to be sophisticated to prove the concept to design partners.
- Whether Postgres is self-hosted alongside the API or a managed database service (managed is usually worth the small cost at this stage — one less thing to operate).
- Domain name and HTTPS (a real cert, not self-signed) — required before any real login flow, since auth tokens over plain HTTP are not acceptable even for a prototype with real users.

**Build:**
- Containerize the FastAPI app properly for deployment (a production `Dockerfile`, not just local `docker-compose`).
- Set up CI to build and deploy on merge to `main` (this can reuse patterns from Stage 16's GitHub Action, extended with a deploy step) — but this deploy pipeline is separate from, and must not be confused with, the SIEM-deployment pipeline from Stage 17. Naming should make this distinction unambiguous in the code and docs.

**Verification:**
- Access the dashboard from a device that is not your development machine (phone, different network) to confirm it's genuinely reachable, not just "works because I'm on the same network as the container."

---

### Stage 23 — Real Splunk Integration Test

**Goal:** Prove the Splunk adapter built in Stage 17 works against an actual Splunk instance, not just a mocked network boundary.

**Why this matters now, not later:** every "deployment successful" result you've seen so far is a mock returning success. Real Splunk has real authentication quirks, real API rate limits, real SPL syntax edge cases that `pySigma-backend-splunk` might not perfectly cover. Finding this out before a design partner tries it live is much cheaper than finding out during their onboarding.

**Build:**
- Get access to a Splunk free trial or developer instance.
- Run the existing `drave deploy` flow against it for real — same Tier 3 confirmation gate, same manifest logging, but hitting a real `splunklib.client.connect()` instead of the mock.

**Verification:**
- A real rule deploys and is visible in the real Splunk instance's saved searches.
- The real smoke test (Step 66) actually queries real Splunk and gets a real result.
- Deliberately break a rule and confirm the real automated rollback (Step 67) actually reverts it in the real instance, not just in the mocked test suite.

---

## 3. Order and Dependencies

```
Stage 19 (Auth) → Stage 20 (Tenant Isolation)   [20 depends on 19 — can't scope by tenant without knowing who's logged in]
                → Stage 21 (Secrets)             [independent, can run in parallel with 19/20]
Stage 19+20+21  → Stage 22 (Hosting)             [don't host something with no real auth/isolation/secrets story]
Stage 22        → Stage 23 (Real Splunk)         [optional to sequence before hosting, but cheaper to test once, for real, after the environment is stable]
```

Do not skip ahead to Stage 22 (hosting) before Stages 19–21 are done and verified — putting a mocked-auth, trust-the-client-tenant-id system on the public internet is a real security exposure, not just an engineering shortcut.

---

## 4. What Comes After Phase 2

Once Stage 19–23 are done and verified with the same rigor as Phase 1: **Phase 3 (Product)** — UI redesign, onboarding flow, error handling, documentation — and then **Phase 4 (Clients)** — 1–2 design partners before any paying customer. Those get their own roadmap documents once Phase 2 is actually closed, not before.
