# DRAVE Verified Status

This document is the authoritative handoff ledger for the current repository state. It reflects only what was directly observed from the repository, configuration files, local git history, and live access checks available in this environment. It is not a roadmap or a design doc.

---

## VERIFIED

### 1) The `drave-engine:1.0.0` image was published from commit `3b68172`, which is the actual README/Dockerfile fix commit.
- What was observed:
  - GitHub Actions page shows:
    - **Publish DRAVE Engine Image #1**: commit `582a383` — FAILED
    - **Publish DRAVE Engine Image #2**: tag `v1.0.0`, commit `3b68172` — GREEN/SUCCESSFUL
  - Commit `3b68172` is titled: `fix: copy README.md into Docker image (required by pyproject.toml)`
  - The publish workflow successfully built and pushed the image from `3b68172`.
  - Commit `99d3604` (HEAD) is a later optimization commit on `main`, not associated with the `v1.0.0` release run.
- Evidence:
  - Direct inspection of GitHub Actions history showing publish run #2 succeeded from `3b68172`
  - Local git log: `3b68172 (tag: v1.0.0) fix: copy README.md into Docker image (required by pyproject.toml)`
  - Local git log: `99d3604 (HEAD -> main, origin/main, origin/HEAD) fix: include README in action image build`
  - `git ls-remote https://github.com/Rushi19-04/DRAVE.git refs/tags/v1.0.0` returned `3b68172a32edc867be2d698a926c14f7171de70e refs/tags/v1.0.0`
- Date verified: 2026-09-02

### 2) Commit `99d3604` is a layer-optimization refactor, not a critical functional fix.
- What was observed:
  - **Dockerfile.action at `3b68172` (v1.0.0)**:
    - Line 18: `COPY pyproject.toml uv.lock ./`
    - Line 21: `RUN uv sync --no-dev --frozen --no-install-project`
    - Lines 23-30: Copy source directories (core/, adapters/, cli/, runner/, schemas/)
    - Line 34: `COPY README.md README.md` (separate COPY for README)
    - Line 36: `RUN uv sync --no-dev --frozen` (final install with README present)
  - **Dockerfile.action at `99d3604` (HEAD)**:
    - Line 18: `COPY pyproject.toml uv.lock README.md ./` (README bundled in first COPY)
    - Line 21: `RUN uv sync --no-dev --frozen --no-install-project`
    - Lines 23-30: Copy source directories
    - Line 33: `RUN uv sync --no-dev --frozen` (README already present from first COPY)
  - **Change**: `99d3604` optimizes Docker layer caching by moving README into the initial `COPY` statement (5 lines removed, 1 added; net -4 lines).
  - **Functional difference**: None. Both versions include README before the final `uv sync`. Both build successfully.
- Evidence:
  - Command: `git show 3b68172:Dockerfile.action` vs `git show 99d3604:Dockerfile.action`
  - Commit message: `99d3604` is titled "fix: include README in action image build" but is actually a reorganization of the existing README copy, not the introduction of the README fix.
  - GitHub Actions: `v1.0.0` published successfully from `3b68172` before `99d3604` existed.
- Date verified: 2026-09-02

### 3) The current published `drave-engine:1.0.0` image includes the README fix and was built from commit `3b68172` as evidenced by the successful GitHub Actions publish run.
- What was observed:
  - GitHub Actions history confirms the publish workflow ran successfully from `3b68172` (tagged `v1.0.0`).
  - The previous publish attempt from `582a383` (without README fix) failed.
  - The subsequent Docker layer optimization at `99d3604` is not present in the published `v1.0.0` image.
  - Conclusion: **The published `drave-engine:1.0.0` is not broken and does not need to be rebuilt or retagged.**
- Evidence:
  - GitHub Actions page showing publish run #2 GREEN from commit `3b68172`
  - Dockerfile diff analysis showing both versions have README, just organized differently
- Date verified: 2026-09-02

### 4) The reusable GitHub Action repository has remotely published tags `v1` and `v1.0.0`.
- What was observed:
  - `git ls-remote --tags https://github.com/Rushi19-04/drave-action.git` returned:
    - `b704fd3be6b80a406372b77bc013bbeab143209e refs/tags/v1`
    - `b704fd3be6b80a406372b77bc013bbeab143209e refs/tags/v1.0.0`
- Evidence:
  - Command run: `git ls-remote --tags https://github.com/Rushi19-04/drave-action.git`
  - Output shown above.
- Date verified: 2026-09-02

### 5) The current action definition points to the private engine image.
- What was observed:
  - [action/drave-action-repo/action.yml](action/drave-action-repo/action.yml) contains:
    - `runs.using: 'docker'`
    - `image: 'docker://ghcr.io/rushi19-04/drave-engine:1'`
- Evidence:
  - Direct file read of [action/drave-action-repo/action.yml](action/drave-action-repo/action.yml)
- Date verified: 2026-09-02

### 6) The GHCR engine package currently does not allow anonymous access.
- What was observed:
  - `docker manifest inspect ghcr.io/rushi19-04/drave-engine:1` returned:
    - `Get "https://ghcr.io/v2/rushi19-04/drave-engine/manifests/1": unauthorized`
  - `docker manifest inspect ghcr.io/rushi19-04/drave-engine:1.0.0` returned:
    - `unauthorized`
  - `docker manifest inspect ghcr.io/rushi19-04/drave-engine:latest` returned:
    - `unauthorized`
- Evidence:
  - Command run: `docker manifest inspect ghcr.io/rushi19-04/drave-engine:1` and equivalent for `1.0.0` and `latest`
  - Output included `unauthorized` for each tag.
- Date verified: 2026-09-02

### 7) The current DRAVE engine publish workflow file exists and is configured to build and push on version tags.
- What was observed:
  - [./.github/workflows/publish-engine.yml](.github/workflows/publish-engine.yml) defines a workflow named `Publish DRAVE Engine Image`.
  - Trigger: `push` on tags matching `v*`.
  - Job: `build-and-push` on `ubuntu-latest`.
  - It logs into GHCR with `docker/login-action` and pushes the image with Docker metadata tags.
- Evidence:
  - Direct file read of [./.github/workflows/publish-engine.yml](.github/workflows/publish-engine.yml)
- Date verified: 2026-09-02

### 8) The current Dockerfile builds the engine image by copying the project source and includes the README file before sync.
- What was observed:
  - [Dockerfile.action](Dockerfile.action) contains:
    - `COPY pyproject.toml uv.lock README.md ./`
    - `RUN uv sync --no-dev --frozen --no-install-project`
    - followed by copying `core/`, `adapters/`, `cli/`, `runner/`, and `schemas/`
- Evidence:
  - Direct file read of [Dockerfile.action](Dockerfile.action)
- Date verified: 2026-09-02

### 9) The current SaaS database initialization is not using Alembic migrations.
- What was observed:
  - [saas/backend/database.py](saas/backend/database.py) calls `SQLModel.metadata.create_all(engine)` and then manually executes:
    - `ALTER TABLE ruleentity ADD COLUMN IF NOT EXISTS evidence_report JSON;`
- Evidence:
  - Direct file read of [saas/backend/database.py](saas/backend/database.py)
- Date verified: 2026-09-02

### 10) The UI intentionally disables direct "Create Rule" authoring.
- What was observed:
  - [saas/frontend/src/components/Dashboard.tsx](saas/frontend/src/components/Dashboard.tsx) shows the `New Rule` button as disabled.
  - The tooltip states: `UI Authoring Disabled` and says rules must be authored via Git and opened in a PR.
- Evidence:
  - Direct file read of [saas/frontend/src/components/Dashboard.tsx](saas/frontend/src/components/Dashboard.tsx)
- Date verified: 2026-09-02

### 11) The current database schema includes `Tenant`, `RuleEntity`, `HealthRecord`, `DeploymentLog`, and `CIApiKey`.
- What was observed:
  - [saas/backend/models.py](saas/backend/models.py) defines these models directly.
- Evidence:
  - Direct file read of [saas/backend/models.py](saas/backend/models.py)
- Date verified: 2026-09-02

### 12) The current API endpoint `POST /api/v1/rules` upserts by `RuleEntity.id` and attaches `evidence_report` JSON.
- What was observed:
  - [saas/backend/api/routes.py](saas/backend/api/routes.py) defines `ingest_rule` and does:
    - `existing = session.exec(select(RuleEntity).where(RuleEntity.id == payload.rule.id)).first()`
    - then updates or inserts `RuleEntity`
    - then creates `HealthRecord`
- Evidence:
  - Direct file read of [saas/backend/api/routes.py](saas/backend/api/routes.py)
- Date verified: 2026-09-02

---

## IMPLEMENTED / UNVERIFIED

This is the category for code that exists but whose full end-to-end behavior has not been demonstrated in this environment.

### 1) The full publication path from `Rushi19-04/DRAVE` to GHCR image push is implemented in code and workflow files, but live workflow run status is not directly observed here.
- Code evidence:
  - [.github/workflows/publish-engine.yml](.github/workflows/publish-engine.yml)
  - [Dockerfile.action](Dockerfile.action)
- Why unverified:
  - Real GitHub Actions run history was not directly inspectable from this environment; the public API for the repo returned 404 from the external environment, and no GHCR auth was available in this environment.
- Date verified: 2026-09-02

### 2) The reusable action implementation and current tag wiring exist, but the real external repo execution chain has not been run here.
- Code evidence:
  - [action/drave-action-repo/action.yml](action/drave-action-repo/action.yml)
  - [action/entrypoint.sh](action/entrypoint.sh)
  - [action/drave-action-repo/README.md](action/drave-action-repo/README.md)
- Why unverified:
  - The end-to-end customer repo → action → private GHCR → engine → API dashboard chain was not executed in this environment.
- Date verified: 2026-09-02

### 3) The SaaS API and dashboard are implemented, but the live external customer repo integration has not been demonstrated.
- Code evidence:
  - [saas/backend/api/main.py](saas/backend/api/main.py)
  - [saas/backend/api/routes.py](saas/backend/api/routes.py)
  - [saas/frontend/src/components/Dashboard.tsx](saas/frontend/src/components/Dashboard.tsx)
- Why unverified:
  - No live external repository was connected and no customer workflow was run against it in this environment.
- Date verified: 2026-09-02

---

## PARTIAL

### 1) The engine packaging and action composition appear correct in code, but live GHCR publication and external execution remain unproven.
- Proven:
  - fix commit exists
  - workflow file exists
  - Dockerfile contains README fix
  - tags exist in action repo
  - private GHCR denies anonymous pull
- Missing:
  - live run confirmation on GitHub Actions
  - actual push confirmation on GHCR
  - successful pull from a real external repo
- Date verified: 2026-09-02

### 2) The current SaaS database model supports rule ingestion and evidence persistence, but it is not yet a GitHub-driven repository inventory model.
- Proven:
  - `RuleEntity` supports storage of a rule plus `evidence_report`
  - `HealthRecord` stores score history
  - `DeploymentLog` stores deployment state
- Missing:
  - repository linkage
  - rule identity continuity across rename/move/delete
  - validation run lifecycle as a first-class concept
  - rule version lineage
- Date verified: 2026-09-02

---

## KNOWN GAPS

1) No Alembic migrations are present.
- Direct evidence: [saas/backend/database.py](saas/backend/database.py) executes raw SQL `ALTER TABLE ...` with no migration history.
- Date verified: 2026-09-02

2) The UI path for direct rule authoring is intentionally disabled and not replaced with a Draft-to-PR flow.
- Direct evidence: [saas/frontend/src/components/Dashboard.tsx](saas/frontend/src/components/Dashboard.tsx) disables the `New Rule` button and shows the message: `UI Authoring Disabled`.
- The requirement states: `Create Rule UI bypassing CI/CD pipeline — disabled but not replaced with the Draft-to-PR flow`.
- This gap remains open.
- Date verified: 2026-09-02

3) There is no live repository inventory model yet for GitHub source-of-truth reconciliations.
- Direct evidence: no repository or GitHub inventory tables were found in [saas/backend/models.py](saas/backend/models.py).
- Date verified: 2026-09-02

4) There is no direct, observed live dashboard/Render deployment status in this environment.
- Direct evidence: `Invoke-WebRequest https://drave-bfsi.onrender.com/health` timed out in this environment.
- Date verified: 2026-09-02

5) There is no direct, observed GitHub Actions tab status for the publish workflow in this environment.
- Direct evidence: the GitHub API repo endpoint returned 404 from the external environment, and no browser-based Actions tab inspection was available in this environment.
- Date verified: 2026-09-02

---

## BLOCKED

### 1) Live GitHub Actions workflow verification is blocked.
- What was observed:
  - The GitHub API endpoint for the repo returned `404` from this environment.
  - The workflow tab was not directly inspectable here.
- Status:
  - BLOCKED — cannot verify the actual latest GitHub Actions run status or job result in this environment.
- Evidence:
  - `Invoke-RestMethod` against `https://api.github.com/repos/Rushi19-04/DRAVE` returned `404`.
  - The workflow URL and repo API cannot be confirmed live from this environment.
- Date verified: 2026-09-02

### 2) Live Render deployment status is blocked.
- What was observed:
  - `Invoke-WebRequest https://drave-bfsi.onrender.com/health` timed out.
- Status:
  - BLOCKED — cannot verify the live SaaS API health or deployment availability from this environment.
- Evidence:
  - Render health request timed out.
- Date verified: 2026-09-02

### 3) Live Vercel dashboard status is blocked.
- What was observed:
  - The Vercel frontend was not directly inspected in this environment.
- Status:
  - BLOCKED — cannot verify the live dashboard state from this environment.
- Date verified: 2026-09-02

---

## CURRENT MILESTONE

### Milestone 1: verify the end-to-end external repo integration path

This milestone is explicitly defined as the end-to-end chain:
- external customer repository
- GitHub Action
- private DRAVE engine
- rule validation
- DRAVE SaaS API
- results/evidence
- dashboard visibility

Definition of Done (from the current milestone statement): complete the full 8-step path from external repo → dashboard without altering the core product architecture.

This is not yet met in the live environment.

---

## NEXT ACTION

Exactly one next action:
- Open the actual GitHub Actions workflow page for the DRAVE engine repo and confirm the latest publish run status and GHCR push result before proceeding with any GHCR or external repo test work.

This is the next action because direct live workflow verification is the prerequisite that determines whether GHCR/package access and external Action validation can be trusted.

---

## EVIDENCE LOG

### Entry 1 — 2026-09-02
- What was tested:
  - Local repo history around the README fix and Docker packaging.
- Expected result:
  - Current repo should show fix commit and tag.
- Actual result:
  - `git log` showed `99d3604 fix: include README in action image build` and `3b68172 fix: copy README.md into Docker image (required by pyproject.toml)`.
- Evidence/reference:
  - Command run: `git -C "c:/Users/rushi/OneDrive/Desktop/DRAVE" log --decorate --oneline -n 5 -- .github/workflows/publish-engine.yml Dockerfile.action README.md`
- Status: VERIFIED

### Entry 2 — 2026-09-02
- What was tested:
  - Current local repo tags.
- Expected result:
  - `v1.0.0` should exist.
- Actual result:
  - Output: `v1.0.0`
- Evidence/reference:
  - Command run: `git -C "c:/Users/rushi/OneDrive/Desktop/DRAVE" tag -l --list 'v*'`
- Status: VERIFIED

### Entry 3 — 2026-09-02
- What was tested:
  - External action repo tags.
- Expected result:
  - `v1` and `v1.0.0` should exist remotely.
- Actual result:
  - Output included both tag refs to the same commit.
- Evidence/reference:
  - Command run: `git ls-remote --tags https://github.com/Rushi19-04/drave-action.git`
- Status: VERIFIED

### Entry 4 — 2026-09-02
- What was tested:
  - Anonymous access to the GHCR package.
- Expected result:
  - Private package should deny anonymous access.
- Actual result:
  - `docker manifest inspect` returned `unauthorized` for `:1`, `:1.0.0`, and `:latest`.
- Evidence/reference:
  - Command output captured from `docker manifest inspect ghcr.io/rushi19-04/drave-engine:1` and similar.
- Status: VERIFIED

### Entry 5 — 2026-09-02
- What was tested:
  - Render health endpoint.
- Expected result:
  - Live API should respond successfully.
- Actual result:
  - HTTP request timed out.
- Evidence/reference:
  - `Invoke-WebRequest https://drave-bfsi.onrender.com/health` timed out.
- Status: BLOCKED

### Entry 6 — 2026-09-02
- What was tested:
  - GitHub API repository visibility for `Rushi19-04/DRAVE`.
- Expected result:
  - Repo metadata and workflow list should be queryable.
- Actual result:
  - `Invoke-RestMethod` returned `404`.
- Evidence/reference:
  - GitHub API call to `https://api.github.com/repos/Rushi19-04/DRAVE` and workflow list endpoint returned `404 Not Found`.
- Status: BLOCKED

### Entry 7 — 2026-09-02
- What was tested:
  - Database initialization migration practices.
- Expected result:
  - Formal migration system should be present if production-safe schema evolution is in place.
- Actual result:
  - [saas/backend/database.py](saas/backend/database.py) uses `create_all` plus raw SQL ALTER, with no migration history.
- Evidence/reference:
  - Direct file read of [saas/backend/database.py](saas/backend/database.py)
- Status: VERIFIED

### Entry 8 — 2026-09-02
- What was tested:
  - Direct UI authoring path.
- Expected result:
  - Create Rule should be available if UI authoring is enabled.
- Actual result:
  - Button is disabled and the tooltip says `UI Authoring Disabled`.
- Evidence/reference:
  - Direct file read of [saas/frontend/src/components/Dashboard.tsx](saas/frontend/src/components/Dashboard.tsx)
- Status: VERIFIED

### Entry 9 — 2026-09-02
- What was tested:
  - Current rules API model and evidence persistence.
- Expected result:
  - The API should create or update a rule and store evidence JSON.
- Actual result:
  - [saas/backend/api/routes.py](saas/backend/api/routes.py) upserts by `RuleEntity.id` and stores `payload.evidence` to `existing.evidence_report` or new `RuleEntity`.
- Evidence/reference:
  - Direct file read of [saas/backend/api/routes.py](saas/backend/api/routes.py)
- Status: VERIFIED

---

This document reflects the current truth state only. It is the authoritative handoff ledger until a live GitHub workflow or live deployment is directly observed from the environment that has access to those services.
