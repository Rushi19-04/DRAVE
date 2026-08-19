# AGENTS.md — DRAVE

Instructions for any AI coding agent (Claude Code, Antigravity, Cursor, Copilot Workspace, etc.) working in this repository.

> **Full approval rules live in `DRAVE-Approval-Policy.md`. This file is the entry point every agent should read first — treat the policy doc as binding, not optional guidance.**

---

## 1. Project Overview

DRAVE (Detection Rule Analysis, Versioning, and Evaluation) is a detection engineering platform. See `DRAVE-Knowledge-Base.md` for product concepts and `DRAVE-Build-Blueprint.md` for architecture and build order.

Stack: Python 3.11+, uv, Typer, Pydantic v2, pySigma, FastAPI, SQLModel, PostgreSQL, Arq/Redis. Dashboard: React + TypeScript.

---

## 2. Setup Commands

```bash
uv sync
uv run pytest
uv run python cli/main.py test
```

---

## 3. Code Style

- Format/lint with `ruff` — run `uv run ruff check .` and `uv run ruff format .` before finishing any change.
- Type-check with `mypy` — `uv run mypy core adapters cli api`.
- All new modules use Pydantic v2 models for data shapes; no bare dicts crossing module boundaries.
- Detection rules and test fixtures are YAML under `detections/`; never hand-edit generated JSON results.

---

## 4. Testing Instructions

- Run `uv run pytest` for DRAVE's own codebase tests.
- Run `uv run python cli/main.py test` to exercise the detection Test Runner against fixtures — this is a *different* test system (it tests detection rules, not Python code). Don't conflate the two.
- Any change to `core/`, `adapters/`, or `cli/` must keep both test suites green before being proposed.

---

## 5. Approval / Autonomy Boundaries — READ THIS

This repository follows a **tiered autonomy model**. Before taking any action, classify it:

| Tier | Meaning | Agent behavior |
|---|---|---|
| 🟢 **Autonomous** | Safe, reversible, local-only | Do it, then report what you did |
| 🟡 **Ask-first** | Reversible but consequential, or touches shared state | Stop, describe the exact action, wait for explicit "yes/approved/go ahead" |
| 🔴 **Never without named human sign-off** | Irreversible, production-impacting, security/credential-sensitive | Do not do it even if asked casually — require an explicit, unambiguous approval statement, and log it |

**The full classification table is in `DRAVE-Approval-Policy.md`.** When in doubt, treat the action as 🟡 at minimum. Never upgrade your own confidence from 🟡 to 🟢 to save a round-trip.

Quick reference — always ask first, no exceptions:
- Anything that deploys, rolls back, or otherwise touches a real SIEM or production environment
- `git push` to `main`/production branches, force-push, branch deletion, history rewrite
- Merging a PR
- Installing new dependencies not already in `pyproject.toml`
- Deleting files, dropping DB tables/columns, running migrations against non-local databases
- Touching secrets, credentials, `.env` files, or CI/CD secret configuration
- Changing volume policies, hard gates, or approval/CI logic itself

---

## 6. PR Instructions

- One logical change per PR. Title format: `[phase-x] short description` (e.g. `[phase-a] add sigma in-memory adapter`).
- Include the DRAVE Evidence Report output in the PR description where applicable (Syntax/Schema/Unit/Regression/Attack/Robustness/Volume/ATT&CK).
- Do not merge your own PRs. Ask for human review per Section 5.
