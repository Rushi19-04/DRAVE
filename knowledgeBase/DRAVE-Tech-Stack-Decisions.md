# DRAVE — Tech Stack & Architecture Decisions

This document serves as the definitive reference for the real technologies chosen for the DRAVE project (as of Phase 2 completion) and the rationale behind each choice. 

---

## 1. Authentication & Identity
**Chosen Tool**: Clerk
**Alternatives Considered**: Auth0, Cognito, custom JWT implementation.
**Why Clerk?**
- Provides an extremely fast, drop-in React components approach (`<SignedIn>`, `<SignedOut>`, `<UserButton>`) that drastically cuts frontend scaffolding time for prototypes.
- Zero-config JWKS (JSON Web Key Set) endpoints (`/.well-known/jwks.json`) making backend API validation using standard cryptographic libraries straightforward and robust.
- Out-of-the-box UI for managing user sessions and a very generous dev-tier permissiveness.
**Why not Auth0?** Auth0's React SDK requires significantly more boilerplate for simple B2B multi-tenant setups, and Clerk's developer experience for Next.js/Vite is vastly superior for rapid prototyping.

## 2. API Backend & Web Hosting
**Chosen Tool**: FastAPI (Python) on Render (Web Service)
**Alternatives Considered**: Flask, Django, Railway, Heroku.
**Why FastAPI?**
- Best-in-class integration with Pydantic, enabling automatic validation and serialization of our `DetectionRule` and `EvidenceReport` models.
- Auto-generated OpenAPI/Swagger documentation out of the box (`/docs`), crucial for a platform that serves headless CI pipelines.
**Why Render?**
- Provides native Dockerfile support for the backend, simplifying the deployment of complex Python environments (like `pySigma` and `uv`).
- Excellent free/hobby tier offering with seamless GitHub integration. 
**Why not Railway?** While Railway is excellent, Render's native Docker support combined with its predictable free tier made it the safer choice for a Python-heavy ML/Security backend.
**Known Limitations/Tradeoffs**: Free tier instances spin down after 15 minutes of inactivity ("cold starts"). This causes initial API requests or GitHub webhook payloads to delay by up to 50 seconds while the container boots up.

## 3. Database & ORM
**Chosen Tool**: Neon (Serverless Postgres) + SQLModel
**Alternatives Considered**: Supabase, SQLite, standard SQLAlchemy, Prisma.
**Why Neon?**
- Pure Serverless PostgreSQL that scales to zero and provisions instantly.
- Seamless connection strings that drop straight into Python standard tooling without needing heavy client libraries (like Supabase's JS/Python SDKs).
**Why not Supabase?** We only needed a raw Postgres connection string for our backend, not Supabase's full BaaS (Auth, Storage, Realtime). Neon provides a purer database-only serverless experience.
**Why SQLModel?**
- Created by the author of FastAPI. Allows us to declare one class that acts as *both* a Pydantic data validation model and a SQLAlchemy ORM model (e.g., `class RuleEntity(DetectionRule, SQLModel, table=True)`), entirely eliminating the boilerplate of maintaining separate API schemas and DB schemas.

## 4. Frontend & Hosting
**Chosen Tool**: React (Vite/TypeScript) on Vercel
**Alternatives Considered**: Next.js, Create React App, Netlify.
**Why Vite + React?**
- Fast HMR (Hot Module Replacement) and optimized production builds. 
- A Single Page Application (SPA) was sufficient for the DRAVE dashboard; Next.js SSR/SSG was unnecessary overhead for a purely client-side authenticated dashboard.
**Why Vercel?**
- Best-in-class CI/CD for frontend applications.
- Zero-config routing and deployment for Vite projects. 

## 5. CI/CD & Automation
**Chosen Tool**: GitHub Actions
**Alternatives Considered**: GitLab CI, Jenkins, CircleCI.
**Why GitHub Actions?**
- Native integration with the repository where the rules are version-controlled.
- Easily defined YAML workflows (`drave-ci.yml`, `drave-sync.yml`) that can securely access secrets (`DRAVE_API_KEY`) and trigger Docker-based Python scripts (`uv run python cli/...`) without provisioning custom runners.
- Seamless status checks and PR gating directly in the developer's workflow.

## 6. Machine-to-Machine Auth (CI Sync)
**Chosen Tool**: Database-backed API Keys with SHA-256 Hashing
**Alternatives Considered**: Clerk B2B machine tokens, Bcrypt/Argon2 hashing, hardcoded config bypass.
**Why SHA-256?**
- API keys are high-entropy, 256-bit secure random strings (`secrets.token_hex(32)`). Because they are not human-generated passwords, dictionary attacks are mathematically impossible.
- Using SHA-256 provides the necessary security (a database breach only reveals hashes, not usable keys) without the massive CPU overhead on every single API request that slow algorithms like `bcrypt` require, which would artificially bottleneck high-volume CI pipeline syncs.
**Implementation Detail**: The API keys are scoped to the specific Clerk Tenant ID that generated them, ensuring Tenant A's CI pipeline can never overwrite Tenant B's detection rules.

## 7. Package Management & Build
**Chosen Tool**: `uv` (Astral)
**Alternatives Considered**: `pip`, `poetry`, `pipenv`.
**Why `uv`?**
- Blisteringly fast rust-based Python package installer and resolver.
- Simplified dependency locking and virtual environment management via `pyproject.toml`, significantly speeding up local development and Docker build times.

## 8. Containerization
**Chosen Tool**: Docker (`Dockerfile.prod`)
**Why Docker?**
- Ensures absolute parity between the developer's local environment, the GitHub Actions runner, and the production Render web service.
- The `Dockerfile.prod` specifically leverages multi-stage builds and `uv`'s caching mechanisms to create an extremely lightweight, secure, and fast-booting production image.

## 9. Detection Engine
**Chosen Tool**: `pySigma`
**Alternatives Considered**: Custom AST parsers, regex engines.
**Why pySigma?**
- The industry standard for parsing, validating, and converting Sigma rules into SIEM-specific queries.
- Modular architecture allows us to build custom backends and pipelines (like our `SplunkAdapter`) while relying on a battle-tested core engine for schema validation and dependency extraction.
