"""FastAPI Application (Step 69)."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from saas.backend.database import init_db
from saas.backend.api.routes import router
from saas.backend.config import settings

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize DB
    init_db()
    yield
    # Shutdown

app = FastAPI(
    title="DRAVE SaaS API",
    description="Multi-tenant API for managing detection rules and deployments.",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[url.strip() for url in settings.frontend_urls.split(",")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")
