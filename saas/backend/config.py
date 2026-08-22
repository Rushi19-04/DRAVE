from pydantic_settings import BaseSettings, SettingsConfigDict

import os

# Dynamically resolve the absolute path to saas/backend/.env
ENV_PATH = os.path.join(os.path.dirname(__file__), ".env")

class Settings(BaseSettings):
    """Application settings, loaded from environment variables or .env file."""
    
    # Database
    database_url: str
    
    # Authentication (Clerk)
    clerk_secret_key: str
    clerk_issuer_url: str

    # CORS
    frontend_urls: str = "http://localhost:5173,http://127.0.0.1:5173"

    # CI/CD Automation (Server-Side Tenant Mapping)
    ci_api_key: str | None = None
    ci_tenant_id: str | None = None

    model_config = SettingsConfigDict(
        env_file=ENV_PATH,
        env_file_encoding="utf-8",
        extra="ignore"  # Ignore extra fields in the .env file
    )

# Instantiate a global settings object to be used across the app
settings = Settings()
