"""
platform/backend/app/config.py
SECURITY.md ref: §1 (secrets never exposed to frontend) and §5 (secrets management)

Every secret-shaped value here has NO default in production mode — pydantic-settings
reads exclusively from environment variables (or a local .env file that is
git-ignored, see ../../.gitignore). This module is imported by every other
module in the backend for configuration; nothing else reads os.environ
directly, so a secret-handling audit only has to look in one place.
"""
from __future__ import annotations

import secrets
import warnings
from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- environment ---
    environment: str = Field(default="development")  # "development" | "production"
    debug: bool = Field(default=False)

    # --- secrets: no defaults for the ones that matter in production; see
    # validate_production_secrets() below, which refuses to boot insecurely ---
    secret_key: str = Field(default_factory=lambda: secrets.token_urlsafe(48))
    database_url: str = Field(default="sqlite:///./dev.db")
    redis_url: str | None = Field(default=None)  # rate-limit storage backend; None -> in-memory (dev only)

    # --- JWT / sessions (SECURITY.md §1: sessions expire) ---
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    email_verification_token_expire_hours: int = 24
    password_reset_token_expire_minutes: int = 60

    # --- rate limiting (SECURITY.md §4) ---
    login_rate_limit: str = "5/minute"
    register_rate_limit: str = "5/hour"
    password_reset_rate_limit: str = "3/hour"
    copilot_rate_limit: str = "15/minute"
    upload_rate_limit: str = "10/minute"
    default_rate_limit: str = "100/minute"

    # --- uploads (SECURITY.md §6) ---
    max_upload_mb: int = 50
    allowed_upload_extensions: tuple[str, ...] = (".csv", ".pcap", ".pcapng")

    # --- CORS: explicit allow-list, never "*" with credentials ---
    cors_allowed_origins: list[str] = Field(default_factory=lambda: ["http://localhost:8000"])

    # --- email service (verification / password reset) ---
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    email_from_address: str = "no-reply@nexusai-forecast.local"

    # --- optional: LLM-generated copilot narration (platform enhancement
    # only — never required, never used by the offline ml_core demo). Server-
    # side only; the key is never sent to the frontend. See rag_service.py. ---
    anthropic_api_key: str | None = None

    # --- ml_core bridge ---
    ml_core_root: str = "../../"  # relative to platform/backend/, points at the repo root's src/

    @field_validator("environment")
    @classmethod
    def _validate_env(cls, v: str) -> str:
        if v not in {"development", "production", "test"}:
            raise ValueError("environment must be 'development', 'production', or 'test'")
        return v


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    _validate_production_secrets(settings)
    return settings


def _validate_production_secrets(settings: Settings) -> None:
    """Refuse to boot in production with a dev-mode secret or DB. This is the
    single most common way real deployments accidentally ship a hackathon
    demo's throwaway secret key to production — fail loudly instead."""
    if settings.environment != "production":
        return
    problems = []
    if len(settings.secret_key) < 32:
        problems.append("SECRET_KEY is too short for production (need >=32 chars of real entropy).")
    if settings.database_url.startswith("sqlite"):
        problems.append("DATABASE_URL is SQLite — use PostgreSQL in production (see docker-compose.yml).")
    if settings.debug:
        problems.append("DEBUG=true in production leaks stack traces — set DEBUG=false.")
    if not settings.redis_url:
        warnings.warn(
            "REDIS_URL not set in production: rate limiting will fall back to a "
            "per-process in-memory store, which does NOT share state across multiple "
            "backend workers/replicas. Set REDIS_URL for correct rate limiting at scale.",
            stacklevel=2,
        )
    if problems:
        raise RuntimeError("Refusing to start in production mode:\n- " + "\n- ".join(problems))
