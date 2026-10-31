"""Typed, validated configuration (12-factor: everything comes from the environment).

Fail-fast philosophy: if the app is misconfigured (weak JWT secret, missing API key
for the chosen LLM provider) it refuses to start instead of failing at 2 AM on the
first real request.
"""
from decimal import Decimal
from functools import lru_cache
from typing import Literal

from pydantic import SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

LLMProvider = Literal["openai", "anthropic", "ollama"]


class Settings(BaseSettings):
    # All env vars are prefixed LL_ (e.g. LL_DATABASE_URL) to avoid collisions.
    model_config = SettingsConfigDict(env_file=".env", env_prefix="LL_", extra="ignore")

    env: Literal["dev", "test", "prod"] = "dev"
    app_name: str = "LedgerLens"
    log_level: str = "INFO"

    # --- Persistence -------------------------------------------------------
    database_url: str = "postgresql+asyncpg://ledgerlens:ledgerlens@localhost:5432/ledgerlens"
    storage_dir: str = "./data/uploads"

    # --- Auth --------------------------------------------------------------
    jwt_secret: SecretStr  # required, no default on purpose
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "ledgerlens"
    jwt_audience: str = "ledgerlens-api"
    access_token_minutes: int = 30

    # --- AI (provider-agnostic) ------------------------------------------
    llm_provider: LLMProvider = "ollama"
    llm_model: str = "llama3.1:8b"
    llm_timeout_seconds: float = 90.0
    openai_api_key: SecretStr | None = None
    anthropic_api_key: SecretStr | None = None
    ollama_base_url: str = "http://localhost:11434"

    # --- Upload / processing limits (defence against resource exhaustion) --
    max_upload_mb: int = 10
    max_pdf_pages: int = 30
    max_llm_chars: int = 30_000

    # --- Business rules ----------------------------------------------------
    auto_approve_limit: Decimal = Decimal("5000.00")

    # --- HTTP --------------------------------------------------------------
    cors_origins: list[str] = []
    enable_docs: bool = True
    login_rate_per_minute: int = 10
    upload_rate_per_minute: int = 30

    @field_validator("jwt_secret")
    @classmethod
    def _secret_is_strong(cls, v: SecretStr) -> SecretStr:
        if len(v.get_secret_value()) < 32:
            raise ValueError("LL_JWT_SECRET must be at least 32 characters")
        return v

    @model_validator(mode="after")
    def _provider_has_credentials(self) -> "Settings":
        if self.llm_provider == "openai" and not self.openai_api_key:
            raise ValueError("LL_OPENAI_API_KEY is required when LL_LLM_PROVIDER=openai")
        if self.llm_provider == "anthropic" and not self.anthropic_api_key:
            raise ValueError("LL_ANTHROPIC_API_KEY is required when LL_LLM_PROVIDER=anthropic")
        return self

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]  (values come from env)
