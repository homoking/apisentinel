from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for API, dashboard, scanner, and CLI."""

    app_name: str = "APISentinel"
    environment: str = Field(default="development")
    debug: bool = False
    database_url: str = Field(
        default="sqlite:///./.data/apisentinel.db",
        description="Use postgresql+psycopg://user:pass@host:5432/apisentinel in production.",
    )
    redis_url: str | None = None
    openai_api_key: str | None = None
    ai_provider: str = Field(default="local", description="local or openai")
    request_timeout_seconds: float = 10.0
    user_agent: str = "APISentinel/0.1 (+https://github.com/example/apisentinel)"
    data_dir: Path = Path(".data")

    model_config = SettingsConfigDict(env_prefix="APISENTINEL_", env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    return settings
