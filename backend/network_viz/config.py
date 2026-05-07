from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Network Policy Visualization"
    environment: str = Field(default="local")
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    database_url: str = Field(
        default="postgresql+asyncpg://network_viz:network_viz@localhost:5432/network_viz"
    )
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    pfsense_xml_path: Path | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="NETWORK_VIZ_",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
