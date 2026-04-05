from __future__ import annotations

from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class BackendConfig(BaseSettings):
    """Backend server configuration loaded from environment variables.

    All fields have sensible defaults for local development.
    Prefix all env vars with AGENTSHIELD_ (for example,
    AGENTSHIELD_PORT=9000).
    """

    model_config = SettingsConfigDict(env_prefix="AGENTSHIELD_")

    redis_url: str = "redis://localhost:6379"
    redis_channel: str = "agentshield:events"

    event_store_max_size: int = 10_000
    persist_events: bool = False
    persistence_path: Path = Path("agentshield_events.jsonl")

    cors_origins: list[str] = ["http://localhost:3000"]

    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "INFO"

    @field_validator("port")
    @classmethod
    def validate_port(cls, value: int) -> int:
        """Validate backend HTTP port range.

        Args:
            value: Candidate port value.

        Returns:
            Validated port value.

        Raises:
            ValueError: If the port is outside 1-65535.
        """
        if value < 1 or value > 65_535:
            raise ValueError("port must be between 1 and 65535")
        return value

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        """Validate backend log level.

        Args:
            value: Candidate log level string.

        Returns:
            Upper-case validated log level.

        Raises:
            ValueError: If level is not one of supported values.
        """
        normalized = value.upper()
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if normalized not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}, got {value!r}")
        return normalized

    @field_validator("event_store_max_size")
    @classmethod
    def validate_store_size(cls, value: int) -> int:
        """Validate rolling event store capacity.

        Args:
            value: Candidate max-size value.

        Returns:
            Validated positive integer.

        Raises:
            ValueError: If value is not positive.
        """
        if value <= 0:
            raise ValueError("event_store_max_size must be > 0")
        return value

    @field_validator("cors_origins")
    @classmethod
    def validate_cors_origins(cls, value: list[str]) -> list[str]:
        """Validate CORS origins list.

        Args:
            value: Candidate origin list.

        Returns:
            Validated non-empty origin list.

        Raises:
            ValueError: If list is empty.
        """
        if not value:
            raise ValueError("cors_origins must contain at least one origin")
        return value
