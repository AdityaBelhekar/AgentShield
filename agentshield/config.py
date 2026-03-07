"""AgentShield configuration via Pydantic Settings.

Loads configuration from environment variables with the
``AGENTSHIELD_`` prefix, or from a ``.env`` file.
"""

from __future__ import annotations

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AgentShieldConfig(BaseSettings):
    """Central configuration for the AgentShield runtime.

    All fields can be overridden via environment variables
    prefixed with ``AGENTSHIELD_``.  For example,
    ``AGENTSHIELD_LOG_LEVEL=DEBUG`` sets :pyattr:`log_level`.
    """

    model_config = SettingsConfigDict(
        env_prefix="AGENTSHIELD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Core ────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379"
    log_level: str = "INFO"
    policy_path: str | None = None
    detection_enabled: bool = True
    blocking_enabled: bool = True

    # ── Detector thresholds ─────────────────────────────
    goal_drift_threshold: float = 0.35
    goal_drift_block_threshold: float = 0.55
    memory_poison_zscore_threshold: float = 2.5
    injection_similarity_threshold: float = 0.80
    injection_pattern_threshold: float = 0.25

    # ── Event system ────────────────────────────────────
    event_channel: str = "agentshield:events"
    audit_log_path: str = "./logs/audit.jsonl"
    max_event_history: int = 10000

    # ── Embedding model ─────────────────────────────────
    embedding_model: str = "all-MiniLM-L6-v2"
    embedding_device: str = "auto"  # auto | cpu | cuda | rocm

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Ensure log level is a valid Python logging level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid_levels:
            msg = f"Invalid log level '{v}'. Must be one of {valid_levels}"
            raise ValueError(msg)
        return upper
