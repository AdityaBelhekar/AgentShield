"""AgentShield configuration management.

Provides a Pydantic Settings-based configuration class that reads
from environment variables prefixed with ``AGENTSHIELD_`` and from
a ``.env`` file when present.
"""

from __future__ import annotations

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AgentShieldConfig(BaseSettings):
    """Central configuration for the AgentShield runtime.

    All fields can be set via environment variables prefixed with
    ``AGENTSHIELD_`` (e.g. ``AGENTSHIELD_LOG_LEVEL=DEBUG``).

    Attributes:
        redis_url: Redis connection URL.
        log_level: Logging verbosity.
        policy_path: Optional path to a custom YAML policy file.
        detection_enabled: Whether threat detection is active.
        blocking_enabled: Whether detected threats should be blocked.
        goal_drift_threshold: Cosine-distance alert threshold.
        goal_drift_block_threshold: Cosine-distance block threshold.
        memory_poison_zscore_threshold: Z-score threshold for memory poisoning.
        injection_similarity_threshold: Semantic similarity threshold for injections.
        injection_pattern_threshold: Pattern-match confidence threshold.
        event_channel: Redis pub/sub channel name.
        audit_log_path: Filesystem path for the JSONL audit log.
        max_event_history: Maximum events kept in memory.
        embedding_model: Sentence-transformer model name.
        embedding_device: Device for embeddings (``auto``, ``cpu``, ``cuda``, ``rocm``).
    """

    model_config = SettingsConfigDict(
        env_prefix="AGENTSHIELD_",
        env_file=".env",
        extra="ignore",
    )

    redis_url: str = "redis://localhost:6379"
    log_level: str = "INFO"
    policy_path: str | None = None
    detection_enabled: bool = True
    blocking_enabled: bool = True
    goal_drift_threshold: float = 0.35
    goal_drift_block_threshold: float = 0.55
    memory_poison_zscore_threshold: float = 2.5
    injection_similarity_threshold: float = 0.80
    injection_pattern_threshold: float = 0.25
    event_channel: str = "agentshield:events"
    audit_log_path: str = "./logs/audit.jsonl"
    max_event_history: int = 10000
    embedding_model: str = "all-MiniLM-L6-v2"
    embedding_device: str = "auto"

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Ensure log_level is a recognized Python logging level."""
        allowed = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v not in allowed:
            raise ValueError(f"log_level must be one of {allowed}")
        return v

    @field_validator(
        "goal_drift_threshold",
        "goal_drift_block_threshold",
        "injection_similarity_threshold",
        "injection_pattern_threshold",
    )
    @classmethod
    def validate_float_range(cls, v: float) -> float:
        """Ensure threshold values fall within [0.0, 1.0]."""
        if not 0.0 <= v <= 1.0:
            raise ValueError("Threshold must be between 0.0 and 1.0")
        return v
