"""
AgentShield configuration system.

All configuration is loaded from environment variables with
sensible defaults. Uses Pydantic Settings for validation.

Usage:
    config = AgentShieldConfig()           # loads from env
    config = AgentShieldConfig(log_level="DEBUG")  # override

Environment variable prefix: AGENTSHIELD_
Exception: redis_url and embedding_* use their own prefixes.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from loguru import logger
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AgentShieldConfig(BaseSettings):
    """
    Central configuration for the AgentShield SDK.

    All fields can be set via environment variables using the
    AGENTSHIELD_ prefix (except redis_url).

    Example:
        AGENTSHIELD_LOG_LEVEL=DEBUG
        AGENTSHIELD_BLOCKING_ENABLED=false
        REDIS_URL=redis://myredis:6379

    Attributes:
        redis_url: Redis connection string for event pub/sub.
        log_level: Loguru log level. One of DEBUG/INFO/WARNING/ERROR/CRITICAL.
        audit_log_path: Path to the JSONL audit log file.
        detection_enabled: Master switch for all threat detection.
        blocking_enabled: If False, detects but never blocks.
        policy_path: Optional path to a custom YAML policy file.

        goal_drift_threshold: Cosine distance above which drift is flagged.
        goal_drift_block_threshold: Distance above which drift is blocked.
        memory_poison_zscore_threshold: Z-score above which memory writes
            are flagged as anomalous.
        injection_similarity_threshold: Semantic similarity score above
            which prompt injection is detected.
        injection_pattern_threshold: Pattern match score above which
            injection is flagged (lower threshold).
        anomaly_sensitivity: DNA fingerprinting anomaly sensitivity (0-1).
            Higher = more sensitive = more false positives.

        dna_min_sessions: Minimum sessions before DNA baseline is active.
        dna_learning_rate: How quickly the baseline adapts to new sessions.

        canary_enabled: Whether to inject canary tokens into context.
        canary_rotation_sessions: How often to rotate canary tokens.

        embedding_model: Sentence transformer model name.
        embedding_device: Device for embeddings. "auto" detects GPU.

        event_channel: Redis pub/sub channel name.
        max_event_history: Max events kept in memory by backend.
        audit_chain_enabled: Whether cryptographic audit chaining is enabled.
        audit_chain_path: Optional JSONL path for chain persistence.
        audit_chain_max_memory_entries: Max chain entries kept in memory.
    """

    model_config = SettingsConfigDict(
        env_prefix="AGENTSHIELD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ── Infrastructure ─────────────────────────────────────────
    redis_url: str = "redis://localhost:6379"
    log_level: str = "INFO"
    audit_log_path: str = "./logs/audit.jsonl"

    # ── Feature Flags ──────────────────────────────────────────
    detection_enabled: bool = True
    blocking_enabled: bool = True
    canary_enabled: bool = True
    policy_path: str | None = None

    # ── Detection Thresholds ───────────────────────────────────
    goal_drift_threshold: float = 0.35
    goal_drift_block_threshold: float = 0.55
    memory_poison_zscore_threshold: float = 2.5
    injection_similarity_threshold: float = 0.80
    injection_pattern_threshold: float = 0.25
    anomaly_sensitivity: float = 0.85

    # ── DNA Fingerprinting ─────────────────────────────────────
    dna_min_sessions: int = 10
    dna_learning_rate: float = 0.1

    # ── Canary ─────────────────────────────────────────────────
    canary_rotation_sessions: int = 50

    # ── Embeddings ─────────────────────────────────────────────
    embedding_model: str = "all-MiniLM-L6-v2"
    embedding_device: str = "auto"

    # ── Event System ───────────────────────────────────────────
    event_channel: str = "agentshield:events"
    max_event_history: int = 10000
    audit_chain_enabled: bool = Field(
        default=True,
        description="Enable cryptographic audit chain",
    )
    audit_chain_path: Path | None = Field(
        default=None,
        description="JSONL file path for audit chain persistence",
    )
    audit_chain_max_memory_entries: int = Field(
        default=10_000,
        description="Max in-memory chain entries before oldest are dropped",
    )

    # ── Observability ────────────────────────────────────────
    otel_enabled: bool = Field(default=False, description="Enable OTel export")
    otel_service_name: str = Field(
        default="agentshield",
        description="OTel service.name resource attribute",
    )
    otel_otlp_endpoint: str = Field(
        default="http://localhost:4317",
        description="OTLP gRPC collector endpoint",
    )
    otel_export_traces: bool = Field(default=True, description="Export traces")
    otel_export_metrics: bool = Field(default=True, description="Export metrics")

    # ── Notifications ────────────────────────────────────────
    slack_enabled: bool = Field(
        default=False,
        description="Enable Slack webhook alerting",
    )
    slack_webhook_url: str = Field(
        default="",
        description="Slack Incoming Webhook URL",
    )
    slack_min_severity: str = Field(
        default="HIGH",
        description="Minimum severity for Slack alerts",
    )
    slack_cooldown_seconds: int = Field(
        default=60,
        description="Slack rate limit cooldown in seconds",
    )

    pagerduty_enabled: bool = Field(
        default=False,
        description="Enable PagerDuty alerting",
    )
    pagerduty_routing_key: str = Field(
        default="",
        description="PagerDuty Events API v2 routing key (32 chars)",
    )
    pagerduty_min_severity: str = Field(
        default="CRITICAL",
        description="Minimum severity for PagerDuty alerts",
    )
    pagerduty_cooldown_seconds: int = Field(
        default=300,
        description="PagerDuty rate limit cooldown in seconds",
    )

    # Detection tuning - Issue 4 fix (moved from hardcoded)
    rolling_window_size: int = Field(
        default=10,
        description="Rolling window size for goal drift averaging",
    )
    min_prompts_before_block: int = Field(
        default=3,
        description=("Minimum prompt count before goal drift " "triggers a BLOCK"),
    )
    goal_drift_correlation_threshold: float = Field(
        default=0.70,
        description=("Cosine distance threshold at which " "goal drift detector fires"),
    )
    memory_zscore_threshold: float = Field(
        default=3.0,
        description=("Z-score threshold for memory poison " "anomaly detection"),
    )

    # Tool-chain heuristic thresholds (Phase 5D)
    tool_chain_read_send_transition_score: float = Field(
        default=0.40,
        description="Score added for READ -> SEND transitions",
    )
    tool_chain_execute_send_transition_score: float = Field(
        default=0.45,
        description="Score added for EXECUTE -> SEND transitions",
    )
    tool_chain_high_call_velocity_threshold: int = Field(
        default=10,
        description="Tool-call count threshold for high velocity signal",
    )
    tool_chain_high_call_velocity_bonus: float = Field(
        default=0.15,
        description="Score bonus for high tool-call velocity",
    )
    tool_chain_repeated_tool_threshold: int = Field(
        default=3,
        description="Repeat count threshold for repeated-tool signal",
    )
    tool_chain_repeated_tool_bonus: float = Field(
        default=0.20,
        description="Score bonus for repeated-tool signal",
    )
    tool_chain_anomaly_score_threshold: float = Field(
        default=0.40,
        description="Minimum heuristic score required to emit threat",
    )
    tool_chain_flag_threshold: float = Field(
        default=0.40,
        description="Heuristic score threshold for FLAG action",
    )
    tool_chain_alert_threshold: float = Field(
        default=0.60,
        description="Heuristic score threshold for ALERT action",
    )
    tool_chain_block_threshold: float = Field(
        default=0.80,
        description="Heuristic score threshold for BLOCK action",
    )

    # Memory poison detection thresholds (Phase 5D)
    memory_poison_z_score_threshold: float = Field(
        default=3.0,
        description="Z-score threshold for memory poison anomaly signals",
    )
    memory_poison_baseline_window_size: int = Field(
        default=3,
        description="Baseline window size used by memory poison detector",
    )
    memory_poison_min_samples_before_detection: int = Field(
        default=3,
        description="Minimum samples required before memory anomaly scoring",
    )
    memory_poison_anomaly_score_threshold: float = Field(
        default=0.25,
        description="Minimum confidence score required to emit memory poison threat",
    )
    memory_poison_alert_threshold: float = Field(
        default=0.55,
        description="Memory poison confidence threshold for ALERT action",
    )
    memory_poison_block_threshold: float = Field(
        default=0.80,
        description="Memory poison confidence threshold for BLOCK action",
    )

    # ── Validators ─────────────────────────────────────────────

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """
        Validate log level is one of the allowed loguru levels.

        Args:
            v: The log level string to validate.

        Returns:
            Uppercase validated log level string.

        Raises:
            ValueError: If log level is not in the allowed set.
        """
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        normalized = v.upper()
        if normalized not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}, got {v!r}")
        return normalized

    @field_validator(
        "goal_drift_threshold",
        "goal_drift_block_threshold",
        "goal_drift_correlation_threshold",
        "injection_similarity_threshold",
        "injection_pattern_threshold",
        "anomaly_sensitivity",
        "dna_learning_rate",
        "tool_chain_read_send_transition_score",
        "tool_chain_execute_send_transition_score",
        "tool_chain_high_call_velocity_bonus",
        "tool_chain_repeated_tool_bonus",
        "tool_chain_anomaly_score_threshold",
        "tool_chain_flag_threshold",
        "tool_chain_alert_threshold",
        "tool_chain_block_threshold",
        "memory_poison_anomaly_score_threshold",
        "memory_poison_alert_threshold",
        "memory_poison_block_threshold",
    )
    @classmethod
    def validate_float_0_to_1(cls, v: float) -> float:
        """
        Validate float fields that must be between 0.0 and 1.0.

        Args:
            v: Float value to validate.

        Returns:
            Validated float value.

        Raises:
            ValueError: If value is outside [0.0, 1.0].
        """
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"Threshold must be between 0.0 and 1.0, got {v}")
        return v

    @field_validator("memory_poison_zscore_threshold")
    @classmethod
    def validate_zscore_positive(cls, v: float) -> float:
        """
        Validate that z-score threshold is positive.

        Args:
            v: Z-score threshold to validate.

        Returns:
            Validated z-score value.

        Raises:
            ValueError: If z-score is not positive.
        """
        if v <= 0.0:
            raise ValueError(
                f"memory_poison_zscore_threshold must be positive, got {v}"
            )
        return v

    @field_validator("memory_zscore_threshold", "memory_poison_z_score_threshold")
    @classmethod
    def validate_memory_zscore_positive(cls, v: float) -> float:
        """Validate that memory z-score thresholds are positive.

        Args:
            v: Z-score threshold to validate.

        Returns:
            Validated z-score threshold.

        Raises:
            ValueError: If value is non-positive.
        """
        if v <= 0.0:
            raise ValueError(f"memory z-score threshold must be positive, got {v}")
        return v

    @field_validator("dna_min_sessions")
    @classmethod
    def validate_min_sessions(cls, v: int) -> int:
        """
        Validate that minimum sessions for DNA is at least 3.

        Args:
            v: Minimum session count to validate.

        Returns:
            Validated session count.

        Raises:
            ValueError: If value is less than 3.
        """
        if v < 3:
            raise ValueError(f"dna_min_sessions must be at least 3, got {v}")
        return v

    @field_validator(
        "tool_chain_high_call_velocity_threshold",
        "tool_chain_repeated_tool_threshold",
        "memory_poison_baseline_window_size",
        "memory_poison_min_samples_before_detection",
        "audit_chain_max_memory_entries",
    )
    @classmethod
    def validate_positive_int_thresholds(cls, v: int) -> int:
        """Validate integer thresholds that must be positive.

        Args:
            v: Integer threshold value.

        Returns:
            Validated integer threshold.

        Raises:
            ValueError: If value is not positive.
        """
        if v <= 0:
            raise ValueError(f"integer threshold must be positive, got {v}")
        return v

    @model_validator(mode="after")
    def validate_drift_thresholds_ordered(self) -> AgentShieldConfig:
        """
        Validate that goal drift flag threshold < block threshold.

        Returns:
            Self after validation.

        Raises:
            ValueError: If flag threshold >= block threshold.
        """
        if self.goal_drift_threshold >= self.goal_drift_block_threshold:
            raise ValueError(
                f"goal_drift_threshold ({self.goal_drift_threshold}) must be "
                f"less than goal_drift_block_threshold "
                f"({self.goal_drift_block_threshold})"
            )
        return self

    @property
    def agentshield_version(self) -> str:
        """Return the installed AgentShield package version.

        Returns:
            Version string from package metadata when available.
        """
        try:
            return version("agent-shield-sdk")
        except PackageNotFoundError:
            return "unknown"

    def log_active_config(self) -> None:
        """
        Log the active configuration at INFO level.

        Useful for debugging. Called automatically when the
        AgentShieldRuntime initializes.
        Does not log sensitive values like API keys.
        """
        logger.info(
            "AgentShield config loaded | "
            "detection={} blocking={} canary={} "
            "log_level={} embedding_model={}",
            self.detection_enabled,
            self.blocking_enabled,
            self.canary_enabled,
            self.log_level,
            self.embedding_model,
        )
