from __future__ import annotations

from pydantic import BaseModel, field_validator, model_validator

from agentshield.exceptions import ConfigurationError

_ALLOWED_SEVERITIES: tuple[str, ...] = (
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
)


class SIEMConfig(BaseModel):
    """Validated configuration snapshot for SIEM exporters.

    Attributes:
        syslog_enabled: Enable CEF over syslog export.
        syslog_host: Syslog target hostname.
        syslog_port: Syslog target port.
        syslog_protocol: Syslog transport protocol (`udp` or `tcp`).
        http_enabled: Enable HTTP SIEM export.
        http_endpoint: HTTP endpoint URL.
        http_mode: HTTP payload mode (`generic` or `splunk_hec`).
        http_token: Optional auth token for HTTP export.
        http_timeout_seconds: Timeout for HTTP requests in seconds.
        http_max_retries: Retry attempts for HTTP failures.
        redis_channel: Redis event channel to subscribe to.
        min_severity: Minimum threat severity to export.
    """

    syslog_enabled: bool = False
    syslog_host: str = "localhost"
    syslog_port: int = 514
    syslog_protocol: str = "udp"

    http_enabled: bool = False
    http_endpoint: str = ""
    http_mode: str = "generic"
    http_token: str = ""
    http_timeout_seconds: int = 10
    http_max_retries: int = 3

    redis_channel: str = "agentshield:events"
    min_severity: str = "LOW"

    @field_validator("syslog_protocol")
    @classmethod
    def validate_syslog_protocol(cls, value: str) -> str:
        """Validate allowed syslog protocol values.

        Args:
            value: Requested syslog protocol string.

        Returns:
            Lowercase validated protocol.

        Raises:
            ConfigurationError: If protocol is not `udp` or `tcp`.
        """
        normalized = value.lower()
        if normalized not in {"udp", "tcp"}:
            raise ConfigurationError("syslog_protocol must be 'udp' or 'tcp'")
        return normalized

    @field_validator("http_mode")
    @classmethod
    def validate_http_mode(cls, value: str) -> str:
        """Validate allowed HTTP exporter modes.

        Args:
            value: Requested HTTP exporter mode.

        Returns:
            Lowercase validated mode.

        Raises:
            ConfigurationError: If mode is not supported.
        """
        normalized = value.lower()
        if normalized not in {"generic", "splunk_hec"}:
            raise ConfigurationError("http_mode must be 'generic' or 'splunk_hec'")
        return normalized

    @field_validator("min_severity")
    @classmethod
    def validate_min_severity(cls, value: str) -> str:
        """Validate severity threshold value.

        Args:
            value: Minimum severity string.

        Returns:
            Uppercase validated severity.

        Raises:
            ConfigurationError: If severity is unknown.
        """
        normalized = value.upper()
        if normalized not in _ALLOWED_SEVERITIES:
            raise ConfigurationError(
                "min_severity must be one of: INFO LOW MEDIUM HIGH CRITICAL"
            )
        return normalized

    @field_validator("http_max_retries")
    @classmethod
    def validate_http_max_retries(cls, value: int) -> int:
        """Validate retry-attempt bounds.

        Args:
            value: Maximum retry attempts.

        Returns:
            Validated retry count.

        Raises:
            ConfigurationError: If retries are out of supported range.
        """
        if value < 1 or value > 5:
            raise ConfigurationError("http_max_retries must be between 1 and 5")
        return value

    @model_validator(mode="after")
    def validate_http_settings(self) -> SIEMConfig:
        """Validate HTTP endpoint requirements when HTTP export is enabled.

        Returns:
            The validated model instance.

        Raises:
            ConfigurationError: If enabled HTTP config is incomplete or invalid.
        """
        if self.http_enabled:
            if not self.http_endpoint:
                raise ConfigurationError(
                    "http_endpoint is required when http_enabled is true"
                )
            if not (
                self.http_endpoint.startswith("http://")
                or self.http_endpoint.startswith("https://")
            ):
                raise ConfigurationError(
                    "http_endpoint must start with 'http://' or 'https://'"
                )

        return self
