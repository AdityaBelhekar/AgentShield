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


class WebhookConfig(BaseModel):
    """Validated webhook notification configuration snapshot.

    This model validates notification settings before they are passed into
    WebhookNotifier so runtime paths stay simple and fail-safe.

    Attributes:
        slack_enabled: Whether Slack alerting is enabled.
        slack_webhook_url: Slack Incoming Webhook URL.
        slack_min_severity: Minimum severity for Slack notifications.
        slack_cooldown_seconds: Rate-limit cooldown for Slack sends.
        pagerduty_enabled: Whether PagerDuty alerting is enabled.
        pagerduty_routing_key: PagerDuty Events API v2 routing key.
        pagerduty_min_severity: Minimum severity for PagerDuty triggers.
        pagerduty_cooldown_seconds: Rate-limit cooldown for PagerDuty triggers.
        redis_channel: Redis channel to subscribe to for event ingestion.
        http_timeout_seconds: Timeout per webhook HTTP request in seconds.
        max_retries: Max retry attempts per outbound webhook request.
    """

    slack_enabled: bool = False
    slack_webhook_url: str = ""
    slack_min_severity: str = "HIGH"
    slack_cooldown_seconds: int = 60

    pagerduty_enabled: bool = False
    pagerduty_routing_key: str = ""
    pagerduty_min_severity: str = "CRITICAL"
    pagerduty_cooldown_seconds: int = 300

    redis_channel: str = "agentshield:events"
    http_timeout_seconds: int = 10
    max_retries: int = 3

    @field_validator("slack_min_severity", "pagerduty_min_severity")
    @classmethod
    def validate_min_severity(cls, value: str) -> str:
        """Validate allowed severity names.

        Args:
            value: Severity threshold string.

        Returns:
            Uppercase severity value.

        Raises:
            ConfigurationError: If severity is not one of the allowed levels.
        """
        normalized = value.upper()
        if normalized not in _ALLOWED_SEVERITIES:
            raise ConfigurationError(
                "Severity must be one of: INFO LOW MEDIUM HIGH CRITICAL"
            )
        return normalized

    @field_validator("slack_cooldown_seconds")
    @classmethod
    def validate_slack_cooldown_seconds(cls, value: int) -> int:
        """Validate Slack cooldown bounds.

        Args:
            value: Cooldown seconds to validate.

        Returns:
            Validated cooldown.

        Raises:
            ConfigurationError: If value is outside 1..3600.
        """
        if value < 1 or value > 3600:
            raise ConfigurationError(
                "slack_cooldown_seconds must be between 1 and 3600"
            )
        return value

    @field_validator("pagerduty_cooldown_seconds")
    @classmethod
    def validate_pagerduty_cooldown_seconds(cls, value: int) -> int:
        """Validate PagerDuty cooldown bounds.

        Args:
            value: Cooldown seconds to validate.

        Returns:
            Validated cooldown.

        Raises:
            ConfigurationError: If value is outside 1..3600.
        """
        if value < 1 or value > 3600:
            raise ConfigurationError(
                "pagerduty_cooldown_seconds must be between 1 and 3600"
            )
        return value

    @field_validator("max_retries")
    @classmethod
    def validate_max_retries(cls, value: int) -> int:
        """Validate retry-attempt bounds.

        Args:
            value: Maximum retry attempts.

        Returns:
            Validated retry attempts.

        Raises:
            ConfigurationError: If value is outside 1..5.
        """
        if value < 1 or value > 5:
            raise ConfigurationError("max_retries must be between 1 and 5")
        return value

    @model_validator(mode="after")
    def validate_enabled_integrations(self) -> WebhookConfig:
        """Validate integration-specific fields when enabled.

        Returns:
            The validated model instance.

        Raises:
            ConfigurationError: If enabled integration fields are invalid.
        """
        if self.slack_enabled:
            if not self.slack_webhook_url:
                raise ConfigurationError(
                    "slack_webhook_url is required when slack_enabled is true"
                )
            if not self.slack_webhook_url.startswith("https://hooks.slack.com/"):
                raise ConfigurationError(
                    "slack_webhook_url must start with 'https://hooks.slack.com/'"
                )

        if self.pagerduty_enabled:
            if not self.pagerduty_routing_key:
                raise ConfigurationError(
                    "pagerduty_routing_key is required when pagerduty_enabled is true"
                )
            if len(self.pagerduty_routing_key) != 32:
                raise ConfigurationError(
                    "PagerDuty routing_key must be exactly 32 characters"
                )

        return self
