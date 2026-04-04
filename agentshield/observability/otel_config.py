from __future__ import annotations

from pydantic import BaseModel, field_validator

from agentshield.exceptions import ConfigurationError


class OTelConfig(BaseModel):
    """Validated OpenTelemetry exporter configuration.

    This model captures a stable, validated snapshot of observability settings
    at exporter construction time.

    Attributes:
        enabled: Whether the OTel exporter should run.
        service_name: OTel resource service.name value.
        service_version: OTel resource service.version value.
        otlp_endpoint: OTLP gRPC collector endpoint URL.
        export_traces: Whether to export threat and session spans.
        export_metrics: Whether to export counters and histograms.
        export_timeout_ms: OTLP exporter timeout in milliseconds.
        redis_channel: Redis pub/sub channel to subscribe to.
    """

    enabled: bool = True
    service_name: str = "agentshield"
    service_version: str = "0.1.0"
    otlp_endpoint: str = "http://localhost:4317"
    export_traces: bool = True
    export_metrics: bool = True
    export_timeout_ms: int = 5000
    redis_channel: str = "agentshield:events"

    @field_validator("otlp_endpoint")
    @classmethod
    def validate_otlp_endpoint(cls, value: str) -> str:
        """Validate OTLP endpoint URL scheme.

        Args:
            value: Endpoint URL to validate.

        Returns:
            Validated endpoint URL.

        Raises:
            ConfigurationError: If endpoint does not start with HTTP/HTTPS.
        """
        if not (value.startswith("http://") or value.startswith("https://")):
            raise ConfigurationError(
                "otel_config.otlp_endpoint must start with 'http://' or 'https://'"
            )
        return value

    @field_validator("export_timeout_ms")
    @classmethod
    def validate_export_timeout_ms(cls, value: int) -> int:
        """Validate exporter timeout bounds.

        Args:
            value: Timeout in milliseconds.

        Returns:
            Validated timeout value.

        Raises:
            ConfigurationError: If timeout is outside [100, 30000].
        """
        if value < 100 or value > 30000:
            raise ConfigurationError(
                "otel_config.export_timeout_ms must be between 100 and 30000"
            )
        return value
