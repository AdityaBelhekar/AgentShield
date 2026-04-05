from __future__ import annotations

import asyncio
import json
from typing import Any

import redis.asyncio as aioredis
from loguru import logger

from agentshield.observability.otel_config import OTelConfig

_OTEL_AVAILABLE: bool = False
metrics: Any | None = None
trace: Any | None = None
TracerProvider: Any | None = None
BatchSpanProcessor: Any | None = None
MeterProvider: Any | None = None
PeriodicExportingMetricReader: Any | None = None
Resource: Any | None = None
SERVICE_NAME: Any | None = None
SERVICE_VERSION: Any | None = None
OTLPSpanExporter: Any | None = None
OTLPMetricExporter: Any | None = None
Status: Any | None = None
StatusCode: Any | None = None

try:
    from opentelemetry import metrics as _metrics
    from opentelemetry import trace as _trace
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
        OTLPMetricExporter as _OTLPMetricExporter,
    )
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
        OTLPSpanExporter as _OTLPSpanExporter,
    )
    from opentelemetry.sdk.metrics import MeterProvider as _MeterProvider
    from opentelemetry.sdk.metrics.export import (
        PeriodicExportingMetricReader as _PeriodicExportingMetricReader,
    )
    from opentelemetry.sdk.resources import (
        SERVICE_NAME as _SERVICE_NAME,
    )
    from opentelemetry.sdk.resources import (
        SERVICE_VERSION as _SERVICE_VERSION,
    )
    from opentelemetry.sdk.resources import (
        Resource as _Resource,
    )
    from opentelemetry.sdk.trace import TracerProvider as _TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor as _BatchSpanProcessor
    from opentelemetry.trace import Status as _Status
    from opentelemetry.trace import StatusCode as _StatusCode

    metrics = _metrics
    trace = _trace
    OTLPMetricExporter = _OTLPMetricExporter
    OTLPSpanExporter = _OTLPSpanExporter
    MeterProvider = _MeterProvider
    PeriodicExportingMetricReader = _PeriodicExportingMetricReader
    SERVICE_NAME = _SERVICE_NAME
    SERVICE_VERSION = _SERVICE_VERSION
    Resource = _Resource
    TracerProvider = _TracerProvider
    BatchSpanProcessor = _BatchSpanProcessor
    Status = _Status
    StatusCode = _StatusCode

    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False


class OTelExporter:
    """Redis-subscriber OpenTelemetry exporter for AgentShield events.

    The exporter runs off the hot path by consuming the existing Redis pub/sub
    stream and translating security events into OTel traces and metrics.
    """

    _otel_config: OTelConfig
    _redis_url: str
    _redis: aioredis.Redis[Any] | None
    _task: asyncio.Task[None] | None
    _session_spans: dict[str, Any]
    _tracer_provider: Any | None
    _meter_provider: Any | None
    _tracer: Any | None
    _meter: Any | None
    _threat_counter: Any | None
    _sessions_counter: Any | None
    _detection_score_hist: Any | None
    _policy_block_counter: Any | None
    _active: bool

    def __init__(self, otel_config: OTelConfig, redis_url: str) -> None:
        """Initialize the exporter and OTel SDK providers.

        Args:
            otel_config: Validated OTel configuration snapshot.
            redis_url: Redis URL for event subscription.
        """
        self._otel_config = otel_config
        self._redis_url = redis_url
        self._redis = None
        self._task = None
        self._session_spans = {}
        self._tracer_provider = None
        self._meter_provider = None
        self._tracer = None
        self._meter = None
        self._threat_counter = None
        self._sessions_counter = None
        self._detection_score_hist = None
        self._policy_block_counter = None
        self._active = False

        if not self._otel_config.enabled:
            logger.info("OTelExporter disabled by configuration")
            return

        if not _OTEL_AVAILABLE:
            logger.warning(
                "OTel packages not installed. Install agentshield-sdk[observability] "
                "to enable export."
            )
            return

        if (
            metrics is None
            or trace is None
            or TracerProvider is None
            or BatchSpanProcessor is None
            or MeterProvider is None
            or PeriodicExportingMetricReader is None
            or Resource is None
            or SERVICE_NAME is None
            or SERVICE_VERSION is None
            or OTLPSpanExporter is None
            or OTLPMetricExporter is None
        ):
            logger.warning("OTel imports unavailable after initialization guard")
            return

        try:
            metrics_module: Any = metrics
            trace_module: Any = trace
            tracer_provider_cls: Any = TracerProvider
            batch_span_processor_cls: Any = BatchSpanProcessor
            meter_provider_cls: Any = MeterProvider
            metric_reader_cls: Any = PeriodicExportingMetricReader
            resource_cls: Any = Resource
            service_name_key: Any = SERVICE_NAME
            service_version_key: Any = SERVICE_VERSION
            span_exporter_cls: Any = OTLPSpanExporter
            metric_exporter_cls: Any = OTLPMetricExporter

            resource = resource_cls.create(
                {
                    service_name_key: self._otel_config.service_name,
                    service_version_key: self._otel_config.service_version,
                }
            )

            timeout_seconds = self._otel_config.export_timeout_ms / 1000.0

            if self._otel_config.export_traces:
                span_exporter = span_exporter_cls(
                    endpoint=self._otel_config.otlp_endpoint,
                    timeout=timeout_seconds,
                )
                self._tracer_provider = tracer_provider_cls(resource=resource)
                span_processor = batch_span_processor_cls(span_exporter)
                self._tracer_provider.add_span_processor(span_processor)
                trace_module.set_tracer_provider(self._tracer_provider)

            if self._otel_config.export_metrics:
                metric_exporter = metric_exporter_cls(
                    endpoint=self._otel_config.otlp_endpoint,
                    timeout=timeout_seconds,
                )
                metric_reader = metric_reader_cls(
                    exporter=metric_exporter,
                    export_interval_millis=10_000,
                )
                self._meter_provider = meter_provider_cls(
                    resource=resource,
                    metric_readers=[metric_reader],
                )
                metrics_module.set_meter_provider(self._meter_provider)

            self._tracer = trace_module.get_tracer(
                self._otel_config.service_name,
                self._otel_config.service_version,
            )
            self._meter = metrics_module.get_meter(
                self._otel_config.service_name,
                self._otel_config.service_version,
            )

            if self._otel_config.export_metrics and self._meter is not None:
                self._threat_counter = self._meter.create_counter(
                    "agentshield.threats.total",
                    description="Total detected threats",
                )
                self._sessions_counter = self._meter.create_up_down_counter(
                    "agentshield.sessions.active",
                    description="Active sessions",
                )
                self._detection_score_hist = self._meter.create_histogram(
                    "agentshield.detection.score",
                    description="Threat detection confidence score",
                )
                self._policy_block_counter = self._meter.create_counter(
                    "agentshield.policy.blocks.total",
                    description="Total policy block decisions",
                )

            self._active = True
        except Exception as exc:
            logger.warning("OTelExporter initialization failed | error={}", exc)
            self._active = False

    async def start(self) -> None:
        """Start Redis subscription and background export loop."""
        if not self._active:
            return

        try:
            self._redis = aioredis.from_url(self._redis_url, decode_responses=False)
            await self._redis.ping()
            self._task = asyncio.create_task(self._listen_loop())
            logger.info(
                "OTelExporter started. Endpoint: {}",
                self._otel_config.otlp_endpoint,
            )
        except Exception as exc:
            logger.warning("OTelExporter failed to start | error={}", exc)

    async def stop(self) -> None:
        """Stop background tasks, end spans, and shutdown providers."""
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                logger.debug("OTelExporter listener task cancelled")
            except Exception as exc:
                logger.warning("OTelExporter task stop warning | error={}", exc)
            self._task = None

        for session_id, span in list(self._session_spans.items()):
            try:
                span.end()
            except Exception as exc:
                logger.warning(
                    "OTelExporter failed to end orphan span | session={} error={}",
                    session_id,
                    exc,
                )
        self._session_spans.clear()

        if self._tracer_provider is not None:
            try:
                force_flush = getattr(self._tracer_provider, "force_flush", None)
                if callable(force_flush):
                    force_flush()
                shutdown = getattr(self._tracer_provider, "shutdown", None)
                if callable(shutdown):
                    shutdown()
            except Exception as exc:
                logger.warning("OTelExporter tracer shutdown warning | error={}", exc)

        if self._meter_provider is not None:
            try:
                shutdown = getattr(self._meter_provider, "shutdown", None)
                if callable(shutdown):
                    shutdown()
            except Exception as exc:
                logger.warning("OTelExporter meter shutdown warning | error={}", exc)

        if self._redis is not None:
            try:
                close_method = getattr(self._redis, "aclose", None)
                if callable(close_method):
                    close_result = close_method()
                    if asyncio.iscoroutine(close_result):
                        await close_result
                else:
                    legacy_close = getattr(self._redis, "close", None)
                    if callable(legacy_close):
                        legacy_close()
            except Exception as exc:
                logger.warning("OTelExporter Redis close warning | error={}", exc)
            self._redis = None

        logger.info("OTelExporter stopped.")

    async def _listen_loop(self) -> None:
        """Subscribe to Redis and continuously process incoming events."""
        if self._redis is None:
            return

        pubsub = self._redis.pubsub()
        try:
            await pubsub.subscribe(self._otel_config.redis_channel)
            while True:
                try:
                    message = await pubsub.get_message(
                        ignore_subscribe_messages=True,
                        timeout=1.0,
                    )
                    if message is None:
                        continue

                    payload = message.get("data")
                    if isinstance(payload, bytes):
                        payload_text = payload.decode("utf-8")
                    elif isinstance(payload, str):
                        payload_text = payload
                    else:
                        continue

                    raw = json.loads(payload_text)
                    if isinstance(raw, dict):
                        self._process_message(raw)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning("OTelExporter listen loop warning | error={}", exc)
        except asyncio.CancelledError:
            logger.debug("OTelExporter listen loop cancelled")
        except Exception as exc:
            logger.warning("OTelExporter listener setup warning | error={}", exc)
        finally:
            try:
                await pubsub.unsubscribe(self._otel_config.redis_channel)
            except Exception as exc:
                logger.warning("OTelExporter unsubscribe warning | error={}", exc)
            try:
                await pubsub.close()
            except Exception as exc:
                logger.warning("OTelExporter pubsub close warning | error={}", exc)

    def _process_message(self, raw: dict[str, Any]) -> None:
        """Route one raw event payload to the appropriate handler.

        Args:
            raw: Raw deserialized Redis event payload.
        """
        try:
            event_type_raw = str(raw.get("event_type", "")).lower()
            if event_type_raw == "session_start":
                self._handle_session_start(raw)
                return
            if event_type_raw == "session_end":
                self._handle_session_end(raw)
                return
            if event_type_raw == "threat_detected":
                self._handle_threat(raw)
                return
        except Exception as exc:
            logger.warning("OTelExporter event processing warning | error={}", exc)

    def _handle_session_start(self, raw: dict[str, Any]) -> None:
        """Handle SESSION_START event export.

        Args:
            raw: Raw event payload.
        """
        try:
            session_id = self._as_text(raw.get("session_id"))
            agent_id = self._as_text(raw.get("agent_id"), default="unknown")
            if not session_id:
                return

            if self._otel_config.export_traces and self._tracer is not None:
                span = self._tracer.start_span(
                    f"agentshield.session.{agent_id}",
                )
                span.set_attribute("agentshield.session_id", session_id)
                span.set_attribute("agentshield.agent_id", agent_id)
                self._session_spans[session_id] = span

            if self._otel_config.export_metrics and self._sessions_counter is not None:
                self._sessions_counter.add(1, attributes={"agent_id": agent_id})
        except Exception as exc:
            logger.warning("OTelExporter session_start warning | error={}", exc)

    def _handle_session_end(self, raw: dict[str, Any]) -> None:
        """Handle SESSION_END event export.

        Args:
            raw: Raw event payload.
        """
        try:
            session_id = self._as_text(raw.get("session_id"))
            agent_id = self._as_text(raw.get("agent_id"), default="unknown")
            if not session_id:
                return

            threat_count = self._as_int(raw.get("threat_count", raw.get("threats_detected", 0)))
            tool_call_count = self._as_int(
                raw.get("tool_call_count", raw.get("tool_calls_total", 0))
            )

            span = self._session_spans.pop(session_id, None)
            if span is not None:
                span.set_attribute("agentshield.threat_count", threat_count)
                span.set_attribute("agentshield.tool_call_count", tool_call_count)
                span.end()

            if self._otel_config.export_metrics and self._sessions_counter is not None:
                self._sessions_counter.add(-1, attributes={"agent_id": agent_id})
        except Exception as exc:
            logger.warning("OTelExporter session_end warning | error={}", exc)

    def _handle_threat(self, raw: dict[str, Any]) -> None:
        """Handle THREAT_DETECTED event export.

        Args:
            raw: Raw event payload.
        """
        try:
            session_id = self._as_text(raw.get("session_id"))
            agent_id = self._as_text(raw.get("agent_id"), default="unknown")
            threat_type = self._as_text(raw.get("threat_type"), default="UNKNOWN")
            severity = self._as_text(raw.get("severity"), default="INFO")
            recommended_action = self._as_text(
                raw.get("recommended_action"),
                default="ALERT",
            )
            canary_triggered = bool(raw.get("canary_triggered", False))
            threat_score = round(
                self._as_float(raw.get("threat_score", raw.get("confidence", 0.0))),
                4,
            )

            if self._otel_config.export_traces and self._tracer is not None:
                parent_span = self._session_spans.get(session_id)
                trace_module: Any = trace
                span_context = None
                if parent_span is not None and trace_module is not None:
                    span_context = trace_module.set_span_in_context(parent_span)
                span = self._tracer.start_span(
                    f"agentshield.threat.{threat_type}",
                    context=span_context,
                )
                span.set_attribute("agentshield.threat_type", threat_type)
                span.set_attribute("agentshield.severity", severity)
                span.set_attribute(
                    "agentshield.recommended_action",
                    recommended_action,
                )
                span.set_attribute("agentshield.agent_id", agent_id)
                span.set_attribute("agentshield.canary_triggered", canary_triggered)
                span.set_attribute("agentshield.threat_score", threat_score)

                if (
                    recommended_action.upper() == "BLOCK"
                    and Status is not None
                    and StatusCode is not None
                ):
                    span.set_status(Status(status_code=StatusCode.ERROR))
                span.end()

            if self._otel_config.export_metrics:
                threat_attributes = {
                    "threat_type": threat_type,
                    "severity": severity,
                    "recommended_action": recommended_action,
                    "agent_id": agent_id,
                }
                if self._threat_counter is not None:
                    self._threat_counter.add(1, attributes=threat_attributes)
                if self._detection_score_hist is not None:
                    self._detection_score_hist.record(
                        threat_score,
                        attributes={
                            "threat_type": threat_type,
                            "agent_id": agent_id,
                        },
                    )
                if recommended_action.upper() == "BLOCK" and self._policy_block_counter is not None:
                    self._policy_block_counter.add(
                        1,
                        attributes={
                            "threat_type": threat_type,
                            "agent_id": agent_id,
                        },
                    )
        except Exception as exc:
            logger.warning("OTelExporter threat warning | error={}", exc)

    @staticmethod
    def _as_text(value: Any, default: str = "") -> str:
        """Normalize a raw field into a non-null string.

        Args:
            value: Raw field value.
            default: Value to use when the field is missing.

        Returns:
            Normalized string.
        """
        if value is None:
            return default
        return str(value)

    @staticmethod
    def _as_int(value: Any, default: int = 0) -> int:
        """Normalize a raw field into an integer.

        Args:
            value: Raw field value.
            default: Value to use on conversion failures.

        Returns:
            Parsed integer value.
        """
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _as_float(value: Any, default: float = 0.0) -> float:
        """Normalize a raw field into a float.

        Args:
            value: Raw field value.
            default: Value to use on conversion failures.

        Returns:
            Parsed float value.
        """
        try:
            return float(value)
        except (TypeError, ValueError):
            return default
