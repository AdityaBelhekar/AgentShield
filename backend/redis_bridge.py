from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

import redis.asyncio as aioredis
from loguru import logger
from redis.exceptions import RedisError

from agentshield.events.models import (
    AuditLog,
    BaseEvent,
    CanaryEvent,
    EventType,
    LLMEvent,
    MemoryEvent,
    ProvenanceEvent,
    SessionEvent,
    ThreatEvent,
    ToolCallEvent,
)
from agentshield.exceptions import RedisConnectionError
from backend.config import BackendConfig

EVENT_TYPE_MAP: dict[str, type[BaseEvent]] = {
    EventType.TOOL_CALL_START.value: ToolCallEvent,
    EventType.TOOL_CALL_COMPLETE.value: ToolCallEvent,
    EventType.TOOL_CALL_BLOCKED.value: ToolCallEvent,
    EventType.LLM_PROMPT.value: LLMEvent,
    EventType.LLM_RESPONSE.value: LLMEvent,
    EventType.MEMORY_READ.value: MemoryEvent,
    EventType.MEMORY_WRITE.value: MemoryEvent,
    EventType.THREAT_DETECTED.value: ThreatEvent,
    EventType.SESSION_START.value: SessionEvent,
    EventType.SESSION_END.value: SessionEvent,
    EventType.CANARY_INJECTED.value: CanaryEvent,
    EventType.CANARY_TRIGGERED.value: CanaryEvent,
    EventType.PROVENANCE_TAGGED.value: ProvenanceEvent,
    "AUDIT_LOG": AuditLog,
    # Backward-compat aliases.
    "TOOL_CALL_END": ToolCallEvent,
    "LLM_START": LLMEvent,
    "LLM_END": LLMEvent,
}


class RedisBridge:
    """Async Redis pub/sub subscriber for AgentShield events.

    Connects to the same Redis channel the SDK publishes to.
    Deserializes each message into the correct event subtype
    using EVENT_TYPE_MAP, then dispatches to all registered handlers.

    Handlers are called concurrently per message. A failing handler
    never affects other handlers or the listen loop.

    Reconnection uses exponential backoff starting at 1 second,
    doubling each attempt and capped at 30 seconds.
    """

    _config: BackendConfig
    _handlers: list[Callable[[BaseEvent], Awaitable[None]]]
    _client: aioredis.Redis[Any] | None
    _pubsub: aioredis.client.PubSub | None
    _listener_task: asyncio.Task[None] | None
    _stop_event: asyncio.Event

    def __init__(self, config: BackendConfig) -> None:
        """Initialize the Redis bridge.

        Args:
            config: Backend configuration with Redis endpoint and channel.
        """
        self._config = config
        self._handlers = []
        self._client = None
        self._pubsub = None
        self._listener_task = None
        self._stop_event = asyncio.Event()

    async def start(self) -> None:
        """Start the background listener loop.

        Connects lazily inside the listener loop and begins
        processing events from Redis.
        """
        if self._listener_task is not None and not self._listener_task.done():
            logger.warning("RedisBridge start requested while already running")
            return

        self._stop_event.clear()
        self._listener_task = asyncio.create_task(self._listen_loop())
        logger.info(
            "RedisBridge started | url={} channel={}",
            self._config.redis_url,
            self._config.redis_channel,
        )

    async def stop(self) -> None:
        """Stop listener task and close Redis resources.

        Safe to call even if start() was never called.
        """
        self._stop_event.set()

        if self._listener_task is not None:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                logger.debug("RedisBridge listener task cancelled")
            self._listener_task = None

        await self._close_connections()
        logger.info("RedisBridge stopped")

    def register_handler(self, handler: Callable[[BaseEvent], Awaitable[None]]) -> None:
        """Register an async event handler.

        Args:
            handler: Async callable receiving one deserialized event.
        """
        self._handlers.append(handler)
        logger.debug("RedisBridge handler registered | count={}", len(self._handlers))

    async def _listen_loop(self) -> None:
        """Listen for Redis messages and dispatch deserialized events.

        Runs until stop() is called. Any per-message processing
        failure is logged and does not terminate the loop.
        """
        backoff_seconds = 1.0

        while not self._stop_event.is_set():
            try:
                await self._connect_and_subscribe()
                backoff_seconds = 1.0

                if self._pubsub is None:
                    raise RedisConnectionError("Redis pubsub is unavailable")

                while not self._stop_event.is_set():
                    message = await self._pubsub.get_message(
                        ignore_subscribe_messages=True,
                        timeout=1.0,
                    )
                    if message is None:
                        continue

                    event = self._deserialize_message(message)
                    if event is None:
                        continue

                    await self._dispatch(event)

            except asyncio.CancelledError:
                logger.debug("RedisBridge listener loop cancellation received")
                break
            except (RedisConnectionError, RedisError, OSError, ValueError) as exc:
                logger.error(
                    "RedisBridge listen error | backoff={}s error={}",
                    backoff_seconds,
                    exc,
                )
                await self._close_connections()

                if self._stop_event.is_set():
                    break

                await asyncio.sleep(backoff_seconds)
                backoff_seconds = min(backoff_seconds * 2.0, 30.0)

        await self._close_connections()

    async def _dispatch(self, event: BaseEvent) -> None:
        """Dispatch one event to all registered handlers concurrently.

        Args:
            event: Deserialized event model.
        """
        if not self._handlers:
            return

        tasks = [handler(event) for handler in self._handlers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for index, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(
                    "RedisBridge handler failure | handler_index={} error={}",
                    index,
                    result,
                )

    async def _connect_and_subscribe(self) -> None:
        """Establish Redis connection and subscribe to configured channel.

        Raises:
            RedisConnectionError: If the connection or subscription fails.
        """
        try:
            self._client = aioredis.from_url(
                self._config.redis_url,
                decode_responses=False,
            )
            await self._client.ping()
            self._pubsub = self._client.pubsub()
            await self._pubsub.subscribe(self._config.redis_channel)
            logger.info(
                "RedisBridge subscribed | channel={}",
                self._config.redis_channel,
            )
        except (RedisError, OSError, ValueError) as exc:
            raise RedisConnectionError(
                message=(
                    "Failed to connect/subscribe RedisBridge "
                    f"to {self._config.redis_url}"
                ),
                evidence={"channel": self._config.redis_channel, "error": str(exc)},
            ) from exc

    async def _close_connections(self) -> None:
        """Close Redis pubsub and client resources safely."""
        if self._pubsub is not None:
            try:
                await self._pubsub.unsubscribe(self._config.redis_channel)
            except (RedisError, OSError, RuntimeError) as exc:
                logger.warning("RedisBridge unsubscribe failed | error={}", exc)
            try:
                await self._pubsub.close()
            except (RedisError, OSError, RuntimeError) as exc:
                logger.warning("RedisBridge pubsub close failed | error={}", exc)
            self._pubsub = None

        if self._client is not None:
            try:
                await self._client.aclose()
            except (RedisError, OSError, RuntimeError) as exc:
                logger.warning("RedisBridge client close failed | error={}", exc)
            self._client = None

    def _deserialize_message(self, message: dict[str, Any]) -> BaseEvent | None:
        """Deserialize one Redis pub/sub message into an event model.

        Args:
            message: Redis pub/sub message dictionary.

        Returns:
            Deserialized event or None when payload is invalid.
        """
        data = message.get("data")
        if not isinstance(data, (bytes, str)):
            logger.warning("RedisBridge ignored message with unsupported payload type")
            return None

        payload = data.decode("utf-8") if isinstance(data, bytes) else data

        try:
            base_event = BaseEvent.model_validate_json(payload)
        except ValueError as exc:
            logger.error("RedisBridge payload deserialization failed | error={}", exc)
            return None

        model = EVENT_TYPE_MAP.get(base_event.event_type.value)
        if model is None:
            logger.warning(
                "RedisBridge unknown event mapping | event_type={} - using BaseEvent",
                base_event.event_type.value,
            )
            return base_event

        try:
            return model.model_validate_json(payload)
        except ValueError as exc:
            logger.warning(
                "RedisBridge typed deserialization failed | event_type={} error={} - using BaseEvent",
                base_event.event_type.value,
                exc,
            )
            return base_event
