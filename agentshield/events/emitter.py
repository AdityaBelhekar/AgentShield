from __future__ import annotations

import time
from pathlib import Path

import redis
import redis.asyncio as aioredis
from loguru import logger

from agentshield.config import AgentShieldConfig
from agentshield.events.models import BaseEvent
from agentshield.exceptions import EventEmissionError, RedisConnectionError


class EventEmitter:
    """Publishes AgentShield events to Redis and a JSONL audit log.

    Every event emitted by AgentShield flows through this class.
    It handles two output channels in parallel:
    1. Redis pub/sub consumed by the backend in real time.
    2. JSONL file as a persistent local audit log.

    Reliability contract:
        All public emit methods never raise exceptions to callers.
        Failures in Redis or file I/O are caught and logged, and
        execution continues normally.

    Retry strategy:
        Redis publishes are retried with exponential backoff.

    Lazy initialization:
        Redis clients are created only on first use.
    """

    _config: AgentShieldConfig
    _redis_client: redis.Redis[bytes] | None
    _async_redis_client: aioredis.Redis[bytes] | None
    _audit_log_path: Path
    _emit_count: int
    _fail_count: int

    def __init__(self, config: AgentShieldConfig) -> None:
        """Initialize the EventEmitter with SDK configuration.

        Args:
            config: AgentShield configuration for Redis and audit logging.
        """
        self._config = config
        self._redis_client = None
        self._async_redis_client = None
        self._audit_log_path = Path(config.audit_log_path)
        self._emit_count = 0
        self._fail_count = 0

        logger.info(
            "EventEmitter initialized | channel={} log_path={}",
            config.event_channel,
            config.audit_log_path,
        )

    def emit(self, event: BaseEvent) -> None:
        """Synchronously emit a single event to Redis and the audit log.

        This method never raises. All failures are handled internally.

        Args:
            event: Event instance to publish.
        """
        try:
            self._emit_count += 1

            message = self._serialize(event)
            if message is None:
                self._fail_count += 1
                return

            published = self._emit_with_retry(
                channel=self._config.event_channel,
                message=message,
                max_retries=3,
            )

            if not published:
                self._fail_count += 1
                logger.warning(
                    "Redis publish failed after all retries | "
                    "event_id={} type={} session={}",
                    event.id,
                    event.event_type,
                    event.session_id,
                )

            self._write_audit_log(event)

            logger.debug(
                "Event emitted | id={} type={} severity={} session={}",
                event.id,
                event.event_type,
                event.severity,
                event.session_id,
            )
        except (EventEmissionError, RedisConnectionError) as exc:
            self._fail_count += 1
            logger.error("Emit failed with AgentShield exception | error={}", exc)
        except Exception as exc:
            self._fail_count += 1
            logger.error("Unexpected emit failure | error={}", exc)

    async def emit_async(self, event: BaseEvent) -> None:
        """Asynchronously emit a single event using redis.asyncio.

        This method never raises. Redis failures are logged and the
        event is still written to the local audit log.

        Args:
            event: Event instance to publish.
        """
        try:
            self._emit_count += 1

            message = self._serialize(event)
            if message is None:
                self._fail_count += 1
                return

            try:
                client = self._get_async_redis()
                await client.publish(self._config.event_channel, message)
                logger.debug(
                    "Async event emitted | id={} type={}",
                    event.id,
                    event.event_type,
                )
            except Exception as exc:
                self._fail_count += 1
                logger.warning(
                    "Async Redis publish failed | event_id={} error={}",
                    event.id,
                    exc,
                )

            self._write_audit_log(event)
        except (EventEmissionError, RedisConnectionError) as exc:
            self._fail_count += 1
            logger.error("Async emit failed with AgentShield exception | error={}", exc)
        except Exception as exc:
            self._fail_count += 1
            logger.error("Unexpected async emit failure | error={}", exc)

    def emit_batch(self, events: list[BaseEvent]) -> None:
        """Emit multiple events efficiently using a Redis pipeline.

        This method never raises. If Redis pipeline publish fails,
        events are still written to the audit log.

        Args:
            events: Events to publish. Empty list is a no-op.
        """
        try:
            if not events:
                return

            self._emit_count += len(events)
            serialized: list[tuple[BaseEvent, str | None]] = [
                (event, self._serialize(event)) for event in events
            ]

            try:
                client = self._get_redis()
                pipe = client.pipeline(transaction=False)
                for _, message in serialized:
                    if message is not None:
                        pipe.publish(self._config.event_channel, message)
                pipe.execute()
                logger.info(
                    "Batch emitted via pipeline | count={} channel={}",
                    len(events),
                    self._config.event_channel,
                )
            except Exception as exc:
                self._fail_count += 1
                logger.warning(
                    "Batch Redis pipeline failed | count={} error={}",
                    len(events),
                    exc,
                )

            for event, message in serialized:
                if message is None:
                    self._fail_count += 1
                self._write_audit_log(event)
        except (EventEmissionError, RedisConnectionError) as exc:
            self._fail_count += 1
            logger.error("Batch emit failed with AgentShield exception | error={}", exc)
        except Exception as exc:
            self._fail_count += 1
            logger.error("Unexpected batch emit failure | error={}", exc)

    def flush(self) -> None:
        """Close Redis connections and log final emission statistics.

        Safe to call multiple times. This method never raises.
        """
        try:
            if self._redis_client is not None:
                self._redis_client.close()
                self._redis_client = None
                logger.debug("Sync Redis client closed")

            if self._async_redis_client is not None:
                close_method = getattr(self._async_redis_client, "aclose", None)
                if callable(close_method):
                    logger.debug("Async Redis client scheduled for close")
                self._async_redis_client = None
                logger.debug("Async Redis client cleared")

            logger.info(
                "EventEmitter flushed | total_emitted={} total_failed={}",
                self._emit_count,
                self._fail_count,
            )
        except Exception as exc:
            logger.error("Error during EventEmitter flush | error={}", exc)

    def stats(self) -> dict[str, int]:
        """Return emission statistics for monitoring.

        Returns:
            Mapping with total emitted and total failed counters.
        """
        return {
            "total_emitted": self._emit_count,
            "total_failed": self._fail_count,
        }

    def _get_redis(self) -> redis.Redis[bytes]:
        """Lazily initialize and return the synchronous Redis client.

        Returns:
            Configured Redis client.

        Raises:
            RedisConnectionError: If the Redis connection cannot be established.
        """
        if self._redis_client is None:
            try:
                pool = redis.ConnectionPool.from_url(
                    self._config.redis_url,
                    decode_responses=True,
                    max_connections=10,
                )
                client: redis.Redis[bytes] = redis.Redis(connection_pool=pool)
                client.ping()
                self._redis_client = client
                logger.info(
                    "Redis connection established | url={}",
                    self._config.redis_url,
                )
            except Exception as exc:
                raise RedisConnectionError(
                    f"Failed to connect to Redis at {self._config.redis_url}: {exc}"
                ) from exc

        return self._redis_client

    def _get_async_redis(self) -> aioredis.Redis[bytes]:
        """Lazily initialize and return the asynchronous Redis client.

        Returns:
            Configured asynchronous Redis client.
        """
        if self._async_redis_client is None:
            self._async_redis_client = aioredis.from_url(
                self._config.redis_url,
                decode_responses=True,
            )
            logger.debug(
                "Async Redis client initialized | url={}",
                self._config.redis_url,
            )
        return self._async_redis_client

    def _serialize(self, event: BaseEvent) -> str | None:
        """Serialize a BaseEvent to a JSON string.

        Args:
            event: Event object to serialize.

        Returns:
            Serialized JSON string, or None on failure.
        """
        try:
            return event.model_dump_json()
        except Exception as exc:
            logger.error(
                "Event serialization failed | event_id={} type={} error={}",
                getattr(event, "id", "unknown"),
                getattr(event, "event_type", "unknown"),
                exc,
            )
            return None

    def _write_audit_log(self, event: BaseEvent) -> None:
        """Append a single event to the local JSONL audit log.

        Failures are logged and never propagated.

        Args:
            event: Event object to append to the audit file.
        """
        try:
            self._audit_log_path.parent.mkdir(parents=True, exist_ok=True)
            serialized = self._serialize(event)
            if serialized is None:
                self._fail_count += 1
                return
            with self._audit_log_path.open("a", encoding="utf-8") as file_handle:
                file_handle.write(serialized)
                file_handle.write("\n")
        except Exception as exc:
            self._fail_count += 1
            logger.error(
                "Audit log write failed | path={} event_id={} error={}",
                self._audit_log_path,
                getattr(event, "id", "unknown"),
                exc,
            )

    def _emit_with_retry(
        self,
        channel: str,
        message: str,
        max_retries: int = 3,
    ) -> bool:
        """Publish a message to Redis with exponential backoff retries.

        Args:
            channel: Redis pub/sub channel.
            message: Serialized JSON message.
            max_retries: Maximum number of publish attempts.

        Returns:
            True if any attempt succeeds, False otherwise.
        """
        if max_retries < 1:
            logger.warning(
                "Invalid max_retries for publish; treating as one attempt | max_retries={}",
                max_retries,
            )
            max_retries = 1

        delay = 1.0
        for attempt in range(max_retries):
            try:
                client = self._get_redis()
                client.publish(channel, message)
                if attempt > 0:
                    logger.info(
                        "Redis publish succeeded on retry {} | channel={}",
                        attempt + 1,
                        channel,
                    )
                return True
            except Exception as exc:
                logger.warning(
                    "Redis publish attempt {}/{} failed | channel={} error={}",
                    attempt + 1,
                    max_retries,
                    channel,
                    exc,
                )
                if attempt < max_retries - 1:
                    time.sleep(delay)
                    delay *= 2.0

        return False
