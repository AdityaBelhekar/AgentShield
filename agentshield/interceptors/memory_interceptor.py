from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any, Protocol

from loguru import logger

from agentshield.config import AgentShieldConfig
from agentshield.events.emitter import EventEmitter
from agentshield.events.models import EventType, MemoryEvent, SeverityLevel
from agentshield.exceptions import InterceptorError, PolicyViolationError
from agentshield.interceptors.base import BaseInterceptor


class BaseMemory(Protocol):
    """Minimal protocol for memory compatibility across LangChain versions."""

    def save_context(
        self,
        inputs: dict[str, Any],
        outputs: dict[str, Any],
    ) -> Any: ...

    def load_memory_vars(self, inputs: dict[str, Any]) -> dict[str, Any]: ...


class MemoryInterceptor(BaseInterceptor):
    """Intercepts LangChain memory read and write operations.

    Monkey-patches BaseMemory.save_context (write) and
    load_memory_vars (read) to emit MEMORY_WRITE and
    MEMORY_READ events for every memory operation.

    Memory events are consumed by the MemoryPoisonDetector
    in Phase 3E which uses statistical anomaly detection
    to identify anomalous content being written to memory.

    content_preview is capped at 200 characters in the
    MemoryEvent model and is truncated in this interceptor.

    Attributes:
        _target: The BaseMemory instance being monitored.
        _original_save_context: Original save_context method.
        _original_load_memory_vars: Original load_memory_vars.
    """

    _target: BaseMemory | None
    _original_save_context: Callable[..., Any] | None
    _original_load_memory_vars: Callable[..., Any] | None

    def __init__(
        self,
        emitter: EventEmitter,
        config: AgentShieldConfig,
        session_id: uuid.UUID,
        agent_id: str,
    ) -> None:
        """Initialize the MemoryInterceptor.

        Args:
            emitter: EventEmitter for publishing security events.
            config: AgentShieldConfig with detection settings.
            session_id: UUID of the current session.
            agent_id: Human-readable identifier for this agent.
        """
        super().__init__(emitter, config, session_id, agent_id)
        self._target = None
        self._original_save_context = None
        self._original_load_memory_vars = None

        logger.debug("MemoryInterceptor initialized | session={}", session_id)

    def attach(self, target: BaseMemory) -> None:
        """Monkey-patch a BaseMemory instance's read/write methods.

        Stores originals and replaces save_context and
        load_memory_vars with wrapper methods that emit
        events before or after each memory operation.

        Args:
            target: LangChain BaseMemory instance to monitor.

        Raises:
            InterceptorError: If memory object lacks expected
                methods or patching fails.
        """
        try:
            if not hasattr(target, "save_context"):
                raise InterceptorError(
                    f"Memory object {type(target).__name__} has no save_context method"
                )
            if not hasattr(target, "load_memory_vars"):
                raise InterceptorError(
                    f"Memory object {type(target).__name__} has no load_memory_vars method"
                )

            self._original_save_context = target.save_context
            self._original_load_memory_vars = target.load_memory_vars
            self._target = target

            target_obj = self._as_any(target)
            target_obj.save_context = self._save_context_wrapper
            target_obj.load_memory_vars = self._load_memory_vars_wrapper

            self._attached = True

            logger.info(
                "MemoryInterceptor attached | memory_type={} session={}",
                type(target).__name__,
                self._session_id,
            )
        except InterceptorError:
            raise
        except (AttributeError, TypeError, ValueError) as exc:
            raise InterceptorError(
                f"Failed to attach MemoryInterceptor: {exc}"
            ) from exc

    def detach(self) -> None:
        """Restore original save_context and load_memory_vars.

        After detach(), the memory object behaves exactly
        as it did before attach() was called.
        Safe to call even if not currently attached.

        Raises:
            InterceptorError: If restoration fails.
        """
        try:
            if self._target is not None:
                target_obj = self._as_any(self._target)
                if self._original_save_context is not None:
                    target_obj.save_context = self._original_save_context
                if self._original_load_memory_vars is not None:
                    target_obj.load_memory_vars = self._original_load_memory_vars

            self._target = None
            self._original_save_context = None
            self._original_load_memory_vars = None
            self._attached = False

            logger.info("MemoryInterceptor detached | session={}", self._session_id)
        except (AttributeError, TypeError, ValueError) as exc:
            raise InterceptorError(
                f"Failed to detach MemoryInterceptor: {exc}"
            ) from exc

    @property
    def is_attached(self) -> bool:
        """Whether this interceptor is currently active.

        Returns:
            True if attach() has been called and detach()
            has not been called since.
        """
        return self._attached

    def _save_context_wrapper(
        self,
        inputs: dict[str, Any],
        outputs: dict[str, Any],
    ) -> None:
        """Wrapper for BaseMemory.save_context.

        Emits MEMORY_WRITE event before calling original.
        The content preview is built from outputs.

        Args:
            inputs: Input dict passed to save_context.
            outputs: Output dict passed to save_context.

        Raises:
            InterceptorError: If original method is missing.
        """
        try:
            content = str(outputs)
            content_preview = content[:200]
            memory_key = self._extract_memory_key(outputs)

            event = MemoryEvent(
                **self._make_base_kwargs(
                    event_type=EventType.MEMORY_WRITE,
                    severity=SeverityLevel.INFO,
                ),
                operation="write",
                memory_key=memory_key,
                content_preview=content_preview,
                content_length=len(content),
            )
            self._emit(event)

            logger.debug(
                "Memory write intercepted | key={} length={} session={}",
                memory_key,
                len(content),
                self._session_id,
            )
        except Exception as exc:  # pragma: no cover - defensive callback safety
            if isinstance(exc, PolicyViolationError):
                raise
            logger.error("MemoryInterceptor save wrapper error | error={}", exc)

        if self._original_save_context is None:
            raise InterceptorError("save_context wrapper invoked before attach")

        self._original_save_context(inputs, outputs)

    def _load_memory_vars_wrapper(self, inputs: dict[str, Any]) -> dict[str, Any]:
        """Wrapper for BaseMemory.load_memory_vars.

        Calls original first, then emits MEMORY_READ event
        with a preview of the returned memory content.

        Args:
            inputs: Input dict passed to load_memory_vars.

        Returns:
            The memory variables dict from original method.

        Raises:
            InterceptorError: If original method is missing.
        """
        if self._original_load_memory_vars is None:
            raise InterceptorError("load_memory_vars wrapper invoked before attach")

        result_obj = self._original_load_memory_vars(inputs)
        result = dict(result_obj)

        try:
            content = str(result)
            content_preview = content[:200]
            memory_key = self._extract_memory_key(result)

            event = MemoryEvent(
                **self._make_base_kwargs(
                    event_type=EventType.MEMORY_READ,
                    severity=SeverityLevel.INFO,
                ),
                operation="read",
                memory_key=memory_key,
                content_preview=content_preview,
                content_length=len(content),
            )
            self._emit(event)

            logger.debug(
                "Memory read intercepted | key={} length={} session={}",
                memory_key,
                len(content),
                self._session_id,
            )
        except Exception as exc:  # pragma: no cover - defensive callback safety
            if isinstance(exc, PolicyViolationError):
                raise
            logger.error("MemoryInterceptor load wrapper error | error={}", exc)

        return result

    def _extract_memory_key(self, data: dict[str, Any]) -> str:
        """Extract a representative key string from a memory dict.

        Takes the first key from the dict as the memory key
        identifier. Falls back to "memory" if the dict is empty.

        Args:
            data: Memory data dictionary.

        Returns:
            String key identifying this memory operation.
        """
        if data:
            return str(next(iter(data.keys())))
        return "memory"

    def _as_any(self, target: BaseMemory) -> Any:
        """Cast a typed memory object to Any for monkey-patching.

        Args:
            target: Memory object being patched.

        Returns:
            Same object typed as Any for dynamic method assignment.
        """
        return target
