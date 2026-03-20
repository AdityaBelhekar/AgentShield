from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from typing import Any

from loguru import logger

from agentshield.config import AgentShieldConfig
from agentshield.events.emitter import EventEmitter
from agentshield.events.models import BaseEvent
from agentshield.exceptions import EventEmissionError


class BaseInterceptor(ABC):
    """Abstract base class for all AgentShield interceptors.

    An interceptor hooks into a specific layer of an agent framework and emits
    events for everything it observes.

    Three concrete interceptors extend this:
        - LLMInterceptor: hooks LLM calls and chain lifecycle
        - ToolInterceptor: hooks tool invocations
        - MemoryInterceptor: hooks memory read/write operations

    Each interceptor follows the same lifecycle:
        1. __init__: store config, emitter, session context
        2. attach(): hook into the target (agent/tools/memory)
        3. observe: emit events as execution happens
        4. detach(): restore original state cleanly

    Reliability contract:
        _emit() never raises to the interceptor. If event emission fails, it is
        logged and execution continues. The agent must never be interrupted by
        its security layer.

    Attributes:
        _emitter: EventEmitter instance for publishing events.
        _config: AgentShieldConfig with thresholds and flags.
        _session_id: UUID of the current agent session.
        _agent_id: Human-readable agent identifier string.
        _attached: Whether this interceptor is currently active.
    """

    _emitter: EventEmitter
    _config: AgentShieldConfig
    _session_id: uuid.UUID
    _agent_id: str
    _attached: bool

    def __init__(
        self,
        emitter: EventEmitter,
        config: AgentShieldConfig,
        session_id: uuid.UUID,
        agent_id: str,
    ) -> None:
        """Initialize the base interceptor.

        Args:
            emitter: EventEmitter for publishing security events.
            config: AgentShieldConfig with detection settings.
            session_id: UUID of the current session.
            agent_id: Human-readable identifier for this agent.
        """
        self._emitter = emitter
        self._config = config
        self._session_id = session_id
        self._agent_id = agent_id
        self._attached = False

        logger.debug(
            "{} initialized | session={} agent={}",
            self.__class__.__name__,
            session_id,
            agent_id,
        )

    @abstractmethod
    def attach(self, target: Any) -> None:
        """Hook this interceptor into the target object.

        After attach() returns, all relevant events on target will be
        intercepted and emitted via the EventEmitter.

        Args:
            target: The object to hook into. Type varies by subclass.
        """

    @abstractmethod
    def detach(self) -> None:
        """Remove this interceptor and restore original state.

        After detach() returns, the target object behaves exactly as it did
        before attach() was called.
        """

    @property
    @abstractmethod
    def is_attached(self) -> bool:
        """Whether this interceptor is currently active.

        Returns:
            True if attach() has been called and detach() has not been called
            since.
        """

    def _emit(self, event: BaseEvent) -> None:
        """Emit a security event via the EventEmitter.

        Wraps EventEmitter.emit() with interceptor-level error handling. This
        method never raises and logs failures instead.

        Args:
            event: Any BaseEvent subclass instance to emit.
        """
        try:
            self._emitter.emit(event)
        except EventEmissionError as exc:
            logger.error(
                "{} failed to emit event | type={} error={}",
                self.__class__.__name__,
                event.event_type,
                exc,
            )
        except Exception as exc:  # pragma: no cover - defensive safety net
            logger.error(
                "{} unexpected error during emit | type={} error={}",
                self.__class__.__name__,
                event.event_type,
                exc,
            )

    def _make_base_kwargs(self, **overrides: Any) -> dict[str, Any]:
        """Build common kwargs shared by all event constructors.

        Args:
            **overrides: Additional event fields to merge in.

        Returns:
            Dictionary with session_id, agent_id, and any overrides.
        """
        return {
            "session_id": self._session_id,
            "agent_id": self._agent_id,
            **overrides,
        }
