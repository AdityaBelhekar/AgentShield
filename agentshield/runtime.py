from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from langchain_core.tools import BaseTool
from loguru import logger

from agentshield.audit import (
    AuditChainExporter,
    AuditChainStore,
    AuditChainVerifier,
    VerificationResult,
)
from agentshield.config import AgentShieldConfig
from agentshield.detection.engine import DetectionEngine
from agentshield.events.emitter import EventEmitter
from agentshield.events.models import (
    BaseEvent,
    EventType,
    SessionEvent,
    SeverityLevel,
    ToolCallEvent,
    TrustLevel,
)
from agentshield.exceptions import (
    AuditChainError,
    InterceptorError,
    PolicyViolationError,
)
from agentshield.interceptors.llm_interceptor import LLMInterceptor
from agentshield.interceptors.memory_interceptor import MemoryInterceptor
from agentshield.interceptors.tool_interceptor import ToolInterceptor
from agentshield.policy.models import PolicyConfig


class BaseMemory(Protocol):
    """Minimal protocol for memory compatibility across LangChain versions."""

    def save_context(
        self,
        inputs: dict[str, Any],
        outputs: dict[str, Any],
    ) -> Any: ...

    def load_memory_vars(self, inputs: dict[str, Any]) -> dict[str, Any]: ...


@dataclass
class _SessionContext:
    """Internal session state managed by AgentShieldRuntime.

    Created when wrap() is called and destroyed when the
    WrappedAgent context manager exits.

    Attributes:
        session_id: UUID uniquely identifying this session.
        agent_id: Human-readable agent identifier.
        original_task: The task the agent was given.
        framework: Agent framework in use.
        started_at: UTC timestamp of session start.
        started_monotonic: Monotonic start marker for duration.
        llm_interceptor: Attached LLM interceptor.
        tool_interceptor: Attached tool interceptor.
        memory_interceptor: Attached memory interceptor or None.
        event_count: Total events emitted this session.
        threat_count: Total threats detected this session.
    """

    session_id: uuid.UUID
    agent_id: str
    original_task: str
    framework: str
    started_at: datetime
    started_monotonic: float
    llm_interceptor: LLMInterceptor
    tool_interceptor: ToolInterceptor
    memory_interceptor: MemoryInterceptor | None = None
    event_count: int = 0
    threat_count: int = 0


class WrappedAgent:
    """A LangChain agent wrapped with AgentShield protection.

    Context manager that manages the full session lifecycle:
      __enter__: session is already started (done in wrap())
      __exit__: emits SESSION_END, detaches interceptors,
                flushes emitter

    Also provides run() and invoke() as pass-through methods
    to the underlying agent.

    Attributes:
        _agent: The original unwrapped agent.
        _context: Session context for this session.
        _emitter: EventEmitter shared with interceptors.
        _runtime: The AgentShieldRuntime that created this.
    """

    _agent: Any
    _context: _SessionContext
    _emitter: EventEmitter
    _runtime: AgentShieldRuntime

    def __init__(
        self,
        agent: Any,
        context: _SessionContext,
        emitter: EventEmitter,
        runtime: AgentShieldRuntime,
    ) -> None:
        """Initialize WrappedAgent.

        Args:
            agent: The original LangChain agent instance.
            context: Session context for this agent session.
            emitter: EventEmitter for publishing events.
            runtime: The runtime that created this instance.
        """
        self._agent = agent
        self._context = context
        self._emitter = emitter
        self._runtime = runtime

    def __enter__(self) -> WrappedAgent:
        """Enter the runtime context.

        Returns:
            This wrapped agent.
        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any | None,
    ) -> Literal[False]:
        """Exit the runtime context and clean up session resources.

        Args:
            exc_type: Exception type if raised, else None.
            exc_val: Exception instance if raised, else None.
            exc_tb: Traceback if exception raised, else None.

        Returns:
            False so exceptions are not suppressed.
        """
        del exc_type, exc_val, exc_tb
        self.close()
        return False

    def close(self) -> None:
        """Explicitly close the session and clean up resources.

        Safe to call multiple times. Subsequent calls are no-ops.
        """
        self._runtime._close_session(self._context)

    def run(self, input: str, **kwargs: Any) -> str:
        """Run the agent with a string input.

        Args:
            input: String task for the agent to execute.
            **kwargs: Additional kwargs passed to the agent.

        Returns:
            Agent output as a string.
        """
        logger.info(
            "Agent run started | agent={} session={}",
            self._context.agent_id,
            self._context.session_id,
        )

        result = self._agent.invoke({"input": input}, **kwargs)
        if isinstance(result, dict):
            return str(result.get("output", result))
        return str(result)

    def invoke(self, inputs: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        """Invoke the agent with a dictionary of inputs.

        Args:
            inputs: Input dictionary for the agent.
            **kwargs: Additional kwargs passed to the agent.

        Returns:
            Agent output as a dictionary.
        """
        logger.info(
            "Agent invoke started | agent={} session={}",
            self._context.agent_id,
            self._context.session_id,
        )
        result = self._agent.invoke(inputs, **kwargs)
        if isinstance(result, dict):
            return result
        return {"output": str(result)}

    @property
    def session_id(self) -> uuid.UUID:
        """Get the UUID of the current session.

        Returns:
            Current session UUID.
        """
        return self._context.session_id

    @property
    def agent_id(self) -> str:
        """Get the current agent identifier string.

        Returns:
            Agent identifier.
        """
        return self._context.agent_id


class AgentShieldRuntime:
    """Orchestrates AgentShield session lifecycle.

    Creates sessions, attaches interceptors, emits session
    events, and manages cleanup.

    Attributes:
        _config: AgentShieldConfig for this runtime.
        _emitter: Shared EventEmitter across all sessions.
        detection_engine: DetectionEngine for threat orchestration.
        _sessions: Active sessions keyed by session_id.
    """

    _config: AgentShieldConfig
    _emitter: EventEmitter
    _audit_chain: AuditChainStore | None
    detection_engine: DetectionEngine
    _sessions: dict[uuid.UUID, _SessionContext]

    def __init__(self, config: AgentShieldConfig) -> None:
        """Initialize the AgentShieldRuntime.

        Args:
            config: AgentShieldConfig with all runtime settings.
        """
        self._config = config
        if config.audit_chain_enabled:
            self._audit_chain = AuditChainStore(
                persist_path=config.audit_chain_path,
                max_memory_entries=config.audit_chain_max_memory_entries,
            )
        else:
            self._audit_chain = None

        self._emitter = EventEmitter(config, audit_chain=self._audit_chain)
        self.detection_engine = DetectionEngine(config, self._emitter)
        self._sessions = {}

        self._config.log_active_config()
        logger.info("AgentShieldRuntime initialized")

    def wrap(
        self,
        agent: Any,
        tools: list[BaseTool],
        memory: BaseMemory | None = None,
        original_task: str = "",
        agent_id: str = "default",
        framework: str = "langchain",
        tool_trust_overrides: dict[str, TrustLevel] | None = None,
    ) -> WrappedAgent:
        """Wrap an agent with AgentShield protection.

        Args:
            agent: LangChain agent executor to protect.
            tools: List of BaseTool instances the agent uses.
            memory: Optional BaseMemory to monitor.
            original_task: The task string for this session.
            agent_id: Human-readable identifier for this agent.
            framework: Agent framework string for audit logs.
            tool_trust_overrides: Optional per-tool trust level
                overrides for provenance classification.

        Returns:
            WrappedAgent ready to use.

        Raises:
            InterceptorError: If interceptor attachment fails.
        """
        session_id = uuid.uuid4()

        llm_interceptor = LLMInterceptor(
            emitter=self._emitter,
            config=self._config,
            session_id=session_id,
            agent_id=agent_id,
        )
        tool_interceptor = ToolInterceptor(
            emitter=self._emitter,
            config=self._config,
            session_id=session_id,
            agent_id=agent_id,
        )

        memory_interceptor: MemoryInterceptor | None = None

        try:
            llm_interceptor.attach(agent)
            self._wire_llm_event_hook(
                llm_interceptor,
                self._make_llm_event_hook(session_id),
            )
            tool_interceptor.attach(tools)
            tool_interceptor.add_pre_call_hook(self._make_pre_call_hook(session_id))
            tool_interceptor.add_post_call_hook(self._make_post_call_hook(session_id))

            if memory is not None:
                memory_interceptor = MemoryInterceptor(
                    emitter=self._emitter,
                    config=self._config,
                    session_id=session_id,
                    agent_id=agent_id,
                )
                memory_interceptor.attach(memory)
                self._wire_memory_event_hook(
                    memory_interceptor,
                    self._make_memory_event_hook(session_id),
                )
        except InterceptorError:
            if memory_interceptor is not None and memory_interceptor.is_attached:
                memory_interceptor.detach()
            if tool_interceptor.is_attached:
                tool_interceptor.detach()
            if llm_interceptor.is_attached:
                llm_interceptor.detach()
            raise

        context = _SessionContext(
            session_id=session_id,
            agent_id=agent_id,
            original_task=original_task,
            framework=framework,
            started_at=datetime.now(UTC),
            started_monotonic=time.monotonic(),
            llm_interceptor=llm_interceptor,
            tool_interceptor=tool_interceptor,
            memory_interceptor=memory_interceptor,
        )
        self._sessions[session_id] = context

        self.detection_engine.initialize_session(
            session_id=session_id,
            agent_id=agent_id,
            original_task=original_task,
        )
        if tool_trust_overrides:
            tracker = self.detection_engine._provenance_tracker
            tracker_context = tracker._contexts.get(str(session_id))
            if tracker_context is not None:
                tracker_context.tool_trust_overrides = {
                    key.lower(): value for key, value in tool_trust_overrides.items()
                }

        self._emitter.emit(
            SessionEvent(
                session_id=session_id,
                agent_id=agent_id,
                event_type=EventType.SESSION_START,
                severity=SeverityLevel.INFO,
                original_task=original_task,
                framework=framework,
            )
        )

        logger.info(
            "Session started | session={} agent={} task={}",
            session_id,
            agent_id,
            original_task[:50],
        )

        return WrappedAgent(
            agent=agent,
            context=context,
            emitter=self._emitter,
            runtime=self,
        )

    def _make_pre_call_hook(
        self,
        session_id: uuid.UUID,
    ) -> Callable[[ToolCallEvent], Any]:
        """Create a pre-call hook that runs detection on tool events.

        The hook is a closure that captures session_id and
        routes the tool event through the DetectionEngine.
        If DetectionEngine raises PolicyViolationError,
        the hook converts it to a HookResult(block=True).

        Args:
            session_id: Session UUID for context lookup.

        Returns:
            Hook callable for ToolInterceptor.add_pre_call_hook().
        """
        from agentshield.interceptors.tool_interceptor import HookResult

        _ = session_id
        engine = self.detection_engine

        def pre_call_hook(event: ToolCallEvent) -> HookResult:
            session_ctx = self._sessions.get(event.session_id)
            try:
                threats = engine.process_event(event)
                if session_ctx is not None:
                    session_ctx.event_count += 1
                    if threats:
                        session_ctx.threat_count += 1
                return HookResult(block=False)
            except PolicyViolationError as exc:
                if session_ctx is not None:
                    session_ctx.event_count += 1
                    session_ctx.threat_count += 1
                return HookResult(
                    block=True,
                    reason=exc.message,
                    confidence=exc.confidence or 0.0,
                )

        pre_call_hook.__name__ = "detection_engine_hook"
        return pre_call_hook

    def _make_llm_event_hook(
        self,
        session_id: uuid.UUID,
    ) -> Callable[[BaseEvent], None]:
        """Create a callback that routes LLM events through DetectionEngine.

        Raises: PolicyViolationError if detection warrants blocking.

        Args:
            session_id: Session UUID for context lookup.

        Returns:
            Callable that accepts a BaseEvent and processes it.
        """
        engine = self.detection_engine

        def llm_event_hook(event: BaseEvent) -> None:
            session_ctx = self._sessions.get(event.session_id)
            try:
                threats = engine.process_event(event)
                if session_ctx is not None:
                    session_ctx.event_count += 1
                    if threats:
                        session_ctx.threat_count += 1
            except PolicyViolationError:
                if session_ctx is not None:
                    session_ctx.event_count += 1
                    session_ctx.threat_count += 1
                raise
            except (RuntimeError, ValueError, TypeError) as exc:
                logger.error(
                    "DetectionEngine error on LLM event | session={} error={}",
                    str(session_id)[:8],
                    exc,
                )

        llm_event_hook.__name__ = "detection_engine_llm_hook"
        return llm_event_hook

    def _make_memory_event_hook(
        self,
        session_id: uuid.UUID,
    ) -> Callable[[BaseEvent], None]:
        """Create a callback that routes memory events through DetectionEngine.

        Raises: PolicyViolationError if detection warrants blocking.

        Args:
            session_id: Session UUID for context lookup.

        Returns:
            Callable that accepts a BaseEvent and processes it.
        """
        engine = self.detection_engine

        def memory_event_hook(event: BaseEvent) -> None:
            session_ctx = self._sessions.get(event.session_id)
            try:
                threats = engine.process_event(event)
                if session_ctx is not None:
                    session_ctx.event_count += 1
                    if threats:
                        session_ctx.threat_count += 1
            except PolicyViolationError:
                if session_ctx is not None:
                    session_ctx.event_count += 1
                    session_ctx.threat_count += 1
                raise
            except (RuntimeError, ValueError, TypeError) as exc:
                logger.error(
                    "DetectionEngine error on memory event | session={} error={}",
                    str(session_id)[:8],
                    exc,
                )

        memory_event_hook.__name__ = "detection_engine_memory_hook"
        return memory_event_hook

    def _make_post_call_hook(
        self,
        session_id: uuid.UUID,
    ) -> Callable[[ToolCallEvent], None]:
        """Create a post-call hook that routes TOOL_CALL_COMPLETE events.

        Args:
            session_id: Session UUID for context lookup.

        Returns:
            Post-call hook callable for ToolInterceptor.
        """
        engine = self.detection_engine

        def post_call_hook(event: ToolCallEvent) -> None:
            session_ctx = self._sessions.get(event.session_id)
            try:
                threats = engine.process_event(event)
                if session_ctx is not None:
                    session_ctx.event_count += 1
                    if threats:
                        session_ctx.threat_count += 1
            except (RuntimeError, ValueError, TypeError) as exc:
                if session_ctx is not None:
                    session_ctx.event_count += 1
                logger.error(
                    "DetectionEngine error on tool complete | session={} error={}",
                    str(session_id)[:8],
                    exc,
                )

        post_call_hook.__name__ = "detection_engine_post_hook"
        return post_call_hook

    def _wire_llm_event_hook(
        self,
        llm_interceptor: LLMInterceptor,
        hook: Callable[[BaseEvent], None],
    ) -> None:
        """Wrap LLMInterceptor._emit to invoke a runtime-managed hook."""
        original_emit = llm_interceptor._emit

        def emit_with_hook(event: BaseEvent) -> None:
            original_emit(event)
            try:
                hook(event)
            except Exception as exc:
                if isinstance(exc, PolicyViolationError):
                    raise
                logger.error(
                    "LLM event hook error | hook={} error={}",
                    getattr(hook, "__name__", "unknown"),
                    exc,
                )

        llm_interceptor._emit = emit_with_hook  # type: ignore[method-assign]

    def _wire_memory_event_hook(
        self,
        memory_interceptor: MemoryInterceptor,
        hook: Callable[[BaseEvent], None],
    ) -> None:
        """Wrap MemoryInterceptor._emit to invoke a runtime-managed hook."""
        original_emit = memory_interceptor._emit

        def emit_with_hook(event: BaseEvent) -> None:
            original_emit(event)
            try:
                hook(event)
            except Exception as exc:
                if isinstance(exc, PolicyViolationError):
                    raise
                logger.error(
                    "Memory event hook error | hook={} error={}",
                    getattr(hook, "__name__", "unknown"),
                    exc,
                )

        memory_interceptor._emit = emit_with_hook  # type: ignore[method-assign]

    def _close_session(self, context: _SessionContext) -> None:
        """Close a session and clean up all resources.

        Args:
            context: Session context to close.
        """
        if context.session_id not in self._sessions:
            return

        session_duration_seconds = max(
            time.monotonic() - context.started_monotonic,
            0.0,
        )

        try:
            context.llm_interceptor.detach()
            context.tool_interceptor.detach()
            if context.memory_interceptor is not None:
                context.memory_interceptor.detach()
        except InterceptorError as exc:
            logger.error(
                "Error detaching interceptors | session={} error={}",
                context.session_id,
                exc,
            )

        self._emitter.emit(
            SessionEvent(
                session_id=context.session_id,
                agent_id=context.agent_id,
                event_type=EventType.SESSION_END,
                severity=SeverityLevel.INFO,
                original_task=context.original_task,
                framework=context.framework,
                total_events=context.event_count,
                threats_detected=context.threat_count,
                metadata={
                    "session_duration_seconds": round(
                        session_duration_seconds,
                        6,
                    )
                },
            )
        )

        self._emitter.flush()
        self.detection_engine.close_session(context.session_id)
        del self._sessions[context.session_id]

        logger.info(
            "Session closed | session={} agent={} duration={:.2f}s",
            context.session_id,
            context.agent_id,
            session_duration_seconds,
        )

    @property
    def active_sessions(self) -> int:
        """Count active sessions.

        Returns:
            Number of active sessions.
        """
        return len(self._sessions)

    @property
    def audit_chain(self) -> AuditChainStore | None:
        """Return the active audit chain store or None if disabled."""
        return self._audit_chain

    def verify_audit_chain(self) -> VerificationResult | None:
        """Verify the currently configured audit chain.

        Returns:
            VerificationResult when enabled, else None.
        """
        if self._audit_chain is None:
            return None

        verifier = AuditChainVerifier()
        return verifier.verify(self._audit_chain)

    def export_audit_chain(self, output_path: Path, *, format: str = "jsonl") -> None:
        """Export the current audit chain to file.

        Args:
            output_path: Path for export output.
            format: Export format, either "jsonl" or "json".

        Raises:
            AuditChainError: If chain is disabled, format is invalid,
                or export fails.
        """
        if self._audit_chain is None:
            raise AuditChainError(
                "Audit chain export requested but audit chain is disabled"
            )

        exporter = AuditChainExporter(config=self._config)
        normalized_format = format.lower()

        if normalized_format == "jsonl":
            exporter.export_jsonl(self._audit_chain, output_path)
            return

        if normalized_format == "json":
            exporter.export_json_report(self._audit_chain, output_path)
            return

        raise AuditChainError(
            "Unsupported audit chain export format. Use 'jsonl' or 'json'."
        )


def shield(
    agent: Any,
    *,
    tools: list[Any] | None = None,
    memory: BaseMemory | None = None,
    policy: PolicyConfig | str | None = "monitor_only",
    config: AgentShieldConfig | None = None,
    original_task: str = "",
    agent_id: str = "default",
    framework: str = "langchain",
    tool_trust_overrides: dict[str, TrustLevel] | None = None,
) -> WrappedAgent:
    """Wrap an agent with AgentShield protection.

    Creates an AgentShieldRuntime, attaches all configured
    interceptors and detectors, optionally compiles and
    attaches a policy, and returns a WrappedAgent ready to run.

    Args:
        agent: The LangChain agent or callable to protect.
        tools: Optional list of LangChain tools to intercept.
        memory: Optional LangChain BaseMemory to intercept.
        policy: A PolicyConfig, built-in policy name
            string, path to YAML file, or None to run
            with no policy (detection only).
        config: Optional AgentShieldConfig override.
            Uses default config if not provided.
        original_task: Task string for this session.
        agent_id: Human-readable agent identifier.
        framework: Agent framework string.
        tool_trust_overrides: Optional per-tool trust level
            overrides for provenance classification.

    Returns:
        WrappedAgent with full AgentShield protection.
    """
    runtime_config = config or AgentShieldConfig()
    runtime = AgentShieldRuntime(runtime_config)

    policy = policy or "monitor_only"

    runtime.detection_engine.set_policy(policy)
    logger.info(
        "Policy attached via shield() | policy={}",
        policy if isinstance(policy, str) else type(policy).__name__,
    )

    return runtime.wrap(
        agent=agent,
        tools=cast(list[BaseTool], tools or []),
        memory=memory,
        original_task=original_task,
        agent_id=agent_id,
        framework=framework,
        tool_trust_overrides=tool_trust_overrides,
    )
