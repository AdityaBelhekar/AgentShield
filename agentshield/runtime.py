"""Core runtime orchestration and public shield() API for AgentShield."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from loguru import logger

from agentshield.adapters import AdapterConfig, AdapterContext, AdapterRegistry, BaseAdapter
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
    EventType,
    LLMEvent,
    MemoryEvent,
    SessionEvent,
    SeverityLevel,
    ToolCallEvent,
    TrustLevel,
)
from agentshield.exceptions import AuditChainError, ConfigurationError, PolicyViolationError
from agentshield.policy.compiler import CompiledPolicy, PolicyCompiler

_VALID_FRAMEWORKS: tuple[str, ...] = (
    "langchain",
    "llamaindex",
    "autogen",
    "openai",
    "anthropic",
)

_active_runtimes: dict[str, AgentShieldRuntime] = {}


@dataclass(slots=True)
class _SessionContext:
    """Internal runtime session state.

    Attributes:
        session_id: UUID identifying this wrapped session.
        agent_id: Human-readable agent identifier.
        framework: Adapter framework key.
        policy_name: Active policy name.
        original_task: Optional original task text.
        started_at: UTC timestamp for session start.
        started_monotonic: Monotonic start time for duration math.
        event_count: Number of processed events.
        threat_count: Number of threats detected.
        tool_calls_total: Total observed tool calls.
        tool_calls_blocked: Tool calls blocked by policy.
    """

    session_id: uuid.UUID
    agent_id: str
    framework: str
    policy_name: str
    original_task: str
    started_at: datetime
    started_monotonic: float
    event_count: int = 0
    threat_count: int = 0
    tool_calls_total: int = 0
    tool_calls_blocked: int = 0


class WrappedAgent:
    """Runtime-managed wrapper around a protected agent instance."""

    _agent: Any
    _context: _SessionContext
    _runtime: AgentShieldRuntime

    def __init__(self, agent: Any, context: _SessionContext, runtime: AgentShieldRuntime) -> None:
        """Initialize wrapped agent.

        Args:
            agent: Framework-native agent object.
            context: Runtime session context.
            runtime: Runtime that owns this wrapped session.
        """
        self._agent = agent
        self._context = context
        self._runtime = runtime

    def __enter__(self) -> WrappedAgent:
        """Enter context manager.

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
        """Exit context manager and close runtime session.

        Args:
            exc_type: Exception type if one was raised.
            exc_val: Exception value if one was raised.
            exc_tb: Traceback object if one was raised.

        Returns:
            False to always propagate caller exceptions.
        """
        del exc_type, exc_val, exc_tb
        self.close()
        return False

    def __getattr__(self, name: str) -> Any:
        """Delegate unknown attributes to the wrapped agent object.

        Args:
            name: Attribute name.

        Returns:
            Attribute value from wrapped agent.
        """
        return getattr(self._agent, name)

    @property
    def session_id(self) -> uuid.UUID:
        """Return the active session UUID."""
        return self._context.session_id

    @property
    def agent_id(self) -> str:
        """Return wrapped agent identifier."""
        return self._context.agent_id

    def close(self) -> None:
        """Close the wrapped runtime session."""
        self._runtime._close_session(self._context)

    def run(self, input: str, **kwargs: Any) -> Any:
        """Execute the wrapped agent with a best-effort generic run strategy.

        Args:
            input: Prompt or task input text.
            **kwargs: Framework-specific execution kwargs.

        Returns:
            Framework-native execution result.

        Raises:
            ConfigurationError: If no runnable method is available.
        """
        run_method = getattr(self._agent, "run", None)
        if callable(run_method):
            return run_method(input, **kwargs)

        invoke_method = getattr(self._agent, "invoke", None)
        if callable(invoke_method):
            try:
                return invoke_method(input, **kwargs)
            except TypeError:
                return invoke_method({"input": input}, **kwargs)

        query_method = getattr(self._agent, "query", None)
        if callable(query_method):
            return query_method(input, **kwargs)

        chat_method = getattr(self._agent, "chat", None)
        if callable(chat_method):
            return chat_method(input, **kwargs)

        generate_reply_method = getattr(self._agent, "generate_reply", None)
        if callable(generate_reply_method):
            return generate_reply_method(messages=[{"role": "user", "content": input}], **kwargs)

        raise ConfigurationError(
            "Wrapped agent has no runnable surface. Supported run methods: "
            "run, invoke, query, chat, generate_reply."
        )

    def invoke(self, inputs: dict[str, Any] | str, **kwargs: Any) -> Any:
        """Invoke wrapped agent with structured input.

        Args:
            inputs: Input payload.
            **kwargs: Framework-specific invocation kwargs.

        Returns:
            Framework-native invocation result.

        Raises:
            ConfigurationError: If no invocation method is available.
        """
        invoke_method = getattr(self._agent, "invoke", None)
        if callable(invoke_method):
            return invoke_method(inputs, **kwargs)

        if isinstance(inputs, str):
            return self.run(inputs, **kwargs)

        if "input" in inputs:
            return self.run(str(inputs["input"]), **kwargs)

        raise ConfigurationError(
            "Wrapped agent has no invoke() method and input payload does not contain 'input'."
        )


class AgentShieldRuntime:
    """Orchestrate session lifecycle and event routing for one wrapped agent."""

    _config: AgentShieldConfig
    _framework: str
    _agent_id: str
    _policy: CompiledPolicy
    _runtime_session_id: str
    _emitter: EventEmitter
    _audit_chain: AuditChainStore | None
    detection_engine: DetectionEngine
    _sessions: dict[uuid.UUID, _SessionContext]
    _active_session_id: uuid.UUID | None
    _last_prompt_by_session: dict[uuid.UUID, str]
    _tool_start_times: dict[tuple[uuid.UUID, str], float]

    def __init__(
        self,
        config: AgentShieldConfig,
        framework: str,
        agent_id: str,
        compiled_policy: CompiledPolicy,
    ) -> None:
        """Initialize runtime instance.

        Args:
            config: Runtime configuration.
            framework: Active adapter framework key.
            agent_id: Wrapped agent identifier.
            compiled_policy: Compiled policy used by this runtime.
        """
        self._config = config
        self._framework = framework
        self._agent_id = agent_id
        self._policy = compiled_policy
        self._runtime_session_id = str(uuid.uuid4())

        if config.audit_chain_enabled:
            self._audit_chain = AuditChainStore(
                persist_path=config.audit_chain_path,
                max_memory_entries=config.audit_chain_max_memory_entries,
            )
        else:
            self._audit_chain = None

        self._emitter = EventEmitter(config, audit_chain=self._audit_chain)
        self.detection_engine = DetectionEngine(config, self._emitter)
        self.detection_engine.set_policy(compiled_policy.config)

        self._sessions = {}
        self._active_session_id = None
        self._last_prompt_by_session = {}
        self._tool_start_times = {}

        _active_runtimes[self._runtime_session_id] = self

        self._config.log_active_config()
        logger.info(
            "AgentShieldRuntime initialized | runtime={} framework={} policy={} agent={}",
            self._runtime_session_id,
            framework,
            compiled_policy.name,
            agent_id,
        )

    @property
    def config(self) -> AgentShieldConfig:
        """Return active runtime config."""
        return self._config

    @property
    def session_id(self) -> str:
        """Return runtime-level unique identifier."""
        return self._runtime_session_id

    @property
    def framework(self) -> str:
        """Return active framework key."""
        return self._framework

    @property
    def agent_id(self) -> str:
        """Return wrapped agent identifier."""
        return self._agent_id

    @property
    def policy_name(self) -> str:
        """Return active policy name."""
        return self._policy.name

    @property
    def active_sessions(self) -> int:
        """Count active sessions for this runtime."""
        return len(self._sessions)

    def to_agent_record(self) -> dict[str, Any]:
        """Serialize runtime status for backend agent listing.

        Returns:
            Agent metadata dictionary.
        """
        return {
            "name": self._agent_id,
            "framework": self._framework,
            "policy": self._policy.name,
            "status": "active" if self.active_sessions > 0 else "disconnected",
            "active": self.active_sessions > 0,
            "runtime_id": self._runtime_session_id,
        }

    def wrap(
        self,
        agent: Any,
        tools: list[Any] | None = None,
        original_task: str = "",
    ) -> WrappedAgent:
        """Create a wrapped session for the provided agent object.

        Args:
            agent: Framework-native agent instance.
            tools: Optional tool collection used by some adapters.
            original_task: Optional human-readable session task.

        Returns:
            Wrapped agent with lifecycle controls.
        """
        del tools
        session_id = uuid.uuid4()
        context = _SessionContext(
            session_id=session_id,
            agent_id=self._agent_id,
            framework=self._framework,
            policy_name=self._policy.name,
            original_task=original_task,
            started_at=datetime.now(UTC),
            started_monotonic=time.monotonic(),
        )

        self._sessions[session_id] = context
        self._active_session_id = session_id

        self.detection_engine.initialize_session(
            session_id=session_id,
            agent_id=self._agent_id,
            original_task=original_task,
        )

        self._emitter.emit(
            SessionEvent(
                session_id=session_id,
                agent_id=self._agent_id,
                event_type=EventType.SESSION_START,
                severity=SeverityLevel.INFO,
                original_task=original_task,
                framework=self._framework,
                policy_snapshot=self._policy.to_snapshot(),
            )
        )

        logger.info(
            "Session started | runtime={} session={} framework={} policy={} agent={}",
            self._runtime_session_id,
            session_id,
            self._framework,
            self._policy.name,
            self._agent_id,
        )

        return WrappedAgent(agent=agent, context=context, runtime=self)

    def on_llm_start(self, prompt: str) -> None:
        """Record an LLM start event before model invocation.

        Args:
            prompt: Prompt text sent to the model.
        """
        context = self._get_active_context()
        if context is None:
            return

        self._last_prompt_by_session[context.session_id] = prompt
        event = LLMEvent(
            session_id=context.session_id,
            agent_id=context.agent_id,
            event_type=EventType.LLM_PROMPT,
            severity=SeverityLevel.INFO,
            prompt=prompt,
            model=context.framework,
        )
        self._emit_and_process(event, context)

    def on_llm_end(self, response: str) -> None:
        """Record an LLM end event after model invocation.

        Args:
            response: Model response text.
        """
        context = self._get_active_context()
        if context is None:
            return

        prompt = self._last_prompt_by_session.pop(context.session_id, "")
        event = LLMEvent(
            session_id=context.session_id,
            agent_id=context.agent_id,
            event_type=EventType.LLM_RESPONSE,
            severity=SeverityLevel.INFO,
            prompt=prompt,
            response=response,
            model=context.framework,
        )
        self._emit_and_process(event, context)

    def on_tool_start(self, name: str, input: Any) -> None:
        """Record a tool start event.

        Args:
            name: Tool name.
            input: Tool input payload.
        """
        context = self._get_active_context()
        if context is None:
            return

        self._tool_start_times[(context.session_id, name)] = time.monotonic()
        event = ToolCallEvent(
            session_id=context.session_id,
            agent_id=context.agent_id,
            event_type=EventType.TOOL_CALL_START,
            severity=SeverityLevel.INFO,
            tool_name=name,
            tool_input={"value": str(input)},
            trust_level=TrustLevel.EXTERNAL,
        )
        context.tool_calls_total += 1
        self._emit_and_process(event, context)

    def on_tool_end(self, name: str, output: Any) -> None:
        """Record a tool completion event.

        Args:
            name: Tool name.
            output: Tool output payload.
        """
        context = self._get_active_context()
        if context is None:
            return

        started = self._tool_start_times.pop((context.session_id, name), None)
        execution_ms = None
        if started is not None:
            execution_ms = (time.monotonic() - started) * 1000.0

        event = ToolCallEvent(
            session_id=context.session_id,
            agent_id=context.agent_id,
            event_type=EventType.TOOL_CALL_COMPLETE,
            severity=SeverityLevel.INFO,
            tool_name=name,
            tool_output=str(output),
            execution_time_ms=execution_ms,
            trust_level=TrustLevel.EXTERNAL,
        )
        self._emit_and_process(event, context)

    def on_memory_read(self, content: str) -> None:
        """Record memory read interception.

        Args:
            content: Memory content read preview.
        """
        context = self._get_active_context()
        if context is None:
            return

        event = MemoryEvent(
            session_id=context.session_id,
            agent_id=context.agent_id,
            event_type=EventType.MEMORY_READ,
            severity=SeverityLevel.INFO,
            operation="read",
            memory_key="memory",
            content_preview=content,
            content_length=len(content),
        )
        self._emit_and_process(event, context)

    def on_memory_write(self, content: str) -> None:
        """Record memory write interception.

        Args:
            content: Memory content written preview.
        """
        context = self._get_active_context()
        if context is None:
            return

        event = MemoryEvent(
            session_id=context.session_id,
            agent_id=context.agent_id,
            event_type=EventType.MEMORY_WRITE,
            severity=SeverityLevel.INFO,
            operation="write",
            memory_key="memory",
            content_preview=content,
            content_length=len(content),
        )
        self._emit_and_process(event, context)

    def record_inter_agent_message(
        self,
        sender_agent_id: str,
        receiver_agent_id: str,
        content: str,
    ) -> None:
        """Record and evaluate a message exchanged between two agents.

        Args:
            sender_agent_id: Sender identifier.
            receiver_agent_id: Receiver identifier.
            content: Message content.
        """
        context = self._get_active_context()
        if context is None:
            return

        threat = self.detection_engine.record_inter_agent_message(
            sender_agent_id=sender_agent_id,
            receiver_agent_id=receiver_agent_id,
            content=content,
            receiver_session_id=context.session_id,
        )
        if threat is not None:
            context.threat_count += 1

    def _emit_and_process(self, event: Any, context: _SessionContext) -> None:
        """Emit one event and route it through detection.

        Args:
            event: Event model instance.
            context: Active session context.

        Raises:
            PolicyViolationError: If policy blocks execution.
        """
        self._emitter.emit(event)
        try:
            threats = self.detection_engine.process_event(event)
            context.event_count += 1
            if threats:
                context.threat_count += len(threats)
        except PolicyViolationError:
            context.event_count += 1
            context.threat_count += 1
            if getattr(event, "event_type", None) == EventType.TOOL_CALL_START:
                context.tool_calls_blocked += 1
            raise

    def _get_active_context(self) -> _SessionContext | None:
        """Return currently active session context when available."""
        if self._active_session_id is None:
            return None
        return self._sessions.get(self._active_session_id)

    def _close_session(self, context: _SessionContext) -> None:
        """Close an active session and release runtime resources.

        Args:
            context: Session context to close.
        """
        if context.session_id not in self._sessions:
            return

        duration_seconds = max(time.monotonic() - context.started_monotonic, 0.0)

        self._emitter.emit(
            SessionEvent(
                session_id=context.session_id,
                agent_id=context.agent_id,
                event_type=EventType.SESSION_END,
                severity=SeverityLevel.INFO,
                original_task=context.original_task,
                framework=context.framework,
                policy_snapshot=self._policy.to_snapshot(),
                total_events=context.event_count,
                threats_detected=context.threat_count,
                tool_calls_total=context.tool_calls_total,
                tool_calls_blocked=context.tool_calls_blocked,
                metadata={"session_duration_seconds": round(duration_seconds, 6)},
            )
        )

        self._emitter.flush()
        self.detection_engine.close_session(context.session_id)

        del self._sessions[context.session_id]
        self._last_prompt_by_session.pop(context.session_id, None)

        for key in list(self._tool_start_times):
            if key[0] == context.session_id:
                del self._tool_start_times[key]

        if self._active_session_id == context.session_id:
            self._active_session_id = None

        if not self._sessions:
            _active_runtimes.pop(self._runtime_session_id, None)

        logger.info(
            "Session closed | runtime={} session={} duration={:.3f}s",
            self._runtime_session_id,
            context.session_id,
            duration_seconds,
        )

    @property
    def audit_chain(self) -> AuditChainStore | None:
        """Return configured audit chain store when enabled."""
        return self._audit_chain

    def get_audit_chain_store(self) -> AuditChainStore:
        """Return active audit chain store.

        Returns:
            Active audit chain store.

        Raises:
            AuditChainError: If audit chain is disabled.
        """
        if self._audit_chain is None:
            raise AuditChainError("Audit chain store requested but is disabled")
        return self._audit_chain

    def verify_audit_chain(self) -> VerificationResult | None:
        """Verify active audit chain if enabled.

        Returns:
            Verification result when chain is enabled, otherwise None.
        """
        if self._audit_chain is None:
            return None
        verifier = AuditChainVerifier()
        return verifier.verify(self._audit_chain)

    def export_audit_chain(self, output_path: Path, *, format: str = "jsonl") -> None:
        """Export audit chain to disk.

        Args:
            output_path: Destination path.
            format: Output format, jsonl or json.

        Raises:
            AuditChainError: If export fails or format is unsupported.
        """
        if self._audit_chain is None:
            raise AuditChainError(
                "Audit chain export requested but audit chain is disabled"
            )

        exporter = AuditChainExporter(config=self._config)
        normalized = format.lower()
        if normalized == "jsonl":
            exporter.export_jsonl(self._audit_chain, output_path)
            return
        if normalized == "json":
            exporter.export_json_report(self._audit_chain, output_path)
            return

        raise AuditChainError("Unsupported audit chain export format. Use 'jsonl' or 'json'.")


def list_active_agents() -> list[dict[str, Any]]:
    """Return all currently active wrapped-agent records.

    Returns:
        List of agent status dictionaries.
    """
    return [runtime.to_agent_record() for runtime in _active_runtimes.values()]


def _validate_framework_override(framework: str | None) -> str | None:
    """Validate and normalize optional framework override.

    Args:
        framework: Optional framework override value.

    Returns:
        Normalized lower-case framework name, or None.

    Raises:
        ConfigurationError: If framework is unsupported.
    """
    if framework is None:
        return None

    normalized = framework.strip().lower()
    if normalized not in _VALID_FRAMEWORKS:
        options = ", ".join(_VALID_FRAMEWORKS)
        raise ConfigurationError(
            f"Invalid framework '{framework}'. Valid options: {options}."
        )
    return normalized


def _resolve_agent_id(agent: Any) -> str:
    """Resolve a stable human-readable agent identifier.

    Args:
        agent: Wrapped agent object.

    Returns:
        Derived agent identifier.
    """
    for attr in ("agent_id", "name", "id"):
        value = getattr(agent, attr, None)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return type(agent).__name__


def shield(
    agent: Any,
    policy: str | Path = "monitor_only",
    tools: list[Any] | None = None,
    framework: str | None = None,
) -> WrappedAgent:
    """Protect an agent instance with AgentShield interception and detection.

    Args:
        agent: Agent object from a supported framework.
        policy: Built-in policy name or YAML policy path.
        tools: Optional framework tool collection.
        framework: Optional explicit framework override.

    Returns:
        Wrapped agent instance ready for execution.

    Raises:
        ConfigurationError: If framework override is invalid.
    """
    runtime_config = AgentShieldConfig()
    compiled_policy = PolicyCompiler.load(policy, config=runtime_config)

    forced_framework = _validate_framework_override(framework)
    adapter: BaseAdapter
    if forced_framework is None:
        adapter = AdapterRegistry.detect(agent)
        selected_framework = adapter.framework_name
    else:
        adapter = AdapterRegistry.get(forced_framework)
        selected_framework = forced_framework

    agent_id = _resolve_agent_id(agent)
    runtime = AgentShieldRuntime(
        config=runtime_config,
        framework=selected_framework,
        agent_id=agent_id,
        compiled_policy=compiled_policy,
    )

    adapter_context = AdapterContext(
        runtime=runtime,
        config=AdapterConfig(framework_name=selected_framework),
        agent_id=agent_id,
        session_id=runtime.session_id,
    )
    wrapped_framework_agent = adapter.wrap(agent, adapter_context)

    logger.info(
        "shield() configured | framework={} policy={} agent={}",
        selected_framework,
        compiled_policy.name,
        agent_id,
    )

    return runtime.wrap(agent=wrapped_framework_agent, tools=tools or [], original_task="")
