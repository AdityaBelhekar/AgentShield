"""LlamaIndex adapter wiring for AgentShield Phase 10B."""

from __future__ import annotations

import uuid
from importlib.metadata import PackageNotFoundError, version
from typing import TYPE_CHECKING, Any

from loguru import logger

from agentshield.adapters.base import AdapterContext, BaseAdapter
from agentshield.adapters.registry import AdapterRegistry
from agentshield.events.models import EventType, LLMEvent, SeverityLevel
from agentshield.exceptions import AdapterError, AgentShieldError
from agentshield.interceptors.tool_interceptor import ToolInterceptor

if TYPE_CHECKING:
    from agentshield.runtime import AgentShieldRuntime


class _AgentShieldLlamaIndexHandler:
    """Translate LlamaIndex callback events into AgentShield LLM events.

    This handler intentionally relies on duck typing so AgentShield can be
    imported even when llama_index is not installed.

    Attributes:
        _runtime: Active AgentShield runtime instance.
        _agent_id: Agent identifier used for emitted events.
        _session_id: Adapter-scoped session UUID used for emitted events.
        _pending_prompts: Event-id keyed prompt cache for response correlation.
        event_starts_to_ignore: Callback protocol-required ignore list.
        event_ends_to_ignore: Callback protocol-required ignore list.
    """

    _runtime: AgentShieldRuntime
    _agent_id: str
    _session_id: uuid.UUID
    _pending_prompts: dict[str, str]
    event_starts_to_ignore: list[Any]
    event_ends_to_ignore: list[Any]

    def __init__(
        self,
        runtime: AgentShieldRuntime,
        agent_id: str,
        session_id: uuid.UUID,
    ) -> None:
        """Initialize a LlamaIndex-compatible callback handler.

        Args:
            runtime: Active AgentShield runtime instance.
            agent_id: Agent identifier for emitted events.
            session_id: Adapter-scoped session UUID.
        """
        self._runtime = runtime
        self._agent_id = agent_id
        self._session_id = session_id
        self._pending_prompts = {}
        self.event_starts_to_ignore = []
        self.event_ends_to_ignore = []

    def on_event_start(
        self,
        event_type: Any,
        payload: dict[str, Any] | None = None,
        event_id: str = "",
        **kwargs: Any,
    ) -> str:
        """Handle LlamaIndex event start callbacks.

        Args:
            event_type: LlamaIndex callback event type.
            payload: Optional event payload.
            event_id: LlamaIndex event identifier.
            **kwargs: Additional callback fields.

        Returns:
            The event identifier to satisfy callback protocol expectations.
        """
        del kwargs
        try:
            event_type_str = str(event_type)
            if "LLM" in event_type_str:
                prompt = self._extract_prompt(payload)
                self._emit_llm_prompt(
                    prompt=prompt,
                    event_type=event_type_str,
                    event_id=event_id,
                )
        except AgentShieldError as exc:
            logger.debug("llamaindex_handler_event_start_error", error=str(exc))
        return event_id

    def on_event_end(
        self,
        event_type: Any,
        payload: dict[str, Any] | None = None,
        event_id: str = "",
        **kwargs: Any,
    ) -> None:
        """Handle LlamaIndex event end callbacks.

        Args:
            event_type: LlamaIndex callback event type.
            payload: Optional event payload.
            event_id: LlamaIndex event identifier.
            **kwargs: Additional callback fields.
        """
        del kwargs
        try:
            event_type_str = str(event_type)
            if "LLM" in event_type_str:
                response = self._extract_response(payload)
                self._emit_llm_response(
                    response=response,
                    event_type=event_type_str,
                    event_id=event_id,
                )
        except AgentShieldError as exc:
            logger.debug("llamaindex_handler_event_end_error", error=str(exc))

    def start_trace(self, trace_id: str | None = None) -> None:
        """Start trace callback required by LlamaIndex protocol.

        Args:
            trace_id: Optional LlamaIndex trace identifier.
        """
        del trace_id

    def end_trace(
        self,
        trace_id: str | None = None,
        trace_map: dict[str, Any] | None = None,
    ) -> None:
        """End trace callback required by LlamaIndex protocol.

        Args:
            trace_id: Optional LlamaIndex trace identifier.
            trace_map: Optional nested trace structure.
        """
        del trace_id, trace_map

    def _extract_prompt(self, payload: dict[str, Any] | None) -> str:
        """Extract prompt-like content from a LlamaIndex payload.

        Args:
            payload: Callback payload dictionary.

        Returns:
            Best-effort prompt string.
        """
        if payload is None:
            return ""
        if "messages" in payload:
            return str(payload["messages"])
        if "query_str" in payload:
            return str(payload["query_str"])
        if "prompt" in payload:
            return str(payload["prompt"])
        return ""

    def _extract_response(self, payload: dict[str, Any] | None) -> str:
        """Extract response-like content from a LlamaIndex payload.

        Args:
            payload: Callback payload dictionary.

        Returns:
            Best-effort response string.
        """
        if payload is None:
            return ""
        if "response" in payload:
            return str(payload["response"])
        if "output" in payload:
            return str(payload["output"])
        if "completion" in payload:
            return str(payload["completion"])
        return ""

    def _emit_llm_prompt(
        self,
        prompt: str,
        event_type: str,
        event_id: str,
    ) -> None:
        """Emit and process an AgentShield LLM prompt event.

        Args:
            prompt: Prompt content extracted from callback payload.
            event_type: Original LlamaIndex event type name.
            event_id: LlamaIndex callback event identifier.

        Raises:
            AgentShieldError: If detection processing raises a policy error.
        """
        event_key = event_id or str(uuid.uuid4())
        self._pending_prompts[event_key] = prompt

        event = LLMEvent(
            session_id=self._session_id,
            agent_id=self._agent_id,
            event_type=EventType.LLM_PROMPT,
            severity=SeverityLevel.INFO,
            prompt=prompt,
            model="llamaindex",
            metadata={
                "callback_event_id": event_key,
                "callback_event_type": event_type,
            },
        )
        self._runtime._emitter.emit(event)
        self._process_detection(event)

    def _emit_llm_response(
        self,
        response: str,
        event_type: str,
        event_id: str,
    ) -> None:
        """Emit and process an AgentShield LLM response event.

        Args:
            response: Response content extracted from callback payload.
            event_type: Original LlamaIndex event type name.
            event_id: LlamaIndex callback event identifier.

        Raises:
            AgentShieldError: If detection processing raises a policy error.
        """
        event_key = event_id or str(uuid.uuid4())
        prompt = self._pending_prompts.pop(event_key, "")

        event = LLMEvent(
            session_id=self._session_id,
            agent_id=self._agent_id,
            event_type=EventType.LLM_RESPONSE,
            severity=SeverityLevel.INFO,
            prompt=prompt,
            response=response,
            model="llamaindex",
            metadata={
                "callback_event_id": event_key,
                "callback_event_type": event_type,
            },
        )
        self._runtime._emitter.emit(event)
        self._process_detection(event)

    def _process_detection(self, event: LLMEvent) -> None:
        """Route emitted LLM events through the detection engine.

        Args:
            event: AgentShield LLM event to process.

        Raises:
            AgentShieldError: If policy processing raises a violation.
        """
        detection_engine = getattr(self._runtime, "detection_engine", None)
        if detection_engine is None:
            return

        process_event = getattr(detection_engine, "process_event", None)
        if callable(process_event):
            process_event(event)


@AdapterRegistry.register
class LlamaIndexAdapter(BaseAdapter):
    """Adapter for LlamaIndex QueryEngine and AgentRunner objects."""

    framework_name = "llamaindex"

    @classmethod
    def supports(cls, agent: Any) -> bool:
        """Check whether an agent exposes the LlamaIndex callback surface.

        Args:
            agent: Candidate agent object.

        Returns:
            True when callback_manager and query/chat methods are present.
        """
        return hasattr(agent, "callback_manager") and (
            hasattr(agent, "query") or hasattr(agent, "chat")
        )

    def wrap(self, agent: Any, context: AdapterContext) -> Any:
        """Wire AgentShield into a LlamaIndex QueryEngine or AgentRunner.

        Injects an AgentShield callback handler into CallbackManager, wires
        optional tool call hooks, and returns the original agent mutated
        in-place.

        Args:
            agent: LlamaIndex agent or query engine instance.
            context: Adapter runtime context.

        Returns:
            Original agent object mutated in-place.
        """
        adapter_session_id = self._build_adapter_session_id(context)

        try:
            self._initialize_detection_context(
                context=context,
                session_id=adapter_session_id,
            )
            handler = _AgentShieldLlamaIndexHandler(
                runtime=context.runtime,
                agent_id=context.agent_id,
                session_id=adapter_session_id,
            )
            self._inject_callback_handler(
                agent=agent,
                handler=handler,
                context=context,
            )
            self._wire_tool_hooks(
                agent=agent,
                context=context,
                session_id=adapter_session_id,
            )
            self._register_dna_session(
                context=context,
                session_id=adapter_session_id,
            )
        except AgentShieldError as exc:
            logger.error(
                "llamaindex_adapter_wiring_failed",
                error=str(exc),
                agent_id=context.agent_id,
            )

        return agent

    @classmethod
    def get_framework_version(cls) -> str | None:
        """Return installed LlamaIndex core package version.

        Returns:
            Installed llama-index-core version when available, otherwise None.
        """
        try:
            return version("llama-index-core")
        except PackageNotFoundError:
            return None

    def _build_adapter_session_id(self, context: AdapterContext) -> uuid.UUID:
        """Build a deterministic adapter session UUID.

        Args:
            context: Adapter runtime context.

        Returns:
            UUID derived from runtime session and agent identifiers.
        """
        seed = f"{context.session_id}:{context.agent_id}:{self.framework_name}"
        return uuid.uuid5(uuid.NAMESPACE_URL, seed)

    def _initialize_detection_context(
        self,
        context: AdapterContext,
        session_id: uuid.UUID,
    ) -> None:
        """Initialize detection context for callback-translated events.

        Args:
            context: Adapter runtime context.
            session_id: Adapter-scoped session UUID.

        Raises:
            AdapterError: If detection session initialization fails.
        """
        try:
            detection_engine = getattr(context.runtime, "detection_engine", None)
            if detection_engine is None:
                return

            initialize_session = getattr(detection_engine, "initialize_session", None)
            if callable(initialize_session):
                initialize_session(
                    session_id=session_id,
                    agent_id=context.agent_id,
                    original_task="",
                )
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            raise AdapterError("Failed to initialize LlamaIndex detection context") from exc

    def _inject_callback_handler(
        self,
        agent: Any,
        handler: _AgentShieldLlamaIndexHandler,
        context: AdapterContext,
    ) -> None:
        """Inject AgentShield callback handler into LlamaIndex callback manager.

        Args:
            agent: LlamaIndex target object.
            handler: AgentShield callback handler instance.
            context: Adapter runtime context.

        Raises:
            AdapterError: If callback handler injection fails.
        """
        try:
            callback_manager = getattr(agent, "callback_manager", None)
            if callback_manager is not None:
                add_handler = getattr(callback_manager, "add_handler", None)
                if callable(add_handler):
                    add_handler(handler)
                else:
                    handlers = getattr(callback_manager, "handlers", None)
                    if isinstance(handlers, list):
                        handlers.append(handler)
                    else:
                        raise AdapterError(
                            "LlamaIndex callback_manager must provide add_handler() or handlers"
                        )

                logger.debug(
                    "llamaindex_callback_injected",
                    agent_id=context.agent_id,
                )
                return

            agent._agentshield_handler = handler
            logger.warning(
                "llamaindex_no_callback_manager",
                agent_id=context.agent_id,
            )
        except AdapterError:
            raise
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            raise AdapterError("Failed to inject LlamaIndex callback handler") from exc

    def _wire_tool_hooks(
        self,
        agent: Any,
        context: AdapterContext,
        session_id: uuid.UUID,
    ) -> None:
        """Wire ToolInterceptor hooks to LlamaIndex tools when present.

        Args:
            agent: LlamaIndex target object.
            context: Adapter runtime context.
            session_id: Adapter-scoped session UUID.

        Raises:
            AdapterError: If tool interception wiring fails.
        """
        try:
            tools_obj = getattr(agent, "tools", None)
            if not isinstance(tools_obj, list):
                return

            tool_interceptor = ToolInterceptor(
                emitter=context.runtime._emitter,
                config=context.runtime._config,
                session_id=session_id,
                agent_id=context.agent_id,
            )

            make_pre_hook = getattr(context.runtime, "_make_pre_call_hook", None)
            if callable(make_pre_hook):
                tool_interceptor.add_pre_call_hook(make_pre_hook(session_id))

            make_post_hook = getattr(context.runtime, "_make_post_call_hook", None)
            if callable(make_post_hook):
                tool_interceptor.add_post_call_hook(make_post_hook(session_id))

            for tool in tools_obj:
                function_attr = self._resolve_tool_function_attr(tool)
                if function_attr is None:
                    continue

                original_fn_obj = getattr(tool, function_attr, None)
                if not callable(original_fn_obj):
                    continue

                tool_name = self._resolve_tool_name(tool)
                wrapped_fn = tool_interceptor.create_hook(
                    tool_name=tool_name,
                    original_fn=original_fn_obj,
                    agent_id=context.agent_id,
                )
                setattr(tool, function_attr, wrapped_fn)

            logger.debug(
                "llamaindex_tools_wired",
                agent_id=context.agent_id,
                tool_count=len(tools_obj),
            )
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            raise AdapterError("Failed to wire LlamaIndex tools") from exc

    def _register_dna_session(
        self,
        context: AdapterContext,
        session_id: uuid.UUID,
    ) -> None:
        """Register adapter session with DNA system when API is available.

        Args:
            context: Adapter runtime context.
            session_id: Adapter-scoped session UUID.

        Raises:
            AdapterError: If DNA registration fails.
        """
        try:
            detection_engine = getattr(context.runtime, "detection_engine", None)
            if detection_engine is None:
                return

            dna_system = getattr(detection_engine, "dna_system", None)
            if dna_system is None:
                dna_system = getattr(detection_engine, "_dna_system", None)
            if dna_system is None:
                return

            register_session = getattr(dna_system, "register_session", None)
            if callable(register_session):
                register_session(
                    agent_id=context.agent_id,
                    session_id=context.session_id,
                )

            logger.debug(
                "llamaindex_dna_registered",
                agent_id=context.agent_id,
                session_id=str(session_id),
            )
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            raise AdapterError("Failed to register LlamaIndex DNA session") from exc

    def _resolve_tool_function_attr(self, tool: Any) -> str | None:
        """Resolve which callable attribute should be wrapped for a tool.

        Args:
            tool: Tool instance from a LlamaIndex agent.

        Returns:
            Name of callable attribute to patch, or None when unsupported.
        """
        if hasattr(tool, "_run"):
            return "_run"
        if hasattr(tool, "call"):
            return "call"
        return None

    def _resolve_tool_name(self, tool: Any) -> str:
        """Resolve a stable tool name for logging and event emission.

        Args:
            tool: Tool instance from a LlamaIndex agent.

        Returns:
            Best-effort tool name string.
        """
        metadata_obj = getattr(tool, "metadata", None)
        if metadata_obj is not None:
            metadata_name = getattr(metadata_obj, "name", None)
            if metadata_name is not None:
                return str(metadata_name)
        return type(tool).__name__
