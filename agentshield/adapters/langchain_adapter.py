"""LangChain adapter wiring for AgentShield Phase 10B."""

from __future__ import annotations

import uuid
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from loguru import logger

from agentshield.adapters.base import AdapterContext, BaseAdapter
from agentshield.adapters.registry import AdapterRegistry
from agentshield.exceptions import AdapterError, AgentShieldError
from agentshield.interceptors.llm_interceptor import LLMInterceptor
from agentshield.interceptors.memory_interceptor import MemoryInterceptor
from agentshield.interceptors.tool_interceptor import ToolInterceptor


@AdapterRegistry.register
class LangChainAdapter(BaseAdapter):
    """Adapter for LangChain-compatible agent objects."""

    framework_name = "langchain"

    @classmethod
    def supports(cls, agent: Any) -> bool:
        """Check whether the target agent looks like a LangChain agent.

        Args:
            agent: Agent object to inspect.

        Returns:
            True when the object exposes the required LangChain-like surface.
        """
        return (
            hasattr(agent, "run")
            and (hasattr(agent, "callbacks") or hasattr(agent, "callback_manager"))
            and hasattr(agent, "agent")
        )

    def wrap(self, agent: Any, context: AdapterContext) -> Any:
        """Wire all AgentShield interceptors into a LangChain AgentExecutor.

        Attaches LLMInterceptor as a LangChain callback, wires ToolInterceptor
        pre/post hooks onto each tool, and patches agent.memory with
        MemoryInterceptor if memory is present. Returns the original agent
        mutated in-place.

        Args:
            agent: Agent object selected by adapter detection.
            context: Adapter runtime context.

        Returns:
            Original agent object mutated in-place.
        """
        adapter_session_id = self._build_adapter_session_id(context)

        try:
            self._attach_llm_interceptor(
                agent=agent,
                context=context,
                session_id=adapter_session_id,
            )
            self._wire_tool_interceptor(
                agent=agent,
                context=context,
                session_id=adapter_session_id,
            )
            self._patch_memory_interceptor(
                agent=agent,
                context=context,
                session_id=adapter_session_id,
            )
            self._register_detection_session(
                context=context,
                session_id=adapter_session_id,
            )
            self._record_initial_provenance_context(
                context=context,
                session_id=adapter_session_id,
            )
        except AgentShieldError as exc:
            logger.warning(
                "langchain_adapter_wrap_failed",
                agent_id=context.agent_id,
                framework=self.framework_name,
                error=str(exc),
            )

        return agent

    def _build_adapter_session_id(self, context: AdapterContext) -> uuid.UUID:
        """Build a deterministic UUID for adapter-level interception.

        Args:
            context: Adapter runtime context.

        Returns:
            Deterministic UUID derived from adapter context values.
        """
        seed = f"{context.session_id}:{context.agent_id}:{self.framework_name}"
        return uuid.uuid5(uuid.NAMESPACE_URL, seed)

    def _attach_llm_interceptor(
        self,
        agent: Any,
        context: AdapterContext,
        session_id: uuid.UUID,
    ) -> None:
        """Attach LLM interceptor to callbacks or callback manager.

        Args:
            agent: Target LangChain agent object.
            context: Adapter runtime context.
            session_id: Adapter interception session UUID.

        Raises:
            AdapterError: If callback attachment is unsupported.
        """
        try:
            llm_interceptor = LLMInterceptor(
                emitter=context.runtime._emitter,
                config=context.runtime._config,
                session_id=session_id,
                agent_id=context.agent_id,
            )

            make_hook = getattr(context.runtime, "_make_llm_event_hook", None)
            wire_hook = getattr(context.runtime, "_wire_llm_event_hook", None)
            if callable(make_hook) and callable(wire_hook):
                llm_event_hook = make_hook(session_id)
                wire_hook(llm_interceptor, llm_event_hook)

            callbacks_obj = getattr(agent, "callbacks", None)
            if isinstance(callbacks_obj, list):
                agent.callbacks = [*callbacks_obj, llm_interceptor]
            elif hasattr(agent, "callback_manager"):
                callback_manager = getattr(agent, "callback_manager", None)
                add_handler = getattr(callback_manager, "add_handler", None)
                if callable(add_handler):
                    add_handler(llm_interceptor)
                else:
                    raise AdapterError("LangChain callback_manager is missing add_handler()")
            else:
                raise AdapterError("LangChain agent must expose callbacks or callback_manager")
        except AdapterError:
            raise
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            raise AdapterError("Failed to attach LangChain LLM interceptor") from exc

        logger.debug(
            "llm_interceptor_attached",
            agent_id=context.agent_id,
            framework=self.framework_name,
        )

    def _wire_tool_interceptor(
        self,
        agent: Any,
        context: AdapterContext,
        session_id: uuid.UUID,
    ) -> None:
        """Wire ToolInterceptor hooks onto each available tool.

        Args:
            agent: Target LangChain agent object.
            context: Adapter runtime context.
            session_id: Adapter interception session UUID.
        """
        try:
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

            tools_obj = getattr(agent, "tools", None)
            if not isinstance(tools_obj, list):
                return

            for tool in tools_obj:
                original_run = getattr(tool, "_run", None)
                if not callable(original_run):
                    continue

                tool_name = str(getattr(tool, "name", type(tool).__name__))
                hooked = tool_interceptor.create_hook(
                    tool_name=tool_name,
                    original_fn=original_run,
                    agent_id=context.agent_id,
                )
                tool._run = hooked
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            raise AdapterError("Failed to wire LangChain tools") from exc

        logger.debug(
            "tool_interceptor_wired",
            agent_id=context.agent_id,
            tool_count=len(tools_obj),
        )

    def _patch_memory_interceptor(
        self,
        agent: Any,
        context: AdapterContext,
        session_id: uuid.UUID,
    ) -> None:
        """Patch memory object with memory interceptor if memory exists.

        Args:
            agent: Target LangChain agent object.
            context: Adapter runtime context.
            session_id: Adapter interception session UUID.
        """
        try:
            memory_obj = getattr(agent, "memory", None)
            if memory_obj is None:
                return

            memory_interceptor = MemoryInterceptor(
                emitter=context.runtime._emitter,
                config=context.runtime._config,
                session_id=session_id,
                agent_id=context.agent_id,
            )

            make_hook = getattr(context.runtime, "_make_memory_event_hook", None)
            wire_hook = getattr(context.runtime, "_wire_memory_event_hook", None)
            if callable(make_hook) and callable(wire_hook):
                memory_event_hook = make_hook(session_id)
                wire_hook(memory_interceptor, memory_event_hook)

            memory_interceptor.attach(memory_obj)
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            raise AdapterError("Failed to patch LangChain memory") from exc

        logger.debug(
            "memory_interceptor_patched",
            agent_id=context.agent_id,
            memory_type=type(memory_obj).__name__,
        )

    def _register_detection_session(
        self,
        context: AdapterContext,
        session_id: uuid.UUID,
    ) -> None:
        """Register adapter session with detection and DNA systems.

        Args:
            context: Adapter runtime context.
            session_id: Adapter interception session UUID.
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

            dna_system = getattr(detection_engine, "dna_system", None)
            if dna_system is None:
                dna_system = getattr(detection_engine, "_dna_system", None)

            register_session = getattr(dna_system, "register_session", None)
            if callable(register_session):
                register_session(
                    agent_id=context.agent_id,
                    session_id=context.session_id,
                )
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            raise AdapterError("Failed to register LangChain detection session") from exc

        logger.debug(
            "dna_session_registered",
            agent_id=context.agent_id,
            framework=self.framework_name,
            session_id=str(session_id),
        )

    def _record_initial_provenance_context(
        self,
        context: AdapterContext,
        session_id: uuid.UUID,
    ) -> None:
        """Record initial provenance context for adapter session.

        Args:
            context: Adapter runtime context.
            session_id: Adapter interception session UUID.
        """
        try:
            detection_engine = getattr(context.runtime, "detection_engine", None)
            if detection_engine is None:
                return

            provenance_tracker = getattr(detection_engine, "provenance_tracker", None)
            if provenance_tracker is None:
                provenance_tracker = getattr(
                    detection_engine,
                    "_provenance_tracker",
                    None,
                )
            if provenance_tracker is None:
                return

            get_context = getattr(provenance_tracker, "get_context", None)
            context_obj = get_context(session_id) if callable(get_context) else None

            if context_obj is None:
                initialize_session = getattr(provenance_tracker, "initialize_session", None)
                if callable(initialize_session):
                    initialize_session(session_id=session_id)
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            raise AdapterError("Failed to record provenance context") from exc

        logger.debug(
            "provenance_context_recorded",
            agent_id=context.agent_id,
            session_id=str(session_id),
        )

    @classmethod
    def get_framework_version(cls) -> str | None:
        """Return installed LangChain version when available.

        Returns:
            Installed ``langchain`` package version or None if missing.
        """
        try:
            return version("langchain")
        except PackageNotFoundError:
            return None
