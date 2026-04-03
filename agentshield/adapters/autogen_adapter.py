"""AutoGen adapter wiring for AgentShield Phase 10C."""

from __future__ import annotations

import uuid
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from loguru import logger

from agentshield.adapters.base import AdapterContext, BaseAdapter
from agentshield.adapters.registry import AdapterRegistry
from agentshield.events.models import EventType, LLMEvent, SeverityLevel
from agentshield.exceptions import AdapterError, AgentShieldError


@AdapterRegistry.register
class AutoGenAdapter(BaseAdapter):
    """Adapter for AutoGen ConversableAgent message-layer interception."""

    framework_name = "autogen"

    @classmethod
    def supports(cls, agent: Any) -> bool:
        """Check whether the target agent looks like an AutoGen ConversableAgent.

        Args:
            agent: Candidate agent object.

        Returns:
            True when send/receive/initiate_chat/name are present.
        """
        return (
            hasattr(agent, "receive")
            and hasattr(agent, "send")
            and hasattr(agent, "initiate_chat")
            and hasattr(agent, "name")
        )

    @classmethod
    def get_framework_version(cls) -> str | None:
        """Return installed pyautogen package version.

        Returns:
            Installed pyautogen version when available, otherwise None.
        """
        try:
            return version("pyautogen")
        except PackageNotFoundError:
            return None

    def wrap(self, agent: Any, context: AdapterContext) -> Any:
        """Wire AgentShield into an AutoGen ConversableAgent.

        Monkey-patches receive() and send() to intercept inter-agent message
        traffic, emits LLM prompt events for prompt-injection detection, and
        registers this agent in the trust graph.

        Args:
            agent: AutoGen agent selected by adapter detection.
            context: Adapter runtime context.

        Returns:
            Original agent object mutated in-place.
        """
        adapter_session_id = self._build_adapter_session_id(context)
        detection_engine = getattr(context.runtime, "detection_engine", None)

        try:
            self._initialize_detection_context(
                detection_engine=detection_engine,
                context=context,
                session_id=adapter_session_id,
            )
            self._patch_receive(
                agent=agent,
                context=context,
                detection_engine=detection_engine,
                session_id=adapter_session_id,
            )
            self._patch_send(
                agent=agent,
                context=context,
                detection_engine=detection_engine,
                session_id=adapter_session_id,
            )

            logger.debug(
                "autogen_message_hooks_attached",
                agent_id=context.agent_id,
                agent_name=getattr(agent, "name", "unknown"),
            )

            self._register_dna_session(
                detection_engine=detection_engine,
                context=context,
            )
            self._register_trust_graph_agent(
                detection_engine=detection_engine,
                context=context,
            )
        except AgentShieldError as exc:
            logger.error(
                "autogen_adapter_wiring_failed",
                error=str(exc),
                agent_id=context.agent_id,
            )

        return agent

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
        detection_engine: Any,
        context: AdapterContext,
        session_id: uuid.UUID,
    ) -> None:
        """Initialize detection context for adapter-generated events.

        Args:
            detection_engine: Runtime detection engine or None.
            context: Adapter runtime context.
            session_id: Adapter-scoped session UUID.

        Raises:
            AdapterError: If detection session initialization fails.
        """
        try:
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
            raise AdapterError("Failed to initialize AutoGen detection context") from exc

    def _patch_receive(
        self,
        agent: Any,
        context: AdapterContext,
        detection_engine: Any,
        session_id: uuid.UUID,
    ) -> None:
        """Patch AutoGen receive() to inspect incoming inter-agent messages.

        Args:
            agent: Target AutoGen agent.
            context: Adapter runtime context.
            detection_engine: Runtime detection engine or None.
            session_id: Adapter-scoped session UUID.

        Raises:
            AdapterError: If receive patching fails.
        """
        try:
            original_receive = getattr(agent, "receive", None)
            if not callable(original_receive):
                raise AdapterError("AutoGen agent receive() is not callable")

            def _patched_receive(
                message: dict[str, Any] | str,
                sender: Any,
                request_reply: bool | None = None,
                silent: bool | None = False,
            ) -> Any:
                try:
                    sender_id = str(getattr(sender, "name", str(sender)))
                    content = self._extract_content(message)

                    self._record_inter_agent_message(
                        detection_engine=detection_engine,
                        sender_id=sender_id,
                        receiver_id=context.agent_id,
                        content=content,
                        session_id=session_id,
                    )
                    self._emit_prompt_event(
                        detection_engine=detection_engine,
                        context=context,
                        prompt=content,
                        session_id=session_id,
                    )
                except AgentShieldError as exc:
                    logger.warning(
                        "autogen_receive_intercept_error",
                        error=str(exc),
                        agent_id=context.agent_id,
                    )

                return original_receive(message, sender, request_reply, silent)

            agent.receive = _patched_receive
        except AgentShieldError:
            raise
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            raise AdapterError("Failed to patch AutoGen receive()") from exc

    def _patch_send(
        self,
        agent: Any,
        context: AdapterContext,
        detection_engine: Any,
        session_id: uuid.UUID,
    ) -> None:
        """Patch AutoGen send() to inspect outgoing inter-agent messages.

        Args:
            agent: Target AutoGen agent.
            context: Adapter runtime context.
            detection_engine: Runtime detection engine or None.
            session_id: Adapter-scoped session UUID.

        Raises:
            AdapterError: If send patching fails.
        """
        try:
            original_send = getattr(agent, "send", None)
            if not callable(original_send):
                raise AdapterError("AutoGen agent send() is not callable")

            def _patched_send(
                message: dict[str, Any] | str,
                recipient: Any,
                request_reply: bool | None = None,
                silent: bool | None = False,
            ) -> Any:
                try:
                    recipient_id = str(getattr(recipient, "name", str(recipient)))
                    content = self._extract_content(message)

                    self._record_inter_agent_message(
                        detection_engine=detection_engine,
                        sender_id=context.agent_id,
                        receiver_id=recipient_id,
                        content=content,
                        session_id=session_id,
                    )
                except AgentShieldError as exc:
                    logger.warning(
                        "autogen_send_intercept_error",
                        error=str(exc),
                        agent_id=context.agent_id,
                    )

                return original_send(message, recipient, request_reply, silent)

            agent.send = _patched_send
        except AgentShieldError:
            raise
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            raise AdapterError("Failed to patch AutoGen send()") from exc

    def _extract_content(self, message: dict[str, Any] | str) -> str:
        """Extract a text payload from AutoGen send/receive message objects.

        Args:
            message: Message payload passed to send/receive.

        Returns:
            Best-effort string content value.
        """
        if isinstance(message, dict):
            return str(message.get("content", str(message)))
        return str(message)

    def _record_inter_agent_message(
        self,
        detection_engine: Any,
        sender_id: str,
        receiver_id: str,
        content: str,
        session_id: uuid.UUID,
    ) -> None:
        """Record an inter-agent message for trust graph monitoring.

        Args:
            detection_engine: Runtime detection engine or None.
            sender_id: Sending agent identifier.
            receiver_id: Receiving agent identifier.
            content: Message content string.
            session_id: Receiver session UUID for threat attribution.

        Raises:
            AdapterError: If inter-agent recording fails.
        """
        try:
            if detection_engine is None:
                return

            record_message = getattr(detection_engine, "record_inter_agent_message", None)
            if callable(record_message):
                record_message(
                    sender_agent_id=sender_id,
                    receiver_agent_id=receiver_id,
                    content=content,
                    receiver_session_id=session_id,
                )
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            raise AdapterError("Failed to record AutoGen inter-agent message") from exc

    def _emit_prompt_event(
        self,
        detection_engine: Any,
        context: AdapterContext,
        prompt: str,
        session_id: uuid.UUID,
    ) -> None:
        """Emit an LLM_PROMPT event so prompt-injection detection can run.

        Args:
            detection_engine: Runtime detection engine or None.
            context: Adapter runtime context.
            prompt: Prompt text extracted from incoming message.
            session_id: Adapter-scoped session UUID.

        Raises:
            AdapterError: If event emission or processing fails.
        """
        try:
            if detection_engine is None:
                return

            event = LLMEvent(
                session_id=session_id,
                agent_id=context.agent_id,
                event_type=EventType.LLM_PROMPT,
                severity=SeverityLevel.INFO,
                prompt=prompt,
                model="autogen",
                metadata={
                    "framework": self.framework_name,
                    "direction": "inbound_message",
                },
            )
            context.runtime._emitter.emit(event)

            process_event = getattr(detection_engine, "process_event", None)
            if callable(process_event):
                process_event(event)
        except AgentShieldError:
            raise
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            raise AdapterError("Failed to emit AutoGen prompt event") from exc

    def _register_dna_session(self, detection_engine: Any, context: AdapterContext) -> None:
        """Register adapter context with DNA system when API is available.

        Args:
            detection_engine: Runtime detection engine or None.
            context: Adapter runtime context.

        Raises:
            AdapterError: If DNA registration fails.
        """
        try:
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
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            raise AdapterError("Failed to register AutoGen DNA session") from exc

    def _register_trust_graph_agent(
        self,
        detection_engine: Any,
        context: AdapterContext,
    ) -> None:
        """Register the wrapped agent in the inter-agent trust graph.

        Args:
            detection_engine: Runtime detection engine or None.
            context: Adapter runtime context.

        Raises:
            AdapterError: If trust graph registration fails.
        """
        try:
            if detection_engine is None:
                return

            trust_graph = None
            get_trust_graph = getattr(detection_engine, "get_trust_graph", None)
            if callable(get_trust_graph):
                trust_graph = get_trust_graph()
            if trust_graph is None:
                trust_graph = getattr(detection_engine, "_trust_graph", None)
            if trust_graph is None:
                return

            register_agent = getattr(trust_graph, "register_agent", None)
            if callable(register_agent):
                register_agent(context.agent_id)
                logger.debug(
                    "autogen_trust_graph_registered",
                    agent_id=context.agent_id,
                )
        except AgentShieldError:
            raise
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            raise AdapterError("Failed to register AutoGen trust graph agent") from exc
