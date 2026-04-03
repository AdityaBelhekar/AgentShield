"""Raw OpenAI/Anthropic API adapter wiring for AgentShield Phase 10D."""

from __future__ import annotations

import uuid
from importlib.metadata import PackageNotFoundError, version
from typing import Any, ClassVar

from loguru import logger

from agentshield.adapters.base import AdapterContext, BaseAdapter
from agentshield.adapters.registry import AdapterRegistry
from agentshield.events.models import EventType, LLMEvent, SeverityLevel
from agentshield.exceptions import AdapterError, AgentShieldError


@AdapterRegistry.register
class RawAPIAdapter(BaseAdapter):
    """Adapter for raw OpenAI and Anthropic SDK client interception."""

    framework_name: ClassVar[str] = "raw_api"

    @classmethod
    def supports(cls, agent: Any) -> bool:
        """Check whether the target object matches a raw API client surface.

        Args:
            agent: Candidate client object.

        Returns:
            True when the object exposes OpenAI or Anthropic completion methods.
        """
        has_openai_shape = hasattr(agent, "chat") and hasattr(
            getattr(agent, "chat", None),
            "completions",
        )
        has_anthropic_shape = (
            hasattr(agent, "messages")
            and hasattr(getattr(agent, "messages", None), "create")
            and not hasattr(agent, "chat")
        )
        return has_openai_shape or has_anthropic_shape

    @classmethod
    def get_framework_version(cls) -> str | None:
        """Return installed raw-provider SDK version metadata.

        Returns:
            First available version string in the format "package==version",
            otherwise None.
        """
        for package_name in ("openai", "anthropic"):
            try:
                detected_version = version(package_name)
                return f"{package_name}=={detected_version}"
            except PackageNotFoundError:
                continue
        return None

    @classmethod
    def _detect_provider(cls, agent: Any) -> str:
        """Return the detected raw API provider based on duck typing.

        Args:
            agent: Candidate client object.

        Returns:
            Provider name: "openai", "anthropic", or "unknown".
        """
        if hasattr(agent, "chat") and hasattr(getattr(agent, "chat", None), "completions"):
            return "openai"
        if hasattr(agent, "messages") and hasattr(
            getattr(agent, "messages", None),
            "create",
        ):
            return "anthropic"
        return "unknown"

    def wrap(self, agent: Any, context: AdapterContext) -> Any:
        """Wire AgentShield into a raw OpenAI or Anthropic API client.

        Monkey-patches provider completion methods directly on the supplied
        client instance and returns the same object mutated in-place.

        Args:
            agent: Raw provider client object selected by adapter detection.
            context: Adapter runtime context.

        Returns:
            Original client object mutated in-place.
        """
        adapter_session_id = self._build_adapter_session_id(context)
        detection_engine = getattr(context.runtime, "detection_engine", None)

        try:
            self._initialize_detection_context(
                detection_engine=detection_engine,
                context=context,
                session_id=adapter_session_id,
            )

            provider = self._detect_provider(agent)
            logger.debug(
                "raw_api_adapter_detected_provider",
                provider=provider,
                agent_id=context.agent_id,
            )

            if provider == "openai":
                self._patch_openai(
                    agent=agent,
                    context=context,
                    detection_engine=detection_engine,
                    session_id=adapter_session_id,
                )
            elif provider == "anthropic":
                self._patch_anthropic(
                    agent=agent,
                    context=context,
                    detection_engine=detection_engine,
                    session_id=adapter_session_id,
                )
            else:
                logger.warning(
                    "raw_api_unknown_provider",
                    agent_id=context.agent_id,
                )

            self._register_dna_session(
                detection_engine=detection_engine,
                context=context,
            )
        except AgentShieldError as exc:
            logger.error(
                "raw_api_adapter_wiring_failed",
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
        """Initialize a detection context for adapter-emitted LLM events.

        Args:
            detection_engine: Runtime detection engine or None.
            context: Adapter runtime context.
            session_id: Adapter-scoped session UUID.

        Raises:
            AdapterError: If detection context initialization fails.
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
            raise AdapterError("Failed to initialize raw API detection context") from exc

    def _patch_openai(
        self,
        agent: Any,
        context: AdapterContext,
        detection_engine: Any,
        session_id: uuid.UUID,
    ) -> None:
        """Patch OpenAI chat completion create() with AgentShield interception.

        Args:
            agent: OpenAI-like client object.
            context: Adapter runtime context.
            detection_engine: Runtime detection engine or None.
            session_id: Adapter-scoped session UUID.
        """
        try:
            chat_obj = getattr(agent, "chat", None)
            completions_obj = getattr(chat_obj, "completions", None)
            if completions_obj is None:
                logger.warning(
                    "openai_completions_missing",
                    agent_id=context.agent_id,
                )
                return

            original_create = getattr(completions_obj, "create", None)

            if not callable(original_create):
                logger.warning(
                    "openai_create_not_callable",
                    agent_id=context.agent_id,
                )
                return

            def _hooked_create(*args: Any, **kwargs: Any) -> Any:
                prompt = self._extract_prompt_from_messages(kwargs.get("messages", []))

                try:
                    self._emit_prompt_event(
                        detection_engine=detection_engine,
                        context=context,
                        prompt=prompt,
                        provider="openai",
                        session_id=session_id,
                    )
                except AgentShieldError as exc:
                    logger.debug("openai_pre_hook_error", error=str(exc))

                result = original_create(*args, **kwargs)

                response_text = self._extract_openai_response_text(result)
                try:
                    self._emit_response_event(
                        detection_engine=detection_engine,
                        context=context,
                        prompt=prompt,
                        response=response_text,
                        provider="openai",
                        session_id=session_id,
                    )
                except AgentShieldError as exc:
                    logger.debug("openai_post_hook_error", error=str(exc))

                return result

            completions_target: Any = completions_obj
            completions_target.create = _hooked_create
            logger.debug("openai_create_patched", agent_id=context.agent_id)
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            logger.warning(
                "openai_patch_failed",
                agent_id=context.agent_id,
                error=str(exc),
            )

    def _patch_anthropic(
        self,
        agent: Any,
        context: AdapterContext,
        detection_engine: Any,
        session_id: uuid.UUID,
    ) -> None:
        """Patch Anthropic messages create() with AgentShield interception.

        Args:
            agent: Anthropic-like client object.
            context: Adapter runtime context.
            detection_engine: Runtime detection engine or None.
            session_id: Adapter-scoped session UUID.
        """
        try:
            messages_obj = getattr(agent, "messages", None)
            if messages_obj is None:
                logger.warning(
                    "anthropic_messages_missing",
                    agent_id=context.agent_id,
                )
                return

            original_create = getattr(messages_obj, "create", None)

            if not callable(original_create):
                logger.warning(
                    "anthropic_create_not_callable",
                    agent_id=context.agent_id,
                )
                return

            def _hooked_create(*args: Any, **kwargs: Any) -> Any:
                prompt = self._extract_prompt_from_messages(kwargs.get("messages", []))

                try:
                    self._emit_prompt_event(
                        detection_engine=detection_engine,
                        context=context,
                        prompt=prompt,
                        provider="anthropic",
                        session_id=session_id,
                    )
                except AgentShieldError as exc:
                    logger.debug("anthropic_pre_hook_error", error=str(exc))

                result = original_create(*args, **kwargs)

                response_text = self._extract_anthropic_response_text(result)
                try:
                    self._emit_response_event(
                        detection_engine=detection_engine,
                        context=context,
                        prompt=prompt,
                        response=response_text,
                        provider="anthropic",
                        session_id=session_id,
                    )
                except AgentShieldError as exc:
                    logger.debug("anthropic_post_hook_error", error=str(exc))

                return result

            messages_target: Any = messages_obj
            messages_target.create = _hooked_create
            logger.debug("anthropic_create_patched", agent_id=context.agent_id)
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            logger.warning(
                "anthropic_patch_failed",
                agent_id=context.agent_id,
                error=str(exc),
            )

    def _emit_prompt_event(
        self,
        detection_engine: Any,
        context: AdapterContext,
        prompt: str,
        provider: str,
        session_id: uuid.UUID,
    ) -> None:
        """Emit and process an LLM_PROMPT event.

        Args:
            detection_engine: Runtime detection engine or None.
            context: Adapter runtime context.
            prompt: Extracted user prompt text.
            provider: Raw API provider name.
            session_id: Adapter-scoped session UUID.

        Raises:
            AdapterError: If event emission or detection processing fails.
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
                model=provider,
                metadata={
                    "framework": self.framework_name,
                    "provider": provider,
                },
            )
            context.runtime._emitter.emit(event)

            process_event = getattr(detection_engine, "process_event", None)
            if callable(process_event):
                process_event(event)
        except AgentShieldError:
            raise
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            raise AdapterError("Failed to emit raw API prompt event") from exc

    def _emit_response_event(
        self,
        detection_engine: Any,
        context: AdapterContext,
        prompt: str,
        response: str,
        provider: str,
        session_id: uuid.UUID,
    ) -> None:
        """Emit and process an LLM_RESPONSE event.

        Args:
            detection_engine: Runtime detection engine or None.
            context: Adapter runtime context.
            prompt: Prompt text associated with the response.
            response: Extracted response text.
            provider: Raw API provider name.
            session_id: Adapter-scoped session UUID.

        Raises:
            AdapterError: If event emission or detection processing fails.
        """
        try:
            if detection_engine is None:
                return

            event = LLMEvent(
                session_id=session_id,
                agent_id=context.agent_id,
                event_type=EventType.LLM_RESPONSE,
                severity=SeverityLevel.INFO,
                prompt=prompt,
                response=response,
                model=provider,
                metadata={
                    "framework": self.framework_name,
                    "provider": provider,
                },
            )
            context.runtime._emitter.emit(event)

            process_event = getattr(detection_engine, "process_event", None)
            if callable(process_event):
                process_event(event)
        except AgentShieldError:
            raise
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            raise AdapterError("Failed to emit raw API response event") from exc

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
            raise AdapterError("Failed to register raw API DNA session") from exc

    def _extract_prompt_from_messages(self, messages: Any) -> str:
        """Extract prompt text from provider message payloads.

        Args:
            messages: Provider messages payload.

        Returns:
            Joined prompt string.
        """
        if not isinstance(messages, list):
            return ""

        parts: list[str] = []
        for message in messages:
            if not isinstance(message, dict):
                continue
            parts.append(self._coerce_to_text(message.get("content", "")))
        return " ".join(part for part in parts if part)

    def _extract_openai_response_text(self, result: Any) -> str:
        """Extract response text from an OpenAI chat completion result.

        Args:
            result: OpenAI result object.

        Returns:
            Best-effort response text.
        """
        choices = getattr(result, "choices", None)
        if not isinstance(choices, list) or not choices:
            return ""

        first_choice = choices[0]
        message_obj: Any
        if isinstance(first_choice, dict):
            message_obj = first_choice.get("message")
        else:
            message_obj = getattr(first_choice, "message", None)

        if isinstance(message_obj, dict):
            return self._coerce_to_text(message_obj.get("content", ""))
        return self._coerce_to_text(getattr(message_obj, "content", ""))

    def _extract_anthropic_response_text(self, result: Any) -> str:
        """Extract response text from an Anthropic messages result.

        Args:
            result: Anthropic result object.

        Returns:
            Best-effort response text.
        """
        content_blocks = getattr(result, "content", None)
        if not isinstance(content_blocks, list) or not content_blocks:
            return ""

        first_block = content_blocks[0]
        if isinstance(first_block, dict):
            return self._coerce_to_text(first_block.get("text", ""))
        return self._coerce_to_text(getattr(first_block, "text", ""))

    def _coerce_to_text(self, value: Any) -> str:
        """Convert provider message content structures to plain text.

        Args:
            value: Provider content field value.

        Returns:
            String representation suitable for detector input.
        """
        if isinstance(value, str):
            return value

        if isinstance(value, list):
            parts: list[str] = []
            for item in value:
                if isinstance(item, dict):
                    parts.append(str(item.get("text", "")))
                else:
                    parts.append(str(item))
            return " ".join(part for part in parts if part)

        if isinstance(value, dict):
            if "text" in value:
                return str(value.get("text", ""))
            return str(value.get("content", ""))

        return str(value)
