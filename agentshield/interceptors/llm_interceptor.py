from __future__ import annotations

import uuid
from typing import Any

from langchain_core.callbacks.base import BaseCallbackHandler
from langchain_core.outputs import LLMResult
from loguru import logger

from agentshield.config import AgentShieldConfig
from agentshield.events.emitter import EventEmitter
from agentshield.events.models import BaseEvent, EventType, LLMEvent, SeverityLevel
from agentshield.exceptions import InterceptorError, PolicyViolationError
from agentshield.interceptors.base import BaseInterceptor


class LLMInterceptor(BaseCallbackHandler, BaseInterceptor):
    """Intercept LangChain LLM calls and chain lifecycle events.

    This class registers as a LangChain callback handler and emits AgentShield
    events for LLM prompt/response and chain lifecycle callbacks.

    Attributes:
        _pending_prompts: Maps run_id to prompt text for correlating prompt and
            response events.
        _target: Agent or chain object this interceptor is attached to.
    """

    _pending_prompts: dict[str, str]
    _target: Any | None

    def __init__(
        self,
        emitter: EventEmitter,
        config: AgentShieldConfig,
        session_id: uuid.UUID,
        agent_id: str,
    ) -> None:
        """Initialize the LLMInterceptor.

        Args:
            emitter: EventEmitter for publishing security events.
            config: AgentShieldConfig with detection settings.
            session_id: UUID of the current session.
            agent_id: Human-readable identifier for this agent.
        """
        BaseCallbackHandler.__init__(self)
        BaseInterceptor.__init__(self, emitter, config, session_id, agent_id)
        self._pending_prompts = {}
        self._target = None

        logger.debug("LLMInterceptor initialized | session={}", session_id)

    def attach(self, target: Any) -> None:
        """Register this interceptor in the target callback list.

        Args:
            target: LangChain agent executor or chain object.

        Raises:
            InterceptorError: If the target cannot accept callback handlers.
        """
        try:
            if not hasattr(target, "callbacks"):
                raise InterceptorError(
                    f"Target {type(target).__name__} has no callbacks attribute"
                )

            callbacks_obj = target.callbacks
            if callbacks_obj is None:
                target.callbacks = [self]
            elif isinstance(callbacks_obj, list):
                if self not in callbacks_obj:
                    callbacks_obj.append(self)
            else:
                raise InterceptorError(
                    f"Target {type(target).__name__} callbacks is not a list"
                )

            self._target = target
            self._attached = True

            logger.info(
                "LLMInterceptor attached | agent={} session={}",
                self._agent_id,
                self._session_id,
            )
        except InterceptorError:
            raise
        except (AttributeError, TypeError, ValueError) as exc:
            raise InterceptorError(f"Failed to attach LLMInterceptor: {exc}") from exc

    def detach(self) -> None:
        """Remove this interceptor from the target callback list.

        Raises:
            InterceptorError: If detachment fails unexpectedly.
        """
        try:
            if self._target is not None and hasattr(self._target, "callbacks"):
                callbacks_obj = self._target.callbacks
                if isinstance(callbacks_obj, list) and self in callbacks_obj:
                    callbacks_obj.remove(self)
                    if len(callbacks_obj) == 0:
                        self._target.callbacks = None

            self._attached = False
            self._target = None
            self._pending_prompts.clear()

            logger.info(
                "LLMInterceptor detached | agent={} session={}",
                self._agent_id,
                self._session_id,
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise InterceptorError(f"Failed to detach LLMInterceptor: {exc}") from exc

    @property
    def is_attached(self) -> bool:
        """Whether this interceptor is currently attached.

        Returns:
            True if attach() has been called successfully and detach() has not
            been called since.
        """
        return self._attached

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Handle LangChain callback fired when an LLM call starts.

        Args:
            serialized: Serialized LLM config dictionary.
            prompts: Prompt strings sent to the LLM.
            run_id: LangChain run identifier for this call.
            parent_run_id: Parent run UUID if nested.
            **kwargs: Additional callback parameters from LangChain.
        """
        del parent_run_id, kwargs
        try:
            prompt_text = "\n".join(prompts)
            model_name = str(serialized.get("name", "unknown"))

            self._pending_prompts[str(run_id)] = prompt_text

            event = LLMEvent(
                **self._make_base_kwargs(
                    event_type=EventType.LLM_PROMPT,
                    severity=SeverityLevel.INFO,
                ),
                prompt=prompt_text,
                model=model_name,
            )
            self._emit(event)

            logger.debug(
                "LLM prompt intercepted | model={} prompt_len={} session={}",
                model_name,
                len(prompt_text),
                self._session_id,
            )
        except Exception as exc:  # pragma: no cover - callback safety
            self._handle_callback_exception(
                callback_name="on_llm_start",
                run_id=run_id,
                error=exc,
            )

    def on_llm_end(
        self,
        response: LLMResult,
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Handle LangChain callback fired when an LLM call completes.

        Args:
            response: LLM result containing generations and usage metadata.
            run_id: LangChain run identifier for this call.
            parent_run_id: Parent run UUID if nested.
            **kwargs: Additional callback parameters from LangChain.
        """
        del parent_run_id, kwargs
        try:
            prompt_text = self._pending_prompts.pop(str(run_id), "")

            response_text = ""
            if response.generations and response.generations[0]:
                response_text = response.generations[0][0].text

            token_count: int | None = None
            prompt_tokens: int | None = None
            completion_tokens: int | None = None
            model_name = "unknown"

            if response.llm_output:
                usage_obj = response.llm_output.get("token_usage")
                if isinstance(usage_obj, dict):
                    token_count_obj = usage_obj.get("total_tokens")
                    prompt_tokens_obj = usage_obj.get("prompt_tokens")
                    completion_tokens_obj = usage_obj.get("completion_tokens")
                    if isinstance(token_count_obj, int):
                        token_count = token_count_obj
                    if isinstance(prompt_tokens_obj, int):
                        prompt_tokens = prompt_tokens_obj
                    if isinstance(completion_tokens_obj, int):
                        completion_tokens = completion_tokens_obj

                model_name_obj = response.llm_output.get("model_name", "unknown")
                model_name = str(model_name_obj)

            event = LLMEvent(
                **self._make_base_kwargs(
                    event_type=EventType.LLM_RESPONSE,
                    severity=SeverityLevel.INFO,
                ),
                prompt=prompt_text,
                response=response_text,
                model=model_name,
                token_count=token_count,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
            )
            self._emit(event)

            logger.debug(
                "LLM response intercepted | response_len={} tokens={} session={}",
                len(response_text),
                token_count,
                self._session_id,
            )
        except Exception as exc:  # pragma: no cover - callback safety
            self._handle_callback_exception(
                callback_name="on_llm_end",
                run_id=run_id,
                error=exc,
            )

    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Handle LangChain callback fired when an LLM call errors.

        Args:
            error: Exception raised by the LLM call.
            run_id: LangChain run identifier for this call.
            parent_run_id: Parent run UUID if nested.
            **kwargs: Additional callback parameters from LangChain.
        """
        del parent_run_id, kwargs
        try:
            self._pending_prompts.pop(str(run_id), None)

            event = BaseEvent(
                **self._make_base_kwargs(
                    event_type=EventType.LLM_PROMPT,
                    severity=SeverityLevel.HIGH,
                    metadata={
                        "error": str(error),
                        "error_type": type(error).__name__,
                        "run_id": str(run_id),
                    },
                )
            )
            self._emit(event)

            logger.warning(
                "LLM error intercepted | error={} session={}",
                error,
                self._session_id,
            )
        except Exception as exc:  # pragma: no cover - callback safety
            self._handle_callback_exception(
                callback_name="on_llm_error",
                run_id=run_id,
                error=exc,
            )

    def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Handle LangChain callback fired when a chain run starts.

        Args:
            serialized: Serialized chain config dictionary.
            inputs: Input payload for the chain invocation.
            run_id: LangChain run identifier for this chain run.
            parent_run_id: Parent run UUID if nested.
            **kwargs: Additional callback parameters from LangChain.
        """
        del inputs, parent_run_id, kwargs
        try:
            chain_name = str(serialized.get("name", "unknown"))

            event = BaseEvent(
                **self._make_base_kwargs(
                    event_type=EventType.CHAIN_START,
                    severity=SeverityLevel.INFO,
                    metadata={
                        "chain_name": chain_name,
                        "run_id": str(run_id),
                    },
                )
            )
            self._emit(event)

            logger.debug(
                "Chain start intercepted | chain={} session={}",
                chain_name,
                self._session_id,
            )
        except Exception as exc:  # pragma: no cover - callback safety
            self._handle_callback_exception(
                callback_name="on_chain_start",
                run_id=run_id,
                error=exc,
            )

    def on_chain_end(
        self,
        outputs: dict[str, Any],
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Handle LangChain callback fired when a chain run completes.

        Args:
            outputs: Output payload from the chain invocation.
            run_id: LangChain run identifier for this chain run.
            parent_run_id: Parent run UUID if nested.
            **kwargs: Additional callback parameters from LangChain.
        """
        del outputs, parent_run_id, kwargs
        try:
            event = BaseEvent(
                **self._make_base_kwargs(
                    event_type=EventType.CHAIN_END,
                    severity=SeverityLevel.INFO,
                    metadata={"run_id": str(run_id)},
                )
            )
            self._emit(event)

            logger.debug("Chain end intercepted | session={}", self._session_id)
        except Exception as exc:  # pragma: no cover - callback safety
            self._handle_callback_exception(
                callback_name="on_chain_end",
                run_id=run_id,
                error=exc,
            )

    def on_chain_error(
        self,
        error: BaseException,
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Handle LangChain callback fired when a chain run errors.

        Args:
            error: Exception raised by the chain.
            run_id: LangChain run identifier for this chain run.
            parent_run_id: Parent run UUID if nested.
            **kwargs: Additional callback parameters from LangChain.
        """
        del parent_run_id, kwargs
        try:
            event = BaseEvent(
                **self._make_base_kwargs(
                    event_type=EventType.CHAIN_END,
                    severity=SeverityLevel.HIGH,
                    metadata={
                        "error": str(error),
                        "error_type": type(error).__name__,
                        "run_id": str(run_id),
                    },
                )
            )
            self._emit(event)

            logger.warning(
                "Chain error intercepted | error={} session={}",
                error,
                self._session_id,
            )
        except Exception as exc:  # pragma: no cover - callback safety
            self._handle_callback_exception(
                callback_name="on_chain_error",
                run_id=run_id,
                error=exc,
            )

    def _handle_callback_exception(
        self,
        callback_name: str,
        run_id: uuid.UUID,
        error: Exception,
    ) -> None:
        """Handle callback exceptions while preserving policy enforcement.

        Args:
            callback_name: Callback method name for logging context.
            run_id: LangChain run identifier.
            error: Exception raised during callback processing.

        Raises:
            PolicyViolationError: Re-raised to preserve BLOCK semantics.
        """
        if isinstance(error, PolicyViolationError):
            raise error

        logger.error(
            "LLMInterceptor.{} error | run_id={} error={}",
            callback_name,
            run_id,
            error,
        )
