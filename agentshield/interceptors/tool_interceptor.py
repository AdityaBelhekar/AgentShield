from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from langchain_core.tools import BaseTool
from loguru import logger

from agentshield.config import AgentShieldConfig
from agentshield.events.emitter import EventEmitter
from agentshield.events.models import (
    EventType,
    SeverityLevel,
    ToolCallEvent,
    TrustLevel,
)
from agentshield.exceptions import (
    InterceptorError,
    PolicyViolationError,
    ToolCallBlockedError,
)
from agentshield.interceptors.base import BaseInterceptor


@dataclass
class PatchedTool:
    """Stores the original methods of a patched tool.

    Used by detach() to restore the tool to its exact
    pre-patch state. One PatchedTool instance is stored
    per patched tool in ToolInterceptor._patched_tools.

    Attributes:
        tool: The LangChain BaseTool instance that was patched.
        original_run: The original _run method before patching.
        original_arun: The original _arun method before patching.
    """

    tool: BaseTool
    original_run: Callable[..., Any]
    original_arun: Callable[..., Any]


@dataclass
class HookResult:
    """Result returned by a pre-call hook function.

    Pre-call hooks return a HookResult to signal whether
    the tool call should be blocked. If block=True, the
    tool call is cancelled and ToolCallBlockedError is raised.

    Attributes:
        block: If True, the tool call will be blocked.
        reason: Human-readable reason for blocking.
            Required when block=True.
        confidence: Detection confidence score 0.0 to 1.0.
            Used for logging and forensic evidence.
    """

    block: bool = False
    reason: str = field(default="")
    confidence: float = field(default=0.0)


class ToolInterceptor(BaseInterceptor):
    """Intercepts LangChain tool invocations via monkey-patching.

    Wraps each tool's _run and _arun methods with interceptor
    wrappers that emit events and run detection hooks before
    and after every tool execution.

    Unlike LLMInterceptor which uses callbacks (post-execution),
    ToolInterceptor patches at the method level so it can
    block tool calls before they execute.

    Hook System:
        Pre-call hooks run BEFORE tool execution.
        If any pre-call hook returns HookResult(block=True),
        the tool call is blocked and ToolCallBlockedError
        is raised. The detection engine registers its
        analysis functions as pre-call hooks in Phase 3.

        Post-call hooks run AFTER tool execution.
        They receive the tool output and cannot block.
        Used for analysis that requires the output.

    Execution flow per tool call:
        1. Emit TOOL_CALL_START
        2. Run all pre_call_hooks
        3. If any hook blocks -> emit TOOL_CALL_BLOCKED and raise ToolCallBlockedError
        4. Execute original tool._run()
        5. Measure execution_time_ms
        6. Emit TOOL_CALL_COMPLETE with output + time
        7. Run all post_call_hooks

    Attributes:
        _patched_tools: Maps tool name to PatchedTool record.
        _pre_call_hooks: List of hook callables run before exec.
        _post_call_hooks: List of hook callables run after exec.
    """

    _patched_tools: dict[str, PatchedTool]
    _pre_call_hooks: list[Callable[[ToolCallEvent], HookResult]]
    _post_call_hooks: list[Callable[[ToolCallEvent], None]]

    def __init__(
        self,
        emitter: EventEmitter,
        config: AgentShieldConfig,
        session_id: uuid.UUID,
        agent_id: str,
    ) -> None:
        """Initialize the ToolInterceptor.

        Args:
            emitter: EventEmitter for publishing security events.
            config: AgentShieldConfig with detection settings.
            session_id: UUID of the current session.
            agent_id: Human-readable identifier for this agent.
        """
        super().__init__(emitter, config, session_id, agent_id)
        self._patched_tools = {}
        self._pre_call_hooks = []
        self._post_call_hooks = []

        logger.debug(
            "ToolInterceptor initialized | session={}",
            session_id,
        )

    def attach(self, target: list[BaseTool]) -> None:
        """Monkey-patch all tools in the provided list.

        Stores original _run and _arun methods in
        _patched_tools, then replaces them with wrapper
        functions that emit events and run hooks.

        Safe to call multiple times. Already-patched tools
        are skipped to prevent double-patching.

        Args:
            target: List of LangChain BaseTool instances to patch.

        Raises:
            InterceptorError: If patching fails for any tool.
        """
        try:
            for tool in target:
                if tool.name in self._patched_tools:
                    logger.debug(
                        "Tool already patched, skipping | tool={}",
                        tool.name,
                    )
                    continue

                self._patch_tool(tool)

            self._attached = True
            logger.info(
                "ToolInterceptor attached | tools={} session={}",
                list(self._patched_tools.keys()),
                self._session_id,
            )
        except InterceptorError:
            raise
        except (AttributeError, TypeError, ValueError) as exc:
            raise InterceptorError(f"Failed to attach ToolInterceptor: {exc}") from exc

    def detach(self) -> None:
        """Restore all patched tools to their original methods.

        Iterates through _patched_tools and restores each
        tool's _run and _arun to the original callables
        stored at patch time.

        After detach(), all tools behave exactly as they
        did before attach() was called.

        Raises:
            InterceptorError: If restoration fails.
        """
        try:
            for tool_name, patched in self._patched_tools.items():
                patched.tool._run = patched.original_run  # type: ignore[method-assign]
                patched.tool._arun = patched.original_arun  # type: ignore[method-assign]
                logger.debug("Tool restored | tool={}", tool_name)

            self._patched_tools.clear()
            self._attached = False

            logger.info(
                "ToolInterceptor detached | session={}",
                self._session_id,
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise InterceptorError(f"Failed to detach ToolInterceptor: {exc}") from exc

    @property
    def is_attached(self) -> bool:
        """Whether this interceptor is currently active.

        Returns:
            True if at least one tool is currently patched.
        """
        return self._attached

    def add_pre_call_hook(
        self,
        hook: Callable[[ToolCallEvent], HookResult],
    ) -> None:
        """Register a pre-call hook to run before tool execution.

        Pre-call hooks receive the TOOL_CALL_START event and
        return a HookResult. If HookResult.block is True,
        the tool call is cancelled.

        Args:
            hook: Callable that takes a ToolCallEvent and
                returns a HookResult.
        """
        self._pre_call_hooks.append(hook)
        logger.debug(
            "Pre-call hook registered | hook={} session={}",
            hook.__name__,
            self._session_id,
        )

    def add_post_call_hook(
        self,
        hook: Callable[[ToolCallEvent], None],
    ) -> None:
        """Register a post-call hook to run after tool execution.

        Post-call hooks receive the TOOL_CALL_COMPLETE event
        and cannot block execution. Used for analysis that
        requires the tool output.

        Args:
            hook: Callable that takes a ToolCallEvent.
        """
        self._post_call_hooks.append(hook)
        logger.debug(
            "Post-call hook registered | hook={} session={}",
            hook.__name__,
            self._session_id,
        )

    def create_hook(
        self,
        tool_name: str,
        original_fn: Callable[..., Any],
        agent_id: str,
    ) -> Callable[..., Any]:
        """Return wrapped tool function with pre/post interception.

        Emits TOOL_CALL_START before execution, runs pre-call hooks,
        executes the original function, and emits TOOL_CALL_COMPLETE
        after success. If the call is blocked or policy violations are
        raised, emits a failed/blocked event and re-raises.

        Args:
            tool_name: Name of the tool being wrapped.
            original_fn: Original callable to execute.
            agent_id: Agent identifier associated with this tool call.

        Returns:
            Wrapped callable preserving original signature behavior.
        """

        interceptor = self

        def _hooked(*args: Any, **kwargs: Any) -> Any:
            tool_input = interceptor._extract_input(args, kwargs)

            start_event = ToolCallEvent(
                session_id=interceptor._session_id,
                agent_id=agent_id,
                event_type=EventType.TOOL_CALL_START,
                severity=SeverityLevel.INFO,
                metadata={"status": "STARTED"},
                tool_name=tool_name,
                tool_input=tool_input,
                trust_level=TrustLevel.EXTERNAL,
            )
            interceptor._emit(start_event)

            try:
                block_result = interceptor._run_pre_hooks(start_event)
            except PolicyViolationError as exc:
                failed_event = ToolCallEvent(
                    session_id=interceptor._session_id,
                    agent_id=agent_id,
                    event_type=EventType.TOOL_CALL_COMPLETE,
                    severity=SeverityLevel.HIGH,
                    metadata={"status": "FAILED"},
                    tool_name=tool_name,
                    tool_input=tool_input,
                    tool_output=str(exc),
                    trust_level=TrustLevel.EXTERNAL,
                )
                interceptor._emit(failed_event)
                raise

            if block_result is not None and block_result.block:
                blocked_event = ToolCallEvent(
                    session_id=interceptor._session_id,
                    agent_id=agent_id,
                    event_type=EventType.TOOL_CALL_BLOCKED,
                    severity=SeverityLevel.HIGH,
                    metadata={"status": "FAILED"},
                    tool_name=tool_name,
                    tool_input=tool_input,
                    blocked=True,
                    block_reason=block_result.reason,
                    trust_level=TrustLevel.EXTERNAL,
                )
                interceptor._emit(blocked_event)
                raise ToolCallBlockedError(
                    f"Tool call blocked: {block_result.reason}",
                    confidence=block_result.confidence,
                    evidence={
                        "tool_name": tool_name,
                        "tool_input": tool_input,
                        "reason": block_result.reason,
                    },
                )

            start_time = time.monotonic()

            try:
                result = original_fn(*args, **kwargs)
            except PolicyViolationError as exc:
                failed_event = ToolCallEvent(
                    session_id=interceptor._session_id,
                    agent_id=agent_id,
                    event_type=EventType.TOOL_CALL_COMPLETE,
                    severity=SeverityLevel.HIGH,
                    metadata={"status": "FAILED"},
                    tool_name=tool_name,
                    tool_input=tool_input,
                    tool_output=str(exc),
                    execution_time_ms=(time.monotonic() - start_time) * 1000.0,
                    trust_level=TrustLevel.EXTERNAL,
                )
                interceptor._emit(failed_event)
                raise

            execution_time_ms = (time.monotonic() - start_time) * 1000.0
            complete_event = ToolCallEvent(
                session_id=interceptor._session_id,
                agent_id=agent_id,
                event_type=EventType.TOOL_CALL_COMPLETE,
                severity=SeverityLevel.INFO,
                metadata={"status": "COMPLETED"},
                tool_name=tool_name,
                tool_input=tool_input,
                tool_output=str(result),
                execution_time_ms=execution_time_ms,
                trust_level=TrustLevel.EXTERNAL,
            )
            interceptor._emit(complete_event)
            interceptor._run_post_hooks(complete_event)

            return result

        return _hooked

    def _patch_tool(self, tool: BaseTool) -> None:
        """Replace a single tool's _run and _arun with wrappers.

        Stores originals in _patched_tools before replacing.
        The wrapper closures capture tool_name and originals
        so they work correctly even after multiple patches.

        Args:
            tool: The BaseTool instance to patch.

        Raises:
            InterceptorError: If the tool lacks expected methods.
        """
        if not hasattr(tool, "_run"):
            raise InterceptorError(f"Tool {tool.name!r} has no _run method")
        if not hasattr(tool, "_arun"):
            raise InterceptorError(f"Tool {tool.name!r} has no _arun method")

        original_run = tool._run
        original_arun = tool._arun

        self._patched_tools[tool.name] = PatchedTool(
            tool=tool,
            original_run=original_run,
            original_arun=original_arun,
        )

        tool._run = self._make_sync_wrapper(  # type: ignore[method-assign]
            tool.name,
            original_run,
        )
        tool._arun = self._make_async_wrapper(  # type: ignore[method-assign]
            tool.name,
            original_arun,
        )

        logger.debug("Tool patched | tool={}", tool.name)

    def _make_sync_wrapper(
        self,
        tool_name: str,
        original_run: Callable[..., Any],
    ) -> Callable[..., Any]:
        """Build the synchronous wrapper for a tool's _run method.

        Args:
            tool_name: Name of the tool being wrapped.
            original_run: The original _run method to wrap.

        Returns:
            Wrapper function with the same signature as _run.
        """
        interceptor = self

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            tool_input = interceptor._extract_input(args, kwargs)

            start_event = ToolCallEvent(
                **interceptor._make_base_kwargs(
                    event_type=EventType.TOOL_CALL_START,
                    severity=SeverityLevel.INFO,
                ),
                tool_name=tool_name,
                tool_input=tool_input,
                trust_level=TrustLevel.EXTERNAL,
            )
            interceptor._emit(start_event)

            block_result = interceptor._run_pre_hooks(start_event)
            if block_result is not None and block_result.block:
                blocked_event = ToolCallEvent(
                    **interceptor._make_base_kwargs(
                        event_type=EventType.TOOL_CALL_BLOCKED,
                        severity=SeverityLevel.HIGH,
                    ),
                    tool_name=tool_name,
                    tool_input=tool_input,
                    blocked=True,
                    block_reason=block_result.reason,
                    trust_level=TrustLevel.EXTERNAL,
                )
                interceptor._emit(blocked_event)
                raise ToolCallBlockedError(
                    f"Tool call blocked: {block_result.reason}",
                    confidence=block_result.confidence,
                    evidence={
                        "tool_name": tool_name,
                        "tool_input": tool_input,
                        "reason": block_result.reason,
                    },
                )

            start_time = time.monotonic()
            result = original_run(*args, **kwargs)
            execution_time_ms = (time.monotonic() - start_time) * 1000.0

            complete_event = ToolCallEvent(
                **interceptor._make_base_kwargs(
                    event_type=EventType.TOOL_CALL_COMPLETE,
                    severity=SeverityLevel.INFO,
                ),
                tool_name=tool_name,
                tool_input=tool_input,
                tool_output=str(result),
                execution_time_ms=execution_time_ms,
                trust_level=TrustLevel.EXTERNAL,
            )
            interceptor._emit(complete_event)
            interceptor._run_post_hooks(complete_event)

            return result

        return wrapper

    def _make_async_wrapper(
        self,
        tool_name: str,
        original_arun: Callable[..., Any],
    ) -> Callable[..., Any]:
        """Build the asynchronous wrapper for a tool's _arun method.

        Args:
            tool_name: Name of the tool being wrapped.
            original_arun: The original _arun method to wrap.

        Returns:
            Async wrapper function with same signature as _arun.
        """
        interceptor = self

        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            tool_input = interceptor._extract_input(args, kwargs)

            start_event = ToolCallEvent(
                **interceptor._make_base_kwargs(
                    event_type=EventType.TOOL_CALL_START,
                    severity=SeverityLevel.INFO,
                ),
                tool_name=tool_name,
                tool_input=tool_input,
                trust_level=TrustLevel.EXTERNAL,
            )
            interceptor._emit(start_event)

            block_result = interceptor._run_pre_hooks(start_event)
            if block_result is not None and block_result.block:
                blocked_event = ToolCallEvent(
                    **interceptor._make_base_kwargs(
                        event_type=EventType.TOOL_CALL_BLOCKED,
                        severity=SeverityLevel.HIGH,
                    ),
                    tool_name=tool_name,
                    tool_input=tool_input,
                    blocked=True,
                    block_reason=block_result.reason,
                    trust_level=TrustLevel.EXTERNAL,
                )
                interceptor._emit(blocked_event)
                raise ToolCallBlockedError(
                    f"Tool call blocked: {block_result.reason}",
                    confidence=block_result.confidence,
                    evidence={
                        "tool_name": tool_name,
                        "tool_input": tool_input,
                        "reason": block_result.reason,
                    },
                )

            start_time = time.monotonic()
            result = await original_arun(*args, **kwargs)
            execution_time_ms = (time.monotonic() - start_time) * 1000.0

            complete_event = ToolCallEvent(
                **interceptor._make_base_kwargs(
                    event_type=EventType.TOOL_CALL_COMPLETE,
                    severity=SeverityLevel.INFO,
                ),
                tool_name=tool_name,
                tool_input=tool_input,
                tool_output=str(result),
                execution_time_ms=execution_time_ms,
                trust_level=TrustLevel.EXTERNAL,
            )
            interceptor._emit(complete_event)
            interceptor._run_post_hooks(complete_event)

            return result

        return async_wrapper

    def _run_pre_hooks(
        self,
        event: ToolCallEvent,
    ) -> HookResult | None:
        """Run all registered pre-call hooks against the event.

        Stops at the first hook that returns block=True.
        Returns that HookResult immediately without running
        remaining hooks.

        Args:
            event: The TOOL_CALL_START event to analyze.

        Returns:
            First blocking HookResult, or None if all pass.
        """
        for hook in self._pre_call_hooks:
            try:
                result = hook(event)
                if result.block:
                    logger.warning(
                        "Pre-call hook blocked tool | tool={} hook={} reason={} session={}",
                        event.tool_name,
                        hook.__name__,
                        result.reason,
                        self._session_id,
                    )
                    return result
            except Exception as exc:
                if isinstance(exc, PolicyViolationError):
                    raise
                logger.error(
                    "Pre-call hook error | hook={} tool={} error={}",
                    hook.__name__,
                    event.tool_name,
                    exc,
                )
        return None

    def _run_post_hooks(self, event: ToolCallEvent) -> None:
        """Run all registered post-call hooks against the event.

        Post-call hooks cannot block. Errors in post-call
        hooks are logged but never propagated.

        Args:
            event: The TOOL_CALL_COMPLETE event to analyze.
        """
        for hook in self._post_call_hooks:
            try:
                hook(event)
            except Exception as exc:
                if isinstance(exc, PolicyViolationError):
                    raise
                logger.error(
                    "Post-call hook error | hook={} tool={} error={}",
                    hook.__name__,
                    event.tool_name,
                    exc,
                )

    def _extract_input(
        self,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        """Extract tool input from args and kwargs into a dict.

        LangChain tools call _run with either a single string
        positional arg or keyword args. This normalizes both
        into a consistent dict for event storage.

        Args:
            args: Positional arguments from the tool call.
            kwargs: Keyword arguments from the tool call.

        Returns:
            Dictionary representation of the tool input.
        """
        if args and isinstance(args[0], str):
            return {"input": args[0]}
        if args and isinstance(args[0], dict):
            first_arg = args[0]
            return dict(first_arg)
        if kwargs:
            return dict(kwargs)
        return {}
