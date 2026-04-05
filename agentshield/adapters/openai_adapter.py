"""OpenAI raw client adapter with runtime hook interception."""

from __future__ import annotations

import asyncio
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from loguru import logger

from agentshield.adapters.base import AdapterContext, BaseAdapter
from agentshield.adapters.registry import AdapterRegistry
from agentshield.exceptions import AdapterError, PolicyViolationError


@AdapterRegistry.register
class OpenAIAdapter(BaseAdapter):
    """Adapter for raw OpenAI SDK clients."""

    framework_name = "openai"

    @classmethod
    def supports(cls, agent: Any) -> bool:
        """Return whether object appears OpenAI-client compatible.

        Args:
            agent: Candidate object.

        Returns:
            True when object exposes chat.completions.create.
        """
        module_name = str(getattr(agent.__class__, "__module__", "")).lower()
        if module_name.startswith("openai"):
            return True

        chat_obj = getattr(agent, "chat", None)
        completions_obj = getattr(chat_obj, "completions", None)
        return callable(getattr(completions_obj, "create", None))

    def wrap(self, agent: Any, context: AdapterContext) -> Any:
        """Patch OpenAI completion create method with runtime hooks.

        Args:
            agent: OpenAI client.
            context: Runtime context.

        Returns:
            Patched client.

        Raises:
            AdapterError: If client shape is unsupported.
        """
        if getattr(agent, "_agentshield_openai_patched", False):
            return agent

        chat_obj = getattr(agent, "chat", None)
        completions_obj = getattr(chat_obj, "completions", None)
        original_create = getattr(completions_obj, "create", None)
        if not callable(original_create):
            raise AdapterError("OpenAI client does not expose chat.completions.create")

        completions_target: Any = completions_obj

        if asyncio.iscoroutinefunction(original_create):

            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                prompt = self._extract_prompt(kwargs, args)
                context.runtime.on_llm_start(prompt)

                tool_names = self._extract_declared_tools(kwargs)
                for tool_name in tool_names:
                    context.runtime.on_tool_start(tool_name, kwargs)

                try:
                    result = await original_create(*args, **kwargs)
                except PolicyViolationError:
                    raise
                except Exception as error:
                    logger.error(f"Adapter interception failed: {error}")
                    raise

                context.runtime.on_llm_end(self._extract_response(result))

                for tool_name, tool_payload in self._extract_response_tool_calls(result):
                    context.runtime.on_tool_end(tool_name, tool_payload)

                return result

            completions_target.create = async_wrapper
        else:

            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                prompt = self._extract_prompt(kwargs, args)
                context.runtime.on_llm_start(prompt)

                tool_names = self._extract_declared_tools(kwargs)
                for tool_name in tool_names:
                    context.runtime.on_tool_start(tool_name, kwargs)

                try:
                    result = original_create(*args, **kwargs)
                except PolicyViolationError:
                    raise
                except Exception as error:
                    logger.error(f"Adapter interception failed: {error}")
                    raise

                context.runtime.on_llm_end(self._extract_response(result))

                for tool_name, tool_payload in self._extract_response_tool_calls(result):
                    context.runtime.on_tool_end(tool_name, tool_payload)

                return result

            completions_target.create = sync_wrapper

        agent._agentshield_openai_patched = True
        return agent

    def _extract_prompt(self, kwargs: dict[str, Any], args: tuple[Any, ...]) -> str:
        """Extract prompt text from chat completion arguments.

        Args:
            kwargs: Keyword args passed to create().
            args: Positional args passed to create().

        Returns:
            Joined prompt text.
        """
        messages = kwargs.get("messages")
        if not isinstance(messages, list) and args:
            messages = args[0]

        if not isinstance(messages, list):
            return ""

        parts: list[str] = []
        for message in messages:
            if isinstance(message, dict):
                parts.append(str(message.get("content", "")))
            else:
                parts.append(str(message))
        return "\n".join(part for part in parts if part)

    def _extract_response(self, result: Any) -> str:
        """Extract response text from OpenAI completion result.

        Args:
            result: Completion result object.

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
            return str(message_obj.get("content", ""))

        return str(getattr(message_obj, "content", ""))

    def _extract_declared_tools(self, kwargs: dict[str, Any]) -> list[str]:
        """Extract declared tool names from request payload.

        Args:
            kwargs: create() keyword arguments.

        Returns:
            Tool names declared in request.
        """
        tools = kwargs.get("tools")
        if not isinstance(tools, list):
            return []

        names: list[str] = []
        for tool in tools:
            if isinstance(tool, dict):
                function_obj = tool.get("function")
                if isinstance(function_obj, dict) and "name" in function_obj:
                    names.append(str(function_obj["name"]))
        return names

    def _extract_response_tool_calls(self, result: Any) -> list[tuple[str, Any]]:
        """Extract tool calls from model response.

        Args:
            result: Completion result.

        Returns:
            List of tool name and payload pairs.
        """
        choices = getattr(result, "choices", None)
        if not isinstance(choices, list) or not choices:
            return []

        first_choice = choices[0]
        message_obj: Any
        if isinstance(first_choice, dict):
            message_obj = first_choice.get("message")
        else:
            message_obj = getattr(first_choice, "message", None)

        tool_calls = None
        if isinstance(message_obj, dict):
            tool_calls = message_obj.get("tool_calls")
        else:
            tool_calls = getattr(message_obj, "tool_calls", None)

        if not isinstance(tool_calls, list):
            return []

        extracted: list[tuple[str, Any]] = []
        for call in tool_calls:
            if isinstance(call, dict):
                function_obj = call.get("function")
                if isinstance(function_obj, dict):
                    name = str(function_obj.get("name", "tool"))
                    extracted.append((name, function_obj.get("arguments", "")))
            else:
                function_obj = getattr(call, "function", None)
                name = str(getattr(function_obj, "name", "tool"))
                arguments = getattr(function_obj, "arguments", "")
                extracted.append((name, arguments))
        return extracted

    @classmethod
    def get_framework_version(cls) -> str | None:
        """Return installed OpenAI package version.

        Returns:
            Version string or None.
        """
        try:
            return version("openai")
        except PackageNotFoundError:
            return None
