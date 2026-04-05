"""Anthropic raw client adapter with runtime hook interception."""

from __future__ import annotations

import asyncio
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from loguru import logger

from agentshield.adapters.base import AdapterContext, BaseAdapter
from agentshield.adapters.registry import AdapterRegistry
from agentshield.exceptions import AdapterError, PolicyViolationError


@AdapterRegistry.register
class AnthropicAdapter(BaseAdapter):
    """Adapter for raw Anthropic SDK clients."""

    framework_name = "anthropic"

    @classmethod
    def supports(cls, agent: Any) -> bool:
        """Return whether object appears Anthropic-client compatible.

        Args:
            agent: Candidate object.

        Returns:
            True when object exposes messages.create.
        """
        module_name = str(getattr(agent.__class__, "__module__", "")).lower()
        if module_name.startswith("anthropic"):
            return True

        messages_obj = getattr(agent, "messages", None)
        return callable(getattr(messages_obj, "create", None))

    def wrap(self, agent: Any, context: AdapterContext) -> Any:
        """Patch Anthropic messages create method with runtime hooks.

        Args:
            agent: Anthropic client.
            context: Runtime context.

        Returns:
            Patched client.

        Raises:
            AdapterError: If client shape is unsupported.
        """
        if getattr(agent, "_agentshield_anthropic_patched", False):
            return agent

        messages_obj = getattr(agent, "messages", None)
        original_create = getattr(messages_obj, "create", None)
        if not callable(original_create):
            raise AdapterError("Anthropic client does not expose messages.create")

        messages_target: Any = messages_obj

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

                for tool_name, payload in self._extract_response_tool_calls(result):
                    context.runtime.on_tool_end(tool_name, payload)

                return result

            messages_target.create = async_wrapper
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

                for tool_name, payload in self._extract_response_tool_calls(result):
                    context.runtime.on_tool_end(tool_name, payload)

                return result

            messages_target.create = sync_wrapper

        agent._agentshield_anthropic_patched = True
        return agent

    def _extract_prompt(self, kwargs: dict[str, Any], args: tuple[Any, ...]) -> str:
        """Extract prompt text from Anthropic messages payload.

        Args:
            kwargs: Keyword args passed to create().
            args: Positional args passed to create().

        Returns:
            Prompt-like text.
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
        """Extract response text from Anthropic response object.

        Args:
            result: Response object.

        Returns:
            Best-effort text.
        """
        content = getattr(result, "content", None)
        if not isinstance(content, list):
            return ""

        parts: list[str] = []
        for block in content:
            if isinstance(block, dict):
                text = block.get("text")
                if text is not None:
                    parts.append(str(text))
            else:
                text = getattr(block, "text", None)
                if text is not None:
                    parts.append(str(text))
        return "\n".join(part for part in parts if part)

    def _extract_declared_tools(self, kwargs: dict[str, Any]) -> list[str]:
        """Extract declared tool names from request payload.

        Args:
            kwargs: create() keyword arguments.

        Returns:
            Tool name list.
        """
        tools = kwargs.get("tools")
        if not isinstance(tools, list):
            return []

        names: list[str] = []
        for tool in tools:
            if isinstance(tool, dict) and "name" in tool:
                names.append(str(tool["name"]))
        return names

    def _extract_response_tool_calls(self, result: Any) -> list[tuple[str, Any]]:
        """Extract tool_use blocks from Anthropic response payload.

        Args:
            result: Response object.

        Returns:
            Tool call name/payload tuples.
        """
        content = getattr(result, "content", None)
        if not isinstance(content, list):
            return []

        extracted: list[tuple[str, Any]] = []
        for block in content:
            if isinstance(block, dict):
                if block.get("type") == "tool_use":
                    extracted.append((str(block.get("name", "tool")), block.get("input", {})))
            else:
                block_type = getattr(block, "type", None)
                if block_type == "tool_use":
                    name = str(getattr(block, "name", "tool"))
                    payload = getattr(block, "input", {})
                    extracted.append((name, payload))
        return extracted

    @classmethod
    def get_framework_version(cls) -> str | None:
        """Return installed Anthropic package version.

        Returns:
            Version string or None.
        """
        try:
            return version("anthropic")
        except PackageNotFoundError:
            return None
