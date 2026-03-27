from __future__ import annotations

import hashlib

from loguru import logger

from agentshield.events.models import BaseEvent, LLMEvent, MemoryEvent, ToolCallEvent


class EventScrubber:
    """Redact sensitive fields from events before persistence.

    Scrubs raw prompt, response, and tool output fields by replacing content
    with SHA-256 hashes and companion length metadata. Full content is never
    written to persistent audit logs after scrubbing.
    """

    def scrub_llm_event(self, event: LLMEvent) -> LLMEvent:
        """Return a scrubbed copy of an LLM event.

        Args:
            event: LLM event containing prompt/response text.

        Returns:
            New LLMEvent with text fields replaced by SHA-256 hashes.
        """
        prompt_hash, prompt_len = self._hash_with_length(event.prompt)
        response_hash: str | None = None
        response_len = 0
        if event.response is not None:
            response_hash, response_len = self._hash_with_length(event.response)

        metadata = dict(event.metadata)
        metadata["scrubbed_prompt_length"] = prompt_len
        metadata["scrubbed_response_length"] = response_len

        logger.debug(
            "Scrubbed LLM event | id={} prompt_len={} response_len={}",
            event.id,
            prompt_len,
            response_len,
        )

        return event.model_copy(
            update={
                "prompt": prompt_hash,
                "response": response_hash,
                "metadata": metadata,
            }
        )

    def scrub_tool_event(self, event: ToolCallEvent) -> ToolCallEvent:
        """Return a scrubbed copy of a tool-call event.

        Args:
            event: Tool call event potentially containing tool output.

        Returns:
            New ToolCallEvent with tool output replaced by SHA-256 hash.
        """
        if event.tool_output is None:
            return event

        output_hash, output_len = self._hash_with_length(event.tool_output)
        metadata = dict(event.metadata)
        metadata["scrubbed_tool_output_length"] = output_len

        logger.debug(
            "Scrubbed tool event | id={} output_len={} tool={}",
            event.id,
            output_len,
            event.tool_name,
        )

        return event.model_copy(
            update={
                "tool_output": output_hash,
                "metadata": metadata,
            }
        )

    def scrub_memory_event(self, event: MemoryEvent) -> MemoryEvent:
        """Return a scrubbed copy of a memory event.

        Args:
            event: Memory event containing content preview text.

        Returns:
            New MemoryEvent with content preview replaced by SHA-256 hash.
        """
        preview_hash, preview_len = self._hash_with_length(event.content_preview)
        metadata = dict(event.metadata)
        metadata["scrubbed_memory_preview_length"] = preview_len

        logger.debug(
            "Scrubbed memory event | id={} preview_len={}",
            event.id,
            preview_len,
        )

        return event.model_copy(
            update={
                "content_preview": preview_hash,
                "metadata": metadata,
            }
        )

    def scrub(self, event: BaseEvent) -> BaseEvent:
        """Dispatch scrubbing by event type.

        Args:
            event: Event to scrub.

        Returns:
            Scrubbed event copy when supported; otherwise original event.
        """
        if isinstance(event, LLMEvent):
            return self.scrub_llm_event(event)
        if isinstance(event, ToolCallEvent):
            return self.scrub_tool_event(event)
        if isinstance(event, MemoryEvent):
            return self.scrub_memory_event(event)
        return event

    def _hash_with_length(self, content: str) -> tuple[str, int]:
        """Hash content and return hash with original length.

        Args:
            content: Raw content to hash.

        Returns:
            Tuple of hexadecimal SHA-256 hash and original content length.
        """
        encoded = content.encode("utf-8", errors="replace")
        return hashlib.sha256(encoded).hexdigest(), len(content)
