from __future__ import annotations

import re
import uuid
from typing import Any

from loguru import logger

from agentshield.config import AgentShieldConfig
from agentshield.events.models import (
    BaseEvent,
    EventType,
    LLMEvent,
    MemoryEvent,
    ProvenanceEvent,
    ToolCallEvent,
    TrustLevel,
)
from agentshield.exceptions import ProvenanceError
from agentshield.provenance.models import ContentRecord, ProvenanceContext, hash_content

URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>]+" r"|www\.[a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,}"
)

INTERNAL_TOOL_PATTERNS: list[str] = [
    "memory",
    "recall",
    "remember",
    "internal",
    "local",
    "cache",
]

TRUSTED_SOURCE_PATTERNS: list[str] = [
    "user",
    "human",
    "input",
    "query",
]


class ProvenanceTracker:
    """Tracks origin and trust level for content entering LLM context.

    Maintains one ProvenanceContext per active session.
    Receives events from the detection engine event stream
    and classifies each piece of content by source.

    Trust classification rules:
      User messages (LLM_PROMPT, no prior tool context)
        -> TRUSTED
      Memory reads (MEMORY_READ events)
        -> INTERNAL
      Tool outputs from known internal tools
        -> INTERNAL
      Tool outputs from external-facing tools
        -> EXTERNAL
      Tool outputs containing URLs or web content
        -> UNTRUSTED
      Any content from unknown/unclassified sources
        -> UNTRUSTED

    Attributes:
        _config: AgentShieldConfig.
        _contexts: ProvenanceContext per session keyed by UUID.
    """

    _config: AgentShieldConfig
    _contexts: dict[str, ProvenanceContext]

    def __init__(self, config: AgentShieldConfig) -> None:
        """Initialize the ProvenanceTracker.

        Args:
            config: AgentShieldConfig instance.
        """
        self._config = config
        self._contexts = {}
        logger.info("ProvenanceTracker initialized")

    def initialize_session(
        self,
        session_id: uuid.UUID,
        tool_trust_overrides: dict[str, TrustLevel] | None = None,
    ) -> None:
        """Initialize provenance tracking for a new session.

        Args:
            session_id: UUID of the new session.
            tool_trust_overrides: Optional per-tool trust
                level overrides. Keys are tool names,
                values are TrustLevel enum values.
        """
        normalized_overrides = {
            key.lower(): value for key, value in (tool_trust_overrides or {}).items()
        }

        context = ProvenanceContext(
            session_id=session_id,
            tool_trust_overrides=normalized_overrides,
        )
        self._contexts[str(session_id)] = context

        logger.info(
            "Provenance session initialized | session={}",
            str(session_id)[:8],
        )

    def process_event(self, event: BaseEvent) -> ProvenanceEvent | None:
        """Process an event and tag its content with provenance.

        Routes the event to the appropriate classification
        method based on event type. Returns a ProvenanceEvent
        if content was tagged, None if event is not relevant.

        Args:
            event: Any BaseEvent from the interceptor layer.

        Returns:
            ProvenanceEvent with trust tags, or None.

        Raises:
            ProvenanceError: If provenance processing fails.
        """
        session_key = str(event.session_id)
        context = self._contexts.get(session_key)

        if context is None:
            return None

        try:
            if event.event_type == EventType.TOOL_CALL_COMPLETE and isinstance(
                event, ToolCallEvent
            ):
                return self._tag_tool_output(event, context)

            if event.event_type == EventType.LLM_PROMPT and isinstance(event, LLMEvent):
                return self._tag_llm_prompt(event, context)

            if event.event_type == EventType.MEMORY_READ and isinstance(
                event, MemoryEvent
            ):
                return self._tag_memory_content(event, context)

            return None
        except ProvenanceError:
            raise
        except (AttributeError, TypeError, ValueError, RuntimeError) as exc:
            raise ProvenanceError(
                message="Failed to process provenance event",
                evidence={
                    "event_type": event.event_type.value,
                    "session_id": session_key,
                    "error": str(exc),
                },
                session_id=session_key,
            ) from exc

    def get_trust_level(
        self,
        session_id: uuid.UUID,
        content: str,
    ) -> TrustLevel:
        """Get the trust level for a specific content string.

        Hashes the content and looks it up in the session
        provenance context. Returns UNTRUSTED if not found
        to fail secure - unknown content is not trusted.

        Args:
            session_id: UUID of the session.
            content: The content string to look up.

        Returns:
            TrustLevel for this content. UNTRUSTED if unknown.
        """
        context = self._contexts.get(str(session_id))
        if context is None:
            return TrustLevel.UNTRUSTED

        content_hash = hash_content(content)
        trust = context.get_trust_level(content_hash)
        return trust if trust is not None else TrustLevel.UNTRUSTED

    def get_context(self, session_id: uuid.UUID) -> ProvenanceContext | None:
        """Return the full ProvenanceContext for a session.

        Args:
            session_id: UUID of the session.

        Returns:
            ProvenanceContext or None if session not found.
        """
        return self._contexts.get(str(session_id))

    def close_session(self, session_id: uuid.UUID) -> None:
        """Close and clean up a session provenance context.

        Args:
            session_id: UUID of the session to close.
        """
        session_key = str(session_id)
        if session_key in self._contexts:
            context = self._contexts[session_key]
            logger.info(
                "Provenance session closed | session={} records={} untrusted={} flagged={}",
                session_key[:8],
                len(context.records),
                context.untrusted_content_count,
                context.flagged_count,
            )
            del self._contexts[session_key]

    def _tag_tool_output(
        self,
        event: ToolCallEvent,
        context: ProvenanceContext,
    ) -> ProvenanceEvent | None:
        """Tag tool output content with an appropriate trust level.

        Classification logic:
          1. Check tool_trust_overrides first - explicit wins
          2. Check INTERNAL_TOOL_PATTERNS - internal tools
          3. Check if output contains URLs -> UNTRUSTED
          4. Default: EXTERNAL for unknown tools

        Args:
            event: TOOL_CALL_COMPLETE event with tool output.
            context: Session provenance context.

        Returns:
            ProvenanceEvent tagging the tool output.
        """
        if event.tool_output is None:
            return None

        tool_name_lower = event.tool_name.lower()
        content = event.tool_output

        if tool_name_lower in context.tool_trust_overrides:
            trust_level = context.tool_trust_overrides[tool_name_lower]
        elif self._matches_patterns(tool_name_lower, INTERNAL_TOOL_PATTERNS):
            trust_level = TrustLevel.INTERNAL
        elif URL_PATTERN.search(content):
            trust_level = TrustLevel.UNTRUSTED
        else:
            trust_level = TrustLevel.EXTERNAL

        source_url = self._extract_url(content)

        record = self._create_record(
            content=content,
            trust_level=trust_level,
            source_type="tool_output",
            session_id=context.session_id,
            source_tool=event.tool_name,
            source_url=source_url,
        )

        self._register_record(record, context)

        logger.debug(
            "Tool output tagged | tool={} trust={} has_url={} session={}",
            event.tool_name,
            trust_level.value,
            source_url is not None,
            str(context.session_id)[:8],
        )

        return self._build_provenance_event(event=event, record=record)

    def _tag_llm_prompt(
        self,
        event: LLMEvent,
        context: ProvenanceContext,
    ) -> ProvenanceEvent:
        """Tag LLM prompt content with trust level.

        LLM prompts are composite and can contain content
        from multiple sources. If prompt_trust_levels includes
        any UNTRUSTED segment the aggregate trust is UNTRUSTED,
        otherwise TRUSTED.

        Args:
            event: LLM_PROMPT event with prompt content.
            context: Session provenance context.

        Returns:
            ProvenanceEvent tagging the prompt.
        """
        if event.prompt_trust_levels:
            untrusted_sources = [
                key
                for key, value in event.prompt_trust_levels.items()
                if value == TrustLevel.UNTRUSTED.value
            ]
            trust_level = (
                TrustLevel.UNTRUSTED if untrusted_sources else TrustLevel.TRUSTED
            )
        else:
            trust_level = TrustLevel.TRUSTED

        record = self._create_record(
            content=event.prompt,
            trust_level=trust_level,
            source_type="llm_prompt",
            session_id=context.session_id,
        )

        self._register_record(record, context)

        logger.debug(
            "LLM prompt tagged | trust={} session={}",
            trust_level.value,
            str(context.session_id)[:8],
        )

        return self._build_provenance_event(event=event, record=record)

    def _tag_memory_content(
        self,
        event: MemoryEvent,
        context: ProvenanceContext,
    ) -> ProvenanceEvent:
        """Tag memory read content as INTERNAL.

        Memory content originates from the agent's own
        previous sessions. While memory can be poisoned,
        legitimate memory reads are classified INTERNAL.

        Args:
            event: MEMORY_READ event with content preview.
            context: Session provenance context.

        Returns:
            ProvenanceEvent tagging the memory content.
        """
        record = self._create_record(
            content=event.content_preview,
            trust_level=TrustLevel.INTERNAL,
            source_type="memory_read",
            session_id=context.session_id,
            metadata={"memory_key": event.memory_key},
        )

        self._register_record(record, context)

        logger.debug(
            "Memory content tagged | key={} trust=INTERNAL session={}",
            event.memory_key,
            str(context.session_id)[:8],
        )

        return self._build_provenance_event(event=event, record=record)

    def _create_record(
        self,
        content: str,
        trust_level: TrustLevel,
        source_type: str,
        session_id: uuid.UUID,
        source_tool: str | None = None,
        source_url: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ContentRecord:
        """Create a ContentRecord for a piece of content.

        Hashes the content and never stores raw content.

        Args:
            content: The content string to record.
            trust_level: Assigned trust level.
            source_type: Category string for this source.
            session_id: Session UUID.
            source_tool: Tool name if from tool output.
            source_url: URL if web content detected.
            metadata: Optional additional metadata.

        Returns:
            Populated ContentRecord with hashed content.
        """
        return ContentRecord(
            content_hash=hash_content(content),
            trust_level=trust_level,
            source_type=source_type,
            session_id=session_id,
            source_tool=source_tool,
            source_url=source_url,
            metadata=metadata or {},
        )

    def _register_record(
        self,
        record: ContentRecord,
        context: ProvenanceContext,
    ) -> None:
        """Register a ContentRecord in the session context.

        Updates counters for untrusted and flagged content.
        Idempotent behavior: duplicate hashes are skipped.

        Args:
            record: The ContentRecord to register.
            context: Session ProvenanceContext to update.
        """
        if record.content_hash in context.records:
            return

        context.records[record.content_hash] = record

        if record.trust_level == TrustLevel.UNTRUSTED:
            context.untrusted_content_count += 1

        if record.flagged:
            context.flagged_count += 1

    def _build_provenance_event(
        self,
        event: BaseEvent,
        record: ContentRecord,
    ) -> ProvenanceEvent:
        """Build a ProvenanceEvent from a ContentRecord.

        Args:
            event: Source event being tagged.
            record: ContentRecord with provenance data.

        Returns:
            ProvenanceEvent ready for emission.
        """
        return ProvenanceEvent(
            session_id=event.session_id,
            agent_id=event.agent_id,
            event_type=EventType.PROVENANCE_TAGGED,
            content_hash=record.content_hash,
            trust_level=record.trust_level,
            source_tool=record.source_tool,
            source_url=record.source_url,
            content_length=0,
        )

    def _matches_patterns(self, text: str, patterns: list[str]) -> bool:
        """Check whether text contains any configured patterns.

        Args:
            text: Text to inspect. Expected lowercase.
            patterns: List of substring patterns.

        Returns:
            True if any pattern is present.
        """
        return any(pattern in text for pattern in patterns)

    def _extract_url(self, content: str) -> str | None:
        """Extract the first URL from content.

        Args:
            content: Content string to search.

        Returns:
            First URL found, else None.
        """
        match = URL_PATTERN.search(content)
        return match.group(0) if match else None
