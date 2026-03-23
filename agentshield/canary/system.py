from __future__ import annotations

import uuid

from loguru import logger

from agentshield.canary.models import (
    CanarySessionState,
    CanaryToken,
    build_canary_instruction,
    generate_canary_token,
)
from agentshield.config import AgentShieldConfig
from agentshield.events.models import (
    BaseEvent,
    EventType,
    LLMEvent,
    RecommendedAction,
    SeverityLevel,
    ThreatEvent,
    ThreatType,
    ToolCallEvent,
)


class CanarySystem:
    """Manage canary token injection and trigger detection.

    Generates cryptographically unique canary tokens per
    session and scans LLM responses and tool outputs for
    token echoes that indicate active manipulation.

    Detection approach:
      Phase 4B (current):
        - Scans LLM_RESPONSE and TOOL_CALL_COMPLETE events
          for canary token strings
        - If found: immediate ThreatEvent with canary_triggered=True
        - Detection is retrospective - catches echoes after LLM

      Phase 10+ (future with adapter injection):
        - Injects canary instruction into LLM context BEFORE call
        - Full active honeypot behavior

    Token rotation:
      Tokens rotate after canary_rotation_sessions (from config).
      Old tokens kept for recent matching to catch delayed echoes.

    One CanarySystem instance is shared across all sessions.
    Session isolation uses CanarySessionState keyed by UUID.

    Attributes:
        _config: AgentShieldConfig with canary settings.
        _sessions: CanarySessionState per session.
    """

    _config: AgentShieldConfig
    _sessions: dict[str, CanarySessionState]

    def __init__(self, config: AgentShieldConfig) -> None:
        """Initialize the CanarySystem.

        Args:
            config: AgentShieldConfig with canary_enabled
                and canary_rotation_sessions settings.
        """

        self._config = config
        self._sessions = {}

        logger.info(
            "CanarySystem initialized | enabled={}",
            config.canary_enabled,
        )

    def initialize_session(self, session_id: uuid.UUID) -> CanaryToken | None:
        """Initialize canary tracking for a new session.

        Generates the first canary token for this session
        when canary detection is enabled.

        Args:
            session_id: UUID of the new session.

        Returns:
            The generated CanaryToken, or None if disabled.
        """

        if not self._config.canary_enabled:
            logger.debug(
                "Canary disabled - skipping session init | session={}",
                str(session_id)[:8],
            )
            return None

        token = generate_canary_token(session_id)
        state = CanarySessionState(session_id=session_id, active_token=token)
        self._sessions[str(session_id)] = state

        logger.info(
            "Canary session initialized | session={} token_hash={}",
            str(session_id)[:8],
            token.token_hash[:16],
        )

        return token

    def process_event(self, event: BaseEvent) -> ThreatEvent | None:
        """Scan an event for canary token echoes.

        Checks LLM_RESPONSE and TOOL_CALL_COMPLETE events
        for active canary token values.

        If a token echo is detected:
          1. Mark token as triggered
          2. Return a ThreatEvent with canary_triggered=True
             and BLOCK action for immediate enforcement

        Args:
            event: Any BaseEvent to scan.

        Returns:
            ThreatEvent if canary triggered, None if clean.
        """

        if not self._config.canary_enabled:
            return None

        state = self._sessions.get(str(event.session_id))
        if state is None:
            return None

        text_to_scan: str | None = None

        if event.event_type == EventType.LLM_RESPONSE and isinstance(event, LLMEvent):
            text_to_scan = event.response
        elif event.event_type == EventType.TOOL_CALL_COMPLETE and isinstance(
            event, ToolCallEvent
        ):
            text_to_scan = event.tool_output

        if text_to_scan is None:
            return None

        return self._scan_for_canary(text=text_to_scan, state=state, source_event=event)

    def get_canary_instruction(self, session_id: uuid.UUID) -> str | None:
        """Get the canary instruction string for a session.

        Returns the instruction to inject into LLM context
        before the next call. Returns None when canary is
        disabled or no active token exists.

        Args:
            session_id: UUID of the session.

        Returns:
            Canary instruction string, or None.
        """

        if not self._config.canary_enabled:
            return None

        state = self._sessions.get(str(session_id))
        if state is None or state.active_token is None:
            return None

        state.active_token.mark_injected()
        state.total_injections += 1

        instruction = build_canary_instruction(state.active_token)

        logger.debug(
            "Canary instruction generated | session={} injections={}",
            str(session_id)[:8],
            state.active_token.injection_count,
        )

        if (
            self._config.canary_rotation_sessions > 0
            and state.total_injections % self._config.canary_rotation_sessions == 0
        ):
            state.active_token.rotation_due = True
            self.rotate_token(session_id)

        return instruction

    def rotate_token(self, session_id: uuid.UUID) -> CanaryToken | None:
        """Rotate the active canary token for a session.

        Moves the current active token to historical list and
        generates a fresh token.

        Args:
            session_id: UUID of the session to rotate.

        Returns:
            New CanaryToken, or None if session not found.
        """

        state = self._sessions.get(str(session_id))
        if state is None:
            return None

        if state.active_token is not None:
            state.historical_tokens.append(state.active_token)
            state.historical_tokens = state.historical_tokens[-3:]

        new_token = generate_canary_token(session_id)
        state.active_token = new_token

        logger.info(
            "Canary token rotated | session={} new_hash={}",
            str(session_id)[:8],
            new_token.token_hash[:16],
        )

        return new_token

    def close_session(self, session_id: uuid.UUID) -> None:
        """Close and clean up a session's canary state.

        Args:
            session_id: UUID of the session to close.
        """

        session_key = str(session_id)
        state = self._sessions.get(session_key)
        if state is None:
            return

        logger.info(
            "Canary session closed | session={} injections={} triggers={}",
            session_key[:8],
            state.total_injections,
            state.total_triggers,
        )
        del self._sessions[session_key]

    def get_active_token(self, session_id: uuid.UUID) -> CanaryToken | None:
        """Return the active canary token for a session.

        Args:
            session_id: UUID of the session.

        Returns:
            Active CanaryToken or None.
        """

        state = self._sessions.get(str(session_id))
        if state is None:
            return None
        return state.active_token

    def _scan_for_canary(
        self,
        text: str,
        state: CanarySessionState,
        source_event: BaseEvent,
    ) -> ThreatEvent | None:
        """Scan text for active canary token values.

        Checks against active and recent historical tokens
        to catch delayed echoes after rotation.

        Args:
            text: Text to scan for canary echoes.
            state: Session canary state with active tokens.
            source_event: The event containing the text.

        Returns:
            ThreatEvent if canary found, None if clean.
        """

        active_values = state.get_all_active_values()

        triggered_token: CanaryToken | None = None
        for token_value in active_values:
            if token_value in text:
                triggered_token = self._find_token_by_value(state, token_value)
                break

        if triggered_token is None:
            return None

        state.total_triggers += 1
        triggered_token.mark_triggered()

        logger.critical(
            "CANARY TRIGGERED - active LLM manipulation detected | session={} token_hash={}",
            str(state.session_id)[:8],
            triggered_token.token_hash[:16],
        )

        trigger_context = self._redact_trigger_context(
            text=text,
            active_values=active_values,
        )

        evidence: dict[str, object] = {
            "canary_id": triggered_token.token_id,
            "canary_hash": triggered_token.token_hash,
            "trigger_context": trigger_context,
            "source_event_type": source_event.event_type.value,
            "detection_method": "canary_echo",
            "session_total_triggers": state.total_triggers,
        }

        return ThreatEvent(
            session_id=source_event.session_id,
            agent_id=source_event.agent_id,
            event_type=EventType.THREAT_DETECTED,
            severity=SeverityLevel.CRITICAL,
            threat_type=ThreatType.PROMPT_INJECTION,
            confidence=1.0,
            affected_event_id=source_event.id,
            explanation=(
                "Canary token echoed in LLM response - active prompt injection "
                "manipulation confirmed. This is a near-zero false positive detection."
            ),
            recommended_action=RecommendedAction.BLOCK,
            evidence=evidence,
            detector_name="CanarySystem",
            canary_triggered=True,
        )

    def _redact_trigger_context(self, text: str, active_values: set[str]) -> str:
        """Redact canary token values from forensic trigger context.

        Args:
            text: Raw source text that contained the canary echo.
            active_values: Candidate token values currently tracked.

        Returns:
            First 200 chars of source text with canary values redacted.
        """

        redacted = text
        for token_value in active_values:
            redacted = redacted.replace(token_value, "[REDACTED_CANARY]")
        return redacted[:200] if redacted else ""

    def _find_token_by_value(
        self,
        state: CanarySessionState,
        token_value: str,
    ) -> CanaryToken | None:
        """Find a CanaryToken by value in session state.

        Checks active token then historical tokens.

        Args:
            state: Session canary state to search.
            token_value: Token value string to find.

        Returns:
            Matching CanaryToken or None.
        """

        if (
            state.active_token is not None
            and state.active_token.token_value == token_value
        ):
            return state.active_token

        for token in reversed(state.historical_tokens):
            if token.token_value == token_value:
                return token

        return None
