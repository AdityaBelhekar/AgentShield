from __future__ import annotations

from loguru import logger

from agentshield.config import AgentShieldConfig
from agentshield.detection.base_detector import (
    BaseDetector,
    DetectionContext,
)
from agentshield.detection.embedding_service import EmbeddingService
from agentshield.events.models import (
    BaseEvent,
    EventType,
    RecommendedAction,
    SeverityLevel,
    ThreatEvent,
    ThreatType,
    ToolCallEvent,
)

# Static forbidden sequence defaults used by ToolChainDetector.
FORBIDDEN_SEQUENCES: list[tuple[str, ...]] = [
    # Read then send - classic exfiltration
    ("read_file", "send_email"),
    ("read_file", "send_report"),
    ("read_file", "send_message"),
    ("read_file", "post_data"),
    ("read_file", "upload"),
    ("read_file", "webhook"),
    # Multi-read then send - bulk exfiltration
    ("read_file", "read_file", "send_email"),
    ("read_file", "read_file", "send_report"),
    ("read_file", "read_file", "upload"),
    # Search then read then send - recon + exfiltration
    ("search", "read_file", "send_email"),
    ("search", "read_file", "send_report"),
    ("web_search", "read_file", "send_email"),
    # Read then write then send - transform + exfiltrate
    ("read_file", "write_file", "send_email"),
    ("read_file", "write_file", "upload"),
    # Database patterns
    ("query_db", "send_email"),
    ("query_db", "upload"),
    ("query_db", "webhook"),
    ("sql_query", "send_email"),
    ("sql_query", "upload"),
    # Credential patterns
    ("read_credentials", "send_email"),
    ("read_secrets", "send_email"),
    ("get_api_key", "send_email"),
    # Execute then send - code execution + exfil
    ("execute", "send_email"),
    ("run_code", "send_email"),
    ("bash", "send_email"),
    ("shell", "send_email"),
]

READ_PATTERNS: list[str] = [
    "read",
    "load",
    "fetch",
    "get",
    "retrieve",
    "download",
    "open",
    "list",
    "ls",
    "cat",
    "query",
    "search",
    "find",
    "lookup",
    "select",
]

WRITE_PATTERNS: list[str] = [
    "write",
    "save",
    "store",
    "create",
    "update",
    "delete",
    "remove",
    "modify",
    "edit",
    "put",
    "post",
    "insert",
    "append",
]

SEND_PATTERNS: list[str] = [
    "send",
    "email",
    "mail",
    "message",
    "notify",
    "alert",
    "report",
    "upload",
    "publish",
    "push",
    "webhook",
    "transmit",
    "broadcast",
    "post",
    "forward",
    "relay",
    "exfil",
]

EXECUTE_PATTERNS: list[str] = [
    "execute",
    "run",
    "eval",
    "exec",
    "bash",
    "shell",
    "cmd",
    "command",
    "script",
]


class ToolChainDetector(BaseDetector):
    """Detect tool chain escalation attacks in agent execution.

    Analyzes TOOL_CALL_START events by examining the full
    tool call history in DetectionContext to identify
    dangerous sequences of tool invocations.

    Two detection layers:
      1. Forbidden sequence matching - exact pattern detection
      2. Heuristic escalation scoring - category-based analysis

    Hooks into TOOL_CALL_START (not COMPLETE) so dangerous
    tool calls can be blocked BEFORE they execute.

    Does not require embeddings - pure structural analysis
    on tool names and call sequences. Works with or without
    the embedding service available.

    Attributes:
        None beyond BaseDetector attributes.
        All state lives in DetectionContext per session.
    """

    def __init__(
        self,
        config: AgentShieldConfig,
        embedding_service: EmbeddingService,
    ) -> None:
        """Initialize the ToolChainDetector.

        Args:
            config: AgentShieldConfig with detection settings.
            embedding_service: Shared embedding service.
                Not used by this detector but required
                by BaseDetector interface.
        """
        super().__init__(config, embedding_service)
        logger.debug("ToolChainDetector initialized")

    @property
    def detector_name(self) -> str:
        """Return human-readable detector name."""
        return "ToolChainDetector"

    @property
    def supported_event_types(self) -> list[EventType]:
        """Return event types this detector analyzes.

        Hooks into TOOL_CALL_START so dangerous calls can
        be blocked before execution.
        """
        return [EventType.TOOL_CALL_START]

    def analyze(
        self,
        event: BaseEvent,
        context: DetectionContext,
    ) -> ThreatEvent | None:
        """Analyze a tool call start event for chain escalation.

        Builds the candidate sequence (history + current tool)
        and checks it against both detection layers.

        Returns the highest-confidence threat found, or None
        if both layers find no threat.

        Args:
            event: The TOOL_CALL_START event to analyze.
            context: Current session detection context with
                tool_call_history populated.

        Returns:
            ThreatEvent if escalation detected, None if clean.
        """
        if event.event_type != EventType.TOOL_CALL_START:
            return None

        if not isinstance(event, ToolCallEvent):
            return None

        history_names = [
            tool_call.tool_name.lower() for tool_call in context.tool_call_history
        ]
        current_name = event.tool_name.lower()
        candidate_sequence = history_names + [current_name]

        forbidden_result = self._check_forbidden_sequences(
            candidate_sequence=candidate_sequence,
            source_event=event,
            context=context,
        )
        if forbidden_result is not None:
            return forbidden_result

        return self._heuristic_escalation_score(
            candidate_sequence=candidate_sequence,
            source_event=event,
            context=context,
        )

    def _check_forbidden_sequences(
        self,
        candidate_sequence: list[str],
        source_event: ToolCallEvent,
        context: DetectionContext,
    ) -> ThreatEvent | None:
        """Check if recent tool calls match any forbidden sequence.

        Uses suffix matching: checks if the last N tool calls
        in candidate_sequence match the last N patterns in any
        FORBIDDEN_SEQUENCES entry.

        Pattern matching is substring-based and
        case-insensitive for flexibility across different
        tool naming conventions.

        Args:
            candidate_sequence: Tool names including current.
            source_event: The triggering TOOL_CALL_START event.
            context: Session detection context.

        Returns:
            ThreatEvent with confidence 0.95 if match found.
            None if no forbidden sequence matched.
        """
        for pattern in FORBIDDEN_SEQUENCES:
            if self._matches_suffix(sequence=candidate_sequence, pattern=pattern):
                matched_sequence = candidate_sequence[-len(pattern) :]

                explanation = (
                    "Tool chain escalation detected. "
                    f"Sequence {' -> '.join(matched_sequence)} "
                    f"matches forbidden pattern {' -> '.join(pattern)}."
                )

                evidence: dict[str, object] = {
                    "matched_pattern": list(pattern),
                    "actual_sequence": matched_sequence,
                    "full_history": candidate_sequence[-10:],
                    "current_tool": source_event.tool_name,
                    "detection_layer": "forbidden_sequence",
                }

                logger.warning(
                    "Forbidden tool sequence detected | "
                    "pattern={} sequence={} session={}",
                    pattern,
                    matched_sequence,
                    str(context.session_id)[:8],
                )

                return self._build_threat(
                    source_event=source_event,
                    threat_type=ThreatType.TOOL_CHAIN_ESCALATION,
                    confidence=0.95,
                    explanation=explanation,
                    evidence=evidence,
                    action=RecommendedAction.BLOCK,
                    severity=SeverityLevel.HIGH,
                )

        return None

    def _matches_suffix(
        self,
        sequence: list[str],
        pattern: tuple[str, ...],
    ) -> bool:
        """Check if the end of a sequence matches a pattern.

        Each pattern element is matched as a substring of
        the corresponding tool name (case-insensitive).
        The sequence must be at least as long as the pattern.

        Args:
            sequence: List of tool names (lowercased).
            pattern: Tuple of tool name substrings to match.

        Returns:
            True if the sequence suffix matches the pattern.

        Example:
            sequence = ["search", "read_file", "send_email"]
            pattern  = ("read_file", "send_email")
            -> True (last 2 elements match)

            sequence = ["read_file", "search"]
            pattern  = ("read_file", "send_email")
            -> False (send_email not in last position)
        """
        if len(sequence) < len(pattern):
            return False

        suffix = sequence[-len(pattern) :]
        for tool_name, pattern_element in zip(suffix, pattern, strict=True):
            if pattern_element not in tool_name:
                return False
        return True

    def _heuristic_escalation_score(
        self,
        candidate_sequence: list[str],
        source_event: ToolCallEvent,
        context: DetectionContext,
    ) -> ThreatEvent | None:
        """Score the tool call sequence using category heuristics.

        Detects escalation patterns not covered by exact
        forbidden sequence matching. Scores based on:

          READ -> SEND transition:    +config threshold
          EXECUTE -> SEND transition: +config threshold
          High call velocity (>N):    +config bonus
          Repeated tool (>N times):   +config bonus

        Threshold: returns threat only if score is above the configured
        anomaly threshold.

        Args:
            candidate_sequence: Tool names including current.
            source_event: The triggering TOOL_CALL_START event.
            context: Session detection context.

        Returns:
            ThreatEvent if heuristic score >= 0.40.
            None if score too low.
        """
        score = 0.0
        signals: list[str] = []

        current = candidate_sequence[-1] if candidate_sequence else ""
        previous = candidate_sequence[-2] if len(candidate_sequence) >= 2 else ""

        current_is_send = self._is_category(current, SEND_PATTERNS)
        previous_is_read = self._is_category(previous, READ_PATTERNS)
        previous_is_execute = self._is_category(previous, EXECUTE_PATTERNS)

        if current_is_send and previous_is_read:
            score += self._config.tool_chain_read_send_transition_score
            signals.append("read_then_send_transition")

        if current_is_send and previous_is_execute:
            score += self._config.tool_chain_execute_send_transition_score
            signals.append("execute_then_send_transition")

        total_calls = len(candidate_sequence)
        if total_calls > self._config.tool_chain_high_call_velocity_threshold:
            score += self._config.tool_chain_high_call_velocity_bonus
            signals.append(f"high_call_velocity_{total_calls}_calls")

        current_count = candidate_sequence.count(current)
        if current_count > self._config.tool_chain_repeated_tool_threshold:
            score += self._config.tool_chain_repeated_tool_bonus
            signals.append(f"repeated_tool_{current}_{current_count}_times")

        if score < self._config.tool_chain_anomaly_score_threshold:
            return None

        action = self._confidence_to_action(
            confidence=score,
            block_threshold=self._config.tool_chain_block_threshold,
            alert_threshold=self._config.tool_chain_alert_threshold,
            flag_threshold=self._config.tool_chain_flag_threshold,
        )
        severity = self._confidence_to_severity(score)

        explanation = (
            "Heuristic tool chain escalation detected. "
            f"Signals: {', '.join(signals)}. "
            f"Current tool: {source_event.tool_name}."
        )

        evidence: dict[str, object] = {
            "heuristic_score": round(score, 4),
            "signals": signals,
            "current_tool": source_event.tool_name,
            "previous_tool": previous,
            "total_calls": total_calls,
            "recent_sequence": candidate_sequence[-5:],
            "detection_layer": "heuristic",
        }

        logger.warning(
            "Heuristic escalation detected | " "score={:.3f} signals={} session={}",
            score,
            signals,
            str(context.session_id)[:8],
        )

        return self._build_threat(
            source_event=source_event,
            threat_type=ThreatType.TOOL_CHAIN_ESCALATION,
            confidence=min(score, 1.0),
            explanation=explanation,
            evidence=evidence,
            action=action,
            severity=severity,
        )

    def _is_category(
        self,
        tool_name: str,
        patterns: list[str],
    ) -> bool:
        """Check if a tool name matches any pattern in a category.

        Substring matching: any pattern that appears anywhere
        in the tool name counts as a match.

        Args:
            tool_name: Lowercased tool name to classify.
            patterns: List of pattern strings to check against.

        Returns:
            True if any pattern is a substring of tool_name.
        """
        return any(pattern in tool_name for pattern in patterns)
