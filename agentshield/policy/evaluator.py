from __future__ import annotations

from dataclasses import dataclass, field

from loguru import logger

from agentshield.config import AgentShieldConfig
from agentshield.detection.base_detector import DetectionContext
from agentshield.events.models import (
    BaseEvent,
    EventType,
    MemoryEvent,
    ThreatEvent,
    ThreatType,
    ToolCallEvent,
)
from agentshield.policy.compiler import CompiledPolicy
from agentshield.policy.models import (
    PolicyAction,
    PolicyCondition,
    PolicyConditionType,
    PolicyRule,
)


@dataclass
class PolicyDecision:
    """Result of evaluating a policy against an event.

    Produced by PolicyEvaluator.evaluate() for every event
    that is checked against the active CompiledPolicy.

    Attributes:
        action: The resolved PolicyAction for this event.
        matched_rule: The rule that triggered, or None if
            no rule matched (default_action was used).
        reason: Human-readable explanation of the decision.
        should_block: True if action is BLOCK.
        should_suppress: True if action is ALLOW.
            Suppressed events bypass all further detection.
        threats_considered: ThreatEvents that were evaluated.
        event_type: The type of event that was evaluated.
    """

    action: PolicyAction
    matched_rule: PolicyRule | None = None
    reason: str = ""
    should_block: bool = False
    should_suppress: bool = False
    threats_considered: list[ThreatEvent] = field(default_factory=list)
    event_type: EventType | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize decision to dictionary for logging.

        Returns:
            JSON-serializable dictionary.
        """

        return {
            "action": self.action.value,
            "matched_rule": self.matched_rule.id if self.matched_rule else None,
            "reason": self.reason,
            "should_block": self.should_block,
            "should_suppress": self.should_suppress,
            "threats_count": len(self.threats_considered),
            "event_type": self.event_type.value if self.event_type else None,
        }


class PolicyEvaluator:
    """Evaluates events and detection results against a policy.

    Takes a compiled policy and evaluates incoming events
    against its rules to produce PolicyDecisions.

    Evaluation order:
      1. Denied tools check (immediate BLOCK if matched)
      2. Allowed tools check (default action if not in list)
      3. Rules evaluation (first matching rule wins)
      4. Default action (if no rule matched)

    The ALLOW action suppresses all further detection for
    the matched event. This is how developers whitelist
    legitimate behaviors that would otherwise be flagged.

    One PolicyEvaluator per CompiledPolicy.
    Stateless - all context from DetectionContext.

    Attributes:
        _config: AgentShieldConfig.
        _policy: The CompiledPolicy to evaluate against.
    """

    def __init__(
        self,
        config: AgentShieldConfig,
        policy: CompiledPolicy,
    ) -> None:
        """Initialize the PolicyEvaluator.

        Args:
            config: AgentShieldConfig instance.
            policy: CompiledPolicy to evaluate against.
        """

        self._config = config
        self._policy = policy

        logger.info(
            "PolicyEvaluator initialized | policy={} rules={}",
            policy.name,
            len(policy.enabled_rules),
        )

    def evaluate(
        self,
        event: BaseEvent,
        threats: list[ThreatEvent],
        context: DetectionContext,
    ) -> PolicyDecision:
        """Evaluate an event against the active policy.

        Checks denied tools, allowed tools, rules in order,
        then falls back to default_action.

        Args:
            event: The event to evaluate.
            threats: ThreatEvents produced by detectors.
            context: Current session detection context.

        Returns:
            PolicyDecision with resolved action and reason.
        """

        denied_decision = self._check_denied_tools(event)
        if denied_decision is not None:
            return denied_decision

        allowed_decision = self._check_allowed_tools(event)
        if allowed_decision is not None:
            return allowed_decision

        for rule in self._policy.enabled_rules:
            if self._rule_matches(
                rule=rule,
                event=event,
                threats=threats,
                context=context,
            ):
                decision = self._make_decision(
                    action=rule.action,
                    rule=rule,
                    threats=threats,
                    event=event,
                    reason=(f"Rule '{rule.id}' matched: " f"{rule.description}"),
                )

                logger.info(
                    "Policy rule matched | rule={} action={} event_type={}",
                    rule.id,
                    rule.action.value,
                    event.event_type.value,
                )

                return decision

        decision = self._make_decision(
            action=self._policy.default_action,
            rule=None,
            threats=threats,
            event=event,
            reason=(
                "No rule matched - "
                "applying default action: "
                f"{self._policy.default_action.value}"
            ),
        )

        logger.debug(
            "Policy default action | action={} event_type={}",
            self._policy.default_action.value,
            event.event_type.value,
        )

        return decision

    def _check_denied_tools(self, event: BaseEvent) -> PolicyDecision | None:
        """Check if event involves a denied tool.

        Denied tools trigger immediate BLOCK regardless
        of any other rules. This is the highest priority
        check in policy evaluation.

        Args:
            event: Event to check.

        Returns:
            PolicyDecision(BLOCK) if tool denied, else None.
        """

        if not isinstance(event, ToolCallEvent):
            return None

        if event.event_type not in (
            EventType.TOOL_CALL_START,
            EventType.TOOL_CALL_COMPLETE,
        ):
            return None

        if self._policy.is_tool_denied(event.tool_name):
            return PolicyDecision(
                action=PolicyAction.BLOCK,
                matched_rule=None,
                reason=(f"Tool '{event.tool_name}' is in " "denied_tools list"),
                should_block=True,
                should_suppress=False,
                event_type=event.event_type,
            )

        return None

    def _check_allowed_tools(self, event: BaseEvent) -> PolicyDecision | None:
        """Check if event involves a tool not in allowed list.

        If allowed_tools is non-empty and the tool is not
        in the list, apply the default_action.
        If allowed_tools is empty, skip this check.

        Args:
            event: Event to check.

        Returns:
            PolicyDecision with default_action if tool not
            allowed, None if no allowed_tools constraint.
        """

        if not isinstance(event, ToolCallEvent):
            return None

        if event.event_type not in (
            EventType.TOOL_CALL_START,
            EventType.TOOL_CALL_COMPLETE,
        ):
            return None

        if not self._policy.config.allowed_tools:
            return None

        if not self._policy.is_tool_allowed(event.tool_name):
            return self._make_decision(
                action=self._policy.default_action,
                rule=None,
                threats=[],
                event=event,
                reason=(
                    f"Tool '{event.tool_name}' not in "
                    "allowed_tools list - "
                    "applying default action"
                ),
            )

        return None

    def _rule_matches(
        self,
        rule: PolicyRule,
        event: BaseEvent,
        threats: list[ThreatEvent],
        context: DetectionContext,
    ) -> bool:
        """Check if a rule's conditions all match.

        All conditions in a rule must match (AND logic).
        Returns False as soon as any condition fails.

        Args:
            rule: The PolicyRule to evaluate.
            event: Current event.
            threats: Current session threats.
            context: Current detection context.

        Returns:
            True if all conditions match.
        """

        if not rule.conditions:
            return False

        for condition in rule.conditions:
            matches = self._condition_matches(
                condition=condition,
                event=event,
                threats=threats,
                context=context,
            )
            if condition.negate:
                matches = not matches
            if not matches:
                return False

        return True

    def _condition_matches(
        self,
        condition: PolicyCondition,
        event: BaseEvent,
        threats: list[ThreatEvent],
        context: DetectionContext,
    ) -> bool:
        """Evaluate a single policy condition.

        Dispatches to the appropriate condition handler
        based on condition.type.

        Args:
            condition: The PolicyCondition to evaluate.
            event: Current event.
            threats: Current session threats.
            context: Current detection context.

        Returns:
            True if condition matches.
        """

        ctype = condition.type

        if ctype == PolicyConditionType.ALWAYS:
            return True

        if ctype == PolicyConditionType.TOOL_CALL:
            return self._match_tool_call(condition, event)

        if ctype == PolicyConditionType.TOOL_SEQUENCE:
            return self._match_tool_sequence(condition, event, context)

        if ctype == PolicyConditionType.GOAL_DRIFT:
            return self._match_threat_score(
                condition,
                threats,
                ThreatType.GOAL_DRIFT,
            )

        if ctype == PolicyConditionType.INJECTION_SCORE:
            return self._match_threat_score(
                condition,
                threats,
                ThreatType.PROMPT_INJECTION,
            )

        if ctype == PolicyConditionType.MEMORY_WRITE:
            return self._match_memory_write(condition, event)

        if ctype == PolicyConditionType.AGENT_STATE:
            return self._match_agent_state(condition, threats)

        logger.warning("Unknown condition type: {}", ctype)
        return False

    def _match_tool_call(
        self,
        condition: PolicyCondition,
        event: BaseEvent,
    ) -> bool:
        """Match TOOL_CALL condition against event.

        Matches if event is ToolCallEvent AND tool_name
        contains any of condition.tool_names as substring.

        Args:
            condition: TOOL_CALL condition.
            event: Event to check.

        Returns:
            True if tool name matches any condition pattern.
        """

        if not isinstance(event, ToolCallEvent):
            return False

        if not condition.tool_names:
            return True

        tool_lower = event.tool_name.lower()
        return any(name.lower() in tool_lower for name in condition.tool_names)

    def _match_tool_sequence(
        self,
        condition: PolicyCondition,
        event: BaseEvent,
        context: DetectionContext,
    ) -> bool:
        """Match TOOL_SEQUENCE condition against tool history.

        Builds candidate sequence from tool history + current
        event and checks suffix match against condition.sequence.

        Args:
            condition: TOOL_SEQUENCE condition.
            event: Current event (should be ToolCallEvent).
            context: Context with tool_call_history.

        Returns:
            True if tool sequence suffix matches.
        """

        if not isinstance(event, ToolCallEvent):
            return False

        if not condition.sequence:
            return False

        history_names = [t.tool_name.lower() for t in context.tool_call_history]
        current = event.tool_name.lower()
        candidate = history_names + [current]

        pattern = condition.sequence
        if len(candidate) < len(pattern):
            return False

        suffix = candidate[-len(pattern) :]
        return all(pat.lower() in tool for tool, pat in zip(suffix, pattern, strict=True))

    def _match_threat_score(
        self,
        condition: PolicyCondition,
        threats: list[ThreatEvent],
        threat_type: ThreatType,
    ) -> bool:
        """Match GOAL_DRIFT or INJECTION_SCORE condition.

        Matches if any ThreatEvent has the matching type
        AND confidence >= condition.threshold.
        If threshold is None, matches any threat of that type.

        Args:
            condition: GOAL_DRIFT or INJECTION_SCORE condition.
            threats: Current ThreatEvents to check.
            threat_type: Which ThreatType to look for.

        Returns:
            True if matching threat above threshold exists.
        """

        matching = [t for t in threats if t.threat_type == threat_type]

        if not matching:
            return False

        if condition.threshold is None:
            return True

        return any(t.confidence >= condition.threshold for t in matching)

    def _match_memory_write(
        self,
        condition: PolicyCondition,
        event: BaseEvent,
    ) -> bool:
        """Match MEMORY_WRITE condition against event.

        Matches if event is MEMORY_WRITE AND:
          - condition.patterns is empty (match all writes)
          - OR any pattern found in content_preview

        Args:
            condition: MEMORY_WRITE condition.
            event: Event to check.

        Returns:
            True if memory write matches condition.
        """

        if not isinstance(event, MemoryEvent):
            return False

        if event.event_type != EventType.MEMORY_WRITE:
            return False

        if not condition.patterns:
            return True

        content_lower = event.content_preview.lower()
        return any(pattern.lower() in content_lower for pattern in condition.patterns)

    def _match_agent_state(
        self,
        condition: PolicyCondition,
        threats: list[ThreatEvent],
    ) -> bool:
        """Match AGENT_STATE condition against threat severities.

        Matches if any ThreatEvent has severity matching
        one of the condition.agent_states values.

        Args:
            condition: AGENT_STATE condition.
            threats: Current ThreatEvents.

        Returns:
            True if any threat severity matches.
        """

        if not threats:
            return False

        if not condition.agent_states:
            return bool(threats)

        threat_severities = {t.severity.value for t in threats}
        return bool(threat_severities & set(condition.agent_states))

    def _make_decision(
        self,
        action: PolicyAction,
        rule: PolicyRule | None,
        threats: list[ThreatEvent],
        event: BaseEvent,
        reason: str,
    ) -> PolicyDecision:
        """Build a PolicyDecision from resolved action.

        Args:
            action: Resolved PolicyAction.
            rule: Matched rule or None.
            threats: ThreatEvents considered.
            event: The evaluated event.
            reason: Human-readable decision reason.

        Returns:
            Populated PolicyDecision.
        """

        return PolicyDecision(
            action=action,
            matched_rule=rule,
            reason=reason,
            should_block=action == PolicyAction.BLOCK,
            should_suppress=action == PolicyAction.ALLOW,
            threats_considered=threats,
            event_type=event.event_type,
        )
