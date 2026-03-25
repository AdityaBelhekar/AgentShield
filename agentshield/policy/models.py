from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from agentshield.events.models import SeverityLevel


class PolicyAction(StrEnum):
    """Action to take when a policy rule matches.

    Maps to RecommendedAction but used in policy context where the developer
    explicitly configures the response.

    BLOCK: Raise PolicyViolationError, stop execution.
    ALERT: Emit ThreatEvent with HIGH severity, continue.
    FLAG: Emit ThreatEvent with MEDIUM severity, continue.
    LOG: Log the event, no ThreatEvent emitted.
    ALLOW: Explicitly allow and suppress all detection.
    """

    BLOCK = "BLOCK"
    ALERT = "ALERT"
    FLAG = "FLAG"
    LOG = "LOG"
    ALLOW = "ALLOW"


class PolicyConditionType(StrEnum):
    """Types of conditions that can trigger a policy rule.

    Used to classify what kind of check a rule performs. The evaluator in
    Phase 5B dispatches based on this type.

    TOOL_CALL: Matches specific tool names.
    TOOL_SEQUENCE: Matches tool call sequences.
    GOAL_DRIFT: Matches drift score thresholds.
    INJECTION_SCORE: Matches injection confidence scores.
    MEMORY_WRITE: Matches memory write content patterns.
    AGENT_STATE: Matches agent trust state.
    ALWAYS: Always matches (catch-all rule).
    """

    TOOL_CALL = "TOOL_CALL"
    TOOL_SEQUENCE = "TOOL_SEQUENCE"
    GOAL_DRIFT = "GOAL_DRIFT"
    INJECTION_SCORE = "INJECTION_SCORE"
    MEMORY_WRITE = "MEMORY_WRITE"
    AGENT_STATE = "AGENT_STATE"
    ALWAYS = "ALWAYS"


class PolicyCondition(BaseModel):
    """A single condition that triggers a policy rule.

    Conditions are evaluated by CompiledPolicy.evaluate() in Phase 5B. Each
    condition type has specific parameters.

    Attributes:
        type: The kind of condition to check.
        tool_names: Tool names to match for TOOL_CALL.
        sequence: Tool sequence to match for TOOL_SEQUENCE.
        threshold: Numeric threshold for GOAL_DRIFT/INJECTION_SCORE.
        patterns: Text patterns to match for MEMORY_WRITE.
        agent_states: Agent states to match for AGENT_STATE.
        negate: If True, condition matches when check fails.
    """

    type: PolicyConditionType
    tool_names: list[str] = Field(default_factory=list)
    sequence: list[str] = Field(default_factory=list)
    threshold: float | None = None
    patterns: list[str] = Field(default_factory=list)
    agent_states: list[str] = Field(default_factory=list)
    negate: bool = False


class PolicyRule(BaseModel):
    """A single named security rule in a policy.

    Each rule has an ID, description, one or more conditions, and an action to
    take when conditions match.

    Attributes:
        id: Unique rule identifier within the policy.
        description: Human-readable rule description.
        conditions: List of conditions where all must match.
        action: Action to take when the rule matches.
        severity: Severity level for generated events.
        enabled: Whether this rule is active.
        metadata: Additional rule metadata.
    """

    id: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    conditions: list[PolicyCondition] = Field(..., min_length=1)
    action: PolicyAction
    severity: SeverityLevel = SeverityLevel.MEDIUM
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("id")
    @classmethod
    def validate_id_no_spaces(cls, value: str) -> str:
        """Validate rule ID contains no spaces.

        Args:
            value: Rule ID string to validate.

        Returns:
            Validated rule ID.

        Raises:
            ValueError: If ID contains spaces.
        """

        if " " in value:
            raise ValueError(f"Rule ID must not contain spaces: {value!r}")
        return value


class PolicyConfig(BaseModel):
    """Complete policy configuration for an agent.

    A PolicyConfig is a named, versioned collection of PolicyRules. It can be
    loaded from YAML or created programmatically.

    Attributes:
        name: Human-readable policy name.
        version: Policy version string.
        description: What this policy protects against.
        agent_id: Optional agent this policy targets.
        rules: Ordered list of policy rules.
        default_action: Action when no rule matches.
        allowed_tools: Tools explicitly allowed.
        denied_tools: Tools explicitly denied.
        metadata: Additional policy metadata.
    """

    name: str = Field(..., min_length=1)
    version: str = "1.0"
    description: str = ""
    agent_id: str | None = None
    rules: list[PolicyRule] = Field(default_factory=list)
    default_action: PolicyAction = PolicyAction.LOG
    allowed_tools: list[str] = Field(default_factory=list)
    denied_tools: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def get_enabled_rules(self) -> list[PolicyRule]:
        """Return only enabled rules in order.

        Returns:
            Enabled policy rules.
        """

        return [rule for rule in self.rules if rule.enabled]

    def is_tool_allowed(self, tool_name: str) -> bool:
        """Check if a tool is explicitly allowed by this policy.

        If allowed_tools is empty, all tools are allowed unless listed in
        denied_tools.

        Args:
            tool_name: Tool name to check.

        Returns:
            True if the tool is allowed.
        """

        tool_lower = tool_name.lower()
        denied_lower = {tool.lower() for tool in self.denied_tools}

        if tool_lower in denied_lower:
            return False

        if not self.allowed_tools:
            return True

        allowed_lower = {tool.lower() for tool in self.allowed_tools}
        return tool_lower in allowed_lower

    def to_dict(self) -> dict[str, Any]:
        """Serialize policy config to a dictionary.

        Returns:
            JSON-serializable dictionary.
        """

        return self.model_dump()


def _make_no_exfiltration_policy() -> PolicyConfig:
    """Build the no_exfiltration built-in policy.

    Returns:
        PolicyConfig for no_exfiltration.
    """

    return PolicyConfig(
        name="no_exfiltration",
        version="1.0",
        description=(
            "Blocks data exfiltration via tool chains. "
            "Prevents read->send sequences and high goal drift."
        ),
        rules=[
            PolicyRule(
                id="block_read_send",
                description="Block read_file followed by send_email",
                conditions=[
                    PolicyCondition(
                        type=PolicyConditionType.TOOL_SEQUENCE,
                        sequence=["read_file", "send_email"],
                    )
                ],
                action=PolicyAction.BLOCK,
                severity=SeverityLevel.HIGH,
            ),
            PolicyRule(
                id="block_read_upload",
                description="Block read_file followed by upload",
                conditions=[
                    PolicyCondition(
                        type=PolicyConditionType.TOOL_SEQUENCE,
                        sequence=["read_file", "upload"],
                    )
                ],
                action=PolicyAction.BLOCK,
                severity=SeverityLevel.HIGH,
            ),
            PolicyRule(
                id="alert_high_drift",
                description="Alert when goal drift exceeds 0.55",
                conditions=[
                    PolicyCondition(
                        type=PolicyConditionType.GOAL_DRIFT,
                        threshold=0.55,
                    )
                ],
                action=PolicyAction.ALERT,
                severity=SeverityLevel.HIGH,
            ),
            PolicyRule(
                id="block_high_injection",
                description="Block high confidence injection attempts",
                conditions=[
                    PolicyCondition(
                        type=PolicyConditionType.INJECTION_SCORE,
                        threshold=0.80,
                    )
                ],
                action=PolicyAction.BLOCK,
                severity=SeverityLevel.CRITICAL,
            ),
        ],
        default_action=PolicyAction.LOG,
    )


def _make_strict_policy() -> PolicyConfig:
    """Build the strict built-in policy.

    Returns:
        PolicyConfig for strict.
    """

    return PolicyConfig(
        name="strict",
        version="1.0",
        description=(
            "Strict security policy. Lower thresholds, more aggressive "
            "blocking. Suitable for high-security deployments."
        ),
        rules=[
            PolicyRule(
                id="block_read_send",
                description="Block read->send sequences",
                conditions=[
                    PolicyCondition(
                        type=PolicyConditionType.TOOL_SEQUENCE,
                        sequence=["read_file", "send_email"],
                    )
                ],
                action=PolicyAction.BLOCK,
                severity=SeverityLevel.HIGH,
            ),
            PolicyRule(
                id="block_medium_drift",
                description="Block goal drift above 0.35",
                conditions=[
                    PolicyCondition(
                        type=PolicyConditionType.GOAL_DRIFT,
                        threshold=0.35,
                    )
                ],
                action=PolicyAction.BLOCK,
                severity=SeverityLevel.HIGH,
            ),
            PolicyRule(
                id="block_medium_injection",
                description="Block injection above 0.50 confidence",
                conditions=[
                    PolicyCondition(
                        type=PolicyConditionType.INJECTION_SCORE,
                        threshold=0.50,
                    )
                ],
                action=PolicyAction.BLOCK,
                severity=SeverityLevel.HIGH,
            ),
            PolicyRule(
                id="alert_memory_write",
                description="Alert on any memory write",
                conditions=[
                    PolicyCondition(
                        type=PolicyConditionType.MEMORY_WRITE,
                        patterns=[],
                    )
                ],
                action=PolicyAction.ALERT,
                severity=SeverityLevel.MEDIUM,
            ),
            PolicyRule(
                id="block_execute_tools",
                description="Block code execution tools",
                conditions=[
                    PolicyCondition(
                        type=PolicyConditionType.TOOL_CALL,
                        tool_names=[
                            "execute",
                            "bash",
                            "shell",
                            "run_code",
                            "eval",
                            "exec",
                        ],
                    )
                ],
                action=PolicyAction.BLOCK,
                severity=SeverityLevel.CRITICAL,
            ),
        ],
        denied_tools=[
            "execute_code",
            "bash",
            "shell",
            "run_command",
            "eval",
        ],
        default_action=PolicyAction.FLAG,
    )


def _make_monitor_only_policy() -> PolicyConfig:
    """Build the monitor_only built-in policy.

    Returns:
        PolicyConfig for monitor_only.
    """

    return PolicyConfig(
        name="monitor_only",
        version="1.0",
        description=(
            "Monitor-only policy. Detects all threats but never blocks. "
            "Safe for production rollout while evaluating false positive rate."
        ),
        rules=[
            PolicyRule(
                id="log_injection",
                description="Log injection detections",
                conditions=[
                    PolicyCondition(
                        type=PolicyConditionType.INJECTION_SCORE,
                        threshold=0.25,
                    )
                ],
                action=PolicyAction.LOG,
                severity=SeverityLevel.INFO,
            ),
            PolicyRule(
                id="log_drift",
                description="Log goal drift",
                conditions=[
                    PolicyCondition(
                        type=PolicyConditionType.GOAL_DRIFT,
                        threshold=0.35,
                    )
                ],
                action=PolicyAction.LOG,
                severity=SeverityLevel.INFO,
            ),
        ],
        default_action=PolicyAction.LOG,
    )


BUILTIN_POLICIES: dict[str, PolicyConfig] = {
    "no_exfiltration": _make_no_exfiltration_policy(),
    "strict": _make_strict_policy(),
    "monitor_only": _make_monitor_only_policy(),
}
