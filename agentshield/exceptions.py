"""Exceptions raised by AgentShield."""


class AgentShieldError(Exception):
    """Base class for every exception AgentShield raises."""


class PolicyError(AgentShieldError, ValueError):
    """A policy could not be loaded: unknown source, bad YAML, or invalid content."""


class PolicyViolationError(AgentShieldError):
    """A tool call was denied by the active policy."""


class ApprovalRequired(PolicyViolationError):  # noqa: N818 - name fixed by the V2 plan
    """A tool call needs human approval, and none was granted."""


class CanaryLeakError(PolicyViolationError):
    """The session's canary marker appeared in text that was leaving the system."""


class AuditError(AgentShieldError):
    """The audit log could not be opened, resumed or extended safely."""
