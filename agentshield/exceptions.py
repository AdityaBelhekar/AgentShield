"""Exceptions raised by AgentShield."""


class AgentShieldError(Exception):
    """Base class for every exception AgentShield raises."""


class PolicyError(AgentShieldError, ValueError):
    """A policy could not be loaded: unknown source, bad YAML, or invalid content."""
