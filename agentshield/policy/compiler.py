from __future__ import annotations

from pathlib import Path
from typing import Any

from loguru import logger

from agentshield.config import AgentShieldConfig
from agentshield.exceptions import ConfigurationError
from agentshield.policy.models import (
    BUILTIN_POLICIES,
    PolicyAction,
    PolicyConfig,
    PolicyRule,
)


class CompiledPolicy:
    """An executable policy compiled from a PolicyConfig.

    Wraps a PolicyConfig and provides fast lookup methods for policy
    evaluation in Phase 5B.

    Attributes:
        _config: Source policy configuration.
        _enabled_rules: Pre-filtered list of enabled rules.
        _denied_tool_set: Lowercased denied tool names.
        _allowed_tool_set: Lowercased allowed tool names.
    """

    def __init__(self, policy_config: PolicyConfig) -> None:
        """Compile a PolicyConfig into an executable policy.

        Args:
            policy_config: Validated policy configuration.
        """

        self._config = policy_config
        self._enabled_rules = policy_config.get_enabled_rules()
        self._denied_tool_set = {tool.lower() for tool in policy_config.denied_tools}
        self._allowed_tool_set = {tool.lower() for tool in policy_config.allowed_tools}

        logger.info(
            "Policy compiled | name={} rules={} denied_tools={} allowed_tools={}",
            policy_config.name,
            len(self._enabled_rules),
            len(self._denied_tool_set),
            len(self._allowed_tool_set),
        )

    @property
    def name(self) -> str:
        """Return the policy name."""

        return self._config.name

    @property
    def config(self) -> PolicyConfig:
        """Return the source PolicyConfig."""

        return self._config

    @property
    def enabled_rules(self) -> list[PolicyRule]:
        """Return pre-filtered enabled rules."""

        return self._enabled_rules

    @property
    def default_action(self) -> PolicyAction:
        """Return default action when no rule matches."""

        return self._config.default_action

    def is_tool_denied(self, tool_name: str) -> bool:
        """Check if a tool is explicitly denied by this policy.

        Args:
            tool_name: Tool name to check.

        Returns:
            True if the tool is denied.
        """

        return tool_name.lower() in self._denied_tool_set

    def is_tool_allowed(self, tool_name: str) -> bool:
        """Check if a tool is allowed by this policy.

        Args:
            tool_name: Tool name to check.

        Returns:
            True if the tool is allowed.
        """

        return self._config.is_tool_allowed(tool_name)

    def to_snapshot(self) -> dict[str, Any]:
        """Serialize policy to dictionary for session snapshots.

        Returns:
            JSON-serializable policy snapshot.
        """

        return {
            "name": self._config.name,
            "version": self._config.version,
            "rules_count": len(self._enabled_rules),
            "default_action": self._config.default_action.value,
            "denied_tools": list(self._denied_tool_set),
            "allowed_tools": list(self._allowed_tool_set),
        }


class PolicyCompiler:
    """Load, validate, and compile AgentShield policies.

    Supports built-in policy names, YAML files, and PolicyConfig instances.
    """

    def __init__(self, config: AgentShieldConfig) -> None:
        """Initialize the policy compiler.

        Args:
            config: AgentShield runtime configuration.
        """

        self._config = config
        logger.debug("PolicyCompiler initialized")

    def compile(self, policy: str | PolicyConfig | None) -> CompiledPolicy:
        """Compile a policy from any supported source.

        Args:
            policy: None, built-in policy name, YAML path, or PolicyConfig.

        Returns:
            Compiled policy ready for evaluation.

        Raises:
            ConfigurationError: If the policy input is invalid.
        """

        if policy is None:
            logger.info("No policy specified - using monitor_only")
            return self._compile_config(BUILTIN_POLICIES["monitor_only"])

        if isinstance(policy, PolicyConfig):
            return self._compile_config(policy)

        if isinstance(policy, str):
            if policy in BUILTIN_POLICIES:
                return self._compile_builtin(policy)

            path = Path(policy)
            if path.exists() and path.suffix in (".yaml", ".yml"):
                return self._compile_from_yaml(path)

            if path.suffix in (".yaml", ".yml"):
                raise ConfigurationError(f"Policy YAML file not found: {policy}")

            raise ConfigurationError(
                f"Unknown policy: {policy!r}. Valid built-in policies: "
                f"{list(BUILTIN_POLICIES.keys())}. Or provide a path to a .yaml file."
            )

        raise ConfigurationError(
            f"Invalid policy type: {type(policy).__name__}. " "Expected str, PolicyConfig, or None."
        )

    def load_builtin(self, name: str) -> PolicyConfig:
        """Load a built-in policy by name.

        Args:
            name: Built-in policy name.

        Returns:
            Matching PolicyConfig.

        Raises:
            ConfigurationError: If the policy name is unknown.
        """

        if name not in BUILTIN_POLICIES:
            raise ConfigurationError(
                f"Unknown built-in policy: {name!r}. " f"Available: {list(BUILTIN_POLICIES.keys())}"
            )
        return BUILTIN_POLICIES[name]

    def load_from_yaml(self, path: str | Path) -> PolicyConfig:
        """Load a PolicyConfig from a YAML file.

        Args:
            path: Path to the YAML policy file.

        Returns:
            Validated policy configuration.

        Raises:
            ConfigurationError: If file parsing or schema validation fails.
        """

        file_path = Path(path)
        if not file_path.exists():
            raise ConfigurationError(f"Policy file not found: {path}")

        try:
            import yaml
        except ImportError as exc:
            raise ConfigurationError(
                "PyYAML is required to load policy YAML files. " "Install with: pip install pyyaml"
            ) from exc

        try:
            with file_path.open("r", encoding="utf-8") as file:
                raw = yaml.safe_load(file)
        except OSError as exc:
            raise ConfigurationError(f"Failed to read policy YAML: {path} - {exc}") from exc
        except yaml.YAMLError as exc:
            raise ConfigurationError(f"Failed to parse policy YAML: {path} - {exc}") from exc

        if not isinstance(raw, dict):
            raise ConfigurationError(
                f"Policy YAML must be a mapping, got {type(raw).__name__}: {path}"
            )

        try:
            policy_config = PolicyConfig.model_validate(raw)
        except ValueError as exc:
            raise ConfigurationError(f"Policy YAML validation failed: {path} - {exc}") from exc

        logger.info(
            "Policy loaded from YAML | path={} name={} rules={}",
            path,
            policy_config.name,
            len(policy_config.rules),
        )
        return policy_config

    def _compile_builtin(self, name: str) -> CompiledPolicy:
        """Load and compile a built-in policy.

        Args:
            name: Built-in policy name.

        Returns:
            Compiled built-in policy.
        """

        policy_config = self.load_builtin(name)
        logger.info("Built-in policy loaded | name={}", name)
        return self._compile_config(policy_config)

    def _compile_from_yaml(self, path: Path) -> CompiledPolicy:
        """Load and compile a policy from a YAML file.

        Args:
            path: Path to YAML file.

        Returns:
            Compiled policy loaded from YAML.
        """

        policy_config = self.load_from_yaml(path)
        return self._compile_config(policy_config)

    def _compile_config(self, policy_config: PolicyConfig) -> CompiledPolicy:
        """Compile a PolicyConfig into a CompiledPolicy.

        Args:
            policy_config: Validated PolicyConfig.

        Returns:
            Compiled policy instance.
        """

        return CompiledPolicy(policy_config)
