"""Policy manifest: which tools exist, what they touch, and which flows are forbidden.

A policy is YAML (or a dict) validated into immutable models. Unknown keys, labels and
actions are rejected with the path of the offending field, and duplicate YAML keys are
rejected instead of silently overwritten.

    version: 2
    extends: strict                 # optional: start from a built-in policy
    tools:
      read_file:  {labels: [confidential]}
      web_fetch:  {labels: [untrusted, external]}
      send_email: {labels: [external]}
      bash:       {deny: true}
    flows:
      - name: no-shell-after-untrusted
        when: {session_has: [untrusted], tool: bash}
        then: deny
    limits: {max_tool_calls: 50}
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Hashable, Mapping
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, PositiveInt, ValidationError, model_validator

from agentshield.exceptions import PolicyError
from agentshield.session import Label, Verdict


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ToolRule(_Model):
    """What one tool touches. Tool names are matched exactly."""

    labels: frozenset[Label] = frozenset()
    deny: bool = False


class FlowCondition(_Model):
    """All given conditions must hold for the flow to match."""

    session_has: frozenset[Label] = frozenset()
    tool_has: frozenset[Label] = frozenset()
    tool: str | None = None

    @model_validator(mode="after")
    def _not_empty(self) -> FlowCondition:
        if not (self.session_has or self.tool_has or self.tool):
            raise ValueError("needs at least one of session_has, tool_has, tool")
        return self


class Flow(_Model):
    """A forbidden or approval-gated combination of session taint and tool."""

    name: str
    when: FlowCondition
    then: Literal["deny", "ask"]

    @property
    def verdict(self) -> Verdict:
        return Verdict(self.then)


class Limits(_Model):
    """Per-session ceilings. Exceeding one denies the call."""

    max_tool_calls: PositiveInt | None = None
    max_identical_calls: PositiveInt | None = None


class Policy(_Model):
    """A validated, immutable policy."""

    version: Literal[2]
    name: str | None = None
    mode: Literal["enforce", "monitor"] = "enforce"
    unlabelled_tools: Verdict = Verdict.DENY
    tools: dict[str, ToolRule] = {}
    flows: tuple[Flow, ...] = ()
    limits: Limits = Limits()

    @model_validator(mode="after")
    def _flows_are_consistent(self) -> Policy:
        names = [flow.name for flow in self.flows]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            raise ValueError(f"flows: duplicate flow names {duplicates}")
        for i, flow in enumerate(self.flows):
            if flow.when.tool is not None and flow.when.tool not in self.tools:
                raise ValueError(
                    f"flows.{i}.when.tool: {flow.when.tool!r} is not declared under tools"
                )
        return self

    @property
    def digest(self) -> str:
        """SHA-256 of the effective policy; stable across processes and YAML formatting."""
        canonical = json.dumps(
            self.model_dump(mode="python"),
            sort_keys=True,
            separators=(",", ":"),
            default=lambda o: sorted(o) if isinstance(o, frozenset) else str(o),
        )
        return hashlib.sha256(canonical.encode()).hexdigest()


_STRICT: dict[str, Any] = {
    "version": 2,
    "name": "strict",
    "mode": "enforce",
    "unlabelled_tools": "deny",
    "flows": [
        {
            "name": "untrusted-and-confidential-to-external",
            "when": {"session_has": ["untrusted", "confidential"], "tool_has": ["external"]},
            "then": "ask",
        }
    ],
    "limits": {"max_tool_calls": 50, "max_identical_calls": 5},
}

BUILTIN_POLICIES: Mapping[str, Mapping[str, Any]] = {
    "strict": _STRICT,
    # Same rules, but decisions are recorded instead of enforced.
    "monitor": {**_STRICT, "name": "monitor", "mode": "monitor"},
}


def load_policy(source: str | Path | Mapping[str, Any]) -> Policy:
    """Load a built-in policy by name, a YAML file, or an already-parsed mapping."""
    if isinstance(source, Mapping):
        origin, data = "<mapping>", copy.deepcopy(dict(source))
    elif isinstance(source, str) and source in BUILTIN_POLICIES:
        origin, data = f"built-in {source!r}", copy.deepcopy(dict(BUILTIN_POLICIES[source]))
    else:
        path = Path(source)
        if not path.is_file():
            raise PolicyError(
                f"{str(source)!r} is neither a built-in policy "
                f"({', '.join(BUILTIN_POLICIES)}) nor an existing file"
            )
        origin = str(path)
        data = _read_yaml(path)

    data = _apply_extends(data, origin)
    try:
        return Policy.model_validate(data)
    except ValidationError as exc:
        raise PolicyError(_describe(exc, origin)) from None


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        data = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
    except (yaml.YAMLError, PolicyError) as exc:
        raise PolicyError(f"invalid policy {path}: {exc}") from None
    if not isinstance(data, dict):
        raise PolicyError(f"invalid policy {path}: top level must be a mapping")
    return data


def _apply_extends(data: dict[str, Any], origin: str) -> dict[str, Any]:
    base_name = data.pop("extends", None)
    if base_name is None:
        return data
    if not isinstance(base_name, str) or base_name not in BUILTIN_POLICIES:
        raise PolicyError(
            f"invalid policy {origin}:\n  extends: unknown built-in policy {base_name!r} "
            f"(choose from {', '.join(BUILTIN_POLICIES)})"
        )
    merged = copy.deepcopy(dict(BUILTIN_POLICIES[base_name]))
    merged.pop("name", None)
    for key, value in data.items():
        if key == "tools" and isinstance(value, dict):
            merged["tools"] = {**merged.get("tools", {}), **value}
        elif key == "flows" and isinstance(value, list):
            merged["flows"] = [*merged.get("flows", []), *value]
        elif key == "limits" and isinstance(value, dict):
            merged["limits"] = {**merged.get("limits", {}), **value}
        else:
            merged[key] = value
    return merged


def _describe(exc: ValidationError, origin: str) -> str:
    lines = [f"invalid policy {origin}:"]
    for error in exc.errors():
        where = ".".join(str(part) for part in error["loc"])
        message = error["msg"].removeprefix("Value error, ")
        if error["type"] in {"missing", "value_error"} or not where:
            lines.append(f"  {where + ': ' if where else ''}{message}")
        else:
            got = repr(error["input"])
            lines.append(f"  {where}: {message} (got {got[:60]})")
    return "\n".join(lines)


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys instead of keeping the last one."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Hashable, Any]:
        seen: set[Hashable] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                raise PolicyError(
                    f"duplicate key {key!r} at line {key_node.start_mark.line + 1}; "
                    "a later entry would silently replace the earlier one"
                )
            seen.add(key)
        return super().construct_mapping(node, deep)
