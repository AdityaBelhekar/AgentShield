"""Checks on a tool's arguments, before and after the tool runs.

Before: denied paths, denied regexes, URL hosts outside an allow-list, and credentials
leaving through a tool labelled ``external``.
After: a path matching a ``sensitive_glob`` taints the session as ``confidential``.
"""

from __future__ import annotations

import fnmatch
import os
import re
from collections.abc import Sequence
from urllib.parse import urlsplit

from agentshield.policy import ToolRule
from agentshield.secrets import find_secret
from agentshield.session import Label, ToolCall


def argument_violation(call: ToolCall, rule: ToolRule) -> str | None:
    """Return why an argument must not be used, or ``None`` if every check passes."""
    for name, arg_rule in rule.args.items():
        if name not in call.args or call.args[name] is None:
            continue
        value = str(call.args[name])

        if _matches_any_glob(value, arg_rule.deny_glob):
            return f"argument {name!r} matches a denied path pattern"
        for pattern in arg_rule.deny_regex:
            if re.search(pattern, value):
                return f"argument {name!r} matches denied pattern {pattern!r}"
        if arg_rule.allow_domains:
            host = _hostname(value)
            if host is None or not _domain_allowed(host, arg_rule.allow_domains):
                return f"argument {name!r} host {host!r} is not allow-listed"

    if Label.EXTERNAL in rule.labels:
        for name, value in call.args.items():
            secret = find_secret(value)
            if secret is not None:
                return f"argument {name!r} contains what looks like {secret}"
    return None


def sensitive_argument_touched(call: ToolCall, rule: ToolRule) -> bool:
    """Whether the call read a path a manifest marked sensitive."""
    return any(
        name in call.args
        and call.args[name] is not None
        and _matches_any_glob(str(call.args[name]), arg_rule.sensitive_glob)
        for name, arg_rule in rule.args.items()
    )


def _matches_any_glob(value: str, patterns: Sequence[str]) -> bool:
    if not patterns:
        return False
    candidates = _normalise(value)
    normalised_patterns = _patterns(patterns)
    return any(
        fnmatch.fnmatch(candidate, pattern)
        for candidate in candidates
        for pattern in normalised_patterns
    )


def _normalise(value: str) -> set[str]:
    """The value as given and with ``~`` expanded and separators normalised."""
    raw = value.strip().replace("\\", "/")
    expanded = os.path.normpath(os.path.expanduser(value.strip())).replace("\\", "/")
    return {raw, expanded}


def _patterns(patterns: Sequence[str]) -> set[str]:
    normalised: set[str] = set()
    for pattern in patterns:
        raw = pattern.strip().replace("\\", "/")
        expanded = os.path.normpath(os.path.expanduser(pattern.strip())).replace("\\", "/")
        for variant in (raw, expanded):
            normalised.add(variant)
            if variant.startswith("**/"):
                # A leading **/ should also match a path with no directory component.
                normalised.add(variant[3:])
    return normalised


def _hostname(value: str) -> str | None:
    try:
        host = urlsplit(value.strip()).hostname
    except ValueError:
        return None
    return host.lower() if host else None


def _domain_allowed(host: str, allowed: Sequence[str]) -> bool:
    return any(host == domain or host.endswith("." + domain) for domain in allowed)
