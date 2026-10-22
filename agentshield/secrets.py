"""Recognising credential-shaped values in outbound tool arguments.

The scanner returns a description, never the matched value: the value must not end up in
a log line, an audit record or an exception message. These are heuristics for obvious
credential formats, not a general DLP engine.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("Stripe key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b")),
    ("OpenAI API key", re.compile(r"\bsk-(?!ant-)[A-Za-z0-9_-]{20,}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
)

_MAX_DEPTH = 6


def find_secret(value: object, _depth: int = _MAX_DEPTH) -> str | None:
    """Return a description of the first credential-shaped value, or ``None``."""
    if _depth <= 0:
        return None
    if isinstance(value, str):
        for description, pattern in _PATTERNS:
            if pattern.search(value):
                return description
        return None
    if isinstance(value, Mapping):
        for item in value.values():
            found = find_secret(item, _depth - 1)
            if found is not None:
                return found
        return None
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            found = find_secret(item, _depth - 1)
            if found is not None:
                return found
    return None
