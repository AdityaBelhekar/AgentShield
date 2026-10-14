"""Policy loading: valid manifests load; mistakes fail loudly and name the field."""

import os
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

import pytest

from agentshield import Label, Shield, Verdict
from agentshield.exceptions import PolicyError
from agentshield.policy import BUILTIN_POLICIES, Policy, load_policy

EXAMPLE = """\
version: 2
name: example
unlabelled_tools: ask
tools:
  read_file:  {labels: [confidential]}
  web_fetch:  {labels: [untrusted, external]}
  send_email: {labels: [external]}
  bash:       {deny: true}
flows:
  - name: no-shell-after-untrusted
    when: {session_has: [untrusted], tool: bash}
    then: deny
limits: {max_tool_calls: 20, max_identical_calls: 3}
"""


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(dedent(text), encoding="utf-8")
    return path


def rejected(tmp_path: Path, text: str) -> str:
    with pytest.raises(PolicyError) as info:
        load_policy(write(tmp_path, text))
    return str(info.value)


# --- valid policies -------------------------------------------------------------------


def test_builtins_load() -> None:
    strict = load_policy("strict")
    assert strict.mode == "enforce"
    assert strict.unlabelled_tools is Verdict.DENY
    (trifecta,) = strict.flows
    assert trifecta.when.session_has == {Label.UNTRUSTED, Label.CONFIDENTIAL}
    assert trifecta.when.tool_has == {Label.EXTERNAL}
    assert trifecta.verdict is Verdict.ASK

    monitor = load_policy("monitor")
    assert monitor.mode == "monitor"
    assert monitor.flows == strict.flows
    assert set(BUILTIN_POLICIES) == {"strict", "monitor"}


def test_yaml_file_loads(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, EXAMPLE))
    assert policy.name == "example"
    assert policy.unlabelled_tools is Verdict.ASK
    assert policy.tools["web_fetch"].labels == {Label.UNTRUSTED, Label.EXTERNAL}
    assert policy.tools["bash"].deny
    assert not policy.tools["read_file"].deny
    assert policy.flows[0].verdict is Verdict.DENY
    assert (policy.limits.max_tool_calls, policy.limits.max_identical_calls) == (20, 3)


def test_mapping_loads_and_shield_uses_it() -> None:
    shield = Shield.from_policy({"version": 2, "tools": {"calc": {}}})
    assert shield.policy.tools["calc"].labels == frozenset()
    assert shield.policy.unlabelled_tools is Verdict.DENY  # secure default


def test_default_shield_is_strict() -> None:
    assert Shield().policy == load_policy("strict")


def test_tool_names_are_exact(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, EXAMPLE))
    assert "bash" in policy.tools
    assert "Bash" not in policy.tools
    assert "bash_v2" not in policy.tools


def test_extends_merges_with_a_builtin(tmp_path: Path) -> None:
    policy = load_policy(
        write(
            tmp_path,
            """\
            extends: strict
            tools:
              web_fetch: {labels: [untrusted, external]}
            flows:
              - name: extra
                when: {tool_has: [external]}
                then: ask
            limits: {max_tool_calls: 500}
            """,
        )
    )
    assert policy.mode == "enforce"
    assert policy.unlabelled_tools is Verdict.DENY
    assert [f.name for f in policy.flows] == ["untrusted-and-confidential-to-external", "extra"]
    assert policy.limits.max_tool_calls == 500  # overridden
    assert policy.limits.max_identical_calls == 5  # inherited
    assert policy.name is None  # the built-in's name is not inherited


def test_policy_is_immutable() -> None:
    policy = load_policy("strict")
    with pytest.raises(ValueError):
        policy.mode = "monitor"  # type: ignore[misc]


# --- digest ---------------------------------------------------------------------------


def test_digest_ignores_formatting_and_order(tmp_path: Path) -> None:
    a = load_policy(write(tmp_path, EXAMPLE))
    reordered = load_policy(
        {
            "limits": {"max_identical_calls": 3, "max_tool_calls": 20},
            "tools": {
                "bash": {"deny": True},
                "send_email": {"labels": ["external"]},
                "web_fetch": {"labels": ["external", "untrusted"]},
                "read_file": {"labels": ["confidential"]},
            },
            "flows": [
                {
                    "then": "deny",
                    "when": {"tool": "bash", "session_has": ["untrusted"]},
                    "name": "no-shell-after-untrusted",
                }
            ],
            "unlabelled_tools": "ask",
            "name": "example",
            "version": 2,
        }
    )
    assert a.digest == reordered.digest
    assert len(a.digest) == 64


def test_digest_changes_with_content(tmp_path: Path) -> None:
    a = load_policy(write(tmp_path, EXAMPLE))
    b = load_policy(write(tmp_path, EXAMPLE.replace("[confidential]", "[untrusted]")))
    assert a.digest != b.digest


def test_digest_is_stable_across_processes() -> None:
    code = "from agentshield.policy import load_policy; print(load_policy('strict').digest)"
    digests = {
        subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
        ).stdout.strip()
        for seed in ("1", "2", "3")
    }
    assert digests == {load_policy("strict").digest}


# --- rejections name the bad field -----------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param(
            "version: 2\ntools:\n  read_file: {lables: [confidential]}\n",
            ["tools.read_file.lables", "Extra inputs are not permitted"],
            id="typo-in-tool-key",
        ),
        pytest.param(
            "version: 2\nflow: []\n",
            ["flow:", "Extra inputs are not permitted"],
            id="typo-in-top-level-key",
        ),
        pytest.param(
            "version: 2\ntools:\n  read_file: {labels: [secret]}\n",
            ["tools.read_file.labels.0", "'secret'"],
            id="unknown-label",
        ),
        pytest.param(
            "version: 2\nflows:\n  - {name: f, when: {tool_has: [external]}, then: block}\n",
            ["flows.0.then", "'deny' or 'ask'", "'block'"],
            id="unknown-action",
        ),
        pytest.param(
            "version: 2\nflows:\n  - {name: f, when: {tool_has: [external]}, then: allow}\n",
            ["flows.0.then", "'allow'"],
            id="allow-is-not-a-flow-action",
        ),
        pytest.param(
            "version: 2\nunlabelled_tools: block\n",
            ["unlabelled_tools", "'block'"],
            id="unknown-default",
        ),
        pytest.param(
            "version: 2\nmode: audit\n",
            ["mode", "'enforce' or 'monitor'"],
            id="unknown-mode",
        ),
        pytest.param(
            "version: 2\nflows:\n  - {name: f, when: {}, then: deny}\n",
            ["flows.0.when", "at least one of"],
            id="empty-condition",
        ),
        pytest.param(
            "version: 2\ntools: {bash: {}}\nflows:\n  - {name: f, when: {tool: bsh}, then: deny}\n",
            ["flows.0.when.tool", "'bsh' is not declared"],
            id="flow-names-undeclared-tool",
        ),
        pytest.param(
            "version: 2\nflows:\n"
            "  - {name: f, when: {tool_has: [external]}, then: ask}\n"
            "  - {name: f, when: {tool_has: [external]}, then: deny}\n",
            ["duplicate flow names ['f']"],
            id="duplicate-flow-name",
        ),
        pytest.param(
            "version: 2\nlimits: {max_tool_calls: 0}\n",
            ["limits.max_tool_calls", "greater than 0"],
            id="non-positive-limit",
        ),
        pytest.param(
            "version: '1.0'\nrules: []\n",
            ["version: Input should be 2", "rules"],
            id="v1-policy",
        ),
        pytest.param("tools: {}\n", ["version: Field required"], id="missing-version"),
        pytest.param(
            "extends: strcit\n",
            ["extends", "'strcit'", "strict, monitor"],
            id="unknown-extends",
        ),
        pytest.param(
            "version: 2\ntools:\n  bash: {deny: true}\n  bash: {}\n",
            ["duplicate key 'bash' at line 4"],
            id="duplicate-yaml-key",
        ),
        pytest.param("- just\n- a list\n", ["top level must be a mapping"], id="not-a-mapping"),
        pytest.param("version: [2\n", ["invalid policy"], id="broken-yaml"),
    ],
)
def test_bad_policies_are_rejected_with_the_field_named(
    tmp_path: Path, text: str, expected: list[str]
) -> None:
    message = rejected(tmp_path, text)
    for fragment in expected:
        assert fragment in message, message


def test_unknown_source_names_the_builtins() -> None:
    with pytest.raises(PolicyError, match="neither a built-in policy \\(strict, monitor\\)"):
        load_policy("stirct")


def test_errors_carry_the_file_path(tmp_path: Path) -> None:
    path = write(tmp_path, "version: 2\nmode: audit\n")
    with pytest.raises(PolicyError, match="policy.yaml"):
        load_policy(path)


def test_policy_type_is_exported() -> None:
    assert isinstance(load_policy("strict"), Policy)
