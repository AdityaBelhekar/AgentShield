"""The audit log must survive restarts, resist deletion, and verify at scale.

Regression for C8: the 0.1.x chain was unkeyed, so deleting a row and recomputing the
hashes passed verification.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from agentshield import (  # noqa: E402
    AuditError,
    AuditLog,
    Decision,
    Session,
    Shield,
    ToolCall,
    Verdict,
)
from agentshield.audit import GENESIS, record_digest, verify_audit  # noqa: E402
from agentshield.cli import main  # noqa: E402

ALLOW = Decision(Verdict.ALLOW, "allowed by the policy")
DENY = Decision(Verdict.DENY, "denied by the policy", rule="tools.bash.deny")

MANIFEST = {
    "version": 2,
    "unlabelled_tools": "deny",
    "tools": {
        "calc": {},
        "bash": {"deny": True},
    },
}


def write_records(log: AuditLog, count: int, session: Session | None = None) -> None:
    active = session if session is not None else Session()
    for index in range(count):
        log.write(ToolCall("calc", {"n": index}), ALLOW, active, policy="test-policy")


def read_records(path: Path) -> list[dict[str, Any]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if json.loads(line)["type"] == "record"]


def test_a_fresh_log_is_valid_and_unsigned(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    write_records(log, 3)
    log.close()

    report = verify_audit(path)
    assert report.valid, report.errors
    assert report.records == 3
    assert report.signed is False
    assert report.checkpoints == 0


def test_restart_continues_the_same_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()

    first = AuditLog(path, key=key, checkpoint_every=2)
    write_records(first, 3)
    first.close()

    second = AuditLog(path, key=key)
    assert second.sequence == 3
    write_records(second, 2)
    second.close()

    report = verify_audit(path)
    assert report.valid, report.errors
    assert report.records == 5
    assert report.signed is True

    records = read_records(path)
    assert [record["seq"] for record in records] == [0, 1, 2, 3, 4]
    for previous, current in zip(records, records[1:], strict=False):
        assert current["prev"] == previous["hash"]


def test_deleting_a_record_and_rehashing_fails_the_checkpoint(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    log = AuditLog(path, key=key, checkpoint_every=10)
    write_records(log, 5)
    log.close()

    lines = path.read_text(encoding="utf-8").splitlines()
    header = lines[0]
    parsed = [json.loads(line) for line in lines[1:]]
    records = [entry for entry in parsed if entry["type"] == "record"]
    checkpoints = [entry for entry in parsed if entry["type"] == "checkpoint"]
    assert len(records) == 5 and len(checkpoints) == 1

    del records[1]
    previous = GENESIS
    for seq, record in enumerate(records):
        record["seq"] = seq
        record["prev"] = previous
        record.pop("hash")
        record["hash"] = record_digest(record)
        previous = record["hash"]

    # The attacker can even move the checkpoint to the new head; they still cannot sign it.
    checkpoints[0]["seq"] = len(records) - 1
    checkpoints[0]["hash"] = records[-1]["hash"]

    rebuilt = [header] + [json.dumps(entry) for entry in records + checkpoints]
    path.write_text("\n".join(rebuilt) + "\n", encoding="utf-8")

    report = verify_audit(path)
    assert not report.valid
    assert any("signature" in error for error in report.errors)


def test_deleting_the_tail_record_is_caught(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    log = AuditLog(path, key=key, checkpoint_every=10)
    write_records(log, 4)
    log.close()

    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join([*lines[:-2], lines[-1]]) + "\n", encoding="utf-8")

    report = verify_audit(path)
    assert not report.valid
    assert any("checkpoint does not match a record" in error for error in report.errors)


def test_verification_passes_after_50000_records(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    log = AuditLog(path, key=key, checkpoint_every=5000)
    write_records(log, 50_000)
    log.close()

    report = verify_audit(path)
    assert report.valid, report.errors[:3]
    assert report.records == 50_000
    assert report.checkpoints == 10


def test_concurrent_writes_produce_one_valid_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, key=Ed25519PrivateKey.generate(), checkpoint_every=25)
    barrier = threading.Barrier(4)
    errors: list[BaseException] = []

    def worker(worker_id: int) -> None:
        try:
            barrier.wait()
            for index in range(50):
                log.write(
                    ToolCall("calc", {"worker": worker_id, "i": index}),
                    ALLOW,
                    Session(),
                )
        except BaseException as exc:  # surfaced below; pytest can't see thread failures
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    log.close()

    assert not errors
    report = verify_audit(path)
    assert report.valid, report.errors
    assert report.records == 200
    assert [record["seq"] for record in read_records(path)] == list(range(200))


def test_resuming_a_signed_log_needs_the_same_key(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    log = AuditLog(path, key=key)
    write_records(log, 1)
    log.close()

    with pytest.raises(AuditError, match="signed"):
        AuditLog(path)
    with pytest.raises(AuditError, match="different key"):
        AuditLog(path, key=Ed25519PrivateKey.generate())


def test_an_unsigned_log_cannot_be_upgraded_in_place(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    write_records(log, 1)
    log.close()

    with pytest.raises(AuditError, match="unsigned"):
        AuditLog(path, key=Ed25519PrivateKey.generate())


def test_the_engine_audits_allowed_and_denied_decisions(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    shield = Shield.from_policy(MANIFEST, audit=AuditLog(path, key=Ed25519PrivateKey.generate()))
    with shield.session(user="u1", task="test task") as session:
        assert shield.engine.check(ToolCall("calc", {"a": 1})).allowed
        assert not shield.engine.check(ToolCall("bash", {"command": "id"})).allowed
        session_id = session.id
    shield.close()

    report = verify_audit(path)
    assert report.valid, report.errors
    records = read_records(path)
    assert [record["verdict"] for record in records] == ["allow", "deny"]
    assert {record["session"] for record in records} == {session_id}
    assert {record["user"] for record in records} == {"u1"}
    assert all(record["policy"] == shield.policy.digest for record in records)


def test_secrets_are_redacted_before_hashing(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    log = AuditLog(path, key=key)
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    log.write(
        ToolCall(
            "send_email",
            {"to": "x@example.com", "body": aws_key, "password": "hunter2"},
        ),
        ALLOW,
        Session(),
        policy="test-policy",
    )
    log.close()

    raw = path.read_text(encoding="utf-8")
    assert aws_key not in raw
    assert "hunter2" not in raw
    assert "[REDACTED" in raw
    assert verify_audit(path).valid


def test_the_cli_verifies_and_reports_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, key=Ed25519PrivateKey.generate())
    write_records(log, 2)
    log.close()

    assert main(["audit", "verify", str(path)]) == 0
    assert "valid: 2 records" in capsys.readouterr().out

    assert main(["audit", "verify", str(path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["valid"] is True
    assert payload["records"] == 2


def test_the_cli_exits_nonzero_on_a_broken_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("not json\n", encoding="utf-8")
    assert main(["audit", "verify", str(path)]) == 1
    assert "invalid" in capsys.readouterr().err


def test_keygen_writes_a_loadable_private_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from agentshield.audit import load_key

    path = tmp_path / "key.pem"
    assert main(["audit", "keygen", "--out", str(path)]) == 0
    assert path.read_text(encoding="utf-8").startswith("-----BEGIN PRIVATE KEY-----")
    assert "PRIVATE" not in capsys.readouterr().out
    log = AuditLog(tmp_path / "audit.jsonl", key=load_key(path))
    write_records(log, 1)
    log.close()
    assert verify_audit(tmp_path / "audit.jsonl").valid
