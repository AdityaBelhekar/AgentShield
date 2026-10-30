"""Append-only, hash-chained, optionally signed audit log.

One JSON object per line. The first line is a header (format version, algorithm, public
key, checkpoint interval). Each ``record`` covers every one of its own fields plus the
previous record's hash, so changing or reordering a record breaks the chain. A
``checkpoint`` every N records signs the current head with Ed25519, which is what makes a
deleted-and-rehashed chain detectable: the attacker can recompute hashes but cannot forge
a signature without the private key.

The private key never goes in the file. Verification needs only the public key from the
header, so ``agentshield audit verify <file>`` works anywhere::

    from agentshield.audit import AuditLog, generate_key

    audit = AuditLog("audit.jsonl", key=generate_key())
    shield = Shield.from_policy("policy.yaml", audit=audit)
    ...
    audit.close()

Honest limitations. Records after the last checkpoint are chained but not yet signed, so
they can be cut off the end without breaking verification; ``close()`` signs a final
checkpoint, ``verify_audit`` reports the unsigned tail, and a smaller ``checkpoint_every``
shortens it. The header carries the public key, so someone who can rewrite the whole
file can replace both key and signatures. Anchor the header's public key somewhere outside
the file if that threat matters; external anchoring is deliberately out of scope for V2.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

from agentshield.exceptions import AuditError
from agentshield.secrets import redact
from agentshield.session import Decision, Session, ToolCall

FORMAT_VERSION = 1
GENESIS = "0" * 64
_SIGNING_PREFIX = "agentshield-audit-v1"


# --- signing ----------------------------------------------------------------------------
# cryptography is imported inside these helpers so the core stays dependency-light.


def generate_key() -> Any:
    """Return a fresh Ed25519 private key. Needs the ``[audit]`` extra."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise ImportError(
            'signed audit logs need the audit extra: pip install "agentshield-x[audit]"'
        ) from exc
    return Ed25519PrivateKey.generate()


def load_key(path: str | Path) -> Any:
    """Load an unencrypted PKCS#8 Ed25519 private key from a PEM file."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise ImportError(
            'signed audit logs need the audit extra: pip install "agentshield-x[audit]"'
        ) from exc
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise AuditError(f"{str(path)!r} is not an Ed25519 private key")
    return key


def _public_key_b64(key: Any) -> str:
    from cryptography.hazmat.primitives import serialization

    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def _sign(key: Any, message: bytes) -> str:
    return base64.b64encode(key.sign(message)).decode("ascii")


def _verify(public_key_b64: str, signature: str, message: bytes) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    public = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
    try:
        public.verify(base64.b64decode(signature), message)
    except (InvalidSignature, ValueError) as exc:
        raise AuditError("checkpoint signature does not verify") from exc


# --- hashing ----------------------------------------------------------------------------


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    ).encode()


def record_digest(record: Mapping[str, Any]) -> str:
    """SHA-256 over every field of ``record`` except ``hash`` itself."""
    payload = {key: value for key, value in record.items() if key != "hash"}
    return hashlib.sha256(_canonical(payload)).hexdigest()


def checkpoint_message(seq: int, digest: str) -> bytes:
    return f"{_SIGNING_PREFIX}:{seq}:{digest}".encode()


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def _line(record: Mapping[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


# --- the log ----------------------------------------------------------------------------


class AuditLog:
    """One append-only file, resumed from its tail when reopened."""

    def __init__(
        self,
        path: str | Path,
        *,
        key: Any | None = None,
        checkpoint_every: int = 1000,
    ) -> None:
        if checkpoint_every < 1:
            raise AuditError("checkpoint_every must be at least 1")
        self.path = Path(path)
        self._key = key
        self._fh: TextIO | None = None
        self._sequence = 0
        self._last_hash = GENESIS
        self._since_checkpoint = 0
        self._signed = key is not None
        self._checkpoint_every = checkpoint_every
        self._lock = threading.RLock()
        self._load()
        self._fh = self.path.open("a", encoding="utf-8", newline="\n")

    @property
    def signed(self) -> bool:
        return self._signed

    @property
    def sequence(self) -> int:
        """The sequence number the next record will receive."""
        return self._sequence

    def write(
        self,
        call: ToolCall,
        decision: Decision,
        session: Session | None = None,
        *,
        policy: str | None = None,
    ) -> None:
        """Append one decision. Redaction happens before the record is hashed."""
        with self._lock:
            if self._fh is None:
                raise AuditError("the audit log is closed")
            record: dict[str, Any] = {
                "type": "record",
                "seq": self._sequence,
                "ts": _now(),
                "session": session.id if session is not None else None,
                "user": redact(session.user) if session is not None else None,
                "task": redact(session.task) if session is not None else None,
                "policy": policy,
                "tool": redact(call.name),
                "args": redact(dict(call.args)),
                "verdict": decision.verdict.value,
                "rule": decision.rule,
                "reason": redact(decision.reason),
                "prev": self._last_hash,
            }
            record["hash"] = record_digest(record)
            self._append(record)
            self._sequence += 1
            self._last_hash = str(record["hash"])
            self._since_checkpoint += 1
            if self._signed and self._since_checkpoint >= self._checkpoint_every:
                self._checkpoint()

    def close(self) -> None:
        """Sign a final checkpoint and close the file. Safe to call twice."""
        with self._lock:
            if self._fh is None:
                return
            try:
                if self._signed and self._since_checkpoint > 0:
                    self._checkpoint()
            finally:
                self._fh.close()
                self._fh = None

    def __enter__(self) -> AuditLog:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _append(self, record: Mapping[str, Any]) -> None:
        assert self._fh is not None
        self._fh.write(_line(record) + "\n")
        self._fh.flush()

    def _checkpoint(self) -> None:
        assert self._key is not None
        seq = self._sequence - 1
        digest = self._last_hash
        self._append(
            {
                "type": "checkpoint",
                "seq": seq,
                "hash": digest,
                "ts": _now(),
                "signature": _sign(self._key, checkpoint_message(seq, digest)),
            }
        )
        self._since_checkpoint = 0

    def _load(self) -> None:
        if not self.path.exists() or self.path.stat().st_size == 0:
            self._write_header()
            return

        text = self.path.read_text(encoding="utf-8")
        if text and not text.endswith("\n"):
            # A crash left a partial final line. Drop it before appending again.
            text = text[: text.rfind("\n") + 1]
            self.path.write_text(text, encoding="utf-8", newline="\n")
        lines = text.splitlines()
        if not lines:
            self._write_header()
            return

        header = _parse_line(lines[0], 1)
        if header.get("type") != "header":
            raise AuditError(f"{self.path}: first line is not an audit header")
        if header.get("version") != FORMAT_VERSION:
            raise AuditError(f"{self.path}: unsupported format version {header.get('version')!r}")

        algorithm = header.get("algorithm")
        if algorithm == "ed25519":
            if self._key is None:
                raise AuditError(f"{self.path} is signed; pass the same key to append to it")
            if header.get("public_key") != _public_key_b64(self._key):
                raise AuditError(f"{self.path} was signed with a different key")
            self._signed = True
        elif algorithm == "none":
            if self._key is not None:
                raise AuditError(f"{self.path} is unsigned; use a new file for signed records")
            self._signed = False
        else:
            raise AuditError(f"{self.path}: unknown signing algorithm {algorithm!r}")

        interval = header.get("checkpoint_every")
        if not isinstance(interval, int) or interval < 1:
            raise AuditError(f"{self.path}: invalid checkpoint_every in the header")
        self._checkpoint_every = interval

        last_checkpoint = -1
        records = 0
        for line_no, line in enumerate(lines[1:], start=2):
            record = _parse_line(line, line_no)
            kind = record.get("type")
            if kind == "record":
                seq = record.get("seq")
                digest = record.get("hash")
                if not isinstance(seq, int) or not isinstance(digest, str):
                    raise AuditError(f"{self.path}:{line_no}: malformed record")
                records += 1
                self._sequence = seq + 1
                self._last_hash = digest
            elif kind == "checkpoint":
                last_checkpoint = line_no
            else:
                raise AuditError(f"{self.path}:{line_no}: unknown record type")

        self._since_checkpoint = 0
        if last_checkpoint < 0:
            self._since_checkpoint = records
        else:
            for line_no, line in enumerate(lines[1:], start=2):
                if line_no > last_checkpoint and (
                    _parse_line(line, line_no).get("type") == "record"
                ):
                    self._since_checkpoint += 1

        report = verify_audit(self.path)
        if not report.valid:
            raise AuditError(
                f"{self.path} is not a valid audit chain:\n  " + "\n  ".join(report.errors)
            )

    def _write_header(self) -> None:
        header: dict[str, Any] = {
            "type": "header",
            "version": FORMAT_VERSION,
            "algorithm": "ed25519" if self._key is not None else "none",
            "public_key": _public_key_b64(self._key) if self._key is not None else None,
            "checkpoint_every": self._checkpoint_every,
        }
        self.path.write_text(_line(header) + "\n", encoding="utf-8", newline="\n")


# --- verification -----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuditReport:
    """The result of verifying one audit file."""

    valid: bool
    records: int
    checkpoints: int
    signed: bool
    errors: tuple[str, ...] = ()
    unsigned_tail: int = 0
    """In a signed log, records after the last checkpoint: these could be truncated."""

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "records": self.records,
            "checkpoints": self.checkpoints,
            "signed": self.signed,
            "unsigned_tail": self.unsigned_tail,
            "errors": list(self.errors),
        }


def verify_audit(path: str | Path) -> AuditReport:
    """Recompute the chain and every checkpoint signature; never raises."""
    errors: list[str] = []
    records = 0
    checkpoints = 0
    signed = False
    hashes: dict[int, str] = {}
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return AuditReport(False, 0, 0, False, (f"cannot read {path}: {exc}",))

    if not lines:
        return AuditReport(False, 0, 0, False, ("the file is empty",))

    try:
        header = _parse_line(lines[0], 1)
    except AuditError as exc:
        return AuditReport(False, 0, 0, False, (str(exc),))
    if header.get("type") != "header":
        return AuditReport(False, 0, 0, False, ("the first line is not an audit header",))
    if header.get("version") != FORMAT_VERSION:
        return AuditReport(
            False, 0, 0, False, (f"unsupported format version {header.get('version')!r}",)
        )
    algorithm = header.get("algorithm")
    if algorithm not in {"ed25519", "none"}:
        return AuditReport(False, 0, 0, False, (f"unknown algorithm {algorithm!r}",))
    signed = algorithm == "ed25519"
    public_key = header.get("public_key")
    if signed and not isinstance(public_key, str):
        errors.append("the header has no public key")

    expected_seq = 0
    previous = GENESIS
    last_signed_seq = -1

    for line_no, line in enumerate(lines[1:], start=2):
        try:
            record = _parse_line(line, line_no)
        except AuditError as exc:
            errors.append(str(exc))
            break

        kind = record.get("type")
        if kind == "record":
            seq = record.get("seq")
            digest = record.get("hash")
            if not isinstance(seq, int):
                errors.append(f"line {line_no}: sequence number is not an integer")
            elif seq != expected_seq:
                errors.append(f"line {line_no}: expected seq {expected_seq}, got {seq}")
            if record.get("prev") != previous:
                errors.append(f"line {line_no}: previous hash does not match")

            if isinstance(digest, str):
                if record_digest(record) != digest:
                    errors.append(f"line {line_no}: hash does not match the record")
                elif isinstance(seq, int):
                    hashes[seq] = digest
                previous = digest
            else:
                errors.append(f"line {line_no}: record has no hash")
            if isinstance(seq, int):
                expected_seq = seq + 1
            records += 1
        elif kind == "checkpoint":
            checkpoints += 1
            if not signed:
                errors.append(f"line {line_no}: checkpoint in an unsigned log")
                continue
            seq = record.get("seq")
            digest = record.get("hash")
            signature = record.get("signature")
            if not isinstance(seq, int) or not isinstance(digest, str):
                errors.append(f"line {line_no}: malformed checkpoint")
                continue
            if hashes.get(seq) != digest:
                errors.append(f"line {line_no}: checkpoint does not match a record")
            if not isinstance(signature, str) or not isinstance(public_key, str):
                errors.append(f"line {line_no}: checkpoint has no signature")
                continue
            try:
                _verify(public_key, signature, checkpoint_message(seq, digest))
            except AuditError:
                errors.append(f"line {line_no}: checkpoint signature does not verify")
            else:
                last_signed_seq = max(last_signed_seq, seq)
        else:
            errors.append(f"line {line_no}: unknown record type {kind!r}")

    if signed and records and checkpoints == 0:
        errors.append("the signed log has no checkpoints")

    return AuditReport(
        valid=not errors,
        records=records,
        checkpoints=checkpoints,
        signed=signed,
        errors=tuple(errors),
        unsigned_tail=sum(1 for seq in hashes if seq > last_signed_seq) if signed else 0,
    )


def _parse_line(line: str, line_no: int) -> dict[str, Any]:
    try:
        value = json.loads(line)
    except json.JSONDecodeError as exc:
        raise AuditError(f"line {line_no}: invalid JSON: {exc.msg}") from None
    if not isinstance(value, dict):
        raise AuditError(f"line {line_no}: expected a JSON object")
    return value


__all__ = [
    "AuditLog",
    "AuditReport",
    "checkpoint_message",
    "generate_key",
    "load_key",
    "record_digest",
    "verify_audit",
]
