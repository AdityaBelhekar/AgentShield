"""The ``agentshield`` command line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path

from agentshield.audit import generate_key, verify_audit


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)

    if args.command == "audit":
        if args.audit_command == "verify":
            return _verify(args.file, as_json=args.json)
        if args.audit_command == "keygen":
            return _keygen(args.out)

    parser.error("unknown command")
    return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentshield",
        description="Verify AgentShield audit logs and create signing keys.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    audit = commands.add_parser("audit", help="work with an audit log")
    audit_commands = audit.add_subparsers(dest="audit_command", required=True)

    verify = audit_commands.add_parser("verify", help="verify a JSONL audit file")
    verify.add_argument("file", type=Path, help="path to the audit JSONL file")
    verify.add_argument("--json", action="store_true", help="print the report as JSON")

    keygen = audit_commands.add_parser("keygen", help="create an Ed25519 signing key")
    keygen.add_argument("--out", type=Path, required=True, help="path for the PEM file")
    return parser


def _verify(path: Path, *, as_json: bool) -> int:
    report = verify_audit(path)
    if as_json:
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if report.valid else 1

    if report.valid:
        kind = "signed" if report.signed else "unsigned"
        print(f"valid: {report.records} records, {report.checkpoints} checkpoints ({kind})")
        return 0

    print(f"invalid: {len(report.errors)} problem(s) in {path}", file=sys.stderr)
    for error in report.errors:
        print(f"  - {error}", file=sys.stderr)
    return 1


def _keygen(path: Path) -> int:
    from cryptography.hazmat.primitives import serialization

    key = generate_key()
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    with suppress(OSError):  # Windows may not support POSIX modes
        path.chmod(0o600)
    print(f"wrote an Ed25519 private key to {path}")
    return 0
