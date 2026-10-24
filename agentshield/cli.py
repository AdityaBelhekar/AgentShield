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
    if args.command == "bench":
        return _bench(args)

    parser.error("unknown command")
    return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentshield",
        description="Verify AgentShield audit logs, create signing keys, run benchmarks.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    audit = commands.add_parser("audit", help="work with an audit log")
    audit_commands = audit.add_subparsers(dest="audit_command", required=True)

    verify = audit_commands.add_parser("verify", help="verify a JSONL audit file")
    verify.add_argument("file", type=Path, help="path to the audit JSONL file")
    verify.add_argument("--json", action="store_true", help="print the report as JSON")

    keygen = audit_commands.add_parser("keygen", help="create an Ed25519 signing key")
    keygen.add_argument("--out", type=Path, required=True, help="path for the PEM file")

    bench = commands.add_parser(
        "bench",
        help="run the AgentDojo banking benchmark (needs the [bench] extra)",
    )
    bench.add_argument("--suite", default="banking", help="AgentDojo suite name")
    bench.add_argument("--benchmark-version", default="v1.2.2", help="AgentDojo benchmark version")
    bench.add_argument(
        "--model",
        help="a real model (for example gpt-4o-2024-08-06); omit for scripted mode",
    )
    bench.add_argument(
        "--base-url",
        help="OpenAI-compatible endpoint for --model (for example a local server)",
    )
    bench.add_argument("--api-key", help="API key for --base-url")
    bench.add_argument("--attack", default="important_instructions", help="attack name")
    bench.add_argument("--user-tasks", nargs="+", metavar="ID", help="user task ids to run")
    bench.add_argument(
        "--injection-tasks",
        nargs="+",
        metavar="ID",
        help="injection task ids to run",
    )
    bench.add_argument(
        "--approval",
        choices=["deny", "allow"],
        default="deny",
        help="what to do with ask verdicts; default deny (no human)",
    )
    output = bench.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="print the report as JSON")
    output.add_argument("--markdown", action="store_true", help="print a markdown table")
    bench.add_argument("--out", type=Path, help="write the JSON report to this path")
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


def _bench(args: argparse.Namespace) -> int:
    from agentshield.bench import format_markdown, format_table, run_benchmark

    try:
        report = run_benchmark(
            model=args.model,
            base_url=args.base_url,
            api_key=args.api_key,
            attack=args.attack,
            user_tasks=args.user_tasks,
            injection_tasks=args.injection_tasks,
            approval=args.approval,
            suite_name=args.suite,
            benchmark_version=args.benchmark_version,
        )
    except (ImportError, ValueError) as exc:
        print(f"agentshield bench: {exc}", file=sys.stderr)
        return 2

    payload = report.as_dict()
    if args.out is not None:
        args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(payload, indent=2))
    elif args.markdown:
        print(format_markdown(report))
    else:
        print(format_table(report))
    return 0
