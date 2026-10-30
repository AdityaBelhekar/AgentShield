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
    if args.command == "gateway":
        return _gateway(args)
    if args.command == "draft-policy":
        return _draft_policy(args)
    if args.command == "ui":
        return _ui(args)

    parser.error("unknown command")
    return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentshield",
        description="Verify audit logs, run benchmarks, and proxy MCP servers.",
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
        "--classifier",
        action="store_true",
        help="measure the prompt-injection classifier instead (needs the [classifier] extra)",
    )
    bench.add_argument("--threshold", type=float, default=0.5, help="classifier threshold")
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

    gateway = commands.add_parser(
        "gateway",
        help="proxy a stdio MCP server, checking every tools/call",
        usage="agentshield gateway --policy POLICY [--lock FILE] [--audit FILE] -- <command>",
    )
    gateway.add_argument("--policy", required=True, help="built-in policy name or YAML file")
    gateway.add_argument("--audit", type=Path, help="append decisions to this JSONL file")
    gateway.add_argument("--audit-key", type=Path, help="Ed25519 PEM key to sign the audit log")
    gateway.add_argument("--lock", type=Path, help="pin tool descriptions in this lockfile")
    gateway.add_argument("server", nargs=argparse.REMAINDER, help="the MCP server command")

    draft = commands.add_parser(
        "draft-policy",
        help="print a starting policy for an MCP server's tools",
        usage="agentshield draft-policy -- <server command>",
    )
    draft.add_argument("server", nargs=argparse.REMAINDER, help="the MCP server command")

    ui = commands.add_parser("ui", help="render an audit log as an HTML flow graph")
    ui.add_argument("file", type=Path, help="path to the audit JSONL file")
    ui.add_argument("--policy", help="policy whose labels mark the data sources")
    ui.add_argument("--out", type=Path, help="HTML path (default: next to the audit file)")
    return parser


def _verify(path: Path, *, as_json: bool) -> int:
    report = verify_audit(path)
    if as_json:
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if report.valid else 1

    if report.valid:
        kind = "signed" if report.signed else "unsigned"
        print(f"valid: {report.records} records, {report.checkpoints} checkpoints ({kind})")
        if report.unsigned_tail:
            print(
                f"note: the last {report.unsigned_tail} record(s) come after the last "
                "signed checkpoint; removing them would not be detected"
            )
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


def _gateway(args: argparse.Namespace) -> int:
    from agentshield.audit import AuditLog, load_key
    from agentshield.exceptions import AgentShieldError
    from agentshield.gateway import run_gateway
    from agentshield.shield import Shield

    command = _server_command(args.server)
    if not command:
        print("agentshield gateway: give the server command after --", file=sys.stderr)
        return 2
    try:
        audit = None
        if args.audit is not None:
            key = load_key(args.audit_key) if args.audit_key is not None else None
            audit = AuditLog(args.audit, key=key)
        shield = Shield.from_policy(args.policy, audit=audit)
    except (AgentShieldError, OSError) as exc:
        print(f"agentshield gateway: {exc}", file=sys.stderr)
        return 2
    try:
        return run_gateway(shield, command, lock=args.lock)
    except (AgentShieldError, ValueError) as exc:
        print(f"agentshield gateway: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"agentshield gateway: cannot start {command[0]!r}: {exc}", file=sys.stderr)
        return 2
    finally:
        shield.close()


def _draft_policy(args: argparse.Namespace) -> int:
    from agentshield.gateway import draft_policy, list_server_tools

    command = _server_command(args.server)
    if not command:
        print("agentshield draft-policy: give the server command after --", file=sys.stderr)
        return 2
    try:
        tools = list_server_tools(command)
    except (OSError, ValueError) as exc:
        print(f"agentshield draft-policy: {exc}", file=sys.stderr)
        return 2
    print(draft_policy(tools, " ".join(command)), end="")
    return 0


def _ui(args: argparse.Namespace) -> int:
    from agentshield.exceptions import AgentShieldError
    from agentshield.policy import load_policy
    from agentshield.ui import render_html

    try:
        policy = load_policy(args.policy) if args.policy else None
        page = render_html(args.file, policy)
    except (AgentShieldError, OSError, ValueError) as exc:
        print(f"agentshield ui: {exc}", file=sys.stderr)
        return 2
    out = args.out or args.file.with_suffix(".html")
    out.write_text(page, encoding="utf-8")
    print(f"wrote {out}")
    return 0


def _server_command(words: list[str]) -> list[str]:
    return words[1:] if words[:1] == ["--"] else words


def _bench_classifier(args: argparse.Namespace) -> int:
    try:
        from agentshield.classifier import evaluate, load_eval_set, onnx_scorer

        report = evaluate(onnx_scorer(), load_eval_set(), threshold=args.threshold)
    except (ImportError, OSError, ValueError) as exc:
        print(f"agentshield bench: {exc}", file=sys.stderr)
        return 2

    if args.out is not None:
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    def pct(value: float | None) -> str:
        return "-" if value is None else f"{value:.1%}"

    print(f"model: {report['model']}  dataset: {report['dataset']}  threshold: {args.threshold}")
    print(
        f"{'subset':<10}{'rows':>6}{'injections':>12}{'detected':>10}{'benign':>8}{'false pos':>11}"
    )
    for name in ("overall", "english", "german"):
        r = report[name]
        print(
            f"{name:<10}{r['rows']:>6}{r['injections']:>12}{pct(r['detection_rate']):>10}"
            f"{r['benign']:>8}{pct(r['false_positive_rate']):>11}"
        )
    buried, latency = report["buried"], report["latency_ms"]
    print(
        f"detected injections buried 5,000 chars deep ({buried['documents']} docs): single pass "
        f"{pct(buried['single_pass_detection_rate'])}, chunked "
        f"{pct(buried['chunked_detection_rate'])}; clean docs flagged "
        f"{buried['clean_documents_flagged']}"
    )
    print(
        f"latency: short text median {latency['short_median']:.0f} ms, p95 "
        f"{latency['short_p95']:.0f} ms; {buried['chars']:,}-char document median "
        f"{latency['long_median']:.0f} ms, p95 {latency['long_p95']:.0f} ms"
    )
    return 0


def _bench(args: argparse.Namespace) -> int:
    if args.classifier:
        return _bench_classifier(args)
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
