"""AgentShield CLI entry point."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from loguru import logger
from rich.console import Console

from agentshield.audit import (
    AuditChainExporter,
    AuditChainStore,
    AuditChainVerifier,
    ChainedAuditEntry,
    VerificationResult,
)
from agentshield.config import AgentShieldConfig
from agentshield.exceptions import AuditChainError

app = typer.Typer(
    help="AgentShield command line tools.",
    no_args_is_help=True,
)
audit_app = typer.Typer(
    help="Audit chain verification and export commands.",
    no_args_is_help=True,
)
app.add_typer(audit_app, name="audit")

console = Console()


def _load_entries_from_jsonl(chain_path: Path) -> list[ChainedAuditEntry]:
    """Load chained audit entries from a JSONL file.

    Args:
            chain_path: JSONL file containing serialized ChainedAuditEntry objects.

    Returns:
            Parsed chained entries in file order.

    Raises:
            AuditChainError: If the file cannot be read or contains invalid entries.
    """
    if not chain_path.exists():
        raise AuditChainError(f"Audit chain file does not exist: {chain_path}")

    entries: list[ChainedAuditEntry] = []

    try:
        with chain_path.open("r", encoding="utf-8") as file_handle:
            for raw_line in file_handle:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                payload = json.loads(line)
                entry = ChainedAuditEntry.model_validate(payload)
                entries.append(entry)
    except (OSError, ValueError, TypeError) as exc:
        raise AuditChainError(
            f"Failed to parse audit chain file {chain_path}: {exc}"
        ) from exc

    return entries


def _build_store_from_entries(entries: list[ChainedAuditEntry]) -> AuditChainStore:
    """Build an AuditChainStore seeded from existing entries.

    Args:
            entries: Parsed chained entries loaded from persistent storage.

    Returns:
            In-memory AuditChainStore representing the file contents.
    """
    store = AuditChainStore()
    store._entries = list(entries)
    store._next_sequence_number = entries[-1].sequence_number + 1 if entries else 0
    return store


def _render_verification_result(result: VerificationResult) -> None:
    """Render verification results to the terminal.

    Args:
            result: Verification outcome to display.
    """
    if result.is_valid:
        console.print(
            "[green]Audit chain is valid.[/green] " f"entries={result.total_entries}",
        )
        return

    console.print(
        "[red]Audit chain verification failed.[/red] "
        f"entries={result.total_entries} "
        f"first_broken_sequence={result.first_broken_sequence} "
        f"error={result.error_message}",
    )


@audit_app.command("verify")
def verify_audit_chain(
    chain_path: Annotated[
        Path,
        typer.Argument(
            ...,
            exists=False,
            dir_okay=False,
            help="Path to the audit chain JSONL file.",
        ),
    ],
    start: Annotated[
        int | None,
        typer.Option(help="Optional inclusive range start index."),
    ] = None,
    end: Annotated[
        int | None,
        typer.Option(help="Optional inclusive range end index."),
    ] = None,
) -> None:
    """Verify audit-chain integrity from a JSONL file.

    Exit codes:
            0: Chain verified successfully.
            1: Verification completed but chain is invalid.
            2: Verification command failed due to input or parse errors.
    """
    try:
        entries = _load_entries_from_jsonl(chain_path)
        store = _build_store_from_entries(entries)
        verifier = AuditChainVerifier()

        if start is None and end is None:
            result = verifier.verify(store)
        elif start is None or end is None:
            raise AuditChainError(
                "Both --start and --end are required for range verify"
            )
        else:
            result = verifier.verify_range(store, start=start, end=end)
    except AuditChainError as exc:
        logger.error(
            "Audit chain verify command failed | path={} error={}", chain_path, exc
        )
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc

    _render_verification_result(result)
    if not result.is_valid:
        raise typer.Exit(code=1)


@audit_app.command("export")
def export_audit_chain(
    chain_path: Annotated[
        Path,
        typer.Argument(
            ...,
            exists=False,
            dir_okay=False,
            help="Path to the source audit chain JSONL file.",
        ),
    ],
    output_path: Annotated[
        Path,
        typer.Argument(
            ...,
            exists=False,
            dir_okay=False,
            help="Destination path for exported output.",
        ),
    ],
    format: Annotated[
        str,
        typer.Option(help="Export format: jsonl or json."),
    ] = "jsonl",
    session_id: Annotated[
        str | None,
        typer.Option(help="Optional session filter. Only valid when format=json."),
    ] = None,
    include_verification: Annotated[
        bool,
        typer.Option(help="Include verification header for JSONL export."),
    ] = True,
) -> None:
    """Export an audit chain JSONL file to JSONL or JSON report formats.

    Exit codes:
            0: Export succeeded.
            2: Export failed due to input, validation, or I/O errors.
    """
    try:
        normalized_format = format.lower()
        entries = _load_entries_from_jsonl(chain_path)
        store = _build_store_from_entries(entries)
        exporter = AuditChainExporter(config=AgentShieldConfig())

        if normalized_format == "jsonl":
            if session_id is not None:
                raise AuditChainError(
                    "--session-id is only supported when --format json"
                )

            count = exporter.export_jsonl(
                store,
                output_path,
                include_verification=include_verification,
            )
            console.print(
                "[green]Audit chain exported.[/green] "
                f"format=jsonl entries={count} output={output_path}",
            )
            return

        if normalized_format == "json":
            if session_id is not None:
                report = exporter.export_session_report(store, session_id, output_path)
            else:
                report = exporter.export_json_report(store, output_path)

            console.print(
                "[green]Audit chain exported.[/green] "
                f"format=json entries={report['metadata']['chain_length']} "
                f"valid={report['metadata']['is_valid']} output={output_path}",
            )
            return

        raise AuditChainError("Unsupported format. Use jsonl or json.")
    except AuditChainError as exc:
        logger.error(
            "Audit chain export command failed | source={} output={} error={}",
            chain_path,
            output_path,
            exc,
        )
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
