"""Red team command group for AgentShield CLI."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from loguru import logger
from rich import print as rprint
from rich.table import Table

from agentshield.cli.attack_library import (
    ATTACK_LIBRARY,
    AttackCategory,
    AttackSeverity,
)

redteam_app = typer.Typer(
    name="redteam",
    help="Red team your AI agent with curated attack payloads.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)


def _severity_style(severity: AttackSeverity) -> str:
    """Return Rich text style for an attack severity.

    Args:
        severity: Severity enum value.

    Returns:
        Rich style string for display.
    """
    if severity == AttackSeverity.CRITICAL:
        return "bold red"
    if severity == AttackSeverity.HIGH:
        return "red"
    if severity == AttackSeverity.MEDIUM:
        return "yellow"
    return "green"


@redteam_app.command("list")
def list_attacks(
    category: Annotated[
        str | None,
        typer.Option(
            "--category",
            "-c",
            help=(
                "Filter by category. One of: prompt_injection, goal_drift, "
                "tool_chain_escalation, memory_poisoning, inter_agent_injection, "
                "behavioral_anomaly"
            ),
        ),
    ] = None,
    severity: Annotated[
        str | None,
        typer.Option(
            "--severity",
            "-s",
            help="Filter by severity: low, medium, high, critical",
        ),
    ] = None,
) -> None:
    """List available red team attack payloads.

    Args:
        category: Optional attack category filter.
        severity: Optional severity filter.
    """
    attacks = ATTACK_LIBRARY

    if category is not None:
        try:
            parsed_category = AttackCategory(category)
        except ValueError as error:
            valid_categories = ", ".join(item.value for item in AttackCategory)
            typer.echo(
                f"Invalid category: {category}. Must be one of: {valid_categories}"
            )
            raise typer.Exit(code=1) from error
        attacks = [attack for attack in attacks if attack.category == parsed_category]

    if severity is not None:
        try:
            parsed_severity = AttackSeverity(severity)
        except ValueError as error:
            valid_severities = ", ".join(item.value for item in AttackSeverity)
            typer.echo(
                f"Invalid severity: {severity}. Must be one of: {valid_severities}"
            )
            raise typer.Exit(code=1) from error
        attacks = [attack for attack in attacks if attack.severity == parsed_severity]

    logger.info(
        "Listing attacks with filters category={} severity={} count={}",
        category,
        severity,
        len(attacks),
    )

    table = Table(title="AgentShield Attack Library", header_style="bold cyan")
    table.add_column("ID", style="bold")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Severity")
    table.add_column("Tags")

    for attack in attacks:
        tag_text = ", ".join(attack.tags) if attack.tags else "-"
        style = _severity_style(attack.severity)
        severity_text = f"[{style}]{attack.severity.value}[/{style}]"
        table.add_row(
            attack.id,
            attack.name,
            attack.category.value,
            severity_text,
            tag_text,
        )

    rprint(table)
    rprint(f"[bold]Total:[/] {len(attacks)} attacks")


@redteam_app.command("run")
def run_attacks(
    agent_module: Annotated[
        str,
        typer.Argument(
            help=(
                "Python import path to a callable that returns a shielded agent. "
                "Example: myproject.agent:create_agent"
            )
        ),
    ],
    category: Annotated[
        str | None,
        typer.Option(
            "--category",
            "-c",
            help="Only run attacks in this category.",
        ),
    ] = None,
    attack_id: Annotated[
        str | None,
        typer.Option(
            "--attack-id",
            "-a",
            help="Run a single attack by ID.",
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Write JSON report to this path.",
        ),
    ] = None,
    policy: Annotated[
        str,
        typer.Option(
            "--policy",
            "-p",
            help="AgentShield policy to apply.",
        ),
    ] = "monitor_only",
) -> None:
    """Run red team attacks against a live shielded agent.

    Args:
        agent_module: Import path for an agent factory callable.
        category: Optional category filter for selected attacks.
        attack_id: Optional single attack ID to execute.
        output: Optional output path for JSON report.
        policy: Policy mode to apply during runtime execution.
    """
    logger.info(
        "Phase 9B stub invoked: module={} category={} attack_id={} output={} policy={}",
        agent_module,
        category,
        attack_id,
        output,
        policy,
    )
    rprint(
        "[yellow]Phase 9B not yet implemented. This command will run attacks "
        "against a live agent.[/]"
    )
    raise typer.Exit(code=0)
