"""Red team command group for AgentShield CLI."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from loguru import logger
from rich import print as rprint
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from agentshield.cli.attack_library import (
    ATTACK_LIBRARY,
    AttackCategory,
    AttackSeverity,
    get_attack_by_id,
    get_attacks_by_category,
)
from agentshield.cli.certify import CertificationEngine
from agentshield.cli.html_report import HtmlReportRenderer
from agentshield.cli.report import ReportBuilder, ReportSerializer
from agentshield.cli.runner import (
    AgentLoader,
    AttackOutcome,
    AttackResult,
    AttackRunner,
)
from agentshield.exceptions import AgentShieldError

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


def _outcome_style(outcome: AttackOutcome) -> str:
    """Return Rich style for a run outcome.

    Args:
        outcome: Attack outcome enum value.

    Returns:
        Rich style string for display.
    """
    if outcome == AttackOutcome.DETECTED:
        return "bold green"
    if outcome == AttackOutcome.BYPASSED:
        return "bold red"
    if outcome == AttackOutcome.SIMULATED:
        return "dim"
    return "yellow"


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
    html_output: Annotated[
        Path | None,
        typer.Option(
            "--html-output",
            help="Also render and save an HTML report to this path.",
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
        html_output: Optional output path for HTML report.
        policy: Policy mode to apply during runtime execution.
    """
    loader = AgentLoader(agent_module)
    try:
        agent = loader.load()
    except AgentShieldError as exc:
        rprint(f"[red]Failed to load agent:[/] {exc}")
        raise typer.Exit(code=1) from exc

    attacks = ATTACK_LIBRARY
    if attack_id is not None:
        try:
            attacks = [get_attack_by_id(attack_id)]
        except AgentShieldError as exc:
            rprint(f"[red]Failed to select attack:[/] {exc}")
            raise typer.Exit(code=1) from exc
    elif category is not None:
        try:
            parsed_category = AttackCategory(category)
        except ValueError as exc:
            valid_categories = ", ".join(item.value for item in AttackCategory)
            rprint(
                "[red]Invalid category:[/] "
                f"{category}. Must be one of: {valid_categories}"
            )
            raise typer.Exit(code=1) from exc
        attacks = get_attacks_by_category(parsed_category)

    logger.info(
        "Prepared red team run | module={} policy={} attack_count={} "
        "attack_id={} category={}",
        agent_module,
        policy,
        len(attacks),
        attack_id,
        category,
    )

    run_timestamp = datetime.now(UTC).isoformat()
    runner = AttackRunner(agent=agent, policy=policy)
    results: list[AttackResult] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
    ) as progress:
        task = progress.add_task("Running attacks...", total=len(attacks))
        for attack in attacks:
            result = runner.run_single(attack)
            results.append(result)
            progress.advance(task)

    builder = ReportBuilder(
        agent_module=agent_module,
        policy=policy,
        run_timestamp=run_timestamp,
    )
    report = builder.build(results)

    table = Table(title="AgentShield Red Team Results", header_style="bold cyan")
    table.add_column("ID", style="bold")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Outcome")
    table.add_column("Latency (ms)", justify="right")

    for result in report.results:
        style = _outcome_style(result.outcome)
        outcome_text = f"[{style}]{result.outcome.value}[/{style}]"
        table.add_row(
            result.attack_id,
            result.attack_name,
            result.category.value,
            outcome_text,
            f"{result.latency_ms:.2f}",
        )

    rprint(table)

    summary = (
        f"Total: {report.total_attacks}  "
        f"Detected: {report.detected_count}  "
        f"Bypassed: {report.bypassed_count}\n"
        f"Simulated: {report.simulated_count}  "
        f"Errors: {report.error_count}\n"
        f"Detection rate: {report.detection_rate_pct:.2f}%"
    )
    rprint(Panel(summary, title="Summary", border_style="cyan"))

    if output is not None:
        try:
            ReportSerializer.save(report, output)
            rprint(f"[green]Report saved to:[/] {output}")
        except AgentShieldError as exc:
            rprint(f"[red]Failed to save report:[/] {exc}")
            raise typer.Exit(code=1) from exc

    if html_output is not None:
        cert = CertificationEngine.evaluate(report)
        renderer = HtmlReportRenderer(report, cert)
        html_content = renderer.render()
        try:
            HtmlReportRenderer.save(html_content, html_output)
            rprint(f"[green]HTML report saved to:[/] {html_output}")
        except AgentShieldError as exc:
            rprint(f"[red]Failed to save HTML report:[/] {exc}")
            raise typer.Exit(code=1) from exc
