"""Certification command group for AgentShield CLI."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich import print as rprint
from rich.panel import Panel

from agentshield.cli.certify import (
    BadgeRenderer,
    CertificationEngine,
    CertificationTier,
)
from agentshield.cli.html_report import HtmlReportRenderer
from agentshield.cli.report import ReportSerializer
from agentshield.exceptions import AgentShieldError

certify_app = typer.Typer(
    name="certify",
    help="Generate an AgentShield security certification badge.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)


@certify_app.command("generate")
def generate_cert(
    report: Annotated[
        Path,
        typer.Argument(
            help="Path to a red team JSON report (from `redteam run --output`)."
        ),
    ],
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Write certification JSON to this path.",
        ),
    ] = None,
    badge: Annotated[
        Path | None,
        typer.Option(
            "--badge",
            "-b",
            help="Write SVG certification badge to this path.",
        ),
    ] = None,
    html: Annotated[
        Path | None,
        typer.Option(
            "--html",
            help="Write HTML certification report to this path.",
        ),
    ] = None,
) -> None:
    """Generate a security certification from a red team report.

    Args:
        report: Path to red team JSON report.
        output: Optional destination path for certification JSON.
        badge: Optional destination path for certification badge SVG.
        html: Optional destination path for certification HTML report.
    """
    try:
        red_team_report = ReportSerializer.load(report)
    except AgentShieldError as exc:
        rprint(f"[red]Failed to load report:[/] {exc}")
        raise typer.Exit(code=1) from exc

    cert = CertificationEngine.evaluate(red_team_report)

    tier_style = _tier_style(cert.tier)
    tier_text = _tier_text(cert.tier)
    status_text = (
        "[bold green]\\u2713 Certification issued[/]"
        if cert.is_certified
        else "[bold red]\\u2717 Detection rate below 50% threshold[/]"
    )
    panel_body = "\n".join(
        [
            f"[{tier_style}]{tier_text}[/{tier_style}]",
            f"Detection rate: {cert.detection_rate_pct:.2f}%",
            f"Live attacks tested: {cert.live_attacks}",
            f"Certification timestamp: {cert.cert_timestamp}",
            status_text,
        ]
    )
    rprint(
        Panel(
            panel_body,
            title="AgentShield Certification",
            border_style=("green" if cert.is_certified else "red"),
        )
    )

    if badge is not None:
        try:
            BadgeRenderer.save(cert, badge)
            rprint(f"[green]Badge saved to:[/] {badge}")
        except AgentShieldError as exc:
            rprint(f"[red]Failed to save badge:[/] {exc}")
            raise typer.Exit(code=1) from exc

    if html is not None:
        renderer = HtmlReportRenderer(red_team_report, cert)
        html_content = renderer.render()
        try:
            HtmlReportRenderer.save(html_content, html)
            rprint(f"[green]HTML report saved to:[/] {html}")
        except AgentShieldError as exc:
            rprint(f"[red]Failed to save HTML report:[/] {exc}")
            raise typer.Exit(code=1) from exc

    if output is not None:
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(f"{cert.model_dump_json(indent=2)}\n", encoding="utf-8")
            rprint(f"[green]Certification JSON saved to:[/] {output}")
        except OSError as exc:
            error = AgentShieldError(
                f"Failed to write certification JSON to '{output}': {exc}"
            )
            rprint(f"[red]Failed to save certification JSON:[/] {error}")
            raise typer.Exit(code=1) from error


def _tier_style(tier: CertificationTier) -> str:
    """Return terminal style for a certification tier.

    Args:
        tier: Certification tier value.

    Returns:
        Rich style string.
    """
    if tier == CertificationTier.GOLD:
        return "bold yellow"
    if tier == CertificationTier.SILVER:
        return "bold white"
    if tier == CertificationTier.BRONZE:
        return "bold dark_orange"
    return "bold red"


def _tier_text(tier: CertificationTier) -> str:
    """Return terminal label for a certification tier.

    Args:
        tier: Certification tier value.

    Returns:
        Display label text.
    """
    if tier == CertificationTier.NONE:
        return "NOT CERTIFIED"
    return tier.value.upper()
