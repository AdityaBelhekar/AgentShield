"""Root application for the AgentShield CLI."""

from __future__ import annotations

from typing import Annotated

import typer
from rich import print as rprint

from agentshield.cli.commands.certify import certify_app
from agentshield.cli.commands.redteam import redteam_app

app = typer.Typer(
    name="agentshield",
    help="AgentShield Red Team CLI — attack, verify, certify your AI agents.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

app.add_typer(
    redteam_app,
    name="redteam",
    help="Run red team attacks against a live agent.",
)
app.add_typer(
    certify_app,
    name="certify",
    help="Generate a security certification badge for your agent.",
)


def version_callback(value: bool) -> None:
    """Show AgentShield package version and exit."""
    if value:
        from agentshield import __version__

        rprint(f"[bold green]AgentShield[/] v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-v",
            callback=version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = False,
) -> None:
    """AgentShield — trust and observability layer for AI agents."""


def cli() -> None:
    """Invoke the AgentShield CLI."""
    app()
