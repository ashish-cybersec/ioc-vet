"""iocvet — command-line IOC enrichment across multiple threat intel sources.

    iocvet lookup 8.8.8.8
    iocvet lookup evil-domain.com --json
    iocvet providers
"""

from __future__ import annotations

import asyncio
import json
import sys

import typer
from rich.console import Console

from iocvet import __version__
from iocvet.config import ensure_config_scaffold
from iocvet.core.aggregator import enrich, list_provider_status
from iocvet.core.models import Verdict
from iocvet.output.terminal import render_report

app = typer.Typer(
    name="iocvet",
    help="Look up an IP, domain, URL, or file hash across multiple free threat intel sources.",
    add_completion=False,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"iocvet {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    """iocvet — fast, multi-source IOC enrichment from your terminal."""


@app.command()
def lookup(
    ioc: str = typer.Argument(..., help="An IP, domain, URL, or MD5/SHA1/SHA256 hash."),
    as_json: bool = typer.Option(False, "--json", help="Emit machine-readable JSON instead of a table."),
    fail_on_malicious: bool = typer.Option(
        False,
        "--fail-on-malicious",
        help="Exit with status 1 if the overall verdict is malicious. Useful in CI/scripts.",
    ),
) -> None:
    """Enrich a single IOC across every configured provider."""
    report = asyncio.run(enrich(ioc))

    if as_json:
        print(report.model_dump_json(indent=2))
    else:
        render_report(report, console=console)

    if fail_on_malicious and report.overall_verdict == Verdict.MALICIOUS:
        raise typer.Exit(code=1)


@app.command()
def batch(
    file: typer.FileText = typer.Argument(..., help="Path to a file with one IOC per line."),
    as_json: bool = typer.Option(False, "--json", help="Emit a JSON array instead of tables."),
) -> None:
    """Enrich every IOC in a file, one per line. Blank lines and lines
    starting with '#' are ignored.
    """
    iocs = [line.strip() for line in file if line.strip() and not line.strip().startswith("#")]
    if not iocs:
        console.print("[yellow]No IOCs found in file.[/yellow]")
        raise typer.Exit(code=1)

    async def _run_all():
        return await asyncio.gather(*(enrich(ioc) for ioc in iocs))

    reports = asyncio.run(_run_all())

    if as_json:
        print(json.dumps([r.model_dump(mode="json") for r in reports], indent=2))
        return

    for report in reports:
        render_report(report, console=console)
        console.print()


@app.command()
def providers() -> None:
    """List every registered provider and whether it's configured."""
    rows = list_provider_status()
    for row in rows:
        if row["configured"]:
            console.print(f"  [green]✓[/green] {row['name']}")
        elif row["requires_key"]:
            console.print(
                f"  [yellow]○[/yellow] {row['name']} "
                f"[dim](needs {row['env_var']})[/dim]"
            )
        else:
            console.print(f"  [green]✓[/green] {row['name']}")


@app.command()
def configure() -> None:
    """Create a config file scaffold at ~/.config/iocvet/config.toml."""
    path = ensure_config_scaffold()
    console.print(f"Config file ready at [bold]{path}[/bold]")
    console.print("Add your free API keys there, or set environment variables instead:")
    console.print("  [dim]export ABUSEIPDB_API_KEY=...[/dim]")
    console.print("  [dim]export URLHAUS_AUTH_KEY=...[/dim]")


def run() -> None:
    """Entry point used by the console_script and `python -m iocvet`."""
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted.[/dim]")
        sys.exit(130)


if __name__ == "__main__":
    run()
