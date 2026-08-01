"""iocvet — command-line IOC enrichment across multiple threat intel sources.

    iocvet lookup 8.8.8.8
    iocvet lookup evil-domain.com --json
    iocvet providers
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import typer
from rich.console import Console

from iocvet import __version__
from iocvet.config import ConfigError, ensure_config_scaffold
from iocvet.core.aggregator import enrich, enrich_many, list_provider_status
from iocvet.core.cache import DEFAULT_TTL_SECONDS, CacheError, ResultCache
from iocvet.core.defang import is_defanged, refang
from iocvet.core.detector import detect_ioc_type
from iocvet.core.models import IOCType, Verdict
from iocvet.output.csv_output import reports_to_csv
from iocvet.output.terminal import _CHECK, _CIRCLE, render_report

app = typer.Typer(
    name="iocvet",
    help="Look up an IP, domain, URL, or file hash across multiple free threat intel sources.",
    add_completion=False,
)
console = Console()
#: Warnings/errors go here so they never mix into piped --json output.
err_console = Console(stderr=True)


def _open_cache(no_cache: bool, ttl: int) -> ResultCache | None:
    """Build a cache, or None when the user opted out.

    A cache that can't be opened must never stop a lookup, so a CacheError
    (e.g. a symlinked cache path) is reported once and the run continues
    uncached rather than aborting.
    """
    if no_cache:
        return None
    cache = ResultCache(ttl_seconds=ttl)
    try:
        cache.purge_expired()
    except CacheError as exc:
        err_console.print(f"[yellow]Cache disabled:[/yellow] {exc}")
        return None
    return cache


def _warn_if_cache_degraded(cache: ResultCache | None) -> None:
    """Tell the user once if the cache fell over mid-run.

    Silent degradation would mean a cron job quietly re-spending its whole
    quota every night with nobody noticing.
    """
    if cache is not None and cache.degraded_reason:
        err_console.print(f"[yellow]Cache disabled:[/yellow] {cache.degraded_reason}")


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
    as_json: bool = typer.Option(
        False, "--json", help="Emit machine-readable JSON instead of a table."
    ),
    fail_on_malicious: bool = typer.Option(
        False,
        "--fail-on-malicious",
        help="Exit with status 1 if the overall verdict is malicious. Useful in CI/scripts.",
    ),
    fail_on_error: bool = typer.Option(
        False,
        "--fail-on-error",
        help="Exit 3 if no provider could check the IOC (fail-closed for security gates).",
    ),
    no_cache: bool = typer.Option(
        False, "--no-cache", help="Bypass the on-disk cache entirely."
    ),
    refresh: bool = typer.Option(
        False, "--refresh", help="Ignore cached answers and re-query, then update the cache."
    ),
    cache_ttl: int = typer.Option(
        DEFAULT_TTL_SECONDS,
        "--cache-ttl",
        min=0,
        help="How many seconds a cached answer stays valid (0 disables reuse).",
    ),
) -> None:
    """Enrich a single IOC across every configured provider."""
    # Fail loudly on unparseable input. Previously a typo'd IOC ("8.8.8.888")
    # produced a clean-looking UNKNOWN report and exit 0 — which, combined with
    # --fail-on-malicious, means a typo in a CI pipeline silently passes.
    if detect_ioc_type(ioc) is IOCType.UNKNOWN:
        # stderr, not stdout: `iocvet lookup X --json | jq` must never receive
        # human-readable text on the channel a parser is reading.
        err_console.print(
            f"[red]Error:[/red] {ioc!r} is not a recognizable IP, domain, URL, or hash."
        )
        raise typer.Exit(code=2)

    if is_defanged(ioc):
        # Note on stderr so --json stdout stays clean. Lets the analyst confirm
        # we read their pasted-from-a-ticket IOC the way they intended.
        err_console.print(f"[dim]Refanged input → {refang(ioc)}[/dim]")

    cache = _open_cache(no_cache, cache_ttl)
    try:
        report = asyncio.run(enrich(ioc, cache=cache, refresh=refresh))
    finally:
        _warn_if_cache_degraded(cache)
        if cache is not None:
            cache.close()

    if as_json:
        print(report.model_dump_json(indent=2))
    else:
        render_report(report, console=console)

    if fail_on_malicious and report.overall_verdict == Verdict.MALICIOUS:
        raise typer.Exit(code=1)

    if fail_on_error and not report.working_providers:
        # No provider actually answered — "unknown", not "clean". Fail-closed.
        raise typer.Exit(code=3)


@app.command()
def batch(
    file: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        readable=True,
        help="Path to a file with one IOC per line.",
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit a JSON array instead of tables."),
    as_csv: bool = typer.Option(
        False, "--csv", help="Emit CSV (one row per IOC/provider) instead of tables."
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write output to a file instead of stdout (format follows --json/--csv).",
    ),
    fail_on_malicious: bool = typer.Option(
        False,
        "--fail-on-malicious",
        help="Exit 1 if ANY IOC in the file is malicious.",
    ),
    fail_on_error: bool = typer.Option(
        False,
        "--fail-on-error",
        help="Exit 3 if any IOC could not be checked by a single provider "
        "(fail-closed for security gates).",
    ),
    no_cache: bool = typer.Option(
        False, "--no-cache", help="Bypass the on-disk cache entirely."
    ),
    refresh: bool = typer.Option(
        False, "--refresh", help="Ignore cached answers and re-query, then update the cache."
    ),
    cache_ttl: int = typer.Option(
        DEFAULT_TTL_SECONDS,
        "--cache-ttl",
        min=0,
        help="How many seconds a cached answer stays valid (0 disables reuse).",
    ),
) -> None:
    """Enrich every IOC in a file, one per line. Blank lines and lines
    starting with '#' are ignored.
    """
    # Read the file ourselves rather than via typer.FileText: real-world IOC
    # lists come out of Excel/Notepad with a UTF-8 BOM (which would otherwise
    # corrupt the first line) or in a non-UTF-8 encoding (which would crash with
    # a raw UnicodeDecodeError). utf-8-sig strips the BOM; a decode failure
    # becomes a clean message instead of a traceback.
    try:
        text = file.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        err_console.print(
            f"[red]Error:[/red] {file} is not UTF-8 text. Re-save it as UTF-8 "
            "(one IOC per line)."
        )
        raise typer.Exit(code=2) from None

    candidates = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    # Classify once; the previous version called detect_ioc_type twice per line.
    classified = [(c, detect_ioc_type(c)) for c in candidates]
    iocs = [c for c, t in classified if t is not IOCType.UNKNOWN]
    unparseable = [c for c, t in classified if t is IOCType.UNKNOWN]

    if unparseable:
        # Report to stderr so it never contaminates --json output on stdout.
        preview = ", ".join(repr(c) for c in unparseable[:5])
        more = f" (+{len(unparseable) - 5} more)" if len(unparseable) > 5 else ""
        err_console.print(
            f"[yellow]Warning:[/yellow] skipped {len(unparseable)} unparseable line(s): "
            f"{preview}{more}"
        )

    if not iocs:
        err_console.print("[yellow]No valid IOCs found in file.[/yellow]")
        raise typer.Exit(code=1)

    if as_json and as_csv:
        err_console.print("[red]Error:[/red] choose one of --json or --csv, not both.")
        raise typer.Exit(code=2)

    cache = _open_cache(no_cache, cache_ttl)
    try:
        reports = asyncio.run(enrich_many(iocs, cache=cache, refresh=refresh))
    finally:
        _warn_if_cache_degraded(cache)
        if cache is not None:
            cache.close()

    # Build the machine-readable payload once; write it to a file or stdout.
    if as_json:
        payload = json.dumps([r.model_dump(mode="json") for r in reports], indent=2)
    elif as_csv:
        payload = reports_to_csv(reports)
    else:
        payload = None

    if payload is not None:
        if output is not None:
            output.write_text(payload, encoding="utf-8")
            err_console.print(f"[dim]Wrote {len(reports)} result(s) to {output}[/dim]")
        else:
            print(payload)
    else:
        # Pretty tables only make sense on the terminal, not a file.
        if output is not None:
            err_console.print(
                "[red]Error:[/red] --output requires --json or --csv "
                "(the table format is terminal-only)."
            )
            raise typer.Exit(code=2)
        for report in reports:
            render_report(report, console=console)
            console.print()

    if fail_on_malicious and any(r.overall_verdict is Verdict.MALICIOUS for r in reports):
        raise typer.Exit(code=1)

    # Fail-closed option for security gates: if any IOC had zero providers
    # actually answer (all errored or were skipped), the result is "we don't
    # know", not "clean". Exit 3 so a pipeline can distinguish this from a
    # clean run (0) and from a malicious finding (1).
    if fail_on_error and any(not r.working_providers for r in reports):
        raise typer.Exit(code=3)


cache_app = typer.Typer(help="Inspect or clear the on-disk result cache.")
app.add_typer(cache_app, name="cache")


@cache_app.command("stats")
def cache_stats(
    cache_ttl: int = typer.Option(
        DEFAULT_TTL_SECONDS,
        "--cache-ttl",
        min=0,
        help="TTL used to count expired entries.",
    ),
) -> None:
    """Show where the cache lives and how much is in it."""
    cache = ResultCache(ttl_seconds=cache_ttl)
    try:
        info = cache.stats()
    except CacheError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from None
    finally:
        cache.close()

    if not info["available"]:
        console.print(f"  cache unavailable at {info['path']}")
        return
    size_kb = int(info["size_bytes"]) / 1024
    console.print(f"  path      {info['path']}")
    console.print(f"  entries   {info['entries']} ({info['expired']} expired)")
    console.print(f"  size      {size_kb:.1f} KiB")


@cache_app.command("clear")
def cache_clear() -> None:
    """Delete every cached result.

    Also useful for privacy: the cache records which indicators were looked up.
    """
    cache = ResultCache()
    try:
        removed = cache.clear()
    except CacheError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from None
    finally:
        cache.close()
    console.print(f"  cleared {removed} cached result(s)")


@app.command()
def providers() -> None:
    """List every registered provider and whether it's configured."""
    rows = list_provider_status()
    for row in rows:
        if row["configured"]:
            console.print(f"  [green]{_CHECK}[/green] {row['name']}")
        else:
            # Only ever reached when a key is required but missing:
            # is_configured is unconditionally True for keyless providers.
            console.print(
                f"  [yellow]{_CIRCLE}[/yellow] {row['name']} [dim](needs {row['env_var']})[/dim]"
            )


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
    except ConfigError as exc:
        # A broken config file is user error, not a crash. Report it in one
        # line on stderr rather than dumping a traceback.
        err_console.print(f"[red]Config error:[/red] {exc}")
        sys.exit(2)
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted.[/dim]")
        sys.exit(130)


if __name__ == "__main__":
    run()
