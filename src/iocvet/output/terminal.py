"""Pretty terminal rendering of an EnrichmentReport using `rich`."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from iocvet.core.models import EnrichmentReport, ProviderResult, Verdict

_VERDICT_STYLE = {
    Verdict.MALICIOUS: ("bold white on red", "MALICIOUS"),
    Verdict.SUSPICIOUS: ("bold black on yellow", "SUSPICIOUS"),
    Verdict.CLEAN: ("bold white on green", "CLEAN"),
    Verdict.UNKNOWN: ("bold white on grey37", "UNKNOWN"),
}

_ROW_COLOR = {
    Verdict.MALICIOUS: "red",
    Verdict.SUSPICIOUS: "yellow",
    Verdict.CLEAN: "green",
    Verdict.UNKNOWN: "dim",
}


def render_report(report: EnrichmentReport, console: Console | None = None) -> None:
    console = console or Console()
    style, label = _VERDICT_STYLE[report.overall_verdict]

    header = Text()
    header.append(f"{report.ioc}  ", style="bold")
    header.append(f"[{report.ioc_type.value}]  ", style="dim")
    header.append(f" {label} ", style=style)
    if report.from_cache:
        header.append("  (cached)", style="dim italic")

    console.print(Panel(header, expand=False, border_style=_ROW_COLOR[report.overall_verdict]))

    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("Provider")
    table.add_column("Verdict")
    table.add_column("Summary")
    table.add_column("Latency", justify="right")

    for result in report.results:
        table.add_row(*_row_for(result))

    console.print(table)

    skipped = report.skipped_providers
    if skipped:
        names = ", ".join(f"{r.provider} ({r.skipped_reason})" for r in skipped)
        console.print(f"\n[dim]Skipped: {names}[/dim]")

    for result in report.working_providers:
        if result.link:
            console.print(f"[dim]{result.provider} →[/dim] {result.link}")


def _row_for(result: ProviderResult) -> tuple[str, Text, str, str]:
    if result.error:
        return (result.provider, Text("error", style="red"), result.error, "—")
    if result.skipped_reason:
        return (result.provider, Text("skipped", style="dim"), result.skipped_reason, "—")

    style, label = _VERDICT_STYLE[result.verdict]
    verdict_text = Text(f" {label} ", style=style)
    latency = f"{result.latency_ms}ms" if result.latency_ms is not None else "—"
    return (result.provider, verdict_text, result.summary or "—", latency)
