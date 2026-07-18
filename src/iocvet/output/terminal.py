"""Pretty terminal rendering of an EnrichmentReport using `rich`."""

from __future__ import annotations

import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from iocvet.core.models import EnrichmentReport, ProviderResult, Verdict


def _stdout_encoding() -> str:
    """Best-effort name of stdout's encoding, defaulting to utf-8."""
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    return enc


def _can_encode(text: str) -> bool:
    try:
        text.encode(_stdout_encoding())
        return True
    except (UnicodeEncodeError, LookupError):
        return False


#: Glyphs used in output. On a legacy console (Windows cp1252 is the common
#: case) the fancy ones can't be encoded and rich would raise
#: UnicodeEncodeError mid-render — crashing the command. We pick ASCII
#: fallbacks whenever stdout can't represent the preferred glyph, so output
#: degrades gracefully instead of exploding.
_ARROW = "\u2192" if _can_encode("\u2192") else "->"
_CHECK = "\u2713" if _can_encode("\u2713") else "[OK]"
_CIRCLE = "\u25cb" if _can_encode("\u25cb") else "[ ]"


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
            console.print(f"[dim]{result.provider} {_ARROW}[/dim] {result.link}")


def _row_for(result: ProviderResult) -> tuple[str, Text, str, str]:
    if result.error:
        return (result.provider, Text("error", style="red"), result.error, "—")
    if result.skipped_reason:
        return (result.provider, Text("skipped", style="dim"), result.skipped_reason, "—")

    style, label = _VERDICT_STYLE[result.verdict]
    verdict_text = Text(f" {label} ", style=style)
    latency = f"{result.latency_ms}ms" if result.latency_ms is not None else "—"
    return (result.provider, verdict_text, result.summary or "—", latency)
