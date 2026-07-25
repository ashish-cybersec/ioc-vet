"""CSV rendering for batch results.

SOC work lives in spreadsheets, so batch output needs a flat, pivotable form.
The natural grain is one row per (IOC, provider): an analyst can then filter by
verdict, sort by provider, or pivot IOC-by-provider without reshaping anything.
A per-IOC summary row would lose the per-provider detail that makes the tool
worth running, so we emit the long form and let the spreadsheet aggregate.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable

from iocvet.core.models import EnrichmentReport

# Characters that make a spreadsheet treat a cell as a formula. This tool
# ingests untrusted indicators and writes provider-returned text (threat names,
# ISP/org strings, tags) into CSV cells — any of which an attacker can
# influence. Without neutralising these, opening the CSV in Excel/LibreOffice/
# Sheets executes attacker-controlled formulas (CWE-1236, CSV injection).
_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def _sanitize_cell(value: object) -> object:
    """Neutralise spreadsheet formula injection for string cells.

    OWASP's recommended mitigation: prefix a leading formula trigger with a
    single quote so the spreadsheet treats the cell as text. Applied only to
    strings that start with a trigger; numbers and safe strings pass through
    unchanged, so the data stays faithful.
    """
    if isinstance(value, str) and value and value[0] in _FORMULA_TRIGGERS:
        return "'" + value
    return value

_COLUMNS = [
    "ioc",
    "ioc_type",
    "overall_verdict",
    "provider",
    "provider_verdict",
    "summary",
    "link",
    "status",  # ok | skipped | error — so a filter can drop non-answers
    "detail",  # the skip reason or error text, if any
    "latency_ms",
]


def _status_and_detail(result_ok: bool, skipped: str | None, error: str | None) -> tuple[str, str]:
    if skipped is not None:
        return "skipped", skipped
    if error is not None:
        return "error", error
    return "ok", ""


def reports_to_csv(reports: Iterable[EnrichmentReport]) -> str:
    """Render reports as CSV text, one row per (IOC, provider).

    Always writes a header, so an empty run still produces a valid,
    openable file rather than a zero-byte one.
    """
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_COLUMNS, extrasaction="ignore")
    writer.writeheader()

    for report in reports:
        for result in report.results:
            status, detail = _status_and_detail(
                result.ok, result.skipped_reason, result.error
            )
            row = {
                "ioc": report.ioc,
                "ioc_type": report.ioc_type.value,
                "overall_verdict": report.overall_verdict.value,
                "provider": result.provider,
                "provider_verdict": result.verdict.value,
                "summary": result.summary,
                "link": result.link or "",
                "status": status,
                "detail": detail,
                "latency_ms": result.latency_ms if result.latency_ms is not None else "",
            }
            # Neutralise formula injection on every cell before writing. Even
            # "safe-looking" columns (ioc, link) can carry attacker-controlled
            # text, so sanitise uniformly rather than guessing which are safe.
            writer.writerow({k: _sanitize_cell(v) for k, v in row.items()})

    return buffer.getvalue()
