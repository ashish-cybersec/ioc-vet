"""Tests for v0.3.0 additions: IDN (internationalised) domain support and
CSV batch output.
"""

import csv
import io

import pytest

from iocvet.core.detector import detect_ioc_type, normalize
from iocvet.core.models import EnrichmentReport, IOCType, ProviderResult, Verdict
from iocvet.output.csv_output import reports_to_csv

# --- IDN domains -------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected_puny",
    [
        ("münchen.de", "xn--mnchen-3ya.de"),
        ("MÜNCHEN.de", "xn--mnchen-3ya.de"),  # UTS-46 case folding
        ("例え.jp", "xn--r8jz45g.jp"),
        ("россия.рф", "xn--h1alffa9f.xn--p1ai"),  # IDN TLD too
    ],
)
def test_idn_domain_detected_and_normalised_to_punycode(raw, expected_puny):
    """Human-readable IDNs must be accepted (homograph phishing lands this way)
    and canonicalised to the punycode form providers speak on the wire.
    """
    assert detect_ioc_type(raw) is IOCType.DOMAIN
    assert normalize(raw, IOCType.DOMAIN) == expected_puny


def test_idn_forms_collapse_to_one_cache_key():
    """Unicode, upper-case, punycode, and FQDN-dot forms of the same domain
    must produce a single normalised key so they aren't queried repeatedly.
    """
    forms = ["münchen.de", "MÜNCHEN.de", "xn--mnchen-3ya.de", "münchen.de."]
    keys = {normalize(f, IOCType.DOMAIN) for f in forms}
    assert keys == {"xn--mnchen-3ya.de"}


def test_ascii_domains_unaffected_by_idn_path():
    assert detect_ioc_type("evil.com") is IOCType.DOMAIN
    assert normalize("evil.com", IOCType.DOMAIN) == "evil.com"
    assert detect_ioc_type("sub.domain.co.uk") is IOCType.DOMAIN


@pytest.mark.parametrize("junk", ["☃.example", "not_a_domain", "a.b", "xn--p1ai"])
def test_invalid_idn_like_input_still_rejected(junk):
    # A lone snowman, an underscore host, a single-char TLD, and a bare IDN TLD
    # are all non-domains — the IDN path must not turn junk into a domain.
    assert detect_ioc_type(junk) is IOCType.UNKNOWN


def test_punycode_input_accepted_directly():
    assert detect_ioc_type("xn--mnchen-3ya.de") is IOCType.DOMAIN


# --- CSV output --------------------------------------------------------------


def _sample_reports():
    return [
        EnrichmentReport(
            ioc="8.8.8.8",
            ioc_type=IOCType.IPV4,
            overall_verdict=Verdict.CLEAN,
            results=[
                ProviderResult(
                    provider="ip-api",
                    verdict=Verdict.CLEAN,
                    summary="United States · Google",
                    latency_ms=180,
                ),
                ProviderResult(
                    provider="abuseipdb",
                    skipped_reason="no API key configured",
                ),
            ],
        ),
        EnrichmentReport(
            ioc="evil.com",
            ioc_type=IOCType.DOMAIN,
            overall_verdict=Verdict.MALICIOUS,
            results=[
                ProviderResult(
                    provider="urlhaus",
                    verdict=Verdict.MALICIOUS,
                    summary="2 malware URLs online",
                    link="https://urlhaus.abuse.ch/host/evil.com/",
                    latency_ms=310,
                ),
            ],
        ),
    ]


def test_csv_has_one_row_per_ioc_provider():
    out = reports_to_csv(_sample_reports())
    rows = list(csv.DictReader(io.StringIO(out)))
    # 2 providers for the first IOC + 1 for the second = 3 rows.
    assert len(rows) == 3
    assert rows[0]["ioc"] == "8.8.8.8"
    assert rows[0]["provider"] == "ip-api"
    assert rows[2]["ioc"] == "evil.com"


def test_csv_status_column_distinguishes_ok_skipped_error():
    out = reports_to_csv(_sample_reports())
    rows = list(csv.DictReader(io.StringIO(out)))
    statuses = {(r["provider"], r["status"]) for r in rows}
    assert ("ip-api", "ok") in statuses
    assert ("abuseipdb", "skipped") in statuses
    # the skip reason is preserved in the detail column
    skip_row = next(r for r in rows if r["provider"] == "abuseipdb")
    assert "no API key" in skip_row["detail"]


def test_csv_carries_verdicts_and_links():
    out = reports_to_csv(_sample_reports())
    rows = list(csv.DictReader(io.StringIO(out)))
    evil = next(r for r in rows if r["ioc"] == "evil.com")
    assert evil["overall_verdict"] == "malicious"
    assert evil["provider_verdict"] == "malicious"
    assert evil["link"] == "https://urlhaus.abuse.ch/host/evil.com/"
    assert evil["latency_ms"] == "310"


def test_csv_empty_input_still_has_header():
    """An empty run must produce a valid, openable CSV, not a zero-byte file."""
    out = reports_to_csv([])
    rows = list(csv.reader(io.StringIO(out)))
    assert len(rows) == 1  # header only
    assert rows[0][0] == "ioc"


# --- CLI integration for the new batch flags ---------------------------------


def _run_cli(*args, tmp_path=None):
    import os
    import subprocess
    import sys
    from pathlib import Path

    env = dict(os.environ)
    env["IOCVET_CONFIG_DIR"] = str(tmp_path) if tmp_path else "/tmp/iocvet-v030-test"
    return subprocess.run(
        [sys.executable, "-m", "iocvet", *args],
        capture_output=True,
        text=True,
        check=False,
        env=env,
        cwd=str(Path(__file__).parent.parent),
    )


def test_cli_batch_csv_is_parseable(tmp_path):
    f = tmp_path / "iocs.txt"
    f.write_text("8.8.8.8\nevil.com\n")
    proc = _run_cli("batch", str(f), "--csv", tmp_path=tmp_path)
    rows = list(csv.DictReader(io.StringIO(proc.stdout)))
    assert rows, "csv output should have data rows"
    assert {"ioc", "provider", "status"} <= set(rows[0].keys())


def test_cli_batch_output_file_written(tmp_path):
    f = tmp_path / "iocs.txt"
    f.write_text("8.8.8.8\n")
    out = tmp_path / "results.csv"
    proc = _run_cli("batch", str(f), "--csv", "-o", str(out), tmp_path=tmp_path)
    assert out.exists()
    assert proc.stdout == "", "with -o, stdout must stay empty"
    rows = list(csv.DictReader(out.open()))
    assert rows


def test_cli_batch_rejects_json_and_csv_together(tmp_path):
    f = tmp_path / "iocs.txt"
    f.write_text("8.8.8.8\n")
    proc = _run_cli("batch", str(f), "--json", "--csv", tmp_path=tmp_path)
    assert proc.returncode == 2
    assert "not both" in proc.stderr


def test_cli_batch_idn_domain_flows_through(tmp_path):
    """A Unicode domain in a batch file must be accepted and canonicalised,
    not silently dropped as unparseable.
    """
    f = tmp_path / "iocs.txt"
    f.write_text("münchen.de\n")
    proc = _run_cli("batch", str(f), "--json", tmp_path=tmp_path)
    import json

    data = json.loads(proc.stdout)
    assert any(r["ioc"] == "xn--mnchen-3ya.de" for r in data)


# --- CSV formula injection (CWE-1236) ----------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        '=cmd|"/c calc.exe"!A1',
        '@SUM(1+1)*cmd|calc',
        '+HYPERLINK("http://evil","x")',
        '-2+3+cmd|calc',
        "\t=1+1",
        "\r=1+1",
    ],
)
def test_csv_neutralises_formula_injection_in_summary(payload):
    """Provider-returned text is attacker-influenceable (threat names, ISP/org
    strings). A cell starting with a formula trigger must be apostrophe-guarded
    so Excel/LibreOffice/Sheets treat it as text, not a formula.
    """
    rpt = EnrichmentReport(
        ioc="evil.com",
        ioc_type=IOCType.DOMAIN,
        overall_verdict=Verdict.MALICIOUS,
        results=[ProviderResult(provider="p", verdict=Verdict.MALICIOUS, summary=payload)],
    )
    out = reports_to_csv([rpt])
    rows = list(csv.DictReader(io.StringIO(out)))
    cell = rows[0]["summary"]
    # After parse-back, the first character must NOT be a formula trigger.
    assert cell[0] not in ("=", "+", "-", "@", "\t", "\r"), f"unguarded: {cell!r}"
    # The guard is a leading apostrophe, and the original payload is preserved
    # after it (so the analyst still sees the real value).
    assert cell == "'" + payload


def test_csv_injection_guarded_in_error_detail_column():
    rpt = EnrichmentReport(
        ioc="evil.com",
        ioc_type=IOCType.DOMAIN,
        results=[ProviderResult(provider="p", error="=1+1+cmd|calc")],
    )
    rows = list(csv.DictReader(io.StringIO(reports_to_csv([rpt]))))
    assert rows[0]["detail"][0] != "="


def test_csv_does_not_mangle_safe_or_midstring_values():
    """Sanitisation must be surgical: safe text and a '=' that isn't the first
    character are left exactly as-is.
    """
    rpt = EnrichmentReport(
        ioc="evil.com",
        ioc_type=IOCType.DOMAIN,
        results=[
            ProviderResult(provider="a", summary="Germany · M247 · proxy"),
            ProviderResult(provider="b", summary="ratio a=b was observed"),
        ],
    )
    rows = list(csv.DictReader(io.StringIO(reports_to_csv([rpt]))))
    summaries = {r["provider"]: r["summary"] for r in rows}
    assert summaries["a"] == "Germany · M247 · proxy"
    assert summaries["b"] == "ratio a=b was observed"


# --- IDN adversarial guards --------------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    [
        "evil\u202emoc.com",  # RTL override
        "evil\u0000.com",  # null byte
        "münchen..de",  # empty label
        ".münchen.de",  # leading dot
        "xn--.com",  # malformed punycode
    ],
)
def test_hostile_idn_input_rejected_without_crashing(hostile):
    # Must classify as UNKNOWN, never raise.
    assert detect_ioc_type(hostile) is IOCType.UNKNOWN


def test_idn_normalisation_output_is_always_ascii():
    """Whatever we send on the wire must be pure ASCII — a unicode value
    reaching a provider or a cache key would be a correctness and injection risk.
    """
    for raw in ["münchen.de", "россия.рф", "例え.jp", "MÜNCHEN.DE", "ⓔⓥⓘⓛ.com"]:
        norm = normalize(raw, IOCType.DOMAIN)
        assert norm.isascii(), f"{raw!r} normalised to non-ASCII: {norm!r}"
