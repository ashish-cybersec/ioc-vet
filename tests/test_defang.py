"""Tests for refanging defanged IOCs.

Two things matter equally here: that neutered indicators come back correctly,
and that anything already valid is left completely alone. The second set is the
dangerous one — a refang that corrupts a real URL or hash is worse than one
that misses a defang form.
"""

import subprocess
import sys
from pathlib import Path

import pytest

from iocvet.core.defang import is_defanged, refang
from iocvet.core.detector import detect_ioc_type, normalize
from iocvet.core.models import IOCType


@pytest.mark.parametrize(
    "raw, expected, expected_type",
    [
        # Dots
        ("evil[.]com", "evil.com", IOCType.DOMAIN),
        ("evil(.)com", "evil.com", IOCType.DOMAIN),
        ("evil{.}com", "evil.com", IOCType.DOMAIN),
        ("evil[dot]com", "evil.com", IOCType.DOMAIN),
        ("evil(dot)com", "evil.com", IOCType.DOMAIN),
        ("evil [.] com", "evil.com", IOCType.DOMAIN),
        # Scheme
        ("hxxp://evil.com", "http://evil.com", IOCType.URL),
        ("hXXps://evil.com", "https://evil.com", IOCType.URL),
        ("hxxp[://]evil[.]com", "http://evil.com", IOCType.URL),
        ("hxxp[:]//evil[.]com", "http://evil.com", IOCType.URL),
        ("hxxps://evil[.]com/path?a=1", "https://evil.com/path?a=1", IOCType.URL),
        # IPs, including partially-bracketed
        ("1[.]2[.]3[.]4", "1.2.3.4", IOCType.IPV4),
        ("1.2.3[.]4", "1.2.3.4", IOCType.IPV4),
        ("127[.]0[.]0[.]1", "127.0.0.1", IOCType.IPV4),
    ],
)
def test_refang_should_defang(raw, expected, expected_type):
    assert refang(raw) == expected
    assert detect_ioc_type(raw) is expected_type


@pytest.mark.parametrize(
    "clean",
    [
        "evil.com",
        "8.8.8.8",
        "2001:db8::1",
        "http://example.com",
        "https://example.com/path?a=1&b=2",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "44d88612fea8a8f36de82e1278abb02f",
    ],
)
def test_refang_leaves_clean_input_byte_identical(clean):
    assert refang(clean) == clean
    assert not is_defanged(clean)


@pytest.mark.parametrize(
    "raw, expected",
    [
        # Brackets around non-separators must survive: [0] is a legit query value.
        ("https://example.com/search?q=a[0]", "https://example.com/search?q=a[0]"),
        ("https://example.com/list[]=1", "https://example.com/list[]=1"),
        # Substrings that merely contain "dot" / "at" must not be rewritten.
        ("dotcom.example.com", "dotcom.example.com"),
        ("cat.example.com", "cat.example.com"),
        ("category", "category"),
        ("teapot dotless", "teapot dotless"),
    ],
)
def test_refang_must_not_corrupt(raw, expected):
    assert refang(raw) == expected


@pytest.mark.parametrize(
    "clean",
    [
        # Audit regressions: the scheme regex used to eat domains that merely
        # start with "http"/"https", and rewrite bare prose "at"/"dot".
        "httpsomething.com",
        "httporn.com",
        "hxxpo.com",          # "hxxp" but no scheme separator -> not a URL
        "http",
        "https",
        "meet at noon",       # bare "at" in prose must never become "@"
        "go dot org",         # bare "dot" in prose must never become "."
        "http://user:pass@host.com",   # colon+@ in a real URL are legitimate
        "[2001:db8::1]:8080",          # bracketed IPv6 — [:] must not be stripped
    ],
)
def test_refang_audit_danger_cases_unchanged(clean):
    assert refang(clean) == clean


def test_bare_dot_word_is_not_touched():
    # Only BRACKETED word forms refang now. Bare "dot"/"at" — delimited by
    # spaces or not — is left alone, so prose and substrings are safe.
    assert refang("adotb") == "adotb"
    assert refang("dotcom") == "dotcom"
    assert refang("a dot b") == "a dot b"
    assert refang("evil[dot]com") == "evil.com"


@pytest.mark.parametrize(
    "raw",
    ["evil[.]com", "hxxp://evil[.]com", "hxxp[://]evil[.]com", "evil.com", "1[.]2[.]3[.]4"],
)
def test_refang_is_idempotent(raw):
    once = refang(raw)
    assert refang(once) == once


def test_normalize_uses_refanged_value():
    # The value that reaches providers/cache must be the real one, never the
    # defanged surface form.
    assert normalize("evil[.]com", IOCType.DOMAIN) == "evil.com"
    assert normalize("1[.]2[.]3[.]4", IOCType.IPV4) == "1.2.3.4"


def test_is_defanged_flags_only_actual_markers():
    assert is_defanged("evil[.]com")
    assert is_defanged("hxxp://evil.com")
    assert not is_defanged("evil.com")
    assert not is_defanged("https://example.com/x[0]")


# --- CLI integration ---------------------------------------------------------


def _run_cli(*args):
    import os

    env = dict(os.environ)
    env["IOCVET_CONFIG_DIR"] = "/tmp/iocvet-defang-test"
    return subprocess.run(
        [sys.executable, "-m", "iocvet", *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(Path(__file__).parent.parent),
    )


def test_cli_accepts_defanged_domain():
    """The whole point: a defanged IOC pasted from a ticket must not exit 2."""
    proc = _run_cli("lookup", "evil[.]com", "--json")
    assert proc.returncode != 2, f"defanged input was rejected: {proc.stderr}"
    assert proc.stdout.lstrip().startswith("{")


def test_cli_json_stdout_stays_clean_when_refanging():
    """The 'Refanged input →' note must go to stderr, never stdout, or it
    corrupts a --json pipe.
    """
    proc = _run_cli("lookup", "evil[.]com", "--json")
    # stdout must be pure JSON; the refang note lives on stderr.
    assert "Refanged" not in proc.stdout
    assert proc.stdout.lstrip().startswith("{")


def test_cli_reports_refanged_value_on_stderr():
    proc = _run_cli("lookup", "evil[.]com", "--json")
    assert "evil.com" in proc.stderr


def test_cli_batch_refangs_lines():
    """Batch routes through the same detect/normalize path, so defanged lines
    in a file must refang too — and a genuinely unparseable line must still be
    reported, not silently refang-mangled into something valid.
    """
    import os
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("evil[.]com\nhxxp://bad[.]net/x\nnot-an-ioc!!\n")
        path = f.name
    try:
        proc = _run_cli("batch", path, "--json")
        assert proc.returncode == 0
        import json

        data = json.loads(proc.stdout)
        iocs = {r["ioc"] for r in data}
        assert "evil.com" in iocs
        assert "http://bad.net/x" in iocs
        # the junk line is skipped, not turned into a bogus IOC
        assert not any("not-an-ioc" in i for i in iocs)
        assert "unparseable" in proc.stderr
    finally:
        os.unlink(path)
