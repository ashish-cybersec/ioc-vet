"""Security regression tests from the pre-release corporate audit.

These encode the threat model for a tool that turns untrusted indicators into
outbound HTTP requests. Each test maps to a specific finding or a property that
must hold for the tool to be safe to run against attacker-supplied input.
"""

import asyncio
import time

import httpx
import pytest

from iocvet.core.defang import refang
from iocvet.core.detector import detect_ioc_type, is_non_global_ip
from iocvet.core.models import IOCType, Verdict
from iocvet.providers.ipapi import IPAPIProvider

# --- F1: private/internal IPs must never be sent to a third party -------------


@pytest.mark.parametrize(
    "ip",
    [
        "169.254.169.254",  # cloud metadata (AWS/GCP/Azure)
        "127.0.0.1",  # loopback
        "10.0.0.1",  # RFC1918
        "192.168.1.1",  # RFC1918
        "172.16.0.1",  # RFC1918
        "0.0.0.0",  # unspecified
        "::1",  # IPv6 loopback
        "fc00::1",  # IPv6 unique-local
        "fe80::1",  # IPv6 link-local
    ],
)
def test_non_global_ips_are_recognised(ip):
    assert is_non_global_ip(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_global_ips_are_allowed(ip):
    assert not is_non_global_ip(ip)


@pytest.mark.asyncio
async def test_provider_refuses_to_query_private_ip():
    """The core control: a provider must short-circuit on a non-global IP and
    make no network call, so internal addresses never leave the host.
    """
    provider = IPAPIProvider()
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"status": "success"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await provider.run(client, "169.254.169.254", IOCType.IPV4)

    assert not called, "a private/metadata IP must never generate an outbound request"
    assert result.skipped_reason is not None
    assert "private" in result.skipped_reason.lower()


@pytest.mark.asyncio
async def test_public_ip_still_queried():
    provider = IPAPIProvider()
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(
            200, json={"status": "success", "country": "United States", "query": "8.8.8.8"}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await provider.run(client, "8.8.8.8", IOCType.IPV4)

    assert called
    assert result.skipped_reason is None


# --- F2: malformed responses must not leak parser internals ------------------


@pytest.mark.asyncio
async def test_non_json_response_reported_cleanly():
    """A captive portal / MITM / error page (esp. on the plaintext ip-api
    channel) must surface as a clean message, not a raw JSONDecodeError.
    """
    provider = IPAPIProvider()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>captive portal</html>")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await provider.run(client, "8.8.8.8", IOCType.IPV4)

    assert result.error is not None
    assert "non-JSON" in result.error
    assert "Expecting value" not in result.error  # no raw parser text


# --- F4: over-long input rejected --------------------------------------------


def test_absurdly_long_input_is_rejected():
    # Verify the length cap's mechanism, not incidental regex behaviour. A
    # single giant label is rejected by the regex's 63-char label limit anyway,
    # so that wouldn't prove the cap does anything. Instead use MANY short valid
    # labels: this matches the domain regex and is rejected ONLY by the length
    # cap. Removing the cap makes this test fail — which is the point.
    many_labels = ".".join(["ab"] * 900) + ".com"  # ~2700 chars, every label valid
    assert len(many_labels) > 2048
    assert detect_ioc_type(many_labels) is IOCType.UNKNOWN
    # Normal IOCs still work.
    assert detect_ioc_type("evil.com") is IOCType.DOMAIN
    assert detect_ioc_type("a" * 60 + ".com") is IOCType.DOMAIN


# --- SSRF / injection: the detection gate blocks smuggling -------------------


@pytest.mark.parametrize(
    "payload",
    [
        "ip-api.com/../../admin",
        "8.8.8.8/../../x",
        "8.8.8.8%0d%0aHost:evil",
        "8.8.8.8\r\nHost: evil.com",
        "evil.com/path?a=b",
        "evil.com#@internal",
        "8.8.8.8 8.8.4.4",
        "localhost",  # not a valid IOC form; must not become a lookup
    ],
)
def test_injection_payloads_are_blocked(payload):
    """None of these classify as a queryable IOC, so the CLI rejects them with
    exit 2 before any request is built.
    """
    assert detect_ioc_type(payload) is IOCType.UNKNOWN


# --- ReDoS: detection stays linear on pathological input ---------------------


@pytest.mark.parametrize(
    "evil",
    [
        "a." * 20_000,
        "a" * 2048 + "!",
        "a" + "-" * 2000 + "a.com",
    ],
)
def test_detection_is_not_catastrophic(evil):
    start = time.perf_counter()
    detect_ioc_type(evil)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"detection took {elapsed:.2f}s — possible ReDoS"


def test_refang_is_not_catastrophic():
    start = time.perf_counter()
    refang("[.]" * 50_000)
    assert time.perf_counter() - start < 1.0


# --- Verdict safety on a skipped private IP ----------------------------------


def test_private_ip_overall_verdict_is_unknown_not_clean():
    """A private IP we declined to check must read UNKNOWN, never CLEAN — same
    principle as everywhere else: 'not checked' is not 'safe'.
    """
    from iocvet.core.models import EnrichmentReport, ProviderResult

    report = EnrichmentReport(
        ioc="10.0.0.1",
        ioc_type=IOCType.IPV4,
        results=[
            ProviderResult(
                provider="ip-api",
                skipped_reason="private/reserved IP — not sent to external providers",
            )
        ],
    )
    assert report.compute_overall_verdict() is Verdict.UNKNOWN


def test_asyncio_import_present():
    # Guard against a refactor dropping the asyncio import the tests rely on.
    assert asyncio is not None


def test_version_is_single_sourced_and_consistent():
    """--version, __version__, the User-Agent, and pyproject.toml must all agree.

    Regression for a real drift bug: __init__ hardcoded 0.1.0 while pyproject
    said 0.2.0, so a 0.2.0 release would have shipped a CLI that reported 0.1.0
    and sent a User-Agent claiming 0.1.0. Version now derives from installed
    package metadata, so this asserts they can't diverge again.
    """
    import pathlib
    import sys

    if sys.version_info >= (3, 11):
        import tomllib
    else:  # pragma: no cover
        import tomli as tomllib

    import iocvet
    from iocvet.core.aggregator import _USER_AGENT

    # pyproject is the release source of truth (the tag guard checks it too).
    root = pathlib.Path(__file__).parent.parent
    pyproject = tomllib.loads((root / "pyproject.toml").read_text())
    declared = pyproject["project"]["version"]

    assert iocvet.__version__ == declared, (
        f"__version__ ({iocvet.__version__}) != pyproject ({declared}) — "
        "version has drifted from its single source"
    )
    assert declared in _USER_AGENT


# --- G1: fail-closed exit codes for CI gates ---------------------------------


def _run(*args, env_extra=None):
    import os
    import subprocess
    import sys

    env = dict(os.environ)
    env["IOCVET_CONFIG_DIR"] = "/tmp/iocvet-ci-test"
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "iocvet", *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(__import__("pathlib").Path(__file__).parent.parent),
    )


def test_fail_on_error_exits_3_when_nothing_checked():
    """A private IP means every provider skips -> no provider answered. With
    --fail-on-error the tool must fail-closed (exit 3), not pass silently.
    """
    proc = _run("lookup", "10.0.0.1", "--fail-on-error")
    assert proc.returncode == 3


def test_default_exit_code_unchanged_without_flag():
    """--fail-on-error is opt-in: without it, a private IP still exits 0 so
    existing scripts don't break.
    """
    proc = _run("lookup", "10.0.0.1")
    assert proc.returncode == 0


# --- G2 / G3: batch file encoding robustness ---------------------------------


def test_batch_utf8_bom_does_not_drop_first_ioc(tmp_path):
    """Excel/Notepad prepend a UTF-8 BOM. The first IOC must survive it."""
    f = tmp_path / "bom.txt"
    f.write_bytes(b"\xef\xbb\xbf8.8.8.8\nevil.com\n")
    proc = _run("batch", str(f), "--json")
    import json

    iocs = {r["ioc"] for r in json.loads(proc.stdout)}
    assert "8.8.8.8" in iocs and "evil.com" in iocs


def test_batch_non_utf8_file_gives_clean_error_not_traceback(tmp_path):
    """A latin-1 byte used to crash with a raw UnicodeDecodeError traceback."""
    f = tmp_path / "latin1.txt"
    f.write_bytes(b"# c\xe9sar\n8.8.8.8\n")
    proc = _run("batch", str(f))
    assert proc.returncode == 2
    assert "Traceback" not in proc.stderr
    assert "not UTF-8" in proc.stderr


# --- G4: config symlink refusal ----------------------------------------------


def test_config_scaffold_refuses_symlink(tmp_path, monkeypatch):
    from iocvet.config import ConfigError, ensure_config_scaffold

    cfg_dir = tmp_path / "iocvet"
    cfg_dir.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("secret")
    victim.chmod(0o644)
    link = cfg_dir / "config.toml"
    link.symlink_to(victim)

    monkeypatch.setattr("iocvet.config.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("iocvet.config.CONFIG_PATH", link)

    with pytest.raises(ConfigError):
        ensure_config_scaffold()
    # The victim's permissions must not have been touched.
    assert victim.stat().st_mode & 0o777 == 0o644


# --- G5: rate limiter guards against a divide-by-zero -------------------------


def test_rate_limiter_rejects_non_positive_rate():
    from iocvet.providers.base import RateLimiter

    with pytest.raises(ValueError):
        RateLimiter(0)
    with pytest.raises(ValueError):
        RateLimiter(-5)
