"""Regression tests for bugs found in the pre-release audit.

Each test here corresponds to a specific defect that shipped or nearly shipped.
They exist so the same mistake can't return quietly.
"""

import pathlib
import subprocess
import sys

import httpx
import pytest

from iocvet.config import ConfigError
from iocvet.core.detector import detect_ioc_type, normalize
from iocvet.core.models import IOCType, Verdict
from iocvet.providers.abuseipdb import AbuseIPDBProvider


def _abuseipdb_client(**data_overrides) -> httpx.AsyncClient:
    data = {
        "ipAddress": "8.8.8.8",
        "abuseConfidenceScore": 0,
        "totalReports": 0,
        "isWhitelisted": False,
        "countryCode": "US",
        "isp": "Google LLC",
        "reports": [],
    }
    data.update(data_overrides)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": data})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# --- AbuseIPDB verdict mapping ----------------------------------------------


@pytest.mark.asyncio
async def test_stale_reports_with_zero_score_are_not_suspicious():
    """The bug: `score >= THRESHOLD or reports > 0` flagged SUSPICIOUS on any
    address with a single stale misreport, ignoring the score entirely.

    AbuseIPDB's score already weights reporter reputation and decays with age.
    A score of 0 means it has no confidence the address is abusive. Public
    resolvers accumulate junk reports constantly — 8.8.8.8 is the README's own
    example, and it must not come back SUSPICIOUS.
    """
    provider = AbuseIPDBProvider(api_key="k")
    async with _abuseipdb_client(abuseConfidenceScore=0, totalReports=12) as client:
        result = await provider.run(client, "8.8.8.8", IOCType.IPV4)

    assert result.verdict == Verdict.CLEAN
    # The reports still surface as context — the information isn't discarded,
    # it just doesn't drive the verdict.
    assert "12 report(s)" in result.summary


@pytest.mark.asyncio
async def test_whitelisted_ip_is_clean():
    """isWhitelisted was fetched into details and never consulted."""
    provider = AbuseIPDBProvider(api_key="k")
    async with _abuseipdb_client(
        abuseConfidenceScore=15, totalReports=4, isWhitelisted=True
    ) as client:
        result = await provider.run(client, "8.8.8.8", IOCType.IPV4)

    assert result.verdict == Verdict.CLEAN
    assert "whitelisted" in result.summary
    assert result.details["is_whitelisted"] is True


@pytest.mark.asyncio
async def test_whitelist_does_not_mask_a_high_score():
    """A whitelisted host that's been compromised is precisely what we want to
    see. The whitelist is a hint, not an override.
    """
    provider = AbuseIPDBProvider(api_key="k")
    async with _abuseipdb_client(
        abuseConfidenceScore=95, totalReports=300, isWhitelisted=True
    ) as client:
        result = await provider.run(client, "8.8.8.8", IOCType.IPV4)

    assert result.verdict == Verdict.MALICIOUS


@pytest.mark.asyncio
async def test_null_score_does_not_crash():
    """The API can return an explicit null, which a get() default won't catch;
    `None >= 75` raises TypeError and would surface as "unexpected error".
    """
    provider = AbuseIPDBProvider(api_key="k")
    async with _abuseipdb_client(abuseConfidenceScore=None, totalReports=None) as client:
        result = await provider.run(client, "8.8.8.8", IOCType.IPV4)

    assert result.ok
    assert result.verdict == Verdict.CLEAN


@pytest.mark.asyncio
async def test_genuinely_suspicious_still_flags():
    provider = AbuseIPDBProvider(api_key="k")
    async with _abuseipdb_client(abuseConfidenceScore=42, totalReports=11) as client:
        result = await provider.run(client, "185.220.101.45", IOCType.IPV4)

    assert result.verdict == Verdict.SUSPICIOUS


# --- Config error handling ---------------------------------------------------


def test_malformed_toml_raises_configerror_not_tomldecodeerror(tmp_path, monkeypatch):
    """A hand-edited config with a typo used to dump a raw traceback. We tell
    users to hand-edit this file, so a syntax error must be a message.
    """
    cfg = tmp_path / "config.toml"
    cfg.write_text("[keys\nbroken = ")
    monkeypatch.setattr("iocvet.config.CONFIG_PATH", cfg)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    from iocvet.config import get_api_key

    with pytest.raises(ConfigError) as exc:
        get_api_key("ABUSEIPDB_API_KEY", "abuseipdb")
    assert "not valid TOML" in str(exc.value)


def test_non_string_key_raises_configerror(tmp_path, monkeypatch):
    """The bug: a list value is truthy, so `iocvet providers` reported the
    provider as configured and the failure only appeared later as an httpx
    header-encoding error — a config typo surfacing as a network fault.
    """
    cfg = tmp_path / "config.toml"
    cfg.write_text('[keys]\nabuseipdb = ["not", "a", "string"]\n')
    monkeypatch.setattr("iocvet.config.CONFIG_PATH", cfg)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    from iocvet.config import get_api_key

    with pytest.raises(ConfigError) as exc:
        get_api_key("ABUSEIPDB_API_KEY", "abuseipdb")
    assert "must be a string" in str(exc.value)


def test_keys_table_of_wrong_type_raises_configerror(tmp_path, monkeypatch):
    cfg = tmp_path / "config.toml"
    cfg.write_text('keys = "oops"\n')
    monkeypatch.setattr("iocvet.config.CONFIG_PATH", cfg)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    from iocvet.config import get_api_key

    with pytest.raises(ConfigError):
        get_api_key("ABUSEIPDB_API_KEY", "abuseipdb")


def test_env_var_wins_and_skips_the_file_entirely(tmp_path, monkeypatch):
    """CI sets env vars and has no config file. A broken file on disk must not
    break a run that never needed it.
    """
    cfg = tmp_path / "config.toml"
    cfg.write_text("[keys\ntotally broken")
    monkeypatch.setattr("iocvet.config.CONFIG_PATH", cfg)
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "from-env")

    from iocvet.config import get_api_key

    assert get_api_key("ABUSEIPDB_API_KEY", "abuseipdb") == "from-env"


def test_config_scaffold_is_not_world_readable(tmp_path, monkeypatch):
    monkeypatch.setattr("iocvet.config.CONFIG_DIR", tmp_path / "cfg")
    monkeypatch.setattr("iocvet.config.CONFIG_PATH", tmp_path / "cfg" / "config.toml")

    from iocvet.config import ensure_config_scaffold

    path = ensure_config_scaffold()
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700


def test_config_scaffold_tightens_preexisting_loose_permissions(tmp_path, monkeypatch):
    """mkdir(mode=...) is a no-op on an existing directory, so a dir created
    by something else kept its permissions.
    """
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir(mode=0o755)
    cfg_file = cfg_dir / "config.toml"
    cfg_file.write_text("[keys]\n")
    cfg_file.chmod(0o644)

    monkeypatch.setattr("iocvet.config.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("iocvet.config.CONFIG_PATH", cfg_file)

    from iocvet.config import ensure_config_scaffold

    ensure_config_scaffold()
    assert cfg_file.stat().st_mode & 0o777 == 0o600
    assert cfg_dir.stat().st_mode & 0o777 == 0o700


# --- Detector ----------------------------------------------------------------


def test_fqdn_root_dot_is_a_domain():
    """"example.com." is a valid FQDN (RFC 1034) and shows up in DNS logs.
    It used to fall through to UNKNOWN, which now means exit code 2.
    """
    assert detect_ioc_type("example.com.") is IOCType.DOMAIN
    assert normalize("EXAMPLE.COM.", IOCType.DOMAIN) == "example.com"


def test_bare_dots_are_not_domains():
    assert detect_ioc_type(".") is IOCType.UNKNOWN
    assert detect_ioc_type("..") is IOCType.UNKNOWN


# --- CLI stream discipline ---------------------------------------------------


def _run_cli(*args, env_extra=None):
    import os

    env = dict(os.environ)
    env["IOCVET_CONFIG_DIR"] = "/tmp/iocvet-regression-cfg"
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "iocvet", *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(pathlib.Path(__file__).parent.parent),
    )


def test_lookup_error_goes_to_stderr_not_stdout():
    """The bug: `lookup`'s invalid-IOC error printed to stdout, so
    `iocvet lookup bad --json | jq` fed human text to a JSON parser.
    `batch` already did this correctly; `lookup` didn't.
    """
    proc = _run_cli("lookup", "garbage!!", "--json")
    assert proc.returncode == 2
    assert proc.stdout == "", f"stdout must stay clean for parsers, got: {proc.stdout!r}"
    assert "not a recognizable" in proc.stderr


def test_lookup_valid_ioc_keeps_json_on_stdout():
    proc = _run_cli("lookup", "example.com", "--json")
    assert proc.stdout.lstrip().startswith("{")
