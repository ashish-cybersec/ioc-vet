"""Tests for the on-disk result cache (v0.4.0).

The cache is an optimisation layered onto a security tool, which makes two
properties matter more than raw hit rates:

* it must never cache something that isn't a real answer (errors, skips), and
* it must never be able to break a lookup, however broken the database is.

Both are exercised here directly rather than inferred from call counts.
"""

import asyncio
import sqlite3
import time

import httpx
import pytest

from iocvet.core.aggregator import _enrich_one, _instantiate_providers
from iocvet.core.cache import CacheError, ResultCache
from iocvet.core.models import IOCType, ProviderResult, Verdict
from iocvet.providers.abuseipdb import AbuseIPDBProvider
from iocvet.providers.ipapi import IPAPIProvider

_IPAPI_OK = {
    "status": "success",
    "country": "United States",
    "regionName": "Virginia",
    "city": "Ashburn",
    "isp": "Google LLC",
    "org": "Google Public DNS",
    "as": "AS15169",
    "proxy": False,
    "hosting": False,
    "query": "8.8.8.8",
}


def _counting_client(response_factory):
    """An httpx client that records how many requests were actually made."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return response_factory(request)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler)), calls


# --- core hit/miss behaviour -------------------------------------------------


@pytest.mark.asyncio
async def test_second_lookup_is_served_from_cache(tmp_path):
    cache = ResultCache(path=tmp_path / "c.db")
    client, calls = _counting_client(lambda r: httpx.Response(200, json=_IPAPI_OK))
    async with client as c:
        first = await _enrich_one([IPAPIProvider()], c, "8.8.8.8", cache=cache)
        after_first = calls["n"]
        second = await _enrich_one([IPAPIProvider()], c, "8.8.8.8", cache=cache)
    cache.close()

    assert after_first == 1
    assert calls["n"] == 1, "second lookup must not hit the network"
    assert second.from_cache is True
    assert first.results[0].summary == second.results[0].summary


@pytest.mark.asyncio
async def test_expired_entry_is_requeried(tmp_path):
    db = tmp_path / "c.db"
    warm = ResultCache(path=db)
    client, calls = _counting_client(lambda r: httpx.Response(200, json=_IPAPI_OK))
    async with client as c:
        await _enrich_one([IPAPIProvider()], c, "8.8.8.8", cache=warm)
        warm.close()
        # A zero-second TTL makes everything already stale.
        expired = ResultCache(path=db, ttl_seconds=0)
        await _enrich_one([IPAPIProvider()], c, "8.8.8.8", cache=expired)
        expired.close()
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_refresh_requeries_but_still_updates_cache(tmp_path):
    cache = ResultCache(path=tmp_path / "c.db")
    client, calls = _counting_client(lambda r: httpx.Response(200, json=_IPAPI_OK))
    async with client as c:
        await _enrich_one([IPAPIProvider()], c, "8.8.8.8", cache=cache)
        report = await _enrich_one(
            [IPAPIProvider()], c, "8.8.8.8", cache=cache, refresh=True
        )
        assert calls["n"] == 2, "--refresh must re-query"
        assert report.from_cache is False
        # ...and the cache is still warm afterwards.
        await _enrich_one([IPAPIProvider()], c, "8.8.8.8", cache=cache)
        assert calls["n"] == 2, "cache should have been refreshed, not invalidated"
    cache.close()


@pytest.mark.asyncio
async def test_no_cache_means_every_lookup_queries(tmp_path):
    client, calls = _counting_client(lambda r: httpx.Response(200, json=_IPAPI_OK))
    async with client as c:
        await _enrich_one([IPAPIProvider()], c, "8.8.8.8", cache=None)
        await _enrich_one([IPAPIProvider()], c, "8.8.8.8", cache=None)
    assert calls["n"] == 2


# --- what must NOT be cached (the security-critical part) --------------------


@pytest.mark.asyncio
async def test_errors_are_never_cached(tmp_path):
    """A 500 is transient. Caching it would let one upstream blip silently
    degrade every lookup until the TTL expired.
    """
    cache = ResultCache(path=tmp_path / "c.db")
    client, calls = _counting_client(lambda r: httpx.Response(500, text="boom"))
    async with client as c:
        await _enrich_one([IPAPIProvider()], c, "8.8.8.8", cache=cache)
        await _enrich_one([IPAPIProvider()], c, "8.8.8.8", cache=cache)
    cache.close()
    assert calls["n"] == 2, "an errored provider must be retried, not cached"


@pytest.mark.asyncio
async def test_rate_limit_response_is_never_cached(tmp_path):
    cache = ResultCache(path=tmp_path / "c.db")
    client, calls = _counting_client(lambda r: httpx.Response(429, json={}))
    async with client as c:
        await _enrich_one([IPAPIProvider()], c, "8.8.8.8", cache=cache)
        await _enrich_one([IPAPIProvider()], c, "8.8.8.8", cache=cache)
    cache.close()
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_skips_are_never_written_to_the_database(tmp_path):
    """A skip is configuration state, not data. If "no API key" were cached,
    adding the key would appear to do nothing until the entry expired.

    Checked against the database directly: a skip makes no network call either
    way, so counting requests cannot distinguish "cached" from "skipped again".
    """
    db = tmp_path / "c.db"
    cache = ResultCache(path=db)
    client, _ = _counting_client(lambda r: httpx.Response(200, json=_IPAPI_OK))
    async with client as c:
        # skipped: no API key configured
        await _enrich_one([AbuseIPDBProvider(api_key=None)], c, "9.9.9.9", cache=cache)
        # skipped: private IP is never sent to a third party
        await _enrich_one([IPAPIProvider()], c, "10.0.0.1", cache=cache)
        # a genuine answer, for contrast
        await _enrich_one([IPAPIProvider()], c, "8.8.8.8", cache=cache)
    cache.close()

    rows = sqlite3.connect(db).execute("SELECT ioc FROM provider_results").fetchall()
    stored = {r[0] for r in rows}
    assert stored == {"8.8.8.8"}, f"only real answers may be cached, got {stored}"


def test_put_ignores_non_ok_results_directly(tmp_path):
    cache = ResultCache(path=tmp_path / "c.db")
    cache.put(IOCType.IPV4, "1.1.1.1", ProviderResult(provider="p", error="boom"))
    cache.put(IOCType.IPV4, "1.1.1.1", ProviderResult(provider="p", skipped_reason="no key"))
    assert cache.get(IOCType.IPV4, "1.1.1.1", "p") is None
    cache.close()


# --- from_cache reporting ----------------------------------------------------


@pytest.mark.asyncio
async def test_from_cache_ignores_skipped_providers(tmp_path):
    """A skipped provider never touches the network, so a report served from
    cache alongside several skips is still entirely cached. Counting skips as
    live queries would make from_cache permanently False for anyone without a
    full set of API keys.
    """
    cache = ResultCache(path=tmp_path / "c.db")
    providers = _instantiate_providers()

    def responder(request: httpx.Request) -> httpx.Response:
        if "ip-api" in str(request.url):
            return httpx.Response(200, json=_IPAPI_OK)
        return httpx.Response(200, json={})

    client, _ = _counting_client(responder)
    async with client as c:
        cold = await _enrich_one(providers, c, "8.8.8.8", cache=cache)
        warm = await _enrich_one(providers, c, "8.8.8.8", cache=cache)
    cache.close()

    assert cold.from_cache is False
    assert warm.from_cache is True


@pytest.mark.asyncio
async def test_from_cache_false_when_nothing_was_cached(tmp_path):
    cache = ResultCache(path=tmp_path / "c.db")
    client, _ = _counting_client(lambda r: httpx.Response(200, json={}))
    async with client as c:
        # every provider skips a private IP, so nothing is cached
        report = await _enrich_one(_instantiate_providers(), c, "10.0.0.1", cache=cache)
    cache.close()
    assert report.from_cache is False


# --- determinism -------------------------------------------------------------


@pytest.mark.asyncio
async def test_provider_order_is_stable_across_cache_states(tmp_path):
    """Cache hits are collected separately from fresh results, so without an
    explicit re-sort the output order would depend on which providers happened
    to be cached — producing noisy diffs in CI between otherwise equal runs.

    The cached provider is seeded deliberately as the *last* one in
    registration order. Caching the first provider instead would leave
    ``cached + fresh`` accidentally in the right order, and the test would pass
    against the very bug it exists to catch.
    """
    cache = ResultCache(path=tmp_path / "c.db")
    providers = _instantiate_providers()
    expected = [p.name for p in providers]
    last = expected[-1]

    # Pre-seed only the last provider, so an unsorted concatenation would put
    # it first and the assertion below would fail.
    cache.put(
        IOCType.IPV4,
        "8.8.8.8",
        ProviderResult(provider=last, verdict=Verdict.UNKNOWN, summary="seeded"),
    )

    def responder(request: httpx.Request) -> httpx.Response:
        if "ip-api" in str(request.url):
            return httpx.Response(200, json=_IPAPI_OK)
        return httpx.Response(200, json={})

    client, _ = _counting_client(responder)
    async with client as c:
        report = await _enrich_one(providers, c, "8.8.8.8", cache=cache)
    cache.close()

    assert [r.provider for r in report.results] == expected


# --- resilience: a broken cache must never break a lookup --------------------


def test_corrupt_database_degrades_instead_of_raising(tmp_path):
    db = tmp_path / "corrupt.db"
    db.write_bytes(b"absolutely not a sqlite file" * 40)
    cache = ResultCache(path=db)

    assert cache.get(IOCType.IPV4, "8.8.8.8", "ip-api") is None
    cache.put(IOCType.IPV4, "8.8.8.8", ProviderResult(provider="ip-api", summary="x"))
    assert cache.degraded_reason is not None
    assert cache.stats()["available"] is False
    cache.close()


@pytest.mark.asyncio
async def test_lookup_still_works_with_a_corrupt_cache(tmp_path):
    db = tmp_path / "corrupt.db"
    db.write_bytes(b"garbage" * 100)
    cache = ResultCache(path=db)
    client, calls = _counting_client(lambda r: httpx.Response(200, json=_IPAPI_OK))
    async with client as c:
        report = await _enrich_one([IPAPIProvider()], c, "8.8.8.8", cache=cache)
    cache.close()
    assert calls["n"] == 1
    assert report.results[0].ok, "a broken cache must not break the lookup"


def test_symlinked_cache_path_is_refused(tmp_path):
    """Same TOCTOU class as the config file: a pre-planted symlink would let a
    local attacker redirect our writes and our chmod onto a file of theirs.
    """
    victim = tmp_path / "victim"
    victim.write_text("secret")
    victim.chmod(0o644)
    link = tmp_path / "cache.db"
    link.symlink_to(victim)

    cache = ResultCache(path=link)
    with pytest.raises(CacheError):
        cache.get(IOCType.IPV4, "8.8.8.8", "ip-api")
    assert victim.stat().st_mode & 0o777 == 0o644
    assert victim.read_text() == "secret"


def test_cache_file_and_directory_permissions(tmp_path):
    """The cache records which indicators were investigated — sensitive on a
    shared host.
    """
    cache = ResultCache(path=tmp_path / "sub" / "c.db")
    cache.put(IOCType.IPV4, "8.8.8.8", ProviderResult(provider="p", summary="ok"))
    path = cache.path
    cache.close()
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700


def test_schema_version_mismatch_rebuilds_instead_of_failing(tmp_path):
    """An upgrade must never fail against a cache written by an older release."""
    db = tmp_path / "c.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE provider_results (wrong_column TEXT)")
    conn.execute("PRAGMA user_version = 999")
    conn.commit()
    conn.close()

    cache = ResultCache(path=db)
    cache.put(IOCType.IPV4, "8.8.8.8", ProviderResult(provider="p", summary="ok"))
    hit = cache.get(IOCType.IPV4, "8.8.8.8", "p")
    cache.close()
    assert hit is not None and hit.summary == "ok"


def test_unreadable_row_is_a_miss_not_a_crash(tmp_path):
    db = tmp_path / "c.db"
    cache = ResultCache(path=db)
    cache.put(IOCType.IPV4, "8.8.8.8", ProviderResult(provider="p", summary="ok"))
    cache.close()

    conn = sqlite3.connect(db)
    conn.execute("UPDATE provider_results SET payload = 'not json'")
    conn.commit()
    conn.close()

    cache2 = ResultCache(path=db)
    assert cache2.get(IOCType.IPV4, "8.8.8.8", "p") is None
    cache2.close()


# --- maintenance operations --------------------------------------------------


def test_stats_reports_entries_and_expiry(tmp_path):
    cache = ResultCache(path=tmp_path / "c.db")
    cache.put(IOCType.IPV4, "8.8.8.8", ProviderResult(provider="p", summary="ok"))
    info = cache.stats()
    cache.close()
    assert info["available"] is True
    assert info["entries"] == 1
    assert info["expired"] == 0


def test_clear_removes_everything(tmp_path):
    cache = ResultCache(path=tmp_path / "c.db")
    cache.put(IOCType.IPV4, "8.8.8.8", ProviderResult(provider="a", summary="ok"))
    cache.put(IOCType.IPV4, "1.1.1.1", ProviderResult(provider="b", summary="ok"))
    removed = cache.clear()
    assert removed == 2
    assert cache.get(IOCType.IPV4, "8.8.8.8", "a") is None
    assert cache.stats()["entries"] == 0
    cache.close()


def test_purge_expired_only_drops_stale_entries(tmp_path):
    db = tmp_path / "c.db"
    cache = ResultCache(path=db)
    cache.put(IOCType.IPV4, "8.8.8.8", ProviderResult(provider="p", summary="fresh"))
    cache.close()

    # Back-date the row well past any sane TTL.
    conn = sqlite3.connect(db)
    conn.execute("UPDATE provider_results SET cached_at = ?", (time.time() - 999_999,))
    conn.commit()
    conn.close()

    cache2 = ResultCache(path=db)
    cache2.put(IOCType.IPV4, "1.1.1.1", ProviderResult(provider="p", summary="new"))
    purged = cache2.purge_expired()
    assert purged == 1
    assert cache2.get(IOCType.IPV4, "1.1.1.1", "p") is not None
    cache2.close()


# --- concurrency -------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_access_is_safe(tmp_path):
    """enrich_many runs providers for several IOCs at once against one
    connection; sqlite3 is not thread-safe by default, so this must not corrupt
    or raise.
    """
    cache = ResultCache(path=tmp_path / "c.db")
    client, _ = _counting_client(lambda r: httpx.Response(200, json=_IPAPI_OK))
    async with client as c:
        await asyncio.gather(
            *(
                _enrich_one([IPAPIProvider()], c, f"8.8.8.{i}", cache=cache)
                for i in range(1, 21)
            )
        )
    entries = cache.stats()["entries"]
    cache.close()
    assert entries == 20


@pytest.mark.asyncio
async def test_cached_verdict_matches_the_original(tmp_path):
    """A cached answer must round-trip identically — a verdict that changed on
    the way through the cache would be a silent correctness bug.
    """
    cache = ResultCache(path=tmp_path / "c.db")
    proxy_response = dict(_IPAPI_OK, proxy=True)
    client, _ = _counting_client(lambda r: httpx.Response(200, json=proxy_response))
    async with client as c:
        fresh = await _enrich_one([IPAPIProvider()], c, "8.8.8.8", cache=cache)
        cached = await _enrich_one([IPAPIProvider()], c, "8.8.8.8", cache=cache)
    cache.close()

    assert fresh.overall_verdict is Verdict.SUSPICIOUS
    assert cached.overall_verdict is fresh.overall_verdict
    assert cached.results[0].summary == fresh.results[0].summary
    assert cached.results[0].details == fresh.results[0].details


# --- CLI integration ---------------------------------------------------------


def _run_cli(*args, cache_dir, config_dir):
    import os
    import subprocess
    import sys
    from pathlib import Path

    env = dict(os.environ)
    env["IOCVET_CACHE_DIR"] = str(cache_dir)
    env["IOCVET_CONFIG_DIR"] = str(config_dir)
    return subprocess.run(
        [sys.executable, "-m", "iocvet", *args],
        capture_output=True,
        text=True,
        check=False,
        env=env,
        cwd=str(Path(__file__).parent.parent),
    )


def test_cli_cache_stats_and_clear(tmp_path):
    cache_dir = tmp_path / "cache"
    config_dir = tmp_path / "cfg"
    stats = _run_cli("cache", "stats", cache_dir=cache_dir, config_dir=config_dir)
    assert stats.returncode == 0
    assert "entries" in stats.stdout

    cleared = _run_cli("cache", "clear", cache_dir=cache_dir, config_dir=config_dir)
    assert cleared.returncode == 0
    assert "cleared" in cleared.stdout


def test_cli_no_cache_flag_accepted(tmp_path):
    proc = _run_cli(
        "lookup",
        "10.0.0.1",
        "--no-cache",
        "--json",
        cache_dir=tmp_path / "cache",
        config_dir=tmp_path / "cfg",
    )
    assert proc.returncode == 0
    assert proc.stdout.lstrip().startswith("{")


def test_cli_no_cache_creates_no_database(tmp_path):
    cache_dir = tmp_path / "cache"
    _run_cli(
        "lookup",
        "10.0.0.1",
        "--no-cache",
        "--json",
        cache_dir=cache_dir,
        config_dir=tmp_path / "cfg",
    )
    assert not (cache_dir / "cache.db").exists(), "--no-cache must not touch disk"


# --- audit findings: concurrency, clock skew, growth, poisoning --------------


def test_wal_mode_is_enabled(tmp_path):
    """iocvet is a CLI, so several copies genuinely run at once (a nightly cron
    plus an analyst, or parallel CI jobs). Under SQLite's default journal every
    writer takes a whole-database exclusive lock; measured at 8 of 12
    concurrent processes losing their cache to "database is locked". WAL lets
    readers proceed during a write and removes the contention.
    """
    cache = ResultCache(path=tmp_path / "c.db")
    cache.put(IOCType.IPV4, "8.8.8.8", ProviderResult(provider="p", summary="ok"))
    cache.close()
    mode = (
        sqlite3.connect(tmp_path / "c.db")
        .execute("PRAGMA journal_mode")
        .fetchone()[0]
    )
    assert mode.lower() == "wal"


def test_wal_sidecar_files_are_not_world_readable(tmp_path):
    """The -wal and -shm files hold the same investigative data as the main
    database, so they need the same 0600 treatment.
    """
    cache = ResultCache(path=tmp_path / "c.db")
    cache.put(IOCType.IPV4, "8.8.8.8", ProviderResult(provider="p", summary="ok"))
    cache.close()
    for suffix in ("-wal", "-shm"):
        sidecar = tmp_path / ("c.db" + suffix)
        if sidecar.exists():
            assert sidecar.stat().st_mode & 0o777 == 0o600, f"{sidecar.name} too open"


def test_future_dated_entry_is_not_served(tmp_path):
    """A row stamped in the future (clock jump, restored backup, tampering)
    would never expire under a plain age check — leaving a stale verdict cached
    permanently. For a threat tool an immortal "clean" is exactly wrong.
    """
    db = tmp_path / "c.db"
    cache = ResultCache(path=db)
    cache.put(IOCType.IPV4, "8.8.8.8", ProviderResult(provider="p", summary="ok"))
    cache.close()

    conn = sqlite3.connect(db)
    conn.execute("UPDATE provider_results SET cached_at = ?", (time.time() + 10**9,))
    conn.commit()
    conn.close()

    cache2 = ResultCache(path=db)
    assert cache2.get(IOCType.IPV4, "8.8.8.8", "p") is None
    assert cache2.purge_expired() == 1, "future-dated rows must also be purged"
    cache2.close()


def test_entry_cap_evicts_oldest(tmp_path, monkeypatch):
    """Without a ceiling a large feed would grow the file without bound —
    roughly 4 KB per entry, so 100k entries is ~390 MB in a home directory.
    """
    import iocvet.core.cache as cache_module

    monkeypatch.setattr(cache_module, "MAX_ENTRIES", 50)
    cache = ResultCache(path=tmp_path / "c.db")
    for i in range(120):
        cache.put(
            IOCType.IPV4,
            f"10.0.{i // 256}.{i % 256}",
            ProviderResult(provider="p", summary="x"),
        )
    cache.purge_expired()
    remaining = cache.stats()["entries"]
    cache.close()
    assert remaining <= 50


@pytest.mark.parametrize(
    "hostile",
    [
        "'; DROP TABLE provider_results; --",
        '" OR 1=1 --',
        "8.8.8.8'); DELETE FROM provider_results; --",
    ],
)
def test_sql_injection_through_ioc_value_is_inert(tmp_path, hostile):
    """IOC values come from untrusted feeds and reports. They are bound as
    parameters, never interpolated, so they can only ever be data.
    """
    db = tmp_path / "c.db"
    cache = ResultCache(path=db)
    cache.put(IOCType.DOMAIN, hostile, ProviderResult(provider="p", summary="x"))
    cache.put(IOCType.DOMAIN, "normal.com", ProviderResult(provider="p", summary="y"))
    assert cache.get(IOCType.DOMAIN, hostile, "p") is not None
    cache.close()

    rows = sqlite3.connect(db).execute("SELECT COUNT(*) FROM provider_results").fetchone()[0]
    assert rows == 2, "table must survive; the value is data, not SQL"


@pytest.mark.parametrize(
    "payload",
    [
        "not json at all",
        "null",
        "[1, 2, 3]",
        '{"provider": "p", "verdict": "not_a_real_verdict"}',
        "[" * 500 + "]" * 500,
    ],
)
def test_hostile_cache_payload_is_a_safe_miss(tmp_path, payload):
    """A tampered or corrupt row must degrade to a cache miss, never crash the
    lookup and never execute anything.
    """
    db = tmp_path / "c.db"
    cache = ResultCache(path=db)
    cache.put(IOCType.IPV4, "8.8.8.8", ProviderResult(provider="p", summary="ok"))
    cache.close()

    conn = sqlite3.connect(db)
    conn.execute("UPDATE provider_results SET payload = ?", (payload,))
    conn.commit()
    conn.close()

    cache2 = ResultCache(path=db)
    assert cache2.get(IOCType.IPV4, "8.8.8.8", "p") is None
    cache2.close()


@pytest.mark.asyncio
async def test_api_key_never_written_to_the_cache_file(tmp_path):
    secret = "SUPER_SECRET_KEY_9999"
    db = tmp_path / "c.db"
    cache = ResultCache(path=db)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "abuseConfidenceScore": 10,
                    "totalReports": 2,
                    "isWhitelisted": False,
                    "countryCode": "US",
                    "isp": "Example",
                }
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        await _enrich_one([AbuseIPDBProvider(api_key=secret)], c, "8.8.8.8", cache=cache)
    cache.close()

    assert secret.encode() not in db.read_bytes()


@pytest.mark.asyncio
async def test_private_ip_is_never_cached(tmp_path):
    """The private-IP guard short-circuits before any request, so there is no
    answer to cache — and caching the skip would be wrong anyway.
    """
    db = tmp_path / "c.db"
    cache = ResultCache(path=db)
    client, _ = _counting_client(lambda r: httpx.Response(200, json=_IPAPI_OK))
    async with client as c:
        await _enrich_one([IPAPIProvider()], c, "169.254.169.254", cache=cache)
    cache.close()
    rows = sqlite3.connect(db).execute("SELECT COUNT(*) FROM provider_results").fetchone()[0]
    assert rows == 0


def test_unusable_cache_location_degrades_without_raising(tmp_path):
    """A cache that cannot be created (read-only volume, path blocked by a
    file) must never stop the tool from running.
    """
    blocker = tmp_path / "blocked"
    blocker.write_text("i am a file, not a directory")
    cache = ResultCache(path=blocker / "c.db")

    assert cache.get(IOCType.IPV4, "8.8.8.8", "p") is None
    cache.put(IOCType.IPV4, "8.8.8.8", ProviderResult(provider="p", summary="x"))
    assert cache.degraded_reason is not None
    assert cache.stats()["available"] is False
    cache.close()
