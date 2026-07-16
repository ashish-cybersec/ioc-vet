"""Tests for domain enrichment: the RDAP provider and URLhaus host lookup.

As in test_providers.py, everything is mocked — no live key or network needed.
Where a request's shape matters (parameter names, redirect handling), the
tests capture the outgoing request and assert on it rather than trusting a
canned response to prove anything.
"""

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from iocvet.core.models import IOCType, Verdict
from iocvet.providers.rdap import RDAPProvider
from iocvet.providers.urlhaus import URLhausProvider


def _client(json_body: dict, status_code: int = 200) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json=json_body)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _iso_days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rdap_body(registered_days_ago: int) -> dict:
    return {
        "objectClassName": "domain",
        "ldhName": "example.com",
        "status": ["client transfer prohibited"],
        "events": [
            {"eventAction": "registration", "eventDate": _iso_days_ago(registered_days_ago)},
            {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "handle": "292",
                "vcardArray": [
                    "vcard",
                    [["version", {}, "text", "4.0"], ["fn", {}, "text", "MarkMonitor Inc."]],
                ],
            }
        ],
        "nameservers": [{"ldhName": "ns1.example.com"}, {"ldhName": "ns2.example.com"}],
    }


# --- RDAP --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rdap_only_supports_domains():
    provider = RDAPProvider()
    assert provider.supports(IOCType.DOMAIN)
    assert not provider.supports(IOCType.IPV4)
    assert not provider.supports(IOCType.URL)
    assert not provider.supports(IOCType.MD5)


@pytest.mark.asyncio
async def test_rdap_needs_no_api_key():
    """The zero-config promise: rdap must run for a user with no keys at all."""
    provider = RDAPProvider()
    assert provider.is_configured


@pytest.mark.asyncio
async def test_rdap_old_domain_is_unknown_not_clean():
    """An old domain is not a verified-safe domain. RDAP has no reputation
    data, so it must never claim CLEAN.
    """
    provider = RDAPProvider()
    async with _client(_rdap_body(registered_days_ago=4000)) as client:
        result = await provider.run(client, "example.com", IOCType.DOMAIN)

    assert result.ok
    assert result.verdict == Verdict.UNKNOWN
    assert "MarkMonitor" in result.summary
    assert result.details["age_days"] > 3000
    assert result.details["registrar"] == "MarkMonitor Inc."


@pytest.mark.asyncio
async def test_rdap_newly_registered_domain_is_suspicious():
    provider = RDAPProvider()
    async with _client(_rdap_body(registered_days_ago=3)) as client:
        result = await provider.run(client, "totally-legit-bank.com", IOCType.DOMAIN)

    assert result.verdict == Verdict.SUSPICIOUS
    assert "newly registered" in result.summary
    assert result.details["age_days"] == 3


@pytest.mark.asyncio
async def test_rdap_boundary_just_over_threshold_is_unknown():
    provider = RDAPProvider()
    async with _client(_rdap_body(registered_days_ago=31)) as client:
        result = await provider.run(client, "example.com", IOCType.DOMAIN)

    assert result.verdict == Verdict.UNKNOWN


@pytest.mark.asyncio
async def test_rdap_follows_redirects():
    """rdap.org is a bootstrap server: it answers 302 and points at whichever
    registry is authoritative for the TLD. httpx does not follow redirects by
    default, so without follow_redirects the provider would parse the 302 body
    and find nothing.
    """
    provider = RDAPProvider()
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if "rdap.org" in str(request.url):
            return httpx.Response(
                302, headers={"Location": "https://rdap.verisign.com/com/v1/domain/example.com"}
            )
        return httpx.Response(200, json=_rdap_body(4000))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await provider.run(client, "example.com", IOCType.DOMAIN)

    assert len(seen) == 2, "expected the 302 to be followed to the registry"
    assert "verisign" in seen[1]
    assert result.ok


@pytest.mark.asyncio
async def test_rdap_404_is_unknown_not_error():
    """Plenty of ccTLDs still publish no RDAP server. A 404 means 'no data',
    not 'this lookup failed' — and definitely not 'safe'.
    """
    provider = RDAPProvider()
    async with _client({}, status_code=404) as client:
        result = await provider.run(client, "example.io", IOCType.DOMAIN)

    assert result.verdict == Verdict.UNKNOWN
    assert result.error is None
    assert "no RDAP record" in result.summary


@pytest.mark.asyncio
async def test_rdap_handles_missing_registration_event():
    """Some registries omit the registration event entirely. That must not
    crash, and must not be mistaken for a new domain.
    """
    provider = RDAPProvider()
    body = {"objectClassName": "domain", "events": [], "entities": []}
    async with _client(body) as client:
        result = await provider.run(client, "example.com", IOCType.DOMAIN)

    assert result.ok
    assert result.verdict == Verdict.UNKNOWN
    assert result.details["age_days"] is None
    assert "not published" in result.summary


@pytest.mark.asyncio
async def test_rdap_parses_z_suffix_dates_on_py310():
    """RDAP timestamps end in 'Z'. datetime.fromisoformat only accepts that
    from 3.11, and this project supports 3.10 — so the provider normalizes it
    itself. This asserts the parse actually happened.
    """
    provider = RDAPProvider()
    async with _client(_rdap_body(registered_days_ago=100)) as client:
        result = await provider.run(client, "example.com", IOCType.DOMAIN)

    assert result.details["registered"] is not None
    assert result.details["age_days"] == 100


# --- URLhaus host ------------------------------------------------------------


@pytest.mark.asyncio
async def test_urlhaus_now_supports_domains():
    provider = URLhausProvider(api_key="fake-key-for-test")
    assert provider.supports(IOCType.DOMAIN)


@pytest.mark.asyncio
async def test_urlhaus_host_uses_host_param():
    provider = URLhausProvider(api_key="fake-key-for-test")
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"query_status": "no_results"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await provider.run(client, "evil.tld", IOCType.DOMAIN)

    assert captured[0].url.path.endswith("/host/")
    assert "host=evil.tld" in captured[0].content.decode()


@pytest.mark.asyncio
async def test_urlhaus_host_online_urls_are_malicious():
    provider = URLhausProvider(api_key="fake-key-for-test")
    body = {
        "query_status": "ok",
        "urlhaus_reference": "https://urlhaus.abuse.ch/host/evil.tld/",
        "firstseen": "2026-01-01",
        "url_count": "12",
        "blacklists": {"spamhaus_dbl": "abused_legit_malware", "surbl": "not listed"},
        "urls": [
            {"url_status": "online", "url": "http://evil.tld/a"},
            {"url_status": "offline", "url": "http://evil.tld/b"},
        ],
    }
    async with _client(body) as client:
        result = await provider.run(client, "evil.tld", IOCType.DOMAIN)

    assert result.verdict == Verdict.MALICIOUS
    assert "1 malware URL(s) currently online" in result.summary
    assert "spamhaus_dbl" in result.summary
    assert result.details["url_count"] == 12
    assert result.link == "https://urlhaus.abuse.ch/host/evil.tld/"


@pytest.mark.asyncio
async def test_urlhaus_host_historical_only_is_suspicious_not_malicious():
    """A cleaned-up compromised site shouldn't be branded MALICIOUS forever.
    Shared hosts and CDNs would otherwise be permanently condemned.
    """
    provider = URLhausProvider(api_key="fake-key-for-test")
    body = {
        "query_status": "ok",
        "urlhaus_reference": "https://urlhaus.abuse.ch/host/wasclean.tld/",
        "url_count": "3",
        "blacklists": {"surbl": "not listed"},
        "urls": [{"url_status": "offline"}, {"url_status": "offline"}],
    }
    async with _client(body) as client:
        result = await provider.run(client, "wasclean.tld", IOCType.DOMAIN)

    assert result.verdict == Verdict.SUSPICIOUS
    assert "none currently online" in result.summary


@pytest.mark.asyncio
async def test_urlhaus_host_unknown_domain_is_unknown_not_clean():
    provider = URLhausProvider(api_key="fake-key-for-test")
    async with _client({"query_status": "no_results"}) as client:
        result = await provider.run(client, "example.com", IOCType.DOMAIN)

    assert result.verdict == Verdict.UNKNOWN


@pytest.mark.asyncio
async def test_urlhaus_host_missing_urls_array_falls_back_to_count():
    """The documented host response shows url_count without a urls array.
    Don't crash, and don't infer 'nothing online' as 'nothing recorded'.
    """
    provider = URLhausProvider(api_key="fake-key-for-test")
    body = {"query_status": "ok", "url_count": "7", "firstseen": "2026-01-01"}
    async with _client(body) as client:
        result = await provider.run(client, "evil.tld", IOCType.DOMAIN)

    assert result.verdict == Verdict.SUSPICIOUS
    assert result.details["url_count"] == 7


@pytest.mark.asyncio
async def test_rdap_parses_real_world_example_com_response():
    """Regression fixture captured from a live `curl https://rdap.org/domain/example.com`.

    Mocks written from a spec can silently agree with a buggy parser; this one
    is real registry output, Z-suffix timestamps and all. example.com was
    registered in 1995, so it must land far outside the new-domain threshold.
    """
    provider = RDAPProvider()
    body = {
        "objectClassName": "domain",
        "ldhName": "EXAMPLE.COM",
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2026-01-16T18:26:50Z"},
        ],
        "status": ["client delete prohibited"],
        "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}, {"ldhName": "B.IANA-SERVERS.NET"}],
    }
    async with _client(body) as client:
        result = await provider.run(client, "example.com", IOCType.DOMAIN)

    assert result.ok
    assert result.verdict == Verdict.UNKNOWN
    assert result.details["registered"].startswith("1995-08-14")
    assert result.details["age_days"] > 10000
    assert result.details["nameservers"] == ["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"]
    assert "registered 1995-08-14" in result.summary
