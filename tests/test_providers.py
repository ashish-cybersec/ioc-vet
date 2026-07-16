"""Provider tests use httpx.MockTransport to simulate real API responses
without making live network calls. The fixture payloads below are shaped
to match each provider's actual documented schema, so these tests catch
parsing bugs even though they never touch the network.
"""

import httpx
import pytest

from iocvet.core.models import IOCType, Verdict
from iocvet.providers.abuseipdb import AbuseIPDBProvider
from iocvet.providers.ipapi import IPAPIProvider
from iocvet.providers.urlhaus import URLhausProvider


def _client_with(json_body: dict, status_code: int = 200) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json=json_body)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_ipapi_clean_ip():
    provider = IPAPIProvider()
    body = {
        "status": "success",
        "country": "United States",
        "regionName": "California",
        "city": "Mountain View",
        "isp": "Google LLC",
        "org": "Google Public DNS",
        "as": "AS15169 Google LLC",
        "proxy": False,
        "hosting": True,
        "query": "8.8.8.8",
    }
    async with _client_with(body) as client:
        result = await provider.run(client, "8.8.8.8", IOCType.IPV4)

    assert result.ok
    assert result.verdict == Verdict.UNKNOWN  # no reputation signal, just context
    assert "Mountain View" in result.summary
    assert result.details["is_hosting"] is True


@pytest.mark.asyncio
async def test_ipapi_flags_proxy_as_suspicious():
    provider = IPAPIProvider()
    body = {
        "status": "success",
        "country": "Germany",
        "regionName": "Hesse",
        "city": "Frankfurt",
        "isp": "M247",
        "org": "M247 Europe SRL",
        "as": "AS9009",
        "proxy": True,
        "hosting": True,
        "query": "185.220.101.45",
    }
    async with _client_with(body) as client:
        result = await provider.run(client, "185.220.101.45", IOCType.IPV4)

    assert result.verdict == Verdict.SUSPICIOUS
    assert "proxy" in result.summary.lower()


@pytest.mark.asyncio
async def test_ipapi_skips_non_ip_types():
    provider = IPAPIProvider()
    async with _client_with({}) as client:
        result = await provider.run(client, "example.com", IOCType.DOMAIN)

    assert result.skipped_reason is not None
    assert not result.ok


@pytest.mark.asyncio
async def test_abuseipdb_requires_key_when_unconfigured():
    provider = AbuseIPDBProvider(api_key=None)
    async with _client_with({}) as client:
        result = await provider.run(client, "1.2.3.4", IOCType.IPV4)

    assert result.skipped_reason is not None
    assert "ABUSEIPDB_API_KEY" in result.skipped_reason


@pytest.mark.asyncio
async def test_abuseipdb_high_score_is_malicious():
    provider = AbuseIPDBProvider(api_key="fake-key-for-test")
    body = {
        "data": {
            "ipAddress": "1.2.3.4",
            "abuseConfidenceScore": 92,
            "totalReports": 47,
            "isWhitelisted": False,
            "countryCode": "RU",
            "isp": "Some ISP",
            "reports": [{"categories": [18, 20]}],
        }
    }
    async with _client_with(body) as client:
        result = await provider.run(client, "1.2.3.4", IOCType.IPV4)

    assert result.verdict == Verdict.MALICIOUS
    assert result.details["abuse_confidence_score"] == 92
    assert result.link.endswith("1.2.3.4")


@pytest.mark.asyncio
async def test_abuseipdb_zero_score_is_clean():
    provider = AbuseIPDBProvider(api_key="fake-key-for-test")
    body = {
        "data": {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": 0,
            "totalReports": 0,
            "isWhitelisted": True,
            "countryCode": "US",
            "isp": "Google",
            "reports": [],
        }
    }
    async with _client_with(body) as client:
        result = await provider.run(client, "8.8.8.8", IOCType.IPV4)

    assert result.verdict == Verdict.CLEAN


@pytest.mark.asyncio
async def test_urlhaus_known_malicious_url():
    provider = URLhausProvider(api_key="fake-key-for-test")
    body = {
        "query_status": "ok",
        "id": "223622",
        "urlhaus_reference": "https://urlhaus.abuse.ch/url/223622/",
        "url": "http://evil.tld/bad",
        "url_status": "online",
        "host": "evil.tld",
        "date_added": "2026-01-01 00:00:00 UTC",
        "threat": "malware_download",
        "tags": ["emotet"],
    }
    async with _client_with(body) as client:
        result = await provider.run(client, "http://evil.tld/bad", IOCType.URL)

    assert result.verdict == Verdict.MALICIOUS
    assert "emotet" in result.summary
    assert result.link == "https://urlhaus.abuse.ch/url/223622/"


@pytest.mark.asyncio
async def test_urlhaus_unknown_url_returns_unknown_not_clean():
    """Absence from a malware database isn't proof of safety — should map
    to UNKNOWN, never CLEAN, since URLhaus has no concept of 'verified safe'.
    """
    provider = URLhausProvider(api_key="fake-key-for-test")
    body = {"query_status": "no_results"}
    async with _client_with(body) as client:
        result = await provider.run(client, "http://totally-fine.example/", IOCType.URL)

    assert result.verdict == Verdict.UNKNOWN


@pytest.mark.asyncio
async def test_urlhaus_supported_ioc_types():
    # DOMAIN was added when the /host/ endpoint was wired up; see
    # tests/test_domains.py for the host-lookup behaviour itself. IPs are
    # still out of scope here even though /host/ accepts them — see the
    # note in providers/urlhaus.py.
    provider = URLhausProvider(api_key="fake-key-for-test")
    assert provider.supports(IOCType.URL)
    assert provider.supports(IOCType.DOMAIN)
    assert provider.supports(IOCType.MD5)
    assert provider.supports(IOCType.SHA256)
    assert not provider.supports(IOCType.IPV4)


# --- Request-shape tests -----------------------------------------------------
# The _client_with helper above returns a canned body no matter what the request
# looked like, which means it cannot catch a provider sending the wrong
# parameter name. These tests capture the outgoing request and assert on it.


def _capturing_client(json_body: dict, captured: list[httpx.Request]) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json=json_body)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


_PAYLOAD_BODY = {
    "query_status": "ok",
    "md5_hash": "44d88612fea8a8f36de82e1278abb02f",
    "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "file_type": "exe",
    "signature": "Emotet",
    "firstseen": "2026-01-01",
    "virustotal": {"result": "42/70", "link": "https://virustotal.com/x"},
}


@pytest.mark.asyncio
async def test_urlhaus_md5_uses_md5_hash_param():
    """URLhaus indexes payloads under md5_hash/sha256_hash. Posting a generic
    'hash' param returns no_results — a false negative on real malware.
    """
    provider = URLhausProvider(api_key="fake-key-for-test")
    captured: list[httpx.Request] = []
    async with _capturing_client(_PAYLOAD_BODY, captured) as client:
        result = await provider.run(client, "44d88612fea8a8f36de82e1278abb02f", IOCType.MD5)

    assert result.verdict == Verdict.MALICIOUS
    assert "md5_hash=44d88612fea8a8f36de82e1278abb02f" in captured[0].content.decode()


@pytest.mark.asyncio
async def test_urlhaus_sha256_uses_sha256_hash_param():
    provider = URLhausProvider(api_key="fake-key-for-test")
    sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    captured: list[httpx.Request] = []
    async with _capturing_client(_PAYLOAD_BODY, captured) as client:
        result = await provider.run(client, sha, IOCType.SHA256)

    assert result.verdict == Verdict.MALICIOUS
    assert f"sha256_hash={sha}" in captured[0].content.decode()


@pytest.mark.asyncio
async def test_urlhaus_does_not_claim_sha1_support():
    """URLhaus has no SHA1 index. Claiming support would map every SHA1 lookup
    onto a silent 'not found' rather than an honest skip.
    """
    provider = URLhausProvider(api_key="fake-key-for-test")
    assert not provider.supports(IOCType.SHA1)

    async with _client_with({}) as client:
        result = await provider.run(client, "da39a3ee5e6b4b0d3255bfef95601890afd80709", IOCType.SHA1)
    assert result.skipped_reason is not None


@pytest.mark.asyncio
async def test_rate_limited_response_is_reported_clearly():
    provider = IPAPIProvider()
    provider._limiter = None  # don't actually sleep in tests

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await provider.run(client, "8.8.8.8", IOCType.IPV4)

    assert result.error is not None
    assert "429" in result.error
