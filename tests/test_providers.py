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
async def test_urlhaus_supports_hashes_and_urls_only():
    provider = URLhausProvider(api_key="fake-key-for-test")
    assert provider.supports(IOCType.URL)
    assert provider.supports(IOCType.MD5)
    assert provider.supports(IOCType.SHA256)
    assert not provider.supports(IOCType.IPV4)
    assert not provider.supports(IOCType.DOMAIN)
