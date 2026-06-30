"""AbuseIPDB — free tier allows 1,000 checks/day with a free account.
Sign up: https://www.abuseipdb.com/register (then grab a key from
https://www.abuseipdb.com/account/api).
"""

from __future__ import annotations

import httpx

from iocvet.core.models import IOCType, ProviderResult, Verdict
from iocvet.providers.base import Provider

_API_URL = "https://api.abuseipdb.com/api/v2/check"

# AbuseIPDB returns a 0-100 "confidence of abuse" score, not a verdict —
# these thresholds are a deliberately conservative mapping onto ours.
_MALICIOUS_THRESHOLD = 75
_SUSPICIOUS_THRESHOLD = 25


class AbuseIPDBProvider(Provider):
    name = "abuseipdb"
    requires_key = True
    api_key_env = "ABUSEIPDB_API_KEY"

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in (IOCType.IPV4, IOCType.IPV6)

    async def _query(self, client: httpx.AsyncClient, ioc: str, ioc_type: IOCType) -> ProviderResult:
        resp = await client.get(
            _API_URL,
            params={"ipAddress": ioc, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": self.api_key or "", "Accept": "application/json"},
            timeout=self.timeout_seconds,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})

        score = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)

        if score >= _MALICIOUS_THRESHOLD:
            verdict = Verdict.MALICIOUS
        elif score >= _SUSPICIOUS_THRESHOLD or reports > 0:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.CLEAN

        categories = sorted(
            {cat for r in data.get("reports", [])[:10] for cat in r.get("categories", [])}
        )

        return ProviderResult(
            provider=self.name,
            verdict=verdict,
            summary=f"abuse confidence {score}/100 across {reports} report(s)",
            details={
                "abuse_confidence_score": score,
                "total_reports": reports,
                "is_whitelisted": data.get("isWhitelisted"),
                "category_codes": categories,
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
            },
            link=f"https://www.abuseipdb.com/check/{ioc}",
        )
