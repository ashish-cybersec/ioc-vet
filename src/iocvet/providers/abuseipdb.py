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
# these thresholds map it onto ours.
#
# The score is AbuseIPDB's own aggregate judgement: it already weights reporter
# reputation and decays with age. Report *count* is not a substitute for it.
# An earlier version flagged SUSPICIOUS on `totalReports > 0` regardless of
# score, which meant any address carrying a single stale misreport — including
# heavily-misreported public resolvers like 8.8.8.8, this project's own README
# example — came back SUSPICIOUS. A tool that cries wolf on Google DNS trains
# its users to ignore it. The score drives the verdict; the report count is
# shown in the summary as context.
_MALICIOUS_THRESHOLD = 75
_SUSPICIOUS_THRESHOLD = 25


class AbuseIPDBProvider(Provider):
    name = "abuseipdb"
    requires_key = True
    api_key_env = "ABUSEIPDB_API_KEY"

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in (IOCType.IPV4, IOCType.IPV6)

    async def _query(
        self, client: httpx.AsyncClient, ioc: str, ioc_type: IOCType
    ) -> ProviderResult:
        resp = await client.get(
            _API_URL,
            params={"ipAddress": ioc, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": self.api_key or "", "Accept": "application/json"},
            timeout=self.timeout_seconds,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})

        # `or 0` rather than a get() default: the API can return an explicit
        # null, which a default doesn't catch and which would blow up on
        # comparison.
        score = data.get("abuseConfidenceScore") or 0
        reports = data.get("totalReports") or 0
        whitelisted = bool(data.get("isWhitelisted"))

        if score >= _MALICIOUS_THRESHOLD:
            # A high score outranks the whitelist: whitelisting is a hint, not
            # an override, and a compromised well-known host is exactly the
            # case worth surfacing.
            verdict = Verdict.MALICIOUS
        elif whitelisted:
            # AbuseIPDB actively vouches for this address (major DNS resolvers,
            # search-engine crawlers, and similar).
            verdict = Verdict.CLEAN
        elif score >= _SUSPICIOUS_THRESHOLD:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.CLEAN

        categories = sorted(
            {cat for r in data.get("reports", [])[:10] for cat in r.get("categories", [])}
        )

        return ProviderResult(
            provider=self.name,
            verdict=verdict,
            summary=(
                f"abuse confidence {score}/100 across {reports} report(s)"
                + (" · whitelisted by AbuseIPDB" if whitelisted else "")
            ),
            details={
                "abuse_confidence_score": score,
                "total_reports": reports,
                "is_whitelisted": whitelisted,
                "category_codes": categories,
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
            },
            link=f"https://www.abuseipdb.com/check/{ioc}",
        )
