"""ip-api.com — free, no API key, no signup. Non-commercial use only per
their terms (https://ip-api.com/docs/legal). Note the endpoint is plain
HTTP: SSL is a paid-tier feature on their side, not a choice we're making.

This provider doesn't return a malicious/clean verdict by itself — it has
no reputation data — but it's the one provider that works for every user
immediately with zero setup, so it anchors the "context" section of a
report even when nothing else is configured.
"""

from __future__ import annotations

import httpx

from iocvet.core.models import IOCType, ProviderResult, Verdict
from iocvet.providers.base import Provider

_FIELDS = "status,message,country,regionName,city,isp,org,as,proxy,hosting,query"


class IPAPIProvider(Provider):
    name = "ip-api"
    requires_key = False
    # Documented free-tier cap is 45/min; 40 leaves headroom for retries and
    # for the fact that the window is enforced per source IP, not per process.
    rate_limit_per_minute = 40

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in (IOCType.IPV4, IOCType.IPV6)

    async def _query(self, client: httpx.AsyncClient, ioc: str, ioc_type: IOCType) -> ProviderResult:
        resp = await client.get(
            f"http://ip-api.com/json/{ioc}",
            params={"fields": _FIELDS},
            timeout=self.timeout_seconds,
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") != "success":
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.UNKNOWN,
                error=data.get("message", "lookup failed"),
            )

        is_hosting = bool(data.get("hosting"))
        is_proxy = bool(data.get("proxy"))
        # ip-api gives context, not reputation — "suspicious" only flags
        # known proxy/VPN exit nodes, which is worth surfacing, not damning.
        verdict = Verdict.SUSPICIOUS if is_proxy else Verdict.UNKNOWN

        location = ", ".join(
            part for part in (data.get("city"), data.get("regionName"), data.get("country")) if part
        )
        summary_bits = [location or "location unknown"]
        if data.get("org"):
            summary_bits.append(data["org"])
        if is_proxy:
            summary_bits.append("known proxy/VPN exit node")
        if is_hosting:
            summary_bits.append("hosting/datacenter IP")

        return ProviderResult(
            provider=self.name,
            verdict=verdict,
            summary=" · ".join(summary_bits),
            details={
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "asn": data.get("as"),
                "is_proxy": is_proxy,
                "is_hosting": is_hosting,
            },
        )
