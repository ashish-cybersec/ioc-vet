"""RDAP (Registration Data Access Protocol) — free, no API key, no signup.

RDAP is the IETF/ICANN-mandated successor to WHOIS: same registration data,
but structured JSON instead of a 40-year-old freeform text format. We query
rdap.org, a bootstrap server that redirects each lookup to the registry
authoritative for that TLD.

Like ip-api, this provider returns context rather than reputation — a registry
has no opinion on whether a domain is malicious. The one signal worth acting
on is age: newly registered domains are heavily over-represented in phishing
and malware campaigns, because attackers burn domains faster than they age
them. So a domain registered days ago is flagged SUSPICIOUS, and everything
else is UNKNOWN. An old domain is not a safe domain, so it is never CLEAN.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from iocvet.core.models import IOCType, ProviderResult, Verdict
from iocvet.providers.base import Provider

_BOOTSTRAP_URL = "https://rdap.org/domain"

#: A domain younger than this is worth a second look. 30 days is the common
#: industry threshold for "newly registered domain" in phishing detection.
_NEW_DOMAIN_DAYS = 30


def _parse_rdap_date(value: str | None) -> datetime | None:
    """Parse an RDAP ISO-8601 timestamp into an aware datetime.

    RDAP dates usually end in "Z". `datetime.fromisoformat` only learned to
    accept that suffix in 3.11, and we still support 3.10 — so normalize it
    by hand rather than depending on the interpreter version.
    """
    if not value:
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _event_date(data: dict[str, Any], action: str) -> datetime | None:
    """Pull one eventDate out of RDAP's events array by its eventAction."""
    for event in data.get("events") or []:
        if not isinstance(event, dict):
            continue
        if event.get("eventAction") == action:
            return _parse_rdap_date(event.get("eventDate"))
    return None


def _registrar_name(data: dict[str, Any]) -> str | None:
    """Dig the registrar's name out of RDAP's jCard structure.

    Entities carry a `vcardArray` shaped like:
        ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Name"]]]
    We want the "fn" (full name) field. Every layer is defensively checked
    because registries vary in what they actually populate.
    """
    for entity in data.get("entities") or []:
        if not isinstance(entity, dict):
            continue
        if "registrar" not in (entity.get("roles") or []):
            continue
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
            for field in vcard[1]:
                if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                    return str(field[3])
        if entity.get("handle"):
            return f"IANA {entity['handle']}"
    return None


def _humanize_age(days: int) -> str:
    if days < 1:
        return "today"
    if days < 60:
        return f"{days}d ago"
    if days < 730:
        return f"{days // 30}mo ago"
    return f"{days // 365}y ago"


class RDAPProvider(Provider):
    name = "rdap"
    requires_key = False
    # rdap.org sits behind Cloudflare, which allows 10 requests per 10 seconds
    # before returning 429. That's 60/min; 50 leaves room for the redirect hop.
    rate_limit_per_minute = 50

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type == IOCType.DOMAIN

    async def _query(self, client: httpx.AsyncClient, ioc: str, ioc_type: IOCType) -> ProviderResult:
        # rdap.org answers with a 302 to whichever registry is authoritative
        # for the TLD, so redirects must be followed explicitly — httpx does
        # not follow them by default.
        resp = await client.get(
            f"{_BOOTSTRAP_URL}/{ioc}",
            timeout=self.timeout_seconds,
            follow_redirects=True,
            headers={"Accept": "application/rdap+json"},
        )

        if resp.status_code == 404:
            # Either the domain isn't registered, or the TLD publishes no RDAP
            # server (a handful of ccTLDs still don't). Neither is an error,
            # and neither means the domain is safe.
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.UNKNOWN,
                summary="no RDAP record (unregistered, or TLD has no RDAP server)",
            )
        resp.raise_for_status()
        data = resp.json()

        registered = _event_date(data, "registration")
        expires = _event_date(data, "expiration")
        registrar = _registrar_name(data)

        verdict = Verdict.UNKNOWN
        age_days: int | None = None
        if registered is not None:
            age_days = (datetime.now(timezone.utc) - registered).days
            if age_days < _NEW_DOMAIN_DAYS:
                verdict = Verdict.SUSPICIOUS

        if registered is not None and age_days is not None:
            summary_bits = [f"registered {registered.date().isoformat()} ({_humanize_age(age_days)})"]
            if age_days < _NEW_DOMAIN_DAYS:
                summary_bits.append(f"newly registered (<{_NEW_DOMAIN_DAYS}d)")
        else:
            summary_bits = ["registration date not published"]
        if registrar:
            summary_bits.append(registrar)

        return ProviderResult(
            provider=self.name,
            verdict=verdict,
            summary=" · ".join(summary_bits),
            details={
                "registered": registered.isoformat() if registered else None,
                "expires": expires.isoformat() if expires else None,
                "age_days": age_days,
                "registrar": registrar,
                "status": data.get("status") or [],
                "nameservers": [
                    ns.get("ldhName")
                    for ns in (data.get("nameservers") or [])
                    if isinstance(ns, dict) and ns.get("ldhName")
                ],
            },
            link=f"https://client.rdap.org/?type=domain&object={ioc}",
        )
