"""Runs every registered provider concurrently against one IOC and merges
the results into a single EnrichmentReport. This is the only place that
needs to know about asyncio — providers themselves stay simple.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable, Sequence

import httpx

from iocvet import __version__
from iocvet.config import get_api_key
from iocvet.core.detector import detect_ioc_type, normalize
from iocvet.core.models import EnrichmentReport, IOCType
from iocvet.providers import ALL_PROVIDERS, Provider

_USER_AGENT = f"iocvet/{__version__} (+https://github.com/ashish-cybersec/ioc-vet)"

#: Defensive caps for the shared HTTP client. A hostile or MITM'd endpoint
#: (ip-api is plaintext) could otherwise stream unbounded data into memory or
#: exhaust sockets during a large batch run.
_LIMITS = httpx.Limits(max_connections=20, max_keepalive_connections=10)

#: How many IOCs to have in flight at once during a batch run. Per-provider
#: rate limits do the real pacing; this just caps socket/memory use.
_DEFAULT_CONCURRENCY = 8


def _instantiate_providers() -> list[Provider]:
    instances: list[Provider] = []
    for provider_cls in ALL_PROVIDERS:
        api_key = None
        if provider_cls.requires_key and provider_cls.api_key_env:
            # Convention: env var ABUSEIPDB_API_KEY -> toml key "abuseipdb"
            toml_key = provider_cls.api_key_env.removesuffix("_API_KEY").removesuffix(
                "_AUTH_KEY"
            ).lower()
            api_key = get_api_key(provider_cls.api_key_env, toml_key)
        instances.append(provider_cls(api_key=api_key))
    return instances


async def _enrich_one(
    providers: Sequence[Provider],
    client: httpx.AsyncClient,
    raw_ioc: str,
    ioc_type: IOCType | None = None,
) -> EnrichmentReport:
    resolved_type = ioc_type or detect_ioc_type(raw_ioc)
    ioc = normalize(raw_ioc, resolved_type)

    results = await asyncio.gather(*(p.run(client, ioc, resolved_type) for p in providers))

    report = EnrichmentReport(ioc=ioc, ioc_type=resolved_type, results=list(results))
    report.overall_verdict = report.compute_overall_verdict()
    return report


async def enrich(raw_ioc: str, *, ioc_type: IOCType | None = None) -> EnrichmentReport:
    """Detect (or accept a forced) IOC type, run every applicable provider
    concurrently, and return a populated report.
    """
    providers = _instantiate_providers()
    async with httpx.AsyncClient(headers={"User-Agent": _USER_AGENT}, limits=_LIMITS) as client:
        return await _enrich_one(providers, client, raw_ioc, ioc_type)


async def enrich_many(
    raw_iocs: Iterable[str], *, concurrency: int = _DEFAULT_CONCURRENCY
) -> list[EnrichmentReport]:
    """Enrich a batch of IOCs, reusing one HTTP client and one set of provider
    instances across the whole run.

    Reuse is not just an optimization: each provider's rate limiter is instance
    state, so building fresh providers per IOC (the obvious approach) would let
    every lookup start with a clean quota and blow straight through the free
    tier's cap.

    Duplicate IOCs are looked up once. A batch file with the same address on
    ten lines — or "evil.com" and "EVIL.COM", which normalize identically —
    would otherwise fire ten times per provider, wasting rate-limited quota
    (AbuseIPDB's free tier is 1000/day) and multiplying latency for no new
    information. Each distinct IOC is queried once; the returned list still has
    one report per *unique* input, in first-seen order.
    """
    iocs = list(raw_iocs)
    providers = _instantiate_providers()
    semaphore = asyncio.Semaphore(concurrency)

    # De-duplicate by (detected type, normalized value) — the exact key that
    # determines the actual query — while preserving first-seen order.
    unique: list[str] = []
    seen: set[tuple[IOCType, str]] = set()
    for raw in iocs:
        ioc_type = detect_ioc_type(raw)
        key = (ioc_type, normalize(raw, ioc_type))
        if key not in seen:
            seen.add(key)
            unique.append(raw)

    async with httpx.AsyncClient(headers={"User-Agent": _USER_AGENT}, limits=_LIMITS) as client:

        async def _bounded(ioc: str) -> EnrichmentReport:
            async with semaphore:
                return await _enrich_one(providers, client, ioc)

        return list(await asyncio.gather(*(_bounded(ioc) for ioc in unique)))


def list_provider_status() -> list[dict[str, object]]:
    """Used by `iocvet providers` to show what's configured without making
    any network calls.
    """
    rows = []
    for provider in _instantiate_providers():
        rows.append(
            {
                "name": provider.name,
                "requires_key": provider.requires_key,
                "configured": provider.is_configured,
                "env_var": provider.api_key_env,
            }
        )
    return rows
