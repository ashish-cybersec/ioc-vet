"""Runs every registered provider concurrently against one IOC and merges
the results into a single EnrichmentReport. This is the only place that
needs to know about asyncio — providers themselves stay simple.
"""

from __future__ import annotations

import asyncio

import httpx

from iocvet.config import get_api_key
from iocvet.core.detector import detect_ioc_type, normalize
from iocvet.core.models import EnrichmentReport, IOCType
from iocvet.providers import ALL_PROVIDERS, Provider

_USER_AGENT = "iocvet/0.1 (+https://github.com/your-username/ioc-vet)"


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


async def enrich(raw_ioc: str, *, ioc_type: IOCType | None = None) -> EnrichmentReport:
    """Detect (or accept a forced) IOC type, run every applicable provider
    concurrently, and return a populated report.
    """
    resolved_type = ioc_type or detect_ioc_type(raw_ioc)
    ioc = normalize(raw_ioc, resolved_type)

    providers = _instantiate_providers()

    async with httpx.AsyncClient(headers={"User-Agent": _USER_AGENT}) as client:
        results = await asyncio.gather(
            *(p.run(client, ioc, resolved_type) for p in providers)
        )

    report = EnrichmentReport(ioc=ioc, ioc_type=resolved_type, results=list(results))
    report.overall_verdict = report.compute_overall_verdict()
    return report


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
