"""Base class every provider implements.

Adding a new threat intel source means: subclass Provider, implement
`supports()` and `_query()`, register it in `providers/__init__.py`. That's
the entire contract — the aggregator, caching, and CLI don't need to know
anything new exists. This is intentional: it's the contribution surface
for anyone who wants to add a source we don't cover yet.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod

import httpx

from iocvet.core.models import IOCType, ProviderResult, Verdict


class Provider(ABC):
    """One external threat-intel source."""

    #: Short machine name, also used as the cache namespace and CLI label.
    name: str = "base"

    #: Set to True if this provider needs an API key to function at all.
    requires_key: bool = False

    #: Env var the key is read from, e.g. "ABUSEIPDB_API_KEY".
    api_key_env: str | None = None

    #: Polite default timeout for any single HTTP call.
    timeout_seconds: float = 10.0

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key

    @property
    def is_configured(self) -> bool:
        """Whether this provider has what it needs to actually run."""
        return (not self.requires_key) or bool(self.api_key)

    @abstractmethod
    def supports(self, ioc_type: IOCType) -> bool:
        """Return True if this provider can meaningfully look up this IOC type."""
        raise NotImplementedError

    @abstractmethod
    async def _query(self, client: httpx.AsyncClient, ioc: str, ioc_type: IOCType) -> ProviderResult:
        """Do the actual network call and return a normalized result.

        Implementations should raise on unexpected failures — `run()`
        catches and wraps them so one flaky provider never crashes the
        whole lookup.
        """
        raise NotImplementedError

    async def run(self, client: httpx.AsyncClient, ioc: str, ioc_type: IOCType) -> ProviderResult:
        """Public entrypoint the aggregator calls. Handles skip/error wrapping
        and timing so individual provider implementations stay simple.
        """
        if not self.supports(ioc_type):
            return ProviderResult(
                provider=self.name,
                skipped_reason=f"does not support IOC type '{ioc_type.value}'",
            )
        if not self.is_configured:
            return ProviderResult(
                provider=self.name,
                skipped_reason=(
                    f"no API key configured (set {self.api_key_env})"
                    if self.api_key_env
                    else "not configured"
                ),
            )

        started = time.perf_counter()
        try:
            result = await self._query(client, ioc, ioc_type)
            result.latency_ms = int((time.perf_counter() - started) * 1000)
            return result
        except httpx.TimeoutException:
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.UNKNOWN,
                error=f"timed out after {self.timeout_seconds}s",
            )
        except httpx.HTTPStatusError as exc:
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.UNKNOWN,
                error=f"HTTP {exc.response.status_code} from {self.name}",
            )
        except Exception as exc:  # noqa: BLE001 - last line of defense per provider
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.UNKNOWN,
                error=f"unexpected error: {exc}",
            )
