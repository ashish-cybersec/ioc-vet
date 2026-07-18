"""Base class every provider implements.

Adding a new threat intel source means: subclass Provider, implement
`supports()` and `_query()`, register it in `providers/__init__.py`. That's
the entire contract — the aggregator, caching, and CLI don't need to know
anything new exists. This is intentional: it's the contribution surface
for anyone who wants to add a source we don't cover yet.
"""

from __future__ import annotations

import asyncio
import json
import time
from abc import ABC, abstractmethod

import httpx

from iocvet.core.detector import is_non_global_ip
from iocvet.core.models import IOCType, ProviderResult, Verdict


class RateLimiter:
    """Spaces outbound calls so we stay under a provider's published limit.

    Free tiers are strict: ip-api throttles at 45 req/min and bans an IP for
    an hour on sustained abuse. A batch of a few hundred IOCs fired at full
    concurrency will trip that, so each provider paces its own calls. State
    lives on the provider instance, which is why batch runs reuse instances.
    """

    def __init__(self, per_minute: int) -> None:
        if per_minute <= 0:
            raise ValueError("per_minute must be positive")
        self._interval = 60.0 / per_minute
        self._lock = asyncio.Lock()
        self._next_at = 0.0

    async def acquire(self) -> None:
        async with self._lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            if self._next_at > now:
                await asyncio.sleep(self._next_at - now)
                now = self._next_at
            self._next_at = now + self._interval


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

    #: Published per-minute cap for this source, or None if unmetered/unknown.
    rate_limit_per_minute: int | None = None

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key
        self._limiter = (
            RateLimiter(self.rate_limit_per_minute) if self.rate_limit_per_minute else None
        )

    @property
    def is_configured(self) -> bool:
        """Whether this provider has what it needs to actually run."""
        return (not self.requires_key) or bool(self.api_key)

    @abstractmethod
    def supports(self, ioc_type: IOCType) -> bool:
        """Return True if this provider can meaningfully look up this IOC type."""
        raise NotImplementedError

    @abstractmethod
    async def _query(
        self, client: httpx.AsyncClient, ioc: str, ioc_type: IOCType
    ) -> ProviderResult:
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
        # Never send a private/reserved/loopback/link-local address to a
        # third-party API: it discloses internal network structure and no
        # reputation source can say anything useful about a non-routable IP.
        # Enforced here in the base so every provider — including any added
        # later — inherits it, rather than relying on each to remember.
        if ioc_type in (IOCType.IPV4, IOCType.IPV6) and is_non_global_ip(ioc):
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.UNKNOWN,
                skipped_reason="private/reserved IP — not sent to external providers",
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

        if self._limiter is not None:
            await self._limiter.acquire()

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
        except httpx.ConnectError:
            # DNS failure, refused connection, offline, or a blocking proxy.
            # Report it plainly instead of via the generic-exception catch,
            # whose "unexpected error: All connection attempts failed" reads
            # like a bug rather than "you're offline".
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.UNKNOWN,
                error=f"could not connect to {self.name} (network/DNS)",
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 429:
                return ProviderResult(
                    provider=self.name,
                    verdict=Verdict.UNKNOWN,
                    error="rate limited (HTTP 429) — slow down or add a key",
                )
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.UNKNOWN,
                error=f"HTTP {exc.response.status_code} from {self.name}",
            )
        except json.JSONDecodeError:
            # A non-JSON body where JSON was expected: a captive portal, an
            # error page, or — on the plaintext ip-api channel — a MITM. Report
            # it as what it is rather than leaking raw parser internals like
            # "Expecting value: line 1 column 1".
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.UNKNOWN,
                error=f"invalid (non-JSON) response from {self.name}",
            )
        except Exception as exc:  # last line of defense: one bad provider must not
            # take down the whole lookup, so every unexpected error is captured here.
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.UNKNOWN,
                error=f"unexpected error: {exc}",
            )
