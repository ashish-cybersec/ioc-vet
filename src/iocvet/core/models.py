"""Core data models shared across detectors, providers, and output formatters."""

from __future__ import annotations

import time
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class IOCType(str, Enum):
    """The kind of indicator a user can pass in."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    UNKNOWN = "unknown"


# Hash types grouped for providers that treat "any hash" the same way.
HASH_TYPES = frozenset({IOCType.MD5, IOCType.SHA1, IOCType.SHA256})
IP_TYPES = frozenset({IOCType.IPV4, IOCType.IPV6})


class Verdict(str, Enum):
    """Normalized verdict every provider must map its raw response onto.

    Providers disagree on vocabulary (e.g. "abuse score" vs "malware family"
    vs "detection ratio"). Normalizing to this small set is what lets the
    aggregator combine signal from unrelated sources into one confidence.
    """

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"

    @property
    def severity(self) -> int:
        """Higher = worse. Used by the aggregator to pick the overall verdict."""
        return {
            Verdict.UNKNOWN: 0,
            Verdict.CLEAN: 1,
            Verdict.SUSPICIOUS: 2,
            Verdict.MALICIOUS: 3,
        }[self]


class ProviderResult(BaseModel):
    """What a single provider hands back after looking up one IOC."""

    provider: str
    verdict: Verdict = Verdict.UNKNOWN
    summary: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    link: str | None = None
    error: str | None = None
    skipped_reason: str | None = None
    latency_ms: int | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.skipped_reason is None


class EnrichmentReport(BaseModel):
    """The full result of running every applicable provider on one IOC."""

    ioc: str
    ioc_type: IOCType
    overall_verdict: Verdict = Verdict.UNKNOWN
    results: list[ProviderResult] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    from_cache: bool = False

    def compute_overall_verdict(self) -> Verdict:
        """Pick the worst verdict among providers that actually answered.

        A single 'malicious' from any working provider outweighs several
        'unknown' results from providers that were skipped or errored.
        """
        answered = [r.verdict for r in self.results if r.ok]
        if not answered:
            return Verdict.UNKNOWN
        return max(answered, key=lambda v: v.severity)

    @property
    def working_providers(self) -> list[ProviderResult]:
        return [r for r in self.results if r.ok]

    @property
    def skipped_providers(self) -> list[ProviderResult]:
        return [r for r in self.results if r.skipped_reason]

    @property
    def failed_providers(self) -> list[ProviderResult]:
        return [r for r in self.results if r.error]
