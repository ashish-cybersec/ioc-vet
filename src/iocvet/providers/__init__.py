"""Provider registry.

To add a new threat-intel source:
  1. Create iocvet/providers/yourservice.py with a class subclassing Provider.
  2. Import it below and add it to ALL_PROVIDERS.
That's the whole integration surface — nothing else in the codebase needs
to change. See base.py for the contract new providers must satisfy.
"""

from __future__ import annotations

from iocvet.providers.abuseipdb import AbuseIPDBProvider
from iocvet.providers.base import Provider
from iocvet.providers.ipapi import IPAPIProvider
from iocvet.providers.urlhaus import URLhausProvider

ALL_PROVIDERS: list[type[Provider]] = [
    IPAPIProvider,
    AbuseIPDBProvider,
    URLhausProvider,
]

__all__ = ["Provider", "ALL_PROVIDERS"]
