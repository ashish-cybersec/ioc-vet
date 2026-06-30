"""Detect what kind of IOC a raw string is, so the aggregator knows which
providers are even applicable. No external calls here — pure regex/stdlib.
"""

from __future__ import annotations

import ipaddress
import re

from iocvet.core.models import IOCType

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def detect_ioc_type(raw: str) -> IOCType:
    """Best-effort classification of a single IOC string.

    Order matters: hashes and IPs are checked before the looser domain
    pattern, since a 32-char hex string would otherwise never match a
    domain regex anyway, but defensive ordering keeps this correct if the
    domain pattern is ever loosened.
    """
    value = raw.strip()
    if not value:
        return IOCType.UNKNOWN

    if value.lower().startswith(("http://", "https://")):
        return IOCType.URL

    if _MD5_RE.match(value):
        return IOCType.MD5
    if _SHA1_RE.match(value):
        return IOCType.SHA1
    if _SHA256_RE.match(value):
        return IOCType.SHA256

    try:
        ip = ipaddress.ip_address(value)
        return IOCType.IPV4 if ip.version == 4 else IOCType.IPV6
    except ValueError:
        pass

    if _DOMAIN_RE.match(value):
        return IOCType.DOMAIN

    return IOCType.UNKNOWN


def normalize(raw: str, ioc_type: IOCType) -> str:
    """Light normalization so cache keys and provider calls are consistent."""
    value = raw.strip()
    if ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256, IOCType.DOMAIN):
        return value.lower()
    return value
