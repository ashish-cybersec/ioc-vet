"""Detect what kind of IOC a raw string is, so the aggregator knows which
providers are even applicable. No external calls here — pure regex/stdlib.
"""

from __future__ import annotations

import ipaddress
import re

from iocvet.core.defang import refang
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
    # No legitimate IOC is longer than this: the longest thing we classify is a
    # URL, and 2048 is the de-facto practical URL ceiling. Anything larger is
    # malformed or hostile — reject before running any regex over it. Defense in
    # depth: the regexes are already ReDoS-safe, but there's no reason to spend
    # cycles on megabyte "indicators", and it bounds memory on batch input.
    if len(raw) > 2048:
        return IOCType.UNKNOWN

    # Refang first: analysts paste IOCs straight from tickets and reports,
    # where they arrive neutered (hxxp://evil[.]com). Everything below then
    # classifies the real value.
    value = refang(raw)
    if not value:
        return IOCType.UNKNOWN

    if value.lower().startswith(("http://", "https://")):
        return IOCType.URL

    # "example.com." is a fully-qualified domain name with an explicit root
    # label (RFC 1034) and appears in DNS logs and zone files. Strip the root
    # dot before matching; without this it fell through to UNKNOWN, which now
    # means an exit code 2 rather than a shrug.
    if len(value) > 1 and value.endswith("."):
        value = value[:-1]

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


def is_non_global_ip(value: str) -> bool:
    """True for IPs that must never be sent to a third-party API: private
    (RFC1918), loopback, link-local (incl. cloud metadata 169.254.169.254),
    reserved, multicast, or unspecified.

    Sending these externally is an information-disclosure problem — it tells a
    third party about internal network structure — and pointless besides, since
    no reputation source can say anything useful about a non-routable address.
    """
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return not ip.is_global


def normalize(raw: str, ioc_type: IOCType) -> str:
    """Light normalization so cache keys and provider calls are consistent."""
    # Must refang here too: a defanged input reaches providers via this path,
    # and "evil[.]com" would otherwise be sent to the API verbatim.
    value = refang(raw)
    if ioc_type is IOCType.DOMAIN:
        # Drop the FQDN root dot too, so "example.com." and "example.com"
        # produce one cache key and one provider query rather than two.
        return value.rstrip(".").lower()
    if ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
        return value.lower()
    return value
