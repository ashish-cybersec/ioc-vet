"""Detect what kind of IOC a raw string is, so the aggregator knows which
providers are even applicable. No external calls here — pure regex/stdlib.
"""

from __future__ import annotations

import ipaddress
import re

import idna

from iocvet.core.defang import refang
from iocvet.core.models import IOCType

_DOMAIN_RE = re.compile(
    # Labels: alphanumeric with internal hyphens. TLD: either a normal
    # alphabetic TLD (2-63 letters) or a punycode A-label TLD like "xn--p1ai"
    # (the ASCII form of an IDN TLD such as .рф), which contains digits/hyphens.
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:[a-zA-Z]{2,63}|xn--[a-zA-Z0-9]{2,59})$"
)
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def _to_ascii_domain(value: str) -> str | None:
    """Return the punycode (A-label) form of a domain, or None if it isn't a
    valid domain.

    Internationalised domains — münchen.de, россия.рф — are how homograph and
    lookalike phishing lands, so a threat tool must accept the human-readable
    form. Providers speak ASCII on the wire, so we convert to punycode here and
    match the ASCII result against the domain pattern. A plain ASCII domain
    passes straight through idna unchanged.
    """
    if value.isascii():
        return value if _DOMAIN_RE.match(value) else None
    try:
        # uts46=True applies the standard case-folding/normalisation browsers
        # use, so "MÜNCHEN.de" and "münchen.de" resolve identically.
        ascii_form = idna.encode(value, uts46=True).decode("ascii")
    except idna.IDNAError:
        return None
    return ascii_form if _DOMAIN_RE.match(ascii_form) else None


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

    # Internationalised domain? Accept it if it converts to a valid punycode
    # domain (münchen.de, россия.рф). ASCII domains already matched above.
    if not value.isascii() and _to_ascii_domain(value) is not None:
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
        # Convert IDNs to their ASCII/punycode form so the query sent to
        # providers, and the cache key, are canonical. "MÜNCHEN.de",
        # "münchen.de", and "xn--mnchen-3ya.de" all collapse to one value.
        stripped = value.rstrip(".")
        if not stripped.isascii():
            ascii_form = _to_ascii_domain(stripped)
            if ascii_form is not None:
                return ascii_form.lower()
        # Drop the FQDN root dot too, so "example.com." and "example.com"
        # produce one cache key and one provider query rather than two.
        return stripped.lower()
    if ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
        return value.lower()
    return value
