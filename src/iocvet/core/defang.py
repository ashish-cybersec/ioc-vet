"""Refang defanged IOCs — turn ``hxxp://evil[.]com`` back into a real value.

Defanging is how indicators travel safely through tickets, email, and threat
reports: neutering them so nobody fat-fingers a live malware link. Analysts
paste these straight from a report, so the tool has to accept them.

The overriding requirement is *never corrupt something that was already valid*.
A refang that mangles a real domain or URL is worse than one that misses an
exotic defang form, because it turns a good IOC into a lookup for garbage. So
this module is deliberately conservative:

* It only rewrites the *obfuscated* scheme forms (``hxxp``/``hXXp``), never real
  ``http``/``https`` — those need no refanging, and matching them risks eating a
  domain that merely starts with "http" (e.g. ``httpbin.org``).
* It only un-brackets the separator characters ``.`` ``:`` ``@`` when they are
  wrapped in ``[] () {}`` — never arbitrary bracketed text, so a legitimate
  ``[0]`` in a URL query string survives.
* Word forms are accepted *only when bracketed* (``[dot]`` ``(at)``). The
  space-delimited " dot " / " at " forms are intentionally NOT handled: they
  collide with ordinary prose ("meet at noon") and real defanged IOCs almost
  always use brackets anyway.

The function is idempotent and leaves a clean IOC byte-for-byte unchanged.
"""

from __future__ import annotations

import re

# Obfuscated scheme only: hxxp / hXXp / hxxps. A real scheme separator must
# follow (:// or a defanged form of it), so a domain like "hxxpo.com" — which
# has no separator — is left alone. Real http/https are never matched: they
# need no refang, and matching them would corrupt "httpbin.org" etc.
_SCHEME_RE = re.compile(
    r"^h(?:xx|XX)p(s?)"                      # hxxp / hXXp / hxxps  (never http)
    r"(?:\[://\]|\[:\]//|\(:\)//|://|:?//)",  # required scheme separator, defanged or not
    re.IGNORECASE,
)

# Bracketed / parenthesised / braced separators: [.] (.) {.} [:] [@] etc.
# Only . : @ are eligible — never arbitrary [x], so "?q=a[0]" survives.
_WRAPPED_SEP_RE = re.compile(r"[\[({]\s*([.:@])\s*[\])}]")

# Word forms, BRACKETED ONLY. Bare space-delimited "dot"/"at" is deliberately
# excluded (see module docstring) to avoid corrupting prose.
_WORD_DOT_RE = re.compile(r"[\[(]\s*dot\s*[\])]", re.IGNORECASE)
_WORD_AT_RE = re.compile(r"[\[(]\s*at\s*[\])]", re.IGNORECASE)


def refang(value: str) -> str:
    """Return ``value`` with common defang markers removed.

    Safe to call on already-clean input: a non-defanged IOC round-trips
    unchanged, and ``refang(refang(x)) == refang(x)``.
    """
    text = value.strip()

    # 1. Obfuscated scheme: hxxp[://] -> http://
    text = _SCHEME_RE.sub(lambda m: "http" + m.group(1) + "://", text)

    # 2. Bracketed separators: evil[.]com -> evil.com, 1.2.3[:]80 -> 1.2.3:80
    text = _WRAPPED_SEP_RE.sub(r"\1", text)

    # 3. Bracketed word forms: evil[dot]com -> evil.com, user[at]x -> user@x
    text = _WORD_DOT_RE.sub(".", text)
    text = _WORD_AT_RE.sub("@", text)

    # 4. "evil [.] com" becomes "evil . com" after step 2 — rejoin by dropping
    #    spaces that directly flank a bare . : @ *between word characters*. The
    #    \w boundaries mean a colon inside a real URL ("http://") or IPv6 is
    #    untouched (its neighbours aren't both word chars), and clean input has
    #    no such spaces to collapse.
    text = re.sub(r"(?<=\w)\s*([.:@])\s*(?=\w)", r"\1", text)

    return text


def is_defanged(value: str) -> bool:
    """True if ``value`` appears to contain defang markers.

    Used only to decide whether to tell the user we un-defanged their input;
    detection itself always runs refang() regardless.
    """
    return refang(value) != value.strip()
