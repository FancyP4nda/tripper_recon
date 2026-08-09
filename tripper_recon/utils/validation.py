"""Indicator validation and normalisation.

Every orchestrator entry point gates on these functions (``orchestrators.py:879``, ``:1016``,
``:1149``), so what they reject is exactly what the tool refuses to look at.

Two operations are kept distinct on purpose:

* ``normalize_*`` returns the canonical form of an indicator, or ``None`` when there isn't one.
* ``is_valid_*`` answers a yes/no question and returns a ``bool``.

Validation never mutates what the caller passed. A caller that needs the punycode (A-label) form
of an internationalised name asks ``normalize_domain`` for it.

**Encoding is not folding.** ``normalize_domain`` IDNA-encodes a Unicode name to its A-label form;
it never maps a lookalike codepoint onto its ASCII twin. ``аpple.com`` (Cyrillic U+0430) normalises
to ``xn--pple-43d.com``, which is a different name from ``apple.com`` and stays different. Folding
homographs together here would make the tool report on the wrong domain, which is the whole reason
an analyst is looking at one.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable

# RFC 1035 §2.3.4: 63 octets per label, 255 octets on the wire. 253 is the presentation-form
# equivalent (the wire form spends one octet on each label's length prefix plus one on the root).
_MAX_LABEL_OCTETS = 63
_MAX_NAME_OCTETS = 253

# 32-bit ASN space, exclusive at both ends: AS0 is reserved (RFC 7607).
_MAX_ASN = 2**32

# RFC 1123 §2.1: a label starts and ends with a letter or digit and may contain hyphens between.
# Applied to the ASCII A-label form, after normalisation has lowercased and IDNA-encoded.
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")

# The IDNA ACE prefix (RFC 5890 §2.3.2.1). A TLD is either alphabetic or an A-label.
_ACE_PREFIX = "xn--"


def is_valid_ip(value: str) -> bool:
    """True if *value* parses as an IPv4 or IPv6 address.

    Deliberately does NOT strip surrounding whitespace -- ``is_valid_domain`` does, and the
    asymmetry is documented in ``tests/test_validation.py``. Callers normalise before validating.
    """
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_asn(value: str | int) -> int | None:
    """Return *value* as a plain AS number, or ``None`` if it is not one.

    Accepts the canonical ``AS15169`` presentation form as well as a bare integer or numeric
    string. The prefix strip used to live in ``cli.py`` alone, which meant every non-CLI caller
    refused the form an analyst is most likely to paste.
    """
    try:
        if isinstance(value, str):
            text = value.strip()
            if text[:2].lower() == "as":
                text = text[2:].strip()
            number = int(text)
        else:
            number = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if 0 < number < _MAX_ASN else None


def is_valid_asn(value: str | int) -> bool:
    """True if *value* is an assignable 32-bit AS number (``0 < n < 2**32``)."""
    return normalize_asn(value) is not None


def _is_valid_label(label: str) -> bool:
    """True if *label* is a syntactically valid ASCII DNS label."""
    return 0 < len(label) <= _MAX_LABEL_OCTETS and _LABEL_RE.match(label) is not None


def _is_valid_tld(label: str) -> bool:
    """True if *label* is a plausible top-level domain in A-label form.

    Two shapes exist in the root zone: an alphabetic TLD (``com``, ``de``) and an IDN TLD encoded
    as an A-label (``xn--p1ai`` for ``рф``). An all-numeric final label is rejected, which is what
    keeps a bare IPv4 address from validating as a domain.
    """
    if len(label) < 2 or not _is_valid_label(label):
        return False
    if label.startswith(_ACE_PREFIX):
        return len(label) > len(_ACE_PREFIX)
    return label.isalpha()


def normalize_domain(value: str) -> str | None:
    """Return the canonical ASCII form of *value*, or ``None`` if it is not a valid domain.

    Normalisation is: strip surrounding whitespace, lowercase, drop a single fully-qualifying
    trailing dot, then IDNA-encode to A-labels. ``münchen.de`` returns ``xn--mnchen-3ya.de``;
    an already-encoded name returns unchanged.

    Returns ``None`` rather than raising, so it composes directly into ``is_valid_domain``.
    """
    if not isinstance(value, str):
        return None

    name = value.strip().lower()
    if not name:
        return None

    if name.endswith("."):
        # The fully-qualified form names the root explicitly. One trailing dot is the FQDN
        # notation; two is a malformed empty label and is rejected below with the rest.
        name = name[:-1]
        if not name:
            return None

    try:
        # UnicodeError (a ValueError subclass) covers every failure the stdlib IDNA codec
        # raises: an empty label, an over-long label, and a codepoint nameprep prohibits.
        ascii_name = name.encode("idna").decode("ascii")
    except ValueError:
        return None

    if len(ascii_name) > _MAX_NAME_OCTETS:
        return None

    labels = ascii_name.split(".")
    if len(labels) < 2:
        return None
    if not all(_is_valid_label(label) for label in labels[:-1]):
        return None
    if not _is_valid_tld(labels[-1]):
        return None

    return ascii_name


def is_valid_domain(value: str) -> bool:
    """True if *value* is a syntactically valid domain name, internationalised forms included."""
    return normalize_domain(value) is not None


def dedupe_preserve_order(items: Iterable[str]) -> list[str]:
    """Exact-match dedupe that keeps first occurrence. Does not normalise case."""
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out
