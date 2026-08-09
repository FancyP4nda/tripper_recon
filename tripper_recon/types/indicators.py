"""Indicator typing: one ordered, auditable classifier for anything an analyst pastes.

Roadmap 6.3. Under pressure an analyst has one string and no patience for choosing a
subcommand, and today the tool refuses most of what they would paste: a CIDR prefix, a file
hash, an email address and a bare ``evil.com/a/b`` all fail every validator in
``utils/validation.py``, and a defanged indicator crashes ``cli.py`` outright. :func:`detect`
is the front door that fixes that, and it is the base the ``check`` verb and bulk mode sit on.

**Pure functions only. No I/O, no network, no name resolution.** Classification is string work
and nothing here is permitted to become anything else. In particular, a URL is decomposed, never
fetched, and a redirect or shortener is never expanded: that is an active fetch of the target
with HEAD no exemption (``docs/OPSEC.md`` section 7). Every URL this module classifies therefore
carries ``redirect_chain: None`` with the state ``not_resolved``, which is a statement about what
the tool deliberately did not do, not a gap waiting to be filled by a local expansion.

Two design rules do the real work.

**Order is the whole algorithm, and it is declared.** The types overlap -- ``1.2.3.4/24`` is a
prefix and also parses as a scheme-less URL, ``15169`` is an AS number and also an integer, 32
hex characters are a digest and also a syntactically valid DNS label. :data:`DETECTION_ORDER`
fixes which reading wins, most specific first, and every input is run against *every* classifier
so the losers can be reported rather than discarded.

**Ambiguity is reported, never silently resolved.** Three fields carry it:
:attr:`Indicator.confidence` says how firm the reading is, :attr:`Indicator.alternatives` names
the other types that also parsed, and :attr:`Indicator.attempts` records every classifier that
was tried with the reason it declined. An ``UNKNOWN`` result is therefore never a shrug -- it
tells the analyst exactly which seven readings were attempted and why each was rejected.

Nothing here decides whether an indicator is *worth* investigating; that is the verdict engine's
job (``tripper_recon/verdict/``). This module does record what it can see about routability, so
a caller can refuse a private address before it reaches a third party, and it deliberately does
not raise on one: reporting "this is RFC 1918" is more useful than refusing to classify it.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import parse_qsl, unquote, urlsplit

from tripper_recon.utils.refang import refang

__all__ = [
    "ASSUMED_SCHEME",
    "DETECTION_ORDER",
    "MAX_ASN",
    "WEB_SCHEMES",
    "Attempt",
    "Confidence",
    "Indicator",
    "IndicatorType",
    "detect",
]


# --------------------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------------------


class IndicatorType(str, Enum):
    """What a pasted string turned out to be.

    ``str``-valued so the wire form survives JSON serialisation unchanged, matching
    :class:`tripper_recon.types.models.ProviderStatus`.
    """

    ASN = "asn"
    CIDR = "cidr"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    URL = "url"
    EMAIL = "email"
    DOMAIN = "domain"
    #: Nothing matched. :attr:`Indicator.attempts` says what was tried and why each declined.
    UNKNOWN = "unknown"

    @property
    def is_ip(self) -> bool:
        return self in {IndicatorType.IPV4, IndicatorType.IPV6}

    @property
    def is_hash(self) -> bool:
        return self in {IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256}


class Confidence(str, Enum):
    """How firm a classification is.

    ``CERTAIN`` means the string cannot reasonably be read as anything else: ``AS15169``,
    ``185.220.101.5``, an explicit-scheme URL. ``PROBABLE`` means the reading is the best one
    available but the input was genuinely ambiguous or incomplete -- a bare integer read as an
    AS number, a scheme this tool supplied rather than observed. ``NONE`` belongs to
    :attr:`IndicatorType.UNKNOWN` alone.
    """

    CERTAIN = "certain"
    PROBABLE = "probable"
    NONE = "none"


#: Classifier order. Most specific first; the first match wins and the rest become
#: :attr:`Indicator.alternatives`. Changing this changes what the tool investigates for a given
#: paste, so it is a declared constant rather than the incidental order of a function body.
DETECTION_ORDER: Tuple[str, ...] = ("asn", "cidr", "ip", "hash", "url", "email", "domain")

#: Highest assignable AS number. 4294967295 is reserved (RFC 7300) and AS0 is invalid.
MAX_ASN = 4294967294

#: Schemes this tool is willing to treat as a URL. Anything else (``file``, ``ldap``, ``jar``)
#: is rejected rather than investigated: no provider here holds intelligence about it, and
#: guessing at one would send a malformed indicator to five third parties.
WEB_SCHEMES = frozenset({"http", "https", "ftp", "ftps"})

#: Supplied when the input has no scheme at all (``evil.com/a/b``). Recorded as *assumed* in
#: both the notes and ``parts``, never asserted: the assumption changes the VirusTotal URL
#: identifier, and therefore whether a report is found at all.
ASSUMED_SCHEME = "http"

_SCHEME_SEPARATOR = "://"

_DEFAULT_PORTS: Dict[str, int] = {"http": 80, "https": 443, "ftp": 21, "ftps": 990}

#: Query parameter names that habitually carry another URL. An open-redirect parameter is a
#: candidate indicator for the analyst to run separately -- never something this tool resolves.
_REDIRECT_PARAM_HINTS = frozenset(
    {
        "url",
        "uri",
        "next",
        "redirect",
        "redirect_uri",
        "redir",
        "dest",
        "destination",
        "target",
        "continue",
        "goto",
        "link",
        "out",
        "return",
        "returnurl",
    }
)


# --------------------------------------------------------------------------------------
# Result types
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Attempt:
    """One classifier's verdict on the input.

    Recorded for every classifier on every call, matched or not. On an ``UNKNOWN`` result this
    tuple is the entire explanation the analyst gets, so ``detail`` names the specific reason
    rather than restating the type.
    """

    kind: str
    matched: bool
    detail: str


@dataclass(frozen=True)
class Indicator:
    """A classified indicator: what was pasted, what it is, and what was uncertain about it.

    ``raw`` is the analyst's string exactly as supplied and ``value`` is the canonical form the
    tool would investigate. Both are kept because a tool that silently rewrites its input
    produces output that cannot be defended in a case write-up.
    """

    #: Exactly as pasted, before refanging or normalisation.
    raw: str
    type: IndicatorType
    #: Canonical, normalised form. For ``UNKNOWN`` this is the refanged input, unchanged.
    value: str
    confidence: Confidence
    #: True when a defanging rule fired. Cosmetic trimming alone does not set it.
    defanged_input: bool = False
    #: Names of the :mod:`tripper_recon.utils.refang` rules that fired, in order.
    refang_transforms: Tuple[str, ...] = ()
    #: Everything uncertain, assumed, or worth an analyst's attention about this reading.
    notes: Tuple[str, ...] = ()
    #: Other types that also parsed, in detection order. Non-empty means genuine ambiguity.
    alternatives: Tuple[IndicatorType, ...] = ()
    #: Every classifier that ran, with the reason it matched or declined.
    attempts: Tuple[Attempt, ...] = ()
    #: Type-specific decomposition: URL scheme/host/port/path, CIDR prefix length, and so on.
    parts: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        # Explicit because ``parts`` is a dict and the generated hash would raise on it. Hashing
        # on :attr:`key` keeps the hash consistent with the generated field-wise ``__eq__``:
        # equal indicators necessarily share a key, so they necessarily share a hash.
        return hash(self.key)

    @property
    def key(self) -> Tuple[IndicatorType, str]:
        """Deduplication identity: the canonical value under its type.

        Equality stays field-wise, because two pastes that produced the same value from
        different raw strings are not the same evidence. Bulk mode (roadmap 6.10) counts
        occurrences, and this is what it counts on.
        """
        return (self.type, self.value)

    @property
    def is_known(self) -> bool:
        return self.type is not IndicatorType.UNKNOWN

    @property
    def is_ambiguous(self) -> bool:
        """True when more than one reading parsed, or the winning one is not certain."""
        return bool(self.alternatives) or self.confidence is not Confidence.CERTAIN

    def explain(self) -> str:
        """A detection trace an analyst can read, for a ``--explain`` flag or a case note."""
        lines = [
            f"raw:        {self.raw!r}",
            f"value:      {self.value!r}",
            f"type:       {self.type.value} ({self.confidence.value})",
        ]
        if self.defanged_input:
            lines.append(f"refanged:   {', '.join(self.refang_transforms)}")
        if self.alternatives:
            lines.append(f"also parsed as: {', '.join(t.value for t in self.alternatives)}")
        for note in self.notes:
            lines.append(f"note:       {note}")
        for attempt in self.attempts:
            marker = "match " if attempt.matched else "reject"
            lines.append(f"  {marker} {attempt.kind:7} {attempt.detail}")
        return "\n".join(lines)


# --------------------------------------------------------------------------------------
# Internal classifier plumbing
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Candidate:
    """A successful classification, before ambiguity across classifiers is resolved."""

    type: IndicatorType
    value: str
    confidence: Confidence
    notes: Tuple[str, ...] = ()
    parts: Dict[str, Any] = field(default_factory=dict)


#: A classifier returns a :class:`_Candidate` on a match, or the reason it declined as a string.
_Outcome = Union[_Candidate, str]

_BRACKETED_HOST_RE = re.compile(r"\[([^\[\]]+)\](?P<rest>.*)", re.DOTALL)


def _non_routable_reason(obj: Any) -> Optional[str]:
    """Why an address or network is not something a third party holds intelligence about.

    Ordered most-specific first: a loopback address is also private, and reporting it as
    "private" would be true but useless.
    """
    for attribute, label in (
        ("is_unspecified", "unspecified"),
        ("is_loopback", "loopback"),
        ("is_link_local", "link-local"),
        ("is_multicast", "multicast"),
        ("is_private", "private or otherwise non-public (RFC 1918, CGNAT, documentation range)"),
        ("is_reserved", "reserved"),
    ):
        if getattr(obj, attribute, False):
            return label
    return None


def _routability_note(label: str) -> str:
    return (
        f"non-routable ({label}): no third-party provider holds intelligence about it, and sending "
        "it to one would disclose internal addressing"
    )


# --------------------------------------------------------------------------------------
# Domain shape — shared by the domain, email and URL classifiers
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _DomainShape:
    value: str
    labels: Tuple[str, ...]
    ascii_only: bool
    notes: Tuple[str, ...]
    error: Optional[str]


def _reject_domain(reason: str) -> _DomainShape:
    return _DomainShape(value="", labels=(), ascii_only=True, notes=(), error=reason)


def _domain_shape(text: str) -> _DomainShape:
    """Validate and normalise a hostname without consulting anything.

    Self-contained on purpose. ``utils.validation.is_valid_domain`` rejects a trailing root dot
    and every internationalised name (roadmap 6.4, a different lane), and detection cannot wait
    on that: an IDN homograph is a routine phishing artefact and refusing to classify one is the
    behaviour this module exists to remove.
    """
    notes: List[str] = []
    candidate = text

    if candidate.endswith("."):
        candidate = candidate[:-1]
        notes.append("trailing root dot removed")

    if not candidate:
        return _reject_domain("empty hostname")
    if any(character.isspace() for character in candidate):
        return _reject_domain("contains whitespace")
    for character in "/@:?#\\":
        if character in candidate:
            return _reject_domain(f"contains {character!r}, which cannot appear in a hostname")
    if len(candidate.encode("utf-8")) > 253:
        return _reject_domain("exceeds the 253-octet limit on a fully qualified name")

    labels = tuple(candidate.split("."))
    if len(labels) < 2:
        return _reject_domain("single label: not fully qualified, so no registry or provider can be asked about it")
    for label in labels:
        if not label:
            return _reject_domain("empty label (consecutive or leading dots)")
        if len(label.encode("utf-8")) > 63:
            return _reject_domain(f"label {label[:20]!r} exceeds the 63-octet limit")
        if label.startswith("-") or label.endswith("-"):
            return _reject_domain(f"label {label!r} starts or ends with a hyphen")
        if not all(character.isalnum() or character in "-_" for character in label):
            return _reject_domain(f"label {label!r} contains a character outside the letter/digit/hyphen set")

    # Underscore labels (_dmarc, _domainkey, SRV records) are valid DNS names and invalid
    # hostnames (RFC 952 / RFC 1123). They turn up constantly in mail-security reports, so they
    # are accepted and flagged rather than refused.
    if any("_" in label for label in labels[:-1]):
        notes.append("underscore label present: a valid DNS name but not a valid hostname (RFC 952/1123)")
    if "_" in labels[-1]:
        return _reject_domain(f"top-level label {labels[-1]!r} contains an underscore")

    tld = labels[-1]
    if tld.isdigit():
        return _reject_domain(
            f"top-level label {tld!r} is numeric, so this is not a hostname -- a dotted-decimal string "
            "of this shape is an IP address, not a domain"
        )
    if len(tld) < 2:
        return _reject_domain(f"top-level label {tld!r} is shorter than two characters")
    if not tld.isalpha() and not tld.lower().startswith("xn--"):
        return _reject_domain(f"top-level label {tld!r} is neither alphabetic nor punycode")

    ascii_only = candidate.isascii()
    if not ascii_only:
        notes.append(
            "internationalised domain name: the ASCII/punycode (xn--) form is NOT computed here, so the "
            "lookup value is the Unicode form. IDNA conversion and homograph checks are roadmap item 6.4"
        )
    if any(label.lower().startswith("xn--") for label in labels):
        notes.append("punycode label present: the Unicode form is not computed here (roadmap 6.4)")

    return _DomainShape(
        value=candidate.lower(),
        labels=tuple(label.lower() for label in labels),
        ascii_only=ascii_only,
        notes=tuple(notes),
        error=None,
    )


# --------------------------------------------------------------------------------------
# Classifiers
# --------------------------------------------------------------------------------------

_ASN_RE = re.compile(r"as[n]?[\s:_-]?(\d{1,10})", re.IGNORECASE)
_BARE_INTEGER_RE = re.compile(r"(\d{1,10})")


def _classify_asn(text: str) -> _Outcome:
    match = _ASN_RE.fullmatch(text)
    prefixed = match is not None
    if match is None:
        match = _BARE_INTEGER_RE.fullmatch(text)
    if match is None:
        return "no 'AS' prefix and not a bare integer"

    number = int(match.group(1))
    if not 0 < number <= MAX_ASN:
        return f"{number} is outside the assignable AS range 1..{MAX_ASN}"

    notes: Tuple[str, ...] = ()
    confidence = Confidence.CERTAIN
    if not prefixed:
        confidence = Confidence.PROBABLE
        notes = (
            "bare integer read as an AS number; 'AS<n>' would be unambiguous. An integer this shape is "
            "equally plausible as a ticket number, a port or a truncated paste",
        )
    return _Candidate(
        type=IndicatorType.ASN,
        value=f"AS{number}",
        confidence=confidence,
        notes=notes,
        parts={"asn": number, "prefixed": prefixed},
    )


def _classify_cidr(text: str) -> _Outcome:
    if "/" not in text:
        return "no '/' present, so not a network prefix"

    candidate = text
    notes: List[str] = []
    bracket = _BRACKETED_HOST_RE.fullmatch(text)
    if bracket is not None and bracket.group("rest").startswith("/"):
        candidate = bracket.group(1) + bracket.group("rest")
        notes.append("bracketed IPv6 form: the brackets are URL syntax and are not part of the prefix")

    try:
        network = ipaddress.ip_network(candidate, strict=False)
    except ValueError as exc:
        return f"not a valid network prefix ({exc})"

    try:
        ipaddress.ip_network(candidate, strict=True)
    except ValueError:
        notes.append(f"host bits were set in the input; normalised to the network address {network}")

    if network.num_addresses == 1:
        notes.append("single-address prefix: equivalent to the bare address")
    routability = _non_routable_reason(network)
    if routability is not None:
        notes.append(_routability_note(routability))

    return _Candidate(
        type=IndicatorType.CIDR,
        value=str(network),
        confidence=Confidence.CERTAIN,
        notes=tuple(notes),
        parts={
            "version": network.version,
            "network_address": str(network.network_address),
            "prefix_length": network.prefixlen,
            "num_addresses": network.num_addresses,
            "is_private": network.is_private,
        },
    )


def _classify_ip(text: str) -> _Outcome:
    candidate = text
    notes: List[str] = []
    bracket = _BRACKETED_HOST_RE.fullmatch(text)
    if bracket is not None and not bracket.group("rest"):
        candidate = bracket.group(1)
        notes.append("bracketed IPv6 literal: the brackets are URL syntax and are not part of the address")

    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as exc:
        return f"not a valid IP address ({exc})"

    value = str(address)
    if value != candidate:
        notes.append(f"normalised from {candidate!r} to its canonical compressed form")
    routability = _non_routable_reason(address)
    if routability is not None:
        notes.append(_routability_note(routability))

    return _Candidate(
        type=IndicatorType.IPV4 if address.version == 4 else IndicatorType.IPV6,
        value=value,
        confidence=Confidence.CERTAIN,
        notes=tuple(notes),
        parts={
            "version": address.version,
            "is_global": address.is_global,
            "is_private": address.is_private,
        },
    )


_HEX_RE = re.compile(r"[0-9a-fA-F]+")
_HASH_TYPES: Dict[int, IndicatorType] = {
    32: IndicatorType.MD5,
    40: IndicatorType.SHA1,
    64: IndicatorType.SHA256,
}


def _classify_hash(text: str) -> _Outcome:
    if not _HEX_RE.fullmatch(text):
        return "not a pure hexadecimal string"
    hash_type = _HASH_TYPES.get(len(text))
    if hash_type is None:
        return f"{len(text)} hex characters matches no digest length (32 = MD5, 40 = SHA-1, 64 = SHA-256)"

    notes = [
        f"{len(text)} hex characters is also a syntactically valid single DNS label; read as a digest "
        "because a bare label is not a fully qualified domain and cannot be looked up as one"
    ]
    if text != text.lower():
        notes.append("lower-cased: digests are compared case-insensitively and providers index them lower-case")

    return _Candidate(
        type=hash_type,
        value=text.lower(),
        confidence=Confidence.CERTAIN,
        notes=tuple(notes),
        parts={"algorithm": hash_type.value, "hex_length": len(text)},
    )


_SCHEME_PREFIX_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*)" + re.escape(_SCHEME_SEPARATOR))
_PATH_SEPARATOR_RE = re.compile(r"[/?#]")

#: Stated on every URL. The tool records what it did not do, so an analyst reading a report is
#: never left to assume the chain was checked and came back empty.
_REDIRECT_NOTE = (
    "redirect chain NOT RESOLVED: expanding a shortener or following a redirect is an active fetch of "
    "the target and HEAD is no exemption (docs/OPSEC.md section 7). A chain can only come from a scan "
    "somebody else already completed"
)


def _host_kind(
    host: str,
) -> Tuple[str, Optional[ipaddress.IPv4Address | ipaddress.IPv6Address], Optional[_DomainShape]]:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        shape = _domain_shape(host)
        return ("domain" if shape.error is None else "other"), None, shape
    return ("ipv4" if address.version == 4 else "ipv6"), address, None


def _classify_url(text: str) -> _Outcome:
    notes: List[str] = []
    scheme_match = _SCHEME_PREFIX_RE.match(text)

    if scheme_match is not None:
        scheme = scheme_match.group(1).lower()
        if scheme not in WEB_SCHEMES:
            return f"scheme {scheme!r} is not one this tool investigates ({', '.join(sorted(WEB_SCHEMES))})"
        target = text
        scheme_assumed = False
    else:
        separator = _PATH_SEPARATOR_RE.search(text)
        if separator is None:
            return "no scheme and no path separator, so it is a bare host rather than a URL"
        if _SCHEME_SEPARATOR in text[: separator.start()]:
            return f"contains {_SCHEME_SEPARATOR!r} but no parsable scheme in front of it"
        target = ASSUMED_SCHEME + _SCHEME_SEPARATOR + text
        scheme = ASSUMED_SCHEME
        scheme_assumed = True

    try:
        split = urlsplit(target)
        port = split.port
        raw_host = split.hostname or ""
    except ValueError as exc:
        return f"not parsable as a URL ({exc})"

    host = raw_host.rstrip(".").lower()
    if not host:
        return "no host component"

    kind, address, shape = _host_kind(host)
    if kind == "other" and scheme_assumed:
        reason = shape.error if shape is not None else "unparsable"
        return f"the text before the first path separator is not a host ({reason})"

    confidence = Confidence.CERTAIN
    if scheme_assumed:
        confidence = Confidence.PROBABLE
        notes.append(
            f"scheme assumed to be {ASSUMED_SCHEME!r}: it was NOT present in the input. The assumption "
            "changes the VirusTotal URL identifier and therefore whether a report is found at all"
        )
    if kind == "other":
        confidence = Confidence.PROBABLE
        reason = shape.error if shape is not None else "unparsable"
        notes.append(f"host {host!r} parses as neither a domain nor an IP address ({reason})")
    if kind in {"ipv4", "ipv6"}:
        notes.append("host is an IP literal: there is no domain pivot here, so investigate the address directly")
        if address is not None:
            routability = _non_routable_reason(address)
            if routability is not None:
                notes.append(_routability_note(routability))
    if shape is not None and shape.error is None:
        notes.extend(shape.notes)
        if not shape.ascii_only:
            confidence = Confidence.PROBABLE

    userinfo_present = bool(split.username or split.password)
    if userinfo_present:
        notes.append(
            "userinfo present: embedded credentials are a routine phishing disguise. The value is "
            "withheld from the canonical form so it cannot reach a log or a report"
        )

    embedded = _embedded_url_candidates(split.query)
    for name in sorted({name for name, _ in embedded}):
        notes.append(
            f"query parameter {name!r} carries a URL: offered as a CANDIDATE indicator for the analyst to "
            "run separately, never something this tool resolves"
        )
    notes.append(_REDIRECT_NOTE)

    netloc = f"[{host}]" if kind == "ipv6" else host
    if port is not None:
        netloc = f"{netloc}:{port}"
    value = f"{scheme}{_SCHEME_SEPARATOR}{netloc}{split.path}"
    if split.query:
        value += f"?{split.query}"
    if split.fragment:
        value += f"#{split.fragment}"

    return _Candidate(
        type=IndicatorType.URL,
        value=value,
        confidence=confidence,
        notes=tuple(notes),
        parts={
            "scheme": scheme,
            "scheme_assumed": scheme_assumed,
            "host": host,
            "host_type": kind,
            "port": port,
            "port_explicit": port is not None,
            "effective_port": port if port is not None else _DEFAULT_PORTS.get(scheme),
            # Path and query keep their case: they routinely carry the campaign identifier, and
            # lower-casing one changes the URL a provider is asked about.
            "path": split.path,
            "path_decoded": unquote(split.path),
            "query": split.query,
            "fragment": split.fragment,
            "userinfo_present": userinfo_present,
            "embedded_url_candidates": [value for _, value in embedded],
            "redirect_chain": None,
            "redirect_chain_state": "not_resolved",
        },
    )


def _embedded_url_candidates(query: str) -> List[Tuple[str, str]]:
    """Query values that are themselves URLs. Extracted for the analyst, never followed."""
    if not query:
        return []
    found: List[Tuple[str, str]] = []
    for name, raw_value in parse_qsl(query, keep_blank_values=True):
        decoded = unquote(raw_value)
        looks_like_url = _SCHEME_PREFIX_RE.match(decoded) is not None or decoded.startswith("//")
        if looks_like_url or (name.lower() in _REDIRECT_PARAM_HINTS and _PATH_SEPARATOR_RE.search(decoded)):
            found.append((name, decoded))
    return found


# RFC 5322 dot-atom, which is what mail systems in the field actually accept. Quoted local
# parts ("odd name"@example.com) are legal and are deliberately not supported: they are
# vanishingly rare in indicator feeds and accepting them would widen the URL/email overlap.
_EMAIL_LOCAL_RE = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*")


def _classify_email(text: str) -> _Outcome:
    if text.count("@") != 1:
        return "does not contain exactly one '@'"
    local, _, domain = text.partition("@")
    if not local:
        return "empty local part"
    if len(local.encode("utf-8")) > 64:
        return "local part exceeds the 64-octet limit (RFC 5321)"
    if not _EMAIL_LOCAL_RE.fullmatch(local):
        return "local part contains characters outside the RFC 5322 dot-atom set"

    shape = _domain_shape(domain)
    if shape.error is not None:
        return f"the text after '@' is not a valid domain ({shape.error})"

    notes = [
        "local part left case-sensitive: RFC 5321 leaves its interpretation to the receiving host, so "
        "folding it could change which mailbox the indicator names",
        *shape.notes,
    ]
    return _Candidate(
        type=IndicatorType.EMAIL,
        value=f"{local}@{shape.value}",
        confidence=Confidence.CERTAIN if shape.ascii_only else Confidence.PROBABLE,
        notes=tuple(notes),
        parts={"local_part": local, "domain": shape.value},
    )


def _classify_domain(text: str) -> _Outcome:
    shape = _domain_shape(text)
    if shape.error is not None:
        return shape.error
    return _Candidate(
        type=IndicatorType.DOMAIN,
        value=shape.value,
        confidence=Confidence.CERTAIN if shape.ascii_only else Confidence.PROBABLE,
        notes=shape.notes,
        parts={
            "labels": list(shape.labels),
            "tld": shape.labels[-1],
            "label_count": len(shape.labels),
            "ascii_only": shape.ascii_only,
        },
    )


_CLASSIFIERS: Tuple[Tuple[str, Callable[[str], _Outcome]], ...] = (
    ("asn", _classify_asn),
    ("cidr", _classify_cidr),
    ("ip", _classify_ip),
    ("hash", _classify_hash),
    ("url", _classify_url),
    ("email", _classify_email),
    ("domain", _classify_domain),
)


# --------------------------------------------------------------------------------------
# The entry point
# --------------------------------------------------------------------------------------


def detect(raw: str) -> Indicator:
    """Classify one pasted string. Pure; performs no I/O and no name resolution.

    The input is refanged first (:func:`tripper_recon.utils.refang.refang`), then run against
    every classifier in :data:`DETECTION_ORDER`. The first match wins; the others are reported
    as :attr:`Indicator.alternatives`, and every classifier that declined is reported in
    :attr:`Indicator.attempts` with its reason.

    Never raises on content. An unclassifiable string returns :attr:`IndicatorType.UNKNOWN`
    carrying the full attempt list, because "I could not tell" with seven stated reasons is
    actionable and a bare failure is not.

    Raises:
        TypeError: if ``raw`` is not a ``str`` -- a programming error at a trust boundary.
    """
    refanged = refang(raw)
    text = refanged.value

    attempts: List[Attempt] = []
    matches: List[_Candidate] = []
    for kind, classifier in _CLASSIFIERS:
        outcome = classifier(text) if text else "input is empty"
        if isinstance(outcome, _Candidate):
            attempts.append(Attempt(kind=kind, matched=True, detail=f"parsed as {outcome.type.value}"))
            matches.append(outcome)
        else:
            attempts.append(Attempt(kind=kind, matched=False, detail=outcome))

    notes: List[str] = []
    if refanged.was_defanged:
        notes.append(
            "input was defanged and has been refanged for lookup ("
            + ", ".join(refanged.transforms)
            + "); the raw form is preserved and is what a report should display"
        )

    if not matches:
        notes.append(
            "no classifier matched. Detection order was: " + ", ".join(DETECTION_ORDER) + ". "
            "Each attempt below states why it declined"
        )
        return Indicator(
            raw=raw,
            type=IndicatorType.UNKNOWN,
            value=text,
            confidence=Confidence.NONE,
            defanged_input=refanged.was_defanged,
            refang_transforms=refanged.transforms,
            notes=tuple(notes),
            attempts=tuple(attempts),
        )

    chosen = matches[0]
    alternatives = tuple(candidate.type for candidate in matches[1:])
    if alternatives:
        notes.append(
            "ambiguous: also parses as "
            + ", ".join(alternative.value for alternative in alternatives)
            + f". Read as {chosen.type.value} because detection order puts it first; pass an explicit "
            "type to override"
        )
    notes.extend(chosen.notes)

    return Indicator(
        raw=raw,
        type=chosen.type,
        value=chosen.value,
        confidence=chosen.confidence,
        defanged_input=refanged.was_defanged,
        refang_transforms=refanged.transforms,
        notes=tuple(notes),
        alternatives=alternatives,
        attempts=tuple(attempts),
        parts=dict(chosen.parts),
    )
