"""URL decomposition (roadmap 6.5). Pure, total, and incapable of touching the target.

This module turns a URL-shaped string into a typed record. It performs **no I/O of any kind**:
no socket, no name resolution, no HTTP client, no redirect following, no shortener expansion.
That is not an implementation detail, it is the reason the module can exist at all. W6 is where
a passive tool most easily stops being passive, because the obvious next line of code after
"parse the URL" is "and see where it goes" -- and that fetch is exactly what burns a single-use
phishing link and tells a live actor they are being looked at (``docs/OPSEC.md`` sections 1 and
7). :class:`RedirectChain` exists to make the honest answer -- NOT RESOLVED, and here is why --
a first-class value rather than a missing field somebody later fills in with a request.

Defanged examples. Every URL written in this module is defanged (``hxxps://``) on purpose: the
static passivity gate treats any absolute-URL literal in package source as an unreviewed egress
destination and fails the build on it (``tests/test_passivity.py``). The test suite for this
module uses real URLs, because ``tests/`` is not scanned.

What the decomposition preserves, and why each choice is a decision rather than a default:

* **Only the scheme and the host are lowercased.** Path, query and fragment are case-sensitive
  by RFC 3986 and in practice carry the campaign identifier, the victim token and the redirector
  key. Case-folding them destroys the evidence that links two samples to one campaign.
* **A missing scheme is recorded as assumed, never silently invented.** ``evil.com/a`` parses
  with ``scheme="https"`` and ``scheme_assumed=True``, plus a :attr:`UrlAnomaly.SCHEME_ASSUMED`
  entry. An analyst reading the record can tell what the sender actually wrote.
* **Userinfo is surfaced, not dropped.** ``hxxps://user:pw@evil.com/p`` currently loses its
  credentials on the way through the CLI. The construction is itself a phishing signal -- the
  brand goes in the username, the real host goes after the ``@`` -- so it is recorded as
  :attr:`ParsedURL.userinfo_present` and flagged.
* **Host oddities are signals, not noise to be normalised away.** Percent-encoding, overlong
  UTF-8 escapes, undecodable punycode, mixed-script labels, empty labels and integer/hex/octal
  address forms are all recorded on :attr:`ParsedURL.anomalies` with the host left exactly as it
  was written (bar the required lowercasing). A parser that quietly repairs these produces a
  clean-looking record of a hostile string.
* **The parser is total.** Apart from an empty input it never raises: a malformed URL is
  evidence, and refusing to represent it pushes the analyst back to reading the raw string.

**Validation is not this module's job.** ``utils/validation.py`` (roadmap 6.4) decides whether a
host is acceptable; :func:`parse_url` only decomposes and observes. Refanging (``hxxp`` ->
``http``, ``[.]`` -> ``.``) is roadmap 6.1 and runs *before* this function.

**Registrable domain (eTLD+1) is deliberately not guessed** -- see
:class:`RegistrableDomainStatus`.
"""

from __future__ import annotations

import re
import unicodedata
from enum import Enum
from ipaddress import ip_address
from typing import Dict, FrozenSet, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, model_validator

__all__ = [
    "DEFAULT_SCHEME",
    "NOT_RESOLVED_REASON",
    "WEB_SCHEMES",
    "Anomaly",
    "HostKind",
    "ParsedURL",
    "RedirectChain",
    "RedirectResolution",
    "RegistrableDomainStatus",
    "UrlAnomaly",
    "UrlParseError",
    "parse_url",
    "summarise_anomalies",
]

#: Assumed when the input carries no scheme. Recorded as assumed, never presented as observed.
DEFAULT_SCHEME = "https"

#: Schemes this tool investigates. Anything else is recorded as :attr:`UrlAnomaly.SCHEME_NON_WEB`
#: rather than rejected -- ``javascript:`` and ``data:`` payloads are findings, not parse errors.
WEB_SCHEMES: FrozenSet[str] = frozenset({"http", "https"})


class UrlParseError(ValueError):
    """The input could not be decomposed at all.

    Raised only for an empty or whitespace-only input. Every other malformation -- an unbalanced
    IPv6 bracket, a port that is not a number, a host of nothing but dots -- is recorded as an
    :class:`Anomaly` on a :class:`ParsedURL` that still carries whatever could be read. A parser
    that raises on hostile input hands the analyst back the raw string and no observations.
    """


# --------------------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------------------


class HostKind(str, Enum):
    """What the host component turned out to be."""

    #: A name. Says nothing about whether the name is resolvable or well-formed.
    DNS_NAME = "dns_name"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    #: No host at all: a non-hierarchical URL, or an authority that was empty.
    NONE = "none"


class UrlAnomaly(str, Enum):
    """Observations worth an analyst's attention. Recording one never changes the parse.

    These are *signals*, not errors. Several are individually unremarkable -- plenty of benign
    sites use IDN -- and become interesting in combination, which is why they are emitted as a
    list for a scorer to weigh rather than collapsed into a verdict here.
    """

    #: The input contained ASCII control characters (tab, CR, LF, NUL...). They were removed
    #: before parsing, which is what a browser does, and recorded because splitting a hostname
    #: across an embedded newline is a filter-evasion technique, not a typo.
    RAW_CONTROL_CHARACTERS = "raw_control_characters"
    #: No scheme was written; :data:`DEFAULT_SCHEME` was assumed.
    SCHEME_ASSUMED = "scheme_assumed"
    #: The scheme is not http or https.
    SCHEME_NON_WEB = "scheme_non_web"
    #: A scheme with no ``//`` authority: ``javascript:``, ``data:``, ``mailto:``, ``tel:``.
    NON_HIERARCHICAL_URL = "non_hierarchical_url"
    #: Credentials were present before the ``@``.
    USERINFO_PRESENT = "userinfo_present"
    #: The username itself looks like a hostname, which is the classic
    #: ``hxxps://www.bank.example@evil.com/`` display trick.
    USERINFO_IMPERSONATES_HOST = "userinfo_impersonates_host"
    #: There was no host to parse.
    HOST_MISSING = "host_missing"
    #: The host contained a ``%`` escape. A hostname never needs one; browsers decode it anyway.
    HOST_PERCENT_ENCODED = "host_percent_encoded"
    #: The host contained non-ASCII characters (an IDN in its unicode form).
    HOST_NON_ASCII = "host_non_ascii"
    #: The host contained at least one ``xn--`` label.
    HOST_PUNYCODE_LABEL = "host_punycode_label"
    #: An ``xn--`` label would not decode. Malformed punycode is not a typo an operator makes.
    HOST_PUNYCODE_UNDECODABLE = "host_punycode_undecodable"
    #: An ``xn--`` label decoded, but re-encoding the result did not reproduce it. The two forms
    #: of the same host disagree, so the label a resolver sees is not the label a human reads.
    HOST_PUNYCODE_ROUND_TRIP_MISMATCH = "host_punycode_round_trip_mismatch"
    #: One label mixes writing systems (Latin with Cyrillic, say). The homograph signal.
    HOST_MIXED_SCRIPT = "host_mixed_script"
    #: The host contained an empty label: a leading dot, or ``..``.
    HOST_EMPTY_LABEL = "host_empty_label"
    #: The host ended in a dot. Legal as a fully-qualified name and a known filter-evasion form,
    #: so the dot is kept and the fact is reported.
    HOST_TRAILING_DOT = "host_trailing_dot"
    #: The host is an address written in a non-dotted-quad form: integer, hex, or octal.
    HOST_OBFUSCATED_IP_FORM = "host_obfuscated_ip_form"
    #: Multiple colons outside brackets: an IPv6 literal that was not bracketed, or an unbalanced
    #: bracket. The whole authority is kept as the host rather than guessed at.
    HOST_MALFORMED_IPV6 = "host_malformed_ipv6"
    #: A port was written that is not an integer in 0-65535. Kept verbatim in
    #: :attr:`ParsedURL.port_raw`; :attr:`ParsedURL.port` stays ``None``.
    PORT_INVALID = "port_invalid"
    #: A percent escape decoded to an overlong UTF-8 sequence (``%C0%AE`` for ``.``, say). There
    #: is no legitimate producer of these; they exist to slip a character past a filter that
    #: decodes differently from the consumer.
    OVERLONG_PERCENT_ENCODING = "overlong_percent_encoding"
    #: ``%25`` appears, so a literal ``%`` is encoded. Often a double-encoding attempt.
    DOUBLE_PERCENT_ENCODING = "double_percent_encoding"


class RegistrableDomainStatus(str, Enum):
    """Whether an eTLD+1 could be established, and if not, why not.

    **This module never guesses an eTLD+1.** Deriving one requires the Public Suffix List, which
    is neither a dependency of this package nor derivable from the host string: ``evil.co.uk``
    and ``evil.com.au`` reduce to ``co.uk`` and ``com.au`` under any last-two-labels rule, while
    ``a.evil.com`` reduces correctly. A wrong eTLD+1 does not fail loudly -- it silently pivots
    an entire investigation onto the wrong entity, and every artefact downstream inherits the
    error looking exactly as confident as a right one.

    So the honest states are the ones below, and :attr:`ParsedURL.pivot_host` gives callers the
    full host to pivot on instead. :attr:`RESOLVED` exists for the day a PSL-backed
    implementation lands; the model validator makes it unusable without an actual value.
    """

    #: A public suffix list established the boundary. Not produced by this implementation.
    RESOLVED = "resolved"
    #: A name was present, but no public suffix list is available to split it.
    UNAVAILABLE_NO_PUBLIC_SUFFIX_LIST = "unavailable_no_public_suffix_list"
    #: The host is an IP literal, so there is no registrable domain to find.
    NOT_APPLICABLE_IP_LITERAL = "not_applicable_ip_literal"
    #: A single label (``localhost``) has no registrable domain.
    NOT_APPLICABLE_SINGLE_LABEL = "not_applicable_single_label"
    #: There was no host.
    NOT_APPLICABLE_NO_HOST = "not_applicable_no_host"


class RedirectResolution(str, Enum):
    """How a redirect chain came to be known -- or, normally, why it is not known."""

    #: Nobody followed it, and this tool never will.
    NOT_RESOLVED = "NOT RESOLVED"
    #: A third party's already-completed scan recorded it. The only permitted source.
    FROM_PASSIVE_RECORD = "FROM PASSIVE RECORD"


#: Why :func:`parse_url` never reports a chain. Written once so the report, the model default and
#: the OPSEC document cannot drift apart.
NOT_RESOLVED_REASON = (
    "not followed: resolving a redirect or expanding a shortener is an active fetch of the "
    "target, and a bodyless request is not exempt. The target's server logs the request and its "
    "source, single-use links are burned by the lookup, and kits that serve benign content to "
    "the first visitor invert the verdict. See docs/OPSEC.md section 7. A chain can be reported "
    "here only when a third party already recorded one."
)


# --------------------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------------------


class _Frozen(BaseModel):
    """Immutable, and an unknown key is an error rather than a silently ignored field."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class Anomaly(_Frozen):
    """One observation about the URL, with enough detail to act on without re-parsing."""

    code: UrlAnomaly
    #: Which component it was seen in: ``url``, ``scheme``, ``userinfo``, ``host``, ``port``,
    #: ``path``, ``query`` or ``fragment``. Lets a renderer group them the way an analyst reads.
    component: str = Field(min_length=1)
    #: What was actually seen. Never a recommendation, never a score.
    detail: str = Field(min_length=1)

    def __str__(self) -> str:
        return f"{self.code.value} [{self.component}]: {self.detail}"


class RedirectChain(_Frozen):
    """Where a URL leads -- reported honestly as unknown, or sourced from someone else's scan.

    The default and only state :func:`parse_url` can produce is
    :attr:`RedirectResolution.NOT_RESOLVED`, so a report can say "NOT RESOLVED, because following
    it would be an active fetch" instead of leaving a blank an analyst reads as "no redirect".
    Those are opposite claims and the blank is the dangerous one.

    There is no ``resolve()`` method and there must never be one. The only way this object gains
    hops is :meth:`from_passive_record`, which requires a named third-party source -- a chain
    with no provenance is an assertion, and one produced locally is a passivity breach.
    """

    resolution: RedirectResolution = RedirectResolution.NOT_RESOLVED
    reason: str = Field(default=NOT_RESOLVED_REASON, min_length=1)
    #: The chain as some third party recorded it, first hop first. Empty unless resolved.
    hops: Tuple[str, ...] = ()
    #: Where the chain ended, as that third party saw it, at :attr:`observed_at`.
    final_url: Optional[str] = None
    #: The provider and field the chain came from, e.g. ``"virustotal:last_final_url"``.
    source: Optional[str] = None
    #: When the third party observed it, RFC 3339. A cached chain is a historical claim: the
    #: redirector may point somewhere else now, and often does.
    observed_at: Optional[str] = None

    @model_validator(mode="after")
    def _unresolved_means_empty(self) -> RedirectChain:
        if self.resolution is RedirectResolution.NOT_RESOLVED:
            if self.hops or self.final_url:
                raise ValueError(
                    "a NOT RESOLVED redirect chain may not carry hops or a final URL. If a "
                    "third party recorded the chain, build it with "
                    "RedirectChain.from_passive_record so the source is on the record."
                )
        elif not self.source:
            raise ValueError(
                "a resolved redirect chain must name the passive source it came from. An "
                "unsourced chain is indistinguishable from one this tool fetched itself, which "
                "it must never do (docs/OPSEC.md section 7)."
            )
        return self

    @property
    def resolved(self) -> bool:
        """True only when a third party's completed scan supplied the chain."""
        return self.resolution is RedirectResolution.FROM_PASSIVE_RECORD

    @classmethod
    def not_resolved(cls, reason: str = NOT_RESOLVED_REASON) -> RedirectChain:
        """The default state. ``reason`` is overridable for a caller that consulted a passive
        source and found no record -- "nobody has scanned this" is a different fact from
        "we did not look"."""
        return cls(resolution=RedirectResolution.NOT_RESOLVED, reason=reason)

    @classmethod
    def from_passive_record(
        cls,
        hops: Tuple[str, ...],
        *,
        source: str,
        final_url: Optional[str] = None,
        observed_at: Optional[str] = None,
    ) -> RedirectChain:
        """Build a chain from a scan a third party already completed.

        ``source`` is required and must name the provider and field, because the whole
        distinction this class enforces is between a chain somebody else recorded and one this
        tool went and fetched.
        """
        if not source.strip():
            raise ValueError("a passively-sourced redirect chain must name its source")
        return cls(
            resolution=RedirectResolution.FROM_PASSIVE_RECORD,
            reason=f"sourced from {source}; not followed by this tool",
            hops=tuple(hops),
            final_url=final_url if final_url is not None else (hops[-1] if hops else None),
            source=source,
            observed_at=observed_at,
        )

    def render(self) -> str:
        """One line for a report. Always states the resolution word first."""
        if not self.resolved:
            return f"{self.resolution.value} -- {self.reason}"
        chain = " -> ".join(self.hops) if self.hops else "(no hops recorded)"
        when = f", observed {self.observed_at}" if self.observed_at else ""
        return f"{self.resolution.value} ({self.source}{when}): {chain}"


class ParsedURL(_Frozen):
    """A decomposed URL. Every field is an observation; none of them required a request."""

    #: The input exactly as given, before control characters were removed or anything was
    #: trimmed. The evidence record starts here.
    raw: str
    scheme: str
    #: True when no scheme was written and :data:`DEFAULT_SCHEME` was supplied by this parser.
    scheme_assumed: bool = False
    #: False for ``javascript:``, ``data:``, ``mailto:`` and friends, where :attr:`path` holds
    #: the opaque body and there is no host.
    is_hierarchical: bool = True

    #: Whether credentials preceded the host. The construction is a phishing signal in itself.
    userinfo_present: bool = False
    #: The userinfo verbatim, password included. This is attacker-authored content belonging to
    #: the indicator under investigation, not an operator credential, and dropping it is the
    #: defect this field exists to fix. Human-facing output should use :attr:`masked_url`.
    userinfo: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None

    #: Lowercased, brackets removed for IPv6. Otherwise exactly as written -- percent escapes,
    #: empty labels, trailing dot and all.
    host: str = ""
    host_kind: HostKind = HostKind.NONE
    #: The unicode (IDN) form, when every label could be expressed as one. ``None`` for IP
    #: literals and when a label would not decode.
    host_unicode: Optional[str] = None
    #: The all-ASCII (punycode) form -- what a resolver would actually be asked for. ``None`` for
    #: IP literals and when a label would not encode.
    host_punycode: Optional[str] = None

    #: Always ``None`` in this implementation. Read :attr:`registrable_domain_status` for why and
    #: pivot on :attr:`pivot_host` instead.
    registrable_domain: Optional[str] = None
    registrable_domain_status: RegistrableDomainStatus = RegistrableDomainStatus.NOT_APPLICABLE_NO_HOST

    #: The port when it is an integer in range, else ``None`` with :attr:`port_raw` set.
    port: Optional[int] = None
    #: The port exactly as written, present only when one was written.
    port_raw: Optional[str] = None

    #: Case-preserved. Path and query carry campaign identifiers; lowercasing them loses the
    #: link between two samples.
    path: str = ""
    query: str = ""
    fragment: str = ""

    anomalies: Tuple[Anomaly, ...] = ()
    #: NOT RESOLVED, always, when this object came from :func:`parse_url`.
    redirect_chain: RedirectChain = Field(default_factory=RedirectChain.not_resolved)

    @model_validator(mode="after")
    def _registrable_domain_is_consistent(self) -> ParsedURL:
        resolved = self.registrable_domain_status is RegistrableDomainStatus.RESOLVED
        if resolved and not self.registrable_domain:
            raise ValueError("registrable_domain_status is RESOLVED but no registrable_domain was supplied")
        if not resolved and self.registrable_domain:
            raise ValueError(
                f"registrable_domain {self.registrable_domain!r} was supplied with status "
                f"{self.registrable_domain_status.value}. An eTLD+1 that is not backed by a "
                "public suffix list must not be recorded as one; a wrong boundary mis-pivots "
                "the whole investigation and looks exactly as confident as a right one."
            )
        return self

    # -- derived views -------------------------------------------------------------------

    @property
    def anomaly_codes(self) -> Tuple[UrlAnomaly, ...]:
        """Just the codes, in the order they were observed."""
        return tuple(anomaly.code for anomaly in self.anomalies)

    def has_anomaly(self, code: UrlAnomaly) -> bool:
        return any(anomaly.code is code for anomaly in self.anomalies)

    @property
    def host_ascii(self) -> str:
        """The form a resolver would be asked for: punycode when derivable, else the host."""
        return self.host_punycode or self.host

    @property
    def pivot_host(self) -> str:
        """What to pivot an investigation on.

        The full host, deliberately. Without a public suffix list the eTLD+1 is not derivable,
        and a guessed one sends the investigation to the wrong entity (see
        :class:`RegistrableDomainStatus`).
        """
        return self.host

    @property
    def host_in_url(self) -> str:
        """The host as it appears inside a URL: re-bracketed when it is an IPv6 literal."""
        return f"[{self.host}]" if self.host_kind is HostKind.IPV6 else self.host

    @property
    def authority(self) -> str:
        """``userinfo@host:port`` with IPv6 re-bracketed. Empty for a non-hierarchical URL."""
        if not self.is_hierarchical:
            return ""
        credentials = "" if self.userinfo is None else f"{self.userinfo}@"
        port = "" if self.port_raw is None else f":{self.port_raw}"
        return f"{credentials}{self.host_in_url}{port}"

    def _rebuild(self, authority: str) -> str:
        separator = "://" if self.is_hierarchical else ":"
        tail = self.path
        if self.query:
            tail += f"?{self.query}"
        if self.fragment:
            tail += f"#{self.fragment}"
        return f"{self.scheme}{separator}{authority}{tail}"

    @property
    def normalised_url(self) -> str:
        """The URL reassembled from the parsed components.

        Lowercased scheme and host, everything else byte-for-byte as written. Re-parsing this
        string yields the same components, which is the round-trip property the tests pin --
        with the one deliberate exception that :attr:`scheme_assumed` becomes ``False``, because
        after reassembly the scheme really is written down.
        """
        return self._rebuild(self.authority)

    @property
    def masked_url(self) -> str:
        """:attr:`normalised_url` with any password replaced. For human-facing output."""
        if self.password is None:
            return self.normalised_url
        port = "" if self.port_raw is None else f":{self.port_raw}"
        return self._rebuild(f"{self.username or ''}:***@{self.host_in_url}{port}")


# --------------------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------------------

# RFC 3986 section 3.1 scheme syntax, anchored to the hierarchical "//" form. Requiring the
# slashes is what stops "evil.com:8080/a" being read as a URL in scheme "evil.com" -- a dot is a
# legal scheme character, so the naive reading is syntactically valid and wildly wrong.
_HIERARCHICAL_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://")

# The same scheme syntax without the slashes, for "javascript:", "data:", "mailto:".
_OPAQUE_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):(.*)$", re.DOTALL)

# What follows a colon when the colon is a port separator rather than a scheme separator:
# digits, then optionally a path, query or fragment. "localhost:8080/a" and "evil.com:443".
_PORT_TAIL_RE = re.compile(r"^\d*(?:[/?#].*)?$", re.DOTALL)

#: Where the authority ends, per RFC 3986 section 3.2.
_AUTHORITY_END = "/?#"

# C0 controls and DEL. Browsers strip tab/CR/LF from a URL, so a hostname split across an
# embedded newline resolves anyway; the stripping is reproduced here and recorded as a signal.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

_PERCENT_ESCAPE_RE = re.compile(r"%([0-9A-Fa-f]{2})")

_ASCII_DIGITS_RE = re.compile(r"^[0-9]+$")

# An address written as a single integer, or with hex or octal octets. Each is a documented way
# of writing an address that a filter matching dotted quads will miss.
_OBFUSCATED_ADDRESS_PART_RE = re.compile(r"^(?:0[xX][0-9A-Fa-f]+|0[0-7]+|[0-9]+)$")


def _record(anomalies: List[Anomaly], code: UrlAnomaly, component: str, detail: str) -> None:
    anomalies.append(Anomaly(code=code, component=component, detail=detail))


def _split_tail(text: str) -> Tuple[str, str, str]:
    """Split ``path?query#fragment`` per RFC 3986 section 3: fragment first, then query.

    Hand-written rather than delegated to :func:`urllib.parse.urlsplit`, for two reasons that
    both bear directly on what this module is for. ``urlsplit`` deletes tab, CR and LF from the
    input without saying so, which erases the evidence of an embedded-newline evasion this
    parser exists to record; and it raises ``ValueError`` on an unbalanced IPv6 bracket, which
    turns a hostile-but-informative string into no observations at all. The algorithm itself is
    two partitions and is fully specified by the RFC.
    """
    head, _, fragment = text.partition("#")
    path, _, query = head.partition("?")
    return path, query, fragment


def _split_scheme(text: str) -> Tuple[str, bool, str]:
    """Return ``(scheme, hierarchical, remainder)``. An empty scheme means none was written.

    ``remainder`` is what follows ``scheme://`` for a hierarchical URL, or what follows
    ``scheme:`` for an opaque one.
    """
    match = _HIERARCHICAL_SCHEME_RE.match(text)
    if match:
        return match.group(1).lower(), True, text[match.end() :]

    if text.startswith("//"):  # protocol-relative: an authority with the scheme left off
        return "", True, text[2:]

    # A colon this early is a scheme separator only when what follows is not a port. Without
    # that test 'evil.com:8080/a' parses as scheme 'evil.com' -- syntactically valid, and it
    # loses the host entirely.
    opaque = _OPAQUE_SCHEME_RE.match(text)
    if opaque and not _PORT_TAIL_RE.match(opaque.group(2)):
        return opaque.group(1).lower(), False, opaque.group(2)

    return "", True, text


def _split_authority(remainder: str) -> Tuple[str, str]:
    """Split the authority from everything after it."""
    for index, char in enumerate(remainder):
        if char in _AUTHORITY_END:
            return remainder[:index], remainder[index:]
    return remainder, ""


def _split_host_and_port(hostport: str, anomalies: List[Anomaly]) -> Tuple[str, Optional[str], bool]:
    """Return ``(host, port_text, is_bracketed)`` without repairing anything."""
    if hostport.startswith("["):
        closing = hostport.find("]")
        if closing == -1:
            _record(
                anomalies,
                UrlAnomaly.HOST_MALFORMED_IPV6,
                "host",
                f"opening bracket with no closing bracket in {hostport!r}; kept as written",
            )
            return hostport, None, False
        host = hostport[1:closing]
        after = hostport[closing + 1 :]
        if after.startswith(":"):
            return host, after[1:], True
        if after:
            _record(
                anomalies,
                UrlAnomaly.HOST_MALFORMED_IPV6,
                "host",
                f"trailing {after!r} after the bracketed address",
            )
        return host, None, True

    if hostport.count(":") > 1:
        _record(
            anomalies,
            UrlAnomaly.HOST_MALFORMED_IPV6,
            "host",
            f"{hostport.count(':')} colons outside brackets; an IPv6 literal in a URL must be "
            "bracketed. The whole authority is kept as the host rather than guessed at",
        )
        return hostport, None, False

    if ":" in hostport:
        host, _, port_text = hostport.partition(":")
        return host, port_text, False
    return hostport, None, False


def _classify_host(host: str, bracketed: bool, anomalies: List[Anomaly]) -> HostKind:
    if not host:
        return HostKind.NONE
    try:
        address = ip_address(host)
    except ValueError:
        if bracketed:
            _record(
                anomalies,
                UrlAnomaly.HOST_MALFORMED_IPV6,
                "host",
                f"{host!r} was bracketed as an IPv6 literal but is not one",
            )
        return HostKind.DNS_NAME
    return HostKind.IPV6 if address.version == 6 else HostKind.IPV4


def _script_of(char: str) -> Optional[str]:
    """A coarse writing-system label from the character's Unicode name.

    ``LATIN SMALL LETTER A`` -> ``LATIN``, ``CYRILLIC SMALL LETTER A`` -> ``CYRILLIC``. Coarse on
    purpose: the question is only whether one label mixes writing systems, and the first word of
    the Unicode name answers it without a script-property table.
    """
    if not char.isalpha():
        return None
    try:
        return unicodedata.name(char).split()[0]
    except ValueError:  # unnamed codepoint
        return None


def _label_to_ascii(label: str) -> Optional[str]:
    """One label in punycode form, or ``None`` when it will not encode."""
    if label.isascii():
        return label
    try:
        return "xn--" + label.encode("punycode").decode("ascii")
    except (UnicodeError, ValueError):
        return None


def _label_to_unicode(label: str) -> Optional[str]:
    """One ``xn--`` label decoded, or ``None`` when it will not decode."""
    if not label.lower().startswith("xn--"):
        return label
    body = label[4:]
    if not body:
        return None
    try:
        return body.encode("ascii").decode("punycode")
    except (UnicodeError, ValueError):
        return None


def _has_overlong_utf8(text: str) -> bool:
    """True when the text's percent escapes decode to an overlong UTF-8 sequence.

    0xC0 and 0xC1 can only ever start an overlong two-byte form; 0xE0 followed by 0x80-0x9F and
    0xF0 followed by 0x80-0x8F are the overlong three- and four-byte forms. No encoder emits
    these. They exist so that a filter and its consumer disagree about what the string says.
    """
    escapes = _PERCENT_ESCAPE_RE.findall(text)
    if not escapes:
        return False
    octets = [int(value, 16) for value in escapes]
    for index, octet in enumerate(octets):
        if octet in (0xC0, 0xC1):
            return True
        following = octets[index + 1] if index + 1 < len(octets) else None
        if following is None:
            continue
        if octet == 0xE0 and 0x80 <= following <= 0x9F:
            return True
        if octet == 0xF0 and 0x80 <= following <= 0x8F:
            return True
    return False


def _inspect_encoding(text: str, component: str, anomalies: List[Anomaly]) -> None:
    """Percent-encoding signals that apply to any component."""
    if "%25" in text:
        _record(
            anomalies,
            UrlAnomaly.DOUBLE_PERCENT_ENCODING,
            component,
            "contains %25, an encoded percent sign, which is how a double-encoded escape is written",
        )
    if _has_overlong_utf8(text):
        _record(
            anomalies,
            UrlAnomaly.OVERLONG_PERCENT_ENCODING,
            component,
            "percent escapes decode to an overlong UTF-8 sequence, which no encoder produces",
        )


def _inspect_host(host: str, host_kind: HostKind, anomalies: List[Anomaly]) -> Tuple[Optional[str], Optional[str]]:
    """Record host-level signals and return ``(host_unicode, host_punycode)``.

    Nothing here changes ``host``. Every finding is additive, because a parser that repairs a
    hostile hostname produces a clean-looking record of it.
    """
    if not host:
        _record(anomalies, UrlAnomaly.HOST_MISSING, "host", "no host component was present")
        return None, None

    if "%" in host:
        _record(
            anomalies,
            UrlAnomaly.HOST_PERCENT_ENCODED,
            "host",
            f"{host!r} contains a percent escape; a hostname never requires one",
        )
    _inspect_encoding(host, "host", anomalies)

    if host_kind in (HostKind.IPV4, HostKind.IPV6):
        return None, None

    # A single trailing dot is the fully-qualified form and is stripped for label analysis only;
    # the host field keeps it, because writing one is also a way past a naive string filter.
    core = host[:-1] if host.endswith(".") else host
    labels = core.split(".")
    if host.endswith(".") and core:
        _record(
            anomalies,
            UrlAnomaly.HOST_TRAILING_DOT,
            "host",
            "the host ends in a dot (a fully-qualified name); kept as written",
        )
    if any(not label for label in labels):
        _record(
            anomalies,
            UrlAnomaly.HOST_EMPTY_LABEL,
            "host",
            f"{host!r} contains an empty label (a leading dot, '..', or a host of only dots)",
        )

    if not host.isascii():
        _record(
            anomalies,
            UrlAnomaly.HOST_NON_ASCII,
            "host",
            f"{host!r} contains non-ASCII characters (an internationalised name)",
        )
    if any(label.lower().startswith("xn--") for label in labels):
        _record(
            anomalies,
            UrlAnomaly.HOST_PUNYCODE_LABEL,
            "host",
            f"{host!r} contains a punycode label",
        )

    for label in labels:
        scripts = {script for script in (_script_of(char) for char in label) if script}
        if len(scripts) > 1:
            _record(
                anomalies,
                UrlAnomaly.HOST_MIXED_SCRIPT,
                "host",
                f"label {label!r} mixes writing systems ({', '.join(sorted(scripts))}), which is "
                "how a homograph is built",
            )

    # host_kind already excluded a well-formed address, so anything that still parses as a
    # sequence of integer/hex/octal parts is an address written in a form a dotted-quad filter
    # will not match. At most four parts, or it is not an address at all.
    if 1 <= len(labels) <= 4 and all(label and _OBFUSCATED_ADDRESS_PART_RE.match(label) for label in labels):
        _record(
            anomalies,
            UrlAnomaly.HOST_OBFUSCATED_IP_FORM,
            "host",
            f"{host!r} is an address written in integer, hex or octal form rather than as a "
            "dotted quad, which defeats a filter matching dotted quads",
        )

    # Encoding uses the labels of the host as written, trailing dot included, so that joining
    # them back up reproduces the host rather than quietly normalising it.
    all_labels = host.split(".")
    ascii_labels = [_label_to_ascii(label) for label in all_labels]
    unicode_labels = [_label_to_unicode(label) for label in all_labels]

    for label, decoded in zip(all_labels, unicode_labels, strict=False):
        if decoded is None:
            _record(
                anomalies,
                UrlAnomaly.HOST_PUNYCODE_UNDECODABLE,
                "host",
                f"punycode label {label!r} does not decode",
            )
            continue
        if decoded == label:
            continue
        re_encoded = _label_to_ascii(decoded)
        if re_encoded is None or re_encoded.lower() != label.lower():
            _record(
                anomalies,
                UrlAnomaly.HOST_PUNYCODE_ROUND_TRIP_MISMATCH,
                "host",
                f"label {label!r} decodes to {decoded!r} but re-encodes to {re_encoded!r}; the "
                "name a resolver sees and the name a human reads are not the same name",
            )

    # Empty labels are kept, not filtered: dropping them would silently turn 'evil..com' into
    # 'evil.com' and delete the trailing dot, which are two of the signals recorded above.
    host_punycode = (
        None
        if any(label is None for label in ascii_labels)
        else ".".join(label for label in ascii_labels if label is not None)
    )
    host_unicode = (
        None
        if any(label is None for label in unicode_labels)
        else ".".join(label for label in unicode_labels if label is not None)
    )
    return host_unicode, host_punycode


def _registrable_domain_status(host: str, host_kind: HostKind) -> RegistrableDomainStatus:
    if host_kind is HostKind.NONE or not host:
        return RegistrableDomainStatus.NOT_APPLICABLE_NO_HOST
    if host_kind in (HostKind.IPV4, HostKind.IPV6):
        return RegistrableDomainStatus.NOT_APPLICABLE_IP_LITERAL
    if len([label for label in host.rstrip(".").split(".") if label]) < 2:
        return RegistrableDomainStatus.NOT_APPLICABLE_SINGLE_LABEL
    return RegistrableDomainStatus.UNAVAILABLE_NO_PUBLIC_SUFFIX_LIST


def parse_url(value: str, *, default_scheme: str = DEFAULT_SCHEME) -> ParsedURL:
    """Decompose a URL. Performs no I/O and contacts nothing, ever.

    ``default_scheme`` is recorded as assumed whenever it is used. Raises :class:`UrlParseError`
    only for an empty input; every other malformation is reported as an :class:`Anomaly` on a
    record that still carries whatever could be read.
    """
    raw = value
    trimmed = value.strip()
    anomalies: List[Anomaly] = []

    controls = _CONTROL_CHARS_RE.findall(trimmed)
    if controls:
        _record(
            anomalies,
            UrlAnomaly.RAW_CONTROL_CHARACTERS,
            "url",
            "the input contained control characters "
            f"({', '.join(sorted({f'U+{ord(c):04X}' for c in controls}))}); they were removed "
            "before parsing, as a browser would, and are recorded because splitting a hostname "
            "across an embedded newline is a filter-evasion technique",
        )
        trimmed = _CONTROL_CHARS_RE.sub("", trimmed)

    if not trimmed:
        raise UrlParseError("cannot parse an empty URL")

    written_scheme, hierarchical, remainder = _split_scheme(trimmed)
    assumed = not written_scheme
    scheme = default_scheme.lower() if assumed else written_scheme
    if assumed:
        _record(
            anomalies,
            UrlAnomaly.SCHEME_ASSUMED,
            "scheme",
            f"no scheme was written; {scheme!r} was assumed by this parser and is not what the sender wrote",
        )
    if scheme not in WEB_SCHEMES:
        _record(
            anomalies,
            UrlAnomaly.SCHEME_NON_WEB,
            "scheme",
            f"scheme {scheme!r} is not http or https",
        )

    if not hierarchical:
        _record(
            anomalies,
            UrlAnomaly.NON_HIERARCHICAL_URL,
            "url",
            f"{scheme!r} carries an opaque body rather than a '//' authority; there is no host",
        )
        path, query, fragment = _split_tail(remainder)
        _inspect_encoding(path, "path", anomalies)
        _inspect_encoding(query, "query", anomalies)
        return ParsedURL(
            raw=raw,
            scheme=scheme,
            scheme_assumed=assumed,
            is_hierarchical=False,
            host_kind=HostKind.NONE,
            registrable_domain_status=RegistrableDomainStatus.NOT_APPLICABLE_NO_HOST,
            path=path,
            query=query,
            fragment=fragment,
            anomalies=tuple(anomalies),
        )

    authority, tail = _split_authority(remainder)
    path, query, fragment = _split_tail(tail)

    userinfo: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    hostport = authority
    if "@" in authority:
        # Rightmost '@' wins: an unencoded '@' inside the userinfo is legal-ish and common in
        # credential-bearing lures, and taking the leftmost would move half the userinfo into
        # the host.
        userinfo, _, hostport = authority.rpartition("@")
        username, separator, remainder_pw = userinfo.partition(":")
        password = remainder_pw if separator else None
        _record(
            anomalies,
            UrlAnomaly.USERINFO_PRESENT,
            "userinfo",
            f"credentials precede the host (username {username!r}"
            f"{', password present' if password is not None else ''}). The CLI drops these "
            "today; the construction is itself a phishing signal",
        )
        if "." in username and len(username) > 3:
            _record(
                anomalies,
                UrlAnomaly.USERINFO_IMPERSONATES_HOST,
                "userinfo",
                f"username {username!r} is shaped like a hostname, which is the 'brand-name@real-host' display trick",
            )

    host, port_raw, bracketed = _split_host_and_port(hostport, anomalies)
    host = host.lower()
    host_kind = _classify_host(host, bracketed, anomalies)
    host_unicode, host_punycode = _inspect_host(host, host_kind, anomalies)

    if port_raw == "":  # 'evil.com:' -- a separator with nothing after it is no port at all
        port_raw = None
    port: Optional[int] = None
    if port_raw is not None:
        # str.isdigit() is true for Arabic-Indic and other non-ASCII digits, which int() then
        # happily accepts; an ASCII-only match is what a port actually is.
        if _ASCII_DIGITS_RE.match(port_raw) and int(port_raw) <= 65535:
            port = int(port_raw)
        else:
            _record(
                anomalies,
                UrlAnomaly.PORT_INVALID,
                "port",
                f"{port_raw!r} is not an integer in 0-65535; kept verbatim, not repaired",
            )

    _inspect_encoding(path, "path", anomalies)
    _inspect_encoding(query, "query", anomalies)

    return ParsedURL(
        raw=raw,
        scheme=scheme,
        scheme_assumed=assumed,
        is_hierarchical=True,
        userinfo_present=userinfo is not None,
        userinfo=userinfo,
        username=username,
        password=password,
        host=host,
        host_kind=host_kind,
        host_unicode=host_unicode,
        host_punycode=host_punycode,
        registrable_domain=None,
        registrable_domain_status=_registrable_domain_status(host, host_kind),
        port=port,
        port_raw=port_raw,
        path=path,
        query=query,
        fragment=fragment,
        anomalies=tuple(anomalies),
        redirect_chain=RedirectChain.not_resolved(),
    )


def summarise_anomalies(parsed: ParsedURL) -> Dict[str, List[str]]:
    """Anomaly details grouped by component, for a renderer that shows them under each field."""
    grouped: Dict[str, List[str]] = {}
    for anomaly in parsed.anomalies:
        grouped.setdefault(anomaly.component, []).append(f"{anomaly.code.value}: {anomaly.detail}")
    return grouped
