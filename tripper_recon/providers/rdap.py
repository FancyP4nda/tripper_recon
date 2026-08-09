"""RDAP -- registration data straight from the registry that holds it. Roadmap 8.2.

The domain path has VirusTotal and OTX, and both answer the same question: has anybody seen
this before. RDAP answers two questions nothing else in this tool can:

* **When was this domain registered.** A name created nine days ago that resolves to a login
  page is the single most actionable fact available in a phishing triage, and it costs nothing
  -- no key, no quota, no submission.
* **Who do I send the abuse report to.** The registrar's abuse address is the operational
  output of an incident, and it is carried in the same response.

Neither is a reputation score. Both are registry facts, which is what makes them useful when
every reputation provider says "no data" because the domain is nine days old.


THE DESIGN PROBLEM, AND HOW IT IS RESOLVED
------------------------------------------

RDAP has no single endpoint. Every TLD and every RIR runs its own server, and a client finds
the right one through a bootstrap step (STD 95, RFC 9224, "Finding the Authoritative
Registration Data Access Protocol (RDAP) Service"). There are two ways to do that step and they
are not equivalent for a tool whose whole claim is a reviewed, static list of hosts it will
contact:

1. **Aggregator.** ``rdap.org`` accepts a query for any resource and answers ``302`` with a
   ``Location`` header naming the authoritative server (about.rdap.org). It is a *redirector*,
   not a proxy -- it never returns registration data itself, so using it means following a
   redirect to a host chosen at runtime. That is precisely the hole the egress allowlist exists
   to close, and unbounded redirect-following is forbidden outright by ``docs/OPSEC.md``
   section 7. It also inserts a third party -- one volunteer's service, rate-limited to ten
   requests per ten seconds -- between the operator and the registry, which learns the
   operator's entire indicator list for the privilege.

2. **Bootstrap client-side, then call the registry directly.** IANA publishes the mapping as
   four static JSON files (the DNS, IPv4, IPv6 and AS-number bootstrap registries, RFC 9224).
   Fetch them once, cache them, resolve the authoritative base URL locally, and issue exactly
   one ``GET`` to that base URL.

**This module does (2), and follows no redirects at all.** Three properties follow, and they are
the reason for the choice:

* **The indicator never leaves for an intermediary.** IANA sees one request for a static file
  per process, whatever the indicator was. The registry sees the query, because the registry is
  the party that holds the answer. Nobody else sees anything.
* **There is no redirect to bound.** :func:`_rdap_lookup` sets redirect-following off explicitly, and
  a ``3xx`` from a registry is reported as :data:`ERROR_UNEXPECTED_REDIRECT` with the host it
  pointed at, so the operator can review that host deliberately instead of a client following
  it silently.
* **The destination is still checked before the socket opens.** The resolved base URL is a
  *dynamic* host -- that is inherent to RDAP and cannot be designed away. So this module
  refuses to issue the request unless the host is on ``utils.http.ALLOWED_EGRESS_HOSTS``, and
  returns :data:`ERROR_REGISTRY_NOT_ALLOWLISTED` naming the host when it is not. The runtime
  hook in ``utils/http.py`` would raise ``PassiveBoundaryViolation`` in that case, which is a
  programming-error path that aborts the run; a provider that knows its destination is dynamic
  owes the caller a clean envelope instead. **The hook remains the enforcement.** The check
  here is the courtesy that keeps an unlisted TLD from looking like a crash.

A consequence worth stating plainly rather than hiding: **a domain in a TLD whose registry is
not on the allowlist returns UNKNOWN, not clean.** That is the honest failure and it is the
same shape as every other missing-coverage answer in this tool. The remedy is to add the host,
which is a review step, not a code change here.

**Nothing in this design can be pointed at the target.** The bootstrap file is IANA's, keyed by
TLD and by address range; the target contributes only which row is selected, never the host in
it. A registry RDAP server is a third party that already holds the data, which is the test
``docs/OPSEC.md`` section 1 applies to every destination.


WHY A 404 IS NOT A CLEAN RESULT
-------------------------------

An RDAP ``404`` means this registry has no object with that name *right now*. It is returned
for a name that was never registered, for one that just dropped, and by at least one large
registry for names it does hold but will not answer for. It is :data:`ERROR_NOT_FOUND` --
terminal UNKNOWN -- and it must never be rendered as "no adverse findings".

**One more way to earn a 404: asking for the wrong name.** A registry holds an object for the
*registrable* domain, not for every name under it, so ``login.secure.example.com`` returns 404
while ``example.com`` returns the record. Finding the registrable name requires the Public
Suffix List, which this package does not carry, so **the caller passes the name it wants
looked up** and every envelope -- success or failure -- carries the resource that was actually
asked for, so the operator can see it. Deriving the boundary from the bootstrap entry would be
right for ``com`` and wrong for ``co.uk``, and a provider that silently rewrites the indicator
is worse than one that reports the miss.


READING THE RESPONSE
--------------------

Shapes follow STD 95, RFC 9083, "JSON Responses for the Registration Data Access Protocol
(RDAP)", which obsoletes RFC 7483 (the query format is its companion RFC 9082, obsoleting
RFC 7482). The members this module reads:

* ``events[]`` -- each with a required ``eventAction`` and ``eventDate``. The registered actions
  used here are ``registration``, ``expiration`` and ``last changed``.
* ``entities[]`` -- each with ``roles[]`` (registered values include ``registrar``,
  ``registrant``, ``abuse``, ``technical``), a jCard ``vcardArray`` carrying ``fn``, ``email``
  and ``tel``, and ``publicIds[]`` of ``{type, identifier}`` shape which is where the IANA
  Registrar ID lives. **Entities nest**: the abuse contact is normally an entity *inside* the
  registrar entity, so the search below is recursive. A flat scan finds the abuse address on
  roughly none of the gTLD registries.
* ``status[]`` -- RFC 8056 maps every EPP status onto an RDAP one by lowercasing the camelCase
  and inserting spaces, so the value on the wire is ``"client hold"``, not ``"clientHold"``.
  Registries emit both in practice, so :func:`_normalize_status` accepts either and normalises
  to the RFC 8056 form before anything is compared.
* ``nameservers[]`` -- ``ldhName`` plus optional ``ipAddresses`` of ``{v4:[], v6:[]}``.
* ``secureDNS`` -- ``delegationSigned``, ``dsData[]``, ``keyData[]``.

Every one of those members is optional, and registries vary enormously in which they send. The
coercion helpers below turn an absent or wrong-typed field into ``None`` or an empty list, never
into a benign-looking value. That rule is the whole reason this tool exists.
"""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import re
import time
import weakref
from typing import Any, Dict, FrozenSet, Iterator, List, MutableMapping, Optional, Sequence, Tuple
from urllib.parse import quote

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff
from tripper_recon.utils.http import ALLOWED_EGRESS_HOSTS

# --------------------------------------------------------------------------------------
# Destinations
# --------------------------------------------------------------------------------------

#: IANA's bootstrap registries, published as static JSON (RFC 9224). This is the ONLY host this
#: module names in a URL literal. Every other destination it contacts is read out of these files
#: at runtime and checked against the egress allowlist before a request is built.
IANA_BOOTSTRAP_BASE = "https://data.iana.org/rdap"

#: Bootstrap Service Registry for Domain Name Space (RFC 9224).
BOOTSTRAP_DNS_URL = f"{IANA_BOOTSTRAP_BASE}/dns.json"

#: Bootstrap Service Registry for IPv4 Address Space (RFC 9224).
BOOTSTRAP_IPV4_URL = f"{IANA_BOOTSTRAP_BASE}/ipv4.json"

#: Bootstrap Service Registry for IPv6 Address Space (RFC 9224).
BOOTSTRAP_IPV6_URL = f"{IANA_BOOTSTRAP_BASE}/ipv6.json"

#: Bootstrap Service Registry for AS Number Space (RFC 9224).
BOOTSTRAP_ASN_URL = f"{IANA_BOOTSTRAP_BASE}/asn.json"

#: RDAP's own media type, registered by RFC 9083. Sent alongside plain JSON because a handful of
#: registry servers content-negotiate and answer 406 to an ``application/json``-only Accept.
RDAP_ACCEPT = "application/rdap+json, application/json"

#: How long a fetched bootstrap file is reused before it is fetched again. IANA republishes these
#: rarely -- a new TLD or a re-delegated one -- so an hour is far inside the useful lifetime while
#: still bounding how stale a long-lived process can get. A single CLI invocation fetches once.
BOOTSTRAP_TTL_SECONDS = 3600.0

#: Age at or below which a domain is flagged as newly registered. This is a JUDGEMENT, not a
#: registry fact: thirty days is roughly the window in which a name registered for a campaign has
#: not yet been reported anywhere, which is exactly when every reputation provider answers "no
#: data" and this field is the only signal on the screen. It is published in the payload as
#: ``rdap_newly_registered_threshold_days`` so a consumer can disagree with it explicitly rather
#: than inherit it silently.
NEWLY_REGISTERED_DAYS = 30.0

#: How deep the entity search descends. The abuse contact is one level inside the registrar
#: entity in every gTLD response observed in the specification's own examples; five levels is
#: generous and bounds a hostile or looping response.
MAX_ENTITY_DEPTH = 5


# --------------------------------------------------------------------------------------
# Error slugs
#
# Named rather than inlined so a caller, a test and the renderer cannot disagree about the
# spelling. Every one of them means UNKNOWN. None of them means clean.
# --------------------------------------------------------------------------------------

#: The registry answered, and holds no such object. Terminal UNKNOWN -- see the module docstring.
ERROR_NOT_FOUND = "not_found"

#: The IANA bootstrap file could not be fetched or parsed, so no authoritative server is known.
ERROR_BOOTSTRAP_UNAVAILABLE = "bootstrap_unavailable"

#: The bootstrap file parsed, and contains no service covering this TLD, address or AS number.
ERROR_NO_AUTHORITATIVE_SERVER = "no_authoritative_server"

#: A service exists but publishes no ``https`` base URL. Never downgraded to cleartext: an RDAP
#: query carries the indicator under investigation in its path.
ERROR_NO_SECURE_URL = "no_secure_rdap_url"

#: The authoritative server resolved to a host that is not on ``ALLOWED_EGRESS_HOSTS``. No
#: request was built. The host is reported so it can be reviewed and added deliberately.
ERROR_REGISTRY_NOT_ALLOWLISTED = "registry_not_allowlisted"

#: The registry answered 3xx. Not followed -- see the module docstring.
ERROR_UNEXPECTED_REDIRECT = "unexpected_redirect"

#: The registry rejected the query as malformed (400). Retrying cannot help.
ERROR_INVALID_REQUEST = "invalid_request"

#: The indicator could not be put into the form RDAP queries use.
ERROR_INVALID_INDICATOR = "invalid_indicator"

#: A 2xx whose body is not a JSON object, or is not the object class that was asked for.
ERROR_INVALID_RESPONSE = "invalid_response"


class _BootstrapError(Exception):
    """Internal: a bootstrap file could not be obtained or made sense of.

    Carried as an exception rather than an envelope because the bootstrap step happens inside a
    helper shared by three public functions, each of which converts it to the same envelope. It
    never escapes this module.
    """

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


# --------------------------------------------------------------------------------------
# Coercion helpers
#
# Every field read from a registry response goes through one of these. RDAP responses vary
# enormously between registries and most members are optional, so a missing field must read as
# absent and never as a benign value.
# --------------------------------------------------------------------------------------


def _as_dict(value: Any) -> Dict[str, Any]:
    """Return ``value`` when it is a dict, otherwise an empty dict."""
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    """Return ``value`` when it is a list, otherwise an empty list."""
    return value if isinstance(value, list) else []


def _as_str(value: Any) -> Optional[str]:
    """Return a non-empty stripped string, otherwise ``None``.

    Deliberately not ``str(value)``: coercing a dict or a list into text would manufacture a
    plausible-looking date or address out of a malformed response.
    """
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _as_int(value: Any) -> Optional[int]:
    """Return an int, or ``None``. ``bool`` is rejected -- ``True`` is an ``int`` to Python.

    A numeric string is accepted, because the IANA Registrar ID is published as a string in
    ``publicIds`` and as an integer by at least one registry.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = _as_str(value)
    if text is None:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _as_bool(value: Any) -> Optional[bool]:
    """Return a bool, or ``None``. A missing ``delegationSigned`` is unknown, not ``False``."""
    return value if isinstance(value, bool) else None


def _str_list(value: Any) -> List[str]:
    """The non-empty strings in ``value``, deduplicated, order preserved.

    Order is preserved rather than sorted for nameservers, where the registry's own order is
    occasionally meaningful and never misleading.
    """
    seen: List[str] = []
    for item in _as_list(value):
        text = _as_str(item)
        if text is not None and text not in seen:
            seen.append(text)
    return seen


# --------------------------------------------------------------------------------------
# Timestamps
# --------------------------------------------------------------------------------------


def _parse_rfc3339(value: Any) -> Optional[datetime.datetime]:
    """Parse an RDAP ``eventDate`` into an aware datetime, or ``None``.

    RFC 9083 requires RFC 3339, and registries mostly comply. Two accommodations are made for
    the ones that do not: a trailing ``Z`` is rewritten to ``+00:00`` because
    ``datetime.fromisoformat`` rejects it on Python 3.10, and a fractional-second field of an
    unusual length is retried with the fraction removed for the same reason.

    A value that survives neither is reported as unparseable rather than guessed at. A wrong
    registration date is worse than no registration date -- it would be read as an age.
    """
    text = _as_str(value)
    if text is None:
        return None
    normalized = text[:-1] + "+00:00" if text[-1] in "Zz" else text
    for candidate in (normalized, _without_fractional_seconds(normalized)):
        if candidate is None:
            continue
        try:
            parsed = datetime.datetime.fromisoformat(candidate)
        except ValueError:
            continue
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=datetime.timezone.utc)
    return None


def _without_fractional_seconds(text: str) -> Optional[str]:
    """``2020-01-01T00:00:00.12345+00:00`` -> ``2020-01-01T00:00:00+00:00``, else ``None``."""
    dot = text.find(".")
    if dot == -1:
        return None
    end = dot + 1
    while end < len(text) and text[end].isdigit():
        end += 1
    return text[:dot] + text[end:]


def _reference_now(now: Optional[datetime.datetime]) -> datetime.datetime:
    """The clock used for every age in one call. ``now`` is the test seam."""
    if now is None:
        return datetime.datetime.now(tz=datetime.timezone.utc)
    return now if now.tzinfo is not None else now.replace(tzinfo=datetime.timezone.utc)


def _age_days(value: Any, *, now: datetime.datetime) -> Optional[float]:
    """Age of a timestamp in days, or ``None`` when it could not be parsed.

    A negative value is returned as-is rather than clamped. Negative means the event is stamped
    in the future, which is clock skew or a broken record and is worth seeing; flooring it at
    zero would present a corrupt date as a brand-new registration.
    """
    parsed = _parse_rfc3339(value)
    if parsed is None:
        return None
    return round((now - parsed).total_seconds() / 86400.0, 2)


# --------------------------------------------------------------------------------------
# The bootstrap registries
# --------------------------------------------------------------------------------------


class _Bootstrap:
    """One parsed IANA bootstrap file.

    ``services`` is the RFC 9224 shape flattened to ``(entries, https_base_urls)`` pairs, with
    non-conforming rows dropped at parse time so every matcher below can assume the shape.
    ``publication`` is carried because it is provenance: it dates the mapping that chose the
    server, and a consumer reading a registry answer deserves to know how old the routing
    decision was.
    """

    __slots__ = ("publication", "services", "version")

    def __init__(
        self,
        *,
        version: Optional[str],
        publication: Optional[str],
        services: List[Tuple[List[str], List[str]]],
    ) -> None:
        self.version = version
        self.publication = publication
        self.services = services


def _parse_bootstrap(body: Any) -> _Bootstrap:
    """Turn a bootstrap response body into a :class:`_Bootstrap`.

    RFC 9224 defines each element of ``services`` as a two-element array: an Entry Array and a
    Service URL array. Rows that are not that shape, or that carry no usable entry or no usable
    URL, are dropped rather than half-kept -- a partially-parsed routing table would silently
    send a query to the wrong registry.

    Only ``https`` base URLs are retained. RFC 9224 says the secure transport is to be preferred;
    this module goes further and refuses the cleartext form outright, because the query path
    carries the indicator under investigation.
    """
    envelope = _as_dict(body)
    raw_services = envelope.get("services")
    if not isinstance(raw_services, list):
        raise _BootstrapError("bootstrap body has no 'services' array")

    services: List[Tuple[List[str], List[str]]] = []
    for row in raw_services:
        if not isinstance(row, list) or len(row) < 2:
            continue
        entries = _str_list(row[0])
        urls = [url for url in _str_list(row[1]) if url.lower().startswith("https://")]
        if not entries or not urls:
            continue
        services.append((entries, urls))

    if not services:
        raise _BootstrapError("bootstrap body contains no usable service rows")

    return _Bootstrap(
        version=_as_str(envelope.get("version")),
        publication=_as_str(envelope.get("publication")),
        services=services,
    )


#: Fetched bootstrap files, keyed by URL: ``(monotonic fetch time, parsed file)``.
_bootstrap_cache: Dict[str, Tuple[float, _Bootstrap]] = {}

#: One lock per bootstrap URL per event loop.
#:
#: Keyed by loop, weakly, for the same reason ``utils/http.py`` keys its semaphore that way: an
#: ``asyncio.Lock`` attaches to the loop that first awaits it, so one lock shared across two
#: ``asyncio.run`` calls in the same process raises ``RuntimeError`` the moment it actually has
#: to make a caller wait. The lock matters because a bulk run resolves many domains at once and
#: without it every one of them would fetch the same multi-hundred-kilobyte file.
_loop_locks: MutableMapping[asyncio.AbstractEventLoop, Dict[str, asyncio.Lock]] = weakref.WeakKeyDictionary()


def clear_bootstrap_cache() -> None:
    """Drop every cached bootstrap file. Exposed for tests; nothing in production calls it."""
    _bootstrap_cache.clear()


def _cached(url: str, *, ttl: float) -> Optional[_Bootstrap]:
    entry = _bootstrap_cache.get(url)
    if entry is None:
        return None
    fetched_at, bootstrap = entry
    if ttl <= 0 or (time.monotonic() - fetched_at) > ttl:
        return None
    return bootstrap


def _lock_for(url: str) -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    locks = _loop_locks.get(loop)
    if locks is None:
        locks = {}
        _loop_locks[loop] = locks
    lock = locks.get(url)
    if lock is None:
        lock = asyncio.Lock()
        locks[url] = lock
    return lock


async def _load_bootstrap(*, client: httpx.AsyncClient, url: str, ttl: float) -> _Bootstrap:
    """Return the parsed bootstrap file at ``url``, fetching it at most once per TTL per loop.

    The cache is checked twice: once before taking the lock, so the common case costs nothing,
    and once after, so the waiters behind a fetch do not each repeat it. Raises
    :class:`_BootstrapError` on anything that leaves no usable routing table; the caller turns
    that into the :data:`ERROR_BOOTSTRAP_UNAVAILABLE` envelope.
    """
    cached = _cached(url, ttl=ttl)
    if cached is not None:
        return cached

    async with _lock_for(url):
        cached = _cached(url, ttl=ttl)
        if cached is not None:
            return cached

        async def _call() -> httpx.Response:
            return await client.get(url, headers={"Accept": "application/json"}, follow_redirects=False)

        try:
            response = await with_exponential_backoff(_call)
        except Exception as exc:  # noqa: BLE001 -- converted to an envelope by the caller
            raise _BootstrapError(f"could not fetch {url}: {type(exc).__name__}") from exc

        if response.status_code != 200:
            raise _BootstrapError(f"{url} answered HTTP {response.status_code}")
        try:
            body = response.json()
        except ValueError as exc:
            raise _BootstrapError(f"{url} did not return JSON") from exc

        bootstrap = _parse_bootstrap(body)
        _bootstrap_cache[url] = (time.monotonic(), bootstrap)
        return bootstrap


# --------------------------------------------------------------------------------------
# Matching an indicator to its authoritative service
# --------------------------------------------------------------------------------------


def _match_domain(bootstrap: _Bootstrap, name: str) -> Optional[Tuple[str, List[str]]]:
    """Longest label-wise suffix match, per RFC 9224.

    "The domain name's labels are matched right to left"; where both ``com`` and
    ``example.com`` are registered, the longer entry wins. Implemented by generating every
    suffix of the query name and preferring the one with the most labels.
    """
    labels = [label for label in name.lower().split(".") if label]
    if not labels:
        return None

    best: Optional[Tuple[int, str, List[str]]] = None
    for entries, urls in bootstrap.services:
        for entry in entries:
            entry_labels = [label for label in entry.lower().strip(".").split(".") if label]
            if not entry_labels or len(entry_labels) > len(labels):
                continue
            if labels[-len(entry_labels) :] != entry_labels:
                continue
            if best is None or len(entry_labels) > best[0]:
                best = (len(entry_labels), ".".join(entry_labels), urls)
    if best is None:
        return None
    return best[1], best[2]


def _match_network(bootstrap: _Bootstrap, address: str) -> Optional[Tuple[str, List[str]]]:
    """Longest-prefix match of an address against the IPv4/IPv6 bootstrap entries.

    Entries are CIDR blocks. The most specific covering block wins, which is what makes an
    early-registry legacy block resolve to the RIR that actually administers it rather than to
    whichever row happened to be listed first.
    """
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None

    best: Optional[Tuple[int, str, List[str]]] = None
    for entries, urls in bootstrap.services:
        for entry in entries:
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            if network.version != parsed.version or parsed not in network:
                continue
            if best is None or network.prefixlen > best[0]:
                best = (network.prefixlen, str(network), urls)
    if best is None:
        return None
    return best[1], best[2]


def _match_asn(bootstrap: _Bootstrap, asn: int) -> Optional[Tuple[str, List[str]]]:
    """Match an AS number against the bootstrap entries, which are ``N`` or ``N-M`` ranges.

    The narrowest covering range wins, for the same reason the network matcher prefers the
    longest prefix: a specific delegation inside a broader legacy block is the authoritative
    one.
    """
    best: Optional[Tuple[int, str, List[str]]] = None
    for entries, urls in bootstrap.services:
        for entry in entries:
            bounds = _asn_range(entry)
            if bounds is None:
                continue
            low, high = bounds
            if not low <= asn <= high:
                continue
            width = high - low
            if best is None or width < best[0]:
                best = (width, entry, urls)
    if best is None:
        return None
    return best[1], best[2]


def _asn_range(entry: str) -> Optional[Tuple[int, int]]:
    """``"64496"`` -> ``(64496, 64496)``; ``"64496-64511"`` -> ``(64496, 64511)``; else ``None``."""
    text = entry.strip()
    if "-" in text:
        low_text, _, high_text = text.partition("-")
        low, high = _as_int(low_text), _as_int(high_text)
        if low is None or high is None or low > high:
            return None
        return low, high
    single = _as_int(text)
    return None if single is None else (single, single)


def _select_base_url(urls: Sequence[str]) -> Optional[str]:
    """The first ``https`` base URL, normalised to end in a single ``/``.

    RFC 9082 resolves the query path against the base URL, so the trailing slash decides whether
    the last path segment of the base is kept or replaced. Registries publish the base both ways
    and getting it wrong produces a 404 that looks exactly like "no such domain".
    """
    for url in urls:
        if url.lower().startswith("https://"):
            return url if url.endswith("/") else url + "/"
    return None


def _host_of(url: str) -> str:
    """Lowercased hostname of an absolute URL, port and userinfo stripped."""
    try:
        return (httpx.URL(url).host or "").lower()
    except (ValueError, TypeError):
        return ""


# --------------------------------------------------------------------------------------
# Indicator normalisation
# --------------------------------------------------------------------------------------

_ASCII_LABEL_RE = re.compile(r"^[A-Za-z0-9_-]{1,63}$")


def _query_name(domain: str) -> Optional[str]:
    """The A-label form of ``domain``, lowercased, root dot removed. ``None`` if unusable.

    RFC 9082 permits either A-labels or U-labels in a query and asks that they not be mixed.
    A-labels are used here because they are what every registry indexes and because they are
    unambiguous in a URL path. A U-label input is converted per label; a label that will not
    encode makes the whole name unusable, which is reported rather than papered over with a
    partial conversion.

    Underscore labels are accepted: ``_dmarc.example.com`` is a real name an analyst pastes, and
    the registry will simply answer 404 for it.
    """
    text = _as_str(domain)
    if text is None:
        return None
    text = text.strip().rstrip(".")
    if not text:
        return None

    labels: List[str] = []
    for label in text.split("."):
        if not label:
            return None
        if label.isascii():
            if not _ASCII_LABEL_RE.match(label):
                return None
            labels.append(label.lower())
            continue
        try:
            encoded = "xn--" + label.lower().encode("punycode").decode("ascii")
        except (UnicodeError, ValueError):
            return None
        if len(encoded) > 63:
            return None
        labels.append(encoded)

    if len(labels) < 2:
        # A bare TLD has no domain object to look up at the registry's domain endpoint. Saying
        # so here is better than spending a request to be told 404.
        return None
    return ".".join(labels)


# --------------------------------------------------------------------------------------
# The one request this module makes
# --------------------------------------------------------------------------------------


async def _rdap_lookup(
    *,
    client: httpx.AsyncClient,
    bootstrap_url: str,
    path_prefix: str,
    resource: str,
    matcher_result: Optional[Tuple[str, List[str]]],
    bootstrap: _Bootstrap,
    allowed_hosts: FrozenSet[str],
) -> Dict[str, Any]:
    """Issue the single ``GET`` to the authoritative registry, or explain why it was not issued.

    Returns either ``{"ok": True, "body": <parsed>, ...routing metadata}`` or a failure envelope.
    Redirect-following is off: a ``3xx`` is reported with the host it named so that host can be
    reviewed, never followed. See the module docstring for why that is the whole point.
    """
    if matcher_result is None:
        return {
            "ok": False,
            "error": ERROR_NO_AUTHORITATIVE_SERVER,
            "message": f"the IANA bootstrap registry at {bootstrap_url} lists no RDAP service covering this resource",
        }

    matched_entry, urls = matcher_result
    base = _select_base_url(urls)
    if base is None:
        return {
            "ok": False,
            "error": ERROR_NO_SECURE_URL,
            "message": f"the RDAP service for {matched_entry!r} publishes no https base URL",
        }

    host = _host_of(base)
    if host not in allowed_hosts:
        return {
            "ok": False,
            "error": ERROR_REGISTRY_NOT_ALLOWLISTED,
            "rdap_server": base,
            "rdap_server_host": host,
            "rdap_bootstrap_entry": matched_entry,
            "message": (
                f"the authoritative RDAP server for {matched_entry!r} is {host!r}, which is not on "
                "the egress allowlist. No request was made. This is UNKNOWN, not a clean result. "
                "Add the host to ALLOWED_EGRESS_HOSTS in tripper_recon/utils/http.py, to "
                "ALLOWED_HOSTS in tests/test_passivity.py and to the destination table in "
                "docs/OPSEC.md section 2, in the same commit, if it should be contacted."
            ),
        }

    url = base + path_prefix + resource

    async def _call() -> Dict[str, Any]:
        response = await client.get(url, headers={"Accept": RDAP_ACCEPT}, follow_redirects=False)
        status = response.status_code
        if status == 404:
            # Terminal UNKNOWN. See the module docstring: a registry that holds no record is not
            # a registry that vouched for the name.
            return {"ok": False, "error": ERROR_NOT_FOUND, "rdap_server": base, "rdap_server_host": host}
        if status == 400:
            return {"ok": False, "error": ERROR_INVALID_REQUEST, "status": status, "rdap_server": base}
        if 300 <= status < 400:
            location = _as_str(response.headers.get("Location"))
            redirect_host = (_host_of(location) or None) if location is not None else None
            return {
                "ok": False,
                "error": ERROR_UNEXPECTED_REDIRECT,
                "status": status,
                "rdap_server": base,
                "rdap_server_host": host,
                "rdap_redirect_host": redirect_host,
                "message": (
                    "the registry redirected. Redirects are not followed: the destination host is "
                    "chosen at runtime and the egress allowlist is what makes every destination a "
                    "reviewed one (docs/OPSEC.md section 7)."
                ),
            }
        response.raise_for_status()
        try:
            body = response.json()
        except ValueError:
            return {"ok": False, "error": ERROR_INVALID_RESPONSE, "rdap_server": base}
        if not isinstance(body, dict):
            return {"ok": False, "error": ERROR_INVALID_RESPONSE, "rdap_server": base}
        return {
            "ok": True,
            "body": body,
            "rdap_server": base,
            "rdap_server_host": host,
            "rdap_bootstrap_entry": matched_entry,
            "rdap_bootstrap_publication": bootstrap.publication,
        }

    return await with_exponential_backoff(_call)


# --------------------------------------------------------------------------------------
# Entities, events, status
# --------------------------------------------------------------------------------------


def _roles(entity: Dict[str, Any]) -> List[str]:
    """Lowercased ``roles`` of one entity."""
    return [role.lower() for role in _str_list(entity.get("roles"))]


def _walk_entities(entities: Any, *, depth: int = 0) -> Iterator[Dict[str, Any]]:
    """Yield every entity in the tree, parents before children, bounded by :data:`MAX_ENTITY_DEPTH`.

    Recursion is not optional. RFC 9083's own domain example nests the abuse entity inside the
    registrar entity, and that is what the gTLD registries emit: a flat scan of
    ``domain.entities`` finds a registrar and no abuse address at all.
    """
    if depth > MAX_ENTITY_DEPTH:
        return
    for item in _as_list(entities):
        if not isinstance(item, dict):
            continue
        yield item
        yield from _walk_entities(item.get("entities"), depth=depth + 1)


def _entity_with_role(entities: Any, role: str) -> Optional[Dict[str, Any]]:
    """The first entity anywhere in the tree carrying ``role``."""
    for entity in _walk_entities(entities):
        if role in _roles(entity):
            return entity
    return None


def _vcard_properties(entity: Dict[str, Any]) -> List[List[Any]]:
    """The jCard property arrays of one entity, or an empty list.

    ``vcardArray`` is ``["vcard", [<property>, ...]]`` where each property is at least
    ``[name, params, type, value]`` (RFC 9083 section 5.1). Anything shorter is skipped: a
    property whose value slot is missing has nothing to contribute.
    """
    array = entity.get("vcardArray")
    if not isinstance(array, list) or len(array) < 2:
        return []
    return [prop for prop in _as_list(array[1]) if isinstance(prop, list) and len(prop) >= 4]


def _vcard_value(entity: Dict[str, Any], name: str) -> Optional[str]:
    """The value of the first jCard property called ``name``, as a string.

    A structured value -- ``n`` and ``adr`` are arrays -- is joined on spaces after dropping the
    empty components, which is what those properties look like on the wire when a registry
    publishes a partial address.
    """
    for prop in _vcard_properties(entity):
        if not isinstance(prop[0], str) or prop[0].lower() != name.lower():
            continue
        value = prop[3]
        text = _as_str(value)
        if text is not None:
            return text
        if isinstance(value, list):
            parts = [part for part in (_as_str(item) for item in value) if part is not None]
            if parts:
                return " ".join(parts)
    return None


def _vcard_tel(entity: Dict[str, Any], *, want_fax: bool = False) -> Optional[str]:
    """The first ``tel`` property, preferring voice over fax (or the reverse).

    Values arrive as ``tel:`` URIs and as bare text depending on the registry; the scheme is
    stripped so a consumer gets one shape. Fax numbers are excluded from the voice answer
    because sending an abuse report to a fax line is a failed report.
    """
    fallback: Optional[str] = None
    for prop in _vcard_properties(entity):
        if not isinstance(prop[0], str) or prop[0].lower() != "tel":
            continue
        params = _as_dict(prop[1])
        raw_types = params.get("type")
        types = {t.lower() for t in _str_list(raw_types)} if isinstance(raw_types, list) else set()
        single = _as_str(raw_types)
        if single is not None:
            types.add(single.lower())
        is_fax = "fax" in types
        if is_fax != want_fax:
            if fallback is None and not types:
                fallback = _strip_tel_scheme(prop[3])
            continue
        value = _strip_tel_scheme(prop[3])
        if value is not None:
            return value
    return fallback


def _strip_tel_scheme(value: Any) -> Optional[str]:
    """``"tel:+1-555-0100"`` -> ``"+1-555-0100"``. A bare number is returned unchanged."""
    text = _as_str(value)
    if text is None:
        return None
    if not text.lower().startswith("tel:"):
        return text
    return _as_str(text[4:])


def _public_id(entity: Dict[str, Any], needle: str) -> Optional[str]:
    """The ``publicIds`` identifier whose ``type`` contains ``needle``, case-insensitively.

    Registries spell the type "IANA Registrar ID" and "IANA registrar id"; matching on a
    substring rather than equality is what keeps the registrar ID from vanishing on the ones
    that capitalise differently.
    """
    for item in _as_list(entity.get("publicIds")):
        entry = _as_dict(item)
        type_text = _as_str(entry.get("type"))
        if type_text is None or needle.lower() not in type_text.lower():
            continue
        identifier = _as_str(entry.get("identifier"))
        if identifier is not None:
            return identifier
    return None


_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _normalize_status(value: str) -> str:
    """Put one status value into the RFC 8056 form: lowercase, words separated by spaces.

    RFC 8056 defines the RDAP status by "converting the EPP 'camelCase' representation to
    lowercase with a space character inserted between word boundaries", so the value on the wire
    is ``"client hold"``. Registries emit the EPP spelling ``clientHold`` anyway. Normalising
    both to one form is what lets :data:`ADVERSE_STATUSES` be a plain set instead of a list of
    spellings that will be incomplete the first time a new registry is queried.
    """
    spaced = _CAMEL_BOUNDARY_RE.sub(" ", value.strip())
    return " ".join(spaced.replace("_", " ").replace("-", " ").lower().split())


#: Statuses that say the registry or the registrar has acted against the domain, or that it is
#: on its way out of the zone. Every one of them is a fact about the registration, not a
#: reputation judgement -- ``client hold`` in particular is what a registrar sets when it has
#: accepted an abuse report and pulled the name out of DNS.
ADVERSE_STATUSES: FrozenSet[str] = frozenset(
    {
        "client hold",
        "server hold",
        "pending delete",
        "redemption period",
        "pending restore",
    }
)


def _statuses(payload: Dict[str, Any]) -> Tuple[List[str], List[str], List[str]]:
    """``(raw, normalized, adverse)`` status lists for one RDAP object."""
    raw = _str_list(payload.get("status"))
    normalized: List[str] = []
    for value in raw:
        candidate = _normalize_status(value)
        if candidate and candidate not in normalized:
            normalized.append(candidate)
    adverse = [value for value in normalized if value in ADVERSE_STATUSES]
    return raw, normalized, adverse


def _events(payload: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    """``(compact event records, first date per action)``.

    First-wins rather than last-wins: a registry that lists an action twice is describing the
    original event and a correction, and the earlier one is the registration this tool cares
    about. Both are kept in the record list either way, so nothing is lost by the choice.
    """
    records: List[Dict[str, Any]] = []
    by_action: Dict[str, str] = {}
    for item in _as_list(payload.get("events")):
        entry = _as_dict(item)
        action = _as_str(entry.get("eventAction"))
        date = _as_str(entry.get("eventDate"))
        if action is None and date is None:
            continue
        normalized = _normalize_status(action) if action is not None else None
        records.append({"action": normalized, "date": date, "actor": _as_str(entry.get("eventActor"))})
        if normalized is not None and date is not None and normalized not in by_action:
            by_action[normalized] = date
    return records, by_action


def _abuse_contact(entities: Any) -> Dict[str, Any]:
    """Abuse email and phone, plus where in the entity tree they were found.

    Falls back to the registrar entity's own address when no entity carries the ``abuse`` role.
    That fallback is labelled in ``rdap_abuse_contact_source`` rather than presented as an abuse
    contact, because a registrar's general address and its designated abuse address are
    different queues with different obligations.
    """
    abuse = _entity_with_role(entities, "abuse")
    if abuse is not None:
        return {
            "rdap_abuse_email": _vcard_value(abuse, "email"),
            "rdap_abuse_phone": _vcard_tel(abuse),
            "rdap_abuse_handle": _as_str(abuse.get("handle")),
            "rdap_abuse_contact_source": "abuse_role",
        }

    registrar = _entity_with_role(entities, "registrar")
    if registrar is not None:
        email = _vcard_value(registrar, "email")
        if email is not None or _vcard_tel(registrar) is not None:
            return {
                "rdap_abuse_email": email,
                "rdap_abuse_phone": _vcard_tel(registrar),
                "rdap_abuse_handle": _as_str(registrar.get("handle")),
                "rdap_abuse_contact_source": "registrar_entity_fallback",
            }

    return {
        "rdap_abuse_email": None,
        "rdap_abuse_phone": None,
        "rdap_abuse_handle": None,
        "rdap_abuse_contact_source": None,
    }


def _nameservers(payload: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
    """``(nameserver records, glue addresses)``.

    A domain with no ``nameservers`` member and a domain with an empty one are both reported as
    an empty list, and the ``inactive`` status is what distinguishes "the registry told us there
    are none" from "the registry did not say". Guessing between them here would invent a
    delegation state.
    """
    records: List[Dict[str, Any]] = []
    glue: List[str] = []
    for item in _as_list(payload.get("nameservers")):
        entry = _as_dict(item)
        name = _as_str(entry.get("ldhName")) or _as_str(entry.get("unicodeName"))
        addresses = _as_dict(entry.get("ipAddresses"))
        v4 = _str_list(addresses.get("v4"))
        v6 = _str_list(addresses.get("v6"))
        if name is None and not v4 and not v6:
            continue
        records.append({"name": name.lower() if name else None, "ipv4": v4, "ipv6": v6})
        for address in v4 + v6:
            if address not in glue:
                glue.append(address)
    return records, glue


def _secure_dns(payload: Dict[str, Any]) -> Dict[str, Any]:
    """DNSSEC delegation state.

    ``delegationSigned`` absent stays ``None``. An unsigned delegation and an unreported one are
    different claims, and only one of them is the registry's.
    """
    secure = _as_dict(payload.get("secureDNS"))
    if not secure:
        return {"rdap_dnssec_delegation_signed": None, "rdap_dnssec_ds_count": None, "rdap_dnssec_key_count": None}
    ds_data = _as_list(secure.get("dsData"))
    key_data = _as_list(secure.get("keyData"))
    return {
        "rdap_dnssec_delegation_signed": _as_bool(secure.get("delegationSigned")),
        "rdap_dnssec_ds_count": len(ds_data),
        "rdap_dnssec_key_count": len(key_data),
    }


# --------------------------------------------------------------------------------------
# Payload shaping
# --------------------------------------------------------------------------------------


def _routing_fields(lookup: Dict[str, Any]) -> Dict[str, Any]:
    """Provenance for the routing decision: which server answered, and how old the map was."""
    return {
        "rdap_server": lookup.get("rdap_server"),
        "rdap_server_host": lookup.get("rdap_server_host"),
        "rdap_bootstrap_entry": lookup.get("rdap_bootstrap_entry"),
        "rdap_bootstrap_publication": lookup.get("rdap_bootstrap_publication"),
    }


def _domain_payload(body: Dict[str, Any], lookup: Dict[str, Any], *, now: datetime.datetime) -> Dict[str, Any]:
    """Shape a domain response into the provider ``data`` mapping.

    Dates first, deliberately. The registration date is the reason this provider exists: it is
    the one field here that changes a triage decision on its own.
    """
    entities = body.get("entities")
    event_records, by_action = _events(body)
    raw_status, normalized_status, adverse_status = _statuses(body)
    nameservers, glue = _nameservers(body)

    registration = by_action.get("registration") or by_action.get("reregistration")
    age = _age_days(registration, now=now)

    registrar = _entity_with_role(entities, "registrar")
    registrant = _entity_with_role(entities, "registrant")

    payload: Dict[str, Any] = {
        "rdap_registration_date": registration,
        "rdap_age_days": age,
        "rdap_is_newly_registered": None if age is None else age <= NEWLY_REGISTERED_DAYS,
        "rdap_newly_registered_threshold_days": NEWLY_REGISTERED_DAYS,
        "rdap_expiration_date": by_action.get("expiration"),
        "rdap_last_changed_date": by_action.get("last changed"),
        "rdap_last_update_of_rdap_db": by_action.get("last update of rdap database"),
        "rdap_events": event_records,
        "rdap_registrar_name": _vcard_value(registrar, "fn") if registrar else None,
        "rdap_registrar_iana_id": _as_int(_public_id(registrar, "iana registrar id")) if registrar else None,
        "rdap_registrar_handle": _as_str(registrar.get("handle")) if registrar else None,
        "rdap_registrant_name": _vcard_value(registrant, "fn") if registrant else None,
        "rdap_registrant_organization": _vcard_value(registrant, "org") if registrant else None,
        "rdap_status": normalized_status,
        "rdap_status_raw": raw_status,
        "rdap_adverse_status": adverse_status,
        "rdap_has_adverse_status": bool(adverse_status),
        "rdap_is_inactive": "inactive" in normalized_status,
        "rdap_nameservers": nameservers,
        "rdap_nameserver_names": [record["name"] for record in nameservers if record["name"]],
        "rdap_nameserver_count": len(nameservers),
        "rdap_nameserver_glue_addresses": glue,
        "rdap_ldh_name": _as_str(body.get("ldhName")),
        "rdap_unicode_name": _as_str(body.get("unicodeName")),
        "rdap_handle": _as_str(body.get("handle")),
        "rdap_object_class": _as_str(body.get("objectClassName")),
        "rdap_conformance": _str_list(body.get("rdapConformance")),
        "rdap_notice_count": len(_as_list(body.get("notices"))),
    }
    payload.update(_abuse_contact(entities))
    payload.update(_secure_dns(body))
    payload.update(_routing_fields(lookup))
    return payload


def _network_payload(body: Dict[str, Any], lookup: Dict[str, Any], *, now: datetime.datetime) -> Dict[str, Any]:
    """Shape an IP-network response into the provider ``data`` mapping."""
    entities = body.get("entities")
    event_records, by_action = _events(body)
    raw_status, normalized_status, adverse_status = _statuses(body)
    registration = by_action.get("registration")

    payload: Dict[str, Any] = {
        "rdap_registration_date": registration,
        "rdap_age_days": _age_days(registration, now=now),
        "rdap_last_changed_date": by_action.get("last changed"),
        "rdap_events": event_records,
        "rdap_network_handle": _as_str(body.get("handle")),
        "rdap_network_name": _as_str(body.get("name")),
        "rdap_network_type": _as_str(body.get("type")),
        "rdap_network_start_address": _as_str(body.get("startAddress")),
        "rdap_network_end_address": _as_str(body.get("endAddress")),
        "rdap_network_ip_version": _as_str(body.get("ipVersion")),
        "rdap_network_country": _as_str(body.get("country")),
        "rdap_network_parent_handle": _as_str(body.get("parentHandle")),
        "rdap_network_cidr": _cidr_blocks(body),
        "rdap_status": normalized_status,
        "rdap_status_raw": raw_status,
        "rdap_adverse_status": adverse_status,
        "rdap_object_class": _as_str(body.get("objectClassName")),
        "rdap_conformance": _str_list(body.get("rdapConformance")),
    }
    payload.update(_abuse_contact(entities))
    payload.update(_routing_fields(lookup))
    return payload


def _cidr_blocks(body: Dict[str, Any]) -> List[str]:
    """``cidr0_cidrs`` blocks as ``prefix/length`` strings, when the registry sends them.

    The CIDR extension is optional and several registries omit it, in which case the start and
    end addresses are the only description of the block and are reported on their own.
    """
    blocks: List[str] = []
    for item in _as_list(body.get("cidr0_cidrs")):
        entry = _as_dict(item)
        prefix = _as_str(entry.get("v4prefix")) or _as_str(entry.get("v6prefix"))
        length = _as_int(entry.get("length"))
        if prefix is None or length is None:
            continue
        block = f"{prefix}/{length}"
        if block not in blocks:
            blocks.append(block)
    return blocks


def _autnum_payload(body: Dict[str, Any], lookup: Dict[str, Any], *, now: datetime.datetime) -> Dict[str, Any]:
    """Shape an autonomous-system response into the provider ``data`` mapping."""
    entities = body.get("entities")
    event_records, by_action = _events(body)
    raw_status, normalized_status, adverse_status = _statuses(body)
    registration = by_action.get("registration")

    payload: Dict[str, Any] = {
        "rdap_registration_date": registration,
        "rdap_age_days": _age_days(registration, now=now),
        "rdap_last_changed_date": by_action.get("last changed"),
        "rdap_events": event_records,
        "rdap_autnum_handle": _as_str(body.get("handle")),
        "rdap_autnum_name": _as_str(body.get("name")),
        "rdap_autnum_type": _as_str(body.get("type")),
        "rdap_autnum_start": _as_int(body.get("startAutnum")),
        "rdap_autnum_end": _as_int(body.get("endAutnum")),
        "rdap_autnum_country": _as_str(body.get("country")),
        "rdap_status": normalized_status,
        "rdap_status_raw": raw_status,
        "rdap_adverse_status": adverse_status,
        "rdap_object_class": _as_str(body.get("objectClassName")),
        "rdap_conformance": _str_list(body.get("rdapConformance")),
    }
    payload.update(_abuse_contact(entities))
    payload.update(_routing_fields(lookup))
    return payload


# --------------------------------------------------------------------------------------
# Public surface
# --------------------------------------------------------------------------------------


def _stamp(envelope: Dict[str, Any], key: str, value: Any) -> Dict[str, Any]:
    """Record the resource that was actually asked for on an envelope, in place.

    Applied to failure envelopes as well as successes. A ``not_found`` that does not say what
    was queried is unreadable when the caller passed a subdomain and the registry only holds
    the registrable name -- see the module docstring.
    """
    envelope[key] = value
    return envelope


def _allowed(allowed_hosts: Optional[FrozenSet[str]]) -> FrozenSet[str]:
    """The egress allowlist in force. The argument is a test seam, not a production knob.

    Defaulting to ``utils.http.ALLOWED_EGRESS_HOSTS`` rather than copying it at import time
    keeps this module and the runtime hook reading the same list, which is the property that
    stops this check and the enforcement from disagreeing.
    """
    return ALLOWED_EGRESS_HOSTS if allowed_hosts is None else allowed_hosts


async def rdap_domain(
    *,
    client: httpx.AsyncClient,
    domain: str,
    allowed_hosts: Optional[FrozenSet[str]] = None,
    ttl: float = BOOTSTRAP_TTL_SECONDS,
    now: Optional[datetime.datetime] = None,
) -> Dict[str, Any]:
    """Registration data for one domain, from the registry that holds it. No API key, no quota.

    Two ``GET``s at most and usually one: the IANA bootstrap file is cached for the process, so
    a bulk run pays for it once. The second is the query to the authoritative registry.

    ``now`` and ``ttl`` are test seams. ``allowed_hosts`` overrides the egress allowlist for
    tests; production leaves it ``None`` so this module and ``utils/http.py`` read one list.
    """
    name = _query_name(domain)
    if name is None:
        return {
            "ok": False,
            "error": ERROR_INVALID_INDICATOR,
            "message": "not a queryable domain name: RDAP needs at least two encodable labels",
        }

    try:
        bootstrap = await _load_bootstrap(client=client, url=BOOTSTRAP_DNS_URL, ttl=ttl)
    except _BootstrapError as exc:
        return _stamp(
            {"ok": False, "error": ERROR_BOOTSTRAP_UNAVAILABLE, "message": exc.detail}, "rdap_query_name", name
        )

    lookup = await _rdap_lookup(
        client=client,
        bootstrap_url=BOOTSTRAP_DNS_URL,
        path_prefix="domain/",
        resource=quote(name, safe=""),
        matcher_result=_match_domain(bootstrap, name),
        bootstrap=bootstrap,
        allowed_hosts=_allowed(allowed_hosts),
    )
    if not lookup.get("ok"):
        return _stamp(lookup, "rdap_query_name", name)

    payload = _domain_payload(_as_dict(lookup.get("body")), lookup, now=_reference_now(now))
    payload["rdap_query_name"] = name
    return {"ok": True, "data": payload}


async def rdap_ip(
    *,
    client: httpx.AsyncClient,
    ip: str,
    allowed_hosts: Optional[FrozenSet[str]] = None,
    ttl: float = BOOTSTRAP_TTL_SECONDS,
    now: Optional[datetime.datetime] = None,
) -> Dict[str, Any]:
    """Allocation data for one IP address, from the RIR that holds it.

    Cheap because the machinery is already here: the IPv4 and IPv6 bootstrap files resolve to
    the five RIRs and nothing else, so unlike the domain path there is no long tail of registry
    hosts to review.
    """
    try:
        parsed = ipaddress.ip_address(ip.strip())
    except (ValueError, AttributeError):
        return {"ok": False, "error": ERROR_INVALID_INDICATOR, "message": "not an IP address"}

    bootstrap_url = BOOTSTRAP_IPV4_URL if parsed.version == 4 else BOOTSTRAP_IPV6_URL
    try:
        bootstrap = await _load_bootstrap(client=client, url=bootstrap_url, ttl=ttl)
    except _BootstrapError as exc:
        envelope = {"ok": False, "error": ERROR_BOOTSTRAP_UNAVAILABLE, "message": exc.detail}
        return _stamp(envelope, "rdap_query_resource", str(parsed))

    lookup = await _rdap_lookup(
        client=client,
        bootstrap_url=bootstrap_url,
        path_prefix="ip/",
        resource=quote(str(parsed), safe=":"),
        matcher_result=_match_network(bootstrap, str(parsed)),
        bootstrap=bootstrap,
        allowed_hosts=_allowed(allowed_hosts),
    )
    if not lookup.get("ok"):
        return _stamp(lookup, "rdap_query_resource", str(parsed))

    payload = _network_payload(_as_dict(lookup.get("body")), lookup, now=_reference_now(now))
    payload["rdap_query_resource"] = str(parsed)
    return {"ok": True, "data": payload}


async def rdap_asn(
    *,
    client: httpx.AsyncClient,
    asn: int,
    allowed_hosts: Optional[FrozenSet[str]] = None,
    ttl: float = BOOTSTRAP_TTL_SECONDS,
    now: Optional[datetime.datetime] = None,
) -> Dict[str, Any]:
    """Registration data for one autonomous system number, from the RIR that holds it."""
    number = _as_int(asn)
    if number is None or number < 0 or number > 4294967295:
        return {"ok": False, "error": ERROR_INVALID_INDICATOR, "message": "not a 32-bit AS number"}

    try:
        bootstrap = await _load_bootstrap(client=client, url=BOOTSTRAP_ASN_URL, ttl=ttl)
    except _BootstrapError as exc:
        envelope = {"ok": False, "error": ERROR_BOOTSTRAP_UNAVAILABLE, "message": exc.detail}
        return _stamp(envelope, "rdap_query_resource", number)

    lookup = await _rdap_lookup(
        client=client,
        bootstrap_url=BOOTSTRAP_ASN_URL,
        path_prefix="autnum/",
        resource=str(number),
        matcher_result=_match_asn(bootstrap, number),
        bootstrap=bootstrap,
        allowed_hosts=_allowed(allowed_hosts),
    )
    if not lookup.get("ok"):
        return _stamp(lookup, "rdap_query_resource", number)

    payload = _autnum_payload(_as_dict(lookup.get("body")), lookup, now=_reference_now(now))
    payload["rdap_query_resource"] = number
    return {"ok": True, "data": payload}
