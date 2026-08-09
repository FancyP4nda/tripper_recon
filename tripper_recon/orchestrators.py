"""Per-indicator orchestration: fan out to the providers, assemble one result.

Three entry points -- :func:`investigate_ip`, :func:`investigate_domain`, :func:`investigate_asn`
-- and one shared shape underneath them.

What changed here and why (roadmap W2/W3):

* **One call helper.** ``_call_provider`` replaced 23 hand-copied ``try / await / except``
  blocks. Every provider call is now timed, rate-limited, error-classified and wrapped in a
  :class:`ProviderCall` envelope by the same code path.
* **The ok/error distinction survives assembly.** The renderer still receives ``{}`` for a
  provider that did not answer, because that is the shape it consumes -- but ``provider_status``
  now carries the outcome, the redacted error and the elapsed time for every provider, so
  "never asked" and "asked, came back clean" stop being indistinguishable downstream.
* **The limiter bounds real work.** It wraps the await, not ``asyncio.create_task``.
* **Every path is one wave.** The domain path awaited five providers serially per IP and then
  looped IPs serially; the ASN path fully drained one wave before creating the next. Both now
  gather, with an explicit ceiling so a domain with many A records cannot fan out without
  limit.
* **A wall-clock deadline exists.** Nothing had elapsed-time awareness and OTX alone carries a
  worst case near 84 seconds per provider.
* **Non-public addressing is refused on both paths.** The IP path checked ``is_private`` only,
  which covers neither 224/4 nor 240/4, and the domain path checked nothing at all -- so a
  split-horizon or sinkholed domain forwarded internal addressing to five third parties under
  the operator's own API keys.

What changed here and why (roadmap W4):

* **``ok`` reflects what was learned, not what parsed.** See :ref:`the contract <ok-contract>`
  below. ``investigate_ip`` used to return ``ok=True`` the moment the address parsed, so a run
  in which every provider was unconfigured or down was indistinguishable, to anything keyed on
  the result, from a clean lookup.
* **Coverage is published, not implied.** Every result carries a :class:`Coverage` on
  ``result.coverage`` and its dump on ``data['coverage']``: which providers answered, which
  errored, which had no credential, and which were never attempted -- by name, with
  ``headline`` already rendered as "2 of 6 providers answered". W3.6 put the raw material in
  ``provider_status``; this is the counted form. The denominator comes from the declared
  ``*_PROVIDERS`` sets, never from the calls that happened to be made.
* **Run metadata is published.** :class:`RunMetadata` on ``result.run`` and ``data['run']``:
  tool, version, run id and RFC 3339 UTC start. The run id is shared by every target in one
  invocation, so a bulk run correlates.
* **Warnings reach the renderer.** ``investigate_asn`` computed a ``warnings`` list that only
  the JSON path ever read, because the console renderers are handed ``result.data`` and nothing
  else. All three paths now compute warnings, and all three mirror them into
  ``data['warnings']``.
* **Skipped addresses survive.** A domain resolving to three internal addresses and one public
  one is not a domain with one address. Each refused address is a :class:`SkippedAddress` on
  ``result.skipped_addresses``, keeps its existing ``data['skipped_ips']`` entry, is counted in
  ``data['addresses']``, and raises a warning naming it.

What changed here and why (roadmap W5):

* **The result carries a verdict.** Collection ends at ``_finalise``; adjudication runs after
  it, in :func:`_adjudicate_ip` and :func:`_adjudicate_domain`, and publishes the verdict onto
  ``data['verdict']`` (plus one per address on the domain path). The scoring engine itself is
  pure -- every load and the clock read happen here.
* **The domain and its addresses are scored separately and never merged.** A phishing kit on a
  CDN is a malicious domain on a shared address; both statements are true, and any merge either
  indicts the CDN's other tenants or clears the kit.
* **A scoring failure never becomes a clean report.** If the ruleset will not load or the engine
  raises, ``data['verdict_error']`` and a warning say so and the collected data still stands.

.. _ok-contract:

**The ``ok`` contract, and the exit code that rides on it.**

``cli.py`` maps ``not result.ok`` onto a non-zero exit for every subcommand, so this rule is a
public interface. Automation may rely on it:

``ok is False`` when, and only when, one of the following holds:

1. the target failed validation (``Invalid IP address`` / ``Invalid domain`` / ``Invalid ASN``);
2. the target is non-public addressing the tool refuses to forward to a third party;
3. the wall-clock deadline fired before the run completed; or
4. **no provider answered.** ``result.coverage.answered_count`` is zero while at least one
   provider was applicable, because every one was unconfigured, errored or never attempted.
   Nothing was learned.

``ok is True`` otherwise. **``ok is True`` does not mean the lookup was complete**, and a caller
that treats it that way is making the mistake this contract exists to prevent. A partial answer
-- two providers of six -- is ``ok=True``. Read ``result.coverage`` (or ``data['coverage']``,
whose ``headline`` is already rendered) before drawing any conclusion from sparse output;
``coverage.is_complete`` is the flag that says the answer is whole.

Cases 1-3 return an empty ``data``; the failure is entirely in ``errors``, and ``coverage`` is
``None`` -- which :attr:`InvestigationResult.coverage_or_unknown` reads as zero coverage, never
as full. Case 4 returns the full ``data``, because coverage, run metadata and per-provider
status are exactly what the operator needs in order to see *why* nothing came back; it also
states the blackout as the first entry in ``errors``, so the terse console failure branch has
something to print.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import os
import time
from ipaddress import ip_address
from typing import (
    Any,
    Awaitable,
    Callable,
    Coroutine,
    Dict,
    FrozenSet,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
)
from urllib.parse import urlsplit

import httpx

from tripper_recon.providers import abusech as abusech_provider
from tripper_recon.providers import internetdb as internetdb_provider
from tripper_recon.providers import rdap as rdap_provider
from tripper_recon.providers import tranco as tranco_provider
from tripper_recon.providers.abusech import abusech_host_summary, abusech_url_summary
from tripper_recon.providers.abuseipdb import abuseipdb_check
from tripper_recon.providers.caida import caida_asrank
from tripper_recon.providers.cloudflare_radar import fetch_asn_metadata
from tripper_recon.providers.cloudflare_rest import bgp_incidents
from tripper_recon.providers.internetdb import internetdb_host
from tripper_recon.providers.ipinfo import ipinfo_asn, ipinfo_ip
from tripper_recon.providers.otx import otx_domain_pulses, otx_ip_pulses
from tripper_recon.providers.peeringdb import peeringdb_ixps_for_asn
from tripper_recon.providers.rdap import rdap_asn, rdap_domain, rdap_ip
from tripper_recon.providers.ripestat import (
    abuse_contact,
    announced_prefixes,
    as_overview,
    asn_neighbours,
    routing_status,
)
from tripper_recon.providers.shodan_api import shodan_host
from tripper_recon.providers.tranco import tranco_rank
from tripper_recon.providers.virustotal import (
    VT_URL_NO_REPORT_ERROR,
    vt_domain_summary,
    vt_ip_summary,
    vt_url_summary,
)
from tripper_recon.types.models import (
    ApiKeys,
    Coverage,
    InvestigationResult,
    ProviderCall,
    ProviderStatus,
    RunMetadata,
    SkippedAddress,
    SkipReason,
    coverage_from_result_data,
    current_run,
)
from tripper_recon.utils.cache import (
    CacheLookup,
    active_cache,
    format_age,
    freshness_warnings,
    summarise_freshness,
)
from tripper_recon.utils.http import (
    ALLOWED_EGRESS_HOSTS,
    PassiveBoundaryViolation,
    create_client,
    rate_limited,
)
from tripper_recon.utils.logging import logger
from tripper_recon.utils.redact import redact_text, redact_url
from tripper_recon.utils.urls import HostKind, ParsedURL, RedirectChain, parse_url
from tripper_recon.utils.validation import dedupe_preserve_order, is_valid_domain, is_valid_ip, normalize_asn
from tripper_recon.verdict import engine as verdict_engine
from tripper_recon.verdict import signals as verdict_signals
from tripper_recon.verdict.config import IndicatorScope, ScoringConfig, default_config
from tripper_recon.verdict.known_infrastructure import KnownInfrastructure, load_catalogue
from tripper_recon.verdict.models import Verdict

log = logger("orchestrators")

# --------------------------------------------------------------------------------------
# Budgets
# --------------------------------------------------------------------------------------

#: Wall-clock ceiling for one indicator, applied by :func:`_with_deadline`.
#:
#: There was no elapsed-time awareness anywhere before this. A single provider can take ~84
#: seconds in its worst case (OTX, four attempts at a 20-second timeout), and a domain with
#: several A records multiplied that. The ceiling is generous rather than tight -- the point
#: is that a run terminates and says why, not that it terminates quickly.
DEFAULT_TARGET_DEADLINE_SECONDS = 180.0

#: How many resolved IPs of one domain are enriched at once. The global rate limiter bounds
#: requests in flight; this bounds how many coroutine trees exist, so a domain with 40 A
#: records does not create 200 pending provider calls before the first one returns.
MAX_CONCURRENT_IPS = 8

#: How many neighbour ASNs are resolved to names at once. ``--neighbors N`` resolves up to 3N
#: (upstream, downstream, uncertain) and previously gathered all of them unbounded.
MAX_CONCURRENT_NEIGHBOUR_LOOKUPS = 8

#: Cache scopes (roadmap 7.7). One provider can be asked different questions about different
#: kinds of indicator -- abuse.ch answers about a host at ``domain`` scope and about an exact link
#: at ``url`` scope -- so the scope is part of the cache key and not decoration. The strings match
#: the subcommand names, which is what makes a case directory's ``scope`` field readable.
SCOPE_IP = "ip"
SCOPE_DOMAIN = "domain"
SCOPE_URL = "url"
SCOPE_ASN = "asn"

#: The pseudo-provider under which a name resolution is cached.
#:
#: Not a provider -- it is the tool's one active step (``docs/OPSEC.md`` §3) -- but it is an
#: outbound question with an answer that ages, and ``--offline`` is worthless if it cannot avoid
#: making it. Its lifetime is the shortest in ``cache.yaml`` for the reason recorded there: a DNS
#: answer has an authoritative TTL of its own, and fast-flux infrastructure exists precisely to
#: make yesterday's answer wrong.
DNS_PROVIDER = "dns"

#: Provider error values that mean "no credential, so nothing was asked". Shared by
#: :func:`_should_suppress` and the envelope builder so the two cannot disagree about which
#: failures are configuration rather than incidents.
NOT_CONFIGURED_ERRORS: FrozenSet[str] = frozenset(
    {"missing_api_key", "missing_api_token", "missing_token", "API key not configured"}
)

#: The providers each path INTENDS to consult, which is the denominator of "N of M answered".
#:
#: Declared rather than counted from the calls that happened, because the two differ in exactly
#: the case that matters. ``cloudflare_asn`` on the IP path is a second wave that only runs when
#: IPinfo returned an ASN, so when IPinfo fails, Cloudflare is never attempted at all -- and a
#: denominator derived from attempts would quietly shrink from six to five and report better
#: coverage for the worse run. :meth:`Coverage.from_status_map` files an expected provider with
#: no status entry as ``skipped``, which keeps it in the denominator where it belongs.
#:
#: ``shodan`` is ONE slot with two implementations (roadmap 8.1). The paid host lookup runs when
#: ``SHODAN_API_KEY`` is set and the keyless InternetDB extract runs when it is not, so exactly
#: one of them can ever answer for an address. Listing both would permanently understate coverage
#: by one for every operator; the payload's ``source`` field says which dataset replied.
IP_PROVIDERS: Tuple[str, ...] = (
    "virustotal",
    "ipinfo",
    "shodan",
    "abuseipdb",
    "otx",
    "cloudflare_asn",
    "rdap",
    "abusech",
)

#: The domain-level providers, asked about the name itself rather than about an address.
DOMAIN_PROVIDERS: Tuple[str, ...] = ("virustotal", "otx", "rdap", "tranco", "abusech")

#: The URL-level providers, asked about the whole link rather than about its host.
#:
#: One entry today. The urlscan SEARCH provider (``providers/urlscan.py``) is written and tested,
#: and its host is now allowlisted in both places (``utils/http.ALLOWED_EGRESS_HOSTS`` and
#: ``tests/test_passivity.ALLOWED_HOSTS``), so the passive boundary no longer blocks it. Wiring it
#: in changes this tuple, which is the DENOMINATOR of the URL-scope coverage ratio -- doing that
#: in the same change that moved the boundary would have made a passivity change and a coverage
#: change indistinguishable in one diff. It is the next step, not an oversight; docs/OPSEC.md
#: section 6 gap 3 records the interim state and why the allowlist entry leads the wiring.
#: Declared as a tuple rather than counted from the calls made, for the reason on
#: :data:`IP_PROVIDERS`.
#:
#: abuse.ch joined in the 0.2.0 ruleset. URLhaus is a database *of malware distribution URLs*, so
#: this scope is where it is strongest: an exact-URL record carries a retrieved file and its hash,
#: with none of the shared-hosting ambiguity a host-level hit inherits.
URL_PROVIDERS: Tuple[str, ...] = ("virustotal_url", "abusech")

#: How far a URL investigation pivots, shallowest first. See :func:`investigate_url`.
#:
#: ``url``  -- the link itself: whoever already holds a report on this exact URL.
#: ``host`` -- ``url`` plus the host's own reputation. **Still fully passive**: no name is
#:             resolved, so the target's nameserver learns nothing (``docs/OPSEC.md`` §3).
#: ``full`` -- ``host`` plus every public address the host resolves to. This is the only depth
#:             that resolves, so it is the only depth that touches the one documented exception.
URL_DEPTHS: Tuple[str, ...] = ("url", "host", "full")

#: The depth :func:`investigate_url` uses when the caller does not choose one.
DEFAULT_URL_DEPTH = "full"

#: The ASN providers. Order matches the single gather wave in :func:`_investigate_asn`.
ASN_PROVIDERS: Tuple[str, ...] = (
    "ipinfo_asn",
    "ripe_overview",
    "ripe_abuse",
    "caida",
    "peeringdb",
    "ripe_routing_status",
    "ripe_neighbors",
    "ripe_prefixes",
    "cloudflare_bgp",
    "cloudflare_asn",
    "rdap",
)


# --------------------------------------------------------------------------------------
# The egress gate for newly-wired providers
# --------------------------------------------------------------------------------------
#
# Adding a provider to the sets above is only half of wiring it: its host also has to be on
# ``utils.http.ALLOWED_EGRESS_HOSTS``, on ``ALLOWED_HOSTS`` in ``tests/test_passivity.py``, and in
# the ``docs/OPSEC.md`` section 2 table. Those three live in files this change does not own, and
# they land together in the integration commit.
#
# Until they do, calling one of these providers would raise ``PassiveBoundaryViolation`` from the
# httpx request hook -- and ``_call_provider`` re-raises that deliberately, so a single unlisted
# host would abort every investigation the tool performs. Missing coverage is a gap; an
# investigation that dies at the first provider is an outage.
#
# So the host is checked before the call is built, and an unlisted one becomes an explicit
# ``skipped`` status entry with the reason attached: the provider stays in the coverage
# denominator, ``_coverage_warnings`` names it under "never attempted", and nothing goes near a
# socket. ``providers/rdap.py`` already took this approach for the registry hosts it resolves at
# runtime, and its reasoning applies unchanged here.
#
# **This is not the enforcement.** The request hook is, and it is untouched. This check exists so
# that an un-allowlisted provider reports missing coverage instead of taking the run down with it,
# and it reads ``ALLOWED_EGRESS_HOSTS`` live rather than copying it, so it starts passing the
# moment the integrator adds the entries -- with no second edit here.


def _host_of(url: str) -> str:
    """The hostname of a provider's base URL, lowercased. ``""`` when there is not one."""
    return (urlsplit(url).hostname or "").lower()


#: Every host a newly-wired provider needs, derived from that provider's own module constants
#: rather than written out here. Two reasons: a literal would drift from the module it describes,
#: and ``tests/test_passivity.py`` scans this package for URL literals, so the honest way to name
#: a host in this file is to ask the module that owns it.
NEW_PROVIDER_EGRESS_HOSTS: Dict[str, Tuple[str, ...]] = {
    "internetdb": (_host_of(internetdb_provider.INTERNETDB_BASE),),
    # Only the IANA bootstrap file. The registry host is chosen at runtime from that file and is
    # checked against the same allowlist inside ``providers/rdap.py``, which reports
    # ``registry_not_allowlisted`` for a TLD nobody has reviewed.
    "rdap": (_host_of(rdap_provider.IANA_BOOTSTRAP_BASE),),
    "tranco": (_host_of(tranco_provider.TRANCO_BASE),),
    "abusech": (
        _host_of(abusech_provider.URLHAUS_URL_ENDPOINT),
        _host_of(abusech_provider.THREATFOX_ENDPOINT),
    ),
}


def _unpermitted_hosts(provider: str) -> Tuple[str, ...]:
    """The hosts ``provider`` needs that the egress allowlist does not yet carry."""
    return tuple(host for host in NEW_PROVIDER_EGRESS_HOSTS.get(provider, ()) if host not in ALLOWED_EGRESS_HOSTS)


def _not_allowlisted_call(provider: str, hosts: Sequence[str]) -> ProviderCall:
    """A ``skipped`` envelope for a provider whose host is not yet permitted.

    ``suppressed`` keeps it out of ``errors``: nothing failed, and an operator reading an error
    list should not be told an incident occurred because a wiring step is outstanding. The gap
    is still stated -- ``Coverage`` files it under ``skipped`` and the warning line names it.
    """
    joined = ", ".join(hosts)
    return ProviderCall(
        provider=provider,
        outcome=ProviderStatus.SKIPPED,
        error={
            "error": "host_not_allowlisted",
            "hosts": list(hosts),
            "message": (
                f"{provider} was not consulted: {joined} is not on the egress allowlist "
                "(utils/http.ALLOWED_EGRESS_HOSTS). No request was made."
            ),
        },
        summary=f"{provider} | host_not_allowlisted | {joined}",
        suppressed=True,
    )


async def _call_if_permitted(
    provider: str,
    factory: Callable[[], Awaitable[Dict[str, Any]]],
    *,
    scope: Optional[str] = None,
    indicator: Optional[str] = None,
) -> ProviderCall:
    """Call ``provider`` when its host is allowlisted; otherwise record that it was skipped.

    ``factory`` is a callable rather than an awaitable so that the coroutine is never even
    created when the provider is skipped -- an un-awaited coroutine is a warning and, under
    ``-W error``, a failure. The same property is what lets the cache lane serve a hit without
    building a request.
    """
    missing = _unpermitted_hosts(provider)
    if missing:
        return _not_allowlisted_call(provider, missing)
    return await _call_provider(provider, factory, scope=scope, indicator=indicator)


# --------------------------------------------------------------------------------------
# Error payloads (unchanged semantics -- tests pin these)
# --------------------------------------------------------------------------------------


def _safe_request_url(obj: Any) -> str | None:
    """Read a request URL without trusting the attribute to exist or behave.

    httpx implements `.request` as a property that raises RuntimeError when unset, and
    getattr's default only swallows AttributeError -- so the naive getattr(obj, "request", None)
    made the error handler itself crash on a RequestError built without a request.
    """
    try:
        req = getattr(obj, "request", None)
        if req is None:
            return None
        return redact_url(str(req.url))
    except Exception:  # noqa: BLE001 - the error path must never raise
        return None


def _error_payload(err: Exception) -> Dict[str, Any]:
    # Every string leaving this function is redacted: Shodan and IPInfo authenticate in the
    # query string, so both the request URL and the exception text carry the API key, and
    # this payload reaches console output and -o json.
    if isinstance(err, httpx.HTTPStatusError):
        resp = err.response
        return {
            "ok": False,
            "error": "http_error",
            "status_code": resp.status_code if resp else None,
            "reason": resp.reason_phrase if resp else None,
            "url": _safe_request_url(resp),
            "message": redact_text(str(err)),
        }
    if isinstance(err, httpx.RequestError):
        return {
            "ok": False,
            "error": "network_error",
            "url": _safe_request_url(err),
            "message": redact_text(str(err)),
        }
    return {"ok": False, "error": type(err).__name__, "message": redact_text(str(err))}


def _error_details(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in payload.items() if k != "ok" and v is not None}


def _error_summary(provider: str, payload: Dict[str, Any]) -> str:
    details = _error_details(payload)
    parts: List[str] = [provider]
    status = details.get("status_code")
    if status is None:
        status = details.get("status")
    if status is not None:
        parts.append(str(status))
    reason = details.get("reason")
    if reason:
        parts.append(str(reason))
    message = details.get("message")
    if message and str(message) not in parts:
        parts.append(str(message))
    return " | ".join(parts)


def _should_suppress(provider: str, payload: Dict[str, Any]) -> bool:
    if not payload or payload.get("ok"):
        return False
    # A provider may report `error` as a list (Cloudflare's GraphQL errors array). `x in {...}`
    # against an unhashable operand raises TypeError, so normalise before every membership test.
    err = payload.get("error")
    if not isinstance(err, (str, type(None))):
        err = None
    status = payload.get("status") or payload.get("status_code")
    if not isinstance(status, (int, str, type(None))):
        status = None
    if err in NOT_CONFIGURED_ERRORS:
        return True
    if provider == "ipinfo_asn" and err in {"unauthorized", "http_error"} and status in {401, 403}:
        return True
    if provider.startswith("cloudflare"):
        if err in {"missing_api_token"}:
            return True
        if err == "http_error" and status == 400:
            return True
    return bool(provider.startswith("ripe_") and err == "network_error")


def _env_keys() -> ApiKeys:
    return ApiKeys(
        cloudflare_api_token=os.getenv("CLOUDFLARE_API_TOKEN"),
        vt_api_key=os.getenv("VT_API_KEY"),
        shodan_api_key=os.getenv("SHODAN_API_KEY"),
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY"),
        ipinfo_token=os.getenv("IPINFO_TOKEN"),
        otx_api_key=os.getenv("OTX_API_KEY"),
    )


#: The abuse.ch Auth-Key variable. Read separately rather than added to :class:`ApiKeys` because
#: that model lives in ``types/models.py``, which the change that introduced it did not own.
#:
#: The two load-bearing pieces are now in place. ``utils.redact._SECRET_ENV_VARS`` carries it,
#: so the value is stripped from error payloads like every other credential -- and it needs
#: that more than the others do, because abuse.ch authenticates in a request HEADER, which the
#: query-parameter redaction cannot see. ``tests/conftest.PROVIDER_ENV_VARS`` clears it, so the
#: operator's real key cannot reach a test run. Folding the variable into ``ApiKeys`` is
#: tidying that buys no behaviour and is deliberately left alone.
ABUSECH_ENV_VAR = "ABUSECH_AUTH_KEY"


def _abusech_key() -> Optional[str]:
    """The abuse.ch Auth-Key, or ``None``. Absence yields ``missing_api_key``, never a request."""
    return os.getenv(ABUSECH_ENV_VAR)


# --------------------------------------------------------------------------------------
# The one provider call helper
# --------------------------------------------------------------------------------------


def _envelope(provider: str, payload: Dict[str, Any], elapsed: float) -> ProviderCall:
    """Wrap one provider payload, preserving the ok/error/not-configured distinction."""
    if payload.get("ok"):
        data = payload.get("data")
        return ProviderCall(
            provider=provider,
            outcome=ProviderStatus.OK,
            elapsed_seconds=elapsed,
            data=data if isinstance(data, dict) else {},
        )

    err = payload.get("error")
    outcome = (
        ProviderStatus.NOT_CONFIGURED if isinstance(err, str) and err in NOT_CONFIGURED_ERRORS else ProviderStatus.ERROR
    )
    return ProviderCall(
        provider=provider,
        outcome=outcome,
        elapsed_seconds=elapsed,
        error=_error_details(payload),
        summary=_error_summary(provider, payload),
        suppressed=_should_suppress(provider, payload),
    )


#: What a call site may hand :func:`_call_provider`: a coroutine, or a factory that builds one.
#:
#: The factory form is the one that matters. A cache hit must not create a request at all, and a
#: coroutine created and then not awaited is a ``RuntimeWarning`` -- a failure under ``-W error``.
#: The awaitable form is retained because it is the shape ``tests/test_http.py`` drives this
#: function with, and because a call with no indicator to key on cannot be cached anyway.
CallSource = Any


def _resolve_call(call: CallSource) -> Awaitable[Dict[str, Any]]:
    """Build the coroutine, if it has not been built already."""
    if callable(call):
        built: Awaitable[Dict[str, Any]] = call()
        return built
    awaitable: Awaitable[Dict[str, Any]] = call
    return awaitable


def _discard_call(call: CallSource) -> None:
    """Close a coroutine the cache lane decided not to await, so Python does not warn about it.

    A factory has no ``close`` and needs none: its coroutine was never created. Only the eager
    form -- a coroutine object handed in directly -- has to be closed, and closing it is what
    keeps ``RuntimeWarning: coroutine ... was never awaited`` out of a cached run.
    """
    close = getattr(call, "close", None)
    if callable(close):
        close()


def _offline_call(provider: str, *, reason: str, lookup: Optional[CacheLookup] = None) -> ProviderCall:
    """A ``skipped`` envelope for a question ``--offline`` refused to answer.

    **This is the load-bearing half of ``--offline``.** The alternative -- serving the expired
    entry anyway, because it is right there and nearly fresh -- is the exact behaviour that turns
    a cache into a mechanism for laundering staleness. A stated gap costs coverage; a stale value
    presented as current costs the report its defensibility.

    ``suppressed=True`` for the same reason ``_not_allowlisted_call`` uses it: nothing failed, so
    an operator reading the error list should not be shown an incident. The gap is still stated
    everywhere it matters -- ``Coverage`` files it under ``skipped``, ``_coverage_warnings`` names
    it under "never attempted", and the freshness warning names it again as unanswerable offline.
    """
    detail: Dict[str, Any] = {
        "error": "offline_no_usable_cache",
        "message": f"{provider} was not consulted: --offline is in force and {reason}. No request was made.",
    }
    if lookup is not None:
        detail["cache_state"] = lookup.state.value
        if lookup.age_seconds is not None:
            detail["cached_age_seconds"] = round(lookup.age_seconds, 3)
            detail["cached_age"] = format_age(lookup.age_seconds)
        if lookup.entry is not None:
            detail["cached_queried_at"] = lookup.entry.queried_at
    return ProviderCall(
        provider=provider,
        outcome=ProviderStatus.SKIPPED,
        error=detail,
        summary=f"{provider} | offline | {reason}",
        suppressed=True,
    )


async def _call_provider(
    provider: str,
    call: CallSource,
    *,
    scope: Optional[str] = None,
    indicator: Optional[str] = None,
) -> ProviderCall:
    """Await one provider under the concurrency limiter and wrap whatever comes back.

    This is the only place in the package that awaits a provider. Everything it guarantees --
    the limiter actually bounding in-flight requests, the elapsed time being recorded, a raised
    exception being redacted rather than escaping -- holds for every provider because there is
    no second code path. That is also why the TTL cache lives here: one gate in, one gate out.

    **The cache is inert unless a caller installed a session** (``utils.cache.use_cache``). With
    no session this function behaves exactly as it did before: every call goes to the network and
    nothing is written to disk. ``scope`` and ``indicator`` are what make a call cacheable; a call
    without them is always live, because a cache key that does not name the thing being asked
    about would collide across targets.

    Order of operations, and each step is a rule rather than an optimisation:

    1. **Look up before building the request.** A hit returns the stored payload with its original
       ``queried_at`` intact -- never restamped -- and the disclosure recorded on the session for
       :func:`_status_map` to publish.
    2. **In ``--offline``, refuse rather than degrade.** A miss, an expired entry, or a call with
       nothing to key on all become a stated gap. No socket is opened on any of those paths, which
       is what makes "exactly zero network calls" a property rather than an aspiration.
    3. **Store only success.** An error is a state of the world at one instant; replaying it would
       outlive its cause.

    The bare ``except Exception`` is deliberate and is the reason this function exists: one
    provider raising must not take the other four down with it. Two things are NOT absorbed:

    * ``BaseException``, so a deadline cancellation reaches :func:`_with_deadline` rather than
      being filed as a provider failure.
    * :class:`PassiveBoundaryViolation`, because it means this tool tried to contact a host
      nobody approved -- most plausibly the target itself. Recording that as one more line in
      an error list would turn the loudest signal the codebase has into routine noise. It is a
      defect in the tool, and it is meant to stop the run.
    """
    session = active_cache()
    cacheable = session is not None and scope is not None and indicator is not None

    if session is not None and scope is not None and indicator is not None:
        lookup = session.lookup(provider=provider, scope=scope, indicator=indicator)
        if lookup.is_hit and lookup.entry is not None:
            _discard_call(call)
            # The payload is replayed byte-for-byte. `_envelope` reads `ok` and `data` exactly as
            # it would from a live call, so a cached answer and a fresh one are the same evidence
            # to every downstream reader -- with the difference recorded, never erased.
            return _envelope(provider, dict(lookup.entry.payload), 0.0)
        if session.offline:
            _discard_call(call)
            session.note_refusal(provider=provider, scope=scope, indicator=indicator, reason=lookup.reason)
            return _offline_call(provider, reason=lookup.reason, lookup=lookup)
    elif session is not None and session.offline:
        # No indicator to key on, so there is nothing this call could ever have been served from.
        # Offline is a boundary, not a preference: refuse instead of reaching the network.
        _discard_call(call)
        return _offline_call(provider, reason="this call carries no cache key and cannot be served from cache")

    # The session's clock, not the wall clock, when a session pinned one. A run that reads ages
    # from one clock and stamps new entries from another files them in its own future, and
    # ``CacheStore.get`` then correctly refuses to date them. One clock per run, read and write.
    queried_at = session.clock() if session is not None else dt.datetime.now(dt.timezone.utc)
    started = time.monotonic()
    try:
        async with rate_limited():
            payload = await _resolve_call(call)
    except PassiveBoundaryViolation:
        raise
    except Exception as exc:  # noqa: BLE001 - converted to a redacted payload, never swallowed
        payload = _error_payload(exc)
    elapsed = time.monotonic() - started

    if not isinstance(payload, dict):
        payload = {
            "ok": False,
            "error": "invalid_provider_payload",
            "message": f"{provider} returned {type(payload).__name__}, expected dict",
        }
    if cacheable and session is not None and scope is not None and indicator is not None:
        session.store_payload(
            provider=provider,
            scope=scope,
            indicator=indicator,
            payload=payload,
            queried_at=queried_at,
        )
    return _envelope(provider, payload, elapsed)


def _collect_errors(
    calls: Mapping[str, ProviderCall], *, prefix: str = ""
) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    """Split provider failures into the per-provider detail map and the human summary lines.

    Suppressed failures (an unset API key, IPinfo's free tier refusing ASN lookups) are left
    out of both, exactly as before -- but unlike before they remain visible in
    :func:`_status_map`, so nothing is actually lost.
    """
    provider_errors: Dict[str, Dict[str, Any]] = {}
    messages: List[str] = []
    for key, call in calls.items():
        if call.ok or call.suppressed:
            continue
        if call.error:
            provider_errors[key] = call.error
        messages.append(f"{prefix}{call.summary}")
    return provider_errors, messages


def _status_map(
    calls: Mapping[str, ProviderCall],
    *,
    scope: Optional[str] = None,
    indicator: Optional[str] = None,
    overrides: Optional[Mapping[str, Tuple[str, str]]] = None,
) -> Dict[str, Dict[str, Any]]:
    """Per-provider outcome, cost, error and **freshness**, for every provider considered.

    This is the record that stops absence from reading as safety. ``data['virustotal'] == {}``
    is ambiguous; ``provider_status['virustotal']['outcome'] == 'not_configured'`` is not.

    ``scope`` and ``indicator`` are what let this function ask the cache session what it did for
    each provider, and the answer lands on ``entry['cache']``: whether the value was replayed,
    when it was actually obtained, how old it is, and when it expires. Without that block a
    consumer reading ``outcome == "ok"`` has no way to tell a lookup from a replay -- which is
    the one distinction this workstream exists to preserve.

    The cache is asked with ``call.provider``, not with the output key, because the two differ
    exactly where it matters: the paid Shodan record and the keyless InternetDB extract share the
    output key ``shodan`` and are two different datasets with two different entries.

    ``overrides`` names the calls in this map whose cache key is NOT ``(scope, indicator)``. There
    is one today: ``cloudflare_asn`` appears in a per-address status map but answers a question
    about the ASN, so it is filed at ASN scope and two addresses in one network share the entry.
    Without the override its record would not be found, and a replayed answer would be counted as
    a fresh one -- an error in the one direction this module may not make.
    """
    session = active_cache()
    status: Dict[str, Dict[str, Any]] = {}
    for key, call in calls.items():
        entry: Dict[str, Any] = {
            "outcome": call.outcome.value,
            "elapsed_seconds": round(call.elapsed_seconds, 3),
        }
        if call.error:
            entry["error"] = call.error
        if call.suppressed:
            entry["suppressed"] = True
        if session is not None:
            override = (overrides or {}).get(key)
            call_scope, call_indicator = override if override is not None else (scope, indicator)
            if call_scope is not None and call_indicator is not None:
                record = session.record_for(provider=call.provider, scope=call_scope, indicator=call_indicator)
                if record is not None:
                    entry["cache"] = record
        status[key] = entry
    return status


# --------------------------------------------------------------------------------------
# Coverage, run metadata and the warnings that carry them to the screen (W4.2-W4.5)
# --------------------------------------------------------------------------------------


def _suppressed_names(data: Mapping[str, Any]) -> List[str]:
    """Providers whose failure was deliberately kept out of ``errors``, across every scope.

    A suppressed failure is still a provider that did not answer. It is kept out of the error
    list because it is expected noise (IPinfo's free tier refusing ASN lookups, RIPEstat
    flapping), not because it is nothing -- and W3.6 was explicit that suppression is a
    rendering decision, never a data-loss one.

    Unconfigured providers are excluded here only because ``Coverage.unconfigured`` already
    names them, and saying it twice reads as two separate problems.

    Names are namespaced exactly as :func:`types.models.coverage_from_result_data` namespaces
    them, so the two lists can be read side by side.
    """
    names: List[str] = []

    def _scan(status_map: Any, prefix: str) -> None:
        if not isinstance(status_map, Mapping):
            return
        for name, entry in status_map.items():
            if not isinstance(entry, Mapping) or not entry.get("suppressed"):
                continue
            # NOT_CONFIGURED is named by ``Coverage.unconfigured`` and SKIPPED by
            # ``Coverage.skipped``; repeating either here reads as a second, separate problem.
            # This list is for calls that were MADE and failed in an expected way.
            if entry.get("outcome") in {ProviderStatus.NOT_CONFIGURED.value, ProviderStatus.SKIPPED.value}:
                continue
            names.append(f"{prefix}{name}")

    _scan(data.get("provider_status"), "")
    _scan(data.get("url_provider_status"), "url:")
    _scan(data.get("domain_provider_status"), "domain:")
    for entry in data.get("ips") or []:
        if isinstance(entry, Mapping):
            _scan(entry.get("provider_status"), f"{entry.get('ip') or '?'}:")
    return names


def _is_blackout(coverage: Coverage) -> bool:
    """True when providers were applicable and none of them answered. See the ``ok`` contract."""
    return coverage.applicable_count > 0 and coverage.answered_count == 0


def _blackout_error(target: str, coverage: Coverage) -> str:
    """The sentence that goes in ``errors`` when nothing answered.

    It lands in ``errors`` rather than only in ``warnings`` because ``cli.py``'s failure branch
    prints ``'; '.join(res.errors)`` and nothing else. A blackout caused entirely by unset API
    keys produces no provider errors at all, so without this line the operator would be told
    the lookup failed and given a blank reason.
    """
    return (
        f"no provider answered for {target} ({coverage.headline}): this is an intelligence blackout, not a clean result"
    )


def _coverage_warnings(
    coverage: Coverage,
    *,
    suppressed: Sequence[str],
    skipped_addresses: Sequence[SkippedAddress],
) -> List[str]:
    """Say on the screen what the data already knew: which providers were never asked.

    This is the whole point of W4. A run with two of six keys configured prints one score and
    one error, and an analyst reads sparse output as a clean indicator unless something tells
    them the other four were never consulted.

    The coverage sentences come first and the per-address ones after, so a renderer that shows
    only the first warning shows the load-bearing one.
    """
    warnings: List[str] = []

    if _is_blackout(coverage):
        warnings.append(f"no provider answered ({coverage.headline}): absence of findings here is absence of evidence")
    elif not coverage.is_complete:
        warnings.append(f"partial coverage: {coverage.headline}")

    if coverage.unconfigured:
        warnings.append("never asked, no API key configured: " + ", ".join(coverage.unconfigured))
    if coverage.skipped:
        warnings.append("never attempted: " + ", ".join(coverage.skipped))
    if suppressed:
        warnings.append("failed, and kept out of the error list as expected noise: " + ", ".join(suppressed))

    warnings.extend(address.explanation for address in skipped_addresses)
    return warnings


def _finalise(
    data: Dict[str, Any],
    *,
    target: str,
    run: RunMetadata,
    errors: List[str],
    expected: Sequence[str],
    domain_expected: Optional[Sequence[str]] = None,
    skipped_addresses: Sequence[SkippedAddress] = (),
    coverage: Optional[Coverage] = None,
) -> InvestigationResult:
    """Compute coverage, publish it with the run metadata, and settle ``ok``.

    One helper for all three orchestrators on purpose: ``ok`` is now a public contract that
    automation keys an exit code on, and three hand-written copies of the rule would eventually
    be three different rules.

    Coverage and run metadata are written into ``data`` **as well as** onto the model fields.
    The model fields are the typed interface; the ``data`` copies exist because the console
    renderers are handed ``result.data`` and nothing else, which is exactly why the ASN path's
    ``warnings`` reached the JSON consumer and never reached the screen (W4.3).

    ``coverage`` overrides the computed figure, and exists for exactly one caller: the URL path
    merges three differently-scoped status maps (URL, host, per-address) whose expected provider
    sets differ, and :func:`types.models.coverage_from_result_data` applies a single ``expected``
    to both the top-level and the per-address maps. Rather than teach that function a fourth
    shape from a file this lane does not own, :func:`_url_coverage` builds the merge and hands it
    in. Every other caller leaves this ``None`` and gets the computed figure.
    """
    if coverage is None:
        coverage = coverage_from_result_data(data, expected=expected, domain_expected=domain_expected)
    warnings = _coverage_warnings(
        coverage,
        suppressed=_suppressed_names(data),
        skipped_addresses=skipped_addresses,
    )

    # Freshness leads the warning list, ahead of the coverage sentences. "N of M answered" is
    # true of a run that queried everything a second ago and of a run that replayed everything
    # from last Tuesday; a reader who sees only the first line has to be shown the difference,
    # because it is the difference between an answer and a claim about the past.
    session = active_cache()
    if session is not None:
        freshness = summarise_freshness(data, offline=session.offline)
        data["freshness"] = freshness
        data["cache"] = session.summary()
        warnings = [*freshness_warnings(freshness), *warnings]

    data["coverage"] = coverage.model_dump()
    data["run"] = run.model_dump()
    data["warnings"] = warnings

    blackout = _is_blackout(coverage)
    if blackout:
        errors.insert(0, _blackout_error(target, coverage))

    return InvestigationResult(
        ok=not blackout,
        data=data,
        warnings=warnings,
        errors=errors,
        run=run,
        coverage=coverage,
        skipped_addresses=list(skipped_addresses),
    )


# --------------------------------------------------------------------------------------
# Adjudication (roadmap 5.8, 5.10) -- collection ends, the verdict engine begins
#
# The engine is pure: signals, coverage, ruleset and a clock in, one verdict out. Every piece
# of I/O it needs -- loading the ruleset, loading the known-infrastructure catalogue, reading
# the wall clock -- happens here, in the caller, which is what keeps the engine exhaustively
# testable offline and lets a saved case be re-scored later under the ruleset that produced the
# original answer.
#
# Two rules shape everything below.
#
# **The engine reads pre-suppression state.** `_should_suppress` drops an unset API key from
# the error list, which is a reasonable rendering decision and a fatal scoring one: it makes an
# unconfigured OTX indistinguishable from an OTX that answered "nothing known". The engine is
# handed `provider_status` and the published `Coverage`, both of which keep every provider that
# was *applicable* in the denominator whether or not its failure was suppressed.
#
# **A verdict failure degrades to "not computed", never to a clean panel.** Adjudication runs
# after `_finalise`, and if it raises, the collection result still stands, `ok` is untouched,
# and `data['verdict_error']` plus a warning say plainly that nothing was adjudicated. The
# alternative -- a report with no verdict line and no explanation -- reads as unremarkable,
# which is the exact failure mode this workstream exists to remove.
# --------------------------------------------------------------------------------------


class _Adjudicator(NamedTuple):
    """The ruleset, the allowlist and the clock, loaded once per investigation."""

    cfg: ScoringConfig
    catalogue: KnownInfrastructure
    now: dt.datetime


def _adjudicator() -> Tuple[Optional[_Adjudicator], Optional[str]]:
    """Load the scoring inputs, or report why they could not be loaded.

    ``(tools, None)`` on success and ``(None, reason)`` on failure. Both loaders raise loudly
    by design -- an empty allowlist and a missing ruleset are each indistinguishable from a
    working one until they produce a wrong answer -- so the failure is caught here exactly once
    and turned into a stated gap rather than an exception that loses the collected data.
    """
    try:
        return _Adjudicator(default_config(), load_catalogue(), dt.datetime.now(dt.timezone.utc)), None
    except Exception as exc:  # noqa: BLE001 - a scoring-config fault must not lose the collection
        reason = f"scoring configuration could not be loaded: {type(exc).__name__}: {exc}"
        log["error"]("Verdict engine unavailable", error=reason)
        return None, reason


def _announcing_asn(entry: Mapping[str, Any]) -> Optional[int]:
    """The ASN IPinfo reported for this address, when it reported one.

    Passed to the catalogue because CIDR coverage for AWS, GCP, Azure and Akamai is deliberately
    partial and ASN matching is the only thing that catches them. A missing ASN degrades the
    lookup to CIDR-only; it is never an error.
    """
    for source in (entry.get("ipinfo"), entry.get("asn_meta")):
        if not isinstance(source, Mapping):
            continue
        raw = source.get("asn")
        if raw is None or isinstance(raw, bool):
            continue
        try:
            return int(raw)
        except (TypeError, ValueError):
            continue
    return None


def _ip_verdict(
    entry: Mapping[str, Any],
    *,
    ip: str,
    tools: _Adjudicator,
    coverage: Optional[Coverage] = None,
) -> Verdict:
    """Adjudicate one address. ``coverage`` overrides the entry's own, for the standalone path."""
    decision = tools.catalogue.evaluate(
        indicator=ip,
        indicator_type="ip",
        asn=_announcing_asn(entry),
        as_of=tools.now.date(),
    )
    return verdict_engine.evaluate_ip_analysis(
        entry,
        cfg=tools.cfg,
        now=tools.now,
        coverage=coverage,
        infrastructure=decision,
    )


def _record_verdict_failure(result: InvestigationResult, reason: str) -> None:
    """State the gap everywhere a consumer might look for a verdict, including per address.

    The per-address stamp matters on the domain path: each resolved address gets its own panel,
    and a panel with no verdict line and no explanation reads as a panel with nothing to
    report. Every scope that would have carried a verdict carries the reason it does not.
    """
    result.data["verdict_error"] = reason
    for entry in result.data.get("ips") or []:
        if isinstance(entry, dict) and entry.get("verdict") is None:
            entry["verdict_error"] = reason
    warning = f"no verdict was computed: {reason}"
    result.warnings.append(warning)
    result.data["warnings"] = list(result.warnings)


def _attach_verdicts(
    result: InvestigationResult,
    *,
    verdict: Optional[Verdict],
    ip_verdicts: Sequence[Verdict] = (),
) -> InvestigationResult:
    """Publish verdicts onto the result, on ``data`` and on the typed fields when they exist.

    ``data`` is written unconditionally: the console renderers are handed ``result.data`` and
    nothing else, and ``-o json`` dumps it, so this is the path that actually reaches both
    consumers today. The per-address verdicts live on their own entries in ``data['ips']``
    rather than in a parallel list, so a verdict cannot drift away from the evidence it
    adjudicates.

    The typed fields are the published W5.1 interface (``InvestigationResult.verdict`` and
    ``.ip_verdicts``) and are set only when the model declares them. That model is not this
    lane's file; setting them conditionally means the wiring is already correct on the day the
    field lands, and setting them unconditionally would drop the values silently until then --
    pydantic ignores an unknown key in ``model_copy(update=...)`` rather than raising.
    """
    if verdict is not None:
        result.data["verdict"] = verdict.to_json_dict()

    declared = set(InvestigationResult.model_fields)
    if not {"verdict", "ip_verdicts"} <= declared:
        return result
    return result.model_copy(update={"verdict": verdict, "ip_verdicts": list(ip_verdicts)})


def _adjudicate_ip(result: InvestigationResult, *, ip: str) -> InvestigationResult:
    """Score one standalone address and attach the verdict.

    The scoring view adds ``ip`` to the published payload rather than changing that payload's
    shape: ``data`` for the ``ip`` subcommand has never carried the address as a key, JSON
    consumers parse it as it stands, and the engine only needs the address to name the
    indicator it is adjudicating.
    """
    tools, reason = _adjudicator()
    if tools is None:
        _record_verdict_failure(result, reason or "the verdict engine is unavailable")
        return result
    try:
        entry: Dict[str, Any] = {**result.data, "ip": ip}
        verdict = _ip_verdict(entry, ip=ip, tools=tools, coverage=result.coverage_or_unknown)
    except Exception as exc:  # noqa: BLE001 - a scoring fault must not lose the collection
        log["error"]("Verdict computation failed", target=ip, error=f"{type(exc).__name__}: {exc}")
        _record_verdict_failure(result, f"the scoring engine raised {type(exc).__name__}: {exc}")
        return result
    return _attach_verdicts(result, verdict=verdict)


def _adjudicate_domain(result: InvestigationResult, *, domain: str) -> InvestigationResult:
    """Score the domain and each of its addresses, separately and never merged.

    A phishing kit on a CDN is a ``MALICIOUS`` domain on a ``KNOWN_INFRASTRUCTURE`` address and
    both are true. Merging the two either indicts every other tenant behind that address or
    clears the phishing kit, so the domain verdict lands on ``data['verdict']`` and each
    address verdict lands on its own entry in ``data['ips']``.
    """
    tools, reason = _adjudicator()
    if tools is None:
        _record_verdict_failure(result, reason or "the verdict engine is unavailable")
        return result

    ip_verdicts: List[Verdict] = []
    try:
        verdict = verdict_engine.evaluate_domain_intel(result.data, cfg=tools.cfg, now=tools.now)
        for entry in result.data.get("ips") or []:
            if not isinstance(entry, dict):
                continue
            address = str(entry.get("ip") or "")
            if not address:
                continue
            address_verdict = _ip_verdict(entry, ip=address, tools=tools)
            entry["verdict"] = address_verdict.to_json_dict()
            ip_verdicts.append(address_verdict)
    except Exception as exc:  # noqa: BLE001 - a scoring fault must not lose the collection
        log["error"]("Verdict computation failed", target=domain, error=f"{type(exc).__name__}: {exc}")
        _record_verdict_failure(result, f"the scoring engine raised {type(exc).__name__}: {exc}")
        return result
    return _attach_verdicts(result, verdict=verdict, ip_verdicts=ip_verdicts)


# --------------------------------------------------------------------------------------
# Target guards
# --------------------------------------------------------------------------------------

# Checked in order, and the order matters: 127.0.0.1 is both loopback and private, and the
# private label is the one the operator already knows. ``is_private`` alone -- the only check
# that existed -- covers neither 224/4 (multicast) nor 240/4 (reserved).
_NON_PUBLIC_CATEGORIES: Tuple[Tuple[str, str], ...] = (
    ("is_private", "Private"),
    ("is_loopback", "Loopback"),
    ("is_link_local", "Link-local"),
    ("is_multicast", "Multicast"),
    ("is_reserved", "Reserved"),
    ("is_unspecified", "Unspecified"),
)


def non_public_ip_reason(ip: str) -> Optional[str]:
    """Label the reason ``ip`` must not be sent to a third party, or ``None`` if it is public.

    Forwarding internal addressing to VirusTotal, Shodan, IPinfo, AbuseIPDB and OTX under the
    operator's own API keys discloses the operator's network to five vendors, and the answer
    would be worthless anyway. Split-horizon DNS and sinkholed domains make this a routine
    case on the domain path, not a hypothetical one.
    """
    try:
        parsed = ip_address(ip)
    except ValueError:
        return None
    for attribute, label in _NON_PUBLIC_CATEGORIES:
        if getattr(parsed, attribute, False):
            return label
    return None


# --------------------------------------------------------------------------------------
# Deadline
# --------------------------------------------------------------------------------------


async def _with_deadline(
    work: Coroutine[Any, Any, InvestigationResult],
    *,
    target: str,
    deadline: Optional[float],
) -> InvestigationResult:
    """Run ``work`` under a wall-clock ceiling, reporting a breach rather than raising.

    Only ``asyncio.TimeoutError`` is caught. A ``CancelledError`` -- the operator interrupting,
    or an outer deadline firing -- propagates, which is what ``cli.py`` expects: it narrows on
    ``BaseException`` precisely because this deadline makes cancellation reachable.
    """
    limit = DEFAULT_TARGET_DEADLINE_SECONDS if deadline is None else deadline
    if limit <= 0:
        return await work
    try:
        return await asyncio.wait_for(work, limit)
    except asyncio.TimeoutError:
        log["error"]("Investigation exceeded its deadline", target=target, deadline_seconds=limit)
        return InvestigationResult(
            ok=False,
            errors=[f"Investigation of {target} exceeded the {limit:g}s wall-clock deadline"],
            data={},
        )


# --------------------------------------------------------------------------------------
# Shared fan-outs
# --------------------------------------------------------------------------------------


def _exposure_call(*, client: httpx.AsyncClient, keys: ApiKeys, ip: str) -> Awaitable[ProviderCall]:
    """One exposure lookup for ``ip``, choosing the paid Shodan record or the keyless extract.

    **The choice is made on key presence, not on the paid call's outcome** (roadmap 8.1). Falling
    back on a paid 404 would re-ask a second Shodan surface about the same address, doubling the
    egress to learn nothing: a paid 404 is already a terminal "no record", which is an
    observation, not a failure to be retried elsewhere.

    The paid record is preferred whenever a key exists, because InternetDB is a strict subset --
    it drops the per-service banners, the network owner, and ``last_update``. Losing the
    observation date is the worst of the three: it removes the tool's only means of saying how
    old an open-port list is, and preferring it for a key-holding operator would be a silent
    downgrade of something they are paying for.
    """
    if keys.shodan_api_key:
        return _call_provider(
            "shodan",
            lambda: shodan_host(client=client, api_key=keys.shodan_api_key, ip=ip),
            scope=SCOPE_IP,
            indicator=ip,
        )
    # Same coverage key: two implementations of one slot, never two slots. Two cache entries
    # though -- InternetDB is a strict subset of the paid record, and filing them together would
    # let a keyless run's thinner answer be replayed to a key-holding one.
    return _call_if_permitted("internetdb", lambda: internetdb_host(client=client, ip=ip), scope=SCOPE_IP, indicator=ip)


async def _ip_provider_wave(*, client: httpx.AsyncClient, keys: ApiKeys, ip: str) -> Dict[str, ProviderCall]:
    """The seven per-IP providers, in one wave."""
    virustotal, ipinfo, shodan, abuseipdb, otx, rdap, abusech = await asyncio.gather(
        _call_provider(
            "virustotal",
            lambda: vt_ip_summary(client=client, api_key=keys.vt_api_key, ip=ip),
            scope=SCOPE_IP,
            indicator=ip,
        ),
        _call_provider(
            "ipinfo",
            lambda: ipinfo_ip(client=client, token=keys.ipinfo_token, ip=ip),
            scope=SCOPE_IP,
            indicator=ip,
        ),
        _exposure_call(client=client, keys=keys, ip=ip),
        _call_provider(
            "abuseipdb",
            lambda: abuseipdb_check(client=client, api_key=keys.abuseipdb_api_key, ip=ip),
            scope=SCOPE_IP,
            indicator=ip,
        ),
        _call_provider(
            "otx",
            lambda: otx_ip_pulses(client=client, api_key=keys.otx_api_key, ip=ip),
            scope=SCOPE_IP,
            indicator=ip,
        ),
        _call_if_permitted("rdap", lambda: rdap_ip(client=client, ip=ip), scope=SCOPE_IP, indicator=ip),
        _call_if_permitted(
            "abusech",
            lambda: abusech_host_summary(client=client, api_key=_abusech_key(), host=ip),
            scope=SCOPE_IP,
            indicator=ip,
        ),
    )
    return {
        "virustotal": virustotal,
        "ipinfo": ipinfo,
        # Keyed ``shodan`` whichever implementation ran; the payload's ``source`` says which.
        "shodan": shodan,
        "abuseipdb": abuseipdb,
        "otx": otx,
        "rdap": rdap,
        "abusech": abusech,
    }


class _AsnMeta(NamedTuple):
    """Cloudflare's ASN metadata, its call envelope, and the ASN it was asked about.

    The ASN travels back out because it is the cache key that call was filed under, and
    :func:`_status_map` needs it to find the record. Deriving it again downstream from
    ``asn_meta['asn']`` would work right up to the run where Cloudflare failed and the dict is
    empty, which is exactly the run where the distinction matters least and the bug hides best.
    """

    data: Dict[str, Any]
    call: Optional[ProviderCall]
    asn: Optional[int]


def _cloudflare_cache_override(asn: Optional[int]) -> Dict[str, Tuple[str, str]]:
    """The ``overrides`` argument for a status map containing ``cloudflare_asn``."""
    return {} if asn is None else {"cloudflare_asn": (SCOPE_ASN, str(asn))}


async def _asn_meta_for_ip(*, client: httpx.AsyncClient, keys: ApiKeys, ipinfo: ProviderCall) -> _AsnMeta:
    """Cloudflare Radar metadata for the ASN IPinfo reported, when it reported one.

    Second wave by necessity, not by oversight: the ASN is not known until IPinfo answers.
    """
    if not ipinfo.ok:
        return _AsnMeta({}, None, None)
    raw_asn = ipinfo.data.get("asn")
    if not raw_asn:
        return _AsnMeta({}, None, None)
    try:
        asn = int(raw_asn)
    except (TypeError, ValueError):
        return _AsnMeta({}, None, None)

    # Cached at ASN scope, not at the address's. The answer is a property of the ASN, so two
    # addresses in the same network share one entry -- which is where most of the quota relief on
    # a domain with eight A records actually comes from.
    call = await _call_provider(
        "cloudflare_asn",
        lambda: fetch_asn_metadata(client=client, api_token=keys.cloudflare_api_token, asn=asn),
        scope=SCOPE_ASN,
        indicator=str(asn),
    )
    return _AsnMeta(call.data if call.ok else {}, call, asn)


def _ip_entry(
    ip: str,
    calls: Mapping[str, ProviderCall],
    asn_meta: Dict[str, Any],
    *,
    asn: Optional[int] = None,
) -> Dict[str, Any]:
    """The per-IP analysis dict ``reporting.console.render_ip_analysis`` consumes."""
    status = _status_map(calls, scope=SCOPE_IP, indicator=ip, overrides=_cloudflare_cache_override(asn))
    return {
        "ip": ip,
        "ptr": None,
        "virustotal": calls["virustotal"].data,
        "shodan": calls["shodan"].data,
        "ipinfo": calls["ipinfo"].data,
        "abuseipdb": calls["abuseipdb"].data,
        "otx": calls["otx"].data,
        "rdap": calls["rdap"].data,
        "abusech": calls["abusech"].data,
        "asn_meta": asn_meta,
        "provider_status": status,
        # Per address, not only per run: on the domain path each address gets its own panel,
        # and one address answered by five providers beside one answered by none is exactly
        # the distinction a single run-level number would flatten.
        "coverage": Coverage.from_status_map(status, expected=IP_PROVIDERS).model_dump(),
    }


# --------------------------------------------------------------------------------------
# IP
# --------------------------------------------------------------------------------------


async def investigate_ip(ip: str, *, deadline: Optional[float] = None) -> InvestigationResult:
    """Investigate one IP address across the five per-IP providers, plus ASN metadata.

    ``ok`` follows the contract in the module docstring: ``False`` for a malformed address, for
    non-public addressing this tool refuses to forward, for a deadline breach, and for a run in
    which no provider answered. ``True`` otherwise -- including for a partial answer, whose
    extent is in ``data['coverage']``. ``ok=True`` is not a claim that the lookup was complete.
    """
    if not is_valid_ip(ip):
        return InvestigationResult(ok=False, errors=["Invalid IP address"], data={})

    reason = non_public_ip_reason(ip)
    if reason is not None:
        return InvestigationResult(ok=False, errors=[f"{reason} IP address {ip} cannot be investigated."], data={})

    return await _with_deadline(_investigate_ip(ip), target=ip, deadline=deadline)


async def _investigate_ip(ip: str) -> InvestigationResult:
    keys = _env_keys()
    async with create_client() as client:
        calls = await _ip_provider_wave(client=client, keys=keys, ip=ip)
        cloudflare = await _asn_meta_for_ip(client=client, keys=keys, ipinfo=calls["ipinfo"])
        if cloudflare.call is not None:
            calls["cloudflare_asn"] = cloudflare.call

        provider_errors, result_errors = _collect_errors(calls)

        data: Dict[str, Any] = {
            "ipinfo": calls["ipinfo"].data,
            "virustotal": calls["virustotal"].data,
            "shodan": calls["shodan"].data,
            "abuseipdb": calls["abuseipdb"].data,
            "otx": calls["otx"].data,
            "rdap": calls["rdap"].data,
            "abusech": calls["abusech"].data,
            "asn_meta": cloudflare.data,
            "provider_status": _status_map(
                calls,
                scope=SCOPE_IP,
                indicator=ip,
                overrides=_cloudflare_cache_override(cloudflare.asn),
            ),
        }
        if provider_errors:
            data["errors"] = provider_errors

        result = _finalise(
            data,
            target=ip,
            run=current_run(),
            errors=result_errors,
            expected=IP_PROVIDERS,
        )
    # Outside the client block on purpose: adjudication is pure computation over what was
    # already collected, and holding an HTTP client open across it would suggest otherwise.
    return _adjudicate_ip(result, ip=ip)


# --------------------------------------------------------------------------------------
# Domain
# --------------------------------------------------------------------------------------


def _tag_ip_sources(active: Sequence[str], passive: Sequence[str]) -> List[Tuple[str, str]]:
    """Order addresses active-first and record where each one came from.

    ``ips = active_ips + passive_ips`` destroyed a distinction the author's own variable names
    show he understood. "Resolved now" and "seen historically by VirusTotal" are different
    evidentiary claims: a passive-only address may be years stale, and an active-only address
    is one no passive source has ever corroborated. A verdict has to be able to tell them
    apart, so the label travels with the address rather than being reconstructed later.
    """
    active_set = set(active)
    passive_set = set(passive)
    tagged: List[Tuple[str, str]] = []
    for ip in dedupe_preserve_order([*active, *passive]):
        if ip in active_set and ip in passive_set:
            source = "active+passive"
        elif ip in active_set:
            source = "active"
        else:
            source = "passive"
        tagged.append((ip, source))
    return tagged


def _passive_ips_from_vt(vt_data: Mapping[str, Any]) -> List[str]:
    records = vt_data.get("vt_dns_records") or []
    out: List[str] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        if record.get("type") not in {"A", "AAAA"}:
            continue
        value = record.get("value")
        if value:
            out.append(str(value))
    return out


async def _enrich_domain_ip(
    *, client: httpx.AsyncClient, keys: ApiKeys, ip: str, source: str
) -> Tuple[Dict[str, Any], List[str]]:
    """One resolved address of a domain: five providers in one wave, then Cloudflare."""
    calls = await _ip_provider_wave(client=client, keys=keys, ip=ip)
    cloudflare = await _asn_meta_for_ip(client=client, keys=keys, ipinfo=calls["ipinfo"])
    if cloudflare.call is not None:
        calls["cloudflare_asn"] = cloudflare.call

    provider_errors, messages = _collect_errors(calls, prefix=f"{ip} :: ")

    entry = _ip_entry(ip, calls, cloudflare.data, asn=cloudflare.asn)
    entry["source"] = source
    if provider_errors:
        entry["errors"] = provider_errors
    return entry, messages


def _skipped_address(ip: str, source: str, reason: str) -> SkippedAddress:
    """One address the non-public guard refused, as a typed record.

    An address that vanishes from the output is worse than one reported as not investigated: a
    domain resolving to three internal addresses and one public one renders as a domain with
    one address, and the analyst is never told the other three exist.

    ``reason`` arrives as the human label from ``_NON_PUBLIC_CATEGORIES`` (``Private``,
    ``Link-local``); :class:`SkipReason` normalises the casing and the hyphen/underscore drift,
    and falls back to ``OTHER`` with the original wording preserved rather than dropping a
    category it does not recognise.
    """
    label = reason.strip().lower()
    parsed = SkipReason(label)
    return SkippedAddress(
        address=ip,
        reason=parsed,
        source=source,
        detail=label if parsed is SkipReason.OTHER else None,
    )


async def investigate_domain(domain: str, *, deadline: Optional[float] = None) -> InvestigationResult:
    """Investigate one domain: domain-level intel, then every public address it resolves to.

    ``ok`` follows the contract in the module docstring: ``False`` for a malformed domain, for a
    deadline breach, and for a run in which no provider answered at either level. ``True``
    otherwise, with ``data['coverage']`` stating how much of what was attempted came back.

    Addresses refused by the non-public guard are **not** dropped. They appear in
    ``data['skipped_ips']`` with their provenance and the reason, are counted in
    ``data['coverage']['addresses_skipped']``, and each one raises a warning.
    """
    if not is_valid_domain(domain):
        return InvestigationResult(ok=False, errors=["Invalid domain"], data={})
    return await _with_deadline(_investigate_domain(domain), target=domain, deadline=deadline)


class _DomainCollection(NamedTuple):
    """Everything the host stage of an investigation gathered, before assembly into ``data``."""

    calls: Dict[str, ProviderCall]
    intel: Dict[str, Any]
    provider_errors: Dict[str, Dict[str, Any]]
    messages: List[str]
    entries: List[Dict[str, Any]]
    skipped: List[SkippedAddress]
    #: True when the system resolver was used **on this run**, i.e. when the OPSEC §3 exception
    #: was exercised. A resolution replayed from cache leaves this False: no query left the host,
    #: which is the whole claim ``collection.passive_only`` makes.
    resolved_actively: bool
    #: Said out loud whenever the address list is not a live resolution -- a replay, or nothing at
    #: all under ``--offline``. ``None`` when the resolver ran normally.
    resolution_note: Optional[str] = None


async def _resolve_addresses(domain: str) -> Tuple[List[str], Optional[str], bool]:
    """Resolve ``domain``, or replay a cached resolution, or refuse under ``--offline``.

    Returns ``(addresses, note, resolved_actively)``.

    The system resolver is the one outbound step this tool takes that is not a provider call
    (``docs/OPSEC.md`` §3), and ``--offline`` is worth nothing if it cannot avoid it: a run that
    contacts no provider but still queries DNS has still told a nameserver what the operator is
    looking at. So resolution goes through the same cache lane as everything else, under the
    ``dns`` pseudo-provider and the shortest lifetime in the ruleset.

    Two rules that are not obvious:

    * **An empty answer is never stored.** ``resolve_domain`` returns ``[]`` for NXDOMAIN and for
      a resolver timeout alike, and filing that as a successful observation would let one flaky
      lookup teach the cache that a domain has no addresses.
    * **A replayed list means ``resolved_actively`` is False.** No query left this host on this
      run, so ``collection.passive_only`` says so -- and the note says where the list came from
      and how old it is, because a cached A record is a historical claim about a mapping that
      fast-flux infrastructure exists specifically to invalidate.
    """
    # utils.dns is the one sanctioned resolution site (docs/OPSEC.md section 3); the import
    # stays local so tests/test_passivity.py keeps seeing exactly one resolver module.
    from tripper_recon.utils.dns import resolve_domain

    session = active_cache()
    if session is None:
        return list(await resolve_domain(domain)), None, True

    lookup = session.lookup(provider=DNS_PROVIDER, scope=SCOPE_DOMAIN, indicator=domain)
    if lookup.is_hit and lookup.entry is not None:
        payload = lookup.entry.payload.get("data")
        addresses = (
            [str(value) for value in (payload or {}).get("addresses") or []] if isinstance(payload, dict) else []
        )
        note = (
            f"the address list was replayed from cache: resolved {format_age(lookup.age_seconds)} ago "
            f"(at {lookup.entry.queried_at}), not now. Nothing was asked of the resolver on this run"
        )
        return addresses, note, False

    if session.offline:
        session.note_refusal(provider=DNS_PROVIDER, scope=SCOPE_DOMAIN, indicator=domain, reason=lookup.reason)
        note = (
            "--offline: the host was not resolved and no usable cached resolution exists "
            f"({lookup.reason}). No address was investigated, which is missing coverage, not a clean result"
        )
        return [], note, False

    # The session's clock, for the reason given in ``_call_provider``: one clock per run.
    queried_at = session.clock()
    addresses = list(await resolve_domain(domain))
    if addresses:
        session.store_payload(
            provider=DNS_PROVIDER,
            scope=SCOPE_DOMAIN,
            indicator=domain,
            payload={"ok": True, "data": {"addresses": addresses}},
            queried_at=queried_at,
        )
    return addresses, None, True


async def _collect_domain(
    *,
    client: httpx.AsyncClient,
    keys: ApiKeys,
    domain: str,
    resolve_addresses: bool = True,
) -> _DomainCollection:
    """The host stage: domain-level intel, then optionally the addresses the name resolves to.

    Shared by :func:`_investigate_domain` and :func:`_investigate_url` so that the URL path
    composes the existing pivot instead of growing a second copy of it. A second copy would
    drift, and the thing it would drift on is the non-public-address guard.

    ``resolve_addresses=False`` makes this stage **fully passive**: no name is resolved and no
    address is enriched, so the target's authoritative nameserver learns nothing. That is what
    ``--depth host`` buys on the URL path, and it is the honest default for a link whose host
    the analyst has not yet decided to touch. Domain-level intel is unaffected: VirusTotal and
    OTX are asked about the name either way, and VirusTotal's passive A/AAAA records still
    arrive in ``intel``.
    """
    vt_domain, otx_domain, rdap_call, tranco_call, abusech_call = await asyncio.gather(
        _call_provider(
            "virustotal_domain",
            lambda: vt_domain_summary(client=client, api_key=keys.vt_api_key, domain=domain),
            scope=SCOPE_DOMAIN,
            indicator=domain,
        ),
        _call_provider(
            "otx_domain",
            lambda: otx_domain_pulses(client=client, api_key=keys.otx_api_key, domain=domain),
            scope=SCOPE_DOMAIN,
            indicator=domain,
        ),
        _call_if_permitted(
            "rdap", lambda: rdap_domain(client=client, domain=domain), scope=SCOPE_DOMAIN, indicator=domain
        ),
        _call_if_permitted(
            "tranco", lambda: tranco_rank(client=client, domain=domain), scope=SCOPE_DOMAIN, indicator=domain
        ),
        _call_if_permitted(
            "abusech",
            lambda: abusech_host_summary(client=client, api_key=_abusech_key(), host=domain),
            scope=SCOPE_DOMAIN,
            indicator=domain,
        ),
    )

    intel: Dict[str, Any] = {}
    passive_ips: List[str] = []
    if vt_domain.ok:
        intel["virustotal"] = vt_domain.data
        passive_ips = _passive_ips_from_vt(vt_domain.data)
    if otx_domain.ok:
        intel["otx"] = otx_domain.data
    if rdap_call.ok:
        intel["rdap"] = rdap_call.data
    if tranco_call.ok:
        intel["tranco"] = tranco_call.data
    if abusech_call.ok:
        intel["abusech"] = abusech_call.data

    calls = {
        "virustotal": vt_domain,
        "otx": otx_domain,
        "rdap": rdap_call,
        "tranco": tranco_call,
        "abusech": abusech_call,
    }
    provider_errors, messages = _collect_errors(calls)

    if not resolve_addresses:
        return _DomainCollection(
            calls=calls,
            intel=intel,
            provider_errors=provider_errors,
            messages=messages,
            entries=[],
            skipped=[],
            resolved_actively=False,
        )

    active_ips, resolution_note, resolved_actively = await _resolve_addresses(domain)

    enrichable: List[Tuple[str, str]] = []
    skipped: List[SkippedAddress] = []
    for ip, source in _tag_ip_sources(active_ips, passive_ips):
        reason = non_public_ip_reason(ip)
        if reason is None:
            enrichable.append((ip, source))
            continue
        skipped.append(_skipped_address(ip, source, reason))

    gate = asyncio.Semaphore(MAX_CONCURRENT_IPS)

    async def _bounded(ip: str, source: str) -> Tuple[Dict[str, Any], List[str]]:
        async with gate:
            return await _enrich_domain_ip(client=client, keys=keys, ip=ip, source=source)

    enriched = await asyncio.gather(*(_bounded(ip, source) for ip, source in enrichable))

    entries: List[Dict[str, Any]] = []
    address_messages: List[str] = []
    for entry, entry_messages in enriched:
        entries.append(entry)
        address_messages.extend(entry_messages)

    # Per-address messages first, then the domain-level ones -- the order the domain path has
    # always published, which `tests/test_orchestrators.py` reads positionally.
    return _DomainCollection(
        calls=calls,
        intel=intel,
        provider_errors=provider_errors,
        messages=[*address_messages, *messages],
        entries=entries,
        skipped=skipped,
        resolved_actively=resolved_actively,
        resolution_note=resolution_note,
    )


def _address_accounting(entries: Sequence[Dict[str, Any]], skipped: Sequence[SkippedAddress]) -> Dict[str, int]:
    return {
        "resolved": len(entries) + len(skipped),
        "investigated": len(entries),
        "skipped": len(skipped),
    }


def _skipped_ip_rows(skipped: Sequence[SkippedAddress]) -> List[Dict[str, Any]]:
    """Always present, even when empty.

    A renderer that sees the key only when something was skipped cannot tell "none were
    skipped" from "this build does not report skips", and the second reading is the one that
    gets an analyst hurt.
    """
    return [{"ip": address.address, "source": address.source, "reason": address.reason.value} for address in skipped]


async def _investigate_domain(domain: str) -> InvestigationResult:
    keys = _env_keys()

    async with create_client() as client:
        collected = await _collect_domain(client=client, keys=keys, domain=domain)

    out = collected.entries
    skipped = collected.skipped
    result_errors: List[str] = list(collected.messages)

    data: Dict[str, Any] = {
        "domain": domain,
        "ips": out,
        "domain_provider_status": _status_map(collected.calls, scope=SCOPE_DOMAIN, indicator=domain),
        "addresses": _address_accounting(out, skipped),
        "skipped_ips": _skipped_ip_rows(skipped),
        # Published on the domain path too, not only on the URL path: whether the resolver ran
        # is a fact about this run's egress, and a replayed address list means it did not.
        "collection": {
            "passive_only": not collected.resolved_actively,
            "active_steps": ["system resolver (docs/OPSEC.md section 3)"] if collected.resolved_actively else [],
        },
    }
    if collected.intel:
        data["domain_intel"] = collected.intel
    if collected.provider_errors:
        data["domain_errors"] = collected.provider_errors

    result = _finalise(
        data,
        target=domain,
        run=current_run(),
        errors=result_errors,
        expected=IP_PROVIDERS,
        domain_expected=DOMAIN_PROVIDERS,
        skipped_addresses=skipped,
    )
    if collected.resolution_note:
        result.warnings.insert(0, collected.resolution_note)
        result.data["warnings"] = list(result.warnings)
    return _adjudicate_domain(result, domain=domain)


# --------------------------------------------------------------------------------------
# URL (roadmap 6.8)
#
# The one thing to understand about this path: **it adds no new way to reach the target.**
# A URL investigation is the URL-report lookup plus the existing host -> address -> ASN pivot,
# composed. Nothing here fetches the link, follows a redirect, expands a shortener, or submits
# the URL anywhere for analysis. `redirect_chain` is reported as NOT RESOLVED unless a third
# party's already-completed scan supplied one, and then it is stamped with that party's name
# and the date they saw it, because a cached chain is a historical claim and a redirector that
# pointed at a kit last month may point at a parked page today.
#
# It also fixes a routing defect rather than papering over it: a URL with an IP-literal host
# ("hxxp://185.220.101.5:8080/x", written defanged here because tests/test_passivity.py fails the
# build on any absolute URL literal whose host is not allowlisted -- the same reason
# the URL parser in ``utils.urls`` defangs its own docstrings) used to be handed to the domain
# orchestrator, where
# `is_valid_domain` rejected it and the analyst got "Invalid domain" for a perfectly well-formed
# indicator. Here the host's kind decides which existing stage runs.
# --------------------------------------------------------------------------------------

#: Schemes a URL investigation will look up. Anything else is refused rather than guessed at:
#: no provider in this tool holds intelligence about ``file:``, ``javascript:`` or ``data:``,
#: and forwarding one would spend quota to learn nothing.
INVESTIGABLE_URL_SCHEMES: FrozenSet[str] = frozenset({"http", "https"})

#: The address-provenance tag for the single address a URL's IP-literal host contributes.
#: Distinct from ``active``/``passive`` because nothing was resolved -- the analyst wrote the
#: address into the link, and ``reporting.console`` echoes an unrecognised tag verbatim.
URL_HOST_SOURCE = "url-host"

#: Said out loud, at the top of the warning list, whenever VirusTotal holds no report.
#:
#: The provider module refuses to map this onto the shared ``not_found`` error precisely so it
#: cannot land in ``Coverage.answered``: for an address, "no record" is evidence, because the
#: address exists whether or not anyone submitted it. For a URL it is not. A link that went live
#: an hour ago has no report, and neither does a link nobody has ever seen; the two are
#: indistinguishable here and neither is exculpatory.
VT_URL_NO_REPORT_WARNING = (
    "VirusTotal holds no report for this URL. That is the ordinary state of a link nobody has "
    "submitted yet -- including one stood up an hour ago -- and it carries no exculpatory weight"
)


def _has_no_vt_url_report(call: ProviderCall) -> bool:
    """True when VirusTotal answered specifically "nobody has ever submitted this URL"."""
    return bool(call.error) and call.error.get("error") == VT_URL_NO_REPORT_ERROR


def _url_anomaly_rows(parsed: ParsedURL) -> List[Dict[str, str]]:
    """The parser's observations, flattened for JSON and for the renderer.

    Anomalies are signals for a reader (and, once ``verdict/`` grows ``url.*`` signal ids, for a
    scorer). They are never a verdict here: plenty of benign sites use IDN, and it is the
    combination that is interesting.
    """
    return [
        {"code": anomaly.code.value, "component": anomaly.component, "detail": anomaly.detail}
        for anomaly in parsed.anomalies
    ]


def _redirect_chain_from_vt(vt_url_data: Mapping[str, Any]) -> RedirectChain:
    """Read VirusTotal's recorded chain, or say plainly that nobody's scan supplied one.

    Three distinct facts, kept distinct, because collapsing them is how a report starts implying
    that a link does not redirect:

    * a chain a third party recorded -- carried with the provider, the field and the date;
    * a passive source consulted that held no chain -- ``not_resolved`` with that as the reason;
    * nothing consulted at all -- the default reason, which says we did not look.

    This tool never resolves one. There is no branch here that could.
    """
    observation = vt_url_data.get("vt_redirect_observation")
    source = observation.get("source") if isinstance(observation, Mapping) else None
    observed_at = observation.get("observed_at") if isinstance(observation, Mapping) else None

    hops_raw = vt_url_data.get("vt_redirection_chain")
    hops = tuple(str(hop) for hop in hops_raw if str(hop).strip()) if isinstance(hops_raw, (list, tuple)) else ()
    final_url = vt_url_data.get("vt_last_final_url")
    final = str(final_url) if isinstance(final_url, str) and final_url.strip() else None

    if source and (hops or final):
        return RedirectChain.from_passive_record(
            hops,
            source=str(source),
            final_url=final,
            observed_at=str(observed_at) if observed_at else None,
        )
    return RedirectChain.not_resolved(
        "VirusTotal holds a report for this URL and it records no redirect. That is one passive "
        "source saying so at one moment, not a statement about where the link leads now."
    )


def _url_coverage(
    *,
    url_status: Mapping[str, Any],
    domain_status: Optional[Mapping[str, Any]],
    entries: Sequence[Mapping[str, Any]],
) -> Coverage:
    """Merge the URL, host and per-address coverages, each against its own expected set.

    Built here rather than by ``coverage_from_result_data`` because that function applies one
    ``expected`` sequence to both the top-level and the per-address maps, and on this path those
    are different provider sets. The namespacing matches it exactly (``url:``, ``domain:``,
    ``<address>:``) so the two never state ratios in different vocabularies.
    """
    parts: List[Coverage] = [Coverage.from_status_map(url_status, expected=URL_PROVIDERS, prefix="url:")]
    if domain_status is not None:
        parts.append(Coverage.from_status_map(domain_status, expected=DOMAIN_PROVIDERS, prefix="domain:"))
    for entry in entries:
        per_ip = entry.get("provider_status")
        if isinstance(per_ip, Mapping):
            parts.append(Coverage.from_status_map(per_ip, expected=IP_PROVIDERS, prefix=f"{entry.get('ip') or '?'}:"))
    return Coverage.merge(parts)


def _url_target_error(parsed: ParsedURL) -> Optional[str]:
    """Why this URL cannot be investigated, or ``None`` when it can.

    Refusing is cheap and quota is not. Each branch below is a case where every provider call
    would be made against a string that cannot have a report.
    """
    if not parsed.is_hierarchical:
        return (
            f"{parsed.scheme}: is not a hierarchical URL, so there is no host to investigate. "
            "Investigate whatever the payload contains instead"
        )
    if parsed.scheme.lower() not in INVESTIGABLE_URL_SCHEMES:
        return (
            f"scheme {parsed.scheme!r} is not one this tool investigates "
            f"({', '.join(sorted(INVESTIGABLE_URL_SCHEMES))})"
        )
    if not parsed.host:
        return "Invalid URL: no host component"
    if parsed.host_kind in {HostKind.IPV4, HostKind.IPV6}:
        reason = non_public_ip_reason(parsed.host)
        if reason is not None:
            return f"{reason} IP address {parsed.host} cannot be investigated."
    return None


async def investigate_url(
    url: str,
    *,
    depth: str = DEFAULT_URL_DEPTH,
    deadline: Optional[float] = None,
) -> InvestigationResult:
    """Investigate one URL: the link itself, then optionally its host and its addresses.

    ``depth`` is one of :data:`URL_DEPTHS`. ``url`` and ``host`` are fully passive -- no name is
    resolved at either -- and ``full`` adds the resolver step that ``docs/OPSEC.md`` §3 discloses.

    ``ok`` follows the same contract as every other entry point (module docstring): ``False``
    for a URL this tool refuses or cannot parse a host out of, for non-public addressing, for a
    deadline breach, and for a run in which no provider answered at any level.
    """
    if depth not in URL_DEPTHS:
        return InvestigationResult(
            ok=False,
            errors=[f"Invalid depth {depth!r}: expected one of {', '.join(URL_DEPTHS)}"],
            data={},
        )

    parsed = parse_url(url)
    refusal = _url_target_error(parsed)
    if refusal is not None:
        return InvestigationResult(ok=False, errors=[refusal], data={})

    return await _with_deadline(
        _investigate_url(parsed, depth=depth),
        target=parsed.masked_url,
        deadline=deadline,
    )


async def _investigate_url(parsed: ParsedURL, *, depth: str) -> InvestigationResult:
    keys = _env_keys()
    target = parsed.normalised_url
    host = parsed.host
    host_is_address = parsed.host_kind in {HostKind.IPV4, HostKind.IPV6}

    result_errors: List[str] = []
    url_intel: Dict[str, Any] = {}
    entries: List[Dict[str, Any]] = []
    skipped: List[SkippedAddress] = []
    domain_status: Optional[Dict[str, Any]] = None
    domain_intel: Dict[str, Any] = {}
    domain_errors: Dict[str, Dict[str, Any]] = {}
    resolved_actively = False
    resolution_note: Optional[str] = None

    async with create_client() as client:
        vt_url_call, abusech_url_call = await asyncio.gather(
            _call_provider(
                "virustotal_url",
                lambda: vt_url_summary(client=client, api_key=keys.vt_api_key, url=target),
                scope=SCOPE_URL,
                indicator=target,
            ),
            # The exact-URL abuse.ch lookup: URLhaus's own URL endpoint plus an EXACT ThreatFox
            # search. This is the strongest form of the abuse.ch observation -- a record for this
            # link rather than for something that once happened on its host.
            _call_if_permitted(
                "abusech",
                lambda: abusech_url_summary(client=client, api_key=_abusech_key(), url=target),
                scope=SCOPE_URL,
                indicator=target,
            ),
        )
        url_calls = {"virustotal_url": vt_url_call, "abusech": abusech_url_call}
        if vt_url_call.ok:
            url_intel["virustotal"] = vt_url_call.data
        if abusech_url_call.ok:
            url_intel["abusech"] = abusech_url_call.data

        url_errors, url_messages = _collect_errors(url_calls)
        result_errors.extend(url_messages)

        if depth != "url":
            if host_is_address:
                # No name to look up, so the host stage IS the address stage. Nothing resolves.
                entry, messages = await _enrich_domain_ip(client=client, keys=keys, ip=host, source=URL_HOST_SOURCE)
                entries.append(entry)
                result_errors.extend(messages)
            else:
                collected = await _collect_domain(
                    client=client,
                    keys=keys,
                    domain=host,
                    resolve_addresses=depth == "full",
                )
                domain_status = _status_map(collected.calls, scope=SCOPE_DOMAIN, indicator=host)
                domain_intel = collected.intel
                domain_errors = collected.provider_errors
                entries = collected.entries
                skipped = collected.skipped
                resolved_actively = collected.resolved_actively
                resolution_note = collected.resolution_note
                result_errors.extend(collected.messages)

    url_status = _status_map(url_calls, scope=SCOPE_URL, indicator=target)
    vt_url_data = url_intel.get("virustotal")
    chain = _redirect_chain_from_vt(vt_url_data) if isinstance(vt_url_data, Mapping) else RedirectChain.not_resolved()

    data: Dict[str, Any] = {
        # `url` is the evidence form and carries the URL byte-for-byte, credentials included:
        # machines consume the JSON export and a rewritten indicator breaks them. `url_display`
        # is the form a human-facing renderer prints, with any password masked.
        "url": target,
        "url_display": parsed.masked_url,
        "url_raw": parsed.raw,
        "depth": depth,
        "scheme": parsed.scheme,
        "scheme_assumed": parsed.scheme_assumed,
        "host": host,
        "host_kind": parsed.host_kind.value,
        "host_ascii": parsed.host_ascii,
        # The full host, deliberately. ``utils.urls`` never guesses an eTLD+1, and a guessed one
        # pivots the investigation onto the wrong entity while looking exactly as confident.
        "pivot_host": parsed.pivot_host,
        "registrable_domain": parsed.registrable_domain,
        "registrable_domain_status": parsed.registrable_domain_status.value,
        "port": parsed.port,
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment,
        "userinfo_present": parsed.userinfo_present,
        "url_anomalies": _url_anomaly_rows(parsed),
        "redirect_chain": {**chain.model_dump(mode="json"), "rendered": chain.render()},
        "url_provider_status": url_status,
        "ips": entries,
        "addresses": _address_accounting(entries, skipped),
        "skipped_ips": _skipped_ip_rows(skipped),
        "collection": {
            "passive_only": not resolved_actively,
            "active_steps": ["system resolver (docs/OPSEC.md section 3)"] if resolved_actively else [],
        },
    }
    if url_intel:
        data["url_intel"] = url_intel
    if url_errors:
        data["url_errors"] = url_errors
    if domain_status is not None:
        data["domain"] = host
        data["domain_provider_status"] = domain_status
        if domain_intel:
            data["domain_intel"] = domain_intel
        if domain_errors:
            data["domain_errors"] = domain_errors

    result = _finalise(
        data,
        target=parsed.masked_url,
        run=current_run(),
        errors=result_errors,
        expected=IP_PROVIDERS,
        domain_expected=DOMAIN_PROVIDERS,
        skipped_addresses=skipped,
        coverage=_url_coverage(url_status=url_status, domain_status=domain_status, entries=entries),
    )
    if resolution_note:
        result.warnings.insert(0, resolution_note)
        result.data["warnings"] = list(result.warnings)
    if _has_no_vt_url_report(url_calls["virustotal_url"]):
        # Published as its own flag rather than left for a renderer to re-derive from the error
        # payload. "no report exists" and "the query failed" are different facts and only one
        # of them means nobody has ever submitted this link; a renderer that cannot tell them
        # apart prints the wrong one.
        result.data["url_report_missing"] = True
        result.warnings.insert(0, VT_URL_NO_REPORT_WARNING)
        result.data["warnings"] = list(result.warnings)
    return _adjudicate_url(result, parsed=parsed, host_is_address=host_is_address)


def _adjudicate_url(result: InvestigationResult, *, parsed: ParsedURL, host_is_address: bool) -> InvestigationResult:
    """Score the URL, and separately its host and each of its addresses. Never merged.

    Same rule as the domain path, one level up: a phishing page on a compromised WordPress site
    is a malicious URL on a host that is itself a victim, and both statements have to survive to
    the screen. The URL verdict lands on ``data['verdict']``, the host's on
    ``data['host_verdict']``, and each address's on its own entry in ``data['ips']``.

    **The URL scope now scores, but only from abuse.ch.** ``urlhaus.listing`` and
    ``threatfox.ioc`` are the only signals in the ruleset whose ``applies_to`` includes ``url``,
    which is the right first pair: URLhaus is a database *of malware distribution URLs*, so an
    exact-URL record carries a retrieved file and its hash with none of the shared-hosting
    ambiguity a host-level hit inherits.

    VirusTotal's URL report is collected and rendered and is deliberately **not** scored: the
    ruleset declares no ``vt.*`` signal for this scope, and inventing one in code would put a
    scoring constant in a ``.py`` file. Until those weights land, a URL with no abuse.ch record
    scores nothing and the verdict says ``INSUFFICIENT_DATA`` -- which is the true answer here,
    not a degradation.
    """
    tools, reason = _adjudicator()
    if tools is None:
        _record_verdict_failure(result, reason or "the verdict engine is unavailable")
        return result

    ip_verdicts: List[Verdict] = []
    try:
        verdict = verdict_engine.evaluate(
            indicator=parsed.masked_url,
            scope=IndicatorScope.URL,
            signals=verdict_signals.extract_url_signals(
                result.data.get("url_intel"), tools.cfg, tools.now, url=parsed.masked_url
            ),
            coverage=result.coverage_or_unknown,
            cfg=tools.cfg,
            now=tools.now,
            passive_only=bool((result.data.get("collection") or {}).get("passive_only", True)),
            active_collection=tuple((result.data.get("collection") or {}).get("active_steps") or ()),
        )
        if not host_is_address and result.data.get("domain_provider_status") is not None:
            host_verdict = verdict_engine.evaluate_domain_intel(result.data, cfg=tools.cfg, now=tools.now)
            result.data["host_verdict"] = host_verdict.to_json_dict()
        for entry in result.data.get("ips") or []:
            if not isinstance(entry, dict):
                continue
            address = str(entry.get("ip") or "")
            if not address:
                continue
            address_verdict = _ip_verdict(entry, ip=address, tools=tools)
            entry["verdict"] = address_verdict.to_json_dict()
            ip_verdicts.append(address_verdict)
    except Exception as exc:  # noqa: BLE001 - a scoring fault must not lose the collection
        log["error"]("Verdict computation failed", target=parsed.masked_url, error=f"{type(exc).__name__}: {exc}")
        _record_verdict_failure(result, f"the scoring engine raised {type(exc).__name__}: {exc}")
        return result
    return _attach_verdicts(result, verdict=verdict, ip_verdicts=ip_verdicts)


# --------------------------------------------------------------------------------------
# ASN
# --------------------------------------------------------------------------------------


async def _resolve_neighbour_names(*, client: httpx.AsyncClient, asns: Sequence[int]) -> Dict[int, str]:
    """Resolve neighbour ASNs to holder names, at most ``MAX_CONCURRENT_NEIGHBOUR_LOOKUPS`` at a time.

    ``--neighbors 8`` asks for up to 24 lookups and the previous code gathered every one of
    them at once. Failures are dropped rather than surfaced: a missing neighbour NAME degrades
    the display to the bare ASN, which is not a finding.
    """
    gate = asyncio.Semaphore(MAX_CONCURRENT_NEIGHBOUR_LOOKUPS)

    async def _one(asn: int) -> Tuple[int, ProviderCall]:
        async with gate:
            return asn, await _call_provider(
                "ripe_neighbour_overview",
                lambda: as_overview(client=client, asn=asn),
                scope=SCOPE_ASN,
                indicator=str(asn),
            )

    names: Dict[int, str] = {}
    for asn, call in await asyncio.gather(*(_one(a) for a in asns)):
        if not call.ok:
            continue
        holder = call.data.get("holder")
        if holder:
            names[asn] = holder.split(" - ", 1)[-1] if " - " in holder else holder
    return names


def _asn_call(
    provider: str,
    factory: Callable[[], Awaitable[Dict[str, Any]]],
    asn: int,
) -> Awaitable[ProviderCall]:
    """One ASN-scope provider call. Exists only to keep the ten-way gather below readable."""
    return _call_provider(provider, factory, scope=SCOPE_ASN, indicator=str(asn))


async def investigate_asn(
    asn: int | str,
    *,
    resolve_neighbors: int = 0,
    enrich: bool = False,
    enrich_limit: int = 50,
    deadline: Optional[float] = None,
) -> InvestigationResult:
    """Investigate one ASN across the ten registry, routing and reputation providers.

    ``ok`` follows the contract in the module docstring: ``False`` for a malformed or
    out-of-range ASN, for a deadline breach, and for a run in which no provider answered.
    ``True`` otherwise, with ``data['coverage']`` stating how partial the answer is.
    """
    # Parse once, then check, rather than validate-then-reparse. The old pairing of
    # `is_valid_asn(asn)` with `int(asn)` encoded the assumption that anything the validator
    # accepts is `int()`-parsable, and roadmap 6.4 broke it by making the validator accept
    # "AS15169" -- on which `int()` raises ValueError straight out of this coroutine. The
    # ASN is still validated; the prefix is just normalised off before it is.
    asn_int = normalize_asn(asn)
    if asn_int is None:
        return InvestigationResult(ok=False, errors=["Invalid ASN"], data={})
    return await _with_deadline(
        _investigate_asn(asn_int, resolve_neighbors=resolve_neighbors, enrich=enrich, enrich_limit=enrich_limit),
        target=f"AS{asn_int}",
        deadline=deadline,
    )


async def _investigate_asn(
    asn_int: int, *, resolve_neighbors: int, enrich: bool, enrich_limit: int
) -> InvestigationResult:
    keys = _env_keys()
    async with create_client() as client:
        # One wave. The previous code fully drained IPinfo, RIPEstat overview, abuse contact,
        # CAIDA, PeeringDB and both Cloudflare calls before it even CREATED the routing-status,
        # neighbours and prefixes tasks, which depend on none of them.
        (
            ipi,
            ripe,
            rp_abuse,
            caida,
            pdb,
            rs,
            nb,
            ap,
            cf_bgp,
            cf,
            rdap_call,
        ) = await asyncio.gather(
            _asn_call("ipinfo_asn", lambda: ipinfo_asn(client=client, token=keys.ipinfo_token, asn=asn_int), asn_int),
            _asn_call("ripe_overview", lambda: as_overview(client=client, asn=asn_int), asn_int),
            _asn_call("ripe_abuse", lambda: abuse_contact(client=client, asn=asn_int), asn_int),
            _asn_call("caida", lambda: caida_asrank(client=client, asn=asn_int), asn_int),
            _asn_call("peeringdb", lambda: peeringdb_ixps_for_asn(client=client, asn=asn_int), asn_int),
            _asn_call("ripe_routing_status", lambda: routing_status(client=client, asn=asn_int), asn_int),
            _asn_call("ripe_neighbors", lambda: asn_neighbours(client=client, asn=asn_int), asn_int),
            _asn_call("ripe_prefixes", lambda: announced_prefixes(client=client, asn=asn_int), asn_int),
            _asn_call(
                "cloudflare_bgp",
                lambda: bgp_incidents(client=client, api_token=keys.cloudflare_api_token, asn=asn_int),
                asn_int,
            ),
            _asn_call(
                "cloudflare_asn",
                lambda: fetch_asn_metadata(client=client, api_token=keys.cloudflare_api_token, asn=asn_int),
                asn_int,
            ),
            _call_if_permitted(
                "rdap", lambda: rdap_asn(client=client, asn=asn_int), scope=SCOPE_ASN, indicator=str(asn_int)
            ),
        )

        calls: Dict[str, ProviderCall] = {
            "ipinfo_asn": ipi,
            "ripe_overview": ripe,
            "ripe_abuse": rp_abuse,
            "caida": caida,
            "peeringdb": pdb,
            "ripe_routing_status": rs,
            "ripe_neighbors": nb,
            "ripe_prefixes": ap,
            "cloudflare_bgp": cf_bgp,
            "cloudflare_asn": cf,
            "rdap": rdap_call,
        }
        provider_errors, result_errors = _collect_errors(calls)

        meta: Dict[str, Any] = {}
        # Prefer Cloudflare values when present; fall back to IPinfo
        if cf.ok:
            meta.update(cf.data)
        if ipi.ok:
            # Only set fields that are missing from CF
            for k, v in ipi.data.items():
                if k not in meta or meta.get(k) in (None, ""):
                    meta[k] = v
        if ripe.ok:
            holder = ripe.data.get("holder")
            name = holder
            if name and ("-" in name):
                name = name.split(" - ", 1)[-1]
            if name and (not meta.get("name")):
                meta["name"] = name
            # Country code could be combined into name like asn tool; keep separate
        if rp_abuse.ok:
            contacts = rp_abuse.data.get("abuse_contacts") or []
            if contacts:
                meta["abuseContacts"] = contacts
        if caida.ok:
            for k, v in caida.data.items():
                if k not in meta or meta.get(k) in (None, ""):
                    meta[k] = v
        if pdb.ok:
            ixps = pdb.data.get("ixps") or []
            existing = meta.get("ixps") or []
            existing_names = {i.get("name") for i in existing if isinstance(i, dict) and i.get("name")}
            new_names = {i.get("name") for i in ixps if isinstance(i, dict) and i.get("name")}
            names = sorted(str(n) for n in (existing_names | new_names) if n)
            if names:
                meta["ixps"] = [{"name": n} for n in names]

        # Attach CF BGP incidents summary if available
        meta_bgp: Dict[str, Any] = {}
        if cf_bgp.ok:
            meta_bgp = dict(cf_bgp.data)
        # Add RIPE routing counts
        if rs.ok:
            d = rs.data
            v4p = (d.get("announced_space", {}).get("v4", {}) or {}).get("prefixes")
            v6p = (d.get("announced_space", {}).get("v6", {}) or {}).get("prefixes")
            neigh = d.get("observed_neighbours")
            meta_bgp.update(
                {
                    "ripe_announced_prefixes_v4": v4p,
                    "ripe_announced_prefixes_v6": v6p,
                    "ripe_observed_neighbours": neigh,
                }
            )
        # Add RIPE neighbours lists
        if nb.ok:
            neighs = nb.data.get("neighbours", [])
            upstream = [n.get("asn") for n in neighs if n.get("type") == "left"]
            downstream = [n.get("asn") for n in neighs if n.get("type") == "right"]
            uncertain = [n.get("asn") for n in neighs if n.get("type") == "uncertain"]
            meta_bgp.update(
                {
                    "ripe_upstream_asns": upstream,
                    "ripe_downstream_asns": downstream,
                    "ripe_uncertain_asns": uncertain,
                }
            )
            # Optionally resolve first N neighbor names via RIPE as-overview
            if resolve_neighbors and resolve_neighbors > 0:
                to_resolve: set[int] = set()
                for seq in (
                    upstream[:resolve_neighbors],
                    downstream[:resolve_neighbors],
                    uncertain[:resolve_neighbors],
                ):
                    for a in seq:
                        if isinstance(a, int):
                            to_resolve.add(a)
                # Sorted, not set-ordered: the lookup order was previously whatever the set
                # iterated as, which is stable within a run but not across them.
                name_map = await _resolve_neighbour_names(client=client, asns=sorted(to_resolve))

                def _name_list(lst: list[int]) -> list[str]:
                    out: list[str] = []
                    for a in lst[:resolve_neighbors]:
                        nm = name_map.get(int(a))
                        out.append(f"{nm} ({a})" if nm else str(a))
                    return out

                meta_bgp.update(
                    {
                        "ripe_upstream_named": _name_list(upstream),
                        "ripe_downstream_named": _name_list(downstream),
                        "ripe_uncertain_named": _name_list(uncertain),
                    }
                )
        # Add announced prefixes lists (limited)
        if ap.ok:
            prefs = ap.data.get("prefixes", [])
            v4_list = [
                p.get("prefix") for p in prefs if isinstance(p.get("prefix"), str) and ":" not in p.get("prefix")
            ]
            v6_list = [p.get("prefix") for p in prefs if isinstance(p.get("prefix"), str) and ":" in p.get("prefix")]
            meta_bgp.update(
                {
                    "ripe_prefixes_v4": v4_list,
                    "ripe_prefixes_v6": v6_list,
                }
            )
            # Optional enrichment: placeholder aggregation (fast). Full whois/pWhois can be added later.
            if enrich:
                inetnums = {
                    "v4": v4_list[:enrich_limit],
                    "v6": v6_list[:enrich_limit],
                    "other_v4": [],
                    "other_v6": [],
                }
                meta_bgp.update({"inetnums": inetnums})

        # The per-provider tokens this path has always computed. They stay, unchanged, because
        # the JSON consumers already parse them; the coverage sentences go in front of them so
        # a renderer that shows only the first line shows the load-bearing one.
        provider_warnings: list[str] = []
        if keys.cloudflare_api_token and not cf.ok:
            provider_warnings.append("cloudflare_query_failed_or_missing")
        if not ipi.ok and not ipi.suppressed:
            provider_warnings.append("ipinfo_query_failed_or_missing")
        if not ripe.ok:
            provider_warnings.append("ripestat_overview_failed")
        if not rp_abuse.ok:
            provider_warnings.append("ripestat_abuse_failed")
        if not caida.ok:
            provider_warnings.append("caida_failed")
        if not pdb.ok:
            provider_warnings.append("peeringdb_failed")

        data: Dict[str, Any] = {
            "asn": asn_int,
            "meta": meta,
            "bgp": meta_bgp,
            # Published under its own key rather than merged into ``meta``. The RIR's allocation
            # record and the aggregate the other nine providers build are different claims with
            # different provenance, and ``meta`` already resolves conflicts by precedence -- an
            # RDAP field folded in there would become indistinguishable from an IPinfo one.
            "rdap": rdap_call.data,
            "provider_status": _status_map(calls, scope=SCOPE_ASN, indicator=str(asn_int)),
        }
        if provider_errors:
            data["errors"] = provider_errors

        result = _finalise(
            data,
            target=f"AS{asn_int}",
            run=current_run(),
            errors=result_errors,
            expected=ASN_PROVIDERS,
        )
        # The per-provider tokens are appended after the coverage sentences rather than merged
        # into them, so a renderer showing only the first warning shows the load-bearing one.
        # Reassigned through ``result.data`` rather than the local ``data``: pydantic copies a
        # ``Dict[str, Any]`` field on validation, so the two are no longer the same object.
        result.warnings.extend(provider_warnings)
        result.data["warnings"] = list(result.warnings)
        return result
