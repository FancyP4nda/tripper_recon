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
"""

from __future__ import annotations

import asyncio
import os
import time
from ipaddress import ip_address
from typing import Any, Awaitable, Coroutine, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple

import httpx

from tripper_recon.providers.abuseipdb import abuseipdb_check
from tripper_recon.providers.caida import caida_asrank
from tripper_recon.providers.cloudflare_radar import fetch_asn_metadata
from tripper_recon.providers.cloudflare_rest import bgp_incidents
from tripper_recon.providers.ipinfo import ipinfo_asn, ipinfo_ip
from tripper_recon.providers.otx import otx_domain_pulses, otx_ip_pulses
from tripper_recon.providers.peeringdb import peeringdb_ixps_for_asn
from tripper_recon.providers.ripestat import (
    abuse_contact,
    announced_prefixes,
    as_overview,
    asn_neighbours,
    routing_status,
)
from tripper_recon.providers.shodan_api import shodan_host
from tripper_recon.providers.virustotal import vt_domain_summary, vt_ip_summary
from tripper_recon.types.models import ApiKeys, InvestigationResult, ProviderCall, ProviderOutcome
from tripper_recon.utils.http import PassiveBoundaryViolation, create_client, rate_limited
from tripper_recon.utils.logging import logger
from tripper_recon.utils.redact import redact_text, redact_url
from tripper_recon.utils.validation import dedupe_preserve_order, is_valid_asn, is_valid_domain, is_valid_ip

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

#: Provider error values that mean "no credential, so nothing was asked". Shared by
#: :func:`_should_suppress` and the envelope builder so the two cannot disagree about which
#: failures are configuration rather than incidents.
NOT_CONFIGURED_ERRORS: FrozenSet[str] = frozenset(
    {"missing_api_key", "missing_api_token", "missing_token", "API key not configured"}
)


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


# --------------------------------------------------------------------------------------
# The one provider call helper
# --------------------------------------------------------------------------------------


def _envelope(provider: str, payload: Dict[str, Any], elapsed: float) -> ProviderCall:
    """Wrap one provider payload, preserving the ok/error/not-configured distinction."""
    if payload.get("ok"):
        data = payload.get("data")
        return ProviderCall(
            provider=provider,
            outcome=ProviderOutcome.OK,
            elapsed_seconds=elapsed,
            data=data if isinstance(data, dict) else {},
        )

    err = payload.get("error")
    outcome = (
        ProviderOutcome.NOT_CONFIGURED
        if isinstance(err, str) and err in NOT_CONFIGURED_ERRORS
        else ProviderOutcome.ERROR
    )
    return ProviderCall(
        provider=provider,
        outcome=outcome,
        elapsed_seconds=elapsed,
        error=_error_details(payload),
        summary=_error_summary(provider, payload),
        suppressed=_should_suppress(provider, payload),
    )


async def _call_provider(provider: str, call: Awaitable[Dict[str, Any]]) -> ProviderCall:
    """Await one provider under the concurrency limiter and wrap whatever comes back.

    This is the only place in the package that awaits a provider. Everything it guarantees --
    the limiter actually bounding in-flight requests, the elapsed time being recorded, a raised
    exception being redacted rather than escaping -- holds for every provider because there is
    no second code path.

    The bare ``except Exception`` is deliberate and is the reason this function exists: one
    provider raising must not take the other four down with it. Two things are NOT absorbed:

    * ``BaseException``, so a deadline cancellation reaches :func:`_with_deadline` rather than
      being filed as a provider failure.
    * :class:`PassiveBoundaryViolation`, because it means this tool tried to contact a host
      nobody approved -- most plausibly the target itself. Recording that as one more line in
      an error list would turn the loudest signal the codebase has into routine noise. It is a
      defect in the tool, and it is meant to stop the run.
    """
    started = time.monotonic()
    try:
        async with rate_limited():
            payload = await call
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


def _status_map(calls: Mapping[str, ProviderCall]) -> Dict[str, Dict[str, Any]]:
    """Per-provider outcome, cost and error, for every provider that was considered.

    This is the record that stops absence from reading as safety. ``data['virustotal'] == {}``
    is ambiguous; ``provider_status['virustotal']['outcome'] == 'not_configured'`` is not.
    """
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
        status[key] = entry
    return status


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


async def _ip_provider_wave(*, client: httpx.AsyncClient, keys: ApiKeys, ip: str) -> Dict[str, ProviderCall]:
    """The five per-IP providers, in one wave."""
    virustotal, ipinfo, shodan, abuseipdb, otx = await asyncio.gather(
        _call_provider("virustotal", vt_ip_summary(client=client, api_key=keys.vt_api_key, ip=ip)),
        _call_provider("ipinfo", ipinfo_ip(client=client, token=keys.ipinfo_token, ip=ip)),
        _call_provider("shodan", shodan_host(client=client, api_key=keys.shodan_api_key, ip=ip)),
        _call_provider("abuseipdb", abuseipdb_check(client=client, api_key=keys.abuseipdb_api_key, ip=ip)),
        _call_provider("otx", otx_ip_pulses(client=client, api_key=keys.otx_api_key, ip=ip)),
    )
    return {
        "virustotal": virustotal,
        "ipinfo": ipinfo,
        "shodan": shodan,
        "abuseipdb": abuseipdb,
        "otx": otx,
    }


async def _asn_meta_for_ip(
    *, client: httpx.AsyncClient, keys: ApiKeys, ipinfo: ProviderCall
) -> Tuple[Dict[str, Any], Optional[ProviderCall]]:
    """Cloudflare Radar metadata for the ASN IPinfo reported, when it reported one.

    Second wave by necessity, not by oversight: the ASN is not known until IPinfo answers.
    """
    if not ipinfo.ok:
        return {}, None
    raw_asn = ipinfo.data.get("asn")
    if not raw_asn:
        return {}, None
    try:
        asn = int(raw_asn)
    except (TypeError, ValueError):
        return {}, None

    call = await _call_provider(
        "cloudflare_asn", fetch_asn_metadata(client=client, api_token=keys.cloudflare_api_token, asn=asn)
    )
    return (call.data if call.ok else {}), call


def _ip_entry(ip: str, calls: Mapping[str, ProviderCall], asn_meta: Dict[str, Any]) -> Dict[str, Any]:
    """The per-IP analysis dict ``reporting.console.render_ip_analysis`` consumes."""
    return {
        "ip": ip,
        "ptr": None,
        "virustotal": calls["virustotal"].data,
        "shodan": calls["shodan"].data,
        "ipinfo": calls["ipinfo"].data,
        "abuseipdb": calls["abuseipdb"].data,
        "otx": calls["otx"].data,
        "asn_meta": asn_meta,
        "provider_status": _status_map(calls),
    }


# --------------------------------------------------------------------------------------
# IP
# --------------------------------------------------------------------------------------


async def investigate_ip(ip: str, *, deadline: Optional[float] = None) -> InvestigationResult:
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
        asn_meta, cloudflare = await _asn_meta_for_ip(client=client, keys=keys, ipinfo=calls["ipinfo"])
        if cloudflare is not None:
            calls["cloudflare_asn"] = cloudflare

        provider_errors, result_errors = _collect_errors(calls)

        data: Dict[str, Any] = {
            "ipinfo": calls["ipinfo"].data,
            "virustotal": calls["virustotal"].data,
            "shodan": calls["shodan"].data,
            "abuseipdb": calls["abuseipdb"].data,
            "otx": calls["otx"].data,
            "asn_meta": asn_meta,
            "provider_status": _status_map(calls),
        }
        if provider_errors:
            data["errors"] = provider_errors

        return InvestigationResult(ok=True, data=data, errors=result_errors)


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
    asn_meta, cloudflare = await _asn_meta_for_ip(client=client, keys=keys, ipinfo=calls["ipinfo"])
    if cloudflare is not None:
        calls["cloudflare_asn"] = cloudflare

    provider_errors, messages = _collect_errors(calls, prefix=f"{ip} :: ")

    entry = _ip_entry(ip, calls, asn_meta)
    entry["source"] = source
    if provider_errors:
        entry["errors"] = provider_errors
    return entry, messages


async def investigate_domain(domain: str, *, deadline: Optional[float] = None) -> InvestigationResult:
    if not is_valid_domain(domain):
        return InvestigationResult(ok=False, errors=["Invalid domain"], data={})
    return await _with_deadline(_investigate_domain(domain), target=domain, deadline=deadline)


async def _investigate_domain(domain: str) -> InvestigationResult:
    keys = _env_keys()
    result_errors: List[str] = []
    warnings: List[str] = []
    domain_intel: Dict[str, Any] = {}
    domain_errors: Dict[str, Dict[str, Any]] = {}

    async with create_client() as client:
        vt_domain, otx_domain = await asyncio.gather(
            _call_provider(
                "virustotal_domain", vt_domain_summary(client=client, api_key=keys.vt_api_key, domain=domain)
            ),
            _call_provider("otx_domain", otx_domain_pulses(client=client, api_key=keys.otx_api_key, domain=domain)),
        )

        passive_ips: List[str] = []
        if vt_domain.ok:
            domain_intel["virustotal"] = vt_domain.data
            passive_ips = _passive_ips_from_vt(vt_domain.data)
        if otx_domain.ok:
            domain_intel["otx"] = otx_domain.data

        domain_calls = {"virustotal": vt_domain, "otx": otx_domain}
        domain_errors, domain_error_msgs = _collect_errors(domain_calls)

        # utils.dns is the one sanctioned resolution site (docs/OPSEC.md section 3); the import
        # stays local so tests/test_passivity.py keeps seeing exactly one resolver module.
        from tripper_recon.utils.dns import resolve_domain

        active_ips = await resolve_domain(domain)

        enrichable: List[Tuple[str, str]] = []
        skipped: List[Dict[str, str]] = []
        for ip, source in _tag_ip_sources(active_ips, passive_ips):
            reason = non_public_ip_reason(ip)
            if reason is None:
                enrichable.append((ip, source))
                continue
            skipped.append({"ip": ip, "source": source, "reason": reason.lower()})
            warnings.append(f"{ip} ({source}) skipped: {reason.lower()} addressing is never sent to a provider")

        gate = asyncio.Semaphore(MAX_CONCURRENT_IPS)

        async def _bounded(ip: str, source: str) -> Tuple[Dict[str, Any], List[str]]:
            async with gate:
                return await _enrich_domain_ip(client=client, keys=keys, ip=ip, source=source)

        enriched = await asyncio.gather(*(_bounded(ip, source) for ip, source in enrichable))

    out: List[Dict[str, Any]] = []
    for entry, messages in enriched:
        out.append(entry)
        result_errors.extend(messages)
    result_errors.extend(domain_error_msgs)

    data: Dict[str, Any] = {
        "domain": domain,
        "ips": out,
        "domain_provider_status": _status_map(domain_calls),
    }
    if domain_intel:
        data["domain_intel"] = domain_intel
    if domain_errors:
        data["domain_errors"] = domain_errors
    if skipped:
        data["skipped_ips"] = skipped

    return InvestigationResult(ok=True, data=data, warnings=warnings, errors=result_errors)


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
            return asn, await _call_provider("ripe_neighbour_overview", as_overview(client=client, asn=asn))

    names: Dict[int, str] = {}
    for asn, call in await asyncio.gather(*(_one(a) for a in asns)):
        if not call.ok:
            continue
        holder = call.data.get("holder")
        if holder:
            names[asn] = holder.split(" - ", 1)[-1] if " - " in holder else holder
    return names


async def investigate_asn(
    asn: int | str,
    *,
    resolve_neighbors: int = 0,
    enrich: bool = False,
    enrich_limit: int = 50,
    deadline: Optional[float] = None,
) -> InvestigationResult:
    if not is_valid_asn(asn):
        return InvestigationResult(ok=False, errors=["Invalid ASN"], data={})
    asn_int = int(asn)
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
        ) = await asyncio.gather(
            _call_provider("ipinfo_asn", ipinfo_asn(client=client, token=keys.ipinfo_token, asn=asn_int)),
            _call_provider("ripe_overview", as_overview(client=client, asn=asn_int)),
            _call_provider("ripe_abuse", abuse_contact(client=client, asn=asn_int)),
            _call_provider("caida", caida_asrank(client=client, asn=asn_int)),
            _call_provider("peeringdb", peeringdb_ixps_for_asn(client=client, asn=asn_int)),
            _call_provider("ripe_routing_status", routing_status(client=client, asn=asn_int)),
            _call_provider("ripe_neighbors", asn_neighbours(client=client, asn=asn_int)),
            _call_provider("ripe_prefixes", announced_prefixes(client=client, asn=asn_int)),
            _call_provider(
                "cloudflare_bgp",
                bgp_incidents(client=client, api_token=keys.cloudflare_api_token, asn=asn_int),
            ),
            _call_provider(
                "cloudflare_asn",
                fetch_asn_metadata(client=client, api_token=keys.cloudflare_api_token, asn=asn_int),
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

        warnings: list[str] = []
        if keys.cloudflare_api_token and not cf.ok:
            warnings.append("cloudflare_query_failed_or_missing")
        if not ipi.ok and not ipi.suppressed:
            warnings.append("ipinfo_query_failed_or_missing")
        if not ripe.ok:
            warnings.append("ripestat_overview_failed")
        if not rp_abuse.ok:
            warnings.append("ripestat_abuse_failed")
        if not caida.ok:
            warnings.append("caida_failed")
        if not pdb.ok:
            warnings.append("peeringdb_failed")

        data: Dict[str, Any] = {
            "asn": asn_int,
            "meta": meta,
            "bgp": meta_bgp,
            "provider_status": _status_map(calls),
        }
        if provider_errors:
            data["errors"] = provider_errors

        return InvestigationResult(ok=True, data=data, warnings=warnings, errors=result_errors)
