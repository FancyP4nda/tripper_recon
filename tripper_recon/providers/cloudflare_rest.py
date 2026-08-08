"""Cloudflare Radar BGP incident counts for one ASN.

Two read-only GET endpoints: BGP hijack events and BGP route-leak events over the past 52
weeks, filtered to one involved ASN. Nothing here touches the ASN's own infrastructure.

The returned envelope keeps two things apart that the previous version conflated:

* ``total_incidents`` is the PROVIDER's count across all pages (``result_info.total_count``).
  Nothing in this module counted it.
* ``as_hijacker`` and ``as_victim`` are COUNTS this module took over event objects it
  actually examined. They are reported only when every incident the provider says exists has
  been examined, and ``as_victim`` only when the events themselves name their victims.

The old code counted hijacker events over a single unpaginated response, subtracted that
from the all-pages total, and called the remainder ``as_victim``. The result corresponded to
nothing, and ``reporting/console.py`` rendered it as the sentence "always as a victim" -- an
attribution claim in an incident report, manufactured from arithmetic over two different
denominators.

So: when the split cannot be substantiated it is omitted and ``split_unavailable_reason``
says why. A renderer must show it as unavailable, must not print a count of ``None`` as if it
were zero, and must never re-derive the victim figure by subtracting ``as_hijacker`` from
``total_incidents`` -- that subtraction is the defect this module exists to remove.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff

CF_BASE = "https://api.cloudflare.com/client/v4/radar"

HIJACKS_URL = f"{CF_BASE}/bgp/hijacks/events"
LEAKS_URL = f"{CF_BASE}/bgp/leaks/events"

# Upper bound on the page walk. The split is only reported over a complete enumeration, and an
# unbounded walk would be both a quota problem and needless egress. Past this limit the counts
# are reported as unavailable rather than estimated.
MAX_EVENT_PAGES = 10

# Keys under which a hijack event may name the ASNs it victimised. Read defensively: if none of
# them is present the victim count is reported as unavailable, never inferred.
VICTIM_ASN_KEYS: Tuple[str, ...] = ("victim_asns", "victim_asn")


def _as_int(value: Any) -> Optional[int]:
    """Return ``value`` when it is a real int. ``bool`` is not an incident count."""
    if isinstance(value, bool):
        return None
    return value if isinstance(value, int) else None


def _json_or_none(response: httpx.Response) -> Optional[Any]:
    try:
        return response.json()
    except ValueError:
        return None


def _result_info(payload: Any) -> Dict[str, Any]:
    if isinstance(payload, dict):
        info = payload.get("result_info")
        if isinstance(info, dict):
            return info
    return {}


def _extract_events(payload: Any) -> List[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    result = payload.get("result")
    if not isinstance(result, dict):
        return []
    events = result.get("events")
    if not isinstance(events, list):
        return []
    return [e for e in events if isinstance(e, dict)]


def _event_key(event: Dict[str, Any]) -> str:
    """Identity for de-duplication across pages.

    De-duplication is load-bearing, not tidiness: if the API ignores the ``page`` parameter and
    replays the first page, counting the replay would re-manufacture exactly the inflated
    figures this module removes. Without a stable ``id`` the whole event body is the key.
    """
    ident = event.get("id")
    if isinstance(ident, (str, int)) and not isinstance(ident, bool):
        return f"id:{ident}"
    try:
        return "body:" + json.dumps(event, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return "body:" + repr(event)


def _victim_asns(event: Dict[str, Any]) -> Optional[List[int]]:
    """ASNs the provider names as victims of this event, or ``None`` when the event is silent.

    An empty list means the provider named no victims, which is an observation. ``None`` means
    the event carries no victim field at all, which is an absence of evidence.
    """
    for key in VICTIM_ASN_KEYS:
        if key not in event:
            continue
        raw = event[key]
        if isinstance(raw, list):
            return [v for v in (_as_int(x) for x in raw) if v is not None]
        single = _as_int(raw)
        if single is not None:
            return [single]
    return None


async def _walk_hijack_events(
    *,
    client: httpx.AsyncClient,
    params: Dict[str, Any],
    headers: Dict[str, str],
    first_payload: Any,
    total_incidents: Optional[int],
) -> Tuple[List[Dict[str, Any]], int, Optional[str]]:
    """Enumerate hijack events across pages.

    Returns ``(events, pages_fetched, stop_reason)``. ``stop_reason`` is ``None`` only when the
    walk reached the provider's own total; every other value names why the enumeration is
    partial, and a partial enumeration cannot support a role split.

    Page one is the caller's already-issued request, sent with the original parameters, so this
    walk never changes the first call. Later pages are best effort: a failure keeps whatever was
    collected and reports the enumeration as incomplete rather than discarding the response.
    """
    per_page = _as_int(_result_info(first_payload).get("per_page"))

    seen: Dict[str, Dict[str, Any]] = {}
    for event in _extract_events(first_payload):
        seen.setdefault(_event_key(event), event)

    pages_fetched = 1
    if total_incidents is None:
        return list(seen.values()), pages_fetched, "total_count_unavailable"
    if len(seen) >= total_incidents:
        return list(seen.values()), pages_fetched, None

    while pages_fetched < MAX_EVENT_PAGES:
        page_params: Dict[str, Any] = dict(params)
        page_params["page"] = pages_fetched + 1
        if per_page is not None:
            page_params["per_page"] = per_page
        try:
            response = await client.get(HIJACKS_URL, params=page_params, headers=headers)
        except httpx.HTTPError:
            return list(seen.values()), pages_fetched, "pagination_request_failed"
        if response.status_code >= 400:
            return list(seen.values()), pages_fetched, "pagination_http_error"
        payload = _json_or_none(response)
        if payload is None:
            return list(seen.values()), pages_fetched, "pagination_response_unparsable"

        pages_fetched += 1
        added = 0
        for event in _extract_events(payload):
            key = _event_key(event)
            if key not in seen:
                seen[key] = event
                added += 1
        if added == 0:
            # Empty page, or the provider ignored `page` and replayed one already counted.
            # Either way the walk cannot make progress and the totals stay unreconciled.
            return list(seen.values()), pages_fetched, "pagination_made_no_progress"
        if len(seen) >= total_incidents:
            return list(seen.values()), pages_fetched, None

    return list(seen.values()), pages_fetched, "pagination_page_limit_reached"


def _summarise_hijacks(
    *,
    asn: int,
    events: List[Dict[str, Any]],
    total_incidents: Optional[int],
    pages_fetched: int,
    stop_reason: Optional[str],
) -> Dict[str, Any]:
    """Build the hijack envelope, reporting only the figures the events actually substantiate."""
    events_examined = len(events)
    counts_complete = total_incidents is not None and events_examined >= total_incidents

    as_hijacker: Optional[int] = None
    as_victim: Optional[int] = None
    reason: Optional[str] = None

    if not counts_complete:
        # A role count over part of the set is not a role count. Report neither.
        reason = stop_reason or "enumeration_incomplete"
    else:
        as_hijacker = sum(1 for e in events if _as_int(e.get("hijacker_asn")) == asn)
        victim_lists = [_victim_asns(e) for e in events]
        if all(v is not None for v in victim_lists):
            as_victim = sum(1 for v in victim_lists if v is not None and asn in v)
        else:
            # The events do not say who was victimised. "Involved but not the hijacker" is not
            # the same claim as "victim", so the victim count stays absent.
            reason = "events_do_not_name_victims"

    return {
        # Provider total across all pages. `None` means the provider did not report one --
        # which is not zero incidents.
        "total_incidents": total_incidents,
        # Counted by this module over the events it examined.
        "events_examined": events_examined,
        "pages_fetched": pages_fetched,
        "counts_complete": counts_complete,
        "as_hijacker": as_hijacker,
        "as_victim": as_victim,
        "split_available": as_hijacker is not None and as_victim is not None,
        "split_unavailable_reason": reason,
    }


async def bgp_incidents(*, client: httpx.AsyncClient, api_token: Optional[str], asn: int) -> Dict[str, Any]:
    if not api_token:
        return {"ok": False, "error": "missing_api_token"}
    headers = {"Authorization": f"Bearer {api_token}"}
    params: Dict[str, Any] = {"dateRange": "52w", "involvedAsn": asn}

    async def _call() -> Dict[str, Any]:
        r1 = await client.get(HIJACKS_URL, params=params, headers=headers)
        r2 = await client.get(LEAKS_URL, params=params, headers=headers)
        if r1.status_code >= 400 and r2.status_code >= 400:
            return {"ok": False, "error": "http_error"}
        out: Dict[str, Any] = {}
        if r1.status_code < 400:
            j1 = _json_or_none(r1)
            total_incidents = _as_int(_result_info(j1).get("total_count"))
            if j1 is None:
                events: List[Dict[str, Any]] = []
                pages_fetched = 1
                stop_reason: Optional[str] = "response_unparsable"
            else:
                events, pages_fetched, stop_reason = await _walk_hijack_events(
                    client=client,
                    params=params,
                    headers=headers,
                    first_payload=j1,
                    total_incidents=total_incidents,
                )
            out["hijacks"] = _summarise_hijacks(
                asn=asn,
                events=events,
                total_incidents=total_incidents,
                pages_fetched=pages_fetched,
                stop_reason=stop_reason,
            )
        if r2.status_code < 400:
            # Route leaks carry no role split: this is the provider's own total, or `None` when
            # it did not report one. `None` is not zero leaks.
            out["leaks"] = {"total_incidents": _as_int(_result_info(_json_or_none(r2)).get("total_count"))}
        return {"ok": True, "data": out}

    return await with_exponential_backoff(_call)
