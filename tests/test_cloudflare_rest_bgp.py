"""Cloudflare Radar BGP incident counts — what the envelope is allowed to assert.

Roadmap item 4.7. The previous implementation counted hijacker events over a single
unpaginated response, subtracted that from the all-pages ``result_info.total_count``, and
labelled the remainder ``as_victim``; ``reporting/console.py`` then rendered the result as the
prose "always as a victim". These tests pin the replacement contract:

* a role split is reported only over a COMPLETE enumeration of the provider's own total;
* ``as_victim`` is reported only when the events name their victims — never by subtraction;
* a missing ``total_count`` stays ``None`` and never collapses into an affirmative zero.

Every request is served by respx. Nothing here opens a socket.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import httpx
import pytest
import respx

from tripper_recon.providers.cloudflare_rest import (
    HIJACKS_URL,
    LEAKS_URL,
    MAX_EVENT_PAGES,
    bgp_incidents,
)

ASN = 64500
OTHER_ASN = 64501


def _event(*, ident: str, hijacker: int, victims: Optional[List[int]]) -> Dict[str, Any]:
    event: Dict[str, Any] = {"id": ident, "hijacker_asn": hijacker}
    if victims is not None:
        event["victim_asns"] = victims
    return event


def _page(
    events: List[Dict[str, Any]], *, total_count: Optional[int], per_page: Optional[int] = None
) -> Dict[str, Any]:
    result_info: Dict[str, Any] = {}
    if total_count is not None:
        result_info["total_count"] = total_count
    if per_page is not None:
        result_info["per_page"] = per_page
    return {"result": {"events": events}, "result_info": result_info}


def _leaks(total_count: Optional[int]) -> Dict[str, Any]:
    return _page([], total_count=total_count)


async def _run() -> Dict[str, Any]:
    async with httpx.AsyncClient() as client:
        return await bgp_incidents(client=client, api_token="token-not-a-real-key", asn=ASN)


@respx.mock
async def test_single_page_complete_counts_both_roles() -> None:
    """One page covering the provider's whole total: both counts are substantiated."""
    events = [
        _event(ident="a", hijacker=ASN, victims=[OTHER_ASN]),
        _event(ident="b", hijacker=OTHER_ASN, victims=[ASN]),
        _event(ident="c", hijacker=OTHER_ASN, victims=[ASN, 64502]),
    ]
    respx.get(HIJACKS_URL).mock(return_value=httpx.Response(200, json=_page(events, total_count=3)))
    respx.get(LEAKS_URL).mock(return_value=httpx.Response(200, json=_leaks(0)))

    hijacks = (await _run())["data"]["hijacks"]

    assert hijacks["total_incidents"] == 3
    assert hijacks["events_examined"] == 3
    assert hijacks["counts_complete"] is True
    assert hijacks["as_hijacker"] == 1
    assert hijacks["as_victim"] == 2
    assert hijacks["split_available"] is True
    assert hijacks["split_unavailable_reason"] is None


@respx.mock
async def test_pagination_counts_over_the_full_set() -> None:
    """The counts come from every page, not from page one against an all-pages total."""
    page_one = [_event(ident=f"p1-{i}", hijacker=ASN, victims=[OTHER_ASN]) for i in range(2)]
    page_two = [_event(ident=f"p2-{i}", hijacker=OTHER_ASN, victims=[ASN]) for i in range(2)]
    pages = {1: page_one, 2: page_two}
    requested: List[int] = []

    def _serve(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params.get("page", 1))
        requested.append(page)
        return httpx.Response(200, json=_page(pages.get(page, []), total_count=4, per_page=2))

    respx.get(HIJACKS_URL).mock(side_effect=_serve)
    respx.get(LEAKS_URL).mock(return_value=httpx.Response(200, json=_leaks(1)))

    hijacks = (await _run())["data"]["hijacks"]

    assert requested == [1, 2], "page one must keep the original parameters; page two follows result_info"
    assert hijacks["pages_fetched"] == 2
    assert hijacks["events_examined"] == 4
    assert hijacks["counts_complete"] is True
    assert hijacks["as_hijacker"] == 2
    assert hijacks["as_victim"] == 2
    assert hijacks["split_available"] is True


@respx.mock
async def test_provider_ignoring_page_parameter_yields_no_split() -> None:
    """A replayed page must not be counted twice and must not produce a split.

    This is the failure the old arithmetic hid: page one held no event where this ASN was the
    hijacker, so the report asserted "always as a victim" for an ASN that may be the hijacker in
    every incident the walk never saw.
    """
    page_one = [_event(ident="only", hijacker=OTHER_ASN, victims=[ASN])]
    respx.get(HIJACKS_URL).mock(return_value=httpx.Response(200, json=_page(page_one, total_count=100)))
    respx.get(LEAKS_URL).mock(return_value=httpx.Response(200, json=_leaks(0)))

    hijacks = (await _run())["data"]["hijacks"]

    assert hijacks["total_incidents"] == 100
    assert hijacks["events_examined"] == 1, "the replayed page is de-duplicated, not re-counted"
    assert hijacks["counts_complete"] is False
    assert hijacks["as_hijacker"] is None
    assert hijacks["as_victim"] is None
    assert hijacks["split_available"] is False
    assert hijacks["split_unavailable_reason"] == "pagination_made_no_progress"


@respx.mock
async def test_page_walk_is_bounded() -> None:
    """The walk stops at MAX_EVENT_PAGES and reports the enumeration as partial."""
    counter = {"n": 0}

    def _serve(request: httpx.Request) -> httpx.Response:
        counter["n"] += 1
        event = _event(ident=f"e-{counter['n']}", hijacker=ASN, victims=[OTHER_ASN])
        return httpx.Response(200, json=_page([event], total_count=10_000, per_page=1))

    respx.get(HIJACKS_URL).mock(side_effect=_serve)
    respx.get(LEAKS_URL).mock(return_value=httpx.Response(200, json=_leaks(0)))

    hijacks = (await _run())["data"]["hijacks"]

    assert counter["n"] == MAX_EVENT_PAGES
    assert hijacks["pages_fetched"] == MAX_EVENT_PAGES
    assert hijacks["counts_complete"] is False
    assert hijacks["as_hijacker"] is None
    assert hijacks["split_unavailable_reason"] == "pagination_page_limit_reached"


@respx.mock
async def test_pagination_http_error_keeps_page_one_and_reports_partial() -> None:
    """A failed later page degrades the claim; it does not discard the response or raise."""

    def _serve(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("page") is None:
            events = [_event(ident="p1", hijacker=ASN, victims=[OTHER_ASN])]
            return httpx.Response(200, json=_page(events, total_count=5, per_page=1))
        return httpx.Response(500, json={"errors": ["boom"]})

    respx.get(HIJACKS_URL).mock(side_effect=_serve)
    respx.get(LEAKS_URL).mock(return_value=httpx.Response(200, json=_leaks(2)))

    hijacks = (await _run())["data"]["hijacks"]

    assert hijacks["events_examined"] == 1
    assert hijacks["counts_complete"] is False
    assert hijacks["as_hijacker"] is None
    assert hijacks["as_victim"] is None
    assert hijacks["split_unavailable_reason"] == "pagination_http_error"


@respx.mock
async def test_events_without_victim_fields_report_hijacker_only() -> None:
    """A complete enumeration substantiates the hijacker count; victims stay unavailable.

    "Involved but not the hijacker" is not the same claim as "victim", so no victim figure is
    derived from the complement.
    """
    events = [
        _event(ident="a", hijacker=ASN, victims=None),
        _event(ident="b", hijacker=OTHER_ASN, victims=None),
    ]
    respx.get(HIJACKS_URL).mock(return_value=httpx.Response(200, json=_page(events, total_count=2)))
    respx.get(LEAKS_URL).mock(return_value=httpx.Response(200, json=_leaks(0)))

    hijacks = (await _run())["data"]["hijacks"]

    assert hijacks["counts_complete"] is True
    assert hijacks["as_hijacker"] == 1
    assert hijacks["as_victim"] is None
    assert hijacks["split_available"] is False
    assert hijacks["split_unavailable_reason"] == "events_do_not_name_victims"


@respx.mock
async def test_missing_total_count_is_none_not_zero() -> None:
    """An absent total stays absent. Rendering it as 0 would assert "no incidents"."""
    events = [_event(ident="a", hijacker=OTHER_ASN, victims=[ASN])]
    respx.get(HIJACKS_URL).mock(return_value=httpx.Response(200, json=_page(events, total_count=None)))
    respx.get(LEAKS_URL).mock(return_value=httpx.Response(200, json=_leaks(None)))

    data = (await _run())["data"]

    assert data["hijacks"]["total_incidents"] is None
    assert data["hijacks"]["events_examined"] == 1
    assert data["hijacks"]["counts_complete"] is False
    assert data["hijacks"]["split_unavailable_reason"] == "total_count_unavailable"
    assert data["leaks"]["total_incidents"] is None


@respx.mock
async def test_zero_incidents_is_a_counted_zero() -> None:
    """A genuine zero is reported as zero, with the split available and empty."""
    respx.get(HIJACKS_URL).mock(return_value=httpx.Response(200, json=_page([], total_count=0)))
    respx.get(LEAKS_URL).mock(return_value=httpx.Response(200, json=_leaks(0)))

    hijacks = (await _run())["data"]["hijacks"]

    assert hijacks["total_incidents"] == 0
    assert hijacks["counts_complete"] is True
    assert hijacks["as_hijacker"] == 0
    assert hijacks["as_victim"] == 0
    assert hijacks["split_available"] is True


@respx.mock
async def test_unparsable_hijack_body_does_not_fabricate_counts() -> None:
    """A 200 with a non-JSON body yields an empty, explicitly incomplete envelope."""
    respx.get(HIJACKS_URL).mock(return_value=httpx.Response(200, content=b"<html>not json</html>"))
    respx.get(LEAKS_URL).mock(return_value=httpx.Response(200, json=_leaks(3)))

    data = (await _run())["data"]

    assert data["hijacks"]["total_incidents"] is None
    assert data["hijacks"]["events_examined"] == 0
    assert data["hijacks"]["as_hijacker"] is None
    assert data["hijacks"]["split_unavailable_reason"] == "response_unparsable"
    assert data["leaks"]["total_incidents"] == 3


@respx.mock
async def test_hijacks_error_leaves_only_leaks() -> None:
    """One endpoint failing does not invent a hijack envelope for the other."""
    respx.get(HIJACKS_URL).mock(return_value=httpx.Response(403, json={"errors": ["nope"]}))
    respx.get(LEAKS_URL).mock(return_value=httpx.Response(200, json=_leaks(4)))

    result = await _run()

    assert result["ok"] is True
    assert "hijacks" not in result["data"]
    assert result["data"]["leaks"]["total_incidents"] == 4


@respx.mock
async def test_both_endpoints_failing_is_an_error_envelope() -> None:
    respx.get(HIJACKS_URL).mock(return_value=httpx.Response(500, json={"errors": ["boom"]}))
    respx.get(LEAKS_URL).mock(return_value=httpx.Response(500, json={"errors": ["boom"]}))

    result = await _run()

    assert result == {"ok": False, "error": "http_error"}


@respx.mock
async def test_missing_token_makes_no_request() -> None:
    async with httpx.AsyncClient() as client:
        result = await bgp_incidents(client=client, api_token=None, asn=ASN)

    assert result == {"ok": False, "error": "missing_api_token"}
    assert respx.calls.call_count == 0


@respx.mock
async def test_events_without_ids_are_deduplicated_by_body() -> None:
    """Replayed pages of id-less events must not inflate the examined count."""
    event = {"hijacker_asn": OTHER_ASN, "victim_asns": [ASN]}
    respx.get(HIJACKS_URL).mock(return_value=httpx.Response(200, json=_page([event, dict(event)], total_count=50)))
    respx.get(LEAKS_URL).mock(return_value=httpx.Response(200, json=_leaks(0)))

    hijacks = (await _run())["data"]["hijacks"]

    assert hijacks["events_examined"] == 1
    assert hijacks["counts_complete"] is False
    assert hijacks["as_victim"] is None


@pytest.mark.parametrize("bad_total", ["12", True, None, 3.5])
@respx.mock
async def test_non_integer_total_count_is_rejected(bad_total: Any) -> None:
    """A string or bool total is not an incident count and must not become one."""
    payload = {"result": {"events": []}, "result_info": {"total_count": bad_total}}
    respx.get(HIJACKS_URL).mock(return_value=httpx.Response(200, content=json.dumps(payload).encode()))
    respx.get(LEAKS_URL).mock(return_value=httpx.Response(200, json=_leaks(0)))

    hijacks = (await _run())["data"]["hijacks"]

    assert hijacks["total_incidents"] is None
    assert hijacks["counts_complete"] is False
    assert hijacks["as_hijacker"] is None
