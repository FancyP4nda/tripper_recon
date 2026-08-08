"""Unit tests for tripper_recon.providers.peeringdb.

PeeringDB is the one provider queried with no API key at all, and it enforces a real rate
limit on anonymous callers. That makes request *count* a correctness property here, not just
a performance one, so most of these tests assert on ``route.call_count``.

The defect these tests pin down (roadmap 3.10): the ``/net`` search and the N per-net fetches
used to live inside a single retried closure, so a transient failure on the last fetch
replayed the search and every earlier fetch. N+1 requests became up to 2N+2. Each request now
carries its own retry budget and the per-net fetches run concurrently under a bound.

Every request is served by respx; nothing in this module opens a socket.
"""

from __future__ import annotations

import asyncio
from typing import Any, AsyncIterator, Dict, Iterator

import httpx
import pytest
import respx

from tripper_recon.providers import peeringdb as pdb_mod
from tripper_recon.providers.peeringdb import MAX_CONCURRENT_NET_LOOKUPS, peeringdb_ixps_for_asn
from tripper_recon.utils import backoff as backoff_mod

NET_SEARCH_URL = "https://www.peeringdb.com/api/net"
NET_RECORD_RE = r"https://www\.peeringdb\.com/api/net/\d+"


def _net_url(net_id: int) -> str:
    return f"https://www.peeringdb.com/api/net/{net_id}"


def _net_search(*net_ids: int) -> httpx.Response:
    """The ``/net?asn__in=`` response: one record per net id."""
    return httpx.Response(200, json={"data": [{"id": net_id, "asn": 64500} for net_id in net_ids]})


def _net_record(*ix_names: str) -> httpx.Response:
    """The ``/net/{id}`` response carrying a ``netixlan_set``."""
    return httpx.Response(
        200,
        json={"data": [{"id": 1, "netixlan_set": [{"name": name} for name in ix_names]}]},
    )


@pytest.fixture()
async def client() -> AsyncIterator[httpx.AsyncClient]:
    """A plain client. ``create_client`` is not used: HTTP/2 negotiation is not under test."""
    async with httpx.AsyncClient() as c:
        yield c


@pytest.fixture()
def instant_retries(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Make ``with_exponential_backoff`` retry without waiting.

    Note this patches the attribute on the real ``asyncio`` module, so a test using this
    fixture must not depend on ``asyncio.sleep`` actually sleeping.
    """

    async def _no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(backoff_mod.asyncio, "sleep", _no_sleep)
    yield


async def test_returns_sorted_deduped_ixp_names(client: httpx.AsyncClient) -> None:
    """The envelope is ``{"ok": True, "data": {"ixps": [{"name": ...}]}}``, sorted and deduped.

    Two net records naming the same IXP collapse to one entry: an ASN commonly holds several
    net records that overlap at the same exchange.
    """
    async with respx.mock(assert_all_called=False) as router:
        router.get(NET_SEARCH_URL).mock(return_value=_net_search(1, 2))
        router.get(_net_url(1)).mock(return_value=_net_record("DE-CIX Frankfurt", "Equinix Ashburn"))
        router.get(_net_url(2)).mock(return_value=_net_record("Equinix Ashburn", "AMS-IX"))

        result = await peeringdb_ixps_for_asn(client=client, asn=64500)

    assert result == {
        "ok": True,
        "data": {"ixps": [{"name": "AMS-IX"}, {"name": "DE-CIX Frankfurt"}, {"name": "Equinix Ashburn"}]},
    }


async def test_no_net_records_returns_an_empty_ixp_list(client: httpx.AsyncClient) -> None:
    """An ASN PeeringDB has never heard of yields ``ixps: []`` and issues no follow-up request."""
    async with respx.mock(assert_all_called=False) as router:
        search = router.get(NET_SEARCH_URL).mock(return_value=httpx.Response(200, json={"data": []}))
        records = router.route(method="GET", url__regex=NET_RECORD_RE).mock(return_value=_net_record("nope"))

        result = await peeringdb_ixps_for_asn(client=client, asn=64500)

    assert result == {"ok": True, "data": {"ixps": []}}
    assert search.call_count == 1
    assert records.call_count == 0


async def test_http_error_on_the_search_returns_the_error_envelope_without_retrying(
    client: httpx.AsyncClient,
) -> None:
    """A 429 is reported with its status and is NOT retried.

    ``with_exponential_backoff`` only retries on exceptions, and the search returns rather
    than raising on a >=400. Retrying a rate-limit response by hammering it four more times
    is exactly the behaviour this provider must not have (roadmap 3.5 owns the wider policy).
    """
    async with respx.mock(assert_all_called=False) as router:
        search = router.get(NET_SEARCH_URL).mock(return_value=httpx.Response(429, json={"meta": {}}))

        result = await peeringdb_ixps_for_asn(client=client, asn=64500)

    assert result == {"ok": False, "error": "http_error", "status": 429}
    assert search.call_count == 1


async def test_http_error_on_one_net_record_drops_only_that_record(client: httpx.AsyncClient) -> None:
    """A 404 on one net record must not lose the IXPs the other records reported."""
    async with respx.mock(assert_all_called=False) as router:
        router.get(NET_SEARCH_URL).mock(return_value=_net_search(1, 2))
        router.get(_net_url(1)).mock(return_value=httpx.Response(404, json={"meta": {}}))
        router.get(_net_url(2)).mock(return_value=_net_record("LINX LON1"))

        result = await peeringdb_ixps_for_asn(client=client, asn=64500)

    assert result == {"ok": True, "data": {"ixps": [{"name": "LINX LON1"}]}}


async def test_transient_failure_on_one_record_does_not_replay_the_others(
    client: httpx.AsyncClient, instant_retries: None
) -> None:
    """THE regression test for roadmap 3.10.

    Net 3 fails twice and then succeeds. Only net 3 is re-requested: the search and nets 1
    and 2 are each issued exactly once. Under the old single-closure retry the same scenario
    cost three searches and three fetches of every earlier record.
    """
    async with respx.mock(assert_all_called=False) as router:
        search = router.get(NET_SEARCH_URL).mock(return_value=_net_search(1, 2, 3))
        first = router.get(_net_url(1)).mock(return_value=_net_record("AMS-IX"))
        second = router.get(_net_url(2)).mock(return_value=_net_record("DE-CIX Frankfurt"))
        third = router.get(_net_url(3)).mock(
            side_effect=[
                httpx.ConnectError("reset"),
                httpx.ConnectError("reset"),
                _net_record("LINX LON1"),
            ]
        )

        result = await peeringdb_ixps_for_asn(client=client, asn=64500)

    assert result["ok"] is True
    assert result["data"]["ixps"] == [{"name": "AMS-IX"}, {"name": "DE-CIX Frankfurt"}, {"name": "LINX LON1"}]
    assert search.call_count == 1
    assert first.call_count == 1
    assert second.call_count == 1
    assert third.call_count == 3


async def test_exhausted_retries_on_a_record_propagate_without_replaying_the_search(
    client: httpx.AsyncClient, instant_retries: None
) -> None:
    """An exception that survives its own retry budget still escapes to the caller.

    That is the pre-existing contract -- ``orchestrators`` catches it and records
    ``peeringdb_failed`` -- and it is deliberately preserved. Returning ``ixps: []`` here
    would assert "this ASN peers at no exchange", which is a claim the run cannot support.
    What changed is the blast radius: the search and the healthy records are each issued once.
    """
    async with respx.mock(assert_all_called=False) as router:
        search = router.get(NET_SEARCH_URL).mock(return_value=_net_search(1, 2))
        healthy = router.get(_net_url(1)).mock(return_value=_net_record("AMS-IX"))
        doomed = router.get(_net_url(2)).mock(side_effect=httpx.ConnectError("reset"))

        with pytest.raises(httpx.ConnectError):
            await peeringdb_ixps_for_asn(client=client, asn=64500)

    assert search.call_count == 1
    assert healthy.call_count == 1
    # retries=3 in with_exponential_backoff, so four attempts at this one request and no more.
    assert doomed.call_count == 4


async def test_net_records_are_fetched_concurrently_under_a_bound(client: httpx.AsyncClient) -> None:
    """Concurrent, but never unbounded.

    An ASN with many net records must not open a connection per record against a keyless,
    rate-limited provider. The observed peak proves both halves: greater than one means the
    fetches really are concurrent, and no more than the bound means the fan-out is capped.
    """
    net_count = MAX_CONCURRENT_NET_LOOKUPS * 3
    in_flight = 0
    peak = 0

    async def _record(_request: httpx.Request) -> httpx.Response:
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        try:
            await asyncio.sleep(0.01)
            return _net_record("AMS-IX")
        finally:
            in_flight -= 1

    async with respx.mock(assert_all_called=False) as router:
        router.get(NET_SEARCH_URL).mock(return_value=_net_search(*range(1, net_count + 1)))
        records = router.route(method="GET", url__regex=NET_RECORD_RE).mock(side_effect=_record)

        result = await peeringdb_ixps_for_asn(client=client, asn=64500)

    assert result == {"ok": True, "data": {"ixps": [{"name": "AMS-IX"}]}}
    assert records.call_count == net_count
    assert peak > 1, "per-net fetches ran in sequence"
    assert peak <= MAX_CONCURRENT_NET_LOOKUPS, f"fan-out reached {peak}, bound is {MAX_CONCURRENT_NET_LOOKUPS}"


async def test_net_record_without_an_id_is_skipped(client: httpx.AsyncClient) -> None:
    """A record with no usable id costs no request, and does not abort the rest."""
    async with respx.mock(assert_all_called=False) as router:
        router.get(NET_SEARCH_URL).mock(
            return_value=httpx.Response(200, json={"data": [{"asn": 64500}, {"id": 7, "asn": 64500}]})
        )
        records = router.route(method="GET", url__regex=NET_RECORD_RE).mock(return_value=_net_record("AMS-IX"))

        result = await peeringdb_ixps_for_asn(client=client, asn=64500)

    assert result == {"ok": True, "data": {"ixps": [{"name": "AMS-IX"}]}}
    assert records.call_count == 1
    assert records.calls[0].request.url.path == "/api/net/7"


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("empty data array", {"data": []}),
        ("no netixlan_set", {"data": [{"id": 1}]}),
        ("netixlan entry with no name", {"data": [{"id": 1, "netixlan_set": [{"ix_id": 5}]}]}),
    ],
)
async def test_degenerate_net_record_shapes_yield_no_names(
    client: httpx.AsyncClient, label: str, payload: Dict[str, Any]
) -> None:
    """Provider payloads that are well-formed JSON but carry nothing usable."""
    async with respx.mock(assert_all_called=False) as router:
        router.get(NET_SEARCH_URL).mock(return_value=_net_search(1))
        router.get(_net_url(1)).mock(return_value=httpx.Response(200, json=payload))

        result = await peeringdb_ixps_for_asn(client=client, asn=64500)

    assert result == {"ok": True, "data": {"ixps": []}}, label


async def test_search_is_issued_once_per_call(client: httpx.AsyncClient) -> None:
    """Total request count for the happy path is exactly 1 + N.

    Stated as its own assertion because it is the property the whole restructure exists to
    protect, and a future refactor that reintroduces an outer retry would break it here.
    """
    async with respx.mock(assert_all_called=False) as router:
        search = router.get(NET_SEARCH_URL).mock(return_value=_net_search(1, 2, 3))
        records = router.route(method="GET", url__regex=NET_RECORD_RE).mock(return_value=_net_record("AMS-IX"))

        await peeringdb_ixps_for_asn(client=client, asn=64500)

        total_requests = len(router.calls)

    assert search.call_count == 1
    assert records.call_count == 3
    assert total_requests == 4


def test_fan_out_bound_is_a_named_constant() -> None:
    """The bound has to stay inspectable and sane.

    A future edit that raises this to a large number turns one ASN investigation into a burst
    against an unauthenticated provider, so pin the shape of the knob rather than leaving it
    to review.
    """
    assert isinstance(MAX_CONCURRENT_NET_LOOKUPS, int)
    assert 1 < MAX_CONCURRENT_NET_LOOKUPS <= 10
    assert pdb_mod.PDB_BASE == "https://www.peeringdb.com/api"
