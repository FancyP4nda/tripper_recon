"""Unit tests for tripper_recon.providers.internetdb (roadmap 8.1).

Three properties carry the weight here, and each has its own section below.

1. **A 404 is UNKNOWN, never clean.** InternetDB answers 404 for most of the address space. If
   that ever becomes ``ok: True`` with an empty port list, the tool starts telling analysts "we
   looked and found nothing exposed" about hosts it knows nothing about. That is the single most
   damaging thing this module could do, so it is asserted from both directions: the envelope is
   an error, and the envelope is *not* a success carrying empty lists.

2. **It is a fallback, not a replacement.** The paid provider on ``api.shodan.io`` returns strictly
   more -- per-service banners, the network owner, and the observation date. The tests pin the
   host apart, pin the absence of ``org`` and ``last_update`` rather than letting them appear as
   ``None``, and pin the shared key names so a consumer written against the paid provider reads
   this one unchanged. A future "unification" fails here.

3. **Keyless means the egress IP is the identifier and a 429 is terminal.** There is no
   ``api_key`` parameter and no ``missing_api_key`` path; there is a rate limit, breached against
   the whole connection. A 429 must cost exactly one request, because the ban is already in force
   by the time it is read.

Every request is served by respx; nothing in this module opens a socket, and no credential is
read from the environment -- ``conftest.clear_provider_env`` guarantees the second part.
"""

from __future__ import annotations

import inspect
from typing import Any, AsyncIterator, Dict, Iterator, List

import httpx
import pytest
import respx

from tripper_recon.providers import internetdb as idb_mod
from tripper_recon.providers import shodan_api as paid_mod
from tripper_recon.providers.internetdb import INTERNETDB_BASE, INTERNETDB_SOURCE, internetdb_host
from tripper_recon.utils import backoff as backoff_mod

IP = "203.0.113.10"
IPV6 = "2001:db8::1"
IDB_URL = f"{INTERNETDB_BASE}/{IP}"

#: The full documented response: the six top-level fields InternetDB returns.
FULL_PAYLOAD: Dict[str, Any] = {
    "ip": IP,
    "ports": [443, 22, 80],
    "hostnames": ["b.example.invalid", "a.example.invalid"],
    "cpes": ["cpe:/a:openbsd:openssh:8.4", "cpe:/a:nginx:nginx"],
    "tags": ["self-signed", "starttls"],
    "vulns": ["CVE-2021-44228", "CVE-2014-0160"],
}


@pytest.fixture()
async def client() -> AsyncIterator[httpx.AsyncClient]:
    """A plain client. ``create_client`` is not used: transport behaviour is not under test."""
    async with httpx.AsyncClient() as c:
        yield c


@pytest.fixture()
def instant_retries(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Make ``with_exponential_backoff`` retry without waiting."""

    async def _no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(backoff_mod.asyncio, "sleep", _no_sleep)
    yield


# --------------------------------------------------------------------------------------
# 1. Extraction
# --------------------------------------------------------------------------------------


async def test_full_payload_is_extracted_sorted_and_deduped(client: httpx.AsyncClient) -> None:
    """The whole envelope, spelled out, so a change to any key name fails here.

    Sorting is a correctness property, not cosmetics: two runs against the same host must diff
    cleanly, and Shodan does not promise an order.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get(IDB_URL).mock(return_value=httpx.Response(200, json=FULL_PAYLOAD))
        result = await internetdb_host(client=client, ip=IP)

    assert result == {
        "ok": True,
        "data": {
            "ports": [22, 80, 443],
            "hostnames": ["a.example.invalid", "b.example.invalid"],
            "cpe": ["cpe:/a:nginx:nginx", "cpe:/a:openbsd:openssh:8.4"],
            "tags": ["self-signed", "starttls"],
            "vulns": ["CVE-2014-0160", "CVE-2021-44228"],
            "ip": IP,
            "source": INTERNETDB_SOURCE,
        },
    }


async def test_cves_survive_which_is_the_capability_this_adds(client: httpx.AsyncClient) -> None:
    """``vulns`` is the reason 8.1 is worth more than a fallback.

    Stated as its own test because it is the field most likely to be dropped by someone
    trimming the payload: it is the one an incident report is actually written from.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get(IDB_URL).mock(
            return_value=httpx.Response(200, json={"ip": IP, "vulns": ["CVE-2023-1234", "CVE-2023-1234"]})
        )
        result = await internetdb_host(client=client, ip=IP)

    assert result["ok"] is True
    assert result["data"]["vulns"] == ["CVE-2023-1234"]


async def test_the_request_is_a_bare_get_with_no_query_string(client: httpx.AsyncClient) -> None:
    """Keyless is observable on the wire: one GET, path ``/<ip>``, nothing in the query.

    The paid sibling authenticates in the query string, which is why ``utils/redact`` exists. If
    a future edit starts appending a key here, this fails -- and so does the assumption that this
    provider's requests are safe to log verbatim.
    """
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(IDB_URL).mock(return_value=httpx.Response(200, json={"ip": IP}))
        await internetdb_host(client=client, ip=IP)

    assert route.call_count == 1
    request = route.calls[0].request
    assert request.method == "GET"
    assert request.url.path == f"/{IP}"
    assert request.url.query == b""


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("every field missing", {}),
        ("fields present but null", {"ports": None, "hostnames": None, "cpes": None, "tags": None, "vulns": None}),
        ("fields are objects, not arrays", {"ports": {"22": True}, "vulns": {"CVE-2021-1": {}}}),
        ("arrays carry the wrong item types", {"ports": ["22", None], "vulns": [1, None], "hostnames": [{"a": 1}]}),
        ("strings are blank or whitespace", {"hostnames": ["", "   "], "tags": [""], "cpes": ["  "]}),
        ("booleans in the port array", {"ports": [True, False, 22]}),
    ],
)
async def test_degenerate_payload_shapes_yield_empty_lists_not_a_traceback(
    client: httpx.AsyncClient, label: str, payload: Dict[str, Any]
) -> None:
    """A provider that changes a field's shape must degrade to absence, never to an exception.

    The boolean case is not hypothetical padding: ``bool`` is an ``int`` subclass, so a stray
    ``true`` in the port array becomes port 1 under any naive ``isinstance(item, int)`` filter.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get(IDB_URL).mock(return_value=httpx.Response(200, json=payload))
        result = await internetdb_host(client=client, ip=IP)

    assert result["ok"] is True, label
    data = result["data"]
    assert data["ports"] == ([22] if label == "booleans in the port array" else []), label
    assert data["hostnames"] == [], label
    assert data["cpe"] == [], label
    assert data["tags"] == [], label
    assert data["vulns"] == [], label


async def test_a_non_object_body_is_treated_as_an_empty_record(client: httpx.AsyncClient) -> None:
    """A 200 carrying a JSON array or a bare string still returns a well-formed envelope."""
    async with respx.mock(assert_all_called=True) as router:
        router.get(IDB_URL).mock(return_value=httpx.Response(200, json=["not", "an", "object"]))
        result = await internetdb_host(client=client, ip=IP)

    assert result["ok"] is True
    assert result["data"]["ports"] == []
    assert result["data"]["ip"] is None


async def test_the_echoed_ip_comes_from_the_response_not_the_request(client: httpx.AsyncClient) -> None:
    """A record describing a different address must be visible, not silently relabelled."""
    async with respx.mock(assert_all_called=True) as router:
        router.get(IDB_URL).mock(return_value=httpx.Response(200, json={"ip": "198.51.100.7", "ports": [80]}))
        result = await internetdb_host(client=client, ip=IP)

    assert result["data"]["ip"] == "198.51.100.7"


async def test_an_ipv6_address_is_queried_rather_than_refused(client: httpx.AsyncClient) -> None:
    """Shodan's published examples are IPv4 and v6 coverage is not documented either way.

    Refusing v6 here would assert a limit the documentation does not state. It is passed through;
    if InternetDB holds no v6 records the answer is a 404, which this module already reports as
    unknown rather than clean.
    """
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(f"{INTERNETDB_BASE}/{IPV6}").mock(return_value=httpx.Response(200, json={"ip": IPV6}))
        result = await internetdb_host(client=client, ip=IPV6)

    assert result["ok"] is True
    assert route.call_count == 1


# --------------------------------------------------------------------------------------
# 2. A 404 is UNKNOWN, never clean
# --------------------------------------------------------------------------------------


async def test_404_is_a_distinct_not_found_error_costing_one_request(client: httpx.AsyncClient) -> None:
    """InternetDB holds no record. That is an error envelope and it is not retried."""
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(IDB_URL).mock(return_value=httpx.Response(404, json={"detail": "No information available"}))
        result = await internetdb_host(client=client, ip=IP)

    assert result == {"ok": False, "error": "not_found"}
    assert route.call_count == 1


async def test_404_never_renders_as_an_empty_but_successful_result(client: httpx.AsyncClient) -> None:
    """THE regression test for the failure mode this provider could most easily introduce.

    ``{"ok": True, "data": {"ports": []}}`` and "no record exists" are the same JSON to a
    renderer and opposite claims to an analyst. The first says the host was checked and nothing
    is exposed; the second says nobody knows. Asserted negatively so that a well-meaning future
    edit -- "a 404 just means no services, let's return an empty list" -- fails loudly.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get(IDB_URL).mock(return_value=httpx.Response(404, json={"detail": "No information available"}))
        result = await internetdb_host(client=client, ip=IP)

    assert result["ok"] is False
    assert "data" not in result
    assert result["error"] == "not_found"


# --------------------------------------------------------------------------------------
# 3. Keyless: no credential path, and a terminal 429
# --------------------------------------------------------------------------------------


def test_there_is_no_api_key_parameter_and_no_missing_key_path() -> None:
    """Keyless is part of the contract, not an implementation detail.

    An ``api_key`` parameter appearing here would mean the fallback had quietly acquired the
    precondition it exists to remove. ``missing_api_key`` is checked in the source because it is
    the slug the orchestrator maps to "not configured", which is what suppresses the paid path
    today.
    """
    parameters = inspect.signature(internetdb_host).parameters
    assert set(parameters) == {"client", "ip"}
    assert all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in parameters.values())

    source = inspect.getsource(idb_mod)
    assert '"missing_api_key"' not in source
    assert "os.environ" not in source and "getenv" not in source


async def test_429_is_terminal_and_costs_exactly_one_request(client: httpx.AsyncClient) -> None:
    """The ban is IP-scoped and already in force by the time the 429 is read.

    ``with_exponential_backoff`` would otherwise retry a 429 three more times. Against a keyless
    provider that throttles the whole egress connection, those attempts cannot succeed and only
    extend the block -- the same reasoning ``providers/peeringdb.py`` records for the other
    keyless provider in the package.
    """
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(IDB_URL).mock(return_value=httpx.Response(429, text="Rate limit exceeded."))
        result = await internetdb_host(client=client, ip=IP)

    assert result == {"ok": False, "error": "rate_limited", "status": 429}
    assert route.call_count == 1


async def test_rate_limited_is_not_confused_with_not_found(client: httpx.AsyncClient) -> None:
    """Two different unknowns must stay distinguishable in the envelope.

    "throttled, ask again later" and "no record exists" lead to different analyst actions, and
    collapsing either into the other loses the one that matters.
    """
    async with respx.mock(assert_all_called=False) as router:
        route = router.get(IDB_URL)

        route.mock(return_value=httpx.Response(404, json={}))
        not_found = await internetdb_host(client=client, ip=IP)

        route.mock(return_value=httpx.Response(429, text=""))
        throttled = await internetdb_host(client=client, ip=IP)

    assert not_found["error"] != throttled["error"]


async def test_an_invalid_ip_is_refused_before_any_request_is_issued(client: httpx.AsyncClient) -> None:
    """The caller-supplied value is interpolated into a URL path, so it is validated first."""
    async with respx.mock(assert_all_called=False) as router:
        catch_all = router.route(host="internetdb.shodan.io").mock(return_value=httpx.Response(200, json={}))

        for bad in ("", "   ", "example.invalid", "203.0.113.10/24", "203.0.113.999", "../../etc/passwd"):
            result = await internetdb_host(client=client, ip=bad)
            assert result == {"ok": False, "error": "invalid_ip"}, bad

    assert catch_all.call_count == 0


# --------------------------------------------------------------------------------------
# 4. Retry policy
# --------------------------------------------------------------------------------------


async def test_a_5xx_is_retried_and_then_succeeds(client: httpx.AsyncClient, instant_retries: None) -> None:
    """Server-side failures are transient and stay inside the house retry policy."""
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(IDB_URL).mock(
            side_effect=[
                httpx.Response(503, text="unavailable"),
                httpx.Response(200, json={"ip": IP, "ports": [443]}),
            ]
        )
        result = await internetdb_host(client=client, ip=IP)

    assert result["ok"] is True
    assert result["data"]["ports"] == [443]
    assert route.call_count == 2


async def test_a_transport_error_is_retried(client: httpx.AsyncClient, instant_retries: None) -> None:
    """A request that may never have arrived is worth repeating."""
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(IDB_URL).mock(
            side_effect=[httpx.ConnectError("reset"), httpx.Response(200, json={"ip": IP})]
        )
        result = await internetdb_host(client=client, ip=IP)

    assert result["ok"] is True
    assert route.call_count == 2


async def test_a_permanent_4xx_raises_on_the_first_attempt(client: httpx.AsyncClient, instant_retries: None) -> None:
    """403 is permanent for this egress IP. Retrying burns three more slots and still fails.

    It escapes to the caller rather than becoming an envelope, which is what the paid sibling
    does and what ``orchestrators._call_provider`` already handles.
    """
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(IDB_URL).mock(return_value=httpx.Response(403, text="forbidden"))

        with pytest.raises(httpx.HTTPStatusError):
            await internetdb_host(client=client, ip=IP)

    assert route.call_count == 1


async def test_exhausted_retries_propagate(client: httpx.AsyncClient, instant_retries: None) -> None:
    """An exception that survives its retry budget reaches the caller.

    Returning an empty record here would assert "nothing is exposed" on the strength of a
    connection that never completed.
    """
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(IDB_URL).mock(side_effect=httpx.ConnectError("reset"))

        with pytest.raises(httpx.ConnectError):
            await internetdb_host(client=client, ip=IP)

    # retries=3 in with_exponential_backoff: four attempts and no more.
    assert route.call_count == 4


# --------------------------------------------------------------------------------------
# 5. Fallback, not replacement -- the anti-unification guards
# --------------------------------------------------------------------------------------


def test_this_is_a_different_host_from_the_paid_provider() -> None:
    """Two hosts, two datasets, two modules.

    Pinned as a constant comparison so that "point InternetDB at the paid base" or "reuse the
    paid base constant" cannot happen quietly. The host is also what the egress allowlist and
    ``tests/test_passivity.py`` gate on, so it is not free to change.
    """
    assert INTERNETDB_BASE == "https://internetdb.shodan.io"
    assert INTERNETDB_BASE != paid_mod.SHODAN_BASE
    assert httpx.URL(INTERNETDB_BASE).host != httpx.URL(paid_mod.SHODAN_BASE).host


async def test_org_and_last_update_are_absent_rather_than_null(client: httpx.AsyncClient) -> None:
    """InternetDB carries neither field. Emitting them as ``None`` would invent a shape.

    ``last_update`` matters most: ``verdict/signals.py`` reads it to age the observation and
    ``reporting/console.py`` renders it. A key that is present and empty invites a consumer to
    treat "no date" as a date it can format; a key that is absent cannot.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get(IDB_URL).mock(return_value=httpx.Response(200, json=FULL_PAYLOAD))
        result = await internetdb_host(client=client, ip=IP)

    assert "org" not in result["data"]
    assert "last_update" not in result["data"]


async def test_shared_keys_match_the_paid_provider_so_one_consumer_reads_both(
    client: httpx.AsyncClient,
) -> None:
    """The four overlapping concepts use the paid provider's key names, plus ``cpe`` for ``cpes``.

    A renderer or signal extractor written against ``shodan_host`` reads this envelope unchanged.
    That is the point of the fallback -- and it is also the trap the module docstring exists to
    close, because looking interchangeable is not being interchangeable.
    """
    fake_key = "test-key-not-a-credential"
    paid_payload = {
        "ports": [22],
        "org": "Example Networks",
        "tags": ["cloud"],
        "hostnames": ["a.example.invalid"],
        "vulns": ["CVE-2014-0160"],
        "last_update": "2026-01-01T00:00:00.000000",
        "data": [{"cpe": ["cpe:/a:nginx:nginx"]}],
    }
    async with respx.mock(assert_all_called=True) as router:
        router.get(IDB_URL).mock(return_value=httpx.Response(200, json=FULL_PAYLOAD))
        paid_url = f"{paid_mod.SHODAN_BASE}/shodan/host/{IP}"
        router.get(paid_url).mock(return_value=httpx.Response(200, json=paid_payload))
        free = await internetdb_host(client=client, ip=IP)
        paid = await paid_mod.shodan_host(client=client, api_key=fake_key, ip=IP)

    shared = {"ports", "hostnames", "cpe", "tags", "vulns"}
    assert shared <= set(free["data"])
    assert shared <= set(paid["data"])

    # And the paid record really does carry more, which is why this one is the fallback.
    extra: List[str] = sorted(set(paid["data"]) - set(free["data"]))
    assert extra == ["last_update", "org"]


def test_the_module_documents_the_difference_from_the_paid_provider() -> None:
    """The docstring is the control that stops a later "unify the two Shodan providers" change.

    Asserted rather than trusted to review: a rewrite that drops the warning has removed the only
    thing standing between a paying operator and a silent capability downgrade.
    """
    doc = idb_mod.__doc__ or ""
    assert "shodan_api" in doc
    assert "fallback" in doc.lower()
    assert "SHODAN_API_KEY" in doc
    for absent_field in ("org", "last_update"):
        assert absent_field in doc
