"""Unit tests for tripper_recon.providers.tranco -- roadmap item 8.3.

Two properties carry most of the weight here, and neither is about parsing.

**The suppressor may only point one way.** Tranco rank exists to close out "is
``microsoft.com`` malicious" cheaply. The moment a consumer reads an absent rank as a reason
for suspicion, the provider has become a machine for flagging every legitimate small business
on the internet, because the list holds about a million domains and the web holds hundreds of
millions. The tests below pin the shape that makes that inference awkward to draw: no risk
number, no band, no classification, an explicit ``tranco_suppression_only`` marker, and an
``tranco_absence_note`` that carries the "this is not adverse" sentence *in the payload* rather
than in a docstring nobody downstream reads.

**Absence of an answer and an answer of absence are different facts.** ``{"ranks": []}`` is
Tranco saying the domain is unranked. A 404, a 403, or a 200 with no ``ranks`` key is Tranco
saying nothing. The first is a successful observation, the rest are errors, and the tests
assert the two never collapse into each other -- the inverse of the invariant in
``docs/ARCHITECTURE.md`` section 8.1, and the same defect one direction over.

The 1 query/second ceiling gets its own section. It cannot be expressed by the global
concurrency semaphore in ``utils/http.py`` (a semaphore bounds requests *in flight*, not
requests *per second*), so it lives in the provider and is tested by observing the actual
spacing of request arrivals under a shortened interval.

Every request is served by respx; nothing in this module opens a socket, and no credential is
read -- the endpoint is keyless.
"""

from __future__ import annotations

import asyncio
import itertools
import time
from typing import Any, AsyncIterator, Dict, Iterator, List

import httpx
import pytest
import respx

from tripper_recon.providers import tranco as tranco_mod
from tripper_recon.providers.tranco import TRANCO_BASE, tranco_rank
from tripper_recon.utils import backoff as backoff_mod

DOMAIN = "example.invalid"
RANKS_URL = f"{TRANCO_BASE}/ranks/domain/{DOMAIN}"


def _ranks(*pairs: tuple[str, int]) -> httpx.Response:
    """The documented 200 body: ``{"ranks": [{"date": "YYYY-mm-dd", "rank": <int>}, ...]}``."""
    return httpx.Response(200, json={"ranks": [{"date": date, "rank": rank} for date, rank in pairs]})


@pytest.fixture()
async def client() -> AsyncIterator[httpx.AsyncClient]:
    """A plain client. ``create_client`` is not used: transport behaviour is not under test."""
    async with httpx.AsyncClient() as c:
        yield c


@pytest.fixture(autouse=True)
def no_pacing(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Disable the 1 qps pacer for every test that is not about the pacer.

    Without this the suite would sleep a real second per request. The pacing tests below
    re-enable it at a short interval and are the only place its behaviour is asserted.
    """
    monkeypatch.setattr(tranco_mod, "MIN_REQUEST_INTERVAL_SECONDS", 0.0)
    yield


@pytest.fixture()
def instant_retries(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Make ``with_exponential_backoff`` retry without waiting.

    This patches the attribute on the real ``asyncio`` module, so a test using this fixture
    must not depend on ``asyncio.sleep`` actually sleeping. The pacing tests deliberately do
    not use it.
    """

    async def _no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(backoff_mod.asyncio, "sleep", _no_sleep)
    yield


# --------------------------------------------------------------------------------------
# The happy path
# --------------------------------------------------------------------------------------


async def test_ranked_domain_returns_the_most_recent_rank_and_the_window(client: httpx.AsyncClient) -> None:
    """``tranco_rank`` is the newest rank, ``tranco_best_rank`` the strongest in the window.

    The response is deliberately served out of date order. Sorting is the provider's job: if it
    trusted the wire order, "the most recent rank" would mean whatever the API felt like
    sending, and a 30-day history read backwards would report the oldest value as current.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get(RANKS_URL).mock(return_value=_ranks(("2026-08-05", 940), ("2026-08-07", 812), ("2026-08-06", 905)))
        out = await tranco_rank(client=client, domain=DOMAIN)

    assert out["ok"] is True
    data = out["data"]
    assert data["tranco_rank"] == 812
    assert data["tranco_rank_date"] == "2026-08-07"
    assert data["tranco_best_rank"] == 812
    assert data["tranco_in_list"] is True
    assert data["tranco_days_ranked"] == 3
    assert data["tranco_history"] == [
        {"date": "2026-08-07", "rank": 812},
        {"date": "2026-08-06", "rank": 905},
        {"date": "2026-08-05", "rank": 940},
    ]
    assert data["tranco_absence_note"] is None


async def test_best_rank_differs_from_current_rank_when_the_domain_slipped(client: httpx.AsyncClient) -> None:
    """A domain drifting down the list is a different fact from one that was never high.

    ``tranco_best_rank`` is not a duplicate of ``tranco_rank``; it is what makes the drift
    visible without a consumer having to walk the history itself.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get(RANKS_URL).mock(return_value=_ranks(("2026-08-01", 1_200), ("2026-08-07", 640_000)))
        out = await tranco_rank(client=client, domain=DOMAIN)

    assert out["data"]["tranco_rank"] == 640_000
    assert out["data"]["tranco_best_rank"] == 1_200


async def test_single_day_presence_is_distinguishable_from_a_steady_presence(client: httpx.AsyncClient) -> None:
    """``tranco_days_ranked`` separates "ranked all month" from "appeared once".

    This is the field that makes the per-domain API worth its 1 qps cost over a cached daily
    snapshot, which can only ever answer present-or-absent today.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get(RANKS_URL).mock(return_value=_ranks(("2026-08-07", 998_000)))
        out = await tranco_rank(client=client, domain=DOMAIN)

    assert out["data"]["tranco_days_ranked"] == 1
    assert out["data"]["tranco_in_list"] is True


# --------------------------------------------------------------------------------------
# The suppressor may only point one way
# --------------------------------------------------------------------------------------


async def test_unranked_domain_is_a_successful_observation_not_an_error(client: httpx.AsyncClient) -> None:
    """``{"ranks": []}`` is Tranco answering. It is ``ok: True`` with the rank fields empty.

    Reporting it as a failure would erase the difference between a domain Tranco has never
    listed and a domain Tranco was never asked about, which is exactly the confusion the
    coverage machinery exists to prevent.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get(RANKS_URL).mock(return_value=_ranks())
        out = await tranco_rank(client=client, domain=DOMAIN)

    assert out["ok"] is True
    data = out["data"]
    assert data["tranco_in_list"] is False
    assert data["tranco_rank"] is None
    assert data["tranco_rank_date"] is None
    assert data["tranco_best_rank"] is None
    assert data["tranco_days_ranked"] == 0
    assert data["tranco_history"] == []


async def test_absence_carries_the_not_adverse_sentence_in_the_payload(client: httpx.AsyncClient) -> None:
    """The "unranked is not suspicious" statement travels with the data.

    Most of the web is unranked. A note left in a docstring protects nothing in the JSON export
    that reaches a ticket, so the sentence is a field. If this test fails because the wording
    moved, the replacement wording must still say, in words, that absence is not adverse.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get(RANKS_URL).mock(return_value=_ranks())
        out = await tranco_rank(client=client, domain=DOMAIN)

    note = out["data"]["tranco_absence_note"]
    assert isinstance(note, str) and note
    assert "NOT adverse" in note
    assert "unranked" in note


async def test_every_success_payload_declares_itself_suppression_only(client: httpx.AsyncClient) -> None:
    """``tranco_suppression_only`` is ``True`` on the ranked and the unranked payload alike.

    It is the machine-readable half of the rule the docstring states: nothing in this payload
    may raise a suspicion score. A consumer that increments from anything here has a defect,
    and this constant is what a reviewer can grep for.
    """
    for response in (_ranks(("2026-08-07", 12)), _ranks()):
        async with respx.mock(assert_all_called=True) as router:
            router.get(RANKS_URL).mock(return_value=response)
            out = await tranco_rank(client=client, domain=DOMAIN)
        assert out["data"]["tranco_suppression_only"] is True


async def test_payload_offers_no_field_an_unranked_domain_could_score_against(
    client: httpx.AsyncClient,
) -> None:
    """The envelope carries no risk number, no band, and no classification.

    This is the structural guard on the whole design. A ``tranco_risk``, ``tranco_score`` or
    ``tranco_suspicion`` field -- however carefully documented -- is an invitation to threshold
    it in the wrong direction, and a "popularity band" is the scoring layer's decision, not a
    provider's (``docs/ARCHITECTURE.md`` section 7: every scoring constant lives in
    ``verdict/scoring.yaml``). The key set is pinned so adding one is a deliberate act that
    fails this test first.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get(RANKS_URL).mock(return_value=_ranks())
        out = await tranco_rank(client=client, domain=DOMAIN)

    assert set(out["data"]) == {
        "tranco_rank",
        "tranco_rank_date",
        "tranco_in_list",
        "tranco_best_rank",
        "tranco_days_ranked",
        "tranco_history",
        "tranco_suppression_only",
        "tranco_absence_note",
    }
    forbidden = ("score", "risk", "suspic", "malic", "verdict", "confidence", "band", "reputation")
    offenders = [key for key in out["data"] if any(word in key.lower() for word in forbidden)]
    assert offenders == []


# --------------------------------------------------------------------------------------
# Failures: a 404 is unknown, never clean
# --------------------------------------------------------------------------------------


async def test_404_is_not_found_and_carries_no_data(client: httpx.AsyncClient) -> None:
    """A 404 is UNKNOWN. It gets its own slug and no ``data`` key at all.

    Nothing benign may be read from it. It is emphatically not the same answer as
    ``tranco_in_list: False``: that is Tranco reporting the domain is unranked, this is Tranco
    reporting nothing, and a consumer that treats them alike has invented an observation.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get(RANKS_URL).mock(return_value=httpx.Response(404))
        out = await tranco_rank(client=client, domain=DOMAIN)

    assert out == {"ok": False, "error": "not_found", "status": 404}
    assert "data" not in out


async def test_404_is_not_retried(client: httpx.AsyncClient) -> None:
    """One request. A 404 is permanent for this indicator; retrying spends pacing slots."""
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(RANKS_URL).mock(return_value=httpx.Response(404))
        await tranco_rank(client=client, domain=DOMAIN)

    assert route.call_count == 1


async def test_403_is_service_unavailable_and_is_not_retried(client: httpx.AsyncClient) -> None:
    """Tranco documents 403 as a temporary service condition, not an authorisation failure.

    It still gets a distinct slug rather than being folded into ``http_error``, because "the
    service is down" and "the domain is unranked" must never render the same way. It is not
    retried: ``utils/backoff.py`` classifies 403 as permanent, and a 403 that is a genuine
    block would be hammered by a loop that cannot tell the two apart.
    """
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(RANKS_URL).mock(return_value=httpx.Response(403))
        out = await tranco_rank(client=client, domain=DOMAIN)

    assert out == {"ok": False, "error": "service_unavailable", "status": 403}
    assert route.call_count == 1


async def test_200_without_a_ranks_array_is_malformed_not_unranked(client: httpx.AsyncClient) -> None:
    """A body with no ``ranks`` key is Tranco saying nothing, and is reported as an error.

    Collapsing it into ``tranco_in_list: False`` would manufacture an observation out of a
    parse failure. That is the same defect as rendering an unqueried provider as a green zero,
    pointed the other way.
    """
    for body in ({}, {"ranks": None}, {"ranks": {"2026-08-07": 12}}, []):
        async with respx.mock(assert_all_called=True) as router:
            router.get(RANKS_URL).mock(return_value=httpx.Response(200, json=body))
            out = await tranco_rank(client=client, domain=DOMAIN)
        assert out["ok"] is False
        assert out["error"] == "malformed_response"
        assert "data" not in out


# --------------------------------------------------------------------------------------
# Failures: retryable statuses
# --------------------------------------------------------------------------------------


async def test_429_is_retried_and_then_succeeds(client: httpx.AsyncClient, instant_retries: None) -> None:
    """429 is the expected failure on a 1 qps endpoint shared with anyone on the same egress IP.

    ``utils/backoff.py`` retries it and honours ``Retry-After``. The pacer prevents this tool
    from causing its own 429s; it cannot prevent somebody else's.
    """
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(RANKS_URL).mock(
            side_effect=[
                httpx.Response(429, headers={"Retry-After": "0"}),
                _ranks(("2026-08-07", 51)),
            ]
        )
        out = await tranco_rank(client=client, domain=DOMAIN)

    assert route.call_count == 2
    assert out["ok"] is True
    assert out["data"]["tranco_rank"] == 51


async def test_429_that_survives_every_retry_propagates(client: httpx.AsyncClient, instant_retries: None) -> None:
    """An exhausted retry budget escapes as an exception, matching every other provider here.

    ``orchestrators._call_provider`` catches it and files a provider error. Swallowing it into
    an envelope in this module would make Tranco the one provider whose failure mode is
    different from the other ten.
    """
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(RANKS_URL).mock(return_value=httpx.Response(429))
        with pytest.raises(httpx.HTTPStatusError):
            await tranco_rank(client=client, domain=DOMAIN)

    assert route.call_count == 4  # one attempt plus the three retries backoff permits


async def test_500_is_retried(client: httpx.AsyncClient, instant_retries: None) -> None:
    """A 5xx is the server's problem, so a second attempt is worth a pacing slot."""
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(RANKS_URL).mock(
            side_effect=[httpx.Response(503), _ranks(("2026-08-07", 7))],
        )
        out = await tranco_rank(client=client, domain=DOMAIN)

    assert route.call_count == 2
    assert out["data"]["tranco_rank"] == 7


# --------------------------------------------------------------------------------------
# Input handling
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
async def test_empty_domain_is_rejected_before_any_request(client: httpx.AsyncClient, value: str) -> None:
    """An empty argument would request the collection, not a domain. Refuse it locally."""
    async with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=r".*").mock(return_value=httpx.Response(200, json={"ranks": []}))
        out = await tranco_rank(client=client, domain=value)

    assert out == {"ok": False, "error": "invalid_domain"}
    assert route.call_count == 0


async def test_surrounding_whitespace_is_stripped_from_the_requested_domain(client: httpx.AsyncClient) -> None:
    """A stray newline off a bulk input file must not become part of the path segment."""
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(RANKS_URL).mock(return_value=_ranks(("2026-08-07", 3)))
        out = await tranco_rank(client=client, domain=f"  {DOMAIN}\n")

    assert out["ok"] is True
    assert str(route.calls[0].request.url) == RANKS_URL


@pytest.mark.parametrize(
    ("indicator", "encoded"),
    [
        ("evil.invalid/../../lists/create", "evil.invalid%2F..%2F..%2Flists%2Fcreate"),
        ("evil.invalid?x=1", "evil.invalid%3Fx%3D1"),
        ("evil.invalid#frag", "evil.invalid%23frag"),
        ("evil.invalid/../", "evil.invalid%2F..%2F"),
    ],
)
async def test_indicator_cannot_escape_its_path_segment(
    client: httpx.AsyncClient, indicator: str, encoded: str
) -> None:
    """A hostile indicator is percent-encoded into exactly one path segment.

    The host is a fixed literal and is never assembled from the indicator, so the passive
    boundary is not at risk here. What is at risk without the encoding is the *path*: a
    traversal or a bare ``?`` would let a target-derived string choose which Tranco endpoint
    gets called, and one of those endpoints queues list-generation work on their
    infrastructure. The runtime egress hook cannot see that, because the host is still right.
    """
    expected = f"{TRANCO_BASE}/ranks/domain/{encoded}"
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(expected).mock(return_value=_ranks())
        out = await tranco_rank(client=client, domain=indicator)

    assert out["ok"] is True
    request_url = route.calls[0].request.url
    assert request_url.host == "tranco-list.eu"
    assert request_url.raw_path.decode() == f"/api/ranks/domain/{encoded}"


# --------------------------------------------------------------------------------------
# Malformed entries inside a well-formed response
# --------------------------------------------------------------------------------------


async def test_unusable_entries_are_dropped_not_guessed_at(client: httpx.AsyncClient) -> None:
    """Entries that cannot answer the question are dropped, and the good ones survive.

    ``True`` is the one worth naming: ``bool`` is an ``int`` subclass in Python, so a naive
    check would turn it into rank 1 -- the single most misleading value this module could
    publish about a domain.
    """
    body: Dict[str, Any] = {
        "ranks": [
            {"date": "2026-08-07", "rank": 42},
            {"date": "2026-08-06", "rank": None},
            {"date": "2026-08-05", "rank": True},
            {"date": "2026-08-04", "rank": 0},
            {"date": "2026-08-03", "rank": -5},
            {"date": "not-a-date", "rank": 9},
            {"date": None, "rank": 9},
            {"rank": 9},
            {"date": "2026-08-02"},
            "not-a-dict",
            None,
        ]
    }
    async with respx.mock(assert_all_called=True) as router:
        router.get(RANKS_URL).mock(return_value=httpx.Response(200, json=body))
        out = await tranco_rank(client=client, domain=DOMAIN)

    assert out["data"]["tranco_history"] == [{"date": "2026-08-07", "rank": 42}]
    assert out["data"]["tranco_days_ranked"] == 1
    assert out["data"]["tranco_rank"] == 42


async def test_a_response_whose_entries_are_all_unusable_reports_absence_honestly(
    client: httpx.AsyncClient,
) -> None:
    """Every entry dropped leaves ``tranco_in_list: False`` -- and the not-adverse note with it.

    This is the one place the "malformed becomes unranked" objection has real force, so it is
    pinned deliberately: the array was present, so Tranco did answer, and the honest reading of
    an answer with no usable rank is that no rank is available. The absence note keeps that
    from being read as a finding.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get(RANKS_URL).mock(return_value=httpx.Response(200, json={"ranks": [{"rank": None}]}))
        out = await tranco_rank(client=client, domain=DOMAIN)

    assert out["ok"] is True
    assert out["data"]["tranco_in_list"] is False
    assert out["data"]["tranco_absence_note"]


# --------------------------------------------------------------------------------------
# The 1 query/second ceiling
# --------------------------------------------------------------------------------------
#
# The published limit is a RATE. The global limiter in utils/http.py is a CONCURRENCY
# semaphore: it bounds how many requests are in flight, not how often they start, so it cannot
# express this ceiling at any setting. These tests use a shortened interval and assert on the
# observed spacing of request arrivals, which is the property that actually matters.

PACING_INTERVAL = 0.08

#: Absolute, not proportional. The pacer spaces the moment each request is *released*; these
#: tests observe the moment each request *arrives* at respx, and the httpx work between the two
#: is a one-time cost on the first call through a fresh client. That skew is a fixed number of
#: milliseconds, so a fixed slack models it correctly where a percentage would either be flaky
#: at a short interval or toothless at a long one. It is far below the interval, so a pacer
#: that did nothing at all would still fail every assertion below by an order of magnitude.
PACING_SLACK = 0.02


def _arrival_recorder(arrivals: List[float]) -> Any:
    """A respx side effect that timestamps each request as it arrives."""

    def _record(_request: httpx.Request) -> httpx.Response:
        arrivals.append(time.monotonic())
        return _ranks(("2026-08-07", 1))

    return _record


def _gaps(arrivals: List[float]) -> List[float]:
    return [later - earlier for earlier, later in itertools.pairwise(arrivals)]


def _assert_paced(arrivals: List[float], *, expected: int) -> None:
    """Assert ``expected`` requests arrived, spaced at the interval, individually and in total.

    The span check is the load-bearing one: it is the property the published ceiling actually
    states -- N queries occupy at least (N-1) intervals of wall clock -- and unlike the
    per-gap check it cannot be satisfied by a pacer that lets a burst through and then sleeps
    for the sum.
    """
    assert len(arrivals) == expected, arrivals
    gaps = _gaps(arrivals)
    assert all(gap >= PACING_INTERVAL - PACING_SLACK for gap in gaps), gaps
    span = arrivals[-1] - arrivals[0]
    assert span >= PACING_INTERVAL * (expected - 1) - PACING_SLACK, span


async def test_concurrent_lookups_are_serialised_one_per_interval(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Four lookups fired at once arrive one interval apart, not all at once.

    This is the case the global semaphore gets wrong. With a concurrency ceiling of ten, ten
    Tranco lookups start simultaneously and every one of them is a rate-limit violation. The
    pacer sleeps while holding its lock, which is what makes the callers queue instead of all
    waking on the same deadline and firing together.
    """
    monkeypatch.setattr(tranco_mod, "MIN_REQUEST_INTERVAL_SECONDS", PACING_INTERVAL)
    arrivals: List[float] = []

    async with respx.mock(assert_all_called=True) as router:
        router.get(RANKS_URL).mock(side_effect=_arrival_recorder(arrivals))
        results = await asyncio.gather(*(tranco_rank(client=client, domain=DOMAIN) for _ in range(4)))

    assert all(result["ok"] for result in results)
    _assert_paced(arrivals, expected=4)


async def test_sequential_lookups_are_paced_too(client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """The ceiling is per process over time, so awaiting calls one after another still waits.

    A caller that hand-rolls a loop instead of using ``asyncio.gather`` gets the same ceiling.
    """
    monkeypatch.setattr(tranco_mod, "MIN_REQUEST_INTERVAL_SECONDS", PACING_INTERVAL)
    arrivals: List[float] = []

    async with respx.mock(assert_all_called=True) as router:
        router.get(RANKS_URL).mock(side_effect=_arrival_recorder(arrivals))
        for _ in range(3):
            assert (await tranco_rank(client=client, domain=DOMAIN))["ok"] is True

    _assert_paced(arrivals, expected=3)


async def test_a_retry_takes_its_own_pacing_slot(client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """A retry is another query and the provider counts it as one, so it waits its turn.

    Retrying a 429 without pacing the retry is how a client turns one rate-limit response into
    a ban. ``asyncio.sleep`` is left real here -- the backoff delay and the pacing delay both
    contribute, and the assertion is only that the second request did not arrive immediately.
    """
    monkeypatch.setattr(tranco_mod, "MIN_REQUEST_INTERVAL_SECONDS", PACING_INTERVAL)
    arrivals: List[float] = []

    def _record(_request: httpx.Request) -> httpx.Response:
        arrivals.append(time.monotonic())
        if len(arrivals) == 1:
            return httpx.Response(429, headers={"Retry-After": "0"})
        return _ranks(("2026-08-07", 1))

    async with respx.mock(assert_all_called=True) as router:
        router.get(RANKS_URL).mock(side_effect=_record)
        out = await tranco_rank(client=client, domain=DOMAIN)

    assert out["ok"] is True
    _assert_paced(arrivals, expected=2)


async def test_the_first_request_on_a_loop_is_not_delayed(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A single-indicator investigation pays nothing. The pacer only spaces the second request.

    Stated as a test because the obvious implementation -- sleep the interval before every
    request -- adds a second to every ``tripper-recon domain`` run for no benefit.
    """
    monkeypatch.setattr(tranco_mod, "MIN_REQUEST_INTERVAL_SECONDS", 5.0)
    async with respx.mock(assert_all_called=True) as router:
        router.get(RANKS_URL).mock(return_value=_ranks(("2026-08-07", 1)))
        started = time.monotonic()
        out = await tranco_rank(client=client, domain=DOMAIN)
        elapsed = time.monotonic() - started

    assert out["ok"] is True
    assert elapsed < 1.0


def test_the_pacer_survives_a_second_event_loop_in_the_same_process(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two ``asyncio.run`` calls each get a pacer bound to their own loop.

    An ``asyncio.Lock`` attaches to the loop that first awaits it, and a module-global one
    shared across loops raises ``RuntimeError`` the moment it actually has to make a caller
    wait. That is the defect ``utils/http.py`` fixed for its semaphore; the pacer is keyed the
    same way so it cannot reintroduce it. This test is deliberately synchronous -- the bug only
    exists when a second loop is created.
    """
    monkeypatch.setattr(tranco_mod, "MIN_REQUEST_INTERVAL_SECONDS", 0.01)

    async def _two_lookups() -> List[Dict[str, Any]]:
        async with httpx.AsyncClient() as c, respx.mock(assert_all_called=True) as router:
            router.get(RANKS_URL).mock(return_value=_ranks(("2026-08-07", 1)))
            return list(await asyncio.gather(*(tranco_rank(client=c, domain=DOMAIN) for _ in range(2))))

    for _ in range(2):
        results = asyncio.run(_two_lookups())
        assert all(result["ok"] for result in results)
