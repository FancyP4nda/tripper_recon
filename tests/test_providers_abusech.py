"""abuse.ch URLhaus + ThreatFox provider -- roadmap 8.7.

Three properties are under test, in descending order of how much damage getting them wrong
would do.

**"No record" must never render as "clean".** URLhaus indexes malware-distribution URLs somebody
reported; ThreatFox indexes IOCs somebody submitted. Neither is a census of the benign internet,
so a miss is UNKNOWN. Every miss path -- ``query_status: no_results``, an HTTP 404, and a
ThreatFox response whose every row was a wildcard collision -- is asserted to produce a failure
envelope rather than a success envelope with an empty list. This is the same defect class as the
green ``0/0`` the whole package is written against.

**The POST is a query, and it must stay one.** URLhaus and ThreatFox accept their arguments by
POST. That is not a submission: nothing here asks abuse.ch to go and look at the target. The
static assertions at the bottom of this file read the module's own source and pin that -- the two
URLhaus form endpoints and the one ThreatFox JSON endpoint are the only destinations, the
ThreatFox selector is the search selector and never the write one, and the live-sample download
route on the URLhaus API appears nowhere. They are static on purpose: the property is about the
paths nobody exercised, and a behavioural test only proves the paths it ran.

**The evidence must survive extraction.** A URLhaus hit is worth more than a reputation score
because it carries a payload hash, a malware-family signature and a live/dead status; a ThreatFox
hit because it carries a named actor and a confidence level. A parser that drops those has thrown
away the reason the provider was added. Field-level tests below use the response bodies from
abuse.ch's own API documentation (retrieved 2026-08-09).

Every request is served by respx. Nothing here opens a socket, and ``conftest.clear_provider_env``
guarantees no real credential is in the environment.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from tripper_recon.providers import abusech as abusech_module
from tripper_recon.providers.abusech import (
    MAX_IOC_RECORDS,
    MAX_PAYLOAD_RECORDS,
    MAX_URL_RECORDS,
    THREATFOX_ENDPOINT,
    THREATFOX_SEARCH_QUERY,
    URLHAUS_BASE,
    URLHAUS_HOST_ENDPOINT,
    URLHAUS_URL_ENDPOINT,
    abusech_host_summary,
    abusech_url_summary,
    threatfox_search,
    urlhaus_host,
    urlhaus_url,
)
from tripper_recon.utils import backoff as backoff_mod

FAKE_KEY = "test-auth-key-not-a-credential"

TARGET_URL = "http://malicious.invalid/VMYB/INV/Outstanding-Invoices/"
TARGET_HOST = "malicious.invalid"
TARGET_IP = "198.51.100.7"


@pytest.fixture()
async def client() -> AsyncIterator[httpx.AsyncClient]:
    """A plain client. ``create_client`` is not used: transport behaviour is not under test."""
    async with httpx.AsyncClient() as c:
        yield c


@pytest.fixture()
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> List[float]:
    """Record backoff delays without waiting, so a retry test costs no wall-clock time."""
    recorded: List[float] = []

    async def _fake_sleep(delay: float) -> None:
        recorded.append(delay)

    monkeypatch.setattr(backoff_mod.asyncio, "sleep", _fake_sleep)
    monkeypatch.setattr(backoff_mod.random, "uniform", lambda _a, _b: 0.0)
    return recorded


# --------------------------------------------------------------------------------------
# Response bodies, taken from the vendor documentation (retrieved 2026-08-09)
# --------------------------------------------------------------------------------------


def _urlhaus_url_body(**overrides: Any) -> Dict[str, Any]:
    """URLhaus "URL information" response. Shape per the urlhaus-api.abuse.ch documentation."""
    body: Dict[str, Any] = {
        "query_status": "ok",
        "id": "105821",
        "urlhaus_reference": "https://urlhaus.abuse.ch/url/105821/",
        "url": TARGET_URL,
        "url_status": "online",
        "host": TARGET_HOST,
        "date_added": "2019-01-19 01:33:26 UTC",
        "last_online": None,
        "threat": "malware_download",
        "blacklists": {"spamhaus_dbl": "abused_legit_malware", "surbl": "listed"},
        "reporter": "Cryptolaemus1",
        "larted": "true",
        "takedown_time_seconds": None,
        "tags": ["emotet", "epoch2", "heodo"],
        "payloads": [
            {
                "firstseen": "2019-01-19 00:00:00 UTC",
                "filename": "5616769081079106.doc",
                "file_type": "doc",
                "response_size": "179664",
                "response_md5": "fedfa8ad9ee7846b88c5da79b32f6551",
                "response_sha256": "dc9f3b226bccb2f1fd4810cde541e5a10d59a1fe683f4a9462293b6ade8d8403",
                "urlhaus_download": "https://urlhaus-api.abuse.ch/v1/download/dc9f3b/",
                "signature": "Heodo",
                "virustotal": {"result": "16 / 58", "percent": "27.59", "link": "https://www.virustotal.com/x"},
                "imphash": "4e4a95a7659118e966a42f4a73311fda",
                "ssdeep": "3072:+hcypCDJeA",
                "tlsh": "1D340235A5E22807",
                "magika": "doc",
            }
        ],
    }
    body.update(overrides)
    return body


def _urlhaus_host_body(**overrides: Any) -> Dict[str, Any]:
    """URLhaus "Host information" response.

    Note ``query_staus`` -- the vendor's documented example misspells the key, and this fixture
    reproduces the documentation verbatim rather than correcting it. See
    ``test_the_documented_query_status_typo_is_tolerated``.
    """
    body: Dict[str, Any] = {
        "query_staus": "ok",
        "urlhaus_reference": "https://urlhaus.abuse.ch/host/malicious.invalid/",
        "host": TARGET_HOST,
        "firstseen": "2019-01-15 07:09:01 UTC",
        "url_count": "120",
        "blacklists": {"spamhaus_dbl": "abused_legit_malware", "surbl": "not listed"},
        "urls": [
            {
                "id": "121319",
                "urlhaus_reference": "https://urlhaus.abuse.ch/url/121319/",
                "url": "http://malicious.invalid/source/Z/5016223.exe",
                "url_status": "online",
                "date_added": "2019-02-11 07:45:05 UTC",
                "threat": "malware_download",
                "reporter": "abuse_ch",
                "larted": "false",
                "takedown_time_seconds": None,
                "tags": ["AZORult", "exe"],
            },
            {
                "id": "121320",
                "urlhaus_reference": "https://urlhaus.abuse.ch/url/121320/",
                "url": "http://malicious.invalid/source/Z/other.exe",
                "url_status": "offline",
                "date_added": "2019-02-12 07:45:05 UTC",
                "threat": "malware_download",
                "reporter": "someone_else",
                "larted": "true",
                "takedown_time_seconds": 3600,
                "tags": None,
            },
        ],
    }
    body.update(overrides)
    return body


def _threatfox_body(*rows: Dict[str, Any]) -> Dict[str, Any]:
    return {"query_status": "ok", "data": list(rows)}


def _ioc_row(**overrides: Any) -> Dict[str, Any]:
    """One ThreatFox IOC. Shape per the threatfox.abuse.ch/api/ documentation."""
    row: Dict[str, Any] = {
        "id": "12",
        "ioc": f"{TARGET_IP}:443",
        "threat_type": "botnet_cc",
        "threat_type_desc": "Indicator that identifies a botnet command&control server (C&C)",
        "ioc_type": "ip:port",
        "ioc_type_desc": "ip:port combination that is used for botnet Command&control (C&C)",
        "malware": "win.cobalt_strike",
        "malware_printable": "Cobalt Strike",
        "malware_alias": "Agentemis,BEACON,CobaltStrike",
        "malware_malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike",
        "confidence_level": 75,
        "first_seen": "2020-12-06 09:10:23 UTC",
        "last_seen": None,
        "reference": None,
        "reporter": "abuse_ch",
        "tags": None,
        "malware_samples": [
            {
                "time_stamp": "2021-03-23 08:18:06 UTC",
                "md5_hash": "5b7e82e051ade4b14d163eea2a17bf8b",
                "sha256_hash": "b325c92fa540edeb89b95dbfd4400c1cb33599c66859a87aead820e568a2ebe7",
                "malware_bazaar": "https://bazaar.abuse.ch/sample/b325c92/",
            }
        ],
    }
    row.update(overrides)
    return row


# --------------------------------------------------------------------------------------
# Missing key
# --------------------------------------------------------------------------------------


async def test_every_entry_point_returns_missing_api_key_rather_than_raising(client: httpx.AsyncClient) -> None:
    """Both platforms now require an Auth-Key, so an unset key is a skipped provider.

    Asserted across all five entry points, not one: the two composed summaries reach the network
    through the three primitives, and a key check on only the outer call would still let an
    unkeyed request leave. ``missing_api_key`` is the spelling
    ``orchestrators.NOT_CONFIGURED_ERRORS`` recognises, so the run reports "never asked" rather
    than "failed".
    """
    async with respx.mock(assert_all_called=False) as router:
        urlhaus_url_route = router.post(URLHAUS_URL_ENDPOINT)
        urlhaus_host_route = router.post(URLHAUS_HOST_ENDPOINT)
        threatfox_route = router.post(THREATFOX_ENDPOINT)

        assert await urlhaus_url(client=client, api_key=None, url=TARGET_URL) == {
            "ok": False,
            "error": "missing_api_key",
        }
        assert await urlhaus_host(client=client, api_key="", host=TARGET_HOST) == {
            "ok": False,
            "error": "missing_api_key",
        }
        assert await threatfox_search(client=client, api_key=None, ioc=TARGET_IP) == {
            "ok": False,
            "error": "missing_api_key",
        }
        assert await abusech_url_summary(client=client, api_key=None, url=TARGET_URL) == {
            "ok": False,
            "error": "missing_api_key",
        }
        assert await abusech_host_summary(client=client, api_key=None, host=TARGET_HOST) == {
            "ok": False,
            "error": "missing_api_key",
        }

        assert not urlhaus_url_route.called
        assert not urlhaus_host_route.called
        assert not threatfox_route.called


# --------------------------------------------------------------------------------------
# Request shape -- the POST is a query
# --------------------------------------------------------------------------------------


async def test_urlhaus_sends_a_form_encoded_query_with_the_auth_key_header(client: httpx.AsyncClient) -> None:
    """Form-encoded POST, ``url`` parameter, ``Auth-Key`` header. No submission field anywhere.

    The body is asserted key-by-key rather than by substring: a request that carried an extra
    parameter would still contain ``url=``, and the whole passivity claim for this provider is
    that the POST body says nothing except which record to read.
    """
    async with respx.mock(assert_all_called=True) as router:
        route = router.post(URLHAUS_URL_ENDPOINT).mock(return_value=httpx.Response(200, json=_urlhaus_url_body()))
        out = await urlhaus_url(client=client, api_key=FAKE_KEY, url=TARGET_URL)

    assert out["ok"] is True
    request = route.calls[0].request
    assert request.method == "POST"
    assert request.headers["Auth-Key"] == FAKE_KEY
    assert request.headers["content-type"].startswith("application/x-www-form-urlencoded")
    assert parse_qs(request.content.decode()) == {"url": [TARGET_URL]}


async def test_urlhaus_host_sends_only_the_host_parameter(client: httpx.AsyncClient) -> None:
    """The host endpoint takes an IPv4 address, a hostname or a domain, so both paths share it."""
    async with respx.mock(assert_all_called=True) as router:
        route = router.post(URLHAUS_HOST_ENDPOINT).mock(return_value=httpx.Response(200, json=_urlhaus_host_body()))
        out = await urlhaus_host(client=client, api_key=FAKE_KEY, host=TARGET_IP)

    assert out["ok"] is True
    assert parse_qs(route.calls[0].request.content.decode()) == {"host": [TARGET_IP]}


async def test_threatfox_sends_the_search_selector_and_nothing_else(client: httpx.AsyncClient) -> None:
    """ThreatFox dispatches on the ``query`` selector, so the selector is the passivity control.

    One endpoint serves both reads and writes on this API. The URL therefore cannot distinguish
    them and the body must: this asserts the selector is the search selector, that the body has
    exactly three keys, and that the transport is JSON as the vendor documents.
    """
    async with respx.mock(assert_all_called=True) as router:
        route = router.post(THREATFOX_ENDPOINT).mock(return_value=httpx.Response(200, json=_threatfox_body(_ioc_row())))
        out = await threatfox_search(client=client, api_key=FAKE_KEY, ioc=TARGET_IP)

    assert out["ok"] is True
    request = route.calls[0].request
    assert request.headers["Auth-Key"] == FAKE_KEY
    assert request.headers["content-type"].startswith("application/json")
    import json as _json

    body = _json.loads(request.content.decode())
    assert body == {"query": THREATFOX_SEARCH_QUERY, "search_term": TARGET_IP, "exact_match": False}
    assert THREATFOX_SEARCH_QUERY == "search_ioc"


# --------------------------------------------------------------------------------------
# "No record" is UNKNOWN, never clean
# --------------------------------------------------------------------------------------


async def test_urlhaus_no_results_is_a_failure_envelope_not_an_empty_success(client: httpx.AsyncClient) -> None:
    """The single most important assertion in this file.

    URLhaus holds URLs somebody reported for distributing malware. A freshly stood-up phishing
    page is *expected* to be absent, which is exactly the hour the answer matters. Returning
    ``{"ok": True, "data": {...count: 0}}`` would hand the renderer a zero to print in green and
    manufacture a clean verdict out of an absence of evidence.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.post(URLHAUS_URL_ENDPOINT).mock(return_value=httpx.Response(200, json={"query_status": "no_results"}))
        out = await urlhaus_url(client=client, api_key=FAKE_KEY, url=TARGET_URL)

    assert out == {"ok": False, "error": "no_results"}
    assert "data" not in out


@pytest.mark.parametrize("status", ["no_result", "no_results"])
async def test_both_miss_spellings_map_to_one_slug(client: httpx.AsyncClient, status: str) -> None:
    """URLhaus documents the plural; ThreatFox's error vocabulary is undocumented.

    Accepting both means an undocumented singular cannot fall through to the verbatim
    pass-through branch and reach a consumer as an unrecognised error string.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.post(THREATFOX_ENDPOINT).mock(return_value=httpx.Response(200, json={"query_status": status}))
        out = await threatfox_search(client=client, api_key=FAKE_KEY, ioc=TARGET_IP)

    assert out == {"ok": False, "error": "no_results"}


async def test_a_404_is_not_found_and_is_never_clean(client: httpx.AsyncClient) -> None:
    """404 means abuse.ch has no page for this indicator. That is UNKNOWN.

    It gets its own slug rather than sharing ``http_error`` so a consumer can tell "the provider
    has no record" from "the provider broke", and it is a failure envelope for the same reason
    ``no_results`` is.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.post(URLHAUS_HOST_ENDPOINT).mock(return_value=httpx.Response(404, json={}))
        out = await urlhaus_host(client=client, api_key=FAKE_KEY, host=TARGET_HOST)

    assert out == {"ok": False, "error": "not_found", "status": 404}


async def test_a_threatfox_response_whose_rows_all_collide_is_a_miss(client: httpx.AsyncClient) -> None:
    """``query_status: ok`` with zero real matches is a miss, and must report as one.

    The wildcard search returns substring collisions. If every returned row is discarded, the
    honest answer is ``no_results`` -- reporting ``ok`` with an empty list would let a consumer
    render "ThreatFox: 0 IOCs" as a clean result the provider never gave.
    """
    collision = _ioc_row(id="99", ioc="18.8.8.80:443")
    async with respx.mock(assert_all_called=True) as router:
        router.post(THREATFOX_ENDPOINT).mock(return_value=httpx.Response(200, json=_threatfox_body(collision)))
        out = await threatfox_search(client=client, api_key=FAKE_KEY, ioc="8.8.8.8")

    assert out["ok"] is False
    assert out["error"] == "no_results"
    assert out["threatfox_returned_count"] == 1
    assert out["threatfox_discarded_partial_matches"] == 1


# --------------------------------------------------------------------------------------
# Transport and status handling
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("code", [401, 403])
async def test_a_rejected_auth_key_is_a_slug_and_is_not_retried(
    client: httpx.AsyncClient, no_sleep: List[float], code: int
) -> None:
    """An invalid Auth-Key is permanent for this key and this indicator.

    Retrying it burns three more requests against the query-volume limits and still fails, so
    the backoff policy raises non-retryable statuses on the first attempt and this module
    converts the status into a slug before that happens. Asserted through the request count, not
    the envelope -- the envelope alone would pass even if three requests had gone out.
    """
    async with respx.mock(assert_all_called=True) as router:
        route = router.post(THREATFOX_ENDPOINT).mock(return_value=httpx.Response(code, json={}))
        out = await threatfox_search(client=client, api_key=FAKE_KEY, ioc=TARGET_IP)

    assert out["ok"] is False
    assert out["error"] == "unauthorized"
    assert out["status"] == code
    assert route.call_count == 1
    assert no_sleep == []


async def test_a_429_is_retried_and_then_succeeds(client: httpx.AsyncClient, no_sleep: List[float]) -> None:
    """abuse.ch enforces query-volume limits, so 429 is the status this provider will meet.

    It is transient, so ``with_exponential_backoff`` must handle it -- which is only true if the
    call is actually wrapped. This is the test that proves the wrapping, not just the retry.
    """
    async with respx.mock(assert_all_called=True) as router:
        route = router.post(URLHAUS_URL_ENDPOINT).mock(
            side_effect=[
                httpx.Response(429, headers={"Retry-After": "2"}, json={}),
                httpx.Response(200, json=_urlhaus_url_body()),
            ]
        )
        out = await urlhaus_url(client=client, api_key=FAKE_KEY, url=TARGET_URL)

    assert out["ok"] is True
    assert route.call_count == 2
    assert no_sleep == [2.0]


async def test_a_non_json_body_is_a_slug_rather_than_an_exception(client: httpx.AsyncClient) -> None:
    """An HTML error page under a 200 must not surface as an unclassified decode exception."""
    async with respx.mock(assert_all_called=True) as router:
        router.post(URLHAUS_URL_ENDPOINT).mock(return_value=httpx.Response(200, text="<html>maintenance</html>"))
        out = await urlhaus_url(client=client, api_key=FAKE_KEY, url=TARGET_URL)

    assert out["ok"] is False
    assert out["error"] == "invalid_response"


async def test_an_undocumented_query_status_reaches_the_caller_verbatim(client: httpx.AsyncClient) -> None:
    """ThreatFox does not document its error vocabulary, so nothing may be guessed about it.

    An unrecognised status is passed through as the slug with the original preserved, rather
    than being reclassified as "no data" -- which would turn a rejected query into an apparent
    clean result.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.post(THREATFOX_ENDPOINT).mock(
            return_value=httpx.Response(200, json={"query_status": "illegal_search_term"})
        )
        out = await threatfox_search(client=client, api_key=FAKE_KEY, ioc="x")

    assert out == {"ok": False, "error": "illegal_search_term", "query_status": "illegal_search_term"}


async def test_a_body_with_no_query_status_at_all_is_invalid_not_ok(client: httpx.AsyncClient) -> None:
    """Absence of the status field is a broken response, never an implied success."""
    async with respx.mock(assert_all_called=True) as router:
        router.post(URLHAUS_HOST_ENDPOINT).mock(return_value=httpx.Response(200, json={"host": TARGET_HOST}))
        out = await urlhaus_host(client=client, api_key=FAKE_KEY, host=TARGET_HOST)

    assert out["ok"] is False
    assert out["error"] == "invalid_response"


async def test_the_documented_query_status_typo_is_tolerated(client: httpx.AsyncClient) -> None:
    """abuse.ch's own host-information example spells the key ``query_staus``.

    Whether that is a documentation error or a live response key cannot be settled without
    issuing a request, which this repo does not do to "try it". Reading only the correct
    spelling would turn every successful host lookup into ``invalid_response``; reading only the
    typo would do the same in the other direction. Both are accepted.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.post(URLHAUS_HOST_ENDPOINT).mock(return_value=httpx.Response(200, json=_urlhaus_host_body()))
        out = await urlhaus_host(client=client, api_key=FAKE_KEY, host=TARGET_HOST)

    assert out["ok"] is True
    assert out["data"]["urlhaus_host"] == TARGET_HOST


# --------------------------------------------------------------------------------------
# URLhaus extraction -- the evidence must survive
# --------------------------------------------------------------------------------------


async def test_urlhaus_url_extraction_carries_the_payload_evidence(client: httpx.AsyncClient) -> None:
    """The fields that make a URLhaus hit outrank every reputation score in this tool.

    A hash, a named malware family, a reporter, a date and a live/dead status. Asserted
    individually rather than as one dict comparison so a failure names the field that was lost.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.post(URLHAUS_URL_ENDPOINT).mock(return_value=httpx.Response(200, json=_urlhaus_url_body()))
        out = await urlhaus_url(client=client, api_key=FAKE_KEY, url=TARGET_URL)

    data = out["data"]
    assert data["urlhaus_id"] == "105821"
    assert data["urlhaus_url_status"] == "online"
    assert data["urlhaus_online"] is True
    assert data["urlhaus_threat"] == "malware_download"
    assert data["urlhaus_tags"] == ["emotet", "epoch2", "heodo"]
    assert data["urlhaus_date_added"] == "2019-01-19 01:33:26 UTC"
    assert data["urlhaus_reporter"] == "Cryptolaemus1"
    assert data["urlhaus_larted"] is True
    assert data["urlhaus_blacklists"] == {"spamhaus_dbl": "abused_legit_malware", "surbl": "listed"}
    assert data["urlhaus_payload_count"] == 1
    assert data["urlhaus_signatures"] == ["Heodo"]
    assert data["urlhaus_payload_first_seen"] == "2019-01-19 00:00:00 UTC"

    payload = data["urlhaus_payloads"][0]
    assert payload["sha256"] == "dc9f3b226bccb2f1fd4810cde541e5a10d59a1fe683f4a9462293b6ade8d8403"
    assert payload["md5"] == "fedfa8ad9ee7846b88c5da79b32f6551"
    assert payload["file_size"] == 179664
    assert payload["signature"] == "Heodo"
    assert payload["virustotal"] == {"result": "16 / 58", "percent": "27.59", "link": "https://www.virustotal.com/x"}


async def test_the_payload_download_link_is_dropped_from_every_record(client: httpx.AsyncClient) -> None:
    """The sample-download route on this API is the abuse.ch analogue of a forbidden endpoint.

    A passive recon CLI must never hold a live sample, and emitting the retrieval link into a
    report invites exactly the fetch ``docs/OPSEC.md`` section 7 forbids. The hashes are carried
    instead: they are the pivot an analyst actually needs and they retrieve nothing.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.post(URLHAUS_URL_ENDPOINT).mock(return_value=httpx.Response(200, json=_urlhaus_url_body()))
        out = await urlhaus_url(client=client, api_key=FAKE_KEY, url=TARGET_URL)

    payload = out["data"]["urlhaus_payloads"][0]
    assert "urlhaus_download" not in payload
    assert not any("download" in key for key in payload)
    assert payload["sha256"] is not None


async def test_the_alternate_payload_field_spellings_are_accepted(client: httpx.AsyncClient) -> None:
    """The URL-information and payload-information responses name the same fields differently.

    ``response_md5``/``response_sha256``/``response_size`` versus ``md5_hash``/``sha256_hash``/
    ``file_size``. Reading only one spelling silently drops the hash -- the single most valuable
    field in the record -- on whichever response shape the parser was not written against.
    """
    body = _urlhaus_url_body(
        payloads=[
            {
                "firstseen": "2019-01-19 00:00:00 UTC",
                "md5_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "sha256_hash": "b" * 64,
                "file_size": 4096,
                "signature": None,
            }
        ]
    )
    async with respx.mock(assert_all_called=True) as router:
        router.post(URLHAUS_URL_ENDPOINT).mock(return_value=httpx.Response(200, json=body))
        out = await urlhaus_url(client=client, api_key=FAKE_KEY, url=TARGET_URL)

    payload = out["data"]["urlhaus_payloads"][0]
    assert payload["md5"] == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert payload["sha256"] == "b" * 64
    assert payload["file_size"] == 4096
    assert payload["signature"] is None
    assert out["data"]["urlhaus_signatures"] is None


@pytest.mark.parametrize(
    ("url_status", "expected_online"),
    [("online", True), ("offline", False), ("unknown", False), (None, None)],
)
async def test_liveness_keeps_four_states_and_collapses_none_of_them(
    client: httpx.AsyncClient, url_status: Any, expected_online: Any
) -> None:
    """``online``, ``offline``, ``unknown`` and absent are four different claims.

    ``unknown`` is abuse.ch saying it does not know; absent is abuse.ch not saying. Mapping the
    absent case to ``False`` would assert a negative the provider never made -- the same defect
    as AbuseIPDB's ``isWhitelisted`` defaulting to ``False``. The raw string is preserved
    alongside the boolean so a consumer can tell ``unknown`` from ``offline``.
    """
    body = _urlhaus_url_body(url_status=url_status)
    async with respx.mock(assert_all_called=True) as router:
        router.post(URLHAUS_URL_ENDPOINT).mock(return_value=httpx.Response(200, json=body))
        out = await urlhaus_url(client=client, api_key=FAKE_KEY, url=TARGET_URL)

    assert out["data"]["urlhaus_online"] is expected_online
    assert out["data"]["urlhaus_url_status"] == url_status


async def test_urlhaus_host_extraction_counts_online_urls_and_keeps_the_provider_total(
    client: httpx.AsyncClient,
) -> None:
    """Two counts with different meanings, kept apart.

    ``urlhaus_url_count`` is abuse.ch's own total for the host, parsed out of the JSON string it
    is sent as. ``urlhaus_online_urls_in_response`` is counted over the records this response
    actually carried, and is a floor rather than a total because abuse.ch does not document
    whether the host response returns every URL it holds.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.post(URLHAUS_HOST_ENDPOINT).mock(return_value=httpx.Response(200, json=_urlhaus_host_body()))
        out = await urlhaus_host(client=client, api_key=FAKE_KEY, host=TARGET_HOST)

    data = out["data"]
    assert data["urlhaus_url_count"] == 120
    assert data["urlhaus_urls_returned"] == 2
    assert data["urlhaus_online_urls_in_response"] == 1
    assert data["urlhaus_online"] is True
    assert data["urlhaus_firstseen"] == "2019-01-15 07:09:01 UTC"
    assert data["urlhaus_tags"] == ["AZORult", "exe"]
    assert data["urlhaus_reporters"] == ["abuse_ch", "someone_else"]
    assert data["urlhaus_urls"][0]["larted"] is False
    assert data["urlhaus_urls"][1]["takedown_time_seconds"] == 3600
    assert data["urlhaus_urls"][1]["tags"] is None


async def test_a_host_with_only_offline_urls_reports_online_false_not_none(client: httpx.AsyncClient) -> None:
    """Known-bad-but-currently-dead is a real finding, and a different one from never-heard-of-it."""
    body = _urlhaus_host_body(
        urls=[{"id": "1", "url": "http://malicious.invalid/a", "url_status": "offline", "threat": "malware_download"}]
    )
    async with respx.mock(assert_all_called=True) as router:
        router.post(URLHAUS_HOST_ENDPOINT).mock(return_value=httpx.Response(200, json=body))
        out = await urlhaus_host(client=client, api_key=FAKE_KEY, host=TARGET_HOST)

    assert out["data"]["urlhaus_online"] is False
    assert out["data"]["urlhaus_online_urls_in_response"] == 0


async def test_record_caps_report_the_true_count_and_flag_the_truncation(client: httpx.AsyncClient) -> None:
    """A cap that hides how much it dropped is the same defect class as a green zero."""
    payloads = [
        {"response_sha256": f"{index:064d}", "signature": f"family-{index % 3}", "firstseen": "2019-01-19 00:00:00 UTC"}
        for index in range(MAX_PAYLOAD_RECORDS + 5)
    ]
    urls = [
        {"id": str(index), "url": f"http://malicious.invalid/{index}", "url_status": "online"}
        for index in range(MAX_URL_RECORDS + 3)
    ]
    async with respx.mock(assert_all_called=True) as router:
        router.post(URLHAUS_URL_ENDPOINT).mock(
            return_value=httpx.Response(200, json=_urlhaus_url_body(payloads=payloads))
        )
        router.post(URLHAUS_HOST_ENDPOINT).mock(return_value=httpx.Response(200, json=_urlhaus_host_body(urls=urls)))
        url_out = await urlhaus_url(client=client, api_key=FAKE_KEY, url=TARGET_URL)
        host_out = await urlhaus_host(client=client, api_key=FAKE_KEY, host=TARGET_HOST)

    assert url_out["data"]["urlhaus_payload_count"] == MAX_PAYLOAD_RECORDS + 5
    assert len(url_out["data"]["urlhaus_payloads"]) == MAX_PAYLOAD_RECORDS
    assert url_out["data"]["urlhaus_payloads_truncated"] is True
    assert url_out["data"]["urlhaus_signatures"] == ["family-0", "family-1", "family-2"]

    assert host_out["data"]["urlhaus_urls_returned"] == MAX_URL_RECORDS + 3
    assert len(host_out["data"]["urlhaus_urls"]) == MAX_URL_RECORDS
    assert host_out["data"]["urlhaus_urls_truncated"] is True
    # Counted over every record the response carried, not over the capped display list.
    assert host_out["data"]["urlhaus_online_urls_in_response"] == MAX_URL_RECORDS + 3


async def test_a_malformed_entry_in_a_list_is_skipped_not_crashed(client: httpx.AsyncClient) -> None:
    """A string where a payload object was expected cannot take the investigation down."""
    body = _urlhaus_url_body(payloads=["not-a-record", None, {"response_sha256": "c" * 64, "signature": "Heodo"}])
    async with respx.mock(assert_all_called=True) as router:
        router.post(URLHAUS_URL_ENDPOINT).mock(return_value=httpx.Response(200, json=body))
        out = await urlhaus_url(client=client, api_key=FAKE_KEY, url=TARGET_URL)

    assert out["data"]["urlhaus_payload_count"] == 1
    assert out["data"]["urlhaus_signatures"] == ["Heodo"]


# --------------------------------------------------------------------------------------
# ThreatFox extraction and wildcard filtering
# --------------------------------------------------------------------------------------


async def test_threatfox_extraction_carries_the_actor_attribution(client: httpx.AsyncClient) -> None:
    """A named family plus a confidence level is what makes this a finding, not a data point."""
    second = _ioc_row(id="13", ioc=TARGET_IP, ioc_type="ip", malware_printable="QakBot", confidence_level=50)
    async with respx.mock(assert_all_called=True) as router:
        router.post(THREATFOX_ENDPOINT).mock(return_value=httpx.Response(200, json=_threatfox_body(_ioc_row(), second)))
        out = await threatfox_search(client=client, api_key=FAKE_KEY, ioc=TARGET_IP)

    data = out["data"]
    assert data["threatfox_ioc_count"] == 2
    assert data["threatfox_malware_families"] == ["Cobalt Strike", "QakBot"]
    assert data["threatfox_malware_ids"] == ["win.cobalt_strike"]
    assert data["threatfox_threat_types"] == ["botnet_cc"]
    assert data["threatfox_confidence_max"] == 75
    assert data["threatfox_confidence_min"] == 50
    assert data["threatfox_first_seen"] == "2020-12-06 09:10:23 UTC"
    # `last_seen: null` means "not re-observed", not "gone". It stays absent rather than being
    # backfilled from first_seen, which would invent a freshness the provider never asserted.
    assert data["threatfox_last_seen"] is None
    assert data["threatfox_reporters"] == ["abuse_ch"]


async def test_malware_sample_references_are_reduced_to_hashes(client: httpx.AsyncClient) -> None:
    """Hashes are a pivot; a sample page link is an invitation to go and get malware."""
    async with respx.mock(assert_all_called=True) as router:
        router.post(THREATFOX_ENDPOINT).mock(return_value=httpx.Response(200, json=_threatfox_body(_ioc_row())))
        out = await threatfox_search(client=client, api_key=FAKE_KEY, ioc=TARGET_IP)

    record = out["data"]["threatfox_iocs"][0]
    assert record["malware_sample_count"] == 1
    assert record["malware_sample_hashes"] == [
        {
            "md5": "5b7e82e051ade4b14d163eea2a17bf8b",
            "sha256": "b325c92fa540edeb89b95dbfd4400c1cb33599c66859a87aead820e568a2ebe7",
        }
    ]
    assert "malware_bazaar" not in record["malware_sample_hashes"][0]


async def test_the_wildcard_search_keeps_ip_port_rows_and_discards_substring_collisions(
    client: httpx.AsyncClient,
) -> None:
    """The reason ``exact_match`` defaults to ``False``, and the reason the results are filtered.

    ThreatFox stores C2 indicators as ``ip:port``, so an exact search for a bare address returns
    nothing at all. The wildcard finds them -- and also finds any row that merely contains the
    address as a substring, which is a false positive the caller would have no way to detect.
    Both halves are asserted here: the port row survives and the collision is dropped and
    counted.
    """
    kept = _ioc_row(id="1", ioc="8.8.8.8:443")
    also_kept = _ioc_row(id="2", ioc="8.8.8.8", ioc_type="ip")
    collision = _ioc_row(id="3", ioc="18.8.8.80:443")
    other = _ioc_row(id="4", ioc="8.8.8.88")

    async with respx.mock(assert_all_called=True) as router:
        router.post(THREATFOX_ENDPOINT).mock(
            return_value=httpx.Response(200, json=_threatfox_body(kept, also_kept, collision, other))
        )
        out = await threatfox_search(client=client, api_key=FAKE_KEY, ioc="8.8.8.8")

    data = out["data"]
    assert [record["ioc"] for record in data["threatfox_iocs"]] == ["8.8.8.8:443", "8.8.8.8"]
    assert data["threatfox_ioc_count"] == 2
    assert data["threatfox_returned_count"] == 4
    assert data["threatfox_discarded_partial_matches"] == 2


async def test_a_bracketed_ipv6_c2_row_is_matched(client: httpx.AsyncClient) -> None:
    """``[2001:db8::1]:443`` is the shape an IPv6 C2 record takes, and it must not be discarded."""
    row = _ioc_row(id="7", ioc="[2001:db8::1]:443")
    async with respx.mock(assert_all_called=True) as router:
        router.post(THREATFOX_ENDPOINT).mock(return_value=httpx.Response(200, json=_threatfox_body(row)))
        out = await threatfox_search(client=client, api_key=FAKE_KEY, ioc="2001:db8::1")

    assert out["ok"] is True
    assert out["data"]["threatfox_ioc_count"] == 1


async def test_exact_match_is_forwarded_and_recorded_in_the_payload(client: httpx.AsyncClient) -> None:
    """A consumer reading the payload can see which search was actually issued."""
    async with respx.mock(assert_all_called=True) as router:
        route = router.post(THREATFOX_ENDPOINT).mock(
            return_value=httpx.Response(200, json=_threatfox_body(_ioc_row(ioc=TARGET_URL, ioc_type="url")))
        )
        out = await threatfox_search(client=client, api_key=FAKE_KEY, ioc=TARGET_URL, exact_match=True)

    import json as _json

    assert _json.loads(route.calls[0].request.content.decode())["exact_match"] is True
    assert out["data"]["threatfox_exact_match"] is True
    assert out["data"]["threatfox_search_term"] == TARGET_URL


async def test_threatfox_data_as_a_string_does_not_crash(client: httpx.AsyncClient) -> None:
    """ThreatFox has answered a miss with ``data`` set to a string rather than an empty array."""
    async with respx.mock(assert_all_called=True) as router:
        router.post(THREATFOX_ENDPOINT).mock(
            return_value=httpx.Response(200, json={"query_status": "ok", "data": "No result"})
        )
        out = await threatfox_search(client=client, api_key=FAKE_KEY, ioc=TARGET_IP)

    assert out["ok"] is False
    assert out["error"] == "no_results"


async def test_the_ioc_record_cap_reports_the_true_match_count(client: httpx.AsyncClient) -> None:
    rows = [_ioc_row(id=str(index), ioc=f"{TARGET_IP}:{4000 + index}") for index in range(MAX_IOC_RECORDS + 4)]
    async with respx.mock(assert_all_called=True) as router:
        router.post(THREATFOX_ENDPOINT).mock(return_value=httpx.Response(200, json=_threatfox_body(*rows)))
        out = await threatfox_search(client=client, api_key=FAKE_KEY, ioc=TARGET_IP)

    assert out["data"]["threatfox_ioc_count"] == MAX_IOC_RECORDS + 4
    assert len(out["data"]["threatfox_iocs"]) == MAX_IOC_RECORDS
    assert out["data"]["threatfox_iocs_truncated"] is True


# --------------------------------------------------------------------------------------
# The composed lookups -- a partial failure must never read as a clean result
# --------------------------------------------------------------------------------------


async def test_a_hit_on_one_platform_succeeds_and_names_the_other_platforms_failure(
    client: httpx.AsyncClient,
) -> None:
    """Half an answer is still an answer, but the missing half must be visible.

    Merging silently would let "URLhaus says malware, ThreatFox was unreachable" render
    identically to "URLhaus says malware, ThreatFox says nothing" -- and the second is evidence
    while the first is a gap.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.post(URLHAUS_URL_ENDPOINT).mock(return_value=httpx.Response(200, json=_urlhaus_url_body()))
        router.post(THREATFOX_ENDPOINT).mock(return_value=httpx.Response(500, json={}))
        out = await abusech_url_summary(client=client, api_key=FAKE_KEY, url=TARGET_URL)

    assert out["ok"] is True
    data = out["data"]
    assert data["abusech_sources"] == ["urlhaus"]
    assert data["abusech_urlhaus_error"] is None
    # An exception raised by one platform becomes that platform's envelope, never the whole
    # lookup's. Losing a URLhaus record naming the malware family being served right now
    # because ThreatFox 500'd would be the most expensive possible way to fail.
    assert data["abusech_threatfox_error"] == "http_error"
    assert data["abusech_actor_attribution"] == ["Heodo"]
    assert data["abusech_online"] is True


async def test_both_platforms_missing_collapses_to_one_honest_no_results(client: httpx.AsyncClient) -> None:
    """Two misses are one miss, not a success with two empty sections."""
    async with respx.mock(assert_all_called=True) as router:
        router.post(URLHAUS_HOST_ENDPOINT).mock(return_value=httpx.Response(200, json={"query_status": "no_results"}))
        router.post(THREATFOX_ENDPOINT).mock(return_value=httpx.Response(200, json={"query_status": "no_result"}))
        out = await abusech_host_summary(client=client, api_key=FAKE_KEY, host=TARGET_HOST)

    assert out == {"ok": False, "error": "no_results"}


async def test_two_different_failures_are_not_collapsed_into_either_one(client: httpx.AsyncClient) -> None:
    """Not-found and key-rejected are different facts, and must both survive the merge.

    Reporting the pair as ``no_results`` would tell the analyst abuse.ch has no record when in
    fact half the question was never asked; reporting it as ``unauthorized`` would be wrong in
    the other direction.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.post(URLHAUS_HOST_ENDPOINT).mock(return_value=httpx.Response(200, json={"query_status": "no_results"}))
        router.post(THREATFOX_ENDPOINT).mock(return_value=httpx.Response(401, json={}))
        out = await abusech_host_summary(client=client, api_key=FAKE_KEY, host=TARGET_HOST)

    assert out == {
        "ok": False,
        "error": "lookup_failed",
        "urlhaus_error": "no_results",
        "threatfox_error": "unauthorized",
    }


async def test_the_composed_attribution_unions_both_platforms(client: httpx.AsyncClient) -> None:
    """``abusech_actor_attribution`` is the field a scoring lane should read before any count."""
    async with respx.mock(assert_all_called=True) as router:
        router.post(URLHAUS_HOST_ENDPOINT).mock(return_value=httpx.Response(200, json=_urlhaus_host_body()))
        router.post(THREATFOX_ENDPOINT).mock(
            return_value=httpx.Response(200, json=_threatfox_body(_ioc_row(ioc=f"{TARGET_HOST}:8080")))
        )
        out = await abusech_host_summary(client=client, api_key=FAKE_KEY, host=TARGET_HOST)

    assert out["ok"] is True
    data = out["data"]
    assert data["abusech_sources"] == ["urlhaus", "threatfox"]
    assert data["abusech_actor_attribution"] == ["Cobalt Strike"]
    assert data["urlhaus_online"] is True
    assert data["threatfox_malware_families"] == ["Cobalt Strike"]


async def test_the_url_summary_searches_threatfox_for_the_exact_url(client: httpx.AsyncClient) -> None:
    """A URL has no ``ip:port`` form, so the wildcard buys nothing and costs precision."""
    async with respx.mock(assert_all_called=True) as router:
        router.post(URLHAUS_URL_ENDPOINT).mock(return_value=httpx.Response(200, json=_urlhaus_url_body()))
        threatfox_route = router.post(THREATFOX_ENDPOINT).mock(
            return_value=httpx.Response(200, json={"query_status": "no_results"})
        )
        await abusech_url_summary(client=client, api_key=FAKE_KEY, url=TARGET_URL)

    import json as _json

    body = _json.loads(threatfox_route.calls[0].request.content.decode())
    assert body["exact_match"] is True
    assert body["search_term"] == TARGET_URL


# --------------------------------------------------------------------------------------
# Passive boundary -- static assertions over this provider's own source
# --------------------------------------------------------------------------------------
#
# tests/test_passivity.py scans the whole package and is the authority. These are local and
# specific: they name the exact routes and selectors on THESE APIs that would turn the provider
# active, so a failure points at the line rather than at a package-wide sweep. They are static
# because the property is about the paths nobody exercised.

_MODULE_SOURCE = Path(abusech_module.__file__).read_text(encoding="utf-8")

#: The ThreatFox selector that writes an IOC into the public corpus. Assembled from fragments so
#: this test file's own text cannot be what a future grep for the literal finds.
_SUBMIT_SELECTOR = "submit" + "_ioc"

#: The URLhaus live-sample retrieval route, same construction.
_SAMPLE_DOWNLOAD_PATH = "/v1/" + "download"


def test_the_write_selector_never_appears_in_this_module() -> None:
    """ThreatFox's endpoint dispatches on the selector, so the selector is the boundary.

    One URL serves reads and writes on this API. The egress allowlist cannot tell them apart and
    neither can a path-based check -- only the body does. If a write selector ever appears here,
    this tool has started contributing the operator's indicator list to a public corpus.
    """
    assert _SUBMIT_SELECTOR not in _MODULE_SOURCE, (
        f"PASSIVE BOUNDARY: {_SUBMIT_SELECTOR} appears in tripper_recon/providers/abusech.py.\n\n"
        "Submitting publishes the indicator under the operator's Auth-Key. This tool looks up "
        "what abuse.ch already holds and writes nothing back (docs/OPSEC.md section 1). The "
        "only selector this module may send is THREATFOX_SEARCH_QUERY."
    )


def test_the_sample_download_route_never_appears_in_this_module() -> None:
    """URLhaus can hand over the malware itself. A passive recon CLI must never hold a sample."""
    assert _SAMPLE_DOWNLOAD_PATH not in _MODULE_SOURCE, (
        f"PASSIVE BOUNDARY: {_SAMPLE_DOWNLOAD_PATH} appears in tripper_recon/providers/abusech.py.\n\n"
        "This is the abuse.ch analogue of the MalwareBazaar retrieval route already forbidden in "
        "docs/OPSEC.md section 7. Carry the hashes, which are the pivot; never the bytes."
    )


def test_every_request_in_this_module_goes_to_one_of_the_three_pinned_endpoints() -> None:
    """The POST allowance for this provider is only as good as the destinations it covers.

    A POST is a legitimate query on both these APIs, which means the verb cannot be the control
    here the way it is elsewhere in the package. The destination has to be, so every call site
    must name one of the three module-level endpoint constants -- an inline URL or a computed
    destination would be a POST to somewhere nobody reviewed.
    """
    allowed = {"URLHAUS_URL_ENDPOINT", "URLHAUS_HOST_ENDPOINT", "THREATFOX_ENDPOINT"}
    calls = re.findall(r"client\.(\w+)\(\s*([A-Za-z_][A-Za-z_0-9]*)", _MODULE_SOURCE)

    assert calls, "no client call sites found -- this test has stopped inspecting anything"
    offenders = [f"client.{verb}({destination})" for verb, destination in calls if destination not in allowed]
    assert not offenders, (
        "PASSIVE BOUNDARY: a request in tripper_recon/providers/abusech.py goes somewhere other "
        f"than the three reviewed endpoints: {offenders}"
    )


@pytest.mark.parametrize("verb", ["get", "head", "put", "patch", "delete", "request", "stream"])
def test_no_other_http_verb_is_used(verb: str) -> None:
    """POST is the query verb on both APIs; nothing else has a reading here."""
    assert not re.search(rf"client\.{verb}\s*\(", _MODULE_SOURCE), (
        f"tripper_recon/providers/abusech.py issues client.{verb}(). Both abuse.ch APIs take "
        "their arguments by form-encoded or JSON POST, and that POST is a QUERY. Any other verb "
        "is a new destination or a new semantic that has not been reviewed."
    )


def test_redirects_are_never_followed_here() -> None:
    """Following a redirect is an active fetch, and the flag is set per-request on a shared client."""
    assert "follow_redirects" not in _MODULE_SOURCE


def test_every_url_literal_in_this_module_points_at_an_abuse_ch_api_host() -> None:
    """A target-derived host in a URL literal here would be a direct fetch of the target."""
    hosts = {
        match.split("://", 1)[1].split("/", 1)[0].lower()
        for match in re.findall(r"https?://[^\s\"'`<>()\[\]\\]+", _MODULE_SOURCE)
    }
    assert hosts == {"urlhaus-api.abuse.ch", "threatfox-api.abuse.ch"}, (
        f"tripper_recon/providers/abusech.py names hosts other than the two abuse.ch API hosts: "
        f"{sorted(hosts)}.\n\n"
        "Both must be on ALLOWED_EGRESS_HOSTS in utils/http.py, ALLOWED_HOSTS in "
        "tests/test_passivity.py and the destination table in docs/OPSEC.md section 2. Anything "
        "else is an outbound destination nobody reviewed."
    )


def test_the_endpoint_constants_are_the_documented_ones() -> None:
    """Pinning a POST by constant NAME is only as good as the constant's value.

    ``test_every_request_in_this_module_goes_to_one_of_the_three_pinned_endpoints`` checks the
    names; repointing a constant would carry the allowance to a destination nobody reviewed.
    """
    assert URLHAUS_BASE == "https://urlhaus-api.abuse.ch/v1"
    assert URLHAUS_URL_ENDPOINT == "https://urlhaus-api.abuse.ch/v1/url/"
    assert URLHAUS_HOST_ENDPOINT == "https://urlhaus-api.abuse.ch/v1/host/"
    assert THREATFOX_ENDPOINT == "https://threatfox-api.abuse.ch/api/v1/"


def test_the_terms_of_use_exposure_is_stated_in_the_module_docstring() -> None:
    """The operator accepted this exposure knowingly; the code must keep saying so.

    Decision Q5 in docs/ROADMAP.md section 4b builds this provider in full, bulk mode included,
    with no gate. An accepted risk that stops being written down becomes an unknown risk one
    refactor later, so the disclosure is asserted rather than trusted to survive editing.
    """
    # Whitespace-normalised: the quotation is wrapped across source lines, and a test that
    # depended on where the wrapping fell would break on the next reflow rather than on the
    # disclosure actually going missing.
    docstring = " ".join((abusech_module.__doc__ or "").split())
    assert "robots, spiders or scripts" in docstring
    assert "accepted the exposure knowingly" in docstring
    assert "no gate" in docstring
