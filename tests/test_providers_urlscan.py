"""urlscan.io provider -- roadmap 6.7.

Two things are under test here, and the second matters more than the first.

**The extraction.** Search and result responses are shaped into the provider envelope, and every
field's *absence* is reported as absence. urlscan's own documentation warns that fields may be
missing and that detailed fields change without notice (https://urlscan.io/docs/result/), so a
parser that turns a missing verdict into a clean verdict, or a missing scan date into a fresh
scan, is the defect this file exists to catch.

**The passive boundary.** This provider is the one place in the package where a passive tool most
easily becomes an active one, because the submission endpoint sits on the same API one call away
from the two read endpoints. Three tests below read the module's own source and assert that the
submission route, the screenshot download and redirect-following are absent from it. They are
static source assertions on purpose: a behavioural test only proves the paths it exercised, and
the property being defended is about the paths nobody exercised.

Every request in this module is served by respx. Nothing here opens a socket, and no key is read
from the environment -- ``conftest.clear_provider_env`` guarantees the second part.
"""

from __future__ import annotations

import datetime
import re
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List

import httpx
import pytest
import respx

from tripper_recon.providers import urlscan as urlscan_module
from tripper_recon.providers.urlscan import (
    MAX_SEARCH_SIZE,
    STALE_AFTER_DAYS,
    URLSCAN_BASE,
    urlscan_result,
    urlscan_search,
    urlscan_search_domain,
    urlscan_search_url,
    urlscan_url_summary,
)

FAKE_KEY = "test-key-not-a-credential"

SEARCH_URL = f"{URLSCAN_BASE}/search/"
UUID = "11111111-2222-3333-4444-555555555555"
OTHER_UUID = "99999999-8888-7777-6666-555555555555"
RESULT_URL = f"{URLSCAN_BASE}/result/{UUID}/"

TARGET_URL = "http://malicious.invalid/login?next=/account"
TARGET_DOMAIN = "malicious.invalid"

#: Fixed clock so every age assertion is deterministic. Scans below are dated relative to it.
NOW = datetime.datetime(2026, 8, 8, 12, 0, 0, tzinfo=datetime.timezone.utc)
FRESH = "2026-08-06T12:00:00.000Z"  # 2 days before NOW
OLD = "2024-08-08T12:00:00.000Z"  # 730 days before NOW


@pytest.fixture()
async def client() -> AsyncIterator[httpx.AsyncClient]:
    """A plain client. ``create_client`` is not used: transport behaviour is not under test."""
    async with httpx.AsyncClient() as c:
        yield c


def _hit(
    *,
    uuid: str = UUID,
    time: str = FRESH,
    visibility: str = "public",
    task_url: str = TARGET_URL,
    page_url: str = "https://final.invalid/landing",
) -> Dict[str, Any]:
    """One entry of the search API's ``results`` array."""
    return {
        "_id": uuid,
        "task": {"uuid": uuid, "time": time, "url": task_url, "visibility": visibility},
        "page": {"url": page_url, "domain": "final.invalid", "ip": "203.0.113.9", "country": "US"},
        "result": f"{URLSCAN_BASE}/result/{uuid}/",
        "screenshot": f"https://urlscan.io/screenshots/{uuid}.png",
    }


def _search_body(*hits: Dict[str, Any], total: int = 1, has_more: bool = False) -> Dict[str, Any]:
    return {"results": list(hits), "total": total, "took": 12, "has_more": has_more}


def _result_body(**overrides: Any) -> Dict[str, Any]:
    """A finished-scan result body. Shape per https://urlscan.io/docs/result/."""
    body: Dict[str, Any] = {
        "task": {
            "uuid": UUID,
            "time": FRESH,
            "url": TARGET_URL,
            "visibility": "public",
            "reportURL": f"https://urlscan.io/result/{UUID}/",
            "screenshotURL": f"https://urlscan.io/screenshots/{UUID}.png",
        },
        "page": {
            "url": "https://final.invalid/landing",
            "domain": "final.invalid",
            "ip": "203.0.113.9",
            "country": "NL",
            "status": "200",
        },
        "lists": {
            "domains": ["cdn.invalid", "final.invalid", "malicious.invalid", "cdn.invalid"],
            "ips": ["203.0.113.9", "198.51.100.4"],
            "countries": ["NL", "US"],
            "urls": ["https://final.invalid/a", "https://final.invalid/b"],
        },
        "data": {
            "redirects": [
                {"url": TARGET_URL, "status": 302},
                {"response": {"url": "https://hop.invalid/x", "status": 301}},
                "https://final.invalid/landing",
            ]
        },
        "verdicts": {
            "overall": {"score": 80, "malicious": True, "hasVerdicts": True},
            "urlscan": {"score": 75, "malicious": True, "categories": ["phishing"], "brands": [{"name": "Acme Bank"}]},
        },
    }
    body.update(overrides)
    return body


# --------------------------------------------------------------------------------------
# Missing key
# --------------------------------------------------------------------------------------


async def test_every_entry_point_returns_missing_api_key_rather_than_raising(client: httpx.AsyncClient) -> None:
    """A provider with no key is a skipped provider, not a crashed investigation.

    Asserted across all five entry points rather than one, because the composed
    ``urlscan_url_summary`` reaches the network through two of the others and a key check on only
    the outer call would still let an unkeyed request leave.
    """
    async with respx.mock(assert_all_called=False) as router:
        search_route = router.get(SEARCH_URL)
        result_route = router.get(RESULT_URL)

        assert await urlscan_search(client=client, api_key=None, query="page.domain:x") == {
            "ok": False,
            "error": "missing_api_key",
        }
        assert await urlscan_search_url(client=client, api_key=None, url=TARGET_URL) == {
            "ok": False,
            "error": "missing_api_key",
        }
        assert await urlscan_search_domain(client=client, api_key="", domain=TARGET_DOMAIN) == {
            "ok": False,
            "error": "missing_api_key",
        }
        assert await urlscan_result(client=client, api_key=None, uuid=UUID) == {
            "ok": False,
            "error": "missing_api_key",
        }
        assert await urlscan_url_summary(client=client, api_key=None, url=TARGET_URL) == {
            "ok": False,
            "error": "missing_api_key",
        }

        assert not search_route.called
        assert not result_route.called


# --------------------------------------------------------------------------------------
# Search
# --------------------------------------------------------------------------------------


async def test_search_url_sends_the_documented_query_and_key_header(client: httpx.AsyncClient) -> None:
    """The query matches both URL fields and pins visibility to public.

    ``page.url`` is the URL after redirection and ``task.url`` is the URL that was submitted
    (https://docs.urlscan.io/pages/search-api-reference). An analyst holding a shortener needs the
    second; an analyst holding a landing page needs the first.
    """
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(SEARCH_URL).mock(return_value=httpx.Response(200, json=_search_body(_hit())))
        out = await urlscan_search_url(client=client, api_key=FAKE_KEY, url=TARGET_URL, now=NOW)

    assert out["ok"] is True
    request = route.calls[0].request
    assert request.headers["API-Key"] == FAKE_KEY
    query = request.url.params["q"]
    assert f'page.url:"{TARGET_URL}"' in query
    assert f'task.url:"{TARGET_URL}"' in query
    assert "task.visibility:public" in query
    assert request.url.params["size"] == "10"


async def test_search_domain_uses_page_domain_not_the_broad_contacted_domain_field(
    client: httpx.AsyncClient,
) -> None:
    """``domain:`` matches anything the page contacted; behind a CDN that is the CDN's traffic."""
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(SEARCH_URL).mock(return_value=httpx.Response(200, json=_search_body(_hit())))
        await urlscan_search_domain(client=client, api_key=FAKE_KEY, domain=TARGET_DOMAIN, now=NOW)

    query = route.calls[0].request.url.params["q"]
    assert query.startswith(f'(page.domain:"{TARGET_DOMAIN}")')
    assert "task.visibility:public" in query


async def test_search_escapes_elasticsearch_reserved_characters(client: httpx.AsyncClient) -> None:
    """An unescaped indicator becomes a syntactically valid *different* query.

    Reserved characters must be backslash-escaped (https://docs.urlscan.io/pages/search-general).
    A URL supplies several by construction, and a quote inside one would otherwise close the
    phrase and let the remainder of an attacker-authored URL be parsed as query operators.
    """
    hostile = 'http://evil.invalid/a"b\\c?d=1 OR page.domain:bank.invalid'
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(SEARCH_URL).mock(return_value=httpx.Response(200, json=_search_body()))
        await urlscan_search_url(client=client, api_key=FAKE_KEY, url=hostile, now=NOW)

    query = route.calls[0].request.url.params["q"]
    # The injected clause survives only inside the quoted phrase; it never appears unquoted.
    assert '\\"b' in query
    assert "\\\\c" in query
    assert query.count('"') % 2 == 0


async def test_search_size_is_clamped_to_the_self_imposed_ceiling(client: httpx.AsyncClient) -> None:
    """urlscan asks callers not to mirror or scrape their data wholesale."""
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(SEARCH_URL).mock(return_value=httpx.Response(200, json=_search_body()))
        await urlscan_search(client=client, api_key=FAKE_KEY, query="page.domain:x", size=10_000, now=NOW)

    assert route.calls[0].request.url.params["size"] == str(MAX_SEARCH_SIZE)


async def test_search_max_age_days_adds_the_documented_relative_date_bound(client: httpx.AsyncClient) -> None:
    """urlscan asks callers to "limit your searches by date if possible".

    https://docs.urlscan.io/pages/api-best-practices
    """
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(SEARCH_URL).mock(return_value=httpx.Response(200, json=_search_body()))
        await urlscan_search_domain(client=client, api_key=FAKE_KEY, domain=TARGET_DOMAIN, max_age_days=7, now=NOW)

    assert "date:>now-7d" in route.calls[0].request.url.params["q"]


async def test_search_drops_non_public_hits_and_reports_how_many_it_dropped(client: httpx.AsyncClient) -> None:
    """An unlisted scan is often another analyst's live investigation; it is not ours to quote.

    The exclusion is counted rather than absorbed. "Scans exist but none are public" and "no scans
    exist" are different findings, and a payload that renders them identically hides the first.
    """
    body = _search_body(
        _hit(uuid=UUID, visibility="public"),
        _hit(uuid=OTHER_UUID, visibility="unlisted"),
        _hit(uuid="private-1", visibility="private"),
        total=3,
    )
    async with respx.mock(assert_all_called=True) as router:
        router.get(SEARCH_URL).mock(return_value=httpx.Response(200, json=body))
        out = await urlscan_search_url(client=client, api_key=FAKE_KEY, url=TARGET_URL, now=NOW)

    data = out["data"]
    assert [record["uuid"] for record in data["urlscan_scans"]] == [UUID]
    assert data["urlscan_public_scan_count"] == 1
    assert data["urlscan_non_public_scans_excluded"] == 2
    assert data["urlscan_total_matches"] == 3


async def test_search_orders_scans_newest_first_and_dates_them(client: httpx.AsyncClient) -> None:
    """The newest public scan must be a property of the data, not of the server's ordering."""
    body = _search_body(_hit(uuid=OTHER_UUID, time=OLD), _hit(uuid=UUID, time=FRESH), total=2)
    async with respx.mock(assert_all_called=True) as router:
        router.get(SEARCH_URL).mock(return_value=httpx.Response(200, json=body))
        out = await urlscan_search_url(client=client, api_key=FAKE_KEY, url=TARGET_URL, now=NOW)

    data = out["data"]
    assert [record["uuid"] for record in data["urlscan_scans"]] == [UUID, OTHER_UUID]
    assert data["urlscan_newest_scan_date"] == FRESH
    assert data["urlscan_newest_scan_age_days"] == pytest.approx(2.0)
    assert data["urlscan_newest_scan_is_stale"] is False
    assert data["urlscan_scans"][1]["scan_age_days"] == pytest.approx(730.0)
    assert data["urlscan_scans"][1]["scan_is_stale"] is True


async def test_search_reports_an_undated_scan_as_undated_and_sorts_it_last(client: httpx.AsyncClient) -> None:
    """A scan whose date will not parse must never win "newest".

    Its currency cannot be argued for at all, so defaulting it to now -- or to epoch -- would put
    a fabricated freshness on the one record that has none.
    """
    body = _search_body(_hit(uuid=OTHER_UUID, time="not-a-timestamp"), _hit(uuid=UUID, time=OLD), total=2)
    async with respx.mock(assert_all_called=True) as router:
        router.get(SEARCH_URL).mock(return_value=httpx.Response(200, json=body))
        out = await urlscan_search_url(client=client, api_key=FAKE_KEY, url=TARGET_URL, now=NOW)

    records = out["data"]["urlscan_scans"]
    assert [record["uuid"] for record in records] == [UUID, OTHER_UUID]
    assert records[1]["scan_age_days"] is None
    assert records[1]["scan_is_stale"] is None


async def test_search_survives_a_response_that_is_not_the_documented_shape(client: httpx.AsyncClient) -> None:
    """urlscan's own warning: "make sure your response parser can handle missing fields"."""
    async with respx.mock(assert_all_called=True) as router:
        router.get(SEARCH_URL).mock(return_value=httpx.Response(200, json={"results": "nonsense"}))
        out = await urlscan_search_url(client=client, api_key=FAKE_KEY, url=TARGET_URL, now=NOW)

    data = out["data"]
    assert out["ok"] is True
    assert data["urlscan_scans"] == []
    assert data["urlscan_public_scan_count"] == 0
    assert data["urlscan_total_matches"] is None
    assert data["urlscan_has_more"] is None
    assert data["urlscan_newest_scan_date"] is None


async def test_search_reports_a_rejected_query_without_retrying_it(client: httpx.AsyncClient) -> None:
    """A malformed query will never parse; three retries only spend rate-limit budget."""
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(SEARCH_URL).mock(return_value=httpx.Response(400, json={"message": "bad query"}))
        out = await urlscan_search(client=client, api_key=FAKE_KEY, query="page.url:(", now=NOW)

    assert out == {"ok": False, "error": "invalid_query"}
    assert route.call_count == 1


# --------------------------------------------------------------------------------------
# Result
# --------------------------------------------------------------------------------------


async def test_result_extracts_the_chain_final_url_contacts_verdict_and_date(client: httpx.AsyncClient) -> None:
    """The whole point of the provider: somebody else's observation, dated."""
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(RESULT_URL).mock(return_value=httpx.Response(200, json=_result_body()))
        out = await urlscan_result(client=client, api_key=FAKE_KEY, uuid=UUID, now=NOW)

    assert route.calls[0].request.headers["API-Key"] == FAKE_KEY
    data = out["data"]

    assert data["urlscan_scan_date"] == FRESH
    assert data["urlscan_scan_age_days"] == pytest.approx(2.0)
    assert data["urlscan_scan_is_stale"] is False
    assert data["urlscan_scan_staleness_threshold_days"] == STALE_AFTER_DAYS

    assert data["urlscan_submitted_url"] == TARGET_URL
    assert data["urlscan_final_url"] == "https://final.invalid/landing"
    assert data["urlscan_redirected"] is True
    assert data["urlscan_redirect_chain"] == [
        {"url": TARGET_URL, "status": 302},
        {"url": "https://hop.invalid/x", "status": 301},
        {"url": "https://final.invalid/landing", "status": None},
    ]
    assert data["urlscan_redirect_chain_hops"] == 3

    assert data["urlscan_contacted_domains"] == ["cdn.invalid", "final.invalid", "malicious.invalid"]
    assert data["urlscan_contacted_ips"] == ["198.51.100.4", "203.0.113.9"]
    assert data["urlscan_contacted_countries"] == ["NL", "US"]
    assert data["urlscan_contacted_url_count"] == 2

    assert data["urlscan_verdict"] == {
        "overall_malicious": True,
        "overall_score": 80.0,
        "overall_has_verdicts": True,
        "urlscan_malicious": True,
        "urlscan_score": 75.0,
        "categories": ["phishing"],
        "brands": ["Acme Bank"],
    }
    assert data["urlscan_screenshot_url"] == f"https://urlscan.io/screenshots/{UUID}.png"
    assert data["urlscan_report_url"] == f"https://urlscan.io/result/{UUID}/"


async def test_result_marks_the_chain_as_somebody_elses_observation_never_resolved_here(
    client: httpx.AsyncClient,
) -> None:
    """Provenance travels with the chain so no consumer has to assume where it came from.

    Resolving a redirect -- including with ``HEAD`` -- is an active fetch of the target and is on
    the deliberately-not-doing list (docs/OPSEC.md section 7). Every hop in the payload was
    observed by urlscan's browser at scan time and is exactly as old as the scan date.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get(RESULT_URL).mock(return_value=httpx.Response(200, json=_result_body()))
        out = await urlscan_result(client=client, api_key=FAKE_KEY, uuid=UUID, now=NOW)

    data = out["data"]
    assert data["urlscan_redirect_chain_resolved_locally"] is False
    assert data["urlscan_redirect_chain_observed_by"] == "urlscan.io"
    assert data["urlscan_redirect_chain_observed_at"] == data["urlscan_scan_date"]
    assert data["urlscan_screenshot_fetched"] is False


async def test_result_flags_a_two_year_old_scan_as_stale(client: httpx.AsyncClient) -> None:
    """Presenting a 2024 scan as current infrastructure is the failure mode this guards."""
    body = _result_body(task={"uuid": UUID, "time": OLD, "url": TARGET_URL, "visibility": "public"})
    async with respx.mock(assert_all_called=True) as router:
        router.get(RESULT_URL).mock(return_value=httpx.Response(200, json=body))
        out = await urlscan_result(client=client, api_key=FAKE_KEY, uuid=UUID, now=NOW)

    data = out["data"]
    assert data["urlscan_scan_age_days"] == pytest.approx(730.0)
    assert data["urlscan_scan_is_stale"] is True


async def test_result_refuses_a_scan_that_is_not_public(client: httpx.AsyncClient) -> None:
    """Lifting an unlisted scan into a report discloses somebody else's live investigation."""
    for visibility in ("unlisted", "private", "UNLISTED"):
        body = _result_body(task={"uuid": UUID, "time": FRESH, "url": TARGET_URL, "visibility": visibility})
        async with respx.mock(assert_all_called=True) as router:
            router.get(RESULT_URL).mock(return_value=httpx.Response(200, json=body))
            out = await urlscan_result(client=client, api_key=FAKE_KEY, uuid=UUID, now=NOW)

        assert out == {"ok": False, "error": "scan_not_public"}, visibility


async def test_result_reads_a_scan_whose_visibility_field_is_absent(client: httpx.AsyncClient) -> None:
    """urlscan documents that fields can be missing; refusing on absence breaks older records.

    The visibility actually observed -- ``None`` here -- is carried through so a consumer can
    apply a stricter rule than this module does.
    """
    body = _result_body(task={"uuid": UUID, "time": FRESH, "url": TARGET_URL})
    async with respx.mock(assert_all_called=True) as router:
        router.get(RESULT_URL).mock(return_value=httpx.Response(200, json=body))
        out = await urlscan_result(client=client, api_key=FAKE_KEY, uuid=UUID, now=NOW)

    assert out["ok"] is True
    assert out["data"]["urlscan_visibility"] is None


async def test_result_reports_a_missing_verdict_as_absent_not_as_clean(client: httpx.AsyncClient) -> None:
    """A missing verdict and a clean verdict must not render identically.

    "We did not learn this" and "we learned it and it was fine" are different findings.
    """
    body = _result_body()
    del body["verdicts"]
    async with respx.mock(assert_all_called=True) as router:
        router.get(RESULT_URL).mock(return_value=httpx.Response(200, json=body))
        out = await urlscan_result(client=client, api_key=FAKE_KEY, uuid=UUID, now=NOW)

    assert out["data"]["urlscan_verdict"] is None


async def test_result_reports_a_missing_chain_as_empty_and_still_detects_redirection(
    client: httpx.AsyncClient,
) -> None:
    """A submitted URL that differs from the final URL is evidence of a redirect on its own."""
    body = _result_body(data={})
    async with respx.mock(assert_all_called=True) as router:
        router.get(RESULT_URL).mock(return_value=httpx.Response(200, json=body))
        out = await urlscan_result(client=client, api_key=FAKE_KEY, uuid=UUID, now=NOW)

    data = out["data"]
    assert data["urlscan_redirect_chain"] == []
    assert data["urlscan_redirect_chain_hops"] == 0
    assert data["urlscan_redirected"] is True


async def test_result_reports_redirection_as_unknown_when_a_url_is_missing(client: httpx.AsyncClient) -> None:
    """``None`` is not ``False``. A missing final URL does not mean the page did not redirect."""
    body = _result_body(page={"domain": "final.invalid"})
    async with respx.mock(assert_all_called=True) as router:
        router.get(RESULT_URL).mock(return_value=httpx.Response(200, json=body))
        out = await urlscan_result(client=client, api_key=FAKE_KEY, uuid=UUID, now=NOW)

    assert out["data"]["urlscan_final_url"] is None
    assert out["data"]["urlscan_redirected"] is None


async def test_result_skips_unparseable_redirect_entries_rather_than_rendering_them(
    client: httpx.AsyncClient,
) -> None:
    """urlscan does not pin the per-entry shape and warns it can change without notice."""
    body = _result_body(data={"redirects": [None, 42, {"status": 301}, {"url": "https://ok.invalid/"}, []]})
    async with respx.mock(assert_all_called=True) as router:
        router.get(RESULT_URL).mock(return_value=httpx.Response(200, json=body))
        out = await urlscan_result(client=client, api_key=FAKE_KEY, uuid=UUID, now=NOW)

    assert out["data"]["urlscan_redirect_chain"] == [{"url": "https://ok.invalid/", "status": None}]


async def test_result_reports_not_found(client: httpx.AsyncClient) -> None:
    """A UUID with no scan behind it is an outcome, not a failure."""
    async with respx.mock(assert_all_called=True) as router:
        router.get(RESULT_URL).mock(return_value=httpx.Response(404, json={"status": 404}))
        out = await urlscan_result(client=client, api_key=FAKE_KEY, uuid=UUID, now=NOW)

    assert out == {"ok": False, "error": "not_found"}


# --------------------------------------------------------------------------------------
# Composed summary
# --------------------------------------------------------------------------------------


async def test_url_summary_reads_the_newest_public_scan_and_keeps_the_search_context(
    client: httpx.AsyncClient,
) -> None:
    """Two GETs: find the scan somebody already ran, then read it. Nothing is submitted."""
    search_body = _search_body(_hit(uuid=OTHER_UUID, time=OLD), _hit(uuid=UUID, time=FRESH), total=2)
    async with respx.mock(assert_all_called=True) as router:
        search_route = router.get(SEARCH_URL).mock(return_value=httpx.Response(200, json=search_body))
        result_route = router.get(RESULT_URL).mock(return_value=httpx.Response(200, json=_result_body()))
        out = await urlscan_url_summary(client=client, api_key=FAKE_KEY, url=TARGET_URL, now=NOW)

    assert search_route.call_count == 1
    assert result_route.call_count == 1
    data = out["data"]
    assert data["urlscan_scan_uuid"] == UUID
    assert data["urlscan_scan_date"] == FRESH
    assert data["urlscan_final_url"] == "https://final.invalid/landing"
    assert data["urlscan_public_scan_count"] == 2
    assert [record["uuid"] for record in data["urlscan_other_scans"]] == [OTHER_UUID]


async def test_url_summary_reports_no_public_scan_rather_than_creating_one(client: httpx.AsyncClient) -> None:
    """The absence of a scan is a finding, not an invitation to submit the target.

    A freshly stood-up phishing page frequently has no public scan. The passive answer is to say
    so; the active answer -- submitting it -- would load the page from urlscan infrastructure and
    publish the indicator. There is no code path here that does the second thing.
    """
    # assert_all_called is False here on purpose: the result route is declared so that a
    # call to it would be RECORDED rather than erroring, and the assertion is that it stayed
    # uncalled. Requiring every declared route to fire would invert that.
    async with respx.mock(assert_all_called=False) as router:
        router.get(SEARCH_URL).mock(return_value=httpx.Response(200, json=_search_body(total=0)))
        result_route = router.get(RESULT_URL)
        out = await urlscan_url_summary(client=client, api_key=FAKE_KEY, url=TARGET_URL, now=NOW)

    assert out == {"ok": False, "error": "no_public_scan"}
    assert not result_route.called


async def test_url_summary_reports_no_public_scan_when_every_hit_is_unlisted(client: httpx.AsyncClient) -> None:
    """Filtered-out scans must not leave the summary reaching for a UUID it may not read."""
    body = _search_body(_hit(uuid=OTHER_UUID, visibility="unlisted"), total=1)
    # assert_all_called is False here on purpose: the result route is declared so that a
    # call to it would be RECORDED rather than erroring, and the assertion is that it stayed
    # uncalled. Requiring every declared route to fire would invert that.
    async with respx.mock(assert_all_called=False) as router:
        router.get(SEARCH_URL).mock(return_value=httpx.Response(200, json=body))
        result_route = router.get(f"{URLSCAN_BASE}/result/{OTHER_UUID}/")
        out = await urlscan_url_summary(client=client, api_key=FAKE_KEY, url=TARGET_URL, now=NOW)

    assert out == {"ok": False, "error": "no_public_scan"}
    assert not result_route.called


async def test_url_summary_propagates_a_failed_search_without_calling_result(client: httpx.AsyncClient) -> None:
    # assert_all_called is False here on purpose: the result route is declared so that a
    # call to it would be RECORDED rather than erroring, and the assertion is that it stayed
    # uncalled. Requiring every declared route to fire would invert that.
    async with respx.mock(assert_all_called=False) as router:
        router.get(SEARCH_URL).mock(return_value=httpx.Response(400, json={"message": "bad query"}))
        result_route = router.get(RESULT_URL)
        out = await urlscan_url_summary(client=client, api_key=FAKE_KEY, url=TARGET_URL, now=NOW)

    assert out == {"ok": False, "error": "invalid_query"}
    assert not result_route.called


# --------------------------------------------------------------------------------------
# Passive boundary — static assertions over this provider's own source
# --------------------------------------------------------------------------------------
#
# tests/test_passivity.py scans the whole package and is the authority. These three are local
# and specific: they name the exact routes on THIS API that would turn the provider active, so a
# failure points straight at the line rather than at a package-wide sweep. They are static
# because the property is about the paths nobody exercised.

_MODULE_SOURCE = Path(urlscan_module.__file__).read_text(encoding="utf-8")

#: The submission route. Assembled from fragments so this test file's own text cannot be what a
#: future grep for the literal finds.
_SUBMISSION_PATH = "/api/v1/" + "scan"

#: Routes that retrieve scan artefacts from urlscan rather than linking to them. Fetching the
#: screenshot or the DOM does not touch the target, but it is bulk retrieval of urlscan's data,
#: which their best-practice page asks callers not to do, and the payload has no use for bytes.
_ARTEFACT_DOWNLOAD_PATHS = ("/dom/", "/api/v1/" + "screenshots")


def test_the_submission_endpoint_does_not_exist_in_this_module() -> None:
    """The one line that would make this tool active.

    Submitting asks urlscan to load the target in a real browser from urlscan infrastructure and,
    unless explicitly made private, publishes the scan -- so the target learns they are being
    looked at, and so does everyone reading the public feed. There is no flag for this and no
    exception (docs/OPSEC.md section 7). If a future change needs it, the answer is that it
    belongs in a different tool.
    """
    assert _SUBMISSION_PATH not in _MODULE_SOURCE, (
        f"PASSIVE BOUNDARY: {_SUBMISSION_PATH} appears in tripper_recon/providers/urlscan.py.\n\n"
        "Submitting a URL instructs urlscan to FETCH the target and publishes the indicator. "
        "Use the search endpoint to find a scan somebody else already ran, then the result "
        "endpoint to read it -- which is what urlscan_url_summary already does."
    )


@pytest.mark.parametrize("path", _ARTEFACT_DOWNLOAD_PATHS)
def test_no_scan_artefact_is_downloaded(path: str) -> None:
    """The screenshot is emitted as a link. Nothing here retrieves bytes from urlscan."""
    assert path not in _MODULE_SOURCE, (
        f"PASSIVE BOUNDARY: {path} appears in tripper_recon/providers/urlscan.py.\n\n"
        "This module emits urlscan_screenshot_url as a clickable pivot and sets "
        "urlscan_screenshot_fetched to False. Retrieving the artefact adds nothing to the "
        "payload and is exactly the bulk retrieval urlscan asks integrators not to do."
    )


def test_no_http_verb_here_can_reach_the_target() -> None:
    """Only GET, only to urlscan, and never following a redirect.

    Following a redirect is an active fetch of the target -- ``HEAD`` included -- so the chain
    this provider reports is somebody else's observation and the client must never be told to
    resolve one itself.
    """
    offenders: List[str] = []
    for lineno, line in enumerate(_MODULE_SOURCE.splitlines(), start=1):
        for marker in (r"\.post\s*\(", r"\.head\s*\(", r"\.put\s*\(", r"\.patch\s*\(", r"\.delete\s*\("):
            if re.search(marker, line):
                offenders.append(f"line {lineno}: {line.strip()}")
        if re.search(r"follow_redirects\s*=\s*True", line):
            offenders.append(f"line {lineno}: {line.strip()}")

    assert not offenders, (
        "PASSIVE BOUNDARY: tripper_recon/providers/urlscan.py issues something other than a "
        "read-only GET, or asks httpx to follow a redirect.\n\n" + "\n".join(f"      {o}" for o in offenders)
    )


def test_every_url_literal_in_this_module_points_at_urlscan() -> None:
    """A target-derived host in a URL literal here would be a direct fetch of the target."""
    hosts = {
        match.split("://", 1)[1].split("/", 1)[0].lower()
        for match in re.findall(r"https?://[^\s\"'`<>()\[\]\\]+", _MODULE_SOURCE)
    }
    unexpected = {host for host in hosts if host not in {"urlscan.io", "docs.urlscan.io"}}
    assert not unexpected, (
        f"tripper_recon/providers/urlscan.py names hosts other than urlscan.io: {sorted(unexpected)}.\n\n"
        "urlscan.io is the provider; docs.urlscan.io appears only in documentation citations. "
        "Anything else is an outbound destination nobody reviewed."
    )
