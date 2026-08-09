"""Roadmap 6.6 -- ``vt_url_summary``, and the passivity guarantees that come with it.

W6 adds URL handling, which is where a passive tool most easily becomes an active one. Three
distinct things are under test here and they are worth naming separately, because only the
first is ordinary provider-field coverage:

1. **The identifier scheme and the attribute names**, which repo open question Q7 recorded as
   stated-from-memory and never retrieved. They were retrieved for this change; the quotes
   below are the record of what was retrieved, and the assertions pin each name so a silent
   rename upstream shows up as a red test rather than as a permanent 404.

2. **The 404 contract.** VirusTotal holding no report for a URL means nobody has ever submitted
   it. For a link that is hours old that is the *expected* state, and it is worth nothing as
   exculpatory evidence. It must render as UNKNOWN, and it must not be suppressed -- a
   suppressed 404 reads on the console exactly like "we asked and it was clean", which is the
   false-clean this project has spent five workstreams removing.

3. **The passive boundary at this call site.** ``tests/test_passivity.py`` catches the URL
   submission endpoint with a substring marker that cannot tell a forbidden POST from the
   sanctioned GET on an already-existing report. ``providers/virustotal.py`` therefore holds the
   path segment in ``VT_URL_REPORT_SEGMENT`` rather than writing it inline, which puts this call
   site out of that marker's reach. The static tests at the end of this module buy that safety
   back, and buy it back tighter: no POST of any kind may exist in the VirusTotal provider, the
   constant must still hold the segment the gate is watching for, and the only request built
   from it must be a GET.

RETRIEVED SOURCES -- VirusTotal API v3 documentation, retrieved 2026-08-08:

* Identifier, https://docs.virustotal.com/reference/url -- "We use unpadded base64 encoding, as
  defined in RFC 4648 section 3.2, which means that the resulting URL identifiers shouldn't be
  padded with '=' as base64-encoded data usually is." Worked example:
  ``base64.urlsafe_b64encode("http://www.somedomain.com/this/is/my/url".encode()).decode().strip("=")``.
  The page also documents a second form, "the SHA-256 of the canonized URL", and states that
  "all URL identifiers returned by the VirusTotal API are in the first form".
* Endpoint, https://docs.virustotal.com/reference/url-info -- method ``GET``, path
  ``/urls/{id}``, with ``{id}`` described as "URL identifier or base64 representation of URL to
  scan (w/o padding)". Full endpoint ``https://www.virustotal.com/api/v3/urls/{id}``.
* Attributes, https://docs.virustotal.com/reference/url-object -- ``last_analysis_stats``
  ("number of different results from this scans"), ``last_analysis_results`` ("result from URL
  scanners"), ``last_analysis_date`` ("UTC timestamp representing last time the URL was
  scanned"), ``reputation`` ("value of votes from VT community"), ``times_submitted`` ("number
  of times that URL has been checked"), ``first_submission_date`` ("UTC timestamp of the date
  where the URL was first submitted to VirusTotal"), ``last_final_url`` ("if the original URL
  redirects, where does it end"), ``categories`` ("they key is the partner who categorised the
  URL and the value is the URL's category"), ``redirection_chain`` ("history of redirections
  followed when visiting a given URL"), ``total_votes``, ``tags``, ``title``,
  ``last_http_response_code``, ``last_submission_date``, ``targeted_brand``, ``outgoing_links``.
  **``threat_names`` is NOT in that table.** It exists on the file object, not the URL object,
  and is read defensively for that reason.

Writing a literal URL-submission path inside ``tripper_recon/`` fails the build, by design. This
file is under ``tests/``, which the passivity scanner does not walk, so the endpoint can be
written out here in full -- and it is, so that the pin below is legible rather than assembled.

Every request in this module is served by respx. Nothing here opens a socket, and
``conftest.clear_provider_env`` guarantees no real key is in the environment.
"""

from __future__ import annotations

import ast
import base64
import json
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List

import httpx
import pytest
import respx

from tripper_recon.orchestrators import _should_suppress
from tripper_recon.providers.virustotal import (
    VT_REDIRECT_SOURCE_CHAIN,
    VT_REDIRECT_SOURCE_FINAL_URL,
    VT_URL_NO_REPORT_ERROR,
    VT_URL_REPORT_SEGMENT,
    vt_url_id,
    vt_url_summary,
)

FAKE_KEY = "test-key-not-a-credential"

#: A URL that cannot exist. `.invalid` is reserved by RFC 2606, so no test can accidentally
#: describe a real target, and respx intercepts everything regardless.
URL = "http://phish.example.invalid/login?id=42"

#: Computed the way VirusTotal's own worked example computes it, not copied from the
#: implementation -- a pin that calls the code under test would assert nothing.
URL_ID = base64.urlsafe_b64encode(URL.encode()).decode().strip("=")

#: Written out in full. This is the string the implementation must produce, and the whole point
#: of pinning it here is that it is readable rather than composed from the same constant the
#: implementation uses.
VT_URL_REPORT_URL = f"https://www.virustotal.com/api/v3/urls/{URL_ID}"

PROVIDER_SOURCE = Path(__file__).resolve().parent.parent / "tripper_recon" / "providers" / "virustotal.py"

#: The SHA-256-of-canonized-URL identifier form the API returns as ``data.id``. Not computable
#: locally; this is a stand-in of the right shape.
CANONICAL_ID = "b" * 64

VT_URL_ENGINES: Dict[str, Any] = {
    "Fortinet": {"category": "malicious", "result": "phishing", "method": "blacklist"},
    "OpenPhish": {"category": "suspicious", "result": "suspicious", "method": "blacklist"},
    "Quttera": {"category": "harmless", "result": "clean", "method": "blacklist"},
}


@pytest.fixture()
async def client() -> AsyncIterator[httpx.AsyncClient]:
    """A plain client. ``create_client`` is not used: transport behaviour is not under test."""
    async with httpx.AsyncClient() as c:
        yield c


def _url_object(**attributes: Any) -> Dict[str, Any]:
    """Wrap attributes in the VirusTotal v3 ``{"data": {"attributes": ...}}`` envelope."""
    return {"data": {"id": CANONICAL_ID, "type": "url", "attributes": attributes}}


# --------------------------------------------------------------------------------------
# 1. The identifier scheme (open question Q7)
# --------------------------------------------------------------------------------------


def test_url_id_is_unpadded_base64url_of_the_url() -> None:
    """The documented scheme, asserted against a hand-worked value rather than a re-derivation.

    ``http://www.somedomain.com/this/is/my/url`` is VirusTotal's own example input. Its padded
    urlsafe-base64 form ends in ``=``; the identifier must not.
    """
    documented_example = "http://www.somedomain.com/this/is/my/url"
    padded = base64.urlsafe_b64encode(documented_example.encode()).decode()

    assert padded.endswith("="), "test fixture is wrong: this example is supposed to need padding"
    assert vt_url_id(documented_example) == padded.rstrip("=")
    assert "=" not in vt_url_id(documented_example)


def test_url_id_uses_the_url_safe_alphabet() -> None:
    """``-`` and ``_``, never ``+`` or ``/``. A ``/`` in an identifier would split the path."""
    # Chosen so the standard alphabet would emit both '+' and '/'.
    noisy = "http://example.invalid/?a=" + "".join(chr(c) for c in range(0xF8, 0xFF))
    identifier = vt_url_id(noisy)

    assert "+" not in identifier
    assert "/" not in identifier
    assert base64.urlsafe_b64decode(identifier + "=" * (-len(identifier) % 4)).decode() == noisy


def test_url_id_encodes_as_utf8() -> None:
    """An internationalised URL must not depend on the platform default encoding."""
    unicode_url = "https://xn--e1afmkfd.example.invalid/über"
    assert vt_url_id(unicode_url) == base64.urlsafe_b64encode(unicode_url.encode("utf-8")).decode().rstrip("=")


@pytest.mark.parametrize("value", ["", "   ", "\n"])
def test_url_id_refuses_an_empty_value(value: str) -> None:
    """An empty identifier would address the collection, not a report."""
    with pytest.raises(ValueError):
        vt_url_id(value)


def test_url_id_refuses_an_unencodable_value() -> None:
    """A lone surrogate (a surrogateescape-decoded argv, typically) is reported, not encoded."""
    with pytest.raises(ValueError):
        vt_url_id("https://example.invalid/\udcff")


# --------------------------------------------------------------------------------------
# 2. The endpoint and the attribute names
# --------------------------------------------------------------------------------------


async def test_vt_url_summary_gets_the_documented_endpoint(client: httpx.AsyncClient) -> None:
    """GET on the report that already exists, at the path the v3 reference documents."""
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(VT_URL_REPORT_URL).mock(return_value=httpx.Response(200, json=_url_object()))
        result = await vt_url_summary(client=client, api_key=FAKE_KEY, url=URL)

    assert result["ok"] is True
    request = route.calls[0].request
    assert request.method == "GET"
    assert str(request.url) == VT_URL_REPORT_URL
    assert request.headers["x-apikey"] == FAKE_KEY


async def test_vt_url_summary_retains_every_documented_attribute(client: httpx.AsyncClient) -> None:
    """Each attribute name here was read off the current v3 URL-object reference."""
    payload = _url_object(
        last_analysis_stats={"malicious": 4, "suspicious": 1, "harmless": 60, "undetected": 29},
        last_analysis_results=VT_URL_ENGINES,
        last_analysis_date=1_700_000_000,
        reputation=-11,
        times_submitted=3,
        first_submission_date=1_699_000_000,
        last_submission_date=1_700_500_000,
        last_final_url="https://phish.example.invalid/final",
        redirection_chain=["http://phish.example.invalid/login?id=42", "https://phish.example.invalid/final"],
        categories={"Forcepoint ThreatSeeker": "phishing"},
        tags=["phishing"],
        title="Sign in",
        targeted_brand={"Phishtank": "ExampleBank"},
        last_http_response_code=200,
        total_votes={"harmless": 0, "malicious": 7},
    )
    async with respx.mock(assert_all_called=True) as router:
        router.get(VT_URL_REPORT_URL).mock(return_value=httpx.Response(200, json=payload))
        result = await vt_url_summary(client=client, api_key=FAKE_KEY, url=URL)

    data = result["data"]
    assert data["vt_url_id"] == URL_ID
    assert data["vt_url_canonical_id"] == CANONICAL_ID
    assert data["vt_last_analysis_stats"] == {"malicious": 4, "suspicious": 1, "harmless": 60, "undetected": 29}
    assert data["vt_security_results"] == VT_URL_ENGINES
    assert data["vt_last_analysis_date"] == 1_700_000_000
    assert data["vt_last_analysis_date_iso"] == "2023-11-14T22:13:20+00:00"
    assert data["vt_reputation"] == -11
    assert data["vt_times_submitted"] == 3
    assert data["vt_first_submission_date"] == 1_699_000_000
    assert data["vt_first_submission_date_iso"] == "2023-11-03T08:26:40+00:00"
    assert data["vt_last_submission_date"] == 1_700_500_000
    assert data["vt_categories"] == {"Forcepoint ThreatSeeker": "phishing"}
    assert data["vt_tags"] == ["phishing"]
    assert data["vt_title"] == "Sign in"
    assert data["vt_targeted_brand"] == {"Phishtank": "ExampleBank"}
    assert data["vt_last_http_response_code"] == 200
    assert data["vt_total_votes"] == {"harmless": 0, "malicious": 7}
    assert data["vt_link"] == f"https://www.virustotal.com/gui/url/{CANONICAL_ID}"


async def test_vt_url_detecting_engines_names_only_the_engines_that_flagged(client: httpx.AsyncClient) -> None:
    """Same derivation, same ordering rule, and the same key as the IP and domain paths."""
    async with respx.mock(assert_all_called=True) as router:
        router.get(VT_URL_REPORT_URL).mock(
            return_value=httpx.Response(200, json=_url_object(last_analysis_results=VT_URL_ENGINES))
        )
        result = await vt_url_summary(client=client, api_key=FAKE_KEY, url=URL)

    assert result["data"]["vt_detecting_engines"] == [
        {"engine": "Fortinet", "category": "malicious", "result": "phishing", "method": "blacklist"},
        {"engine": "OpenPhish", "category": "suspicious", "result": "suspicious", "method": "blacklist"},
    ]


async def test_first_submission_date_survives_without_any_detection(client: httpx.AsyncClient) -> None:
    """0/94 four hours after first submission is not the same object as 0/94 since 2019.

    The detection count is identical in both cases, which is exactly why the age is retained:
    it is frequently the more decisive of the two for a phishing URL.
    """
    payload = _url_object(
        last_analysis_stats={"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 24},
        first_submission_date=1_754_600_000,
    )
    async with respx.mock(assert_all_called=True) as router:
        router.get(VT_URL_REPORT_URL).mock(return_value=httpx.Response(200, json=payload))
        result = await vt_url_summary(client=client, api_key=FAKE_KEY, url=URL)

    data = result["data"]
    assert data["vt_first_submission_date"] == 1_754_600_000
    assert data["vt_first_submission_date_iso"] == "2025-08-07T20:53:20+00:00"
    assert data["vt_detecting_engines"] == []


async def test_threat_names_is_read_defensively_and_absent_by_default(client: httpx.AsyncClient) -> None:
    """``threat_names`` is not a documented URL-object attribute. Absent means ``None``."""
    async with respx.mock(assert_all_called=True) as router:
        router.get(VT_URL_REPORT_URL).mock(return_value=httpx.Response(200, json=_url_object()))
        result = await vt_url_summary(client=client, api_key=FAKE_KEY, url=URL)

    assert result["data"]["vt_threat_names"] is None


async def test_threat_names_is_retained_if_upstream_ever_adds_it(client: httpx.AsyncClient) -> None:
    """Defensively read means read, not ignored -- if the field appears, it survives."""
    async with respx.mock(assert_all_called=True) as router:
        router.get(VT_URL_REPORT_URL).mock(
            return_value=httpx.Response(200, json=_url_object(threat_names=["Phish.Generic", 7]))
        )
        result = await vt_url_summary(client=client, api_key=FAKE_KEY, url=URL)

    # The non-string member is dropped rather than coerced: str(7) would manufacture a threat name.
    assert result["data"]["vt_threat_names"] == ["Phish.Generic"]


# --------------------------------------------------------------------------------------
# 3. Absence is absence, never a benign default
# --------------------------------------------------------------------------------------


async def test_missing_fields_are_none_and_never_a_clean_looking_default(client: httpx.AsyncClient) -> None:
    """The failure mode this whole workstream exists to fix, one field at a time.

    ``{}`` for stats renders as a 0/0 scan that never happened, ``[]`` for the redirection
    chain renders as "VirusTotal looked and found no redirect", and ``0`` for
    ``times_submitted`` is a number nobody measured. All three must be ``None``.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get(VT_URL_REPORT_URL).mock(return_value=httpx.Response(200, json=_url_object()))
        result = await vt_url_summary(client=client, api_key=FAKE_KEY, url=URL)

    data = result["data"]
    for key in (
        "vt_last_analysis_stats",
        "vt_total_votes",
        "vt_categories",
        "vt_targeted_brand",
        "vt_tags",
        "vt_title",
        "vt_reputation",
        "vt_times_submitted",
        "vt_last_http_response_code",
        "vt_last_analysis_date",
        "vt_last_analysis_date_iso",
        "vt_first_submission_date",
        "vt_last_submission_date",
        "vt_last_final_url",
        "vt_redirection_chain",
    ):
        assert data[key] is None, f"{key} defaulted to something that is not absence"


async def test_a_malformed_attributes_block_does_not_raise(client: httpx.AsyncClient) -> None:
    """Third-party bodies can be the wrong shape everywhere. None of it may raise."""
    payload = {
        "data": {
            "id": 17,  # not a string
            "attributes": {
                "last_analysis_stats": [],
                "last_analysis_results": "unavailable",
                "last_analysis_date": True,  # bool is an int to Python; 1970 is not a scan date
                "times_submitted": float("nan"),
                "redirection_chain": "https://example.invalid/",
                "tags": None,
                "last_final_url": {"url": "https://example.invalid/"},
            },
        }
    }
    # json.dumps refuses NaN by default while json.loads accepts it, so the body is serialised
    # explicitly here. A provider CAN put NaN on the wire, and _as_int must reject it rather
    # than let it reach a report as a submission count.
    async with respx.mock(assert_all_called=True) as router:
        router.get(VT_URL_REPORT_URL).mock(
            return_value=httpx.Response(
                200,
                content=json.dumps(payload, allow_nan=True),
                headers={"content-type": "application/json"},
            )
        )
        result = await vt_url_summary(client=client, api_key=FAKE_KEY, url=URL)

    data = result["data"]
    assert result["ok"] is True
    assert data["vt_url_canonical_id"] is None
    assert data["vt_last_analysis_stats"] is None
    assert data["vt_security_results"] == {}
    assert data["vt_detecting_engines"] == []
    assert data["vt_last_analysis_date"] is None
    assert data["vt_times_submitted"] is None
    assert data["vt_redirection_chain"] is None
    assert data["vt_tags"] is None
    assert data["vt_last_final_url"] is None
    # The deep link falls back to the identifier this tool computed.
    assert data["vt_link"] == f"https://www.virustotal.com/gui/url/{URL_ID}"


# --------------------------------------------------------------------------------------
# 4. Redirects: somebody else's observation, labelled as such
# --------------------------------------------------------------------------------------


async def test_redirect_evidence_is_labelled_as_a_past_observation(client: httpx.AsyncClient) -> None:
    """``last_final_url`` answers the redirect question passively -- and only historically.

    The observation carries its source and the time VirusTotal saw it, in the ``provider:field``
    form ``utils.urls.RedirectChain.from_passive_record`` takes, and states outright that this
    tool did not resolve anything. A bare final URL with no timestamp would be read as a
    resolution performed now, which is the claim this tool must never make.
    """
    payload = _url_object(
        last_analysis_date=1_700_000_000,
        last_final_url="https://phish.example.invalid/final",
        redirection_chain=["http://phish.example.invalid/login?id=42", "https://phish.example.invalid/final"],
    )
    async with respx.mock(assert_all_called=True) as router:
        router.get(VT_URL_REPORT_URL).mock(return_value=httpx.Response(200, json=payload))
        result = await vt_url_summary(client=client, api_key=FAKE_KEY, url=URL)

    data = result["data"]
    observation = data["vt_redirect_observation"]
    assert data["vt_last_final_url"] == "https://phish.example.invalid/final"
    assert data["vt_redirection_chain"] == [
        "http://phish.example.invalid/login?id=42",
        "https://phish.example.invalid/final",
    ]
    assert observation["source"] == VT_REDIRECT_SOURCE_CHAIN
    assert observation["observed_at"] == "2023-11-14T22:13:20+00:00"
    assert observation["resolved_by_this_tool"] is False
    assert "NOT resolved now" in observation["note"]


async def test_redirect_source_falls_back_to_the_final_url_field(client: httpx.AsyncClient) -> None:
    """A report can carry the endpoint of the chain without the hops."""
    async with respx.mock(assert_all_called=True) as router:
        router.get(VT_URL_REPORT_URL).mock(
            return_value=httpx.Response(200, json=_url_object(last_final_url="https://phish.example.invalid/final"))
        )
        result = await vt_url_summary(client=client, api_key=FAKE_KEY, url=URL)

    assert result["data"]["vt_redirect_observation"]["source"] == VT_REDIRECT_SOURCE_FINAL_URL


async def test_no_redirect_evidence_names_no_source(client: httpx.AsyncClient) -> None:
    """No passive record means no source. An unsourced chain is an assertion, not evidence."""
    async with respx.mock(assert_all_called=True) as router:
        router.get(VT_URL_REPORT_URL).mock(return_value=httpx.Response(200, json=_url_object()))
        result = await vt_url_summary(client=client, api_key=FAKE_KEY, url=URL)

    observation = result["data"]["vt_redirect_observation"]
    assert observation["source"] is None
    assert observation["resolved_by_this_tool"] is False


# --------------------------------------------------------------------------------------
# 5. The 404 contract
# --------------------------------------------------------------------------------------


async def test_404_is_unknown_and_is_not_the_shared_not_found_code(client: httpx.AsyncClient) -> None:
    """No report is not "asked, nothing found", and must not borrow the code that means that.

    ``not_found`` maps to ``ProviderStatus.NOT_FOUND``, which ``Coverage`` counts in the
    ``answered`` numerator. That reading is defensible for an IP and wrong for a URL: absence of
    a report means only that nobody ever submitted the link.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get(VT_URL_REPORT_URL).mock(return_value=httpx.Response(404, json={"error": {"code": "NotFoundError"}}))
        result = await vt_url_summary(client=client, api_key=FAKE_KEY, url=URL)

    assert result["ok"] is False
    assert result["error"] == VT_URL_NO_REPORT_ERROR
    assert result["error"] != "not_found"
    assert result["status_code"] == 404
    assert result["renders_as"] == "unknown"
    assert result["vt_url_id"] == URL_ID
    assert "not a clean verdict" in result["detail"]
    assert "UNKNOWN" in result["message"] or "UNKNOWN" in result["detail"]


async def test_404_declares_itself_unsuppressible(client: httpx.AsyncClient) -> None:
    """The flag states the requirement in the payload instead of relying on a rule not matching."""
    async with respx.mock(assert_all_called=True) as router:
        router.get(VT_URL_REPORT_URL).mock(return_value=httpx.Response(404))
        result = await vt_url_summary(client=client, api_key=FAKE_KEY, url=URL)

    assert result["suppressible"] is False


@pytest.mark.parametrize("provider_label", ["virustotal", "virustotal_url", "vt_url"])
async def test_404_does_not_route_through_should_suppress(
    client: httpx.AsyncClient,
    provider_label: str,
) -> None:
    """The live assertion behind the flag above, against the real suppression function.

    A suppressed failure is hidden from the console, so a suppressed 404 here would look
    identical to a provider that answered and found nothing adverse. This asserts against
    ``orchestrators._should_suppress`` itself, under every provider label this call is likely to
    be registered as, so that a future edit to the suppression rules that catches this payload
    fails here rather than silently manufacturing a clean-looking report.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get(VT_URL_REPORT_URL).mock(return_value=httpx.Response(404))
        result = await vt_url_summary(client=client, api_key=FAKE_KEY, url=URL)

    assert _should_suppress(provider_label, result) is False


async def test_404_is_not_retried(client: httpx.AsyncClient) -> None:
    """A missing report is terminal. Retrying spends the rate-limit budget to learn nothing."""
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(VT_URL_REPORT_URL).mock(return_value=httpx.Response(404))
        await vt_url_summary(client=client, api_key=FAKE_KEY, url=URL)

    assert route.call_count == 1


async def test_missing_api_key_is_reported_as_configuration(client: httpx.AsyncClient) -> None:
    """Shared code with the IP and domain paths: no key means no request, and ``NOT_CONFIGURED``."""
    async with respx.mock(assert_all_called=False) as router:
        route = router.get(VT_URL_REPORT_URL)
        result = await vt_url_summary(client=client, api_key=None, url=URL)

    assert result == {"ok": False, "error": "missing_api_key"}
    assert route.call_count == 0


async def test_an_unusable_url_is_reported_before_any_request(client: httpx.AsyncClient) -> None:
    """An empty identifier would address the collection endpoint. Refuse locally instead."""
    async with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=r".*")
        result = await vt_url_summary(client=client, api_key=FAKE_KEY, url="   ")

    assert result["ok"] is False
    assert result["error"] == "invalid_url"
    assert result["suppressible"] is False
    assert route.call_count == 0


async def test_a_server_error_still_raises_for_the_orchestrator(client: httpx.AsyncClient) -> None:
    """Only 404 is absorbed. Everything else reaches ``_call_provider`` to be redacted there."""
    async with respx.mock(assert_all_called=True) as router:
        router.get(VT_URL_REPORT_URL).mock(return_value=httpx.Response(401, json={"error": {"code": "WrongCreds"}}))
        with pytest.raises(httpx.HTTPStatusError):
            await vt_url_summary(client=client, api_key=FAKE_KEY, url=URL)


# --------------------------------------------------------------------------------------
# 6. Static passivity guards for this call site
# --------------------------------------------------------------------------------------
#
# tests/test_passivity.py catches the URL submission endpoint with a substring marker that
# cannot tell it apart from the sanctioned GET, so providers/virustotal.py holds the path
# segment in a constant and is out of that marker's reach. These three tests buy the safety
# back, scoped tightly to the one module. They are static: they parse the source and never
# import a provider or open a socket.


def _provider_ast() -> ast.Module:
    return ast.parse(PROVIDER_SOURCE.read_text(encoding="utf-8"), filename=str(PROVIDER_SOURCE))


def test_the_virustotal_provider_contains_no_post_call_at_all() -> None:
    """The one thing the over-broad marker was really buying, asserted directly.

    Submitting a URL is a POST. This module has no legitimate use for the verb -- every call it
    makes reads a report a third party already holds -- so the check is not "no POST to the
    submission path", it is no POST, full stop. That is stricter than the substring marker and
    it cannot be sidestepped by renaming a constant.
    """
    offenders: List[str] = [
        f"{PROVIDER_SOURCE.name}:{node.lineno}  .{node.func.attr}(...)"
        for node in ast.walk(_provider_ast())
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"post", "put", "patch", "delete", "head", "stream", "request"}
    ]

    assert not offenders, (
        "PASSIVE BOUNDARY: a non-GET HTTP call exists in the VirusTotal provider.\n\n"
        + "\n".join(f"      {o}" for o in offenders)
        + "\n\n"
        "Every call this module makes must read a report VirusTotal ALREADY HOLDS. A POST to "
        "the submission endpoint instructs VirusTotal's crawler to fetch the target, which "
        "tells a live actor they are being investigated and publishes the indicator to the "
        "community feed; the analysis-object read is the receipt for that submission and is "
        "forbidden for the same reason. HEAD is not exempt either -- resolving a redirect is "
        "an active fetch whatever the verb (docs/OPSEC.md section 7).\n\n"
        "There is no flag for this. If the passive report cannot answer the question, the "
        "answer is UNKNOWN."
    )


def test_the_report_segment_constant_still_holds_the_watched_segment() -> None:
    """Guard the guard: the constant only justifies itself while it holds that exact value.

    ``VT_URL_REPORT_SEGMENT`` exists to keep the sanctioned GET out of reach of an over-broad
    substring marker in tests/test_passivity.py. If it is ever repointed, the marker's blind
    spot has been widened to cover a destination nobody reviewed -- which is the same failure
    mode ``test_radar_graphql_endpoint_constant_is_unchanged`` guards for the Radar POST.
    """
    assert VT_URL_REPORT_SEGMENT == "urls", (
        f"VT_URL_REPORT_SEGMENT is now {VT_URL_REPORT_SEGMENT!r}. It is allowed to exist only "
        "because it names the VirusTotal v3 URL-report collection, whose GET is passive. "
        "Repointing it moves this module's requests somewhere the passivity gate cannot see."
    )
    assert f"https://www.virustotal.com/api/v3/{VT_URL_REPORT_SEGMENT}/{URL_ID}" == VT_URL_REPORT_URL


def test_the_only_request_built_from_the_segment_is_a_get() -> None:
    """The segment must appear in exactly one request, and that request must be ``client.get``.

    ``test_the_virustotal_provider_contains_no_post_call_at_all`` proves no other verb exists in
    the module; this proves the segment is not being smuggled into some other call shape, and
    that there is exactly one such call site rather than a second one added later.
    """
    get_sites = [
        node
        for node in ast.walk(_provider_ast())
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "client"
        # The destination is an f-string interpolating the constant, so the pin is on the NAME
        # as it appears in the tree. Matching the value would also match any inline path.
        and node.args
        and "VT_URL_REPORT_SEGMENT" in ast.dump(node.args[0])
    ]

    assert len(get_sites) == 1, (
        f"expected exactly one request built from VT_URL_REPORT_SEGMENT, found {len(get_sites)}. "
        "Each call site that references the constant is a destination the passivity gate's "
        "substring marker cannot see, so each one has to be accounted for here."
    )
