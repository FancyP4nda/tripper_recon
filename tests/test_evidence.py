"""Tests for the evidence envelope — roadmap 7.6.

The envelope exists so a report is still defensible three weeks later, which makes two
properties load-bearing and everything else supporting detail:

* **A cached fact must never claim to have been queried now.** ``queried_at`` and
  ``observed_at`` are separate fields with separate meanings, and ``observed_at_source`` says
  which of the two possible origins produced the second one. Tests here fail if any of the
  three is collapsed, defaulted, or silently invented.
* **An evidence file gets attached to a ticket.** Shodan and IPinfo authenticate in the query
  string; VirusTotal, AbuseIPDB, OTX, Cloudflare and abuse.ch authenticate in headers; and a
  401 body routinely echoes the key it just rejected. Every one of those routes is exercised
  below against a fake key, on both a failing and a succeeding request, and the assertion is
  that the key appears NOWHERE — url, headers, body, capture error, or the serialised record.

Two design decisions get their own tests because a future change would otherwise weaken them
quietly:

* Headers are captured by ALLOWLIST. ``test_an_unanticipated_credential_header_is_not_captured``
  sets a header nobody listed, with a value that is NOT in the environment, so redaction cannot
  save it. Only the allowlist can, and it does.
* ``body_sha256`` hashes the FULL body, never the stored one. A truncated, redacted or
  lossily-decoded body is marked in ``body_transforms``, and ``body_is_verbatim`` is the single
  predicate the cache lane must gate replay on.

No test here makes a network call. Everything runs inside ``respx``.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from typing import Any, Dict, List

import httpx
import pytest
import respx
from pydantic import ValidationError

from tripper_recon.utils import evidence as ev
from tripper_recon.utils.evidence import (
    CAPTURED_REQUEST_HEADERS,
    CAPTURED_RESPONSE_HEADERS,
    EVIDENCE_SCHEMA,
    NEVER_CAPTURED_HEADERS,
    TRANSFORM_LOSSY_DECODE,
    TRANSFORM_REDACTED,
    TRANSFORM_TRUNCATED,
    Evidence,
    EvidenceRecorder,
    ObservedAtSource,
    active_recorder,
    capture_evidence,
    record_response,
)
from tripper_recon.utils.http import PassiveBoundaryViolation, create_client
from tripper_recon.utils.redact import REDACTED

# A credential shaped like the real ones: long enough to clear redact._MIN_SECRET_LEN and
# distinctive enough that a substring match cannot pass by accident.
FAKE_KEY = "kJ8sN2pQ7vX4mZ1aB6cD9eF0gH3iL5oR"

SHODAN_URL = "https://api.shodan.io/shodan/host/93.184.216.34"
IPINFO_URL = "https://ipinfo.io/93.184.216.34"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/93.184.216.34"


def _mk(**overrides: Any) -> Evidence:
    """A minimal valid record. Only the fields under test are ever overridden."""
    fields: Dict[str, Any] = {
        "host": "api.shodan.io",
        "method": "GET",
        "url": SHODAN_URL,
        "status_code": 200,
        "http_version": "HTTP/2",
        "queried_at": "2026-08-09T12:00:00Z",
        "body_sha256": hashlib.sha256(b"").hexdigest(),
    }
    fields.update(overrides)
    return Evidence(**fields)


# --------------------------------------------------------------------------------------
# Capture is opt-in, and off changes nothing
# --------------------------------------------------------------------------------------


def test_capture_is_off_by_default() -> None:
    """No recorder in the context is the default state, and it is what "off" means."""
    assert active_recorder() is None


async def test_with_capture_off_the_client_behaves_exactly_as_before() -> None:
    """The response hook is installed unconditionally; with capture off it must be inert.

    The two things that could regress: the body must still be readable by the caller (the hook
    reads it early when capture is on, so an off-path that also read it would be a silent
    behaviour change), and nothing may be recorded anywhere.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get(SHODAN_URL).respond(200, json={"ports": [443]})
        async with create_client() as client:
            response = await client.get(SHODAN_URL)

    assert response.json() == {"ports": [443]}
    assert active_recorder() is None


async def test_capture_records_the_exchange_when_switched_on() -> None:
    async with respx.mock(assert_all_called=True) as router:
        router.get(SHODAN_URL).respond(200, json={"ports": [443]})
        with capture_evidence() as recorder:
            async with create_client() as client:
                response = await client.get(SHODAN_URL)

    assert response.json() == {"ports": [443]}
    assert len(recorder.records) == 1
    record = recorder.records[0]
    assert record.schema_version == EVIDENCE_SCHEMA
    assert record.host == "api.shodan.io"
    assert record.method == "GET"
    assert record.status_code == 200
    assert json.loads(record.body) == {"ports": [443]}


def test_the_recorder_does_not_leak_out_of_its_block() -> None:
    with capture_evidence() as recorder:
        assert active_recorder() is recorder
    assert active_recorder() is None


def test_nested_capture_restores_the_outer_recorder() -> None:
    """A nested block must not orphan the outer recorder — a bulk run nests naturally."""
    with capture_evidence() as outer:
        with capture_evidence() as inner:
            assert active_recorder() is inner
        assert active_recorder() is outer


async def test_the_egress_allowlist_still_refuses_with_capture_on() -> None:
    """The response hook sits BESIDE the request hook. It must not displace it.

    A blocked request never reaches the transport, so it also produces no envelope: there is no
    response to record, and a record of a request that never left would be a fiction.
    """
    with capture_evidence() as recorder:
        async with create_client() as client:
            with pytest.raises(PassiveBoundaryViolation):
                await client.get("https://evil-target.example/")

    assert recorder.records == ()


async def test_create_client_installs_both_hooks() -> None:
    """Guards against a future edit replacing the request hook while adding the response one."""
    from tripper_recon.utils.http import _enforce_egress_allowlist

    async with create_client() as client:
        assert _enforce_egress_allowlist in client.event_hooks["request"]
        assert record_response in client.event_hooks["response"]


# --------------------------------------------------------------------------------------
# Credentials — the hard requirement
# --------------------------------------------------------------------------------------


async def test_no_credential_reaches_the_envelope_on_success_or_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The 7.6 hard requirement, exercised over every authentication route this tool uses.

    Query-string auth (Shodan ``?key=``, IPinfo ``?token=``), header auth (VirusTotal
    ``x-apikey``), a 401 whose body echoes the rejected key, and a 200. The assertion is total:
    the key appears in no field of any record, and in neither serialisation.
    """
    monkeypatch.setenv("SHODAN_API_KEY", FAKE_KEY)
    monkeypatch.setenv("IPINFO_TOKEN", FAKE_KEY)
    monkeypatch.setenv("VT_API_KEY", FAKE_KEY)

    async with respx.mock(assert_all_called=True) as router:
        router.get(url__startswith=SHODAN_URL).respond(200, json={"ports": [22]})
        router.get(url__startswith=IPINFO_URL).respond(
            401,
            text=f'{{"error":"invalid token {FAKE_KEY}"}}',
        )
        router.get(VT_URL).respond(403, json={"error": {"message": f"key {FAKE_KEY} is not authorised"}})

        with capture_evidence() as recorder:
            async with create_client() as client:
                await client.get(SHODAN_URL, params={"key": FAKE_KEY})
                await client.get(IPINFO_URL, params={"token": FAKE_KEY})
                await client.get(VT_URL, headers={"x-apikey": FAKE_KEY})

    records = recorder.records
    assert len(records) == 3
    assert {r.status_code for r in records} == {200, 401, 403}

    for record in records:
        assert FAKE_KEY not in record.url
        assert FAKE_KEY not in record.body
        assert FAKE_KEY not in (record.capture_error or "")
        assert FAKE_KEY not in json.dumps(record.request_headers)
        assert FAKE_KEY not in json.dumps(record.response_headers)
        assert FAKE_KEY not in record.canonical_json()
        assert FAKE_KEY not in record.to_json()

    # And the redaction is visible rather than the value merely being absent: a field silently
    # dropped and a field redacted look identical from the outside, and only one of them is
    # evidence that the control ran.
    assert f"key={REDACTED}" in records[0].url
    assert f"token={REDACTED}" in records[1].url
    assert REDACTED in records[1].body
    assert TRANSFORM_REDACTED in records[1].body_transforms


async def test_an_unanticipated_credential_header_is_not_captured() -> None:
    """The allowlist, proved without redaction's help.

    The header value is deliberately NOT in the environment, so ``redact_text`` cannot see it as
    a secret. If it survives into the record, the capture policy is a denylist that fails open
    on the next provider to invent a header name — which is the failure mode the allowlist
    exists to make impossible.
    """
    unlisted_value = "Unlisted-Provider-Credential-Value"

    async with respx.mock(assert_all_called=True) as router:
        router.get(SHODAN_URL).respond(200, json={})
        with capture_evidence() as recorder:
            async with create_client() as client:
                await client.get(
                    SHODAN_URL,
                    headers={
                        "X-Some-New-Provider-Key": unlisted_value,
                        "Authorization": f"Bearer {unlisted_value}",
                    },
                )

    record = recorder.records[0]
    assert "x-some-new-provider-key" not in record.request_headers
    assert "authorization" not in record.request_headers
    assert unlisted_value not in record.canonical_json()
    # What survives is the content negotiation and the honest User-Agent, and nothing else.
    assert set(record.request_headers) <= CAPTURED_REQUEST_HEADERS


def test_the_allowlists_never_intersect_the_forbidden_set() -> None:
    """Makes the redundancy between the allowlists and NEVER_CAPTURED_HEADERS executable.

    The deny set is not what protects the envelope — the allowlists are. It is the invariant a
    careless widening of an allowlist has to be checked against, and a comment saying so would
    rot. This test is the check.
    """
    assert not CAPTURED_REQUEST_HEADERS & NEVER_CAPTURED_HEADERS
    assert not CAPTURED_RESPONSE_HEADERS & NEVER_CAPTURED_HEADERS


async def test_a_forbidden_header_is_dropped_even_if_it_reaches_the_filter() -> None:
    """Defence in depth: the deny set wins over an allowlist entry, not the other way round."""
    filtered = ev._filter_headers(
        httpx.Headers({"Cookie": "session=abc", "User-Agent": "tripper-recon/test"}),
        frozenset({"cookie", "user-agent"}),
    )
    assert filtered == {"user-agent": "tripper-recon/test"}


async def test_a_capture_failure_is_recorded_and_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    """The hook must never break a lookup, and must never stay silent about failing.

    An exception raised inside the capture path is the one place a raw credential could still
    reach an envelope, because exception text is not something the capture policy shaped. It
    goes through ``redact_text`` like everything else, and the request still succeeds.
    """
    monkeypatch.setenv("SHODAN_API_KEY", FAKE_KEY)

    def boom(raw: bytes, max_body_bytes: int) -> Any:
        raise RuntimeError(f"exploded while holding {FAKE_KEY}")

    monkeypatch.setattr(ev, "_body_fields", boom)

    async with respx.mock(assert_all_called=True) as router:
        router.get(SHODAN_URL).respond(200, json={"ports": [443]})
        with capture_evidence() as recorder:
            async with create_client() as client:
                response = await client.get(SHODAN_URL)

    assert response.status_code == 200  # the lookup survived
    record = recorder.records[0]
    assert record.capture_error is not None
    assert "evidence capture failed" in record.capture_error
    assert FAKE_KEY not in record.capture_error
    assert REDACTED in record.capture_error
    assert record.body_is_verbatim is False  # a capture failure is never replayable


# --------------------------------------------------------------------------------------
# Two timestamps, not one
# --------------------------------------------------------------------------------------


async def test_queried_at_is_ours_and_observed_at_is_the_providers() -> None:
    """The whole point of 7.4: they are different facts and must not collapse into one.

    The ``Date`` header here is deliberately far in the past. A record that reports it as
    ``queried_at``, or that reports "now" as ``observed_at``, is the exact failure this
    workstream exists to prevent.
    """
    before = dt.datetime.now(dt.timezone.utc)

    async with respx.mock(assert_all_called=True) as router:
        router.get(SHODAN_URL).respond(
            200,
            json={"ports": [443]},
            headers={"Date": "Tue, 14 Jul 2026 09:00:00 GMT"},
        )
        with capture_evidence() as recorder:
            async with create_client() as client:
                await client.get(SHODAN_URL)

    after = dt.datetime.now(dt.timezone.utc)
    record = recorder.records[0]

    assert record.observed_at == "2026-07-14T09:00:00Z"
    assert record.observed_at_source is ObservedAtSource.HTTP_DATE
    assert record.observed_at != record.queried_at

    queried = dt.datetime.fromisoformat(record.queried_at.replace("Z", "+00:00"))
    # queried_at is the SEND instant, so it may precede `before` by at most the round trip.
    assert before - dt.timedelta(seconds=5) <= queried <= after
    assert record.elapsed_ms is not None
    assert record.elapsed_ms >= 0.0


async def test_observed_at_is_absent_rather_than_guessed_when_the_provider_is_silent() -> None:
    """No ``Date`` header means the provider said nothing. Nothing is the honest record."""
    async with respx.mock(assert_all_called=True) as router:
        router.get(SHODAN_URL).respond(200, json={}, headers={"Date": ""})
        with capture_evidence() as recorder:
            async with create_client() as client:
                await client.get(SHODAN_URL)

    record = recorder.records[0]
    assert record.observed_at is None
    assert record.observed_at_source is None


async def test_a_malformed_date_header_costs_one_field_not_the_capture() -> None:
    async with respx.mock(assert_all_called=True) as router:
        router.get(SHODAN_URL).respond(200, json={}, headers={"Date": "not a date at all"})
        with capture_evidence() as recorder:
            async with create_client() as client:
                await client.get(SHODAN_URL)

    record = recorder.records[0]
    assert record.observed_at is None
    assert record.observed_at_source is None
    assert record.status_code == 200


def test_a_payload_timestamp_overrides_the_header_and_says_so() -> None:
    """``with_observed_at`` is how a provider attaches what only it can parse.

    VirusTotal's ``last_analysis_date`` is a claim about when the FACT was observed; a ``Date``
    header is only a claim about when the RESPONSE was generated. The payload value wins, and
    the source field records that it did — otherwise a reader cannot tell a months-old
    observation from a seconds-old one.
    """
    original = _mk(observed_at="2026-08-09T11:59:00Z", observed_at_source=ObservedAtSource.HTTP_DATE)
    updated = original.with_observed_at("2026-02-01T00:00:00Z", source=ObservedAtSource.PAYLOAD)

    assert updated.observed_at == "2026-02-01T00:00:00Z"
    assert updated.observed_at_source is ObservedAtSource.PAYLOAD
    # Frozen: the original record is a statement about something that already happened.
    assert original.observed_at == "2026-08-09T11:59:00Z"
    assert original.observed_at_source is ObservedAtSource.HTTP_DATE


def test_a_record_cannot_be_edited_in_place() -> None:
    record = _mk()
    with pytest.raises(ValidationError):
        record.status_code = 500  # type: ignore[misc]


# --------------------------------------------------------------------------------------
# Bodies: bounding, hashing, and marking what was done
# --------------------------------------------------------------------------------------


async def test_an_untouched_body_is_verbatim_and_hashes_to_its_own_bytes() -> None:
    payload = b'{"ports":[22,80,443]}'

    async with respx.mock(assert_all_called=True) as router:
        router.get(SHODAN_URL).respond(200, content=payload)
        with capture_evidence() as recorder:
            async with create_client() as client:
                await client.get(SHODAN_URL)

    record = recorder.records[0]
    assert record.body_transforms == []
    assert record.body_is_verbatim is True
    assert record.body_bytes == len(payload)
    assert record.body_sha256 == hashlib.sha256(payload).hexdigest()
    assert hashlib.sha256(record.body.encode("utf-8")).hexdigest() == record.body_sha256


async def test_a_truncated_body_is_marked_and_the_hash_still_covers_the_whole_response() -> None:
    """The rule that makes truncation safe: never hash the prefix.

    A hash of a truncated body is not a hash of the response, so the hash keeps covering the
    full bytes and ``body_transforms`` is what tells a reader the stored text is a prefix. The
    cache lane reads ``body_is_verbatim`` and refuses to replay this record.
    """
    payload = b"x" * 5_000

    async with respx.mock(assert_all_called=True) as router:
        router.get(SHODAN_URL).respond(200, content=payload)
        with capture_evidence(EvidenceRecorder(max_body_bytes=100)) as recorder:
            async with create_client() as client:
                await client.get(SHODAN_URL)

    record = recorder.records[0]
    assert record.body_transforms == [TRANSFORM_TRUNCATED]
    assert record.body_is_verbatim is False
    assert len(record.body) == 100
    assert record.body_bytes == 5_000
    assert record.body_sha256 == hashlib.sha256(payload).hexdigest()
    assert hashlib.sha256(record.body.encode("utf-8")).hexdigest() != record.body_sha256


async def test_max_body_bytes_zero_keeps_the_metadata_and_stores_no_payload() -> None:
    """The legitimate mode where the payloads themselves are what must not hit disk."""
    payload = b'{"secret_looking":"provider payload"}'

    async with respx.mock(assert_all_called=True) as router:
        router.get(SHODAN_URL).respond(200, content=payload)
        with capture_evidence(EvidenceRecorder(max_body_bytes=0)) as recorder:
            async with create_client() as client:
                await client.get(SHODAN_URL)

    record = recorder.records[0]
    assert record.body == ""
    assert record.body_bytes == len(payload)
    assert record.body_sha256 == hashlib.sha256(payload).hexdigest()
    assert record.body_transforms == [TRANSFORM_TRUNCATED]


async def test_an_undecodable_body_is_marked_lossy_rather_than_dropped() -> None:
    payload = b"\xff\xfe\x00 not utf-8"

    async with respx.mock(assert_all_called=True) as router:
        router.get(SHODAN_URL).respond(200, content=payload)
        with capture_evidence() as recorder:
            async with create_client() as client:
                await client.get(SHODAN_URL)

    record = recorder.records[0]
    assert TRANSFORM_LOSSY_DECODE in record.body_transforms
    assert record.body_is_verbatim is False
    assert record.body_sha256 == hashlib.sha256(payload).hexdigest()


def test_transforms_accumulate_and_are_sorted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Truncating mid-codepoint produces two transforms at once. Both must be recorded.

    Sorted so the serialised record is deterministic: the list is a set of facts, and its order
    must not depend on the order the code happened to discover them.
    """
    monkeypatch.setenv("SHODAN_API_KEY", FAKE_KEY)
    raw = (f'{{"e":"{FAKE_KEY}","pad":"' + "é" * 50 + '"}').encode("utf-8")

    body, body_bytes, digest, transforms = ev._body_fields(raw, max_body_bytes=45)

    assert transforms == sorted(transforms)
    assert TRANSFORM_TRUNCATED in transforms
    assert TRANSFORM_REDACTED in transforms
    assert body_bytes == len(raw)
    assert digest == hashlib.sha256(raw).hexdigest()
    assert FAKE_KEY not in body


# --------------------------------------------------------------------------------------
# Determinism — the cache lane hashes and diffs these
# --------------------------------------------------------------------------------------


def test_canonical_json_is_key_sorted_and_stable() -> None:
    record = _mk(response_headers={"date": "x", "content-type": "application/json"})
    first = record.canonical_json()
    assert first == record.canonical_json()

    keys = list(json.loads(first).keys())
    assert keys == sorted(keys)
    # Compact separators: no whitespace anywhere, so the hash cannot move on formatting alone.
    assert first.startswith('{"body":""')
    assert '", "' not in first and '": "' not in first


def test_two_identical_records_hash_identically() -> None:
    assert _mk().envelope_sha256() == _mk().envelope_sha256()


def test_one_changed_field_changes_the_envelope_hash() -> None:
    assert _mk().envelope_sha256() != _mk(status_code=500).envelope_sha256()


def test_header_capture_order_does_not_affect_the_hash() -> None:
    """httpx preserves wire order, which is not stable between HTTP/1.1 and HTTP/2.

    If header order reached the serialisation, the same response over two protocols would
    produce two different envelope hashes and every diff would be noise.
    """
    ordered = ev._filter_headers(
        httpx.Headers([("date", "d"), ("content-type", "ct"), ("etag", "e")]),
        CAPTURED_RESPONSE_HEADERS,
    )
    reversed_ = ev._filter_headers(
        httpx.Headers([("etag", "e"), ("content-type", "ct"), ("date", "d")]),
        CAPTURED_RESPONSE_HEADERS,
    )
    assert list(ordered) == list(reversed_) == ["content-type", "date", "etag"]
    assert _mk(response_headers=ordered).envelope_sha256() == _mk(response_headers=reversed_).envelope_sha256()


def test_to_json_is_indented_and_sorted_for_diffing() -> None:
    rendered = _mk().to_json()
    lines = rendered.splitlines()
    assert lines[0] == "{"
    assert '"body"' in lines[1]  # sorted: `body` is the first key alphabetically


# --------------------------------------------------------------------------------------
# Cache identity
# --------------------------------------------------------------------------------------


def test_the_cache_key_is_the_fact_asked_not_the_credential_used() -> None:
    """A rotated API key must not invalidate the cache.

    The key is built from the REDACTED url, so two runs under two credentials asking the same
    question produce the same identity — which is correct, because the credential is not part
    of what was asked.
    """
    first = _mk(url=f"https://api.shodan.io/shodan/host/93.184.216.34?key={REDACTED}")
    second = _mk(url=f"https://api.shodan.io/shodan/host/93.184.216.34?key={REDACTED}")
    assert first.cache_key == second.cache_key


def test_the_cache_key_separates_different_indicators() -> None:
    first = _mk(url="https://api.shodan.io/shodan/host/93.184.216.34")
    second = _mk(url="https://api.shodan.io/shodan/host/198.51.100.7")
    assert first.cache_key != second.cache_key


async def test_a_post_query_records_its_body_hash_but_never_its_body() -> None:
    """Cloudflare Radar and abuse.ch send the query in the body, so the URL alone is not identity.

    The bytes themselves are not stored: nothing downstream needs them back, and not storing
    them means no future provider can leak a credential through a request body.
    """
    endpoint = "https://api.cloudflare.com/client/v4/graphql"
    query = {"query": "{ viewer { asn(asn: 15133) { name } } }"}

    async with respx.mock(assert_all_called=True) as router:
        route = router.post(endpoint).respond(200, json={"data": {}})
        with capture_evidence() as recorder:
            async with create_client() as client:
                await client.post(endpoint, json=query)

    sent = route.calls.last.request.content
    record = recorder.records[0]
    assert record.method == "POST"
    assert record.request_body_sha256 == hashlib.sha256(sent).hexdigest()
    # The bytes themselves are nowhere in the record.
    assert "viewer" not in record.canonical_json()


def test_a_get_has_no_request_body_hash() -> None:
    assert _mk().request_body_sha256 is None


# --------------------------------------------------------------------------------------
# Recorder bounds and multi-hop capture
# --------------------------------------------------------------------------------------


async def test_every_redirect_hop_gets_its_own_record() -> None:
    """RDAP follows redirects. Each hop is a separate exchange with a separate provider.

    One record per hop is the honest shape: the bootstrap file and the authoritative registry
    are different third parties that learned different things (docs/OPSEC.md section 2).
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get("https://data.iana.org/rdap/dns.json").respond(
            302, headers={"Location": "https://rdap.verisign.com/com/v1/domain/example.com"}
        )
        router.get("https://rdap.verisign.com/com/v1/domain/example.com").respond(200, json={"ldhName": "example.com"})

        with capture_evidence() as recorder:
            async with create_client() as client:
                await client.get("https://data.iana.org/rdap/dns.json", follow_redirects=True)

    hosts = [r.host for r in recorder.records]
    assert hosts == ["data.iana.org", "rdap.verisign.com"]
    assert [r.status_code for r in recorder.records] == [302, 200]


async def test_a_full_recorder_drops_records_and_counts_them() -> None:
    """Overflow must be visible. An evidence set that is quietly incomplete is the same class
    of lie as a cached fact presented as fresh."""
    async with respx.mock(assert_all_called=True) as router:
        router.get(SHODAN_URL).respond(200, json={})
        router.get(IPINFO_URL).respond(200, json={})

        with capture_evidence(EvidenceRecorder(max_records=1)) as recorder:
            async with create_client() as client:
                await client.get(SHODAN_URL)
                await client.get(IPINFO_URL)

    assert len(recorder.records) == 1
    assert recorder.dropped == 1
    assert recorder.is_complete is False


def test_a_recorder_with_nothing_dropped_reports_itself_complete() -> None:
    recorder = EvidenceRecorder()
    assert recorder.is_complete is True
    assert recorder.dropped == 0
    assert len(recorder) == 0


@pytest.mark.parametrize(
    "kwargs",
    [{"max_body_bytes": -1}, {"max_records": 0}],
    ids=["negative-body-bound", "zero-record-bound"],
)
def test_a_nonsensical_bound_is_rejected_at_construction(kwargs: Dict[str, int]) -> None:
    with pytest.raises(ValueError):
        EvidenceRecorder(**kwargs)  # type: ignore[arg-type]


async def test_rate_limit_headers_are_captured_by_prefix() -> None:
    """Per-provider spellings, all of them counters. The quota work reads these."""
    async with respx.mock(assert_all_called=True) as router:
        router.get(SHODAN_URL).respond(
            200,
            json={},
            headers={
                "X-RateLimit-Remaining": "97",
                "RateLimit-Reset": "60",
                "X-Some-Other-Thing": "ignored",
            },
        )
        with capture_evidence() as recorder:
            async with create_client() as client:
                await client.get(SHODAN_URL)

    headers = recorder.records[0].response_headers
    assert headers["x-ratelimit-remaining"] == "97"
    assert headers["ratelimit-reset"] == "60"
    assert "x-some-other-thing" not in headers


async def test_records_are_returned_in_capture_order() -> None:
    urls: List[str] = [SHODAN_URL, IPINFO_URL, VT_URL]

    async with respx.mock(assert_all_called=True) as router:
        for url in urls:
            router.get(url).respond(200, json={})
        with capture_evidence() as recorder:
            async with create_client() as client:
                for url in urls:
                    await client.get(url)

    assert [r.url for r in recorder.records] == urls
