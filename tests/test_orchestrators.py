"""Regression tests for tripper_recon.orchestrators internals.

Two generations of fixes are pinned here. The W2/W3 section at the bottom covers the refactor:
the provider envelope, IP provenance tagging, the widened non-public-address guard, the
wall-clock deadline, and the fan-out that replaced the serial loops.

Covers the W0 fixes owned by this module (commit ae59d18):

* 0.1 — credential redaction on the error path (``_error_payload``). Pre-fix, the helper copied
  ``str(request.url)`` and ``str(exc)`` verbatim into the investigation result, so a Shodan or
  IPInfo key in the query string reached console output and ``-o json``.
* 0.4 — ``_should_suppress`` normalises non-string ``error`` / ``status`` values. Pre-fix, a
  Cloudflare GraphQL errors ARRAY hit ``err in {...}`` and raised
  ``TypeError: unhashable type: 'list'``.

Plus the standing input controls: ``investigate_ip`` refuses private and malformed addressing and
``investigate_asn`` refuses a non-numeric or out-of-range ASN — all without touching the network.

Every test runs inside a respx mock with no routes registered: any outbound request raises instead
of leaving the machine, which is what "passive-only" has to mean in a test suite.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
import respx

from tripper_recon import orchestrators
from tripper_recon.orchestrators import (
    MAX_CONCURRENT_IPS,
    MAX_CONCURRENT_NEIGHBOUR_LOOKUPS,
    _error_details,
    _error_payload,
    _error_summary,
    _should_suppress,
    _tag_ip_sources,
    investigate_asn,
    investigate_domain,
    investigate_ip,
    non_public_ip_reason,
)
from tripper_recon.utils import http
from tripper_recon.utils.http import PassiveBoundaryViolation
from tripper_recon.utils.redact import _SECRET_ENV_VARS, REDACTED

SECRET = "sk-tripperTESTSECRET-0123456789"


@pytest.fixture(autouse=True)
def clean_secret_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every credential env var so redaction behaviour is deterministic.

    ``redact._known_secrets()`` reads the live environment. Without this, a key present in the
    operator's shell would change what these tests exercise, and a test that only passes on a
    machine with keys loaded is not a regression net.
    """
    for name in _SECRET_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


@asynccontextmanager
async def no_network() -> AsyncIterator[respx.MockRouter]:
    """Assert the enclosed code makes zero HTTP requests.

    No routes are registered, so respx raises ``AllMockedAssertionError`` on any request rather
    than allowing it out. The trailing call-count assertion catches anything respx recorded.
    """
    async with respx.mock(assert_all_called=False) as router:
        yield router
        assert router.calls.call_count == 0, "passive-only violation: an HTTP request was attempted"


def _serialised(payload: dict[str, Any]) -> str:
    return json.dumps(payload, default=str)


# ---------------------------------------------------------------------------
# 0.1 — credential redaction on the error path
# ---------------------------------------------------------------------------


def test_error_payload_redacts_credential_from_http_status_error() -> None:
    """Pre-fix: both ``url`` and ``message`` carried ``key=<the real API key>`` verbatim."""
    url = f"https://api.shodan.io/shodan/host/8.8.8.8?key={SECRET}"
    request = httpx.Request("GET", url)
    response = httpx.Response(429, request=request)
    exc = httpx.HTTPStatusError(
        f"Client error '429 Too Many Requests' for url '{url}'",
        request=request,
        response=response,
    )

    payload = _error_payload(exc)

    assert payload["ok"] is False
    assert payload["error"] == "http_error"
    assert payload["status_code"] == 429
    # The whole serialised payload, not just the url field: the key is embedded in str(exc) too.
    assert SECRET not in _serialised(payload)
    assert REDACTED in payload["url"]
    assert REDACTED in payload["message"]
    # Redaction must not destroy the diagnostic value of the payload.
    assert "api.shodan.io" in payload["url"]


def test_error_payload_redacts_credential_from_request_error() -> None:
    """network_error branch. Pre-fix this branch was unredacted too."""
    url = f"https://ipinfo.io/8.8.8.8/json?token={SECRET}"
    request = httpx.Request("GET", url)
    exc = httpx.ConnectError(f"[Errno -2] Name or service not known while requesting {url}", request=request)

    payload = _error_payload(exc)

    assert payload["ok"] is False
    assert payload["error"] == "network_error"
    assert SECRET not in _serialised(payload)
    assert REDACTED in payload["url"]
    assert REDACTED in payload["message"]


def test_error_payload_redacts_credential_from_plain_exception_url() -> None:
    """Generic branch: a URL embedded in an arbitrary exception message is still redacted."""
    url = f"https://api.shodan.io/shodan/host/8.8.8.8?key={SECRET}"
    payload = _error_payload(ValueError(f"unparseable response from {url}"))

    assert payload["ok"] is False
    assert payload["error"] == "ValueError"
    assert SECRET not in _serialised(payload)
    assert REDACTED in payload["message"]


def test_error_payload_redacts_bare_env_secret_from_plain_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    """Literal redaction: a known key value is scrubbed even when it is not in a URL.

    This is the defence-in-depth half of 0.1 — a credential that arrives by a route the URL
    parser does not anticipate (a header echo, a provider error body) still never reaches output.
    """
    monkeypatch.setenv("SHODAN_API_KEY", SECRET)

    payload = _error_payload(RuntimeError(f"provider rejected credential {SECRET} (quota)"))

    assert SECRET not in _serialised(payload)
    assert REDACTED in payload["message"]


def test_error_payload_leaves_unrelated_query_params_intact() -> None:
    """Only credential-named parameters are redacted; context survives for triage."""
    url = f"https://api.shodan.io/shodan/host/8.8.8.8?key={SECRET}&minify=true"
    request = httpx.Request("GET", url)
    response = httpx.Response(401, request=request)
    exc = httpx.HTTPStatusError("401 Unauthorized", request=request, response=response)

    payload = _error_payload(exc)

    assert SECRET not in _serialised(payload)
    assert "minify=true" in payload["url"]


def test_error_payload_survives_request_error_without_request() -> None:
    """Regression: httpx implements .request as a property that RAISES when unset, and
    getattr's default only swallows AttributeError -- so the naive getattr made the error
    handler itself crash. Fixed by orchestrators._safe_request_url."""
    payload = _error_payload(httpx.ConnectError("connection refused"))
    assert payload["error"] == "network_error"


# ---------------------------------------------------------------------------
# 0.4 — _should_suppress normalises non-string error / status values
# ---------------------------------------------------------------------------


def test_should_suppress_with_list_error_returns_bool() -> None:
    """Cloudflare answers HTTP 200 with a GraphQL ``errors`` ARRAY.

    Pre-fix: ``err in {"missing_api_key", ...}`` raised TypeError: unhashable type: 'list',
    which propagated out of the provider loop and killed the whole investigation.
    """
    payload = {
        "ok": False,
        "error": [{"message": "field 'asn' is not defined", "path": ["viewer"]}],
    }

    result = _should_suppress("cloudflare_asn", payload)

    assert isinstance(result, bool)
    assert result is False  # an unrecognised error shape is surfaced, never silently swallowed


def test_should_suppress_with_dict_error_returns_bool() -> None:
    payload = {"ok": False, "error": {"code": 1006, "message": "invalid token"}}

    result = _should_suppress("cloudflare_bgp", payload)

    assert isinstance(result, bool)
    assert result is False


def test_should_suppress_with_list_status_returns_bool() -> None:
    """``status`` reaching the ``in {401, 403}`` membership test as a list.

    Pre-fix this raised TypeError on the ipinfo_asn branch, which is the one branch that tests
    status membership against a set.
    """
    payload = {"ok": False, "error": "http_error", "status": [401]}

    result = _should_suppress("ipinfo_asn", payload)

    assert isinstance(result, bool)
    assert result is False


@pytest.mark.parametrize(
    ("provider", "payload", "expected"),
    [
        # Suppressed: the operator never supplied a key, so this is configuration, not a failure.
        ("virustotal", {"ok": False, "error": "missing_api_key"}, True),
        ("cloudflare_asn", {"ok": False, "error": "missing_api_token"}, True),
        ("shodan", {"ok": False, "error": "API key not configured"}, True),
        # Suppressed: IPinfo's free tier rejects ASN lookups; that is expected, not an incident.
        ("ipinfo_asn", {"ok": False, "error": "http_error", "status_code": 401}, True),
        ("ipinfo_asn", {"ok": False, "error": "unauthorized", "status": 403}, True),
        # Suppressed: Cloudflare's GraphQL endpoint answers 400 for an unknown ASN.
        ("cloudflare_bgp", {"ok": False, "error": "http_error", "status_code": 400}, True),
        # Suppressed: RIPEstat is best-effort enrichment.
        ("ripe_overview", {"ok": False, "error": "network_error"}, True),
        ("ripe_prefixes", {"ok": False, "error": "network_error"}, True),
        # NOT suppressed: a genuine server-side failure must reach the analyst.
        ("virustotal", {"ok": False, "error": "http_error", "status_code": 500}, False),
        ("ipinfo_asn", {"ok": False, "error": "http_error", "status_code": 500}, False),
        ("ripe_overview", {"ok": False, "error": "http_error", "status_code": 503}, False),
        ("cloudflare_asn", {"ok": False, "error": "http_error", "status_code": 500}, False),
        # A successful or empty payload is never a suppression candidate.
        ("virustotal", {"ok": True, "data": {}}, False),
        ("virustotal", {}, False),
    ],
)
def test_should_suppress_string_cases(provider: str, payload: dict[str, Any], expected: bool) -> None:
    assert _should_suppress(provider, payload) is expected


def test_should_suppress_does_not_generalise_ipinfo_401_to_other_providers() -> None:
    """The 401/403 carve-out is scoped to ipinfo_asn; a VT 401 is a real problem."""
    payload = {"ok": False, "error": "http_error", "status_code": 401}

    assert _should_suppress("ipinfo_asn", payload) is True
    assert _should_suppress("virustotal", payload) is False


# ---------------------------------------------------------------------------
# _error_details / _error_summary on the same awkward shapes
# ---------------------------------------------------------------------------


def test_error_details_drops_ok_and_none_fields() -> None:
    payload = {"ok": False, "error": "http_error", "status_code": 500, "reason": None, "url": None}

    assert _error_details(payload) == {"error": "http_error", "status_code": 500}


def test_error_details_preserves_non_string_error_shapes() -> None:
    payload = {"ok": False, "error": [{"message": "bad field"}]}

    assert _error_details(payload) == {"error": [{"message": "bad field"}]}


def test_error_summary_with_list_error_does_not_raise() -> None:
    payload = {"ok": False, "error": [{"message": "bad field"}], "message": "graphql rejected the query"}

    summary = _error_summary("cloudflare_asn", payload)

    assert isinstance(summary, str)
    assert summary.startswith("cloudflare_asn")
    assert "graphql rejected the query" in summary


def test_error_summary_with_list_status_does_not_raise() -> None:
    payload = {"ok": False, "error": "http_error", "status": [503], "message": "upstream down"}

    summary = _error_summary("ripe_overview", payload)

    assert isinstance(summary, str)
    assert "503" in summary
    assert "upstream down" in summary


def test_error_summary_uses_status_code_when_status_absent() -> None:
    payload = {"ok": False, "error": "http_error", "status_code": 429, "reason": "Too Many Requests"}

    summary = _error_summary("shodan", payload)

    assert summary == "shodan | 429 | Too Many Requests"


def test_error_summary_does_not_repeat_an_identical_message() -> None:
    payload = {"ok": False, "error": "http_error", "status_code": 429, "reason": "boom", "message": "boom"}

    assert _error_summary("shodan", payload) == "shodan | 429 | boom"


def test_error_summary_of_a_redacted_payload_carries_no_credential() -> None:
    """The summary is what lands in InvestigationResult.errors and on the console."""
    url = f"https://api.shodan.io/shodan/host/8.8.8.8?key={SECRET}"
    request = httpx.Request("GET", url)
    response = httpx.Response(401, request=request)
    exc = httpx.HTTPStatusError(f"401 Unauthorized for url '{url}'", request=request, response=response)

    summary = _error_summary("shodan", _error_payload(exc))

    assert SECRET not in summary
    assert REDACTED in summary


# ---------------------------------------------------------------------------
# investigate_ip — private and malformed addressing is refused before any request
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ip", ["10.0.0.1", "192.168.1.1", "127.0.0.1", "172.16.0.5", "169.254.1.1", "::1"])
async def test_investigate_ip_refuses_private_addressing(ip: str) -> None:
    """RFC1918 / loopback / link-local targets must never be sent to a third-party provider.

    Leaking internal addressing to VirusTotal or Shodan is an operational disclosure, and the
    answer would be worthless anyway.
    """
    async with no_network():
        result = await investigate_ip(ip)

    assert result.ok is False
    assert result.data == {}
    assert result.errors
    assert ip in result.errors[0]
    assert "rivate" in result.errors[0]


@pytest.mark.parametrize("ip", ["not-an-ip", "8.8.8", "999.999.999.999", "", "8.8.8.8/24", "8.8.8.8:443"])
async def test_investigate_ip_rejects_malformed_input(ip: str) -> None:
    async with no_network():
        result = await investigate_ip(ip)

    assert result.ok is False
    assert result.errors == ["Invalid IP address"]
    assert result.data == {}


async def test_investigate_ip_accepts_a_public_address_as_far_as_the_guard() -> None:
    """Control for the two tests above: a public address is NOT rejected by the input guard.

    Every provider call is refused by respx rather than by validation, so the run comes back
    ``ok=True`` with per-provider errors. That is how we know the private-IP tests are exercising
    the guard rather than a blanket refusal of everything.
    """
    async with respx.mock(assert_all_called=False):
        result = await investigate_ip("8.8.8.8")

    assert result.ok is True


# ---------------------------------------------------------------------------
# investigate_asn — non-numeric / out-of-range ASNs are refused before any request
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("asn", ["AS15169", "notanasn", "", "1.5", 0, -1, "-1", 2**32, 2**32 + 1, None])
async def test_investigate_asn_rejects_invalid_asn(asn: Any) -> None:
    async with no_network():
        result = await investigate_asn(asn)

    assert result.ok is False
    assert result.errors == ["Invalid ASN"]
    assert result.data == {}


async def test_investigate_asn_accepts_a_valid_asn_as_far_as_the_guard() -> None:
    """Control: 15169 passes validation and is stopped only by the network mock, not by the guard."""
    async with respx.mock(assert_all_called=False):
        result = await investigate_asn(15169)

    assert result.ok is True
    assert result.data["asn"] == 15169
    # Every provider was refused by respx, so each one that ran reports an error.
    assert result.errors


# =======================================================================================
# W2 / W3 — the refactor
# =======================================================================================


@pytest.fixture
def unlimited_rate() -> Iterator[None]:
    """Lift the concurrency ceiling for tests that measure parallelism, then put it back.

    ``configure_rate_limit`` mutates a module global that outlives the test. Several tests
    below assert an exact peak concurrency; with the default ceiling of 10 in force they would
    be measuring the limiter rather than the fan-out they are meant to check.
    """
    saved = http._configured_rate
    http.configure_rate_limit(500)
    try:
        yield
    finally:
        http._configured_rate = saved


class _Probe:
    """Counts concurrent entries and records the high-water mark."""

    def __init__(self) -> None:
        self.current = 0
        self.peak = 0
        self.total = 0

    @asynccontextmanager
    async def track(self) -> AsyncIterator[None]:
        self.current += 1
        self.total += 1
        self.peak = max(self.peak, self.current)
        try:
            yield
        finally:
            self.current -= 1


def _ok(**data: Any) -> dict[str, Any]:
    return {"ok": True, "data": dict(data)}


def _slow_provider(probe: _Probe, *, hold: float = 0.02, **data: Any) -> Callable[..., Any]:
    """A stand-in provider that reports when it is in flight."""

    async def _call(**_kwargs: Any) -> dict[str, Any]:
        async with probe.track():
            await asyncio.sleep(hold)
        return _ok(**data)

    return _call


# ---------------------------------------------------------------------------
# 2.4 — the non-public guard is wider than is_private
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ip", ["224.0.0.1", "239.255.255.250", "233.252.0.1", "ff02::1"])
async def test_investigate_ip_refuses_multicast_addressing(ip: str) -> None:
    """``is_private`` covers neither 224/4 nor ff00::/8, so these reached five providers.

    Multicast addressing in an indicator list is a misconfiguration or an internal capture, and
    forwarding it discloses the operator's own network under the operator's own API keys.
    """
    async with no_network():
        result = await investigate_ip(ip)

    assert result.ok is False
    assert result.data == {}
    assert result.errors == [f"Multicast IP address {ip} cannot be investigated."]


@pytest.mark.parametrize("ip", ["10.0.0.1", "127.0.0.1", "169.254.1.1", "::1", "0.0.0.0", "240.0.0.1"])
async def test_investigate_ip_still_refuses_everything_it_refused_before(ip: str) -> None:
    """The widened guard must not have narrowed anywhere. These all report as private."""
    async with no_network():
        result = await investigate_ip(ip)

    assert result.ok is False
    assert result.errors == [f"Private IP address {ip} cannot be investigated."]


@pytest.mark.parametrize("ip", ["8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"])
def test_non_public_ip_reason_passes_public_space(ip: str) -> None:
    assert non_public_ip_reason(ip) is None


def test_non_public_ip_reason_leaves_parsing_to_the_validator() -> None:
    """An unparseable string is not this function's failure to report -- ``is_valid_ip`` runs
    first and rejects it with the message the tests above pin."""
    assert non_public_ip_reason("not-an-ip") is None


# ---------------------------------------------------------------------------
# 2.3 — IP provenance
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("active", "passive", "expected"),
    [
        (["1.1.1.1"], [], [("1.1.1.1", "active")]),
        ([], ["1.1.1.1"], [("1.1.1.1", "passive")]),
        (["1.1.1.1"], ["1.1.1.1"], [("1.1.1.1", "active+passive")]),
        (
            ["1.1.1.1", "2.2.2.2"],
            ["2.2.2.2", "3.3.3.3"],
            [("1.1.1.1", "active"), ("2.2.2.2", "active+passive"), ("3.3.3.3", "passive")],
        ),
        # Duplicates within one source collapse, and active ordering is preserved.
        (["9.9.9.9", "9.9.9.9"], [], [("9.9.9.9", "active")]),
        ([], [], []),
    ],
)
def test_tag_ip_sources(active: list[str], passive: list[str], expected: list[tuple[str, str]]) -> None:
    """``ips = active_ips + passive_ips`` threw this away.

    "Resolved now" and "seen historically by VirusTotal" are different evidentiary claims: a
    passive-only address may be years stale, and an active-only address is one no passive
    source has corroborated. The verdict engine cannot recover the difference later.
    """
    assert _tag_ip_sources(active, passive) == expected


async def test_domain_entries_carry_their_provenance(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(orchestrators, "_ip_provider_wave", _fake_wave())
    monkeypatch.setattr("tripper_recon.utils.dns.resolve_domain", _fake_resolver(["1.1.1.1", "2.2.2.2"]))
    monkeypatch.setattr(orchestrators, "vt_domain_summary", _vt_domain_with_a_records(["2.2.2.2", "3.3.3.3"]))

    result = await investigate_domain("example.test")

    assert [(e["ip"], e["source"]) for e in result.data["ips"]] == [
        ("1.1.1.1", "active"),
        ("2.2.2.2", "active+passive"),
        ("3.3.3.3", "passive"),
    ]


async def test_domain_path_refuses_non_public_resolved_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    """Split-horizon DNS and sinkholes resolve to RFC1918 routinely.

    Pre-fix the domain path had no guard at all, so those addresses went straight to five
    third parties. They are now excluded, recorded with a reason, and warned about -- dropping
    them silently would be its own small lie.
    """
    monkeypatch.setattr(orchestrators, "_ip_provider_wave", _fake_wave())
    monkeypatch.setattr(
        "tripper_recon.utils.dns.resolve_domain",
        _fake_resolver(["10.0.0.5", "8.8.8.8", "224.0.0.1"]),
    )

    result = await investigate_domain("internal.example.test")

    assert [e["ip"] for e in result.data["ips"]] == ["8.8.8.8"]
    assert result.data["skipped_ips"] == [
        {"ip": "10.0.0.5", "source": "active", "reason": "private"},
        {"ip": "224.0.0.1", "source": "active", "reason": "multicast"},
    ]
    assert any("10.0.0.5" in w for w in result.warnings)
    assert any("224.0.0.1" in w for w in result.warnings)


# ---------------------------------------------------------------------------
# 3.6 — the provider envelope keeps "never asked" apart from "asked, came back clean"
# ---------------------------------------------------------------------------


async def test_provider_status_distinguishes_unconfigured_from_answered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The defect this envelope exists to prevent.

    ``data['virustotal'] == {}`` is what the renderer sees for a provider that answered with
    nothing, for one that errored, and for one that was never asked because no key is set.
    Those are not the same claim, and the last one is not evidence of anything.
    """
    monkeypatch.setenv("SHODAN_API_KEY", "shodan-key-0123456789")
    monkeypatch.setattr(orchestrators, "shodan_host", _fake_provider(_ok(ports=[443])))

    async with respx.mock(assert_all_called=False):
        result = await investigate_ip("8.8.8.8")

    status = result.data["provider_status"]

    # Answered.
    assert status["shodan"]["outcome"] == "ok"
    assert result.data["shodan"] == {"ports": [443]}

    # Never asked -- no credential. Same empty dict, entirely different meaning.
    assert result.data["virustotal"] == {}
    assert status["virustotal"]["outcome"] == "not_configured"
    assert status["virustotal"]["suppressed"] is True

    # Every provider is accounted for, and every one carries its cost.
    assert set(status) >= {"virustotal", "ipinfo", "shodan", "abuseipdb", "otx"}
    assert all("elapsed_seconds" in entry for entry in status.values())


async def test_provider_status_records_a_real_failure_with_its_redacted_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VT_API_KEY", "vt-key-0123456789")

    async with respx.mock(assert_all_called=False) as router:
        # 403, not a 5xx: a rejected credential is not retryable, so this test asserts the
        # envelope rather than sitting through utils.backoff's retry schedule.
        router.get(url__regex=r"https://www\.virustotal\.com/api/v3/ip_addresses/.*").respond(403)
        result = await investigate_ip("8.8.8.8")

    status = result.data["provider_status"]["virustotal"]
    assert status["outcome"] == "error"
    assert status.get("suppressed") is None
    assert status["error"]["status_code"] == 403
    # A non-suppressed failure still reaches the analyst, exactly as before the refactor.
    assert any(msg.startswith("virustotal | 403") for msg in result.errors)
    assert result.data["errors"]["virustotal"]["status_code"] == 403


async def test_asn_path_reports_every_provider_it_considered() -> None:
    async with respx.mock(assert_all_called=False):
        result = await investigate_asn(15169)

    assert set(result.data["provider_status"]) == {
        "ipinfo_asn",
        "ripe_overview",
        "ripe_abuse",
        "caida",
        "peeringdb",
        "ripe_routing_status",
        "ripe_neighbors",
        "ripe_prefixes",
        "cloudflare_bgp",
        "cloudflare_asn",
    }
    # No Cloudflare token in the environment, so both Cloudflare calls are configuration
    # rather than incidents -- recorded, and deliberately absent from the error list.
    assert result.data["provider_status"]["cloudflare_bgp"]["outcome"] == "not_configured"
    assert not any("cloudflare" in msg for msg in result.errors)


async def test_domain_path_reports_its_domain_level_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    # resolve_domain is stubbed even though this test does not care about addresses: it is the
    # one call in the package that leaves the machine without going through respx, and a test
    # suite for a passive tool must not emit a DNS query as a side effect.
    monkeypatch.setattr("tripper_recon.utils.dns.resolve_domain", _fake_resolver([]))

    async with respx.mock(assert_all_called=False):
        result = await investigate_domain("example.test")

    status = result.data["domain_provider_status"]
    assert status["virustotal"]["outcome"] == "not_configured"
    assert status["otx"]["outcome"] == "not_configured"


async def test_one_provider_raising_does_not_take_the_others_down(monkeypatch: pytest.MonkeyPatch) -> None:
    """The whole reason 23 try/except blocks existed. One helper now guarantees it everywhere."""
    monkeypatch.setenv("SHODAN_API_KEY", "shodan-key-0123456789")
    monkeypatch.setenv("OTX_API_KEY", "otx-key-0123456789")

    async def _explode(**_kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("provider module blew up")

    monkeypatch.setattr(orchestrators, "shodan_host", _explode)
    monkeypatch.setattr(orchestrators, "otx_ip_pulses", _fake_provider(_ok(otx_pulse_count=2)))

    async with respx.mock(assert_all_called=False):
        result = await investigate_ip("8.8.8.8")

    assert result.ok is True
    assert result.data["otx"] == {"otx_pulse_count": 2}
    assert result.data["provider_status"]["shodan"]["outcome"] == "error"
    assert result.data["provider_status"]["shodan"]["error"]["error"] == "RuntimeError"


# ---------------------------------------------------------------------------
# 3.7 — per-target wall-clock deadline
# ---------------------------------------------------------------------------


async def test_investigate_ip_reports_a_deadline_breach_instead_of_hanging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """There was no elapsed-time awareness anywhere; OTX alone has a ~84s worst case."""

    async def _never_returns(**_kwargs: Any) -> dict[str, Any]:
        await asyncio.sleep(30)
        raise AssertionError("unreachable")

    monkeypatch.setattr(orchestrators, "_ip_provider_wave", _never_returns)

    started = time.monotonic()
    result = await investigate_ip("8.8.8.8", deadline=0.05)
    elapsed = time.monotonic() - started

    assert result.ok is False
    assert result.data == {}
    assert "deadline" in result.errors[0]
    assert "8.8.8.8" in result.errors[0]
    assert elapsed < 5.0, f"the deadline did not fire; waited {elapsed:.2f}s"


@pytest.mark.parametrize(
    ("call", "target"),
    [
        (lambda: investigate_domain("example.test", deadline=0.05), "example.test"),
        (lambda: investigate_asn(15169, deadline=0.05), "AS15169"),
    ],
    ids=["domain", "asn"],
)
async def test_every_entry_point_carries_a_deadline(
    monkeypatch: pytest.MonkeyPatch, call: Callable[[], Any], target: str
) -> None:
    async def _never_returns(*_args: Any, **_kwargs: Any) -> Any:
        await asyncio.sleep(30)
        raise AssertionError("unreachable")

    monkeypatch.setattr(orchestrators, "vt_domain_summary", _never_returns)
    monkeypatch.setattr(orchestrators, "as_overview", _never_returns)
    # Structurally unreachable behind the hanging domain-level wave, but stubbed anyway: no
    # test may depend on timing to avoid emitting a real DNS query.
    monkeypatch.setattr("tripper_recon.utils.dns.resolve_domain", _fake_resolver([]))

    result = await call()

    assert result.ok is False
    assert target in result.errors[0]
    assert "deadline" in result.errors[0]


async def test_a_non_positive_deadline_disables_the_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit zero is an opt-out, not a zero-second budget."""
    monkeypatch.setattr(orchestrators, "_ip_provider_wave", _fake_wave())

    result = await investigate_ip("8.8.8.8", deadline=0)

    assert result.ok is True


# ---------------------------------------------------------------------------
# 3.8 / 3.9 — the fan-out
# ---------------------------------------------------------------------------


async def test_the_five_per_ip_providers_run_in_one_wave(monkeypatch: pytest.MonkeyPatch, unlimited_rate: None) -> None:
    probe = _Probe()
    for attribute in ("vt_ip_summary", "ipinfo_ip", "shodan_host", "abuseipdb_check", "otx_ip_pulses"):
        monkeypatch.setattr(orchestrators, attribute, _slow_provider(probe))

    result = await investigate_ip("8.8.8.8")

    assert result.ok is True
    assert probe.peak == 5, f"providers ran {probe.peak}-at-a-time; the wave is still partly serial"


async def test_domain_ips_are_enriched_concurrently(monkeypatch: pytest.MonkeyPatch, unlimited_rate: None) -> None:
    """Pre-fix: five bare awaits per IP, inside a serial loop over IPs. Both levels serial."""
    probe = _Probe()
    monkeypatch.setattr(orchestrators, "_ip_provider_wave", _fake_wave(probe))
    monkeypatch.setattr(
        "tripper_recon.utils.dns.resolve_domain",
        _fake_resolver([f"8.8.8.{n}" for n in range(1, 7)]),
    )

    result = await investigate_domain("example.test")

    assert len(result.data["ips"]) == 6
    assert probe.peak == 6, f"IPs were enriched {probe.peak}-at-a-time; the loop is still serial"


async def test_domain_fan_out_is_bounded(monkeypatch: pytest.MonkeyPatch, unlimited_rate: None) -> None:
    """A domain with many A records must not create unbounded work.

    The concurrency ceiling is lifted for this test precisely so the bound being measured is
    ``MAX_CONCURRENT_IPS`` and not the rate limiter standing in for it.
    """
    probe = _Probe()
    monkeypatch.setattr(orchestrators, "_ip_provider_wave", _fake_wave(probe))
    monkeypatch.setattr(
        "tripper_recon.utils.dns.resolve_domain",
        _fake_resolver([f"8.8.{n // 250}.{n % 250}" for n in range(1, 41)]),
    )

    result = await investigate_domain("bigfanout.example.test")

    assert len(result.data["ips"]) == 40
    assert probe.peak == MAX_CONCURRENT_IPS


async def test_asn_providers_run_in_one_wave(monkeypatch: pytest.MonkeyPatch, unlimited_rate: None) -> None:
    """Pre-fix: wave 1 was fully drained before routing-status, neighbours and prefixes were
    even created, and those three depend on nothing in wave 1."""
    probe = _Probe()
    for attribute in (
        "ipinfo_asn",
        "as_overview",
        "abuse_contact",
        "caida_asrank",
        "peeringdb_ixps_for_asn",
        "routing_status",
        "asn_neighbours",
        "announced_prefixes",
        "bgp_incidents",
        "fetch_asn_metadata",
    ):
        monkeypatch.setattr(orchestrators, attribute, _slow_provider(probe))

    result = await investigate_asn(15169)

    assert result.ok is True
    assert probe.peak == 10, f"the ASN path ran {probe.peak}-at-a-time; it is still two waves"


async def test_neighbour_resolution_is_bounded(monkeypatch: pytest.MonkeyPatch, unlimited_rate: None) -> None:
    """``--neighbors 8`` asks for up to 24 lookups; they used to gather unbounded."""
    neighbours = [
        *({"asn": 100 + n, "type": "left"} for n in range(10)),
        *({"asn": 200 + n, "type": "right"} for n in range(10)),
        *({"asn": 300 + n, "type": "uncertain"} for n in range(10)),
    ]
    probe = _Probe()

    async def _overview(*, client: Any, asn: int) -> dict[str, Any]:
        async with probe.track():
            await asyncio.sleep(0.01)
        return _ok(holder=f"AS{asn} - Example Network")

    monkeypatch.setattr(orchestrators, "as_overview", _overview)
    monkeypatch.setattr(orchestrators, "asn_neighbours", _fake_provider(_ok(neighbours=neighbours)))

    result = await investigate_asn(15169, resolve_neighbors=8)

    assert probe.peak <= MAX_CONCURRENT_NEIGHBOUR_LOOKUPS
    # One call in the main wave, then 8 upstream + 8 downstream + 8 uncertain.
    assert probe.total == 25
    assert result.data["bgp"]["ripe_upstream_named"][0] == "Example Network (100)"


# ---------------------------------------------------------------------------
# Helpers used by the section above
# ---------------------------------------------------------------------------


def _fake_provider(payload: dict[str, Any]) -> Callable[..., Any]:
    async def _call(**_kwargs: Any) -> dict[str, Any]:
        return payload

    return _call


def _fake_resolver(addresses: list[str]) -> Callable[..., Any]:
    async def _resolve(_domain: str) -> list[str]:
        return list(addresses)

    return _resolve


def _fake_wave(probe: _Probe | None = None) -> Callable[..., Any]:
    """Stand in for ``_ip_provider_wave`` with five providers that answered emptily."""

    async def _wave(*, client: Any, keys: Any, ip: str) -> dict[str, Any]:
        if probe is None:
            return _empty_calls()
        async with probe.track():
            await asyncio.sleep(0.02)
        return _empty_calls()

    return _wave


def _empty_calls() -> dict[str, Any]:
    return {
        name: orchestrators._envelope(name, _ok(), 0.0)
        for name in ("virustotal", "ipinfo", "shodan", "abuseipdb", "otx")
    }


def _vt_domain_with_a_records(addresses: list[str]) -> Callable[..., Any]:
    records = [{"type": "A", "value": address} for address in addresses]
    return _fake_provider(_ok(vt_dns_records=records))


async def test_a_boundary_violation_is_not_downgraded_to_a_provider_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The one exception ``_call_provider`` must not absorb.

    A ``PassiveBoundaryViolation`` means the tool tried to contact a host nobody approved --
    most plausibly the target itself. Filing that as one more entry in ``result.errors``, beside
    a routine 500, would take the loudest signal in the codebase and make it look like noise.
    """

    async def _off_boundary(**_kwargs: Any) -> dict[str, Any]:
        raise PassiveBoundaryViolation("target-under-investigation.test", "https://REDACTED/")

    monkeypatch.setattr(orchestrators, "vt_ip_summary", _off_boundary)

    with pytest.raises(PassiveBoundaryViolation):
        await investigate_ip("8.8.8.8")
