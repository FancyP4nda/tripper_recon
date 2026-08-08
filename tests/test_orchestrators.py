"""Regression tests for tripper_recon.orchestrators internals.

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

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
import respx

from tripper_recon.orchestrators import (
    _error_details,
    _error_payload,
    _error_summary,
    _should_suppress,
    investigate_asn,
    investigate_ip,
)
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
