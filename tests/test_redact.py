"""Tests for tripper_recon.utils.redact (W0 fix 0.1).

Pre-fix behaviour for every test in this file: ``utils/redact.py`` did not exist. Shodan and
IPInfo authenticate in the query string, so ``str(request.url)`` and ``str(HTTPStatusError)``
both carried the API key verbatim, and ``orchestrators._error_payload`` copied both into the
investigation result -- which reaches console output and ``-o json``. Every assertion below
that a secret is absent from the output is an assertion that would have failed before the fix.

No test here touches the network. ``httpx.Response`` objects are constructed in-process.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from tripper_recon.utils.redact import REDACTED, redact_text, redact_url

SHODAN_URL = "https://api.shodan.io/shodan/host/93.184.216.34?key=sk_live_0123456789abcdef"
FAKE_KEY = "sk_live_0123456789abcdef"


# --------------------------------------------------------------------------------------
# redact_url: sensitive query parameters
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "param",
    [
        "key",
        "apikey",
        "api_key",
        "token",
        "access_token",
        "auth",
        "auth_key",
        "secret",
        "password",
        "passwd",
        "pwd",
    ],
)
def test_redact_url_strips_each_sensitive_param(param: str) -> None:
    """Every name in _SENSITIVE_PARAMS has its value replaced, not merely masked in part."""
    url = f"https://api.example.com/v1/host?{param}={FAKE_KEY}"

    result = redact_url(url)

    assert FAKE_KEY not in result
    assert parse_qs(urlsplit(result).query)[param] == [REDACTED]


@pytest.mark.parametrize("param", ["KEY", "Token", "Api_Key", "ACCESS_TOKEN", "SeCrEt"])
def test_redact_url_param_matching_is_case_insensitive(param: str) -> None:
    """Providers are inconsistent about case; matching is on the lowercased name."""
    url = f"https://api.example.com/v1/host?{param}={FAKE_KEY}"

    result = redact_url(url)

    assert FAKE_KEY not in result
    # The parameter name itself keeps its original case -- only the value changes.
    assert f"{param}={REDACTED}" in result


def test_redact_url_preserves_non_sensitive_params_and_the_rest_of_the_url() -> None:
    """Redaction is surgical. A redacted URL must still be useful for debugging."""
    url = (
        "https://api.abuseipdb.com/api/v2/check"
        f"?ipAddress=93.184.216.34&maxAgeInDays=365&key={FAKE_KEY}&verbose=true#frag"
    )

    result = redact_url(url)
    parts = urlsplit(result)
    query = parse_qs(parts.query)

    assert FAKE_KEY not in result
    assert parts.scheme == "https"
    assert parts.netloc == "api.abuseipdb.com"
    assert parts.path == "/api/v2/check"
    assert parts.fragment == "frag"
    assert query["ipAddress"] == ["93.184.216.34"]
    assert query["maxAgeInDays"] == ["365"]
    assert query["verbose"] == ["true"]
    assert query["key"] == [REDACTED]


def test_redact_url_redacts_every_occurrence_of_a_repeated_sensitive_param() -> None:
    """A duplicated parameter must not leave the second copy exposed."""
    url = f"https://api.example.com/v1?token={FAKE_KEY}&token=second_secret_value_xyz"

    result = redact_url(url)

    assert FAKE_KEY not in result
    assert "second_secret_value_xyz" not in result
    assert parse_qs(urlsplit(result).query)["token"] == [REDACTED, REDACTED]


# --------------------------------------------------------------------------------------
# redact_url: inputs that must not raise
# --------------------------------------------------------------------------------------


def test_redact_url_without_query_string_is_unchanged() -> None:
    """Nothing to redact and no environment secrets set: the URL comes back intact."""
    url = "https://ipinfo.io/93.184.216.34"

    assert redact_url(url) == url


def test_redact_url_on_empty_string_returns_empty_string() -> None:
    assert redact_url("") == ""


@pytest.mark.parametrize(
    "garbage",
    [
        "http://[::1",  # unterminated IPv6 literal -- urlsplit raises ValueError
        "not a url at all",
        "://///",
        "%%%",
        "https://exa mple.com/?key=abc",
        "?key=only-a-query-fragment",
        "\x00\x01\x02",
    ],
)
def test_redact_url_never_raises_on_unparseable_input(garbage: str) -> None:
    """Redaction runs on the error path. Raising here would mask the original failure."""
    result = redact_url(garbage)

    assert isinstance(result, str)


def test_redact_url_never_raises_on_garbage_containing_a_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """The except branch still applies literal redaction -- failing to parse is not an excuse."""
    monkeypatch.setenv("SHODAN_API_KEY", FAKE_KEY)

    result = redact_url(f"http://[::1/path?key={FAKE_KEY}")

    assert FAKE_KEY not in result
    assert REDACTED in result


# --------------------------------------------------------------------------------------
# redact_text: URLs embedded in exception messages
# --------------------------------------------------------------------------------------


def test_redact_text_redacts_a_url_embedded_in_an_exception_message() -> None:
    """The literal shape httpx produces: the failing URL quoted inside the message."""
    message = (
        "Client error '401 Unauthorized' for url "
        f"'{SHODAN_URL}'\n"
        "For more information check: https://developer.mozilla.org/docs/Web/HTTP/Status/401"
    )

    result = redact_text(message)

    assert FAKE_KEY not in result
    assert f"key={REDACTED}" in result
    # Everything diagnostically useful survives.
    assert "401 Unauthorized" in result
    assert "api.shodan.io" in result
    assert "developer.mozilla.org" in result


def test_redact_text_redacts_a_real_httpx_http_status_error() -> None:
    """Constructed in-process from a real httpx response -- no network, real message format.

    This is the exact object ``orchestrators._error_payload`` receives, so it pins the shape
    the fix has to cope with rather than a hand-written approximation of it.
    """
    request = httpx.Request("GET", SHODAN_URL)
    response = httpx.Response(401, request=request)
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as err:
        raw = str(err)
    else:  # pragma: no cover - raise_for_status always raises on 401
        pytest.fail("expected raise_for_status to raise on a 401")

    assert FAKE_KEY in raw  # the leak this fix exists to stop

    assert FAKE_KEY not in redact_text(raw)
    assert FAKE_KEY not in redact_url(str(request.url))


def test_redact_text_on_empty_string_returns_empty_string() -> None:
    assert redact_text("") == ""


def test_redact_text_leaves_a_credential_free_message_alone() -> None:
    message = (
        "Connection timed out after 20.0s while contacting https://stat.ripe.net/data/whois/data.json?resource=AS15133"
    )

    result = redact_text(message)

    assert result == message
    assert REDACTED not in result


# --------------------------------------------------------------------------------------
# Literal redaction from the environment
# --------------------------------------------------------------------------------------


def test_literal_redaction_catches_a_key_with_no_query_string_involved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The defence-in-depth layer: the key arrives by a route the param list cannot see.

    Here it is in a request header dump and in a URL path segment -- neither is a query
    parameter, so name-based redaction does nothing and only literal substitution helps.
    """
    monkeypatch.setenv("SHODAN_API_KEY", FAKE_KEY)

    header_dump = redact_text(f"request headers: {{'X-Api-Key': '{FAKE_KEY}'}} -> 403")
    path_url = redact_url(f"https://api.example.com/v1/{FAKE_KEY}/host")

    assert FAKE_KEY not in header_dump
    assert REDACTED in header_dump
    assert FAKE_KEY not in path_url
    assert path_url == f"https://api.example.com/v1/{REDACTED}/host"


@pytest.mark.parametrize(
    "env_var",
    [
        "CLOUDFLARE_API_TOKEN",
        "VT_API_KEY",
        "SHODAN_API_KEY",
        "ABUSEIPDB_API_KEY",
        "IPINFO_TOKEN",
        "OTX_API_KEY",
    ],
)
def test_literal_redaction_covers_every_credential_env_var(env_var: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(env_var, FAKE_KEY)

    assert FAKE_KEY not in redact_text(f"provider said: {FAKE_KEY}")


def test_literal_redaction_is_environment_scoped(monkeypatch: pytest.MonkeyPatch) -> None:
    """With nothing in the environment there is nothing to substitute.

    Guards the conftest isolation control as much as the module: if this fails, a real key
    from the operator's .env has leaked into the test process.
    """
    result = redact_text(f"provider said: {FAKE_KEY}")

    assert result == f"provider said: {FAKE_KEY}"


# --------------------------------------------------------------------------------------
# _MIN_SECRET_LEN guard
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("short_value", ["abc", "Zq7Wm2P", "1", "key"])
def test_short_env_value_does_not_trigger_runaway_substitution(
    short_value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A placeholder or truncated env value must not shred unrelated output.

    ``SHODAN_API_KEY=abc`` treated as a secret would rewrite every "abc" in every message --
    hostnames, ASN names, WHOIS text. The length floor is what stops that.
    """
    monkeypatch.setenv("SHODAN_API_KEY", short_value)
    text = f"abcdef Zq7Wm2P key 1 abc — asn name 'abc systems' {short_value} tail"

    assert redact_text(text) == text
    assert REDACTED not in redact_text(text)


@pytest.mark.parametrize("blank_value", ["", "   ", "\t\n"])
def test_blank_env_value_does_not_trigger_substitution(blank_value: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty secret would match at every position. It is stripped and discarded."""
    monkeypatch.setenv("VT_API_KEY", blank_value)
    text = "an ordinary message with no credentials in it"

    assert redact_text(text) == text


def test_min_secret_len_boundary_is_eight_characters(monkeypatch: pytest.MonkeyPatch) -> None:
    """Seven characters is below the floor; eight is at it and must be redacted."""
    monkeypatch.setenv("SHODAN_API_KEY", "Zq7Wm2P")  # 7 chars
    assert redact_text("leak Zq7Wm2P end") == "leak Zq7Wm2P end"

    monkeypatch.setenv("SHODAN_API_KEY", "Zq7Wm2Pk")  # 8 chars
    assert redact_text("leak Zq7Wm2Pk end") == f"leak {REDACTED} end"


def test_env_value_is_stripped_before_the_length_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """Surrounding whitespace from a sloppy .env line does not become part of the secret."""
    monkeypatch.setenv("IPINFO_TOKEN", f"  {FAKE_KEY}  ")

    assert FAKE_KEY not in redact_text(f"token was {FAKE_KEY}")


# --------------------------------------------------------------------------------------
# Longest-first ordering
# --------------------------------------------------------------------------------------


def test_longest_secret_is_redacted_first(monkeypatch: pytest.MonkeyPatch) -> None:
    """When one key is a prefix of another, shortest-first leaves the tail exposed.

    Redacting "ABCD1234EFGH" first turns "ABCD1234EFGH5678XY" into "REDACTED5678XY" -- the
    remaining six characters of the longer key are still in the output. Sorting by length
    descending is what prevents that.
    """
    short_key = "ABCD1234EFGH"
    long_key = short_key + "5678XY"
    monkeypatch.setenv("SHODAN_API_KEY", short_key)
    monkeypatch.setenv("VT_API_KEY", long_key)

    result = redact_text(f"leak: {long_key} end")

    assert result == f"leak: {REDACTED} end"
    assert "5678XY" not in result


def test_shorter_secret_is_still_redacted_when_a_longer_one_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ordering must not cause the shorter key to be skipped when it appears alone."""
    short_key = "ABCD1234EFGH"
    monkeypatch.setenv("SHODAN_API_KEY", short_key)
    monkeypatch.setenv("VT_API_KEY", short_key + "5678XY")

    assert redact_text(f"leak: {short_key} end") == f"leak: {REDACTED} end"


def test_both_secrets_redacted_when_both_appear(monkeypatch: pytest.MonkeyPatch) -> None:
    short_key = "ABCD1234EFGH"
    long_key = short_key + "5678XY"
    monkeypatch.setenv("SHODAN_API_KEY", short_key)
    monkeypatch.setenv("VT_API_KEY", long_key)

    result = redact_text(f"a={long_key} b={short_key}")

    assert result == f"a={REDACTED} b={REDACTED}"


# --------------------------------------------------------------------------------------
# Idempotence
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        SHODAN_URL,
        "https://ipinfo.io/93.184.216.34?token=tok_abcdef0123456789&fields=org",
        "https://ipinfo.io/93.184.216.34",
        "",
        "http://[::1",
    ],
)
def test_redact_url_is_idempotent(url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Redaction can be applied on several layers; a second pass must be a no-op."""
    monkeypatch.setenv("SHODAN_API_KEY", FAKE_KEY)

    once = redact_url(url)

    assert redact_url(once) == once


def test_redact_text_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", FAKE_KEY)
    message = f"Client error '401 Unauthorized' for url '{SHODAN_URL}' (header carried {FAKE_KEY} as well)"

    once = redact_text(message)

    assert redact_text(once) == once
    assert FAKE_KEY not in once


def test_redacted_output_contains_no_secret_material(monkeypatch: pytest.MonkeyPatch) -> None:
    """End-to-end sanity: nothing recognisable as the key survives either entry point."""
    monkeypatch.setenv("SHODAN_API_KEY", FAKE_KEY)
    payload: dict[str, Any] = {
        "url": redact_url(SHODAN_URL),
        "message": redact_text(f"Client error '401 Unauthorized' for url '{SHODAN_URL}'"),
    }

    serialised = repr(payload)

    assert FAKE_KEY not in serialised
    assert "sk_live" not in serialised
