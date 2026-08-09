"""Tests for ``tripper_recon.utils.urls`` -- URL decomposition, roadmap 6.5.

Three things are being pinned here, in descending order of how much damage their absence does.

**Passivity.** ``parse_url`` must never contact anything. Two tests enforce that structurally
rather than by inspection: one walks the module's import graph and fails on any networking
module, the other poisons every socket entry point in the standard library and then parses the
whole hostile corpus. A future edit that adds "just a HEAD to see where it redirects" fails both.

**Evidence preservation.** The decomposition exists so an analyst can see what the sender
actually wrote. Case in the path and query, an assumed scheme, dropped credentials, a percent
escape in a hostname -- each has a test asserting the parser reports it rather than tidying it
away. Several of these assert a *negative*: that the parser did NOT normalise something.

**Not guessing.** An eTLD+1 derived without the Public Suffix List is wrong for every
``.co.uk``-shaped host and looks exactly as confident as a right one. The model refuses to carry
one, and a test proves the refusal.

Real URLs appear throughout. ``tests/`` is not scanned by the static passivity gate, which
forbids absolute-URL literals inside ``tripper_recon/`` -- the module under test writes its
examples defanged for that reason.
"""

from __future__ import annotations

import ast
import socket
from pathlib import Path
from typing import Any, List, Tuple

import pytest
from pydantic import ValidationError

from tripper_recon.utils.urls import (
    DEFAULT_SCHEME,
    Anomaly,
    HostKind,
    ParsedURL,
    RedirectChain,
    RedirectResolution,
    RegistrableDomainStatus,
    UrlAnomaly,
    UrlParseError,
    parse_url,
    summarise_anomalies,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "tripper_recon" / "utils" / "urls.py"


# --------------------------------------------------------------------------------------
# The corpus every property test runs over
# --------------------------------------------------------------------------------------
#
# Deliberately hostile. Anything the parser is expected to survive belongs here, so a new
# malformation only has to be added in one place to be covered by totality, purity, round-trip
# and idempotence at once.

CORPUS: Tuple[str, ...] = (
    "https://example.com/",
    "http://example.com",
    "https://example.com/PathCase?Query=Value#Fragment",
    "https://example.com:8443/a/b/c?x=1&y=2#z",
    "example.com/a",
    "example.com:8080/a",
    "//example.com/a",
    "localhost:3000/admin",
    "https://user:pw@example.com/p",
    "https://www.paypal.com@198.51.100.7/login",
    "https://@example.com/",
    "https://[2001:db8::1]/x",
    "https://[2001:db8::1]:8443/x",
    "https://[::1]/",
    "https://198.51.100.7:8080/x",
    "https://xn--mnchen-3ya.de/Weg",
    "https://münchen.de/Weg",
    "https://xn--zzzzzz.example/",
    "https://ex%41mple.com/a",
    "https://example.com./a",
    "https://example..com/a",
    "https://.example.com/a",
    "https://3232235777/a",
    "https://0xc0.0xa8.0x00.0x01/a",
    "https://example.com:99999/a",
    "https://example.com:notaport/a",
    "https://example.com/%C0%AE%C0%AE/etc",
    "https://example.com/a%2541b",
    "javascript:alert(1)",
    "data:text/html;base64,PGI+",
    "mailto:victim@example.com",
    "https:///nohost",
    "https://",
    "https://.",
    "https://[2001:db8::1/x",
    "https://::1/x",
    "https://example.com:",
    "https://example.com?only=query",
    "https://example.com#only-fragment",
    "HTTPS://EXAMPLE.COM/A?B=C#D",
)

#: Fields that must survive a parse -> reassemble -> parse cycle unchanged. ``raw``,
#: ``scheme_assumed`` and ``anomalies`` are excluded on purpose: after reassembly the scheme
#: really is written down, so the second parse honestly reports it as observed.
ROUND_TRIP_FIELDS: Tuple[str, ...] = (
    "scheme",
    "is_hierarchical",
    "userinfo_present",
    "userinfo",
    "username",
    "password",
    "host",
    "host_kind",
    "host_unicode",
    "host_punycode",
    "registrable_domain",
    "registrable_domain_status",
    "port",
    "port_raw",
    "path",
    "query",
    "fragment",
)


def _snapshot(parsed: ParsedURL) -> Tuple[Any, ...]:
    return tuple(getattr(parsed, name) for name in ROUND_TRIP_FIELDS)


# --------------------------------------------------------------------------------------
# 1. Passivity -- the constraint the whole workstream exists to protect
# --------------------------------------------------------------------------------------

#: Importing any of these from a pure parser means somebody added a fetch.
FORBIDDEN_IMPORTS = frozenset(
    {
        "socket",
        "ssl",
        "httpx",
        "requests",
        "aiohttp",
        "urllib3",
        "urllib.request",
        "http.client",
        "asyncio",
        "subprocess",
        "tripper_recon.utils.http",
        "tripper_recon.utils.dns",
    }
)


def _imported_modules(path: Path) -> List[str]:
    names: List[str] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.append(node.module)
    return names


def test_module_imports_nothing_that_can_reach_the_network() -> None:
    """A URL parser that can open a socket will eventually open one.

    W6 adds URL handling, which is where a passive tool most easily becomes an active one: the
    obvious next line after decomposing a URL is following it. Expanding a shortener or
    resolving a redirect is an active fetch of the target -- a bodyless request included -- and
    it burns single-use links and tells a live actor they are being watched (docs/OPSEC.md
    section 7). This module is pure so that the capability is simply absent.
    """
    offenders = sorted({name for name in _imported_modules(MODULE_PATH) if name in FORBIDDEN_IMPORTS})
    assert not offenders, (
        f"tripper_recon/utils/urls.py imports {offenders}, which can reach the network.\n\n"
        "parse_url() is specified as pure: no socket, no name resolution, no HTTP client, no "
        "redirect following, no shortener expansion. If a caller needs the destination of a "
        "redirect, it comes from a scan a THIRD PARTY already completed -- build a "
        "RedirectChain with from_passive_record() and name the provider. There is no flag for "
        "fetching it here, and adding one is not a decision this module gets to make."
    )


def test_parsing_the_hostile_corpus_opens_no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    """The runtime half of the guard: poison every socket entry point, then parse everything.

    The import scan above sees a module-level ``import httpx``. It cannot see a lazily-imported
    client inside a function, and that is exactly how an "only when the caller asks for it"
    fetch would arrive. This test would.
    """

    def _explode(*args: object, **kwargs: object) -> None:
        raise AssertionError(
            "parse_url attempted network I/O. It is specified as pure -- see docs/OPSEC.md "
            "sections 1 and 7 and the module docstring."
        )

    for attribute in ("socket", "create_connection", "getaddrinfo", "gethostbyname", "gethostbyaddr"):
        monkeypatch.setattr(socket, attribute, _explode)

    for url in CORPUS:
        parse_url(url)


def test_redirect_chain_defaults_to_not_resolved_with_a_reason() -> None:
    """The report has to be able to say NOT RESOLVED, and say why.

    A blank field reads as "there is no redirect", which is the opposite claim from "we did not
    look, on purpose". The dangerous reading is the one an empty value produces.
    """
    chain = parse_url("https://bit.ly/abc123").redirect_chain

    assert chain.resolution is RedirectResolution.NOT_RESOLVED
    assert chain.resolved is False
    assert chain.hops == ()
    assert chain.final_url is None
    assert "active fetch" in chain.reason
    assert chain.render().startswith("NOT RESOLVED")


def test_a_shortener_is_not_expanded() -> None:
    """A shortener gets exactly the same treatment as any other host: decomposed, not followed."""
    parsed = parse_url("https://t.co/xYz")

    assert parsed.host == "t.co"
    assert parsed.path == "/xYz"
    assert parsed.redirect_chain.resolution is RedirectResolution.NOT_RESOLVED


def test_an_unresolved_chain_may_not_carry_hops() -> None:
    """The one construction that would let a fetched chain masquerade as an honest blank."""
    with pytest.raises(ValidationError, match="NOT RESOLVED"):
        RedirectChain(resolution=RedirectResolution.NOT_RESOLVED, hops=("https://example.com/",))


def test_a_resolved_chain_must_name_its_passive_source() -> None:
    """A chain with no provenance is indistinguishable from one this tool fetched itself."""
    with pytest.raises(ValidationError, match="passive source"):
        RedirectChain(resolution=RedirectResolution.FROM_PASSIVE_RECORD, hops=("https://example.com/",))

    with pytest.raises(ValueError, match="must name its source"):
        RedirectChain.from_passive_record(("https://example.com/",), source="   ")


def test_a_chain_sourced_from_a_completed_third_party_scan_is_permitted() -> None:
    """The passive answer to the redirect question: somebody else already ran the scan."""
    chain = RedirectChain.from_passive_record(
        ("https://bit.ly/abc123", "https://evil.example/step", "https://evil.example/final"),
        source="virustotal:last_final_url",
        observed_at="2026-08-01T12:00:00Z",
    )

    assert chain.resolved is True
    assert chain.final_url == "https://evil.example/final"
    assert chain.source == "virustotal:last_final_url"
    assert "virustotal:last_final_url" in chain.render()
    assert "2026-08-01T12:00:00Z" in chain.render()


# --------------------------------------------------------------------------------------
# 2. Case handling -- lowercase the scheme and host, and nothing else
# --------------------------------------------------------------------------------------


def test_scheme_and_host_are_lowercased_and_nothing_else_is() -> None:
    """Path and query carry campaign identifiers, victim tokens and redirector keys.

    Case-folding them is not tidying: it destroys the string that links two samples to one
    campaign, and it is irreversible from the parsed record.
    """
    parsed = parse_url("HTTPS://Phish.EXAMPLE.com/CaseSensitive/PaTh?Token=AbC123#FragMent")

    assert parsed.scheme == "https"
    assert parsed.host == "phish.example.com"
    assert parsed.path == "/CaseSensitive/PaTh"
    assert parsed.query == "Token=AbC123"
    assert parsed.fragment == "FragMent"


def test_percent_escape_case_in_the_path_is_preserved() -> None:
    """``%2F`` and ``%2f`` are the same byte and different strings. Keep what was written."""
    assert parse_url("https://example.com/a%2Fb%2fc").path == "/a%2Fb%2fc"


# --------------------------------------------------------------------------------------
# 3. An assumed scheme is recorded as assumed
# --------------------------------------------------------------------------------------


def test_a_missing_scheme_is_recorded_as_assumed_not_silently_invented() -> None:
    parsed = parse_url("evil.example/a")

    assert parsed.scheme == DEFAULT_SCHEME
    assert parsed.scheme_assumed is True
    assert parsed.has_anomaly(UrlAnomaly.SCHEME_ASSUMED)
    assert parsed.host == "evil.example"
    assert parsed.path == "/a"


def test_a_written_scheme_is_not_flagged_as_assumed() -> None:
    parsed = parse_url("http://evil.example/a")

    assert parsed.scheme == "http"
    assert parsed.scheme_assumed is False
    assert not parsed.has_anomaly(UrlAnomaly.SCHEME_ASSUMED)


def test_the_assumed_scheme_is_caller_selectable_and_still_recorded() -> None:
    parsed = parse_url("evil.example/a", default_scheme="HTTP")

    assert parsed.scheme == "http"
    assert parsed.scheme_assumed is True


def test_a_protocol_relative_url_assumes_a_scheme() -> None:
    parsed = parse_url("//evil.example/a")

    assert parsed.scheme_assumed is True
    assert parsed.host == "evil.example"
    assert parsed.path == "/a"


def test_a_host_with_a_port_is_not_mistaken_for_a_scheme() -> None:
    """``evil.example:8080/a`` is the trap: a dot is a legal scheme character.

    The naive reading is syntactically valid and parses to scheme ``evil.example`` with no host
    at all, which loses the indicator entirely.
    """
    parsed = parse_url("evil.example:8080/a")

    assert parsed.scheme == DEFAULT_SCHEME
    assert parsed.scheme_assumed is True
    assert parsed.host == "evil.example"
    assert parsed.port == 8080
    assert parsed.path == "/a"


@pytest.mark.parametrize(
    "url,expected_scheme,expected_body",
    [
        ("javascript:alert(1)", "javascript", "alert(1)"),
        ("data:text/html;base64,PGI+", "data", "text/html;base64,PGI+"),
        ("mailto:victim@example.com", "mailto", "victim@example.com"),
    ],
)
def test_a_non_hierarchical_scheme_keeps_its_opaque_body(url: str, expected_scheme: str, expected_body: str) -> None:
    """``javascript:`` and ``data:`` payloads are findings, not parse failures."""
    parsed = parse_url(url)

    assert parsed.scheme == expected_scheme
    assert parsed.is_hierarchical is False
    assert parsed.path == expected_body
    assert parsed.host == ""
    assert parsed.host_kind is HostKind.NONE
    assert parsed.has_anomaly(UrlAnomaly.NON_HIERARCHICAL_URL)
    assert parsed.has_anomaly(UrlAnomaly.SCHEME_NON_WEB)


# --------------------------------------------------------------------------------------
# 4. Userinfo is surfaced, never dropped
# --------------------------------------------------------------------------------------


def test_userinfo_is_surfaced_rather_than_dropped() -> None:
    """The defect this field exists to fix: the CLI silently discards the credentials today."""
    parsed = parse_url("https://user:pw@evil.example/p")

    assert parsed.userinfo_present is True
    assert parsed.userinfo == "user:pw"
    assert parsed.username == "user"
    assert parsed.password == "pw"
    assert parsed.host == "evil.example"
    assert parsed.has_anomaly(UrlAnomaly.USERINFO_PRESENT)


def test_a_brand_shaped_username_is_flagged_as_the_display_trick() -> None:
    """``www.bank.example@evil.example`` shows the brand and visits the attacker."""
    parsed = parse_url("https://www.paypal.com@198.51.100.7/login")

    assert parsed.host == "198.51.100.7"
    assert parsed.host_kind is HostKind.IPV4
    assert parsed.username == "www.paypal.com"
    assert parsed.has_anomaly(UrlAnomaly.USERINFO_IMPERSONATES_HOST)


def test_an_empty_userinfo_is_still_present() -> None:
    """``https://@host/`` is a construction, not an absence. Report it."""
    parsed = parse_url("https://@evil.example/")

    assert parsed.userinfo_present is True
    assert parsed.userinfo == ""
    assert parsed.host == "evil.example"


def test_the_rightmost_at_sign_separates_userinfo_from_host() -> None:
    """An unencoded ``@`` inside the userinfo is common in lures; the leftmost split loses half
    the credentials into the host."""
    parsed = parse_url("https://user@mail:pw@evil.example/p")

    assert parsed.userinfo == "user@mail:pw"
    assert parsed.host == "evil.example"


def test_a_password_is_masked_for_human_output_but_kept_in_the_record() -> None:
    parsed = parse_url("https://user:hunter2@evil.example/p")

    assert parsed.password == "hunter2"
    assert "hunter2" not in parsed.masked_url
    assert parsed.masked_url == "https://user:***@evil.example/p"
    assert parsed.normalised_url == "https://user:hunter2@evil.example/p"


def test_a_url_without_a_password_masks_to_itself() -> None:
    parsed = parse_url("https://evil.example/p")

    assert parsed.masked_url == parsed.normalised_url


# --------------------------------------------------------------------------------------
# 5. Hosts: IDN, IPv6, and the oddities that are signals
# --------------------------------------------------------------------------------------


def test_an_idn_host_carries_both_the_unicode_and_the_punycode_form() -> None:
    parsed = parse_url("https://münchen.de/Weg")

    assert parsed.host == "münchen.de"
    assert parsed.host_unicode == "münchen.de"
    assert parsed.host_punycode == "xn--mnchen-3ya.de"
    assert parsed.host_ascii == "xn--mnchen-3ya.de"
    assert parsed.has_anomaly(UrlAnomaly.HOST_NON_ASCII)


def test_a_punycode_host_carries_both_forms_too() -> None:
    """Both spellings of one host, whichever spelling arrived."""
    parsed = parse_url("https://xn--mnchen-3ya.de/Weg")

    assert parsed.host == "xn--mnchen-3ya.de"
    assert parsed.host_unicode == "münchen.de"
    assert parsed.host_punycode == "xn--mnchen-3ya.de"
    assert parsed.has_anomaly(UrlAnomaly.HOST_PUNYCODE_LABEL)


def test_undecodable_punycode_is_reported_not_swallowed() -> None:
    parsed = parse_url("https://xn--zzzzzz.example/")

    assert parsed.host == "xn--zzzzzz.example"
    assert parsed.host_unicode is None
    assert parsed.has_anomaly(UrlAnomaly.HOST_PUNYCODE_UNDECODABLE)


def test_a_mixed_script_label_is_reported_as_a_homograph_signal() -> None:
    """``pаypal`` with a Cyrillic 'а'. Indistinguishable on screen, a different name to a resolver."""
    parsed = parse_url("https://pаypal.com/")

    assert parsed.has_anomaly(UrlAnomaly.HOST_MIXED_SCRIPT)
    assert parsed.host_punycode == "xn--pypal-4ve.com"


def test_scripts_differing_across_labels_is_not_a_homograph() -> None:
    """Mixing within one label is the trick; a Cyrillic label beside a Latin TLD is just an IDN."""
    parsed = parse_url("https://пример.com/")

    assert parsed.has_anomaly(UrlAnomaly.HOST_NON_ASCII)
    assert not parsed.has_anomaly(UrlAnomaly.HOST_MIXED_SCRIPT)


@pytest.mark.parametrize(
    "url,host,port",
    [
        ("https://[2001:db8::1]/x", "2001:db8::1", None),
        ("https://[2001:db8::1]:8443/x", "2001:db8::1", 8443),
        ("https://[::1]/", "::1", None),
        ("https://[2001:DB8::1]/x", "2001:db8::1", None),
    ],
)
def test_a_bracketed_ipv6_literal_parses(url: str, host: str, port: int | None) -> None:
    parsed = parse_url(url)

    assert parsed.host == host
    assert parsed.host_kind is HostKind.IPV6
    assert parsed.port == port
    assert parsed.host_in_url == f"[{host}]"
    assert parsed.registrable_domain_status is RegistrableDomainStatus.NOT_APPLICABLE_IP_LITERAL


def test_an_unbracketed_ipv6_literal_is_flagged_and_still_parsed() -> None:
    parsed = parse_url("https://::1/x")

    assert parsed.has_anomaly(UrlAnomaly.HOST_MALFORMED_IPV6)
    assert parsed.host == "::1"
    assert parsed.host_kind is HostKind.IPV6


def test_an_unbalanced_bracket_keeps_the_authority_rather_than_guessing() -> None:
    parsed = parse_url("https://[2001:db8::1/x")

    assert parsed.has_anomaly(UrlAnomaly.HOST_MALFORMED_IPV6)
    assert parsed.host == "[2001:db8::1"
    assert parsed.path == "/x"


@pytest.mark.parametrize(
    "url,code",
    [
        ("https://ex%41mple.com/a", UrlAnomaly.HOST_PERCENT_ENCODED),
        ("https://example.com./a", UrlAnomaly.HOST_TRAILING_DOT),
        ("https://example..com/a", UrlAnomaly.HOST_EMPTY_LABEL),
        ("https://.example.com/a", UrlAnomaly.HOST_EMPTY_LABEL),
        ("https://3232235777/a", UrlAnomaly.HOST_OBFUSCATED_IP_FORM),
        ("https://0xc0.0xa8.0x00.0x01/a", UrlAnomaly.HOST_OBFUSCATED_IP_FORM),
        ("https://0300.0250.0.1/a", UrlAnomaly.HOST_OBFUSCATED_IP_FORM),
        ("https:///nohost", UrlAnomaly.HOST_MISSING),
        ("https://example.com:99999/a", UrlAnomaly.PORT_INVALID),
        ("https://example.com:notaport/a", UrlAnomaly.PORT_INVALID),
        ("https://example.com/%C0%AE%C0%AE/etc", UrlAnomaly.OVERLONG_PERCENT_ENCODING),
        ("https://example.com/a%2541b", UrlAnomaly.DOUBLE_PERCENT_ENCODING),
        ("https://ev\nil.example/a", UrlAnomaly.RAW_CONTROL_CHARACTERS),
    ],
)
def test_host_and_encoding_oddities_are_recorded(url: str, code: UrlAnomaly) -> None:
    assert parse_url(url).has_anomaly(code), f"{url!r} should have recorded {code.value}"


def test_oddities_are_recorded_without_being_normalised_away() -> None:
    """The negative half of the previous test, and the more important half.

    A parser that repairs a hostile hostname produces a clean-looking record of it. The verdict
    engine then scores the repaired string, and the analyst reading the report never sees what
    arrived.
    """
    assert parse_url("https://ex%41mple.com/a").host == "ex%41mple.com"
    assert parse_url("https://example.com./a").host == "example.com."
    assert parse_url("https://example..com/a").host == "example..com"
    assert parse_url("https://3232235777/a").host == "3232235777"
    assert parse_url("https://example.com:99999/a").port_raw == "99999"


def test_an_invalid_port_is_kept_verbatim_and_not_offered_as_an_integer() -> None:
    parsed = parse_url("https://example.com:notaport/a")

    assert parsed.port is None
    assert parsed.port_raw == "notaport"


def test_a_non_ascii_digit_port_is_rejected_rather_than_coerced() -> None:
    """``str.isdigit()`` is true for Arabic-Indic digits and ``int()`` accepts them."""
    parsed = parse_url("https://example.com:٨٠/a")

    assert parsed.port is None
    assert parsed.has_anomaly(UrlAnomaly.PORT_INVALID)


def test_control_characters_are_stripped_the_way_a_browser_strips_them_and_reported() -> None:
    """A hostname split across an embedded newline resolves in a browser. Say so."""
    parsed = parse_url("https://ev\nil.example/a")

    assert parsed.host == "evil.example"
    assert parsed.has_anomaly(UrlAnomaly.RAW_CONTROL_CHARACTERS)
    assert parsed.raw == "https://ev\nil.example/a"


def test_a_clean_url_records_no_anomalies() -> None:
    """The signal list has to be quiet on ordinary input or nobody will read it."""
    assert parse_url("https://example.com/path?q=1#f").anomalies == ()


# --------------------------------------------------------------------------------------
# 6. Registrable domain: not guessed, ever
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url,status",
    [
        ("https://a.b.example.co.uk/", RegistrableDomainStatus.UNAVAILABLE_NO_PUBLIC_SUFFIX_LIST),
        ("https://example.com/", RegistrableDomainStatus.UNAVAILABLE_NO_PUBLIC_SUFFIX_LIST),
        ("https://198.51.100.7/", RegistrableDomainStatus.NOT_APPLICABLE_IP_LITERAL),
        ("https://[2001:db8::1]/", RegistrableDomainStatus.NOT_APPLICABLE_IP_LITERAL),
        ("localhost:3000/", RegistrableDomainStatus.NOT_APPLICABLE_SINGLE_LABEL),
        ("https:///nohost", RegistrableDomainStatus.NOT_APPLICABLE_NO_HOST),
        ("javascript:alert(1)", RegistrableDomainStatus.NOT_APPLICABLE_NO_HOST),
    ],
)
def test_the_registrable_domain_is_never_guessed(url: str, status: RegistrableDomainStatus) -> None:
    """A wrong eTLD+1 silently mis-pivots an entire investigation.

    ``example.co.uk`` reduces to ``co.uk`` under any last-two-labels rule -- the answer is not
    derivable from the string, it needs the Public Suffix List, and this package does not carry
    one. The honest output is the host plus a stated reason.
    """
    parsed = parse_url(url)

    assert parsed.registrable_domain is None
    assert parsed.registrable_domain_status is status
    assert parsed.pivot_host == parsed.host


def test_the_model_refuses_a_registrable_domain_with_no_suffix_list_behind_it() -> None:
    """The rule is enforced in the model, so no caller can add a guess later."""
    with pytest.raises(ValidationError, match="public suffix list"):
        ParsedURL(
            raw="https://example.co.uk/",
            scheme="https",
            host="example.co.uk",
            host_kind=HostKind.DNS_NAME,
            registrable_domain="co.uk",
            registrable_domain_status=RegistrableDomainStatus.UNAVAILABLE_NO_PUBLIC_SUFFIX_LIST,
        )


def test_the_resolved_status_requires_an_actual_value() -> None:
    """The counterpart: the placeholder status cannot be set without the thing it claims."""
    with pytest.raises(ValidationError, match="RESOLVED"):
        ParsedURL(
            raw="https://example.com/",
            scheme="https",
            host="example.com",
            host_kind=HostKind.DNS_NAME,
            registrable_domain_status=RegistrableDomainStatus.RESOLVED,
        )


# --------------------------------------------------------------------------------------
# 7. Round-trip and idempotence properties over the whole corpus
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("url", CORPUS, ids=CORPUS)
def test_reassembling_and_reparsing_preserves_every_component(url: str) -> None:
    """parse -> normalised_url -> parse gives back the same components.

    This is the property that makes ``normalised_url`` safe to store: the reassembled string is
    not a lossy rendering of the record, it is another spelling of it.
    """
    once = parse_url(url)
    twice = parse_url(once.normalised_url)

    assert _snapshot(twice) == _snapshot(once)


@pytest.mark.parametrize("url", CORPUS, ids=CORPUS)
def test_reassembly_is_idempotent(url: str) -> None:
    """A second pass changes nothing, so no pipeline can drift by re-normalising."""
    once = parse_url(url)
    twice = parse_url(once.normalised_url)

    assert twice.normalised_url == once.normalised_url


@pytest.mark.parametrize("url", CORPUS, ids=CORPUS)
def test_parsing_never_raises_on_the_hostile_corpus(url: str) -> None:
    """Totality. A malformed URL is evidence; refusing to represent it loses the observation."""
    parsed = parse_url(url)

    assert parsed.raw == url
    assert isinstance(parsed.anomalies, tuple)


@pytest.mark.parametrize("url", CORPUS, ids=CORPUS)
def test_the_path_query_and_fragment_survive_byte_for_byte(url: str) -> None:
    """Whatever else changes, the case-bearing components appear verbatim in the input."""
    parsed = parse_url(url)
    written = url.strip().replace("\n", "").replace("\r", "").replace("\t", "")

    for component in (parsed.path, parsed.query, parsed.fragment):
        if component:
            assert component in written


@pytest.mark.parametrize("url", CORPUS, ids=CORPUS)
def test_no_parse_reports_a_resolved_redirect_chain(url: str) -> None:
    """Whatever the input, the parser cannot produce a resolved chain. It has no way to."""
    assert parse_url(url).redirect_chain.resolved is False


@pytest.mark.parametrize("url", CORPUS, ids=CORPUS)
def test_the_host_is_lowercase_and_the_scheme_is_lowercase(url: str) -> None:
    parsed = parse_url(url)

    assert parsed.scheme == parsed.scheme.lower()
    assert parsed.host == parsed.host.lower()


def test_uppercase_input_normalises_only_the_scheme_and_host() -> None:
    parsed = parse_url("HTTPS://EXAMPLE.COM/A?B=C#D")

    assert parsed.normalised_url == "https://example.com/A?B=C#D"


# --------------------------------------------------------------------------------------
# 8. Model behaviour
# --------------------------------------------------------------------------------------


def test_the_parsed_record_is_immutable() -> None:
    """A parsed URL is evidence. A caller must not be able to edit the host after the fact."""
    parsed = parse_url("https://example.com/a")

    with pytest.raises(ValidationError):
        parsed.host = "other.example"  # type: ignore[misc]


def test_an_unknown_field_is_rejected() -> None:
    with pytest.raises(ValidationError):
        ParsedURL(raw="x", scheme="https", not_a_field=1)  # type: ignore[call-arg]


def test_the_record_serialises_for_the_json_export() -> None:
    """Everything here has to survive ``-o json`` without a custom encoder."""
    payload = parse_url("https://user:pw@münchen.de:8443/Path?Q=1#F").model_dump(mode="json")

    assert payload["host"] == "münchen.de"
    assert payload["host_punycode"] == "xn--mnchen-3ya.de"
    assert payload["port"] == 8443
    assert payload["path"] == "/Path"
    assert payload["redirect_chain"]["resolution"] == "NOT RESOLVED"
    assert payload["registrable_domain"] is None


def test_anomaly_codes_and_grouping_are_available_without_re_parsing() -> None:
    parsed = parse_url("evil.example:99999/a")

    assert UrlAnomaly.SCHEME_ASSUMED in parsed.anomaly_codes
    grouped = summarise_anomalies(parsed)
    assert "scheme" in grouped
    assert "port" in grouped


def test_an_anomaly_renders_with_its_component_and_detail() -> None:
    anomaly = Anomaly(code=UrlAnomaly.HOST_MISSING, component="host", detail="no host component was present")

    assert str(anomaly) == "host_missing [host]: no host component was present"


@pytest.mark.parametrize("value", ["", "   ", "\n\t"])
def test_an_empty_input_is_the_one_parse_error(value: str) -> None:
    with pytest.raises(UrlParseError):
        parse_url(value)
