"""Unit tests for tripper_recon.types.indicators (roadmap 6.3).

``detect()`` is the front door for the ``check`` verb and for bulk paste mode, which means it
decides what the tool investigates for every input an analyst does not classify by hand. Two
classes of failure matter here and neither raises an exception, so only tests catch them:

* **Silent misclassification.** ``1.2.3.4/24`` read as a domain, ``evil.com/a/b`` refused
  outright, a defanged URL crashing the caller. Those are the verified gaps this module closes.
* **Silent disambiguation.** An input that genuinely reads two ways, resolved to one of them
  with nothing recorded. The module's rule is that ambiguity is REPORTED -- through
  ``confidence``, ``alternatives``, ``attempts`` and ``notes`` -- and the tests below assert on
  those fields rather than only on the winning type.

Everything here is pure: no network, no name resolution, no fixtures.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import List, Tuple

import pytest

from tripper_recon.types import indicators as indicators_module
from tripper_recon.types.indicators import (
    ASSUMED_SCHEME,
    DETECTION_ORDER,
    MAX_ASN,
    Confidence,
    Indicator,
    IndicatorType,
    detect,
)

# --------------------------------------------------------------------------------------
# The classification table
# --------------------------------------------------------------------------------------

#: (raw input, expected type, expected canonical value).
CLASSIFICATION_CASES: List[Tuple[str, IndicatorType, str]] = [
    # ---- ASN ------------------------------------------------------------------------------
    ("AS15169", IndicatorType.ASN, "AS15169"),
    ("as15169", IndicatorType.ASN, "AS15169"),
    ("AS 15169", IndicatorType.ASN, "AS15169"),
    ("ASN15169", IndicatorType.ASN, "AS15169"),
    ("AS-15169", IndicatorType.ASN, "AS15169"),
    ("15169", IndicatorType.ASN, "AS15169"),
    ("1", IndicatorType.ASN, "AS1"),
    (str(MAX_ASN), IndicatorType.ASN, f"AS{MAX_ASN}"),
    # ---- CIDR ------------------------------------------------------------------------------
    ("185.220.101.0/24", IndicatorType.CIDR, "185.220.101.0/24"),
    ("10.0.0.0/8", IndicatorType.CIDR, "10.0.0.0/8"),
    ("2001:db8::/32", IndicatorType.CIDR, "2001:db8::/32"),
    ("[2001:db8::]/32", IndicatorType.CIDR, "2001:db8::/32"),
    ("1.2.3.4/24", IndicatorType.CIDR, "1.2.3.0/24"),
    # ---- IP --------------------------------------------------------------------------------
    ("8.8.8.8", IndicatorType.IPV4, "8.8.8.8"),
    ("185.220.101.5", IndicatorType.IPV4, "185.220.101.5"),
    ("10.0.0.5", IndicatorType.IPV4, "10.0.0.5"),
    ("2001:4860:4860::8888", IndicatorType.IPV6, "2001:4860:4860::8888"),
    ("2001:DB8::1", IndicatorType.IPV6, "2001:db8::1"),
    ("2001:0db8:0000:0000:0000:0000:0000:0001", IndicatorType.IPV6, "2001:db8::1"),
    ("[2001:db8::1]", IndicatorType.IPV6, "2001:db8::1"),
    ("::1", IndicatorType.IPV6, "::1"),
    # ---- hashes -----------------------------------------------------------------------------
    ("44d88612fea8a8f36de82e1278abb02f", IndicatorType.MD5, "44d88612fea8a8f36de82e1278abb02f"),
    ("44D88612FEA8A8F36DE82E1278ABB02F", IndicatorType.MD5, "44d88612fea8a8f36de82e1278abb02f"),
    (
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        IndicatorType.SHA1,
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    ),
    (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        IndicatorType.SHA256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    # ---- URL ---------------------------------------------------------------------------------
    ("https://evil.com/a/b?x=1", IndicatorType.URL, "https://evil.com/a/b?x=1"),
    ("HTTPS://EVIL.COM/A", IndicatorType.URL, "https://evil.com/A"),
    ("evil.com/a/b", IndicatorType.URL, "http://evil.com/a/b"),
    ("http://185.220.101.5:8080/x", IndicatorType.URL, "http://185.220.101.5:8080/x"),
    ("http://[2001:db8::1]:8080/x", IndicatorType.URL, "http://[2001:db8::1]:8080/x"),
    ("ftp://example.com/pub", IndicatorType.URL, "ftp://example.com/pub"),
    ("https://evil.com./a", IndicatorType.URL, "https://evil.com/a"),
    ("https://evil.com/a#frag", IndicatorType.URL, "https://evil.com/a#frag"),
    # ---- email --------------------------------------------------------------------------------
    ("a@evil.com", IndicatorType.EMAIL, "a@evil.com"),
    ("First.Last+tag@Evil.COM", IndicatorType.EMAIL, "First.Last+tag@evil.com"),
    # ---- domain --------------------------------------------------------------------------------
    ("example.com", IndicatorType.DOMAIN, "example.com"),
    ("EXAMPLE.COM", IndicatorType.DOMAIN, "example.com"),
    ("evil.com.", IndicatorType.DOMAIN, "evil.com"),
    ("a.b.c.example.co.uk", IndicatorType.DOMAIN, "a.b.c.example.co.uk"),
    ("xn--80ak6aa92e.com", IndicatorType.DOMAIN, "xn--80ak6aa92e.com"),
    ("_dmarc.example.com", IndicatorType.DOMAIN, "_dmarc.example.com"),
]


@pytest.mark.parametrize(
    "raw,expected_type,expected_value",
    CLASSIFICATION_CASES,
    ids=[case[0] for case in CLASSIFICATION_CASES],
)
def test_detect_classifies_and_normalises(raw: str, expected_type: IndicatorType, expected_value: str) -> None:
    indicator = detect(raw)
    assert indicator.type is expected_type
    assert indicator.value == expected_value
    assert indicator.raw == raw, "the analyst's exact input must survive alongside the canonical value"


# --------------------------------------------------------------------------------------
# Detection order — the whole algorithm
# --------------------------------------------------------------------------------------


def test_every_classifier_runs_on_every_input_in_the_declared_order() -> None:
    """``attempts`` is the audit trail, so it must be complete and ordered, not best-effort."""
    indicator = detect("example.com")
    assert tuple(attempt.kind for attempt in indicator.attempts) == DETECTION_ORDER
    assert all(attempt.detail.strip() for attempt in indicator.attempts)


def test_a_prefix_beats_the_url_reading_of_the_same_string() -> None:
    """``1.2.3.4/24`` parses as both. CIDR is more specific and wins, and the loser is named."""
    indicator = detect("185.220.101.0/24")
    assert indicator.type is IndicatorType.CIDR
    assert IndicatorType.URL in indicator.alternatives
    assert any("also parses as" in note for note in indicator.notes)


def test_an_explicit_asn_beats_the_bare_integer_reading() -> None:
    assert detect("AS15169").confidence is Confidence.CERTAIN
    assert detect("15169").confidence is Confidence.PROBABLE


def test_a_hash_beats_the_bare_label_reading() -> None:
    indicator = detect("44d88612fea8a8f36de82e1278abb02f")
    assert indicator.type is IndicatorType.MD5
    assert any("DNS label" in note for note in indicator.notes)


# --------------------------------------------------------------------------------------
# Ambiguity is reported, never silently resolved
# --------------------------------------------------------------------------------------


def test_a_bare_integer_says_why_it_is_only_probable() -> None:
    indicator = detect("15169")
    assert indicator.type is IndicatorType.ASN
    assert indicator.confidence is Confidence.PROBABLE
    assert indicator.is_ambiguous is True
    assert any("bare integer" in note for note in indicator.notes)


def test_an_ip_records_why_the_domain_reading_was_rejected() -> None:
    """'1.2.3.4' as a domain versus an IP is the canonical ambiguity, so the rejection is legible."""
    indicator = detect("1.2.3.4")
    assert indicator.type is IndicatorType.IPV4
    domain_attempt = next(attempt for attempt in indicator.attempts if attempt.kind == "domain")
    assert domain_attempt.matched is False
    assert "numeric" in domain_attempt.detail


def test_an_assumed_scheme_is_reported_as_assumed_and_lowers_confidence() -> None:
    """A scheme the tool supplied changes the VirusTotal URL identifier, so it is never asserted."""
    indicator = detect("evil.com/a/b")
    assert indicator.type is IndicatorType.URL
    assert indicator.confidence is Confidence.PROBABLE
    assert indicator.parts["scheme_assumed"] is True
    assert indicator.parts["scheme"] == ASSUMED_SCHEME
    assert any("NOT present in the input" in note for note in indicator.notes)


def test_an_explicit_scheme_is_certain() -> None:
    indicator = detect("https://evil.com/a/b")
    assert indicator.confidence is Confidence.CERTAIN
    assert indicator.parts["scheme_assumed"] is False
    assert indicator.is_ambiguous is False


def test_an_internationalised_domain_is_accepted_and_flagged_rather_than_refused() -> None:
    """IDN homographs are a routine phishing artefact; refusing to classify one is the old bug."""
    indicator = detect("münchen.de")
    assert indicator.type is IndicatorType.DOMAIN
    assert indicator.confidence is Confidence.PROBABLE
    assert indicator.parts["ascii_only"] is False
    assert any("punycode" in note for note in indicator.notes)


# --------------------------------------------------------------------------------------
# UNKNOWN has to explain itself
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "1.2.3.4.5",
        "localhost",
        "/etc/passwd",
        "not an indicator",
        "evil-.com",
        "file:///etc/passwd",
        "0",
        "4294967295",
        "deadbeef",
        "@example.com",
        "a@@b.com",
        "..com",
        "",
        "   ",
    ],
)
def test_unknown_lists_every_attempt_with_a_reason(raw: str) -> None:
    indicator = detect(raw)
    assert indicator.type is IndicatorType.UNKNOWN
    assert indicator.confidence is Confidence.NONE
    assert indicator.is_known is False
    assert tuple(attempt.kind for attempt in indicator.attempts) == DETECTION_ORDER
    assert all(attempt.matched is False for attempt in indicator.attempts)
    assert all(attempt.detail.strip() for attempt in indicator.attempts), (
        "an UNKNOWN with a blank reason tells the analyst nothing about why the tool declined"
    )
    assert any("no classifier matched" in note for note in indicator.notes)


def test_an_out_of_range_asn_says_so_rather_than_declining_silently() -> None:
    indicator = detect("4294967295")
    asn_attempt = next(attempt for attempt in indicator.attempts if attempt.kind == "asn")
    assert str(MAX_ASN) in asn_attempt.detail


def test_a_hex_string_of_the_wrong_length_names_the_digest_lengths() -> None:
    indicator = detect("deadbeef")
    hash_attempt = next(attempt for attempt in indicator.attempts if attempt.kind == "hash")
    assert "32" in hash_attempt.detail and "64" in hash_attempt.detail


# --------------------------------------------------------------------------------------
# Verified gaps this closes (docs/review/design-url-support.md section 4.4)
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected_type",
    [
        ("185.220.101.0/24", IndicatorType.CIDR),
        ("44d88612fea8a8f36de82e1278abb02f", IndicatorType.MD5),
        ("a@evil.com", IndicatorType.EMAIL),
        ("evil.com/a/b", IndicatorType.URL),
        ("hxxps://evil[.]com/pay", IndicatorType.URL),
        ("evil[.]com", IndicatorType.DOMAIN),
        ("2001:4860:4860::8888", IndicatorType.IPV6),
        ("http://185.220.101.5:8080/x", IndicatorType.URL),
    ],
)
def test_inputs_that_every_existing_validator_refuses_are_now_classified(
    raw: str, expected_type: IndicatorType
) -> None:
    """Each of these fails ``is_valid_ip``, ``is_valid_asn`` and ``is_valid_domain`` today.

    Verified in ``docs/review/design-url-support.md`` section 4.4: a bare URL, a CIDR prefix, a
    hash and an email all fall through every validator to "Invalid domain", and the defanged
    forms crash ``cli.py`` at ``urlparse``.
    """
    assert detect(raw).type is expected_type


# --------------------------------------------------------------------------------------
# URL decomposition
# --------------------------------------------------------------------------------------


def test_url_parts_are_decomposed_without_touching_the_network() -> None:
    indicator = detect("https://evil.com:8443/Login.php?id=7&Next=2#frag")
    parts = indicator.parts
    assert parts["scheme"] == "https"
    assert parts["host"] == "evil.com"
    assert parts["host_type"] == "domain"
    assert parts["port"] == 8443
    assert parts["port_explicit"] is True
    assert parts["effective_port"] == 8443
    assert parts["path"] == "/Login.php", "path case carries the campaign identifier and must be preserved"
    assert parts["query"] == "id=7&Next=2"
    assert parts["fragment"] == "frag"


def test_a_default_port_is_implicit_but_recorded() -> None:
    """``http://evil.com/`` and ``http://evil.com:80/`` are different VirusTotal identifiers."""
    implicit = detect("http://evil.com/")
    explicit = detect("http://evil.com:80/")
    assert implicit.parts["port_explicit"] is False
    assert implicit.parts["effective_port"] == 80
    assert implicit.value == "http://evil.com/"
    assert explicit.parts["port_explicit"] is True
    assert explicit.value == "http://evil.com:80/"


def test_embedded_credentials_are_surfaced_and_withheld_from_the_value() -> None:
    """``cli.py`` drops userinfo silently today. It is a phishing signal, so it is reported."""
    indicator = detect("https://user:pw@evil.com/p")
    assert indicator.parts["userinfo_present"] is True
    assert "user" not in indicator.value and "pw" not in indicator.value
    assert indicator.value == "https://evil.com/p"
    assert any("userinfo" in note for note in indicator.notes)


def test_a_url_with_an_ip_host_is_routed_at_the_address_not_the_domain_path() -> None:
    """Verified defect: this input dies in the domain orchestrator at ``is_valid_domain`` today."""
    indicator = detect("http://185.220.101.5:8080/x")
    assert indicator.type is IndicatorType.URL
    assert indicator.parts["host_type"] == "ipv4"
    assert indicator.parts["host"] == "185.220.101.5"
    assert any("IP literal" in note for note in indicator.notes)


def test_a_url_with_a_bracketed_ipv6_host_survives_intact() -> None:
    """The refang trap, carried through detection: brackets are URL syntax, not defanging."""
    indicator = detect("http://[2001:db8::1]:8080/x")
    assert indicator.type is IndicatorType.URL
    assert indicator.parts["host_type"] == "ipv6"
    assert indicator.parts["host"] == "2001:db8::1"
    assert indicator.value == "http://[2001:db8::1]:8080/x"
    assert indicator.refang_transforms == ()


@pytest.mark.parametrize("scheme", ["file", "ldap", "jar", "gopher", "javascript"])
def test_a_non_web_scheme_is_refused_with_the_scheme_named(scheme: str) -> None:
    indicator = detect(f"{scheme}://evil.com/x")
    url_attempt = next(attempt for attempt in indicator.attempts if attempt.kind == "url")
    assert url_attempt.matched is False
    assert scheme in url_attempt.detail


def test_a_bare_path_is_not_mistaken_for_a_url() -> None:
    """Without a scheme, the text before the first '/' must be a real host or it is not a URL."""
    for raw in ("/etc/passwd", "foo/bar", "../relative/path"):
        assert detect(raw).type is IndicatorType.UNKNOWN


# --------------------------------------------------------------------------------------
# The passive boundary, expressed in the output
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "https://evil.com/a",
        "http://bit.ly/abc123",
        "evil.com/a/b",
        "http://[2001:db8::1]/x",
    ],
)
def test_every_url_reports_its_redirect_chain_as_not_resolved(raw: str) -> None:
    """Expanding a shortener or following a redirect is an ACTIVE FETCH of the target.

    ``docs/OPSEC.md`` section 7 forbids it outright, HEAD included, so the chain can only ever
    come from a scan somebody else already completed. Recording ``not_resolved`` rather than
    omitting the field is what stops a reader assuming the tool checked and found nothing.
    """
    indicator = detect(raw)
    assert indicator.parts["redirect_chain"] is None
    assert indicator.parts["redirect_chain_state"] == "not_resolved"
    assert any("NOT RESOLVED" in note for note in indicator.notes)


def test_an_open_redirect_parameter_is_offered_as_a_candidate_not_followed() -> None:
    indicator = detect("https://good.com/r?next=https%3A%2F%2Fevil.com%2Fx")
    assert indicator.parts["embedded_url_candidates"] == ["https://evil.com/x"]
    assert any("CANDIDATE indicator" in note for note in indicator.notes)
    assert indicator.parts["redirect_chain_state"] == "not_resolved"


@pytest.mark.parametrize(
    "raw",
    ["10.0.0.5", "127.0.0.1", "169.254.1.1", "224.0.0.1", "fe80::1", "::", "http://10.0.0.5/x", "10.0.0.0/8"],
)
def test_non_routable_targets_are_flagged_so_they_never_reach_a_third_party(raw: str) -> None:
    """The RFC 1918 guard exists on the ip path only; detection has to see the rest.

    Split-horizon DNS and sinkholed domains resolve to internal space, and forwarding that to
    five providers under the operator's API keys discloses internal addressing (roadmap 2.4).
    Detection reports rather than refuses -- naming the reason is more useful to the caller than
    a bare rejection.
    """
    indicator = detect(raw)
    assert indicator.type is not IndicatorType.UNKNOWN
    assert any("non-routable" in note for note in indicator.notes), indicator.notes


def test_a_public_address_is_not_flagged_as_non_routable() -> None:
    for raw in ("8.8.8.8", "185.220.101.5", "2001:4860:4860::8888"):
        assert not any("non-routable" in note for note in detect(raw).notes)


# --------------------------------------------------------------------------------------
# Defanged input is the normal case
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected_type,expected_value",
    [
        ("evil[.]com", IndicatorType.DOMAIN, "evil.com"),
        ("evil(dot)com", IndicatorType.DOMAIN, "evil.com"),
        ("185.220.101[.]5", IndicatorType.IPV4, "185.220.101.5"),
        ("hxxps://evil[.]com/pay", IndicatorType.URL, "https://evil.com/pay"),
        ("hxxp[://]evil[.]com[:]8080[/]a", IndicatorType.URL, "http://evil.com:8080/a"),
        ("user[at]evil[.]com", IndicatorType.EMAIL, "user@evil.com"),
        ("185.220.101[.]0/24", IndicatorType.CIDR, "185.220.101.0/24"),
    ],
)
def test_defanged_input_classifies_and_records_the_refang(
    raw: str, expected_type: IndicatorType, expected_value: str
) -> None:
    indicator = detect(raw)
    assert indicator.type is expected_type
    assert indicator.value == expected_value
    assert indicator.raw == raw
    assert indicator.defanged_input is True
    assert indicator.refang_transforms, "the transforms that fired must be recorded for the report"
    assert any("refanged for lookup" in note for note in indicator.notes)


def test_live_input_is_not_marked_as_defanged() -> None:
    indicator = detect("example.com")
    assert indicator.defanged_input is False
    assert indicator.refang_transforms == ()


def test_surrounding_whitespace_alone_is_not_defanging() -> None:
    indicator = detect("  example.com  ")
    assert indicator.type is IndicatorType.DOMAIN
    assert indicator.value == "example.com"
    assert indicator.defanged_input is False


# --------------------------------------------------------------------------------------
# Normalisation details worth pinning
# --------------------------------------------------------------------------------------


def test_a_prefix_with_host_bits_set_is_normalised_and_says_so() -> None:
    indicator = detect("1.2.3.4/24")
    assert indicator.value == "1.2.3.0/24"
    assert any("host bits" in note for note in indicator.notes)
    assert indicator.parts["prefix_length"] == 24


def test_a_hash_is_lower_cased_for_lookup() -> None:
    indicator = detect("44D88612FEA8A8F36DE82E1278ABB02F")
    assert indicator.value == "44d88612fea8a8f36de82e1278abb02f"
    assert indicator.parts["algorithm"] == "md5"


def test_an_email_local_part_keeps_its_case_and_the_domain_does_not() -> None:
    indicator = detect("First.Last@Evil.COM")
    assert indicator.value == "First.Last@evil.com"
    assert indicator.parts["local_part"] == "First.Last"
    assert indicator.parts["domain"] == "evil.com"


def test_a_trailing_root_dot_is_removed_and_recorded() -> None:
    indicator = detect("evil.com.")
    assert indicator.value == "evil.com"
    assert any("trailing root dot" in note for note in indicator.notes)


def test_an_over_long_label_is_refused() -> None:
    assert detect("a" * 64 + ".com").type is IndicatorType.UNKNOWN
    assert detect("a" * 63 + ".com").type is IndicatorType.DOMAIN


# --------------------------------------------------------------------------------------
# The Indicator value object
# --------------------------------------------------------------------------------------


def test_indicator_is_frozen() -> None:
    indicator = detect("example.com")
    with pytest.raises(FrozenInstanceError):
        indicator.value = "other.com"  # type: ignore[misc]


def test_indicators_deduplicate_on_type_and_canonical_value() -> None:
    """Bulk mode dedupes on ``key``, so it has to collapse spellings of the same indicator.

    Equality stays field-wise on purpose: two pastes that normalised to the same value from
    different raw strings are two observations, and bulk mode counts occurrences.
    """
    spellings = [detect("EXAMPLE.com"), detect("example.com."), detect("example.com")]
    assert len({indicator.key for indicator in spellings}) == 1
    assert len({indicator.key for indicator in [detect("example.com"), detect("other.com")]}) == 2
    # The hash agrees with the key, so a set of Indicators still buckets them together.
    assert len({hash(indicator) for indicator in spellings}) == 1
    assert detect("example.com") == detect("example.com")
    assert detect("example.com") != detect("EXAMPLE.com"), "raw differs, so these are two observations"


def test_explain_renders_the_detection_trace() -> None:
    trace = detect("hxxps://evil[.]com/pay").explain()
    assert "type:       url" in trace
    assert "refanged:" in trace
    assert "reject domain" in trace


def test_indicator_type_helpers() -> None:
    assert IndicatorType.IPV4.is_ip and IndicatorType.IPV6.is_ip
    assert not IndicatorType.DOMAIN.is_ip
    assert IndicatorType.MD5.is_hash and IndicatorType.SHA256.is_hash
    assert not IndicatorType.URL.is_hash


def test_enum_values_are_stable_wire_strings() -> None:
    """These serialise into stored investigations, so renaming one changes archived output."""
    assert [member.value for member in IndicatorType] == [
        "asn",
        "cidr",
        "ipv4",
        "ipv6",
        "md5",
        "sha1",
        "sha256",
        "url",
        "email",
        "domain",
        "unknown",
    ]
    assert [member.value for member in Confidence] == ["certain", "probable", "none"]


@pytest.mark.parametrize("raw", [None, 42, b"example.com"])
def test_non_string_input_raises_type_error(raw: object) -> None:
    with pytest.raises(TypeError):
        detect(raw)  # type: ignore[arg-type]


def test_detect_never_raises_on_hostile_content() -> None:
    """Bulk mode feeds this attacker-authored text, so an exception here is a denial of service."""
    hostile = [
        "[" * 200,
        "a" * 5000,
        "://" * 50,
        "hxxp" * 100,
        "\x00\x01\x02",
        "%00%2e%2e%2f",
        "evil.com\n185.220.101.5",
        "http://[gggg::1]/x",
        "http://evil.com:99999/",
        "​" * 100,
    ]
    for raw in hostile:
        assert isinstance(detect(raw), Indicator)


# --------------------------------------------------------------------------------------
# Passivity: detection cannot become collection
# --------------------------------------------------------------------------------------


def test_indicators_module_imports_nothing_that_can_open_a_socket_or_resolve_a_name() -> None:
    """Detection decomposes a URL. It must remain structurally incapable of visiting one.

    ``tests/test_passivity.py`` enforces this package-wide; this is the local, fast-failing
    version for the module whose whole job is handling target-controlled strings.
    """
    source = Path(indicators_module.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "import httpx",
        "import socket",
        "import requests",
        "urllib.request",
        "getaddrinfo",
        "gethostbyname",
    ):
        assert forbidden not in source, f"{forbidden!r} appears in types/indicators.py"
