"""Unit tests for tripper_recon.utils.validation.

These are the pure functions every orchestrator gates on (`orchestrators.py:114`, `:204`, `:345`),
so a regression here silently changes which indicators the tool refuses to look at.

Tests marked ``xfail(strict=False)`` assert the DESIRED behaviour for a gap that roadmap item 6.4
("Fix domain validation: IDN/punycode via `idna`, path-bearing input, trailing dot; add a per-label
63-octet check") is scheduled to close. They flip to passing automatically when 6.4 lands.
"""

from __future__ import annotations

import pytest

from tripper_recon.utils.validation import (
    dedupe_preserve_order,
    is_valid_asn,
    is_valid_domain,
    is_valid_ip,
)

# --------------------------------------------------------------------------------------
# is_valid_ip
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "8.8.8.8",
        "0.0.0.0",
        "255.255.255.255",
        "192.168.1.1",
        "2001:db8::1",
        "::1",
        "2606:4700:4700::1111",
    ],
)
def test_is_valid_ip_accepts_v4_and_v6(value: str) -> None:
    assert is_valid_ip(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "\t\n",
        "not-an-ip",
        "999.1.1.1",
        "1.2.3",
        "1.2.3.4.5",
        "2001:db8:::1",
        "8.8.8.8/32",  # a prefix is not an address
        "::gggg",
    ],
)
def test_is_valid_ip_rejects_garbage_and_empty(value: str) -> None:
    assert is_valid_ip(value) is False


def test_is_valid_ip_rejects_surrounding_whitespace() -> None:
    """No strip(). Callers must normalise before validating.

    Documented deliberately: `is_valid_domain` DOES strip and `is_valid_ip` does not, and that
    asymmetry is easy to break by accident during a cleanup pass.
    """
    assert is_valid_ip("  8.8.8.8  ") is False
    assert is_valid_ip("8.8.8.8\n") is False


def test_is_valid_ip_rejects_leading_zero_octets() -> None:
    """Leading zeros are ambiguous (historically parsed as octal) and CPython rejects them
    since 3.9.5 / bpo-36384. Locking this in: a hand-rolled replacement for `ipaddress` would
    almost certainly accept `192.168.001.1` and reintroduce the ambiguity."""
    assert is_valid_ip("192.168.001.1") is False
    assert is_valid_ip("010.0.0.1") is False


def test_is_valid_ip_non_string_input_is_not_rejected_by_type() -> None:
    """`ipaddress.ip_address` accepts a packed int and a 4-byte bytes object, so `is_valid_ip`
    inherits that: `is_valid_ip(12345)` is True (it parses as 0.0.48.57). Only ValueError is
    caught, and only str input is annotated -- callers must not rely on this function for type
    validation at a trust boundary."""
    assert is_valid_ip(12345) is True  # type: ignore[arg-type]
    assert is_valid_ip(b"\x08\x08\x08\x08") is True  # type: ignore[arg-type]
    assert is_valid_ip(None) is False  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------
# is_valid_asn
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("value", [15169, "15169", 1, 64512, 2**32 - 1, "  15169  "])
def test_is_valid_asn_accepts_ints_and_numeric_strings(value: str | int) -> None:
    assert is_valid_asn(value) is True


@pytest.mark.parametrize(
    "value",
    [
        0,  # AS0 is reserved (RFC 7607) and the range check excludes it
        -1,
        -15169,
        2**32,  # exclusive upper bound: 32-bit ASN space is 0..2**32-1
        2**64,
        "",
        "   ",
        "abc",
        "15169.0.0",
        None,
        [15169],
    ],
)
def test_is_valid_asn_rejects_out_of_range_and_garbage(value: object) -> None:
    assert is_valid_asn(value) is False  # type: ignore[arg-type]


def test_is_valid_asn_boundaries_are_exclusive_at_zero_and_2_32() -> None:
    assert is_valid_asn(0) is False
    assert is_valid_asn(1) is True
    assert is_valid_asn(2**32 - 1) is True
    assert is_valid_asn(2**32) is False


@pytest.mark.xfail(
    reason="roadmap 6.4: the 'AS' prefix is stripped in cli.py:455 but the validator itself "
    "rejects 'AS15169', so any non-CLI caller (API, bulk mode W6.10) refuses the canonical form",
    strict=False,
)
def test_is_valid_asn_accepts_as_prefixed_form() -> None:
    """DESIRED behaviour. Today `int('AS15169')` raises and the bare `except Exception` returns
    False; normalisation lives only in the CLI, which means it is not shared with any other
    entry point."""
    assert is_valid_asn("AS15169") is True
    assert is_valid_asn("as15169") is True


def test_is_valid_asn_accepts_floats_via_truncation() -> None:
    """Documents a real quirk rather than the desired behaviour: `int(1.5) == 1`, so a float
    silently truncates into a valid ASN. Not a security issue -- recorded so a future tightening
    of this function is a deliberate change, not a surprise."""
    assert is_valid_asn(1.5) is True  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------
# is_valid_domain
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "example.com",
        "sub.example.com",
        "a.b.c.example.co.uk",
        "EXAMPLE.COM",  # normalised via .lower()
        "  Example.COM  ",  # normalised via .strip()
        "xn--mnchen-3ya.de",  # punycode label under an ASCII TLD
        "example-hyphen.com",
        "1example.com",
        "a1.example.com",
    ],
)
def test_is_valid_domain_accepts_normal_forms(value: str) -> None:
    assert is_valid_domain(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "localhost",  # single label, no dot
        "com",
        "example..com",
        "ex_ample.com",  # underscore is not a hostname character
        "-evil.com",  # leading hyphen on the first label
        "example.c",  # TLD shorter than 2
        "example.123",  # all-numeric TLD
        "1.2.3.4",  # an IP is not a domain
        "example.com/path",
        "http://example.com",
        "exa mple.com",
    ],
)
def test_is_valid_domain_rejects_malformed(value: str) -> None:
    assert is_valid_domain(value) is False


def test_is_valid_domain_total_length_boundary_is_253() -> None:
    """The regex lookahead `(?=.{1,253}$)` is the only length control today."""
    at_limit = ("a" * 49 + ".") * 5 + "com"
    assert len(at_limit) == 253
    assert is_valid_domain(at_limit) is True

    over_limit = "a" * 250 + ".com"
    assert len(over_limit) == 254
    assert is_valid_domain(over_limit) is False


@pytest.mark.xfail(
    reason="roadmap 6.4: no per-label 63-octet check -- the regex bounds total length only",
    strict=False,
)
def test_is_valid_domain_rejects_label_over_63_octets() -> None:
    """DESIRED behaviour (RFC 1035 §2.3.4). Today a 64-octet label is accepted, so the tool will
    happily issue provider lookups for a name no resolver can ever answer."""
    assert is_valid_domain("a" * 63 + ".example.com") is True  # at the limit, valid either way
    assert is_valid_domain("a" * 64 + ".example.com") is False


@pytest.mark.xfail(
    reason="roadmap 6.4: trailing-dot (fully-qualified) form is rejected",
    strict=False,
)
def test_is_valid_domain_accepts_trailing_dot() -> None:
    """DESIRED behaviour. `example.com.` is the fully-qualified form and appears in DNS tooling
    output an analyst is likely to paste; today it is refused with a bare "Invalid domain"."""
    assert is_valid_domain("example.com.") is True


@pytest.mark.xfail(
    reason="roadmap 6.4: 'evil-.com' is accepted -- the regex guards a leading hyphen but not a "
    "trailing one, and only on the first label",
    strict=False,
)
def test_is_valid_domain_rejects_trailing_hyphen_label() -> None:
    """DESIRED behaviour (RFC 1123 §2.1: a label may not end in a hyphen)."""
    assert is_valid_domain("evil-.com") is False
    assert is_valid_domain("sub.evil-.com") is False


@pytest.mark.xfail(
    reason="roadmap 6.4: IDN input is rejected instead of being IDNA-encoded",
    strict=False,
)
def test_is_valid_domain_accepts_idn_unicode() -> None:
    """DESIRED behaviour. IDN homographs are a routine phishing artefact; refusing them outright
    means the tool cannot be pointed at the exact indicator an analyst was handed."""
    assert is_valid_domain("münchen.de") is True
    assert is_valid_domain("пример.рф") is True


@pytest.mark.xfail(
    reason="roadmap 6.4: a punycode TLD (xn--p1ai) fails the [A-Za-z]{2,63} TLD class",
    strict=False,
)
def test_is_valid_domain_accepts_punycode_tld() -> None:
    """DESIRED behaviour. `xn--e1afmkfd.xn--p1ai` is the A-label form of `пример.рф` -- the
    encoding the tool would itself produce -- and it is rejected because the final label contains
    digits and hyphens."""
    assert is_valid_domain("xn--e1afmkfd.xn--p1ai") is True


# --------------------------------------------------------------------------------------
# dedupe_preserve_order
# --------------------------------------------------------------------------------------


def test_dedupe_preserve_order_keeps_first_occurrence() -> None:
    assert dedupe_preserve_order(["b", "a", "b", "c", "a"]) == ["b", "a", "c"]


def test_dedupe_preserve_order_empty_and_all_unique() -> None:
    assert dedupe_preserve_order([]) == []
    assert dedupe_preserve_order(["a", "b", "c"]) == ["a", "b", "c"]


def test_dedupe_preserve_order_accepts_any_iterable_and_returns_a_new_list() -> None:
    src = ["1.1.1.1", "8.8.8.8", "1.1.1.1"]
    out = dedupe_preserve_order(iter(src))
    assert out == ["1.1.1.1", "8.8.8.8"]
    assert out is not src
    assert src == ["1.1.1.1", "8.8.8.8", "1.1.1.1"]  # input untouched


def test_dedupe_preserve_order_is_case_sensitive_and_does_not_normalise() -> None:
    """Callers of `orchestrators.py:261` feed this resolver output. It is an exact-match dedupe:
    it will NOT collapse `2001:DB8::1` and `2001:db8::1`, which is worth knowing before relying
    on it to bound provider call counts."""
    assert dedupe_preserve_order(["A.com", "a.com"]) == ["A.com", "a.com"]
