"""Unit tests for tripper_recon.utils.refang (roadmap 6.1).

Defanged indicators are the normal case in a SOC, so this transform sits in front of every
other piece of input handling: detection, the ``check`` verb, and eventually bulk paste mode.
A silent regression here does not crash anything -- it changes which indicator gets
investigated, which is worse.

Three properties get the heavy testing, because those are the three the module promises:

* **Idempotence.** Asserted for every case in this file, not just a chosen few, by
  :func:`test_refang_is_idempotent_for_every_case_in_this_file`.
* **Fidelity on live input.** ``example.com`` and a URL with a real bracketed IPv6 host must
  come back byte-identical. The IPv6 case is the trap: ``[2001:db8::1]`` is valid RFC 3986
  syntax shaped exactly like the bracket defanging the module strips.
* **Auditability.** The rule that fired is recorded, and the raw input is preserved, so a
  mis-refang is debuggable from a stored report rather than only from a live terminal.

No network, no fixtures, no I/O -- ``refang`` is a pure string transform and these tests only
call it.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import List, Set, Tuple

import pytest

from tripper_recon.utils import refang as refang_module
from tripper_recon.utils.refang import (
    PASS_LIMIT_TRANSFORM,
    REFANG_RULES,
    TRANSFORM_DESCRIPTIONS,
    RefangResult,
    refang,
    refang_value,
)

# --------------------------------------------------------------------------------------
# Corpora, shared by the table tests and the idempotence sweep
# --------------------------------------------------------------------------------------

#: (input, expected refanged value). Every realistic defang this module claims to reverse.
DEFANGED_CASES: List[Tuple[str, str]] = [
    # ---- scheme obfuscation ------------------------------------------------------------
    ("hxxp://evil.com/a", "http://evil.com/a"),
    ("hxxps://evil.com/a", "https://evil.com/a"),
    ("hXXps://evil.com/a", "https://evil.com/a"),
    ("HXXPS://EVIL.COM/A", "https://EVIL.COM/A"),
    ("h**ps://evil.com/a", "https://evil.com/a"),
    ("httxs://evil.com/a", "https://evil.com/a"),
    ("meow://evil.com/a", "http://evil.com/a"),
    ("meows://evil.com/a", "https://evil.com/a"),
    ("fxp://evil.com/a", "ftp://evil.com/a"),
    # ---- dots ----------------------------------------------------------------------------
    ("evil[.]com", "evil.com"),
    ("evil(.)com", "evil.com"),
    ("evil{.}com", "evil.com"),
    ("evil[dot]com", "evil.com"),
    ("evil(dot)com", "evil.com"),
    ("evil[DOT]com", "evil.com"),
    ("evil[ . ]com", "evil.com"),
    ("evil dot com", "evil.com"),
    ("185.220.101[.]5", "185.220.101.5"),
    ("evil[.]co[.]uk", "evil.co.uk"),
    # ---- separators ------------------------------------------------------------------------
    ("hxxps[://]evil[.]com", "https://evil.com"),
    ("hxxp[:]//evil[.]com", "http://evil.com"),
    ("hxxp:[//]evil[.]com", "http://evil.com"),
    ("http://evil[.]com[/]a[/]b", "http://evil.com/a/b"),
    ("evil[.]com[:]8080", "evil.com:8080"),
    # ---- at signs -----------------------------------------------------------------------------
    ("user[@]evil[.]com", "user@evil.com"),
    ("user[at]evil[.]com", "user@evil.com"),
    ("user(at)evil(dot)com", "user@evil.com"),
    ("user at evil.com", "user@evil.com"),
    # ---- invisible characters and paste artefacts -----------------------------------------------
    ("evil\u200b.com", "evil.com"),
    ("evil\u200c[.]com", "evil.com"),
    ("\ufeffevil.com", "evil.com"),
    ("evil\u00a0dot\u00a0com", "evil.com"),
    ("  evil[.]com  ", "evil.com"),
    ("<evil[.]com>", "evil.com"),
    ('"evil[.]com"', "evil.com"),
    ("`evil[.]com`", "evil.com"),
    # ---- nesting, which is what makes the fixpoint loop necessary --------------------------------
    ("evil[[.]]com", "evil.com"),
    ("evil[(.)]com", "evil.com"),
    # ---- the composite an analyst actually pastes ------------------------------------------------
    ("hxxps://evil[.]com/login[.]php?id=7", "https://evil.com/login.php?id=7"),
    ("hxxps[://]www[.]evil[.]com[:]8443[/]a[/]b?x=1", "https://www.evil.com:8443/a/b?x=1"),
]

#: Live-looking input that MUST come back untouched. A refanger that mangles these is worse
#: than no refanger: it silently redirects the investigation at a different indicator.
CLEAN_CASES: List[str] = [
    "example.com",
    "evil.co.uk",
    "185.220.101.5",
    "2001:db8::1",
    "AS15169",
    "44d88612fea8a8f36de82e1278abb02f",
    "user@example.com",
    "http://example.com/a/b",
    "https://example.com/path?query=1&other=2#frag",
    "https://example.com/a-b_c/d.e",
    "ftp://example.com/pub",
    "evil.com/a/b",
    "185.220.101.0/24",
    "https://example.com/%2Fencoded%2Fpath",
    # A URL whose path legitimately contains the word "dot" with no spaces around it.
    "https://example.com/dotfiles",
    "https://example.com/a.dot.b",
]

#: The trap. ``[2001:db8::1]`` is a legitimate URL host under RFC 3986 section 3.2.2 and is
#: shaped exactly like the bracket defanging this module strips. Every one of these must
#: survive intact.
IPV6_LITERAL_CASES: List[str] = [
    "[2001:db8::1]",
    "http://[2001:db8::1]/x",
    "https://[2001:db8::1]/x",
    "http://[2001:db8::1]:8080/x",
    "http://[::1]/x",
    "http://[::]/",
    "http://[fe80::1%25eth0]/x",
    "http://[2001:4860:4860::8888]:443/a/b?c=1",
    "http://[::ffff:1.2.3.4]/x",
    "http://[2001:db8:0:0:0:0:0:1]/x",
    "https://user@[2001:db8::1]:8443/p",
]

ALL_INPUTS: List[str] = [case for case, _ in DEFANGED_CASES] + CLEAN_CASES + IPV6_LITERAL_CASES


# --------------------------------------------------------------------------------------
# The transform table
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("raw,expected", DEFANGED_CASES, ids=[c for c, _ in DEFANGED_CASES])
def test_defanged_input_is_refanged(raw: str, expected: str) -> None:
    assert refang(raw).value == expected


@pytest.mark.parametrize("raw", CLEAN_CASES)
def test_live_input_is_returned_untouched(raw: str) -> None:
    """A live indicator must survive refanging byte-for-byte, with nothing recorded."""
    result = refang(raw)
    assert result.value == raw
    assert result.transforms == ()
    assert result.changed is False
    assert result.was_defanged is False


@pytest.mark.parametrize("raw", IPV6_LITERAL_CASES)
def test_bracketed_ipv6_host_is_never_destroyed(raw: str) -> None:
    """The trap case: a real IPv6 literal looks exactly like bracket defanging.

    ``refang('http://[2001:db8::1]/x')`` stripping those brackets would produce a URL pointing
    at a different host, and the analyst would never see it happen. The module masks every
    bracketed group that parses as an IPv6 address before the rule table runs; this is the test
    that fails if that masking is removed or narrowed.
    """
    result = refang(raw)
    assert result.value == raw, f"IPv6 literal mangled: {raw!r} -> {result.value!r}"
    assert result.transforms == ()


def test_defanged_url_with_a_real_ipv6_host_refangs_the_scheme_and_keeps_the_host() -> None:
    """Both halves at once: the scheme is defanged, the host is genuinely bracketed."""
    result = refang("hxxps[://][2001:db8::1]:8443/a[.]php")
    assert result.value == "https://[2001:db8::1]:8443/a.php"
    assert "bracketed_scheme_separator" in result.transforms
    assert "hxxp_scheme" in result.transforms


def test_a_bracketed_group_that_is_not_ipv6_is_still_refanged() -> None:
    """Masking keys off "parses as IPv6", not off "has brackets" -- so `[.]` still works."""
    assert refang_value("[2001:db8:zz::1]") == "[2001:db8:zz::1]"
    assert refang_value("evil[.]com") == "evil.com"


def test_defanged_ipv6_host_is_reassembled() -> None:
    """`[2001:db8[:]:1]` is not valid IPv6, so it is not masked -- and refangs correctly."""
    assert refang_value("hxxp://[2001:db8[:]:1]/x") == "http://[2001:db8::1]/x"


# --------------------------------------------------------------------------------------
# Idempotence
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("raw", ALL_INPUTS)
def test_refang_is_idempotent_for_every_case_in_this_file(raw: str) -> None:
    """``refang(refang(x)) == refang(x)``, asserted over the whole corpus rather than samples.

    Non-idempotence is the failure mode a table-driven refanger reaches for on its own: a rule
    whose output re-triggers another rule leaves a value that changes again on the next call,
    so the same indicator resolves differently depending on how many times it passed through.
    """
    once = refang(raw)
    twice = refang(once.value)
    assert twice.value == once.value
    assert twice.transforms == (), f"a second pass still fired rules: {twice.transforms}"


@pytest.mark.parametrize("depth", [1, 2, 3, 5])
def test_nested_defanging_resolves_inside_one_call(depth: int) -> None:
    raw = "evil" + "[" * depth + "." + "]" * depth + "com"
    assert refang_value(raw) == "evil.com"


def test_pass_limit_is_recorded_rather_than_silently_truncating(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the table ever fails to converge the result says so, instead of lying by omission."""
    monkeypatch.setattr(refang_module, "MAX_PASSES", 1)
    result = refang("evil[[[.]]]com")
    assert PASS_LIMIT_TRANSFORM in result.transforms
    assert result.value != "evil.com"


# --------------------------------------------------------------------------------------
# The audit trail
# --------------------------------------------------------------------------------------


def test_raw_is_preserved_exactly() -> None:
    raw = "  hxxps://evil[.]com  "
    result = refang(raw)
    assert result.raw == raw
    assert result.value == "https://evil.com"


@pytest.mark.parametrize(
    "raw,expected_transforms",
    [
        ("evil[.]com", {"bracketed_dot"}),
        ("evil(dot)com", {"bracketed_dot_word"}),
        ("evil dot com", {"spaced_dot_word"}),
        ("hxxp://evil.com", {"hxxp_scheme"}),
        ("meows://evil.com", {"meow_scheme"}),
        ("fxp://evil.com", {"fxp_scheme"}),
        ("user[@]evil.com", {"bracketed_at"}),
        ("user[at]evil.com", {"bracketed_at_word"}),
        ("user at evil.com", {"spaced_at_word"}),
        ("evil[:]8080", {"bracketed_colon"}),
        ("evil.com[/]a", {"bracketed_slash"}),
        ("http:[//]evil.com", {"bracketed_double_slash"}),
        ("hxxp[://]evil.com", {"bracketed_scheme_separator", "hxxp_scheme"}),
        ("evil\u200b.com", {"zero_width"}),
        ("evil\u00a0dot\u00a0com", {"nbsp", "spaced_dot_word"}),
        ("  evil.com  ", {"strip_wrappers"}),
    ],
)
def test_the_rule_that_fired_is_recorded(raw: str, expected_transforms: Set[str]) -> None:
    """An analyst must be able to see what the tool changed about their input."""
    assert set(refang(raw).transforms) == expected_transforms


def test_transforms_are_recorded_in_the_order_they_fired() -> None:
    result = refang("  hxxps[://]evil[.]com  ")
    assert result.transforms == (
        "strip_wrappers",
        "bracketed_dot",
        "bracketed_scheme_separator",
        "hxxp_scheme",
    )


def test_every_transform_name_has_a_description() -> None:
    """``describe()`` renders these to an analyst, so a nameless rule is a defect."""
    for rule in REFANG_RULES:
        assert rule.name in TRANSFORM_DESCRIPTIONS
        assert TRANSFORM_DESCRIPTIONS[rule.name].strip()
    assert refang("evil[.]com").describe() == (TRANSFORM_DESCRIPTIONS["bracketed_dot"],)


def test_rule_names_are_unique() -> None:
    names = [rule.name for rule in REFANG_RULES]
    assert len(names) == len(set(names))


def test_was_defanged_ignores_cosmetic_trimming() -> None:
    """Whitespace around a paste is not evidence of defanging and must not be reported as it."""
    padded = refang("  example.com  ")
    assert padded.changed is True
    assert padded.was_defanged is False
    assert padded.transforms == ("strip_wrappers",)

    defanged = refang("example[.]com")
    assert defanged.changed is True
    assert defanged.was_defanged is True


# --------------------------------------------------------------------------------------
# Boundaries
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("raw", ["", "   ", "\t\n", "\u200b", "\u00a0"])
def test_empty_and_invisible_input_yields_an_empty_value_without_raising(raw: str) -> None:
    assert refang(raw).value == ""


@pytest.mark.parametrize("raw", [None, 42, b"evil[.]com", ["evil[.]com"]])
def test_non_string_input_raises_type_error(raw: object) -> None:
    """A non-str here is a programming error at a trust boundary, not a malformed indicator.

    Coercing it would hide the bug and would produce a plausible-looking value from ``bytes``.
    """
    with pytest.raises(TypeError):
        refang(raw)  # type: ignore[arg-type]


def test_unmatched_brackets_are_left_alone() -> None:
    """`evil[.)com` is more likely a typo or a regex fragment than a defang. Do not guess."""
    assert refang_value("evil[.)com") == "evil[.)com"


def test_refang_value_returns_only_the_string() -> None:
    assert refang_value("evil[.]com") == "evil.com"
    assert isinstance(refang("evil[.]com"), RefangResult)


def test_result_is_frozen() -> None:
    result = refang("evil[.]com")
    with pytest.raises(FrozenInstanceError):
        result.value = "other"  # type: ignore[misc]


# --------------------------------------------------------------------------------------
# Documented limits -- asserted so they stay documented
# --------------------------------------------------------------------------------------


def test_bare_word_rules_are_indicator_scoped_not_prose_scoped() -> None:
    """A KNOWN LIMIT, pinned so it cannot be forgotten.

    ``evil dot com`` is a defang an analyst really pastes, so the bare-word rules exist. Run
    over a sentence they rewrite ordinary English, which is why bulk extraction (roadmap 6.10)
    must tokenise the paste FIRST and refang each candidate token, never the whole paste. If
    that ever changes, this test fails and the caller's contract has to be revisited.
    """
    assert refang_value("we met at noon") == "we met@noon"
    assert refang_value("connect the dot com") == "connect the.com"


def test_a_path_containing_a_defang_pattern_is_rewritten() -> None:
    """The other known limit: from a string alone, defanging and content are indistinguishable."""
    assert refang_value("https://example.com/a(.)b") == "https://example.com/a.b"


# --------------------------------------------------------------------------------------
# Passivity: this module cannot reach the network, and must stay that way
# --------------------------------------------------------------------------------------


def test_refang_module_imports_nothing_that_can_open_a_socket() -> None:
    """Refanging reconstructs a live-looking URL; it must never be able to visit one.

    ``docs/OPSEC.md`` section 7 forbids redirect and shortener expansion outright, including
    with HEAD. The structural guarantee that this module cannot do it is that it imports
    nothing capable of it. ``tests/test_passivity.py`` enforces the same rule package-wide;
    this is the local, fast-failing version for the module that most invites the mistake.
    """
    source = Path(refang_module.__file__).read_text(encoding="utf-8")
    for forbidden in ("import httpx", "import socket", "import requests", "import urllib.request"):
        assert forbidden not in source, f"{forbidden!r} appears in utils/refang.py"
