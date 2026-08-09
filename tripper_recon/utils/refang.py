"""Refanging: turn a defanged indicator back into a machine-parsable one.

Defanged indicators are the **normal** case in a SOC, not the edge case. They arrive that way
from mail clients, ticketing systems and threat reports, because a live indicator in a document
is a thing the next reader can click. Today ``cli.py`` hands them straight to ``urlparse`` and
raises ``ValueError: Invalid IPv6 URL`` (roadmap 0.7); this module is the transform that makes
them usable (roadmap 6.1).

**Nothing here touches the network.** Every function is a pure string transform over its
argument. Refanging is deliberately kept separate from anything that performs a lookup, so a
reviewer can see in one file that reconstructing a live-looking URL is not the same act as
fetching one. Expanding a shortener or resolving a redirect stays forbidden -- it is an active
fetch of the target, HEAD included (``docs/OPSEC.md`` section 7). This module rewrites
characters and nothing else.

Three properties are load-bearing, and each has tests that fail loudly if it regresses.

**Idempotent.** ``refang(refang(x)).value == refang(x).value`` for every input. The rule table
is applied repeatedly until it reaches a fixpoint rather than once, so nested obfuscation
(``evil[[.]]com``) resolves inside a single call instead of leaving a half-refanged string that
a second call would change again.

**It records what it changed.** :class:`RefangResult` keeps the analyst's ``raw`` string beside
the rewritten ``value`` and names every rule that fired in :attr:`RefangResult.transforms`. A
tool that silently rewrites an analyst's input produces output that cannot be defended in a case
write-up: the report has to show what was pasted and what was investigated.

**It does not mangle a live indicator.** ``example.com`` comes back untouched, and so does a URL
whose host is a real bracketed IPv6 literal. That second case is the trap: ``[2001:db8::1]`` is
legitimate RFC 3986 syntax shaped exactly like the bracket defanging this module removes. It is
handled by masking every bracketed group that parses as an IPv6 address before the rule table
runs and restoring it afterwards, so no rule ever sees it.

Known limits, stated rather than hidden:

* The bare-word rules (``evil dot com``, ``user at evil.com``) are **indicator-scoped, not
  prose-scoped**. Run over a sentence they rewrite ordinary English. Bulk extraction (roadmap
  6.10) must tokenise first and refang each candidate token, never refang the whole paste.
* A path or query that genuinely contains ``(.)``, ``[at]`` or similar is rewritten. From a
  string alone, defanging and that content are indistinguishable.
* Refanging is not decoding. No base64, hex or percent-decoding happens here; guessing at
  obfuscated intent belongs behind an explicit, separate action.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Tuple, Union

__all__ = [
    "MAX_PASSES",
    "NBSP",
    "PASS_LIMIT_TRANSFORM",
    "REFANG_RULES",
    "TRANSFORM_DESCRIPTIONS",
    "ZERO_WIDTH_CHARS",
    "RefangResult",
    "RefangRule",
    "refang",
    "refang_value",
]


# --------------------------------------------------------------------------------------
# Pre-pass: invisible characters and paste artefacts
# --------------------------------------------------------------------------------------

#: Zero-width characters, removed outright. Common in text copied out of rendered HTML and
#: invisible in every console, so an indicator that looks identical to a valid one and still
#: fails to parse is usually one of these. Written as escapes on purpose: a literal here would
#: be an invisible character in the source of the module that exists to delete them.
ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\ufeff"

_ZERO_WIDTH_RE = re.compile(f"[{ZERO_WIDTH_CHARS}]")

#: U+00A0. Renders as a space, is not one, and defeats every ``\s``-naive parser downstream.
#: Folded to an ordinary space rather than deleted, so the spaced ``dot`` / ``at`` rules below
#: still see the separator the analyst intended.
NBSP = "\u00a0"

#: Trimmed from both ends only. Mail clients and chat wrap pasted indicators in these.
_WRAPPER_CHARS = "<>\"'`\u2018\u2019\u201c\u201d \t\r\n"


# --------------------------------------------------------------------------------------
# IPv6 literal protection
# --------------------------------------------------------------------------------------
#
# ``[2001:db8::1]`` is a legitimate URL host (RFC 3986 section 3.2.2) shaped exactly like the
# bracket defanging this module strips. Masking is the only reliable defence: a rule set tuned
# to leave IPv6 alone by pattern is a rule set that a slightly unusual address defeats.
#
# The sentinels are Unicode Private Use Area code points. No rule matches them, and no tool
# that emits indicators produces them.

_MASK_OPEN = "\ue000"
_MASK_CLOSE = "\ue001"

_BRACKETED_RE = re.compile(r"\[([^\[\]\s]{2,60})\]")


def _mask_ipv6_literals(text: str) -> Tuple[str, Dict[str, str]]:
    """Replace every bracketed group that parses as an IPv6 address with an inert sentinel."""
    vault: Dict[str, str] = {}

    def _replace(match: re.Match[str]) -> str:
        try:
            ipaddress.IPv6Address(match.group(1))
        except ValueError:
            return match.group(0)
        token = f"{_MASK_OPEN}{len(vault)}{_MASK_CLOSE}"
        vault[token] = match.group(0)
        return token

    return _BRACKETED_RE.sub(_replace, text), vault


def _unmask(text: str, vault: Dict[str, str]) -> str:
    for token, original in vault.items():
        text = text.replace(token, original)
    return text


# --------------------------------------------------------------------------------------
# The rule table
# --------------------------------------------------------------------------------------

#: A ``re.sub`` replacement: a template string, or a callable for case-sensitive rewrites.
_Replacement = Union[str, Callable[["re.Match[str]"], str]]


@dataclass(frozen=True)
class RefangRule:
    """One defanging convention and its reversal.

    ``name`` is the stable identifier recorded in :attr:`RefangResult.transforms`. It is part
    of the output contract -- an analyst reading a stored investigation sees these strings --
    so renaming one changes what an archived report means.
    """

    name: str
    pattern: re.Pattern[str]
    #: A ``re.sub`` template, or a callable when the replacement depends on what matched.
    replacement: _Replacement
    description: str


def _rule(
    name: str, pattern: str, replacement: _Replacement, description: str, *, ignore_case: bool = False
) -> RefangRule:
    flags = re.IGNORECASE if ignore_case else 0
    return RefangRule(name=name, pattern=re.compile(pattern, flags), replacement=replacement, description=description)


def _lowercase_http_scheme(match: re.Match[str]) -> str:
    """``HXXPS`` -> ``https``, not ``httpS``.

    A scheme is case-insensitive per RFC 3986 but every downstream comparison in this codebase
    is against a lower-case literal, and a template replacement would carry the analyst's
    upper-case ``S`` straight through. The host keeps its case here; normalising that is
    detection's job, where the decision is recorded.
    """
    return "http" + ("s" if match.group(1) else "")


#: Applied in order, repeatedly, until no rule fires.
#:
#: Separators come before schemes so ``hxxps[://]evil[.]com`` resolves in a single pass: the
#: bracketed separator becomes a real one, which is what the scheme rules look ahead for.
#:
#: Every bracket rule requires a MATCHED pair. ``evil[.)com`` is left alone -- more likely a
#: typo or a regex fragment than a defang, and rewriting it would be a guess.
REFANG_RULES: Tuple[RefangRule, ...] = (
    # ---- dots ----------------------------------------------------------------------------
    _rule(
        "bracketed_dot",
        r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}",
        ".",
        "[.] (.) {.} and their spaced variants become a dot",
    ),
    _rule(
        "bracketed_dot_word",
        r"\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\}",
        ".",
        "[dot] (dot) {dot} become a dot",
        ignore_case=True,
    ),
    _rule(
        "spaced_dot_word",
        r"(?<=[0-9A-Za-z_-])\s+dot\s+(?=[0-9A-Za-z_-])",
        ".",
        "the bare word 'dot' between two label characters becomes a dot",
        ignore_case=True,
    ),
    # ---- scheme separators -----------------------------------------------------------------
    _rule(
        "bracketed_scheme_separator",
        r"\[\s*://\s*\]|\(\s*://\s*\)|\{\s*://\s*\}",
        "://",
        "[://] becomes a scheme separator",
    ),
    _rule(
        "bracketed_double_slash",
        r"\[\s*//\s*\]|\(\s*//\s*\)|\{\s*//\s*\}",
        "//",
        "[//] becomes a double slash",
    ),
    _rule(
        "bracketed_slash",
        r"\[\s*/\s*\]|\(\s*/\s*\)|\{\s*/\s*\}",
        "/",
        "[/] becomes a slash",
    ),
    _rule(
        "bracketed_colon",
        r"\[\s*:\s*\]|\(\s*:\s*\)|\{\s*:\s*\}",
        ":",
        "[:] becomes a colon",
    ),
    # ---- at signs ---------------------------------------------------------------------------
    _rule(
        "bracketed_at",
        r"\[\s*@\s*\]|\(\s*@\s*\)|\{\s*@\s*\}",
        "@",
        "[@] becomes an at sign",
    ),
    _rule(
        "bracketed_at_word",
        r"\[\s*at\s*\]|\(\s*at\s*\)|\{\s*at\s*\}",
        "@",
        "[at] (at) {at} become an at sign",
        ignore_case=True,
    ),
    _rule(
        "spaced_at_word",
        r"(?<=[0-9A-Za-z_.+-])\s+at\s+(?=[0-9A-Za-z_-])",
        "@",
        "the bare word 'at' between an address character and a label character becomes an at sign",
        ignore_case=True,
    ),
    # ---- schemes ------------------------------------------------------------------------------
    # Each requires a real "://" immediately after, which the separator rules above have already
    # restored. A bare "hxxp" with nothing after it is not a URL and is left alone.
    _rule(
        "hxxp_scheme",
        r"(?<![0-9A-Za-z])(?:hxxp|h\*\*p|httx)(s?)(?=://)",
        _lowercase_http_scheme,
        "hxxp / hXXp / h**p / httx become http, and the s-suffixed forms become https",
        ignore_case=True,
    ),
    _rule(
        "meow_scheme",
        r"(?<![0-9A-Za-z])meow(s?)(?=://)",
        _lowercase_http_scheme,
        "meow / meows become http / https",
        ignore_case=True,
    ),
    _rule(
        "fxp_scheme",
        r"(?<![0-9A-Za-z])fxp(?=://)",
        "ftp",
        "fxp becomes ftp",
        ignore_case=True,
    ),
)

#: Ceiling on rule-table passes. Reaching it means the table did not converge, which would break
#: idempotency silently; :data:`PASS_LIMIT_TRANSFORM` is recorded instead, so the analyst and the
#: test suite both see it. Five nested bracket layers need five passes; ten is slack.
MAX_PASSES = 10

#: Recorded in :attr:`RefangResult.transforms` when :data:`MAX_PASSES` is exhausted.
PASS_LIMIT_TRANSFORM = "pass_limit_reached"

#: Transforms that are cosmetic rather than evidence of deliberate defanging. Trimming a quote a
#: mail client added says nothing about the analyst's input; ``[.]`` says a great deal.
_COSMETIC_TRANSFORMS = frozenset({"strip_wrappers"})

TRANSFORM_DESCRIPTIONS: Dict[str, str] = {
    "zero_width": "zero-width characters removed (U+200B, U+200C, U+200D, U+FEFF)",
    "nbsp": "non-breaking space (U+00A0) folded to an ordinary space",
    "strip_wrappers": "surrounding whitespace, quotes and angle brackets trimmed",
    PASS_LIMIT_TRANSFORM: f"rule table did not converge within {MAX_PASSES} passes",
    **{rule.name: rule.description for rule in REFANG_RULES},
}


# --------------------------------------------------------------------------------------
# Result
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class RefangResult:
    """What was pasted, what it was rewritten to, and every rule that fired.

    ``raw`` is preserved exactly. Renderers show both, because an analyst must be able to
    confirm the tool investigated the thing they meant.
    """

    raw: str
    value: str
    transforms: Tuple[str, ...] = ()

    @property
    def changed(self) -> bool:
        """True when the rewritten value differs from the raw input in any way at all."""
        return self.value != self.raw

    @property
    def was_defanged(self) -> bool:
        """True when a *defanging* rule fired, ignoring cosmetic trimming.

        This is the flag that belongs in a report. ``' evil.com '`` was not defanged, it was
        pasted with whitespace around it. ``evil[.]com`` was.
        """
        return any(name not in _COSMETIC_TRANSFORMS for name in self.transforms)

    def describe(self) -> Tuple[str, ...]:
        """Human-readable lines for the transforms that fired, in the order they fired."""
        return tuple(TRANSFORM_DESCRIPTIONS.get(name, name) for name in self.transforms)


# --------------------------------------------------------------------------------------
# The transform
# --------------------------------------------------------------------------------------


def refang(raw: str) -> RefangResult:
    """Rewrite a defanged indicator into its live-looking form. Pure; performs no I/O.

    Returns a :class:`RefangResult` carrying the original string, the rewritten value, and the
    ordered names of the rules that fired. Never raises on content: any string is acceptable
    input, the empty string included.

    Raises:
        TypeError: if ``raw`` is not a ``str``. That is a programming error at a trust
            boundary, not a malformed indicator, and coercing it silently would hide the bug.
    """
    if not isinstance(raw, str):
        raise TypeError(f"refang() expects a str, got {type(raw).__name__}")

    fired: List[str] = []
    working = raw

    without_zero_width = _ZERO_WIDTH_RE.sub("", working)
    if without_zero_width != working:
        fired.append("zero_width")
        working = without_zero_width

    if NBSP in working:
        fired.append("nbsp")
        working = working.replace(NBSP, " ")

    trimmed = working.strip(_WRAPPER_CHARS)
    if trimmed != working:
        fired.append("strip_wrappers")
        working = trimmed

    masked, vault = _mask_ipv6_literals(working)

    converged = False
    for _ in range(MAX_PASSES):
        changed_this_pass = False
        for rule in REFANG_RULES:
            replaced, count = rule.pattern.subn(rule.replacement, masked)
            if count:
                masked = replaced
                changed_this_pass = True
                if rule.name not in fired:
                    fired.append(rule.name)
        if not changed_this_pass:
            converged = True
            break

    if not converged:
        fired.append(PASS_LIMIT_TRANSFORM)

    unmasked = _unmask(masked, vault)
    value = unmasked.strip(_WRAPPER_CHARS)
    if value != unmasked and "strip_wrappers" not in fired:
        # Defensive. No rule in the current table can put a wrapper character at an edge -- they
        # emit '.', ':', '/', '@' and scheme letters -- so this is unreachable today. It exists
        # because a future rule that could would otherwise trim silently, and an unrecorded
        # rewrite breaks the contract that everything this function changes is named.
        fired.append("strip_wrappers")

    return RefangResult(raw=raw, value=value, transforms=tuple(fired))


def refang_value(raw: str) -> str:
    """:func:`refang` when only the rewritten string is wanted. Discards the audit trail."""
    return refang(raw).value
