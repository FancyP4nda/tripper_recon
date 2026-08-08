"""Regression tests for ``tripper_recon.reporting.console``.

These lock in three W0 fixes (commit ae59d18):

* **0.2** — ``render_ip_analysis`` must not render a green ``0/0`` when VirusTotal was never
  queried or errored. Pre-fix it summed an empty stats dict to ``0``, formatted
  ``[green]0/0[/]``, and an unset API key was visually indistinguishable from a clean verdict.
* **0.3** — ``esc()`` escapes provider-controlled strings. Pre-fix a provider value containing
  ``[/]`` raised ``rich.errors.MarkupError`` mid-render, and a value containing ``[green]…[/]``
  rendered as actual colour, letting a third party spoof the display.
* **AttributeError** — ``render_asn_header`` called ``meta["organization"].get("name")``
  unconditionally. IPInfo returns ``org`` as a plain string, so a string ``organization``
  raised ``AttributeError``.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import Any

import pytest
from rich.console import Console, RenderableType

from tripper_recon.reporting.console import esc, render_asn_bgp_panels, render_asn_header, render_ip_analysis

# ANSI SGR fragments rich emits for the named colours used by this module.
GREEN = "\x1b[32m"
GREEN_BOLD = "\x1b[1;32m"
RED = "\x1b[31m"
RED_BOLD = "\x1b[1;31m"


def _plain(renderable: RenderableType, *, width: int = 200) -> str:
    """Fallback for the shared ``render`` fixture: renderable -> plain (uncoloured) text."""
    console = Console(width=width, no_color=True, force_terminal=False, legacy_windows=False)
    with console.capture() as capture:
        console.print(renderable)
    return capture.get()


def _ansi(renderable: RenderableType, *, width: int = 200) -> str:
    """Render with colour on, so tests can assert on the *style* and not just the text."""
    console = Console(width=width, force_terminal=True, color_system="truecolor", legacy_windows=False)
    with console.capture() as capture:
        console.print(renderable)
    return capture.get()


# Prefer the shared ``render`` fixture from tests/conftest.py; only define a local one when
# conftest does not supply it, so this module runs standalone without shadowing the shared
# fixture. pytest has already imported conftest by the time this module is imported, but under
# what name depends on the import mode: bare ``conftest`` without tests/__init__.py, and
# ``tests.conftest`` with it. Scan sys.modules rather than guessing.
def _conftest_has_render() -> bool:
    for name, module in list(sys.modules.items()):
        if (name == "conftest" or name.endswith(".conftest")) and hasattr(module, "render"):
            return True
    return False


if not _conftest_has_render():

    @pytest.fixture
    def render() -> Callable[[RenderableType], str]:
        return _plain


# --------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------

IP = "203.0.113.7"

# A real VirusTotal answer for a clean IP: nothing malicious, but 94 engines did report.
REAL_CLEAN_STATS: dict[str, int] = {
    "harmless": 70,
    "malicious": 0,
    "suspicious": 0,
    "undetected": 24,
    "timeout": 0,
}

# The same shape for an IP eight engines flagged.
REAL_DIRTY_STATS: dict[str, int] = {
    "harmless": 60,
    "malicious": 8,
    "suspicious": 2,
    "undetected": 24,
    "timeout": 0,
}


def _ip_data(**overrides: Any) -> dict[str, Any]:
    """Minimal IP payload. Deliberately carries no abuseipdb block: that row is coloured too,
    and its green would pollute a 'nothing is green' assertion about VirusTotal."""
    data: dict[str, Any] = {"ipinfo": {"city": "Ashburn", "country": "US"}}
    data.update(overrides)
    return data


# --------------------------------------------------------------------------------------------
# 0.2 — absent / errored VirusTotal must not render a green 0/0
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides,case",
    [
        ({}, "virustotal key missing entirely"),
        ({"virustotal": {}}, "virustotal present but empty"),
        ({"virustotal": {"vt_last_analysis_stats": {}}}, "stats dict present but empty"),
    ],
)
def test_absent_virustotal_renders_no_data_not_zero_of_zero(
    render: Callable[[RenderableType], str], overrides: dict[str, Any], case: str
) -> None:
    """Pre-fix this rendered ``0/0``; the count is meaningless when nobody answered."""
    out = render(render_ip_analysis(IP, _ip_data(**overrides)))

    assert "virustotal_detections" in out, case
    assert "no data" in out, case
    assert "0/0" not in out, case


@pytest.mark.parametrize(
    "overrides",
    [
        {},
        {"virustotal": {}},
        {"virustotal": {"vt_last_analysis_stats": {}}},
    ],
)
def test_absent_virustotal_is_not_green(overrides: dict[str, Any]) -> None:
    """The display-integrity half of 0.2: absence must not be *coloured* like a clean verdict.

    Pre-fix the row was ``[green]0/0[/]``. Asserting on plain text alone would not catch a
    regression that kept the green and only changed the digits.
    """
    out = _ansi(render_ip_analysis(IP, _ip_data(**overrides)))

    assert GREEN not in out
    assert GREEN_BOLD not in out


def test_errored_virustotal_renders_no_data() -> None:
    """A provider error is the other route to an empty stats dict."""
    data = _ip_data(
        virustotal={},
        errors={"virustotal": {"status_code": 401, "reason": "Unauthorized", "url": "https://vt/api"}},
    )
    out = _plain(render_ip_analysis(IP, data))

    assert "no data" in out
    assert "0/0" not in out
    assert "provider_errors" in out
    assert "status=401" in out


def test_real_clean_scan_still_renders_the_count(render: Callable[[RenderableType], str]) -> None:
    """Do not over-suppress: a real scan where every engine said 'clean' is 0/94, not 'no data'."""
    out = render(render_ip_analysis(IP, _ip_data(virustotal={"vt_last_analysis_stats": REAL_CLEAN_STATS})))

    assert "0/94" in out
    assert "no data" not in out


def test_real_clean_scan_is_green() -> None:
    out = _ansi(render_ip_analysis(IP, _ip_data(virustotal={"vt_last_analysis_stats": REAL_CLEAN_STATS})))

    assert GREEN in out or GREEN_BOLD in out
    assert RED not in out and RED_BOLD not in out


def test_malicious_result_renders_red_with_the_right_count(render: Callable[[RenderableType], str]) -> None:
    vt = {"vt_last_analysis_stats": REAL_DIRTY_STATS}
    plain = render(render_ip_analysis(IP, _ip_data(virustotal=vt)))
    coloured = _ansi(render_ip_analysis(IP, _ip_data(virustotal=vt)))

    assert "8/94" in plain
    assert "no data" not in plain
    assert RED in coloured or RED_BOLD in coloured
    assert GREEN not in coloured and GREEN_BOLD not in coloured


# --------------------------------------------------------------------------------------------
# 0.3 — provider-controlled strings are escaped
# --------------------------------------------------------------------------------------------


def test_otx_pulse_title_with_close_tag_does_not_raise(render: Callable[[RenderableType], str]) -> None:
    """Pre-fix an unescaped ``[/]`` raised MarkupError and killed the whole report."""
    data = _ip_data(otx={"otx_pulse_count": 1, "otx_pulse_titles": ["evil [/] crew"]})

    out = render(render_ip_analysis(IP, data))  # must not raise

    assert "evil [/] crew" in out


def test_otx_pulse_title_colour_tags_render_as_literal_text() -> None:
    """A pulse title of ``[green]0/94 clean[/]`` must read as those characters, never as colour.

    This is the display-spoof case: an attacker who can name a pulse could otherwise paint a
    fake clean verdict into the analyst's terminal.
    """
    title = "[green]0/94 clean[/]"
    data = _ip_data(otx={"otx_pulse_count": 1, "otx_pulse_titles": [title]})
    renderable = render_ip_analysis(IP, data)

    plain = _plain(renderable)
    coloured = _ansi(renderable)

    assert title in plain, "the tags must survive as literal characters"
    assert "[green]" in coloured, "the tag text must still be visible, not consumed as markup"
    assert GREEN not in coloured and GREEN_BOLD not in coloured, "the tag must not become actual colour"


def test_hostile_org_name_is_escaped(render: Callable[[RenderableType], str]) -> None:
    """A hostile org string. Shodan itself only contributes ports here, so the org reaches the
    report through ``asn_meta.organization`` / ``ipinfo.org`` -- same escaping path, same risk."""
    hostile = "Evil[green]Corp[/]"
    data = _ip_data(shodan={"ports": [80, 443]}, asn_meta={"organization": hostile})

    out = render(render_ip_analysis(IP, data))
    coloured = _ansi(render_ip_analysis(IP, data))

    assert hostile in out
    assert GREEN not in coloured and GREEN_BOLD not in coloured


def test_hostile_ipinfo_city_is_escaped(render: Callable[[RenderableType], str]) -> None:
    hostile_city = "Bad[/]Town"
    data = {"ipinfo": {"city": hostile_city, "country": "[red]XX[/]"}}

    out = render(render_ip_analysis(IP, data))  # must not raise

    assert hostile_city in out
    assert "[red]XX[/]" in out


# --------------------------------------------------------------------------------------------
# esc() itself
# --------------------------------------------------------------------------------------------


def test_esc_none_is_empty_string() -> None:
    assert esc(None) == ""


@pytest.mark.parametrize("value,expected", [(0, "0"), (42, "42"), (3.5, "3.5"), (True, "True")])
def test_esc_coerces_non_strings(value: Any, expected: str) -> None:
    assert esc(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("[green]", "\\[green]"),
        ("[/]", "\\[/]"),
        ("a [bold red]b[/] c", "a \\[bold red]b\\[/] c"),
    ],
)
def test_esc_escapes_markup_brackets(value: str, expected: str) -> None:
    assert esc(value) == expected


def test_esc_leaves_plain_text_untouched() -> None:
    assert esc("Cloudflare, Inc.") == "Cloudflare, Inc."


# --------------------------------------------------------------------------------------------
# render_asn_header
# --------------------------------------------------------------------------------------------


def test_asn_header_organization_as_string(render: Callable[[RenderableType], str]) -> None:
    """The AttributeError case: IPInfo hands back ``organization`` as a plain string, and pre-fix
    ``org.get("name")`` blew up before anything rendered."""
    out = render(render_asn_header(13335, {"organization": "Cloudflare, Inc."}))

    assert "AS13335" in out
    assert "Cloudflare, Inc." in out
    # With no explicit `name`, the string organization becomes the AS name and the title.
    assert "AS Name" in out
    assert "Organization" in out


def test_asn_header_organization_as_dict(render: Callable[[RenderableType], str]) -> None:
    out = render(render_asn_header(15169, {"name": "GOOGLE", "organization": {"name": "Google LLC"}}))

    assert "GOOGLE" in out
    assert "Google LLC" in out
    assert "Organization" in out


def test_asn_header_organization_absent(render: Callable[[RenderableType], str]) -> None:
    out = render(render_asn_header(64512, {"name": "EXAMPLE-AS", "rir": "arin"}))

    assert "EXAMPLE-AS" in out
    assert "Organization" not in out
    assert "ARIN" in out  # rir is normalised through the description map


def test_asn_header_with_no_name_at_all(render: Callable[[RenderableType], str]) -> None:
    """Empty meta: no AS Name row, no Organization row, and the title omits the parenthetical."""
    out = render(render_asn_header(64512, {}))

    assert "AS64512" in out
    assert "AS Name" not in out
    assert "Organization" not in out
    assert "()" not in out
    assert "NONE" in out  # Peering @IXPs falls back to NONE


def test_asn_header_escapes_hostile_name(render: Callable[[RenderableType], str]) -> None:
    out = render(render_asn_header(64512, {"name": "AS[/]NAME"}))

    assert "AS[/]NAME" in out


# --------------------------------------------------------------------------------------------
# provider_errors sub-table shapes
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "detail,expected",
    [
        ({"status_code": 429, "reason": "Too Many Requests", "message": "slow down"}, "status=429"),
        ({"status": "403", "url": "https://api.example/v1", "body": "denied"}, "status=403"),
        ({}, "error"),  # dict with nothing usable still renders a placeholder
        ("plain string failure", "plain string failure"),
        (["first", "second"], "first"),
        (None, "provider_errors"),
    ],
)
def test_provider_errors_renders_for_any_detail_shape(detail: Any, expected: str) -> None:
    data = _ip_data(errors={"shodan": detail})

    out = _plain(render_ip_analysis(IP, data))  # must not raise for any shape

    assert "provider_errors" in out
    assert "shodan" in out
    assert expected in out


def test_provider_errors_escapes_hostile_detail() -> None:
    """An error body is provider-controlled too, and reaches the terminal on the failure path."""
    data = _ip_data(errors={"otx": {"message": "boom [/] [green]ok[/]"}})

    plain = _plain(render_ip_analysis(IP, data))
    coloured = _ansi(render_ip_analysis(IP, data))

    assert "boom [/] [green]ok[/]" in plain
    assert GREEN not in coloured and GREEN_BOLD not in coloured


# --------------------------------------------------------------------------------------------
# 4.7 — the BGP hijack envelope
#
# The provider module (``providers/cloudflare_rest.bgp_incidents``) was rewritten so it stops
# emitting a role split it cannot substantiate. Its envelope keys changed, and this renderer
# had to change with them. What is under test here is not formatting: it is that the renderer
# never presents an inference as an observation.
#
# The defect these lock out, in the order it used to happen:
#   1. ``as_victim = total - as_hijacker`` — a subtraction across two different denominators
#      (an all-pages total against a single-page count).
#   2. that remainder rendered as the sentence "always as a victim" — an attribution claim.
#   3. ``hj.get("total") or 0`` — which turned an unknown total into a confident zero, and,
#      after the provider rename, would print the literal string ``None`` as the count.
# --------------------------------------------------------------------------------------------

ASN = 64500


def _hijacks(**overrides: Any) -> dict[str, Any]:
    """A complete hijack envelope in the shape ``_summarise_hijacks`` returns."""
    envelope: dict[str, Any] = {
        "total_incidents": 4,
        "events_examined": 4,
        "pages_fetched": 1,
        "counts_complete": True,
        "as_hijacker": 1,
        "as_victim": 3,
        "split_available": True,
        "split_unavailable_reason": None,
    }
    envelope.update(overrides)
    return envelope


def _bgp_line(render: Callable[..., str], **bgp: Any) -> str:
    """Render the BGP panel group and return it as one whitespace-normalised line."""
    out = render(render_asn_bgp_panels(ASN, {}, bgp), width=200)
    return " ".join(out.split())


# Panel 1 emits these row labels, in this order. Slicing between them isolates a single row,
# which matters for the negative assertions: the panel also carries the ASN and a Radar URL, so
# a bare ``"6" not in line`` would match the ``6`` inside ``AS64500`` and fail for the wrong
# reason. A negative assertion that can pass or fail by accident is not evidence.
_PANEL1_LABELS = (
    "BGP Neighbors",
    "Customer cone",
    "BGP Hijacks (past 1y)",
    "BGP Route leaks (past 1y)",
    "In-depth BGP info",
)


def _bgp_row(render: Callable[..., str], label: str, **bgp: Any) -> str:
    """Return just the value cell of one panel-1 row, whitespace-normalised."""
    line = _bgp_line(render, **bgp)
    if f"{label} " not in line:
        return ""
    tail = line.split(f"{label} ", 1)[1]
    for other in _PANEL1_LABELS:
        if other != label:
            tail = tail.split(f" {other}", 1)[0]
    return tail.strip()


def test_hijack_absent_total_says_unavailable_not_none(render: Callable[..., str]) -> None:
    """Cloudflare reporting no ``total_count`` is unknown, not zero and not the word ``None``.

    Pre-fix, ``hj.get("total") or 0`` read the removed key, got ``None``, and the row rendered
    the affirmative-looking literal ``None`` — which an analyst reads as "no incidents".
    """
    line = _bgp_line(render, hijacks=_hijacks(total_incidents=None, split_available=False))

    assert "BGP Hijacks (past 1y) unavailable (Cloudflare reported no total)" in line
    assert "Involved in" not in line


def test_hijack_zero_total_says_none(render: Callable[..., str]) -> None:
    """A counted zero is a real observation and keeps saying so."""
    line = _bgp_line(render, hijacks=_hijacks(total_incidents=0, events_examined=0, as_hijacker=0, as_victim=0))

    assert "BGP Hijacks (past 1y) None" in line


@pytest.mark.parametrize(
    "as_hijacker,as_victim,expected",
    [
        (0, 4, "Involved in 4 incidents (always as a victim)"),
        (4, 0, "Involved in 4 incidents (always as a hijacker)"),
        (1, 3, "Involved in 4 incidents (1 as hijacker • 3 as victim)"),
    ],
)
def test_hijack_split_is_rendered_when_substantiated(
    render: Callable[..., str], as_hijacker: int, as_victim: int, expected: str
) -> None:
    """The prose forms are permitted — but only over a complete, provider-confirmed split."""
    line = _bgp_line(render, hijacks=_hijacks(as_hijacker=as_hijacker, as_victim=as_victim))

    assert expected in line


def test_hijack_singular_incident(render: Callable[..., str]) -> None:
    line = _bgp_line(render, hijacks=_hijacks(total_incidents=1, events_examined=1, as_hijacker=0, as_victim=1))

    assert "Involved in 1 incident (always as a victim)" in line
    assert "1 incidents" not in line


def test_hijack_without_split_reports_the_reason_and_no_role_numbers(render: Callable[..., str]) -> None:
    """When the enumeration is incomplete the renderer must say so and print no role counts."""
    row = _bgp_row(
        render,
        "BGP Hijacks (past 1y)",
        hijacks=_hijacks(
            total_incidents=97,
            events_examined=50,
            pages_fetched=10,
            counts_complete=False,
            as_hijacker=None,
            as_victim=None,
            split_available=False,
            split_unavailable_reason="pagination_page_limit_reached",
        ),
    )

    assert row == (
        "Involved in 97 incidents (role split unavailable: pagination_page_limit_reached; 50 of 97 incidents examined)"
    )
    assert "as hijacker" not in row
    assert "as victim" not in row


def test_hijack_never_recomputes_the_victim_count(render: Callable[..., str]) -> None:
    """``total_incidents - as_hijacker`` must not reappear in the renderer.

    This is the exact defect the provider rewrite removed. A partial envelope that still
    carries a hijacker count is the shape that tempts a renderer into finishing the arithmetic:
    10 total, 3 hijacker, therefore "7 as victim". Seven is not an observation of anything.
    """
    row = _bgp_row(
        render,
        "BGP Hijacks (past 1y)",
        hijacks=_hijacks(
            total_incidents=10,
            events_examined=3,
            counts_complete=False,
            as_hijacker=3,
            as_victim=None,
            split_available=False,
            split_unavailable_reason="events_do_not_name_victims",
        ),
    )

    assert "7" not in row
    assert "as victim" not in row
    assert "as hijacker" not in row


def test_hijack_split_claimed_but_incomplete_is_not_trusted(render: Callable[..., str]) -> None:
    """A cached or hand-edited envelope claiming a split without both counts prints neither.

    ``split_available`` is the provider's assertion. Rendering ``None as hijacker`` on the
    strength of it would be the same failure mode in a new coat.
    """
    line = _bgp_line(render, hijacks=_hijacks(as_victim=None, split_available=True))

    assert "role split unavailable" in line
    assert "None as" not in line


@pytest.mark.parametrize("bogus", ["4", True, 4.5, None])
def test_hijack_non_integer_total_is_unavailable_never_zero(render: Callable[..., str], bogus: Any) -> None:
    """Anything that is not a real count is unknown. It is never silently coerced to zero."""
    line = _bgp_line(render, hijacks=_hijacks(total_incidents=bogus, split_available=False))

    assert "unavailable (Cloudflare reported no total)" in line
    assert "BGP Hijacks (past 1y) None" not in line


def test_hijack_legacy_envelope_keys_are_not_read(render: Callable[..., str]) -> None:
    """The pre-rewrite keys are gone. Reading them again would resurrect the old semantics."""
    row = _bgp_row(render, "BGP Hijacks (past 1y)", hijacks={"total": 12, "as_hijacker": 5, "as_victim": 7})

    assert row == "unavailable (Cloudflare reported no total)"


def test_hijack_reason_is_escaped(render: Callable[..., str]) -> None:
    """The reason string reaches the terminal; treat it as untrusted like every other field.

    Asserted on the plain render rather than on ANSI: panel 3 legitimately styles its own
    labels green, so a whole-output ``GREEN not in`` check would fail on unrelated colour. If
    the reason were unescaped, rich would consume the tags and the literal text would vanish.
    """
    row = _bgp_row(
        render,
        "BGP Hijacks (past 1y)",
        hijacks=_hijacks(split_available=False, split_unavailable_reason="[green]clean[/]"),
    )

    assert "[green]clean[/]" in row


def test_hijack_row_omitted_when_cloudflare_did_not_answer(render: Callable[..., str]) -> None:
    """No envelope means the question was never answered; the row stays off the screen.

    Rendering a zero here would be the ``0/0`` defect again in a different panel.
    """
    line = _bgp_line(render, ripe_announced_prefixes_v4=3)

    assert "BGP Hijacks" not in line


# --------------------------------------------------------------------------------------------
# route leaks
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "total,expected",
    [
        (None, "BGP Route leaks (past 1y) unavailable (Cloudflare reported no total)"),
        (0, "BGP Route leaks (past 1y) None"),
        (6, "BGP Route leaks (past 1y) 6"),
    ],
)
def test_leaks_distinguish_unknown_from_zero(render: Callable[..., str], total: Any, expected: str) -> None:
    line = _bgp_line(render, leaks={"total_incidents": total})

    assert expected in line


def test_leaks_legacy_total_key_is_not_read(render: Callable[..., str]) -> None:
    row = _bgp_row(render, "BGP Route leaks (past 1y)", leaks={"total": 6})

    assert row == "unavailable (Cloudflare reported no total)"


# --------------------------------------------------------------------------------------------
# 2.3 — address provenance
#
# ``orchestrators._tag_ip_sources`` records whether an address was resolved now or only ever
# seen historically by VirusTotal. Those are different evidentiary claims and the analyst has
# to be able to tell which one is on screen; before this the two were concatenated into one
# undifferentiated list and the distinction was destroyed at assembly time.
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source,must_contain",
    [
        ("active", "resolved now by the system resolver"),
        ("passive", "seen historically in VirusTotal DNS records, may be stale"),
        ("active+passive", "resolved now, and corroborated by VirusTotal DNS history"),
    ],
)
def test_address_source_states_the_evidentiary_claim(
    render: Callable[..., str], source: str, must_contain: str
) -> None:
    out = render(render_ip_analysis(IP, _ip_data(source=source)))

    assert "address_source" in out
    assert source in " ".join(out.split())
    assert must_contain in " ".join(out.split())


def test_passive_only_address_is_not_described_as_resolved(render: Callable[..., str]) -> None:
    """The whole point of the tag: a passive hit must not read as a live answer."""
    out = " ".join(render(render_ip_analysis(IP, _ip_data(source="passive"))).split())

    assert "resolved now" not in out


def test_absent_source_renders_no_row(render: Callable[..., str]) -> None:
    """On the ``ip`` subcommand the operator supplied the address; there is no claim to qualify."""
    out = render(render_ip_analysis(IP, _ip_data()))

    assert "address_source" not in out


@pytest.mark.parametrize("empty", ["", "   ", None])
def test_empty_source_renders_no_row(render: Callable[..., str], empty: Any) -> None:
    out = render(render_ip_analysis(IP, _ip_data(source=empty)))

    assert "address_source" not in out


def test_unknown_source_tag_is_echoed_not_guessed_at(render: Callable[..., str]) -> None:
    """A tag this renderer does not know is still a fact the collector recorded."""
    out = " ".join(render(render_ip_analysis(IP, _ip_data(source="ct-log"))).split())

    assert "address_source ct-log" in out
    assert "resolved now" not in out


def test_hostile_source_tag_is_escaped() -> None:
    coloured = _ansi(render_ip_analysis(IP, _ip_data(source="[green]active[/]")))

    assert GREEN not in coloured and GREEN_BOLD not in coloured
