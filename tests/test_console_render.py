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

and the W4 rendering half (4.4, 4.5, 4.8), which exists to close the tool's most dangerous
gap: with two of six credentials configured the console showed a VirusTotal score and one
Shodan error and said nothing at all about the four providers that were never asked. Sparse
output reads as a clean indicator. The tests below assert the three properties that stop it:

* a **coverage line** in every render, naming the providers that did not answer;
* a **run header** carrying tool version, UTC timestamp and run id, so a pasted report says
  what produced it;
* **no absence rendered as a zero and none rendered in green** — for AbuseIPDB, OTX and Shodan
  as well as for VirusTotal, which W0.2 fixed on its own.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Callable
from typing import Any

import pytest
from rich.console import Console, RenderableType

from tripper_recon import __version__
from tripper_recon.reporting.console import (
    esc,
    render_asn_bgp_panels,
    render_asn_header,
    render_coverage,
    render_domain_header,
    render_ip_analysis,
    render_run_header,
    render_skipped_ips,
    render_warnings,
    summarize_coverage,
)

# ANSI SGR fragments rich emits for the named colours used by this module.
GREEN = "\x1b[32m"
GREEN_BOLD = "\x1b[1;32m"
RED = "\x1b[31m"
RED_BOLD = "\x1b[1;31m"
YELLOW = "\x1b[33m"
YELLOW_BOLD = "\x1b[1;33m"


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


def _row(rendered: str, key: str) -> str:
    """Return the value cell of the ``key`` row of a rendered field table.

    Whole-output assertions were adequate when VirusTotal was the only row that could say
    "no data". It now shares that vocabulary with AbuseIPDB, OTX and Shodan — by design, since
    every provider that did not answer has to say so — which makes a bare ``"no data" not in
    out`` a test of the whole screen rather than of the row it means. Scope to the row.
    """
    for line in rendered.splitlines():
        stripped = line.strip()
        if stripped.startswith(key):
            return stripped[len(key) :].strip()
    return ""


def _status(**outcomes: str) -> dict[str, dict[str, Any]]:
    """A ``provider_status`` map in the shape ``orchestrators._status_map`` emits."""
    return {name: {"outcome": outcome, "elapsed_seconds": 0.4} for name, outcome in outcomes.items()}


#: The realistic failure this whole workstream exists for: two of six credentials configured.
TWO_OF_SIX = _status(
    virustotal="ok",
    shodan="error",
    ipinfo="not_configured",
    abuseipdb="not_configured",
    otx="not_configured",
    cloudflare_asn="not_configured",
)


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
    assert _row(out, "virustotal_detections") == "0/94"
    assert "no data" not in _row(out, "virustotal_detections")


def test_real_clean_scan_is_green() -> None:
    out = _ansi(render_ip_analysis(IP, _ip_data(virustotal={"vt_last_analysis_stats": REAL_CLEAN_STATS})))

    assert GREEN in out or GREEN_BOLD in out
    assert RED not in out and RED_BOLD not in out


def test_malicious_result_renders_red_with_the_right_count(render: Callable[[RenderableType], str]) -> None:
    vt = {"vt_last_analysis_stats": REAL_DIRTY_STATS}
    plain = render(render_ip_analysis(IP, _ip_data(virustotal=vt)))
    coloured = _ansi(render_ip_analysis(IP, _ip_data(virustotal=vt)))

    assert "8/94" in plain
    assert "no data" not in _row(plain, "virustotal_detections")
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


def _fully_answered_ip_data(**overrides: Any) -> dict[str, Any]:
    """An IP payload in which every provider answered with usable data.

    Nothing in this render is yellow: coverage is complete, no row is an absence. That makes it
    the fixture for colour assertions about one specific row — any yellow in the output can
    only have come from the row under test.
    """
    data: dict[str, Any] = {
        "ipinfo": {"city": "Ashburn", "country": "US"},
        "virustotal": {"vt_last_analysis_stats": REAL_CLEAN_STATS},
        "shodan": {"ports": [443]},
        "abuseipdb": {"abuseipdb_reports": 0, "abuseipdb_confidence_score": 0},
        "otx": {"otx_pulse_count": 0},
        "provider_status": _status(virustotal="ok", shodan="ok", ipinfo="ok", abuseipdb="ok", otx="ok"),
    }
    data.update(overrides)
    return data


def test_a_fully_answered_lookup_renders_no_yellow() -> None:
    """The control for the two tests below: without a source row there is nothing yellow left."""
    assert YELLOW not in _ansi(render_ip_analysis(IP, _fully_answered_ip_data()))
    assert YELLOW_BOLD not in _ansi(render_ip_analysis(IP, _fully_answered_ip_data()))


def test_passive_and_active_provenance_do_not_look_alike() -> None:
    """2.3 carried into colour: the weaker evidentiary claim has to be visibly weaker.

    An analyst skimming a domain report reads the address rows, not the glosses beside them.
    "Seen historically in VirusTotal DNS records" and "resolved now" are different claims and
    must not be distinguishable only by careful reading.
    """
    passive = _ansi(render_ip_analysis(IP, _fully_answered_ip_data(source="passive")))
    active = _ansi(render_ip_analysis(IP, _fully_answered_ip_data(source="active")))

    assert YELLOW in passive or YELLOW_BOLD in passive
    assert YELLOW not in active and YELLOW_BOLD not in active


def test_unknown_source_tag_is_not_dressed_up_in_colour() -> None:
    """Styling an uninterpreted tag would assert a strength the renderer has not established."""
    out = _ansi(render_ip_analysis(IP, _fully_answered_ip_data(source="ct-log")))

    assert YELLOW not in out and YELLOW_BOLD not in out
    assert "ct-log" in _plain(render_ip_analysis(IP, _fully_answered_ip_data(source="ct-log")))


# --------------------------------------------------------------------------------------------
# 4.4 — the coverage line
#
# The verified failure this closes: run the tool with two of six credentials set and the screen
# shows a VirusTotal score, one Shodan error, and nothing whatsoever about the four providers
# that were never asked. The truth was in ``provider_status`` the whole time and absent from
# the display. An analyst reads sparse output as a clean indicator.
# --------------------------------------------------------------------------------------------


def test_coverage_line_states_the_ratio_and_names_the_missing_providers(render: Callable[..., str]) -> None:
    out = render(render_ip_analysis(IP, _ip_data(provider_status=TWO_OF_SIX)))

    assert "provider_coverage: 1 of 6 providers answered" in out
    # Naming them is the point: "some providers are missing" is not actionable, "AbuseIPDB and
    # OTX were never asked" is.
    for never_asked in ("abuseipdb", "cloudflare_asn", "ipinfo", "otx"):
        assert never_asked in out
    assert "never asked - no API key configured" in out
    assert "query failed: shodan" in out


def test_coverage_line_sits_above_the_body_not_in_a_footer(render: Callable[..., str]) -> None:
    """A reader who stops after the first screen must still have seen how much was missing."""
    out = render(render_ip_analysis(IP, _ip_data(provider_status=TWO_OF_SIX)))

    assert out.index("provider_coverage") < out.index("virustotal_detections")


def test_coverage_is_rendered_even_when_every_provider_answered(render: Callable[..., str]) -> None:
    status = _status(virustotal="ok", shodan="ok", ipinfo="ok")
    out = render(render_ip_analysis(IP, _ip_data(provider_status=status)))

    assert "provider_coverage: 3 of 3 providers answered" in out


@pytest.mark.parametrize(
    "status,expected_style",
    [
        (_status(a="ok", b="ok"), GREEN_BOLD),
        (_status(a="ok", b="not_configured"), YELLOW_BOLD),
        (_status(a="error", b="not_configured"), RED_BOLD),
        (None, YELLOW_BOLD),
    ],
    ids=["complete", "partial", "nothing-answered", "unknown"],
)
def test_coverage_colour_tracks_completeness(status: Any, expected_style: str) -> None:
    """Colour here is a claim about coverage, never about the indicator.

    Green means the picture is complete. Nothing about this line may be read as "clean", which
    is why the no-status case is yellow rather than absent or green.
    """
    out = _ansi(render_coverage(status))

    assert expected_style in out
    if expected_style is not GREEN_BOLD:
        assert GREEN not in out and GREEN_BOLD not in out


def test_coverage_unknown_when_no_provider_status_was_recorded(render: Callable[..., str]) -> None:
    """Silence about coverage is the failure mode. Unknown coverage says so out loud."""
    out = render(render_ip_analysis(IP, _ip_data()))

    assert "provider_coverage: unknown" in out
    assert "no provider status was recorded" in out


def test_coverage_counts_a_reached_provider_that_holds_no_record_as_answered(
    render: Callable[..., str],
) -> None:
    """``not_found`` is evidence: the provider was reached and holds nothing on this indicator.

    It is still named, because "answered, holds no record" and "answered with data" are not the
    same input to a verdict.
    """
    status = _status(virustotal="ok", otx="not_found")
    out = render(render_ip_analysis(IP, _ip_data(provider_status=status)))

    assert "provider_coverage: 2 of 2 providers answered" in out
    assert "answered, holds no record: otx" in out


@pytest.mark.parametrize("outcome", ["quota_exhausted", "", "  "])
def test_coverage_fails_closed_on_an_outcome_it_does_not_recognise(render: Callable[..., str], outcome: str) -> None:
    """An outcome this renderer has never seen is a gap, never silently counted as coverage.

    The data model is being extended in parallel with this renderer. A new outcome value must
    degrade to "we do not know that this provider answered", which is the safe direction.
    """
    status = _status(virustotal="ok", shodan=outcome)
    out = render(render_ip_analysis(IP, _ip_data(provider_status=status)))

    assert "provider_coverage: 1 of 2 providers answered" in out
    assert "shodan" in out


@pytest.mark.parametrize(
    "junk",
    [None, {}, [], "not a mapping", 7, {"shodan": None}, {"shodan": "ok"}, {"shodan": {"no_outcome_key": 1}}],
)
def test_summarize_coverage_never_raises(junk: Any) -> None:
    """Coverage reporting is the control that stops absence reading as safety.

    It is not allowed to be the thing that crashes the report, so it takes anything.
    """
    summary = summarize_coverage(junk)

    assert summary.answered <= summary.total
    assert summary.answered >= 0


def test_summarize_coverage_reads_a_bare_outcome_string() -> None:
    """Tolerated shape: ``{"shodan": "ok"}`` rather than ``{"shodan": {"outcome": "ok"}}``."""
    summary = summarize_coverage({"shodan": "ok", "otx": "not_configured"})

    assert (summary.answered, summary.total) == (1, 2)
    assert summary.groups["not_configured"] == ["otx"]


def test_coverage_provider_names_cannot_inject_markup() -> None:
    """Provider names are dictionary keys, but the line is built as Text and never parsed.

    A key such as ``[green]clean[/]`` reaches the terminal as those characters, exactly like an
    OTX pulse title does through ``esc``.
    """
    hostile = "[green]clean[/]"
    coloured = _ansi(render_coverage({hostile: {"outcome": "not_configured"}}))
    plain = _plain(render_coverage({hostile: {"outcome": "not_configured"}}))

    assert hostile in plain
    assert GREEN not in coloured and GREEN_BOLD not in coloured


# --------------------------------------------------------------------------------------------
# 4.5 — the run header
#
# The header was ``--- IP lookup for {ip} ---`` and nothing else: no tool version, no
# timestamp, no run id. A report pasted into a ticket could not say what produced it or when,
# and could not be tied back to the JSON export of the same run.
# --------------------------------------------------------------------------------------------


def test_run_header_carries_version_timestamp_and_run_id(render: Callable[..., str]) -> None:
    out = render(
        render_ip_analysis(IP, _ip_data(), run_id="0f3c9a21", generated_at="2026-08-08T12:00:00Z"),
    )

    assert f"--- IP lookup for {IP} ---" in out
    assert f"tripper-recon {__version__}" in out
    assert "2026-08-08T12:00:00Z" in out
    assert "run 0f3c9a21" in out


def test_run_header_reads_the_run_id_off_the_payload(render: Callable[..., str]) -> None:
    """The orchestrator stamps the run onto the result; the renderer should not need telling."""
    out = render(render_ip_analysis(IP, _ip_data(run_id="deadbeef", generated_at="2026-08-08T12:00:00Z")))

    assert "run deadbeef" in out


def test_run_header_says_when_no_run_id_was_recorded(render: Callable[..., str]) -> None:
    """Omitting the field silently would leave the reader unable to tell absent from unset."""
    out = render(render_ip_analysis(IP, _ip_data()))

    assert "run id not recorded" in out


def test_run_header_timestamp_defaults_to_utc_now(render: Callable[..., str]) -> None:
    out = render(render_run_header("--- test ---"))

    assert re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", out)


def test_run_line_is_suppressible_for_nested_blocks_but_coverage_is_not(
    render: Callable[..., str],
) -> None:
    """Domain reports print many IP blocks; repeating the version line on each is noise.

    Coverage is not noise and has no opt-out: each address was investigated by its own set of
    providers and carries its own gap.
    """
    out = render(render_ip_analysis(IP, _ip_data(provider_status=TWO_OF_SIX), show_run_line=False))

    assert f"--- IP lookup for {IP} ---" in out
    assert f"tripper-recon {__version__}" not in out
    assert "provider_coverage: 1 of 6 providers answered" in out


# --------------------------------------------------------------------------------------------
# Absence never reads as safety — the rest of the rows
#
# W0.2 fixed this for VirusTotal alone. Every other provider kept the old behaviour: AbuseIPDB
# fell through a bare ``except`` to a green ``0%``, and OTX and Shodan simply dropped their rows
# and left the pivot link behind, which reads as "asked, found nothing".
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("outcome", ["not_configured", "error", "skipped", "weird_new_outcome"])
def test_abuseipdb_that_did_not_answer_is_never_a_green_zero(outcome: str) -> None:
    data = _ip_data(abuseipdb={}, provider_status=_status(abuseipdb=outcome))
    renderable = render_ip_analysis(IP, data)

    row = _row(_plain(renderable), "abuseipdb_confidence_score")
    coloured = _ansi(renderable)

    assert "no data" in row
    assert "0%" not in row
    assert GREEN not in coloured and GREEN_BOLD not in coloured


def test_abuseipdb_not_configured_says_so(render: Callable[..., str]) -> None:
    out = render(render_ip_analysis(IP, _ip_data(abuseipdb={}, provider_status=_status(abuseipdb="not_configured"))))

    assert "not configured" in _row(out, "abuseipdb_confidence_score")


def test_abuseipdb_zero_from_a_provider_that_answered_is_still_green() -> None:
    """Do not over-suppress. AbuseIPDB answering "nobody has reported this" is a real finding."""
    data = _ip_data(
        abuseipdb={"abuseipdb_reports": 0, "abuseipdb_confidence_score": 0},
        provider_status=_status(abuseipdb="ok"),
    )
    plain = _plain(render_ip_analysis(IP, data))
    coloured = _ansi(render_ip_analysis(IP, data))

    assert _row(plain, "abuseipdb_confidence_score") == "0%"
    assert GREEN in coloured or GREEN_BOLD in coloured


def test_abuseipdb_reported_activity_stays_red(render: Callable[..., str]) -> None:
    data = _ip_data(
        abuseipdb={"abuseipdb_reports": 47, "abuseipdb_confidence_score": 92},
        provider_status=_status(abuseipdb="ok"),
    )

    out = render(render_ip_analysis(IP, data))
    coloured = _ansi(render_ip_analysis(IP, data))

    assert _row(out, "abuseipdb_reports") == "47"
    assert _row(out, "abuseipdb_confidence_score") == "92%"
    assert RED in coloured or RED_BOLD in coloured


@pytest.mark.parametrize("score", [None, "", "n/a", {}, [], True])
def test_abuseipdb_unusable_score_is_not_coerced_to_a_green_zero(score: Any) -> None:
    """``int(conf_val)`` inside a bare ``except`` turned every one of these into ``0`` in green."""
    data = _ip_data(
        abuseipdb={"abuseipdb_reports": 3, "abuseipdb_confidence_score": score},
        provider_status=_status(abuseipdb="ok"),
    )
    plain = _plain(render_ip_analysis(IP, data))

    assert "no data" in _row(plain, "abuseipdb_confidence_score")
    # The count the provider did supply is still shown; only the missing score is withheld.
    assert _row(plain, "abuseipdb_reports") == "3"
    assert GREEN not in _ansi(render_ip_analysis(IP, data))


@pytest.mark.parametrize("score,expected", [(150, "100%"), (-4, "0%"), ("42", "42%")])
def test_abuseipdb_score_is_clamped_to_a_percentage(render: Callable[..., str], score: Any, expected: str) -> None:
    data = _ip_data(
        abuseipdb={"abuseipdb_confidence_score": score},
        provider_status=_status(abuseipdb="ok"),
    )

    assert _row(render(render_ip_analysis(IP, data)), "abuseipdb_confidence_score") == expected


def test_otx_that_was_never_asked_renders_no_data_not_an_absent_row(render: Callable[..., str]) -> None:
    """Pre-fix the count row vanished and the pivot link stayed, which reads as "OTX had nothing"."""
    out = render(render_ip_analysis(IP, _ip_data(otx={}, provider_status=_status(otx="not_configured"))))

    assert "no data" in _row(out, "otx_pulse_count")
    assert "otx_pulse_link" in out


def test_otx_zero_pulses_from_a_provider_that_answered_is_a_zero(render: Callable[..., str]) -> None:
    out = render(
        render_ip_analysis(IP, _ip_data(otx={"otx_pulse_count": 0}, provider_status=_status(otx="ok"))),
    )

    assert _row(out, "otx_pulse_count") == "0"


def test_shodan_that_was_never_asked_says_so_on_the_ports_row(render: Callable[..., str]) -> None:
    """An empty ports list is a finding when Shodan answered and a silence when it did not."""
    out = render(render_ip_analysis(IP, _ip_data(shodan={}, provider_status=_status(shodan="not_configured"))))

    assert "no data" in _row(out, "open_ports")


def test_shodan_that_answered_with_no_ports_says_none_reported(render: Callable[..., str]) -> None:
    out = render(
        render_ip_analysis(IP, _ip_data(shodan={"ports": [], "org": "Example"}, provider_status=_status(shodan="ok"))),
    )

    assert _row(out, "open_ports") == "none reported by Shodan"
    assert "no data" not in _row(out, "open_ports")


def test_virustotal_no_data_names_the_reason_when_it_is_known(render: Callable[..., str]) -> None:
    """W0.2 kept the generic wording; the outcome makes it specific without weakening it."""
    out = render(render_ip_analysis(IP, _ip_data(virustotal={}, provider_status=_status(virustotal="not_configured"))))

    row = _row(out, "virustotal_detections")
    assert "no data" in row
    assert "not configured" in row
    assert "0/0" not in row


def test_virustotal_error_outcome_says_the_query_failed(render: Callable[..., str]) -> None:
    out = render(render_ip_analysis(IP, _ip_data(virustotal={}, provider_status=_status(virustotal="error"))))

    assert _row(out, "virustotal_detections") == "no data - query failed"


# --------------------------------------------------------------------------------------------
# Skipped addresses (domain path)
#
# ``_investigate_domain`` drops private and reserved addresses before enrichment and records
# them in ``data['skipped_ips']``. Nothing rendered them, so an analyst who resolved four
# addresses and saw one investigated had no way to learn what happened to the other three.
# --------------------------------------------------------------------------------------------

SKIPPED = [
    {"ip": "10.0.0.5", "source": "active", "reason": "private"},
    {"ip": "127.0.0.1", "source": "passive", "reason": "loopback"},
]


def test_skipped_addresses_are_listed_with_their_reason(render: Callable[..., str]) -> None:
    block = render_skipped_ips(SKIPPED)
    assert block is not None
    out = " ".join(render(block).split())

    assert "addresses resolved but not investigated (2)" in out
    assert "10.0.0.5 active private" in out
    assert "127.0.0.1 passive loopback" in out


def test_skipped_addresses_state_that_no_provider_was_asked(render: Callable[..., str]) -> None:
    """Without this sentence the block reads as a list of addresses that came back clean."""
    block = render_skipped_ips(SKIPPED)
    assert block is not None
    out = " ".join(render(block).split())

    assert "no provider was asked about these addresses" in out
    assert "nothing here is evidence that they are clean" in out


@pytest.mark.parametrize("empty", [None, [], (), "not a list", 0])
def test_no_skipped_block_when_nothing_was_skipped(empty: Any) -> None:
    assert render_skipped_ips(empty) is None


def test_skipped_addresses_tolerate_a_bare_string_entry(render: Callable[..., str]) -> None:
    block = render_skipped_ips(["10.0.0.5"])
    assert block is not None
    out = " ".join(render(block).split())

    assert "10.0.0.5" in out
    assert "no reason recorded" in out


def test_skipped_addresses_escape_hostile_values() -> None:
    """The reason and source are internal, but the address arrives from VirusTotal DNS history."""
    block = render_skipped_ips([{"ip": "[green]10.0.0.5[/]", "source": "passive", "reason": "private"}])
    assert block is not None

    assert "[green]10.0.0.5[/]" in _plain(block)
    assert GREEN not in _ansi(block) and GREEN_BOLD not in _ansi(block)


# --------------------------------------------------------------------------------------------
# 4.3 — warnings reach the console
#
# The ASN and domain orchestrators compute ``warnings`` and return them. The JSON branch prints
# them; the console branch never read them, so a failed CAIDA or PeeringDB lookup degraded the
# panel in silence.
# --------------------------------------------------------------------------------------------


def test_warnings_are_rendered_with_a_count(render: Callable[..., str]) -> None:
    block = render_warnings(["caida_failed", "peeringdb_failed"])
    assert block is not None
    out = render(block)

    assert "warnings (2):" in out
    assert "caida_failed" in out
    assert "peeringdb_failed" in out


@pytest.mark.parametrize("empty", [None, [], (), ["", "   "], "not a list"])
def test_no_warning_block_when_there_are_no_warnings(empty: Any) -> None:
    assert render_warnings(empty) is None


def test_warning_text_is_never_parsed_as_markup() -> None:
    """A warning quotes an address and a reason, both of which can come from a provider."""
    block = render_warnings(["[green]all clear[/] 10.0.0.5 skipped"])
    assert block is not None

    assert "[green]all clear[/]" in _plain(block)
    assert GREEN not in _ansi(block) and GREEN_BOLD not in _ansi(block)


def test_asn_header_renders_coverage_and_warnings(render: Callable[..., str]) -> None:
    out = render(
        render_asn_header(
            64500,
            {"name": "EXAMPLE-AS"},
            coverage=_status(ripe_overview="ok", caida="error", peeringdb="not_configured"),
            warnings=["caida_failed", "peeringdb_failed"],
        )
    )

    assert "provider_coverage: 1 of 3 providers answered" in out
    assert "query failed: caida" in out
    assert "warnings (2):" in out
    assert "EXAMPLE-AS" in out


def test_asn_header_without_status_still_declares_coverage_unknown(render: Callable[..., str]) -> None:
    out = render(render_asn_header(64500, {"name": "EXAMPLE-AS"}))

    assert "provider_coverage: unknown" in out


def test_domain_header_carries_coverage_warnings_and_skipped_addresses(render: Callable[..., str]) -> None:
    out = render(
        render_domain_header(
            "evil.example",
            coverage=_status(virustotal="ok", otx="not_configured"),
            warnings=["10.0.0.5 (active) skipped: private addressing is never sent to a provider"],
            skipped_ips=SKIPPED,
            run_id="0f3c9a21",
        )
    )

    assert "--- Domain lookup for evil.example ---" in out
    assert "run 0f3c9a21" in out
    assert "domain_provider_coverage: 1 of 2 providers answered" in out
    assert "never asked - no API key configured: otx" in out
    assert "warnings (1):" in out
    assert "addresses resolved but not investigated (2)" in out


# --------------------------------------------------------------------------------------------
# 4.8 — "and N more" on the peering panel
#
# ``orchestrators`` truncates ``ripe_*_named`` to ``--neighbors N`` before the renderer sees
# it, and the renderer computed its "and N more" suffix from that already-truncated list. The
# marker could therefore never fire: eight named upstreams out of two hundred rendered as
# eight upstreams, full stop.
# --------------------------------------------------------------------------------------------


def test_peering_reports_the_peers_hidden_by_the_neighbour_limit(render: Callable[..., str]) -> None:
    named = [f"HOLDER-{i} ({i})" for i in range(8)]
    line = _bgp_line(render, ripe_upstream_named=named, ripe_upstream_asns=list(range(200)))

    assert "and 192 more" in line
    assert "HOLDER-0 (0)" in line


def test_peering_marker_stays_silent_when_nothing_is_hidden(render: Callable[..., str]) -> None:
    asns = [64500, 64501, 64502]
    line = _bgp_line(render, ripe_downstream_named=[str(a) for a in asns], ripe_downstream_asns=asns)

    assert "more" not in line


def test_peering_truncates_a_long_unnamed_list_and_says_by_how_much(render: Callable[..., str]) -> None:
    """The display limit is the renderer's own, so the count must survive that path too."""
    line = _bgp_line(render, ripe_uncertain_asns=list(range(100)))

    assert "and 40 more" in line


def test_peering_holder_names_are_escaped(render: Callable[..., str]) -> None:
    """``--neighbors`` fills this column with RIPE holder names — third-party strings.

    Asserted on the plain render: panel 3 styles its own category column green, so a
    whole-output colour assertion would fail on unrelated markup. An unescaped tag would be
    consumed by rich and the literal text would disappear.
    """
    line = _bgp_line(render, ripe_upstream_named=["Evil[green]Corp[/] (64500)"], ripe_upstream_asns=[64500])

    assert "Evil[green]Corp[/] (64500)" in line


def test_peering_absent_lists_still_render_none(render: Callable[..., str]) -> None:
    line = _bgp_line(render, ripe_announced_prefixes_v4=3)

    assert "Upstream NONE" in line
    assert "Downstream NONE" in line


def test_announced_prefixes_are_escaped(render: Callable[..., str]) -> None:
    """RIPEstat supplies these strings; they reach the terminal on the aggregated-resources panel."""
    line = _bgp_line(render, ripe_prefixes_v4=["[green]192.0.2.0/24[/]"])

    assert "[green]192.0.2.0/24[/]" in line


# --------------------------------------------------------------------------------------------
# The published coverage / run / warnings on ``data``
#
# The orchestrator writes ``data['coverage']``, ``data['run']`` and ``data['warnings']``
# specifically because the console renderers are handed ``result.data`` and nothing else. The
# renderer prefers them over recomputing: the published Coverage knows which providers were
# *expected* and never attempted, which the raw status map cannot show, and two independent
# computations of the same ratio are two chances to disagree with the JSON export.
# --------------------------------------------------------------------------------------------

PUBLISHED_COVERAGE: dict[str, Any] = {
    "answered": ["virustotal"],
    "not_found": [],
    "errored": ["shodan"],
    "unconfigured": ["abuseipdb", "ipinfo", "otx"],
    "skipped": ["cloudflare_asn"],
    "answered_count": 1,
    "applicable_count": 6,
    "is_complete": False,
    "headline": "1 of 6 providers answered",
}


def test_published_coverage_beats_a_recount_from_the_status_map(render: Callable[..., str]) -> None:
    """The status map holds five providers; coverage knows a sixth was never attempted.

    Recomputing from the status map would report 1 of 5 on screen and 1 of 6 in the JSON — the
    console flattering the run, which is the exact direction this workstream forbids.
    """
    data = _ip_data(
        provider_status=_status(
            virustotal="ok", shodan="error", ipinfo="not_configured", abuseipdb="not_configured", otx="not_configured"
        ),
        coverage=PUBLISHED_COVERAGE,
    )

    out = render(render_ip_analysis(IP, data))

    assert "provider_coverage: 1 of 6 providers answered" in out
    assert "never asked - skipped: cloudflare_asn" in out


def test_published_headline_is_reproduced_verbatim(render: Callable[..., str]) -> None:
    """One wording, one place. The screen must not paraphrase the exported figure."""
    coverage = dict(PUBLISHED_COVERAGE, headline="1 of 6 providers answered")
    out = render(render_ip_analysis(IP, _ip_data(coverage=coverage)))

    assert f"provider_coverage: {coverage['headline']}" in out


def test_published_run_metadata_feeds_the_header(render: Callable[..., str]) -> None:
    run = {
        "tool": "tripper-recon",
        "tool_version": "9.9.9",
        "run_id": "20260808T120000Z-abcd1234",
        "started_at": "2026-08-08T12:00:00Z",
    }

    out = render(render_ip_analysis(IP, _ip_data(run=run)))

    assert "tripper-recon 9.9.9" in out
    assert "2026-08-08T12:00:00Z" in out
    assert "run 20260808T120000Z-abcd1234" in out


def test_warnings_the_coverage_line_already_states_are_not_repeated(render: Callable[..., str]) -> None:
    """The orchestrator writes both from the same Coverage object; printing both is noise."""
    data = _ip_data(
        coverage=PUBLISHED_COVERAGE,
        warnings=[
            "partial coverage: 1 of 6 providers answered",
            "never asked, no API key configured: abuseipdb, ipinfo, otx",
            "never attempted: cloudflare_asn",
        ],
    )

    out = render(render_ip_analysis(IP, data))

    assert "warnings (" not in out
    # The information itself is still on screen — it is the second copy that is dropped.
    assert "never asked - no API key configured: abuseipdb, ipinfo, otx" in out


def test_warnings_that_say_something_new_are_printed(render: Callable[..., str]) -> None:
    """Suppressed failures and skipped addresses are not in the coverage line and must survive."""
    data = _ip_data(
        coverage=PUBLISHED_COVERAGE,
        warnings=[
            "partial coverage: 1 of 6 providers answered",
            "failed, and kept out of the error list as expected noise: ripe_overview",
        ],
    )

    out = render(render_ip_analysis(IP, data))

    assert "warnings (1):" in out
    assert "expected noise: ripe_overview" in out


def test_coverage_and_run_contract_against_the_real_models() -> None:
    """Cross-lane contract: render what ``types.models`` actually produces, not a hand-built copy.

    ``Coverage.model_dump()`` and ``RunMetadata.model_dump()`` are the payloads the orchestrator
    writes. If either grows or renames a field this test is where the renderer finds out, rather
    than an analyst finding a report with no coverage line on it.
    """
    from tripper_recon.types.models import RunMetadata, coverage_from_result_data

    data = _ip_data(
        provider_status=_status(virustotal="ok", shodan="error", otx="not_configured"),
    )
    coverage = coverage_from_result_data(data, expected=["virustotal", "shodan", "otx", "abuseipdb"])
    data["coverage"] = coverage.model_dump()
    data["run"] = RunMetadata.new(run_id="20260808T120000Z-abcd1234").model_dump()

    out = _plain(render_ip_analysis(IP, data))

    assert f"provider_coverage: {coverage.headline}" in out
    assert "provider_coverage: 1 of 4 providers answered" in out
    assert "run 20260808T120000Z-abcd1234" in out
    for missing in coverage.missing:
        assert missing in out
