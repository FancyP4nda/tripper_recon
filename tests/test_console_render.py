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

from tripper_recon.reporting.console import esc, render_asn_header, render_ip_analysis

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
