"""Shared fixtures for the tripper_recon test suite.

Two things live here: the environment isolation control, and representative provider payloads.

The provider payload fixtures return the ``data`` sub-dictionary each provider module produces
on success -- that is the shape the orchestrator copies into the analysis dict and the shape
``reporting.console`` consumes. See ``tripper_recon/providers/*.py`` for the originals.
"""

from __future__ import annotations

import io
import os
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from rich.console import Console, RenderableType

# Every environment variable the package reads: six provider credentials, the Cloudflare
# token, and the two behaviour knobs.
#   credentials -> orchestrators._env_keys / orchestrators.ABUSECH_ENV_VAR
#                  / utils.redact._SECRET_ENV_VARS
#   behaviour   -> utils.http (user agent), utils.logging (log level)
PROVIDER_ENV_VARS: tuple[str, ...] = (
    "CLOUDFLARE_API_TOKEN",
    "VT_API_KEY",
    "SHODAN_API_KEY",
    "ABUSEIPDB_API_KEY",
    "IPINFO_TOKEN",
    "OTX_API_KEY",
    "ABUSECH_AUTH_KEY",
    "TRIPPER_RECON_USER_AGENT",
    "TRIPPER_RECON_LOG_LEVEL",
)

# Variables that force `rich` to emit ANSI escapes regardless of whether stdout is a terminal.
# Several tests parse captured stdout as JSON or assert on plain substrings, and an escape
# sequence in the middle of a value breaks both -- so the suite passes or fails depending on the
# shell it was launched from. Cleared for the same reason `render` pins `force_terminal=False`:
# a gate whose result depends on the operator's terminal is not a gate.
#
# Cleared HERE, at conftest import time, and not in a fixture: `rich` reads these when a
# `Console` is CONSTRUCTED, and `tripper_recon.cli` builds its console at module import -- which
# happens when a test module imports it, before any fixture has run. A per-test fixture is too
# late and leaves the failures in place.
COLOUR_FORCING_ENV_VARS: tuple[str, ...] = ("FORCE_COLOR", "CLICOLOR_FORCE")

for _colour_var in COLOUR_FORCING_ENV_VARS:
    os.environ.pop(_colour_var, None)


@pytest.fixture(autouse=True)
def clear_provider_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unset every provider variable before each test.

    This is a SAFETY CONTROL, not a convenience.

    The operator's real API keys live in ``.env`` at the repo root, and anything that calls
    ``utils.env.load_env`` -- directly or via importing the CLI -- pushes them into
    ``os.environ`` for the rest of the process. Two consequences follow, and both are bad:

    1. ``utils.redact`` redacts *whatever is in the environment*. With a real key loaded, a
       redaction test can pass because the operator's key happened to be substituted rather
       than because the code under test works. The test would then fail on CI, where no key
       exists, or -- worse -- silently pass on a machine where the behaviour is broken.
    2. A failing assertion prints the compared values. A real credential in the environment
       can therefore end up in pytest output, in a CI log, and in a pasted bug report.

    Clearing is unconditional and autouse so no test can opt out by forgetting. A test that
    needs a credential sets a fake one with ``monkeypatch.setenv`` after this fixture has run.
    """
    for name in PROVIDER_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def no_real_network() -> Iterator[None]:
    """Intercept every request for the whole session, so an unmocked test cannot reach a provider.

    This is a SAFETY CONTROL, like ``clear_provider_env`` above, and it exists because a test
    that forgets ``@respx.mock`` does not fail -- it succeeds, by contacting the real provider.

    That is worse here than in an ordinary project. Every host this tool talks to is an OSINT
    provider, so an unmocked test spends the operator's quota and writes his egress IP and the
    test's indicator into that provider's logs, on every run. The keyless providers (Tranco,
    Shodan InternetDB, the IANA RDAP bootstrap) make it likelier still, because nothing stops
    them for want of a credential: on the run that first wired them,
    ``test_domain_coverage_spans_both_scopes`` reached ``tranco-list.eu`` and ``data.iana.org``
    for real and counted the answers as provider coverage.

    Implemented as an outer respx router with no routes rather than as a transport patch.
    ``respx.mocks.Mocker.handler`` walks every registered router and returns the first response
    one of them produces, so a test's own router still serves its routes and this one only ever
    sees what nothing else claimed -- which it refuses, with ``AllMockedAssertionError``.
    Patching httpcore or httpx directly does NOT work: respx patches those same objects and
    only patches once, so whichever landed last silently wins.
    """
    respx = pytest.importorskip("respx", reason="respx is required to keep tests off the network")
    with respx.mock(assert_all_called=False, assert_all_mocked=True):
        yield


@pytest.fixture
def render() -> Callable[..., str]:
    """Render a rich renderable to plain text.

    Fixed width and ``force_terminal=False`` keep output deterministic across terminals and
    CI. ``color_system=None`` drops ANSI escapes so assertions compare readable strings --
    note that rich still *parses* markup, so an unescaped ``[green]`` tag is consumed and
    disappears while an escaped one survives as literal text. That difference is exactly what
    the ``console.esc`` tests need to see.
    """

    def _render(renderable: RenderableType, *, width: int = 120) -> str:
        buffer = io.StringIO()
        console = Console(
            file=buffer,
            width=width,
            force_terminal=False,
            color_system=None,
            legacy_windows=False,
            highlight=False,
        )
        console.print(renderable)
        return buffer.getvalue()

    return _render


# --------------------------------------------------------------------------------------
# Provider payloads. Shapes taken from tripper_recon/providers/*.py.
# --------------------------------------------------------------------------------------


@pytest.fixture
def vt_summary_clean() -> dict[str, Any]:
    """VirusTotal IP summary, nothing detected. Shape: providers/virustotal.vt_ip_summary."""
    return {
        "vt_last_analysis_stats": {
            "harmless": 68,
            "malicious": 0,
            "suspicious": 0,
            "undetected": 26,
            "timeout": 0,
        },
        "vt_reputation": 0,
        "vt_link": "https://www.virustotal.com/gui/ip-address/93.184.216.34",
    }


@pytest.fixture
def vt_summary_malicious() -> dict[str, Any]:
    """VirusTotal IP summary with detections. Same stat keys, non-zero ``malicious``."""
    return {
        "vt_last_analysis_stats": {
            "harmless": 55,
            "malicious": 12,
            "suspicious": 3,
            "undetected": 24,
            "timeout": 0,
        },
        "vt_reputation": -37,
        "vt_link": "https://www.virustotal.com/gui/ip-address/198.51.100.7",
    }


@pytest.fixture
def shodan_host() -> dict[str, Any]:
    """Shodan host record. Shape: providers/shodan_api.shodan_host."""
    return {
        "ports": [22, 80, 443, 8080],
        "org": "Example Hosting LLC",
        "tags": ["cloud"],
        "cpe": ["cpe:/a:nginx:nginx:1.24.0", "cpe:/a:openbsd:openssh:9.6"],
    }


@pytest.fixture
def abuseipdb_check() -> dict[str, Any]:
    """AbuseIPDB check result. Shape: providers/abuseipdb.abuseipdb_check."""
    return {
        "abuseipdb_reports": 47,
        "abuseipdb_confidence_score": 92,
    }


@pytest.fixture
def otx_pulse_set() -> dict[str, Any]:
    """OTX pulse summary for an IP. Shape: providers/otx.otx_ip_pulses."""
    return {
        "otx_pulse_count": 3,
        "otx_pulse_titles": [
            "Cobalt Strike C2 infrastructure",
            "Mass scanning hosts 2026-07",
            "Credential stuffing sources",
        ],
    }


@pytest.fixture
def otx_pulse_set_markup() -> dict[str, Any]:
    """OTX pulses whose titles are hostile to rich markup.

    Pulse titles are attacker-influenced free text. ``[/]`` raises ``MarkupError`` when rich
    parses it unescaped, and ``[green]0/94 clean[/]`` renders as a green verdict the tool never
    computed. Both are what ``console.esc`` exists to defuse (W0 fix 0.3).
    """
    return {
        "otx_pulse_count": 2,
        "otx_pulse_titles": [
            "evil [/] campaign",
            "[green]0/94 clean[/] totally benign",
        ],
    }


@pytest.fixture
def ipinfo_record() -> dict[str, Any]:
    """IPInfo record. Shape: providers/ipinfo.ipinfo_ip."""
    return {
        "ip": "93.184.216.34",
        "city": "Los Angeles",
        "country": "US",
        "region": "California",
        "postal": "90009",
        "asn": 15133,
        "org": "AS15133 Edgecast Inc.",
        "coordinates": {"lat": 34.0544, "lon": -118.2440},
        "timezone": "America/Los_Angeles",
        "hostname": None,
    }


@pytest.fixture
def asn_meta() -> dict[str, Any]:
    """Cloudflare Radar ASN metadata. ``organization`` is a dict here."""
    return {
        "asn": 15133,
        "name": "EDGECAST",
        "countryCode": "US",
        "caidaRank": 412,
        "organization": {"name": "Edgecast Inc."},
        "abuseContacts": ["abuse@example.net"],
        "rir": "ARIN",
        "allocationDate": "2007-08-14",
        "ixps": [{"name": "Equinix Ashburn"}, {"name": "DE-CIX Frankfurt"}],
    }


@pytest.fixture
def asn_meta_string_org() -> dict[str, Any]:
    """ASN metadata where ``organization`` is a plain string.

    IPInfo supplies ``org`` as a string, so this shape reaches ``render_asn_header`` whenever
    Cloudflare Radar is unavailable. Assuming a dict raised ``AttributeError`` (W0 fix).
    """
    return {
        "asn": 15133,
        "name": None,
        "organization": "Edgecast Inc.",
        "rir": "arin",
    }


@pytest.fixture
def ip_analysis_data(
    vt_summary_clean: dict[str, Any],
    ipinfo_record: dict[str, Any],
    shodan_host: dict[str, Any],
    abuseipdb_check: dict[str, Any],
    otx_pulse_set: dict[str, Any],
    asn_meta: dict[str, Any],
) -> dict[str, Any]:
    """The composed dict ``console.render_ip_analysis`` consumes.

    Mirrors the ``data`` mapping built in ``orchestrators.investigate_ip``: each key holds the
    provider's ``data`` sub-dict on success, or ``{}`` when the provider failed or was skipped.
    """
    return {
        "virustotal": vt_summary_clean,
        "ipinfo": ipinfo_record,
        "shodan": shodan_host,
        "abuseipdb": abuseipdb_check,
        "otx": otx_pulse_set,
        "asn_meta": asn_meta,
    }
