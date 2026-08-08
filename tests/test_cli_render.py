"""Integration tests for the wiring between ``cli.py`` and ``reporting.console``.

Four lanes built the W4 pieces -- the coverage/run/skip models, the orchestrator that publishes
them, the console renderers that consume them, and the provider fields that give them content --
and coordinated only through written interface notes. This module tests the seams between them,
which is where the notes were and were not honoured.

The two verified gaps this workstream exists to close, both reproduced against the running tool
before these tests were written:

1. With two of six credentials configured the tool showed a VirusTotal score and one Shodan
   error and said nothing whatever about the four providers that were never asked. An analyst
   reads sparse output as a clean indicator.
2. On the domain path, addresses refused by the private/reserved guard vanished from the output
   entirely: three internal addresses and one public one rendered as "1 IP addresses found".

``_cmd_*`` is driven directly with a stubbed orchestrator wherever the subject is rendering, so
these stay fast and deterministic; the one end-to-end case goes through respx. No test here
performs a real network call, and every one runs with the provider environment cleared by the
autouse fixture in conftest.
"""

from __future__ import annotations

import asyncio
import io
import json
from typing import Any, Dict, List, Optional

import pytest
from rich.console import Console

from tripper_recon import cli
from tripper_recon.types.models import Coverage, InvestigationResult, RunMetadata, SkippedAddress, SkipReason

RUN = RunMetadata(
    tool="tripper-recon",
    tool_version="9.9.9",
    run_id="testrun01",
    started_at="2026-08-08T12:00:00Z",  # type: ignore[arg-type]
)

# One address answered by VirusTotal alone: Shodan errored, three providers have no key, and
# Cloudflare was never attempted because IPinfo never returned an ASN.
IP_STATUS: Dict[str, Dict[str, Any]] = {
    "virustotal": {"outcome": "ok", "elapsed_seconds": 0.1},
    "shodan": {"outcome": "error", "elapsed_seconds": 0.1, "error": {"status_code": 500}},
    "ipinfo": {"outcome": "not_configured", "elapsed_seconds": 0.0, "suppressed": True},
    "abuseipdb": {"outcome": "not_configured", "elapsed_seconds": 0.0, "suppressed": True},
    "otx": {"outcome": "not_configured", "elapsed_seconds": 0.0, "suppressed": True},
}

IP_PROVIDERS = ("virustotal", "ipinfo", "shodan", "abuseipdb", "otx", "cloudflare_asn")

VT_CLEAN: Dict[str, Any] = {
    "vt_last_analysis_stats": {"harmless": 70, "malicious": 0, "suspicious": 0, "undetected": 24},
    "vt_reputation": 0,
    "vt_last_analysis_date": 1699999999,
    "vt_last_analysis_date_iso": "2023-11-14T22:13:19+00:00",
    "vt_detecting_engines": [],
    "vt_link": "https://www.virustotal.com/gui/ip-address/93.184.216.34",
}


def _capture(coro_factory: Any) -> tuple[str, int]:
    """Run one ``_cmd_*`` coroutine with the module console redirected to a NON-TTY buffer.

    ``force_terminal=False`` and ``color_system=None`` are the point, not a convenience: this
    is exactly what the output looks like redirected into an incident ticket, and rich strips
    every colour on that path. Anything the tool says only in colour is not said at all here.
    """
    buffer = io.StringIO()
    original = cli.console
    cli.console = Console(file=buffer, width=140, force_terminal=False, color_system=None, legacy_windows=False)
    try:
        code = asyncio.run(coro_factory())
    finally:
        cli.console = original
    return buffer.getvalue(), code


def _ip_entry(ip: str, *, source: Optional[str] = None) -> Dict[str, Any]:
    entry: Dict[str, Any] = {
        "ip": ip,
        "virustotal": VT_CLEAN,
        "shodan": {},
        "ipinfo": {},
        "abuseipdb": {},
        "otx": {},
        "asn_meta": {},
        "provider_status": IP_STATUS,
        "coverage": Coverage.from_status_map(IP_STATUS, expected=IP_PROVIDERS).model_dump(),
    }
    if source is not None:
        entry["source"] = source
    return entry


def _domain_result(*, skipped: List[SkippedAddress], investigated: List[str]) -> InvestigationResult:
    """A domain result shaped exactly as ``orchestrators._investigate_domain`` builds one."""
    domain_status = {
        "virustotal": {"outcome": "ok", "elapsed_seconds": 0.1},
        "otx": {"outcome": "not_configured", "elapsed_seconds": 0.0, "suppressed": True},
    }
    ips = [_ip_entry(ip, source="active") for ip in investigated]
    data: Dict[str, Any] = {
        "domain": "example.com",
        "ips": ips,
        "domain_provider_status": domain_status,
        "domain_intel": {
            "virustotal": {
                "vt_last_analysis_stats": {"harmless": 70, "malicious": 0, "undetected": 24},
                "vt_reputation": 0,
                "vt_last_analysis_date_iso": "2023-11-14T22:13:19+00:00",
                "vt_link": "https://www.virustotal.com/gui/domain/example.com",
            }
        },
        "addresses": {
            "resolved": len(ips) + len(skipped),
            "investigated": len(ips),
            "skipped": len(skipped),
        },
        "skipped_ips": [{"ip": s.address, "source": s.source, "reason": s.reason.value} for s in skipped],
    }
    coverage = Coverage.merge(
        [
            Coverage.from_status_map(domain_status, expected=("virustotal", "otx"), prefix="domain:"),
            *(Coverage.from_status_map(IP_STATUS, expected=IP_PROVIDERS, prefix=f"{ip}:") for ip in investigated),
        ]
    )
    warnings = [f"partial coverage: {coverage.headline}"]
    warnings.append("never asked, no API key configured: " + ", ".join(coverage.unconfigured))
    warnings.extend(s.explanation for s in skipped)
    data["coverage"] = coverage.model_dump()
    data["run"] = RUN.model_dump()
    data["warnings"] = warnings
    return InvestigationResult(
        ok=True,
        data=data,
        warnings=warnings,
        errors=[],
        run=RUN,
        coverage=coverage,
        skipped_addresses=skipped,
    )


def _stub_domain(monkeypatch: pytest.MonkeyPatch, result: InvestigationResult) -> None:
    async def _fake(domain: str, **kwargs: Any) -> InvestigationResult:
        return result

    monkeypatch.setattr(cli, "investigate_domain", _fake)


SKIPPED_THREE = [
    SkippedAddress(address="10.0.0.5", reason=SkipReason.PRIVATE, source="active"),
    SkippedAddress(address="192.168.10.9", reason=SkipReason.PRIVATE, source="active"),
    SkippedAddress(address="127.0.0.1", reason=SkipReason.LOOPBACK, source="active"),
]


# --------------------------------------------------------------------------------------------
# Gap 2 -- addresses skipped by the non-public guard must not vanish
# --------------------------------------------------------------------------------------------


def test_domain_report_names_every_skipped_address_and_says_why(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_domain(monkeypatch, _domain_result(skipped=SKIPPED_THREE, investigated=["93.184.216.34"]))

    out, code = _capture(lambda: cli._cmd_domain("example.com"))

    assert "addresses resolved but not investigated (3)" in out
    for address in ("10.0.0.5", "192.168.10.9", "127.0.0.1"):
        assert address in out
    assert "private addressing - never sent to a provider" in out
    assert "loopback addressing - never sent to a provider" in out
    assert "nothing here is evidence that they are clean" in out
    assert code == 0


def test_domain_report_states_the_real_address_accounting(monkeypatch: pytest.MonkeyPatch) -> None:
    """ "1 IP addresses found" was the lie: three of the four resolved addresses were withheld."""
    _stub_domain(monkeypatch, _domain_result(skipped=SKIPPED_THREE, investigated=["93.184.216.34"]))

    out, _ = _capture(lambda: cli._cmd_domain("example.com"))

    assert "4 addresses resolved, 1 investigated, 3 skipped as non-public" in out
    assert "1 IP addresses found" not in out


def test_domain_with_only_internal_addresses_refuses_to_look_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    """Zero investigated addresses is the case most likely to be read as "nothing found"."""
    _stub_domain(monkeypatch, _domain_result(skipped=SKIPPED_THREE, investigated=[]))

    out, code = _capture(lambda: cli._cmd_domain("example.com"))

    assert "No address was investigated" in out
    assert "Nothing above is evidence that this domain is clean" in out
    assert "No IPs available for IP-level enrichment" not in out
    assert code == 0


def test_skip_warnings_are_not_printed_twice(monkeypatch: pytest.MonkeyPatch) -> None:
    """The orchestrator puts one warning per skipped address in ``warnings``, and the header
    renders the same three addresses as a table. Printing both says six things about three
    facts, and volume is how a reader learns to skim the block that must not be skimmed."""
    _stub_domain(monkeypatch, _domain_result(skipped=SKIPPED_THREE, investigated=["93.184.216.34"]))

    out, _ = _capture(lambda: cli._cmd_domain("example.com"))

    assert out.count("10.0.0.5") == 1
    assert "was not investigated:" not in out


# --------------------------------------------------------------------------------------------
# Gap 1 -- the domain path must say which providers were never asked
# --------------------------------------------------------------------------------------------


def test_domain_header_carries_coverage_run_and_version(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_domain(monkeypatch, _domain_result(skipped=SKIPPED_THREE, investigated=["93.184.216.34"]))

    out, _ = _capture(lambda: cli._cmd_domain("example.com"))

    assert "provider_coverage: 2 of 8 providers answered" in out
    assert "tripper-recon 9.9.9" in out
    assert "run testrun01" in out
    assert "2026-08-08T12:00:00" in out
    # Every gap named, namespaced so the domain-level one is distinguishable from the per-address ones.
    assert "domain:otx" in out
    assert "93.184.216.34:shodan" in out


def test_domain_coverage_line_matches_the_json_headline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Console and JSON must never state two different ratios for one run."""
    result = _domain_result(skipped=SKIPPED_THREE, investigated=["93.184.216.34"])
    _stub_domain(monkeypatch, result)

    console_out, _ = _capture(lambda: cli._cmd_domain("example.com"))
    json_out, _ = _capture(lambda: cli._cmd_domain("example.com", output="json"))

    headline = json.loads(json_out)["coverage"]["headline"]
    assert headline in console_out


def test_per_address_panels_do_not_repeat_the_run_line(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_domain(monkeypatch, _domain_result(skipped=[], investigated=["93.184.216.34", "198.51.100.9"]))

    out, _ = _capture(lambda: cli._cmd_domain("example.com"))

    assert out.count("tripper-recon 9.9.9") == 1
    # ...but each address still declares its own coverage, because a domain answered by five
    # providers for one address and none for another is not one coverage figure.
    assert out.count("provider_coverage: 1 of 6 providers answered") == 2


def test_per_address_panels_never_say_the_run_id_is_unrecorded(monkeypatch: pytest.MonkeyPatch) -> None:
    """The run id was reported as unrecorded on every nested panel: ``data['run']`` sits at the
    top level and the per-address dicts handed to the renderer do not carry it."""
    _stub_domain(monkeypatch, _domain_result(skipped=[], investigated=["93.184.216.34"]))

    out, _ = _capture(lambda: cli._cmd_domain("example.com"))

    assert "run id not recorded" not in out


# --------------------------------------------------------------------------------------------
# No absence rendered as a zero, on the domain path too
# --------------------------------------------------------------------------------------------


def _domain_result_without_vt() -> InvestigationResult:
    domain_status = {
        "virustotal": {"outcome": "not_configured", "elapsed_seconds": 0.0, "suppressed": True},
        "otx": {"outcome": "not_configured", "elapsed_seconds": 0.0, "suppressed": True},
    }
    coverage = Coverage.from_status_map(domain_status, expected=("virustotal", "otx"), prefix="domain:")
    data: Dict[str, Any] = {
        "domain": "example.com",
        "ips": [],
        "domain_provider_status": domain_status,
        "addresses": {"resolved": 0, "investigated": 0, "skipped": 0},
        "skipped_ips": [],
        "coverage": coverage.model_dump(),
        "run": RUN.model_dump(),
        "warnings": [],
    }
    return InvestigationResult(ok=True, data=data, run=RUN, coverage=coverage)


def test_unconfigured_virustotal_never_renders_a_domain_score(monkeypatch: pytest.MonkeyPatch) -> None:
    """W0.2 removed the manufactured green ``0/0`` from the IP path. The domain path, which
    lives in cli.py rather than in the console module, kept printing one."""
    _stub_domain(monkeypatch, _domain_result_without_vt())

    out, _ = _capture(lambda: cli._cmd_domain("example.com"))

    assert "0/0" not in out
    assert "virustotal_detections: no data - not configured, no API key" in out


def test_unconfigured_otx_never_renders_as_an_otx_with_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Dropping the count row and printing the pivot link on its own reads as "OTX had nothing"."""
    _stub_domain(monkeypatch, _domain_result_without_vt())

    out, _ = _capture(lambda: cli._cmd_domain("example.com"))

    assert "otx_pulse_count: no data - not configured, no API key" in out


def test_domain_score_carries_its_own_freshness(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_domain(monkeypatch, _domain_result(skipped=[], investigated=["93.184.216.34"]))

    out, _ = _capture(lambda: cli._cmd_domain("example.com"))

    assert "virustotal_last_analysis: 2023-11-14T22:13:19+00:00" in out


def test_domain_score_without_a_date_says_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _domain_result(skipped=[], investigated=[])
    result.data["domain_intel"]["virustotal"].pop("vt_last_analysis_date_iso")
    _stub_domain(monkeypatch, result)

    out, _ = _capture(lambda: cli._cmd_domain("example.com"))

    assert "virustotal_last_analysis: unknown - VirusTotal supplied no date" in out


def test_domain_otx_pulse_titles_are_escaped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pulse titles are attacker-influenced free text; ``[/]`` raised MarkupError mid-render and
    ``[green]...[/]`` painted a verdict the tool never computed. W0.3 fixed the console module
    and missed this call site."""
    result = _domain_result(skipped=[], investigated=[])
    result.data["domain_intel"]["otx"] = {
        "otx_pulse_count": 2,
        "otx_pulse_titles": ["evil [/] campaign", "[green]0/94 clean[/] totally benign"],
    }
    _stub_domain(monkeypatch, result)

    out, _ = _capture(lambda: cli._cmd_domain("example.com"))

    assert "evil [/] campaign" in out
    assert "[green]0/94 clean[/] totally benign" in out


def test_empty_certificate_block_is_not_printed(monkeypatch: pytest.MonkeyPatch) -> None:
    """``vt_domain_summary`` always emits the certificate key as a fully-shaped dict of Nones,
    so ``if not cert`` never fired and the report carried a heading with nothing under it."""
    result = _domain_result(skipped=[], investigated=[])
    result.data["domain_intel"]["virustotal"]["vt_last_https_certificate"] = {
        "serial_number": None,
        "version": None,
        "thumbprint_sha256": None,
        "signature_algorithm": None,
        "issuer": {},
        "subject": {},
        "validity": {"not_before": None, "not_after": None},
    }
    _stub_domain(monkeypatch, result)

    out, _ = _capture(lambda: cli._cmd_domain("example.com"))

    assert "Last HTTPS Certificate" not in out


# --------------------------------------------------------------------------------------------
# The ASN path -- roadmap 4.3 only closes when the CLI passes coverage and warnings through
# --------------------------------------------------------------------------------------------


def _asn_result(*, ok: bool = True) -> InvestigationResult:
    status = {
        "ipinfo_asn": {"outcome": "ok", "elapsed_seconds": 0.1},
        "caida": {"outcome": "error", "elapsed_seconds": 0.1},
        "peeringdb": {"outcome": "not_configured", "elapsed_seconds": 0.0},
    }
    expected = ("ipinfo_asn", "caida", "peeringdb", "cloudflare_asn")
    coverage = Coverage.from_status_map(status, expected=expected)
    warnings = [f"partial coverage: {coverage.headline}", "caida_failed"]
    data: Dict[str, Any] = {
        "meta": {"name": "EXAMPLE-AS"},
        "bgp": {},
        "provider_status": status,
        "coverage": coverage.model_dump(),
        "run": RUN.model_dump(),
        "warnings": warnings,
    }
    return InvestigationResult(
        ok=ok,
        data=data if ok else data,
        warnings=warnings,
        errors=[] if ok else ["no provider answered for AS64500 (0 of 4 providers answered)"],
        run=RUN,
        coverage=coverage,
    )


def _stub_asn(monkeypatch: pytest.MonkeyPatch, result: InvestigationResult) -> None:
    async def _fake(asn: int, **kwargs: Any) -> InvestigationResult:
        return result

    monkeypatch.setattr(cli, "investigate_asn", _fake)


def test_asn_header_receives_coverage_and_warnings(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_asn(monkeypatch, _asn_result())

    out, code = _capture(lambda: cli._cmd_asn(64500))

    assert "provider_coverage: 1 of 4 providers answered" in out
    assert "provider_coverage: unknown" not in out
    assert "query failed: caida" in out
    assert "never asked - skipped: cloudflare_asn" in out
    assert "caida_failed" in out
    assert "tripper-recon 9.9.9" in out
    assert code == 0


def test_asn_coverage_warning_is_not_duplicated_below_the_coverage_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_asn(monkeypatch, _asn_result())

    out, _ = _capture(lambda: cli._cmd_asn(64500))

    assert out.count("1 of 4 providers answered") == 1


# --------------------------------------------------------------------------------------------
# Exit codes, and what a failed lookup is allowed to leave unsaid
# --------------------------------------------------------------------------------------------


def test_failed_lookup_still_names_the_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    """``ok=False`` for a blackout still returns the full data. Printing the error sentence
    alone throws away the only actionable part: which providers were never asked."""
    _stub_asn(monkeypatch, _asn_result(ok=False))

    out, code = _capture(lambda: cli._cmd_asn(64500))

    assert code == 1
    assert "intelligence blackout" in out or "no provider answered" in out
    assert "provider_coverage: 1 of 4 providers answered" in out


def test_partial_coverage_is_still_exit_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    """A partial answer must stay exit 0; the tool says how partial on the coverage line."""
    _stub_domain(monkeypatch, _domain_result(skipped=SKIPPED_THREE, investigated=["93.184.216.34"]))

    out, code = _capture(lambda: cli._cmd_domain("example.com"))

    assert code == 0
    assert "8 of 8" not in out


def test_blackout_is_exit_one(monkeypatch: pytest.MonkeyPatch) -> None:
    status = {"virustotal": {"outcome": "error"}, "shodan": {"outcome": "error"}}
    coverage = Coverage.from_status_map(status, expected=IP_PROVIDERS)
    blackout = InvestigationResult(
        ok=False,
        data={"provider_status": status, "coverage": coverage.model_dump(), "run": RUN.model_dump()},
        errors=["no provider answered for 93.184.216.34 (0 of 6 providers answered)"],
        run=RUN,
        coverage=coverage,
    )

    async def _fake(ip: str, **kwargs: Any) -> InvestigationResult:
        return blackout

    monkeypatch.setattr(cli, "investigate_ip", _fake)

    out, code = _capture(lambda: cli._cmd_ip("93.184.216.34"))

    assert code == 1
    assert "0 of 6 providers answered" in out


def test_defanged_input_is_exit_two_and_never_reaches_a_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    called: List[str] = []

    async def _fake(domain: str, **kwargs: Any) -> InvestigationResult:
        called.append(domain)
        raise AssertionError("a defanged target must not reach the orchestrator")

    monkeypatch.setattr(cli, "investigate_domain", _fake)

    _out, code = _capture(lambda: cli._cmd_domain("hxxps://evil[.]com"))

    assert code == 2
    assert called == []


# --------------------------------------------------------------------------------------------
# -o json carries the whole W4 surface
# --------------------------------------------------------------------------------------------


def test_domain_json_carries_coverage_run_and_skipped_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_domain(monkeypatch, _domain_result(skipped=SKIPPED_THREE, investigated=["93.184.216.34"]))

    out, code = _capture(lambda: cli._cmd_domain("example.com", output="json"))
    payload = json.loads(out)

    assert code == 0
    assert payload["coverage"]["headline"] == "2 of 8 providers answered"
    assert payload["run"]["tool_version"] == "9.9.9"
    # An RFC 3339 string, not a datetime: rich.print_json cannot serialise the latter.
    assert isinstance(payload["run"]["started_at"], str)
    assert payload["run"]["started_at"].endswith("Z")
    assert [entry["address"] for entry in payload["skipped_addresses"]] == [
        "10.0.0.5",
        "192.168.10.9",
        "127.0.0.1",
    ]
    assert payload["skipped_addresses"][0]["explanation"].startswith("10.0.0.5 (active) was not investigated")
    assert payload["data"]["addresses"] == {"resolved": 4, "investigated": 1, "skipped": 3}
    # Per-address coverage travels too, so a JSON consumer can weigh each address separately.
    assert payload["data"]["ips"][0]["coverage"]["headline"] == "1 of 6 providers answered"


def test_ip_json_carries_the_new_provider_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    status = dict(IP_STATUS)
    coverage = Coverage.from_status_map(status, expected=IP_PROVIDERS)
    data = {
        "virustotal": VT_CLEAN,
        "shodan": {
            "ports": [443],
            "vulns": ["CVE-2021-44228"],
            "hostnames": ["a.example"],
            "last_update": "2024-02-01",
        },
        "abuseipdb": {
            "abuseipdb_confidence_score": 0,
            "abuseipdb_reports": 0,
            "abuseipdb_last_reported_at": None,
            "abuseipdb_is_whitelisted": None,
            "abuseipdb_num_distinct_users": None,
        },
        "ipinfo": {},
        "otx": {"otx_pulse_count": 1, "otx_pulses": [{"name": "p", "author": None}]},
        "asn_meta": {},
        "provider_status": status,
        "coverage": coverage.model_dump(),
        "run": RUN.model_dump(),
        "warnings": [],
    }
    result = InvestigationResult(ok=True, data=data, run=RUN, coverage=coverage)

    async def _fake(ip: str, **kwargs: Any) -> InvestigationResult:
        return result

    monkeypatch.setattr(cli, "investigate_ip", _fake)

    out, code = _capture(lambda: cli._cmd_ip("93.184.216.34", output="json"))
    payload = json.loads(out)
    entry = payload["results"][0]

    assert code == 0
    assert entry["data"]["virustotal"]["vt_last_analysis_date_iso"] == "2023-11-14T22:13:19+00:00"
    assert entry["data"]["shodan"]["vulns"] == ["CVE-2021-44228"]
    assert entry["data"]["otx"]["otx_pulses"] == [{"name": "p", "author": None}]
    # Absence is None, not False or 0 -- a negative no provider ever asserted.
    assert entry["data"]["abuseipdb"]["abuseipdb_is_whitelisted"] is None
    assert entry["coverage"]["headline"] == "1 of 6 providers answered"
    assert entry["run"]["run_id"] == "testrun01"
    assert entry["skipped_addresses"] == []


# --------------------------------------------------------------------------------------------
# The providers -> console seam
#
# The providers lane retained VirusTotal's analysis date, AbuseIPDB's last-reported date and
# Shodan's last_update, and wrote in its interface note: "render these as staleness qualifiers
# next to the scores they qualify -- a score with no date attached is the failure mode W4
# exists to fix. A None date must render as 'unknown', never as a blank or a zero." Nothing
# rendered them. Same for Shodan's `vulns`, which its own module calls the single most
# actionable field the endpoint returns.
# --------------------------------------------------------------------------------------------


RICH_IP_DATA: Dict[str, Any] = {
    "virustotal": {
        "vt_last_analysis_stats": {"harmless": 60, "malicious": 8, "suspicious": 2, "undetected": 24},
        "vt_reputation": -37,
        "vt_last_analysis_date_iso": "2023-11-14T22:13:19+00:00",
        "vt_detecting_engines": [
            {"engine": "BigVendor", "category": "malicious", "result": "Trojan.Gen", "method": "blacklist"},
            {"engine": "OtherVendor", "category": "suspicious", "result": "phishing", "method": "blacklist"},
        ],
    },
    "shodan": {
        "ports": [22, 443],
        "vulns": ["CVE-2019-0708", "CVE-2021-44228"],
        "hostnames": ["mail.example.net"],
        "last_update": "2024-02-01T10:11:12.000000",
    },
    "abuseipdb": {
        "abuseipdb_confidence_score": 92,
        "abuseipdb_reports": 47,
        "abuseipdb_num_distinct_users": 3,
        "abuseipdb_last_reported_at": "2026-07-30T04:11:00+00:00",
    },
    "ipinfo": {},
    "otx": {},
    "asn_meta": {},
    "provider_status": {
        "virustotal": {"outcome": "ok"},
        "shodan": {"outcome": "ok"},
        "abuseipdb": {"outcome": "ok"},
        "ipinfo": {"outcome": "not_configured"},
        "otx": {"outcome": "not_configured"},
    },
}


def _render_ip(data: Dict[str, Any]) -> str:
    from tripper_recon.reporting.console import render_ip_analysis

    buffer = io.StringIO()
    console = Console(file=buffer, width=140, force_terminal=False, color_system=None, legacy_windows=False)
    console.print(render_ip_analysis("93.184.216.34", data))
    return buffer.getvalue()


def test_every_score_carries_the_date_that_qualifies_it() -> None:
    out = _render_ip(RICH_IP_DATA)

    assert "virustotal_last_analysis" in out and "2023-11-14T22:13:19+00:00" in out
    assert "abuseipdb_last_reported" in out and "2026-07-30T04:11:00+00:00" in out
    assert "shodan_last_update" in out and "2024-02-01T10:11:12.000000" in out


def test_a_missing_date_reads_as_unknown_and_never_as_blank_or_zero() -> None:
    data = json.loads(json.dumps(RICH_IP_DATA))
    data["virustotal"].pop("vt_last_analysis_date_iso")
    data["abuseipdb"]["abuseipdb_last_reported_at"] = None
    data["shodan"]["last_update"] = None

    out = _render_ip(data)

    assert out.count("unknown - provider supplied no date") == 3
    assert "1970" not in out


def test_detecting_engines_are_named_not_just_counted() -> None:
    """``8/94`` does not say whether eight no-name engines or eight major vendors flagged it."""
    out = _render_ip(RICH_IP_DATA)

    assert "BigVendor: malicious (Trojan.Gen)" in out
    assert "OtherVendor: suspicious (phishing)" in out


def test_shodan_cves_reach_the_screen() -> None:
    out = _render_ip(RICH_IP_DATA)

    assert "CVE-2019-0708" in out
    assert "CVE-2021-44228" in out
    assert "mail.example.net" in out


def test_a_provider_that_was_never_asked_gets_no_freshness_row() -> None:
    """A "no data" row already says the provider did not answer. A second row declaring that
    its date is unknown too adds a line and no information."""
    data = json.loads(json.dumps(RICH_IP_DATA))
    data["shodan"] = {}
    data["provider_status"]["shodan"] = {"outcome": "not_configured"}

    out = _render_ip(data)

    assert "shodan_last_update" not in out
    assert "open_ports" in out and "no data - not configured, no API key" in out


def test_provider_supplied_dates_are_escaped() -> None:
    """These are third-party strings on the same footing as an OTX pulse title."""
    data = json.loads(json.dumps(RICH_IP_DATA))
    data["shodan"]["last_update"] = "[green]fresh[/]"

    out = _render_ip(data)

    assert "[green]fresh[/]" in out


# --------------------------------------------------------------------------------------------
# End to end: the exact scenario this workstream was written to fix.
#
# Two of six credentials configured, VirusTotal clean, Shodan down, output redirected. Driven
# through the real orchestrator over respx so the coverage figure is computed rather than
# asserted into existence.
# --------------------------------------------------------------------------------------------


@pytest.fixture
def no_backoff_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Take the retry schedule out of the clock; Shodan's 500 is retryable and sleeps by default."""
    import tripper_recon.utils.backoff as backoff

    async def _instant(delay: float, *args: Any, **kwargs: Any) -> None:
        return None

    monkeypatch.setattr(backoff.asyncio, "sleep", _instant)


def test_two_of_six_credentials_says_so_on_the_screen(monkeypatch: pytest.MonkeyPatch, no_backoff_sleep: None) -> None:
    respx = pytest.importorskip("respx")
    import httpx

    monkeypatch.setenv("VT_API_KEY", "vt-test-key")
    monkeypatch.setenv("SHODAN_API_KEY", "shodan-test-key")

    vt_body = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"harmless": 68, "malicious": 0, "suspicious": 0, "undetected": 26},
                "last_analysis_date": 1699999999,
                "reputation": 0,
            }
        }
    }

    with respx.mock(assert_all_called=False) as mock:
        mock.get(url__regex=r"https://www\.virustotal\.com/api/v3/ip_addresses/.*").mock(
            return_value=httpx.Response(200, json=vt_body)
        )
        mock.get(url__regex=r"https://api\.shodan\.io/shodan/host/.*").mock(
            return_value=httpx.Response(500, json={"error": "down"})
        )
        out, code = _capture(lambda: cli._cmd_ip("93.184.216.34"))

    # The headline gap: four providers were never asked and the tool used to say nothing.
    assert "provider_coverage: 1 of 6 providers answered" in out
    assert "never asked - no API key configured: ipinfo, abuseipdb, otx" in out
    assert "never asked - skipped: cloudflare_asn" in out
    assert "query failed: shodan" in out
    # Provenance, so a pasted report says what produced it.
    assert "tripper-recon" in out and "run " in out
    # A partial answer is still exit 0; the coverage line is what qualifies it.
    assert code == 0
    # And no absence rendered as a zero anywhere.
    assert "0/0" not in out
