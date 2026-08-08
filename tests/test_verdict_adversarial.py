"""Adversarial end-to-end cases for the verdict engine (roadmap W5).

These are not unit tests of the extractors. Each one drives the **real** orchestrator with
respx-mocked providers, runs the real ruleset through the real engine, and asserts on the
verdict an analyst would actually be handed. The unit suites can all pass while the assembled
pipeline still answers a question wrongly; this file is the one that would catch that.

The cases are chosen as the ways a scoring engine gets a SOC to stop trusting it:

``a`` allowlisted infrastructure scored malicious -- one ``MALICIOUS`` on ``8.8.8.8`` and every
      other verdict the tool ever emits is discounted.
``b`` an intelligence blackout reported as clean. This is the single most important assertion in
      the file: nothing answered, so there is nothing to be clean about.
``c`` a thin panel reported confidently. One provider out of six is not a consensus.
``d`` the operator's own ``ip_example.md`` -- VirusTotal and AbuseIPDB flatly contradicting each
      other beside fifty near-duplicate OTX pulses from one bulk importer.
``e`` a phishing domain behind a CDN. The Tier B cap protects the shared address and must not
      reach the domain; a detected phishing site reading clean because of where it is hosted is
      a critical false negative.
``f`` the control. An engine that can never say "nothing found" is not conservative, it is
      broken, and every clean indicator would burn analyst time.
``g`` decade-old abuse reports still scoring at full strength.

Every provider is mocked. Nothing in this file may reach the network -- see the
``assert_all_called=False`` respx contexts, which register every route the orchestrator can
take, and ``tests/conftest.py``'s credential isolation.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional

import httpx
import pytest
import respx

from tripper_recon.orchestrators import IP_PROVIDERS, investigate_domain, investigate_ip

VT = "https://www.virustotal.com/api/v3"
OTX = "https://otx.alienvault.com/api/v1"
SHODAN = "https://api.shodan.io"
ABUSE = "https://api.abuseipdb.com/api/v2"
IPINFO = "https://ipinfo.io"
CF_GRAPHQL = "https://api.cloudflare.com/client/v4/radar/graphql"

#: Documentation ranges are refused by the non-public guard (``203.0.113.0/24`` is
#: ``is_private`` in the stdlib), so the unknown-indicator cases use addresses that are public
#: as far as ``ipaddress`` is concerned. Nothing is ever sent to them.
UNKNOWN_IP = "185.220.101.10"
CLOUDFLARE_IP = "104.16.5.5"
PHISH_DOMAIN = "phish-example.test"


@pytest.fixture(autouse=True)
def provider_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fake keys for all six providers.

    Without them every provider short-circuits to ``missing_api_key`` and each case would
    degrade into a duplicate of the blackout test. The values are obviously fake and
    ``conftest.clear_provider_env`` has already removed the operator's real ones.
    """
    for name in (
        "VT_API_KEY",
        "SHODAN_API_KEY",
        "ABUSEIPDB_API_KEY",
        "IPINFO_TOKEN",
        "OTX_API_KEY",
        "CLOUDFLARE_API_TOKEN",
    ):
        monkeypatch.setenv(name, f"fake-{name.lower()}")


# --------------------------------------------------------------------------------------
# Payload builders -- the provider `data` shapes, per tripper_recon/providers/*.py
# --------------------------------------------------------------------------------------


def vt_ip(
    *,
    malicious: int = 0,
    suspicious: int = 0,
    harmless: int = 94,
    reputation: int = 0,
    engines: Optional[Dict[str, Any]] = None,
    analysis_date: Optional[int] = 1754400000,
) -> Dict[str, Any]:
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": 0,
                },
                "reputation": reputation,
                "last_analysis_results": engines or {},
                "last_analysis_date": analysis_date,
            }
        }
    }


def abuse(
    *,
    reports: int = 0,
    score: int = 0,
    last_reported: Optional[str] = None,
    users: int = 0,
    whitelisted: bool = False,
) -> Dict[str, Any]:
    return {
        "data": {
            "totalReports": reports,
            "abuseConfidenceScore": score,
            "lastReportedAt": last_reported,
            "isWhitelisted": whitelisted,
            "usageType": "Data Center/Web Hosting/Transit",
            "isTor": False,
            "countryCode": "US",
            "numDistinctUsers": users,
        }
    }


def otx(pulses: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    return {"pulse_info": {"pulses": pulses or [], "count": len(pulses or [])}}


def shodan(ports: Optional[List[int]] = None) -> Dict[str, Any]:
    return {
        "ports": ports or [],
        "org": "Example Org",
        "tags": [],
        "data": [],
        "vulns": [],
        "hostnames": [],
        "last_update": "2026-08-01T00:00:00.000000",
    }


def ipinfo(ip: str, asn: int = 64500, name: str = "Example") -> Dict[str, Any]:
    return {"ip": ip, "city": "Nowhere", "country": "US", "loc": "0,0", "org": f"AS{asn} {name}"}


#: A successful Cloudflare Radar reply. The key must be absent rather than null: the provider
#: tests ``"errors" in j``, so ``{"errors": None}`` reads as a failure.
CF_ASN_OK: Dict[str, Any] = {"data": {"asn": {"asn": 64500, "name": "Example", "countryCode": "US"}}}


def route_ip_providers(
    mock: respx.MockRouter,
    ip: str,
    *,
    vt: Optional[Dict[str, Any]] = None,
    ab: Optional[Dict[str, Any]] = None,
    ox: Optional[Dict[str, Any]] = None,
    sh: Optional[Dict[str, Any]] = None,
    ipi: Optional[Dict[str, Any]] = None,
) -> None:
    """Register all five per-IP providers plus Cloudflare. ``None`` means a 500, not a silence.

    Every route is registered even when it answers 500, so an unrouted request -- which respx
    would raise on -- stays a signal that the orchestrator went somewhere unexpected.
    """
    for url, body in (
        (f"{VT}/ip_addresses/{ip}", vt),
        (f"{ABUSE}/check", ab),
        (f"{OTX}/indicators/IPv4/{ip}/general", ox),
        (f"{SHODAN}/shodan/host/{ip}", sh),
        (f"{IPINFO}/{ip}", ipi),
    ):
        response = httpx.Response(500) if body is None else httpx.Response(200, json=body)
        mock.get(url).mock(return_value=response)
    mock.post(CF_GRAPHQL).mock(return_value=httpx.Response(200, json=CF_ASN_OK))


def verdict_of(data: Mapping[str, Any]) -> Dict[str, Any]:
    payload = data.get("verdict")
    assert isinstance(payload, dict), f"no verdict was computed: {data.get('verdict_error')!r}"
    return payload


def signal_points(verdict: Mapping[str, Any], signal_id: str) -> Optional[float]:
    for signal in verdict["signals"]:
        if signal["id"] == signal_id:
            return float(signal["points"])
    return None


# --------------------------------------------------------------------------------------
# a -- the allowlist. Getting this wrong ends the tool's credibility in one screen.
# --------------------------------------------------------------------------------------


async def test_a_a_public_resolver_with_clean_data_is_known_infrastructure() -> None:
    """``8.8.8.8`` must reach ``KNOWN_INFRASTRUCTURE`` by allowlist, never by score.

    Public resolvers carry permanent nonzero VirusTotal and AbuseIPDB residue from DNS
    tunnelling and scanning reports. A tool that returns anything resembling malicious for one
    of them teaches the analyst to discount every other verdict it produces.
    """
    with respx.mock(assert_all_called=False) as mock:
        route_ip_providers(
            mock,
            "8.8.8.8",
            vt=vt_ip(harmless=90),
            ab=abuse(),
            ox=otx(),
            sh=shodan(ports=[53]),
            ipi=ipinfo("8.8.8.8", 15169, "GOOGLE"),
        )
        result = await investigate_ip("8.8.8.8")

    verdict = verdict_of(result.data)
    assert verdict["verdict"] == "KNOWN_INFRASTRUCTURE"
    # Reached by list, not by arithmetic: a Tier A record must be behind it.
    forced = [o for o in verdict["overrides_applied"] if o["tier"].upper() == "A" and o["effect"] == "verdict_forced"]
    assert forced, "KNOWN_INFRASTRUCTURE with no Tier A override behind it"
    assert forced[0]["source_retrieved_at"], "the allowlist entry carries no retrieval date, so staleness is invisible"
    assert verdict["allowlist"] is not None


# --------------------------------------------------------------------------------------
# b -- the absent-data rule. The most important assertion in this file.
# --------------------------------------------------------------------------------------


async def test_b_a_total_blackout_is_insufficient_data_and_never_clean() -> None:
    """No provider answered, so there is nothing to be clean about.

    ``NO_ADVERSE_FINDINGS`` is a claim about what the panel reported. When the panel reported
    nothing, the claim is false, and it is the specific false claim that gets a live indicator
    waved through.
    """
    with respx.mock(assert_all_called=False) as mock:
        route_ip_providers(mock, UNKNOWN_IP)  # every provider 500s
        result = await investigate_ip(UNKNOWN_IP)

    verdict = verdict_of(result.data)
    assert verdict["verdict"] == "INSUFFICIENT_DATA"
    assert verdict["verdict"] != "NO_ADVERSE_FINDINGS"
    assert verdict["confidence"] == "LOW"
    assert verdict["coverage"]["answered"] == []
    assert sorted(verdict["coverage"]["errored"]) == sorted(p for p in IP_PROVIDERS if p != "cloudflare_asn")
    # The exit code must not read as a successful clean lookup either.
    assert result.ok is False
    assert any("blackout" in message for message in result.errors)
    # And the reason has to be legible, not just the label.
    assert any("coverage floor" in reason for reason in verdict["adjustment_reasons"])


async def test_b_unconfigured_providers_are_missing_coverage_not_an_excuse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A provider with no API key sits in the denominator. It is absence, not agreement.

    Shrinking the denominator to the providers that happen to be configured would make an
    unconfigured tool look fully covered -- a clean verdict from a panel nobody paid for.
    """
    for name in ("SHODAN_API_KEY", "OTX_API_KEY", "ABUSEIPDB_API_KEY", "CLOUDFLARE_API_TOKEN"):
        monkeypatch.delenv(name, raising=False)

    with respx.mock(assert_all_called=False) as mock:
        route_ip_providers(mock, UNKNOWN_IP, vt=vt_ip(), ipi=ipinfo(UNKNOWN_IP))
        result = await investigate_ip(UNKNOWN_IP)

    verdict = verdict_of(result.data)
    coverage = verdict["coverage"]
    assert set(coverage["unconfigured"]) >= {"shodan", "otx", "abuseipdb"}
    assert coverage["ratio"] < 1.0
    assert verdict["verdict"] == "INSUFFICIENT_DATA"


# --------------------------------------------------------------------------------------
# c -- a thin panel must not sound like a consensus.
# --------------------------------------------------------------------------------------


async def test_c_one_clean_provider_of_six_is_not_confidently_clean() -> None:
    """One provider answering clean is a data point, not an all-clear."""
    with respx.mock(assert_all_called=False) as mock:
        route_ip_providers(mock, UNKNOWN_IP, vt=vt_ip(harmless=90))
        result = await investigate_ip(UNKNOWN_IP)

    verdict = verdict_of(result.data)
    assert verdict["verdict"] == "INSUFFICIENT_DATA"
    assert verdict["confidence"] == "LOW"
    assert verdict["coverage"]["answered"] == ["virustotal"]
    # Coverage is on the object, so the console and the JSON both have to be able to show it.
    assert verdict["coverage"]["ratio"] < verdict["coverage_floor"]


# --------------------------------------------------------------------------------------
# d -- the operator's real ip_example.md case.
# --------------------------------------------------------------------------------------


def _ip_example_pulses() -> List[Dict[str, Any]]:
    """Fifty pulses dominated by bulk-imported near-duplicates from two authors.

    Reconstructed from ``ip_example.md``, which samples five of the fifty titles: one from
    ``NextRayAI`` and four near-identical ``jan2,2025 clone Auto-generated Pulse`` entries from
    ``AlessandroFiori``, all a year old. The authorship of the forty-five unsampled pulses is
    not observable, so this fixture takes the reading the visible evidence supports -- a set
    dominated by bulk importers rather than fifty independent researchers.
    """
    pulses = [
        {
            "id": f"bulk{i}",
            "name": f"IOC Records Provided by @NextRayAI {i}",
            "author_name": "NextRayAI",
            "created": "2025-01-02T00:00:00",
            "modified": "2025-01-02T00:00:00",
            "TLP": "white",
        }
        for i in range(46)
    ]
    pulses += [
        {
            "id": f"clone{i}",
            "name": "jan2,2025 clone Auto-generated Pulse",
            "author_name": "AlessandroFiori",
            "created": "2025-01-02T00:00:00",
            "modified": "2025-01-02T00:00:00",
            "TLP": "white",
        }
        for i in range(4)
    ]
    return pulses


async def test_d_the_ip_example_case_surfaces_the_contradiction_and_deflates_the_pulses() -> None:
    """VT 5/94 beside AbuseIPDB 0%, with fifty pulses that are really a handful.

    Three separate failures are asserted against here, all of them present in the tool before
    the engine existed: the fifty-pulse count read as fifty observations, the two providers'
    disagreement averaged into one uninformative number, and the analyst never told to look.
    """
    engines = {f"VendorMal{i}": {"category": "malicious", "result": "malware"} for i in range(5)}
    engines.update({f"VendorOk{i}": {"category": "harmless", "result": "clean"} for i in range(89)})

    with respx.mock(assert_all_called=False) as mock:
        route_ip_providers(
            mock,
            UNKNOWN_IP,
            vt=vt_ip(malicious=5, harmless=89, reputation=-37, engines=engines),
            ab=abuse(reports=5, score=0, last_reported="2026-07-01T00:00:00+00:00", users=2),
            ox=otx(_ip_example_pulses()),
            sh=shodan(ports=[53]),
            ipi=ipinfo(UNKNOWN_IP, 4808, "China Unicom Beijing Province Network"),
        )
        result = await investigate_ip(UNKNOWN_IP)

    verdict = verdict_of(result.data)

    # The contradiction is named, not averaged into the score.
    rules = [c["rule_id"] for c in verdict["contradictions"]]
    assert "vt_vs_abuseipdb" in rules
    contradiction = next(c for c in verdict["contradictions"] if c["rule_id"] == "vt_vs_abuseipdb")
    assert contradiction["analyst_hint"].strip()
    assert verdict["requires_analyst_review"] is True

    # VirusTotal keeps its full weight. A contradiction caps confidence; it never cancels points.
    assert signal_points(verdict, "vt.weighted_detections") == pytest.approx(17.5)

    # Fifty pulses collapse to a low single-digit effective count.
    otx_signal = next(s for s in verdict["signals"] if s["id"] == "otx.pulse_quality")
    effective = float(otx_signal["evidence"]["effective_pulses"])
    assert effective < 5.0, f"50 near-duplicate pulses from two authors scored {effective} effective"
    assert otx_signal["points"] < 5.0
    assert "50 pulses reported" in otx_signal["observation"]
    assert "one author" in otx_signal["observation"]

    # Adverse evidence exists, so the clean label is unavailable regardless of the band.
    assert verdict["verdict"] == "SUSPICIOUS"
    assert verdict["verdict"] != "NO_ADVERSE_FINDINGS"


# --------------------------------------------------------------------------------------
# e -- the CDN false negative.
# --------------------------------------------------------------------------------------


async def test_e_cdn_hosting_does_not_launder_a_detected_phishing_domain() -> None:
    """Tier B protects the shared address and must not reach the domain verdict.

    Both halves are failure modes. Scoring the shared Cloudflare address as malicious indicts
    every other tenant behind it; letting that same membership clear the domain hands a phishing
    site a clean bill of health because of where it chose to host. The two verdicts are computed
    separately and both are true at once.
    """
    engines = {f"V{i}": {"category": "malicious", "result": "phishing"} for i in range(12)}
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{VT}/domains/{PHISH_DOMAIN}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {"malicious": 12, "suspicious": 2, "harmless": 60},
                            "reputation": -50,
                            "categories": {"VendorA": "phishing", "VendorB": "phishing"},
                            "last_dns_records": [{"type": "A", "value": CLOUDFLARE_IP}],
                            "whois": "Creation Date: 2026-07-25T00:00:00Z",
                            "whois_timestamp": 1753401600,
                            "last_analysis_results": engines,
                            "last_analysis_date": 1754697600,
                            "creation_date": 1753401600,
                        }
                    }
                },
            )
        )
        mock.get(f"{OTX}/indicators/domain/{PHISH_DOMAIN}/general").mock(
            return_value=httpx.Response(200, json={"pulse_info": {"pulses": []}, "malware": [], "passive_dns": []})
        )
        route_ip_providers(
            mock,
            CLOUDFLARE_IP,
            vt=vt_ip(harmless=90),
            ab=abuse(),
            ox=otx(),
            sh=shodan(ports=[80, 443]),
            ipi=ipinfo(CLOUDFLARE_IP, 13335, "CLOUDFLARENET"),
        )
        result = await investigate_domain(PHISH_DOMAIN)

    domain_verdict = verdict_of(result.data)

    # The domain is adverse and stays adverse.
    assert domain_verdict["verdict"] in {"SUSPICIOUS", "MALICIOUS"}
    assert domain_verdict["verdict"] not in {"NO_ADVERSE_FINDINGS", "KNOWN_INFRASTRUCTURE"}
    assert signal_points(domain_verdict, "vt.weighted_detections")
    assert signal_points(domain_verdict, "vt.categories")
    assert signal_points(domain_verdict, "domain.age")

    # Tier B never touched the domain-level verdict. This is the regression that matters: a CDN
    # override reaching the domain scope would be the critical false negative.
    assert domain_verdict["overrides_applied"] == []

    # The address is capped and annotated instead, so nobody blocks a shared edge IP.
    entry = next(e for e in result.data["ips"] if e["ip"] == CLOUDFLARE_IP)
    ip_verdict = entry["verdict"]
    assert ip_verdict["verdict"] != "MALICIOUS"
    assert ip_verdict["attribution_warning"], "a Tier B address carries no attribution warning"
    assert any(o["rule_id"].startswith("cdn.") for o in ip_verdict["overrides_applied"])


# --------------------------------------------------------------------------------------
# f -- the control. The engine must still be able to say "nothing found".
# --------------------------------------------------------------------------------------


async def test_f_a_fully_covered_unremarkable_address_reads_as_no_adverse_findings() -> None:
    """An engine that can never clear anything is broken, not conservative.

    The absent-data rule denies a clean verdict to a panel that did not answer. It must not deny
    one to a panel that did.
    """
    with respx.mock(assert_all_called=False) as mock:
        route_ip_providers(
            mock,
            UNKNOWN_IP,
            vt=vt_ip(harmless=94),
            ab=abuse(),
            ox=otx(),
            sh=shodan(ports=[443]),
            ipi=ipinfo(UNKNOWN_IP),
        )
        result = await investigate_ip(UNKNOWN_IP)

    verdict = verdict_of(result.data)
    assert verdict["verdict"] == "NO_ADVERSE_FINDINGS"
    assert verdict["confidence"] in {"HIGH", "MEDIUM"}
    assert verdict["score"] == 0
    # Earned by affirmative negatives, which is what separates this from case b.
    observed = {s["id"] for s in verdict["signals"]}
    assert {"vt.no_detections", "abuseipdb.no_reports", "otx.no_pulses"} <= observed


# --------------------------------------------------------------------------------------
# g -- staleness must cost points and must be visible.
# --------------------------------------------------------------------------------------


async def test_g_a_2019_abuse_report_is_decayed_and_the_staleness_is_on_screen() -> None:
    """A 100% AbuseIPDB score last reported in 2019 is history, not an alert.

    Two requirements, and the second is the one a decay curve alone does not satisfy: the
    discount has to be legible. A quietly-decayed score is a number the analyst cannot
    reconstruct or argue with.
    """
    stale, fresh = {}, {}
    for label, last_reported in (("stale", "2019-03-04T00:00:00+00:00"), ("fresh", "2026-08-06T00:00:00+00:00")):
        with respx.mock(assert_all_called=False) as mock:
            route_ip_providers(
                mock,
                UNKNOWN_IP,
                vt=vt_ip(harmless=94),
                ab=abuse(reports=120, score=100, last_reported=last_reported, users=30),
                ox=otx(),
                sh=shodan(ports=[22]),
                ipi=ipinfo(UNKNOWN_IP),
            )
            target = stale if label == "stale" else fresh
            target.update(verdict_of((await investigate_ip(UNKNOWN_IP)).data))

    assert stale["score"] < fresh["score"], "a 2019 report scored the same as one from this week"
    assert signal_points(stale, "abuseipdb.confidence") < signal_points(fresh, "abuseipdb.confidence")

    # Visible, not merely applied: the observation names the age and the multiplier.
    observation = next(s for s in stale["signals"] if s["id"] == "abuseipdb.confidence")["observation"]
    assert "days ago" in observation
    assert "recency x" in observation
    # Still adverse. Decay reduces weight; it never converts a report into an all-clear.
    assert stale["verdict"] != "NO_ADVERSE_FINDINGS"


async def test_g_a_missing_report_date_does_not_discount_the_report() -> None:
    """Absent metadata must not argue an indicator clean.

    Regression for a real defect. ``decay_factor`` used to return the profile's open-ended tail
    for an undated observation, on the reasoning that treating it as old is the cautious call.
    Decay only ever multiplies adverse points, so that reasoning is inverted: the same AbuseIPDB
    payload -- 100% confidence, 500 reports, 40 distinct reporters -- scored 35 with
    ``lastReportedAt`` present and 5 with the field absent. One missing field, a sevenfold
    collapse of adverse evidence, and a verdict an analyst would have skipped past.

    The gap now costs confidence (the freshness criterion) instead of score, which is the axis
    it actually belongs on.
    """
    results: Dict[str, Dict[str, Any]] = {}
    for label, last_reported in (("undated", None), ("dated", "2026-08-06T00:00:00+00:00")):
        with respx.mock(assert_all_called=False) as mock:
            route_ip_providers(
                mock,
                UNKNOWN_IP,
                vt=vt_ip(harmless=94),
                ab=abuse(reports=500, score=100, last_reported=last_reported, users=40),
                ox=otx(),
                sh=shodan(ports=[22]),
                ipi=ipinfo(UNKNOWN_IP),
            )
            results[label] = verdict_of((await investigate_ip(UNKNOWN_IP)).data)

    assert results["undated"]["score"] == results["dated"]["score"]
    assert signal_points(results["undated"], "abuseipdb.confidence") == signal_points(
        results["dated"], "abuseipdb.confidence"
    )
    # The unknown is reported rather than priced in.
    observation = next(s for s in results["undated"]["signals"] if s["id"] == "abuseipdb.confidence")["observation"]
    assert "date not reported" in observation
    # And it is the confidence axis, not the score, that absorbs the missing freshness evidence.
    assert results["undated"]["confidence_score"] < results["dated"]["confidence_score"]
