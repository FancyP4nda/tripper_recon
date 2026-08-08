"""Roadmap 4.6 -- the provider fields that were fetched and thrown away.

Four providers already returned fields the tool discarded. This module proves each one now
survives into the envelope, and -- the half that actually matters for a security tool -- that
its *absence* is reported as absence rather than manufactured into a benign-looking value.

The absence tests are not padding. The failure mode this whole workstream exists to fix is a
tool that renders "we did not ask" and "we asked and it was clean" identically. A missing
``isWhitelisted`` that defaults to ``False``, or a missing ``last_analysis_date`` that defaults
to epoch 0, is the same defect one field down.

Every request in this module is served by respx. Nothing here opens a socket, and no key is
read from the environment -- ``conftest.clear_provider_env`` guarantees the second part.
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Dict

import httpx
import pytest
import respx

from tripper_recon.providers.abuseipdb import abuseipdb_check
from tripper_recon.providers.otx import otx_domain_pulses, otx_ip_pulses
from tripper_recon.providers.shodan_api import shodan_host
from tripper_recon.providers.virustotal import vt_domain_summary, vt_ip_summary

FAKE_KEY = "test-key-not-a-credential"
IP = "203.0.113.10"
DOMAIN = "example.invalid"

VT_IP_URL = f"https://www.virustotal.com/api/v3/ip_addresses/{IP}"
VT_DOMAIN_URL = f"https://www.virustotal.com/api/v3/domains/{DOMAIN}"
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
OTX_IP_URL = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{IP}/general"
OTX_DOMAIN_URL = f"https://otx.alienvault.com/api/v1/indicators/domain/{DOMAIN}/general"
SHODAN_URL = f"https://api.shodan.io/shodan/host/{IP}"


@pytest.fixture()
async def client() -> AsyncIterator[httpx.AsyncClient]:
    """A plain client. ``create_client`` is not used: transport behaviour is not under test."""
    async with httpx.AsyncClient() as c:
        yield c


def _vt_attributes(**attributes: Any) -> Dict[str, Any]:
    """Wrap attributes in the VirusTotal v3 ``{"data": {"attributes": ...}}`` envelope."""
    return {"data": {"id": IP, "type": "ip_address", "attributes": attributes}}


VT_ENGINES: Dict[str, Any] = {
    "Kaspersky": {"category": "malicious", "result": "malware", "method": "blacklist"},
    "Sophos": {"category": "suspicious", "result": "suspicious site", "method": "blacklist"},
    "CleanTalk": {"category": "harmless", "result": "clean", "method": "blacklist"},
    "Acme": {"category": "undetected", "result": None, "method": "blacklist"},
}


# --------------------------------------------------------------------------------------
# VirusTotal
# --------------------------------------------------------------------------------------


async def test_vt_ip_retains_the_per_engine_map_and_the_analysis_date(client: httpx.AsyncClient) -> None:
    """``5/94`` is a count; the per-engine map is the finding.

    ``vt_security_results`` carries the full map -- deliberately the same key the domain path
    has always used, so a consumer has one name to read rather than two.
    """
    payload = _vt_attributes(
        last_analysis_stats={"malicious": 1, "suspicious": 1, "harmless": 1, "undetected": 1},
        last_analysis_results=VT_ENGINES,
        last_analysis_date=1_700_000_000,
        reputation=-7,
    )
    async with respx.mock(assert_all_called=True) as router:
        router.get(VT_IP_URL).mock(return_value=httpx.Response(200, json=payload))
        result = await vt_ip_summary(client=client, api_key=FAKE_KEY, ip=IP)

    data = result["data"]
    assert result["ok"] is True
    assert data["vt_security_results"] == VT_ENGINES
    assert data["vt_last_analysis_date"] == 1_700_000_000
    assert data["vt_last_analysis_date_iso"] == "2023-11-14T22:13:20+00:00"
    # Pre-existing keys keep their pre-existing names and meanings.
    assert data["vt_last_analysis_stats"] == {"malicious": 1, "suspicious": 1, "harmless": 1, "undetected": 1}
    assert data["vt_reputation"] == -7
    assert data["vt_link"] == f"https://www.virustotal.com/gui/ip-address/{IP}"


async def test_vt_detecting_engines_names_only_the_engines_that_flagged(client: httpx.AsyncClient) -> None:
    """WHICH engines flagged it, malicious before suspicious, then alphabetical.

    Harmless and undetected verdicts are excluded: a list that included them would be the same
    94-entry blob the console cannot show.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get(VT_IP_URL).mock(
            return_value=httpx.Response(200, json=_vt_attributes(last_analysis_results=VT_ENGINES))
        )
        result = await vt_ip_summary(client=client, api_key=FAKE_KEY, ip=IP)

    assert result["data"]["vt_detecting_engines"] == [
        {"engine": "Kaspersky", "category": "malicious", "result": "malware", "method": "blacklist"},
        {"engine": "Sophos", "category": "suspicious", "result": "suspicious site", "method": "blacklist"},
    ]


async def test_vt_detecting_engines_ordering_is_deterministic(client: httpx.AsyncClient) -> None:
    """Two runs over the same report must diff cleanly (roadmap 4.9 applies here too)."""
    engines = {
        "zeta": {"category": "malicious", "result": "a"},
        "Alpha": {"category": "suspicious", "result": "b"},
        "beta": {"category": "malicious", "result": "c"},
    }
    async with respx.mock(assert_all_called=True) as router:
        router.get(VT_IP_URL).mock(return_value=httpx.Response(200, json=_vt_attributes(last_analysis_results=engines)))
        result = await vt_ip_summary(client=client, api_key=FAKE_KEY, ip=IP)

    assert [e["engine"] for e in result["data"]["vt_detecting_engines"]] == ["beta", "zeta", "Alpha"]


async def test_vt_ip_absent_fields_report_absence_not_a_default(client: httpx.AsyncClient) -> None:
    """An attributes block with none of the new fields must not raise and must not invent one.

    ``vt_last_analysis_date`` of ``None`` says "unknown". A ``0`` would say "scanned in 1970",
    which any freshness rule would read as maximally stale -- a fabricated finding.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get(VT_IP_URL).mock(return_value=httpx.Response(200, json=_vt_attributes()))
        result = await vt_ip_summary(client=client, api_key=FAKE_KEY, ip=IP)

    data = result["data"]
    assert result["ok"] is True
    assert data["vt_security_results"] == {}
    assert data["vt_detecting_engines"] == []
    assert data["vt_last_analysis_date"] is None
    assert data["vt_last_analysis_date_iso"] is None


@pytest.mark.parametrize(
    ("label", "attributes"),
    [
        ("results is null", {"last_analysis_results": None, "last_analysis_date": None}),
        ("results is a list", {"last_analysis_results": [], "last_analysis_date": "not-a-date"}),
        ("results is a string", {"last_analysis_results": "denied", "last_analysis_date": True}),
        ("engine entry is not a dict", {"last_analysis_results": {"Kaspersky": "malicious"}}),
        ("engine entry has no category", {"last_analysis_results": {"Kaspersky": {"result": "x"}}}),
    ],
)
async def test_vt_wrong_typed_fields_do_not_raise(
    client: httpx.AsyncClient, label: str, attributes: Dict[str, Any]
) -> None:
    """Third-party JSON: any field can be the wrong type. None of these may crash a run.

    ``last_analysis_date: True`` is called out deliberately -- ``True`` is an ``int`` to Python,
    so a naive coercion would report a scan date of 1970-01-01T00:00:01Z.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get(VT_IP_URL).mock(return_value=httpx.Response(200, json=_vt_attributes(**attributes)))
        result = await vt_ip_summary(client=client, api_key=FAKE_KEY, ip=IP)

    data = result["data"]
    assert result["ok"] is True, label
    assert data["vt_detecting_engines"] == [], label
    assert data["vt_last_analysis_date"] is None, label
    assert data["vt_last_analysis_date_iso"] is None, label


async def test_vt_domain_adds_freshness_and_keeps_every_existing_key(client: httpx.AsyncClient) -> None:
    """The domain envelope gains the two new keys and loses none of its eleven existing ones."""
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 2, "harmless": 60},
                "last_analysis_results": VT_ENGINES,
                "last_analysis_date": 1_700_000_000,
                "reputation": 3,
                "categories": {"Forcepoint": "phishing"},
                "tags": ["dga"],
                "last_dns_records": [{"type": "A", "value": "203.0.113.10"}],
                "whois": "registrar: example",
                "whois_timestamp": 1_600_000_000,
                "last_https_certificate": {"validity": {"not_after": "2027-01-01"}},
            }
        }
    }
    async with respx.mock(assert_all_called=True) as router:
        router.get(VT_DOMAIN_URL).mock(return_value=httpx.Response(200, json=payload))
        result = await vt_domain_summary(client=client, api_key=FAKE_KEY, domain=DOMAIN)

    data = result["data"]
    assert data["vt_last_analysis_date"] == 1_700_000_000
    assert data["vt_last_analysis_date_iso"] == "2023-11-14T22:13:20+00:00"
    assert [e["engine"] for e in data["vt_detecting_engines"]] == ["Kaspersky", "Sophos"]
    # The pre-existing key for the same map is untouched -- console code reads it by this name.
    assert data["vt_security_results"] == VT_ENGINES
    assert set(data) == {
        "vt_last_analysis_stats",
        "vt_reputation",
        "vt_categories",
        "vt_tags",
        "vt_dns_records",
        "vt_security_results",
        "vt_detecting_engines",
        "vt_last_analysis_date",
        "vt_last_analysis_date_iso",
        "vt_whois",
        "vt_whois_timestamp",
        "vt_last_https_certificate",
        "vt_last_https_certificate_jarm",
        "vt_link",
    }


async def test_vt_404_still_reports_not_found(client: httpx.AsyncClient) -> None:
    """The new fields must not change the not-found envelope. 404 is NOT clean."""
    async with respx.mock(assert_all_called=True) as router:
        router.get(VT_IP_URL).mock(return_value=httpx.Response(404, json={"error": {"code": "NotFoundError"}}))
        result = await vt_ip_summary(client=client, api_key=FAKE_KEY, ip=IP)

    assert result == {"ok": False, "error": "not_found"}


# --------------------------------------------------------------------------------------
# AbuseIPDB
# --------------------------------------------------------------------------------------


async def test_abuseipdb_retains_the_six_discarded_fields(client: httpx.AsyncClient) -> None:
    """``lastReportedAt`` is the point of this one: a 100% score from 2019 is not a 100% score today."""
    payload = {
        "data": {
            "ipAddress": IP,
            "totalReports": 42,
            "abuseConfidenceScore": 100,
            "lastReportedAt": "2019-03-01T12:00:00+00:00",
            "isWhitelisted": False,
            "usageType": "Data Center/Web Hosting/Transit",
            "isTor": True,
            "countryCode": "NL",
            "numDistinctUsers": 3,
        }
    }
    async with respx.mock(assert_all_called=True) as router:
        router.get(ABUSE_URL).mock(return_value=httpx.Response(200, json=payload))
        result = await abuseipdb_check(client=client, api_key=FAKE_KEY, ip=IP)

    assert result["data"] == {
        "abuseipdb_reports": 42,
        "abuseipdb_confidence_score": 100,
        "abuseipdb_last_reported_at": "2019-03-01T12:00:00+00:00",
        "abuseipdb_is_whitelisted": False,
        "abuseipdb_usage_type": "Data Center/Web Hosting/Transit",
        "abuseipdb_is_tor": True,
        "abuseipdb_country_code": "NL",
        "abuseipdb_num_distinct_users": 3,
    }


async def test_abuseipdb_absent_fields_are_none_never_false(client: httpx.AsyncClient) -> None:
    """THE absence test for this provider.

    ``isWhitelisted`` absent must be ``None``, not ``False``. "AbuseIPDB did not say" and
    "AbuseIPDB says it is not whitelisted" are different claims, and a verdict engine that
    reads a defaulted ``False`` as the second one is asserting something no provider said.
    The two pre-existing count fields keep their pre-existing ``0`` defaults.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get(ABUSE_URL).mock(return_value=httpx.Response(200, json={"data": {"ipAddress": IP}}))
        result = await abuseipdb_check(client=client, api_key=FAKE_KEY, ip=IP)

    assert result["data"] == {
        "abuseipdb_reports": 0,
        "abuseipdb_confidence_score": 0,
        "abuseipdb_last_reported_at": None,
        "abuseipdb_is_whitelisted": None,
        "abuseipdb_usage_type": None,
        "abuseipdb_is_tor": None,
        "abuseipdb_country_code": None,
        "abuseipdb_num_distinct_users": None,
    }


@pytest.mark.parametrize(
    ("label", "data"),
    [
        ("explicit nulls", {"lastReportedAt": None, "isWhitelisted": None, "usageType": None}),
        ("empty strings", {"lastReportedAt": "", "usageType": "   ", "countryCode": ""}),
        ("bool where a count belongs", {"numDistinctUsers": True}),
        ("string where a bool belongs", {"isTor": "yes", "isWhitelisted": "true"}),
        ("data is not a dict", {}),
    ],
)
async def test_abuseipdb_wrong_typed_fields_report_none(
    client: httpx.AsyncClient, label: str, data: Dict[str, Any]
) -> None:
    """A malformed field is unknown, not a value. ``isTor: "yes"`` must not become ``True``."""
    body: Dict[str, Any] = {"data": data} if data else {"data": []}
    async with respx.mock(assert_all_called=True) as router:
        router.get(ABUSE_URL).mock(return_value=httpx.Response(200, json=body))
        result = await abuseipdb_check(client=client, api_key=FAKE_KEY, ip=IP)

    envelope = result["data"]
    assert result["ok"] is True, label
    for key in (
        "abuseipdb_last_reported_at",
        "abuseipdb_is_whitelisted",
        "abuseipdb_usage_type",
        "abuseipdb_is_tor",
        "abuseipdb_country_code",
        "abuseipdb_num_distinct_users",
    ):
        assert envelope[key] is None, f"{label}: {key}"


# --------------------------------------------------------------------------------------
# OTX
# --------------------------------------------------------------------------------------


def _otx_pulse(name: str, **extra: Any) -> Dict[str, Any]:
    pulse: Dict[str, Any] = {"name": name}
    pulse.update(extra)
    return pulse


async def test_otx_ip_retains_author_and_dates_for_every_pulse(client: httpx.AsyncClient) -> None:
    """Per-pulse author/created/modified -- the fields that make the count quality-adjustable.

    Deliberately seven pulses: ``otx_pulses`` must NOT inherit the five-entry title cap. A
    diversity measure computed over the first five of fifty pulses is not a diversity measure.
    """
    pulses = [
        _otx_pulse(f"campaign {n}", author_name="cloner", created=f"2024-01-0{n}T00:00:00", modified="2024-02-01")
        for n in range(1, 8)
    ]
    body = {"pulse_info": {"count": 7, "pulses": pulses}}
    async with respx.mock(assert_all_called=True) as router:
        router.get(OTX_IP_URL).mock(return_value=httpx.Response(200, json=body))
        result = await otx_ip_pulses(client=client, api_key=FAKE_KEY, ip=IP)

    data = result["data"]
    # Pre-existing contract, unchanged: the count is every pulse, the titles cap at five.
    assert data["otx_pulse_count"] == 7
    assert data["otx_pulse_titles"] == ["campaign 1", "campaign 2", "campaign 3", "campaign 4", "campaign 5"]
    assert len(data["otx_pulses"]) == 7
    assert data["otx_pulses"][0] == {
        "name": "campaign 1",
        "author": "cloner",
        "created": "2024-01-01T00:00:00",
        "modified": "2024-02-01",
    }
    assert {p["author"] for p in data["otx_pulses"]} == {"cloner"}


@pytest.mark.parametrize(
    ("label", "pulse", "expected"),
    [
        ("flat author_name", {"author_name": "alice"}, "alice"),
        ("nested author.username", {"author": {"username": "bob"}}, "bob"),
        ("nested author.name", {"author": {"name": "carol"}}, "carol"),
        ("bare author string", {"author": "dave"}, "dave"),
        ("flat wins over nested", {"author_name": "alice", "author": {"username": "bob"}}, "alice"),
        ("no author at all", {}, None),
        ("author is a list", {"author": ["eve"]}, None),
        ("author_name is empty", {"author_name": "  "}, None),
    ],
)
async def test_otx_author_extraction_handles_every_observed_shape(
    client: httpx.AsyncClient, label: str, pulse: Dict[str, Any], expected: Any
) -> None:
    """An unattributed pulse reports ``None`` -- it must never count as its own distinct author."""
    body = {"pulse_info": {"pulses": [_otx_pulse("p", **pulse)]}}
    async with respx.mock(assert_all_called=True) as router:
        router.get(OTX_IP_URL).mock(return_value=httpx.Response(200, json=body))
        result = await otx_ip_pulses(client=client, api_key=FAKE_KEY, ip=IP)

    assert result["data"]["otx_pulses"][0]["author"] == expected, label


@pytest.mark.parametrize(
    ("label", "body"),
    [
        ("no pulse_info", {}),
        ("pulse_info is null", {"pulse_info": None}),
        ("pulses is null", {"pulse_info": {"pulses": None}}),
        ("pulses is a dict", {"pulse_info": {"pulses": {"a": 1}}}),
        ("pulse entry is a string", {"pulse_info": {"pulses": ["not-a-pulse"]}}),
    ],
)
async def test_otx_degenerate_pulse_shapes_do_not_raise(
    client: httpx.AsyncClient, label: str, body: Dict[str, Any]
) -> None:
    """A malformed pulse list yields no records and no exception."""
    async with respx.mock(assert_all_called=True) as router:
        router.get(OTX_IP_URL).mock(return_value=httpx.Response(200, json=body))
        result = await otx_ip_pulses(client=client, api_key=FAKE_KEY, ip=IP)

    assert result["ok"] is True, label
    assert result["data"]["otx_pulses"] == [], label


async def test_otx_pulse_missing_dates_reports_none(client: httpx.AsyncClient) -> None:
    """A pulse with no timestamps is dateless, not fresh and not stale."""
    body = {"pulse_info": {"pulses": [_otx_pulse("undated", author_name="alice")]}}
    async with respx.mock(assert_all_called=True) as router:
        router.get(OTX_IP_URL).mock(return_value=httpx.Response(200, json=body))
        result = await otx_ip_pulses(client=client, api_key=FAKE_KEY, ip=IP)

    assert result["data"]["otx_pulses"] == [{"name": "undated", "author": "alice", "created": None, "modified": None}]


async def test_otx_domain_gains_pulses_and_keeps_its_existing_keys(client: httpx.AsyncClient) -> None:
    """The domain envelope gains ``otx_pulses`` and keeps all five of its existing keys."""
    body = {
        "pulse_info": {
            "pulses": [_otx_pulse("phish kit", author_name="alice", created="2025-01-01", modified="2025-01-02")],
            "tags": ["phishing"],
        },
        "malware": [{"hash": "abc"}],
        "passive_dns": [{"address": IP}, {"address": "203.0.113.11"}],
    }
    async with respx.mock(assert_all_called=True) as router:
        router.get(OTX_DOMAIN_URL).mock(return_value=httpx.Response(200, json=body))
        result = await otx_domain_pulses(client=client, api_key=FAKE_KEY, domain=DOMAIN)

    assert result["data"] == {
        "otx_pulse_count": 1,
        "otx_pulse_titles": ["phish kit"],
        "otx_pulses": [{"name": "phish kit", "author": "alice", "created": "2025-01-01", "modified": "2025-01-02"}],
        "otx_tags": ["phishing"],
        "otx_malware_count": 1,
        "otx_passive_dns_count": 2,
    }


# --------------------------------------------------------------------------------------
# Shodan
# --------------------------------------------------------------------------------------


async def test_shodan_retains_vulns_hostnames_and_last_update(client: httpx.AsyncClient) -> None:
    """CVEs, passive reverse names, and the date Shodan last saw the host.

    ``vulns`` is unioned from the top level and from every per-service entry, and the
    per-service form is accepted as both a list and a CVE-keyed dict.
    """
    body = {
        "ports": [22, 443],
        "org": "Example Hosting",
        "tags": ["cloud"],
        "hostnames": ["mail.example.invalid", "example.invalid", "mail.example.invalid"],
        "vulns": ["CVE-2021-44228"],
        "last_update": "2025-11-30T04:05:06.789012",
        "data": [
            {"cpe": ["cpe:/a:apache:http_server"], "vulns": {"CVE-2019-0211": {"verified": False}}},
            {"cpe": ["cpe:/a:openbsd:openssh"], "vulns": ["CVE-2021-44228", "CVE-2023-38408"]},
        ],
    }
    async with respx.mock(assert_all_called=True) as router:
        router.get(SHODAN_URL).mock(return_value=httpx.Response(200, json=body))
        result = await shodan_host(client=client, api_key=FAKE_KEY, ip=IP)

    assert result["data"] == {
        "ports": [22, 443],
        "org": "Example Hosting",
        "tags": ["cloud"],
        "cpe": ["cpe:/a:apache:http_server", "cpe:/a:openbsd:openssh"],
        "vulns": ["CVE-2019-0211", "CVE-2021-44228", "CVE-2023-38408"],
        "hostnames": ["example.invalid", "mail.example.invalid"],
        "last_update": "2025-11-30T04:05:06.789012",
    }


async def test_shodan_absent_new_fields_are_empty_not_missing(client: httpx.AsyncClient) -> None:
    """A host record with no vulns, no hostnames and no date still emits all three keys.

    Empty list and ``None`` are the right values here and they are not interchangeable: Shodan
    reporting no CVEs is a (weak) statement about the host, while no ``last_update`` means the
    freshness of everything else in this envelope is unknown.
    """
    async with respx.mock(assert_all_called=True) as router:
        router.get(SHODAN_URL).mock(return_value=httpx.Response(200, json={"ports": [80], "isp": "Example ISP"}))
        result = await shodan_host(client=client, api_key=FAKE_KEY, ip=IP)

    assert result["data"] == {
        "ports": [80],
        "org": "Example ISP",
        "tags": [],
        "cpe": [],
        "vulns": [],
        "hostnames": [],
        "last_update": None,
    }


@pytest.mark.parametrize(
    ("label", "body"),
    [
        ("vulns is null", {"vulns": None, "hostnames": None, "last_update": None}),
        ("vulns is a string", {"vulns": "CVE-2021-44228"}),
        ("hostnames holds non-strings", {"hostnames": [None, 5, "a.example.invalid", "  "]}),
        ("data is not a list", {"data": "denied"}),
        ("data entry is not a dict", {"data": ["denied"]}),
        ("last_update is a number", {"last_update": 1700000000}),
    ],
)
async def test_shodan_wrong_typed_fields_do_not_raise(
    client: httpx.AsyncClient, label: str, body: Dict[str, Any]
) -> None:
    """Every one of these has to come back as a well-formed envelope rather than an exception."""
    async with respx.mock(assert_all_called=True) as router:
        router.get(SHODAN_URL).mock(return_value=httpx.Response(200, json=body))
        result = await shodan_host(client=client, api_key=FAKE_KEY, ip=IP)

    data = result["data"]
    assert result["ok"] is True, label
    assert isinstance(data["vulns"], list), label
    assert isinstance(data["hostnames"], list), label
    assert data["last_update"] is None or isinstance(data["last_update"], str), label


async def test_shodan_vulns_are_sorted_and_deduped(client: httpx.AsyncClient) -> None:
    """Deterministic ordering: the same host record must render the same list on every run."""
    body = {
        "vulns": ["CVE-2023-38408", "CVE-2019-0211"],
        "data": [{"vulns": ["CVE-2019-0211", "CVE-2021-44228"]}],
    }
    async with respx.mock(assert_all_called=True) as router:
        router.get(SHODAN_URL).mock(return_value=httpx.Response(200, json=body))
        result = await shodan_host(client=client, api_key=FAKE_KEY, ip=IP)

    assert result["data"]["vulns"] == ["CVE-2019-0211", "CVE-2021-44228", "CVE-2023-38408"]


async def test_shodan_404_still_reports_not_found(client: httpx.AsyncClient) -> None:
    """No host record is not the same as a host with no vulns. 404 keeps its own envelope."""
    async with respx.mock(assert_all_called=True) as router:
        router.get(SHODAN_URL).mock(return_value=httpx.Response(404, json={"error": "No information available"}))
        result = await shodan_host(client=client, api_key=FAKE_KEY, ip=IP)

    assert result == {"ok": False, "error": "not_found"}


# --------------------------------------------------------------------------------------
# The unconfigured path, across all four providers
# --------------------------------------------------------------------------------------


async def test_missing_api_key_short_circuits_before_any_request(client: httpx.AsyncClient) -> None:
    """No key means no request and no fabricated empty result.

    Asserted here because the new fields make the success envelope larger, and a regression
    that started returning that envelope with everything empty would render as a clean host.
    """
    async with respx.mock(assert_all_called=False) as router:
        router.route(host__in=["www.virustotal.com", "api.abuseipdb.com", "otx.alienvault.com", "api.shodan.io"])

        assert await vt_ip_summary(client=client, api_key=None, ip=IP) == {"ok": False, "error": "missing_api_key"}
        assert await abuseipdb_check(client=client, api_key=None, ip=IP) == {"ok": False, "error": "missing_api_key"}
        assert await shodan_host(client=client, api_key=None, ip=IP) == {"ok": False, "error": "missing_api_key"}
        assert await otx_ip_pulses(client=client, api_key=None, ip=IP) == {
            "ok": False,
            "error": "API key not configured",
        }

        assert len(router.calls) == 0
