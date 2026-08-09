"""RDAP provider -- roadmap 8.2.

Three things are under test, and the second and third matter more than the first.

**The extraction.** Registration date, registrar, abuse contact, status, nameservers and DNSSEC
are pulled out of responses that follow RFC 9083 loosely, because that is how registries send
them. Every field's *absence* has to read as absence: a domain whose registrar did not publish
an abuse address must not come back with an empty string that renders as "contacted".

**The routing.** RDAP has no single endpoint, so the destination is chosen at runtime from
IANA's bootstrap registries (RFC 9224). The matching rules are longest-suffix for domains,
longest-prefix for addresses and narrowest-range for AS numbers, and getting any of them wrong
sends the query to a registry that will answer 404 for a name that exists -- a false "unknown"
that looks exactly like a real one.

**The passive boundary.** This is the one provider in the package whose destination host is not
a literal in its own source. Four tests below check the consequences directly: a registry host
that is not on the egress allowlist produces an envelope and **no request at all**; a registry
that answers 3xx is reported and **not followed**; only ``data.iana.org`` appears as a URL
literal in the module; and redirect-following is never switched on.

Every request is served by respx. Nothing here opens a socket, and no credential is involved --
RDAP is keyless, which is most of why it is worth having.
"""

from __future__ import annotations

import datetime
import re
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Iterator, List

import httpx
import pytest
import respx

from tripper_recon.providers import rdap as rdap_module
from tripper_recon.providers.rdap import (
    ADVERSE_STATUSES,
    BOOTSTRAP_ASN_URL,
    BOOTSTRAP_DNS_URL,
    BOOTSTRAP_IPV4_URL,
    BOOTSTRAP_IPV6_URL,
    ERROR_BOOTSTRAP_UNAVAILABLE,
    ERROR_INVALID_INDICATOR,
    ERROR_INVALID_REQUEST,
    ERROR_INVALID_RESPONSE,
    ERROR_NO_AUTHORITATIVE_SERVER,
    ERROR_NO_SECURE_URL,
    ERROR_NOT_FOUND,
    ERROR_REGISTRY_NOT_ALLOWLISTED,
    ERROR_UNEXPECTED_REDIRECT,
    IANA_BOOTSTRAP_BASE,
    NEWLY_REGISTERED_DAYS,
    _normalize_status,
    _query_name,
    clear_bootstrap_cache,
    rdap_asn,
    rdap_domain,
    rdap_ip,
)

#: The pretend registry every domain test routes to. ``.invalid`` is reserved by RFC 2606, so
#: this can never become a real destination even if a test escaped its respx mock.
REGISTRY_BASE = "https://rdap.registry.invalid/rdap/"
REGISTRY_HOST = "rdap.registry.invalid"

#: A second registry, used to prove the longest-suffix rule actually picks the longer entry.
DEEP_BASE = "https://rdap.deep.invalid/"
DEEP_HOST = "rdap.deep.invalid"

#: The RIR stand-in for the address and AS-number paths.
RIR_BASE = "https://rdap.rir.invalid/registry/"
RIR_HOST = "rdap.rir.invalid"

#: What the tests pass as the egress allowlist. Production reads ``utils.http`` instead; this is
#: the seam that lets the allowlist behaviour be exercised without touching the real list.
ALLOWED = frozenset({REGISTRY_HOST, DEEP_HOST, RIR_HOST})

#: Fixed clock so every age assertion is exact.
NOW = datetime.datetime(2026, 8, 8, 12, 0, 0, tzinfo=datetime.timezone.utc)
NINE_DAYS_AGO = "2026-07-30T12:00:00Z"
TEN_YEARS_AGO = "2016-08-08T12:00:00Z"


@pytest.fixture(autouse=True)
def _fresh_bootstrap_cache() -> Iterator[None]:
    """The bootstrap cache is module state. Leaking it between tests would hide a fetch."""
    clear_bootstrap_cache()
    yield
    clear_bootstrap_cache()


@pytest.fixture()
async def client() -> AsyncIterator[httpx.AsyncClient]:
    """A plain client. ``create_client`` is not used: transport behaviour is not under test."""
    async with httpx.AsyncClient() as c:
        yield c


# --------------------------------------------------------------------------------------
# Bodies
# --------------------------------------------------------------------------------------


def _dns_bootstrap(**overrides: Any) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "version": "1.0",
        "publication": "2026-07-01T00:00:00Z",
        "services": [
            [["invalid", "test"], [REGISTRY_BASE]],
            [["deep.invalid"], [DEEP_BASE]],
        ],
    }
    body.update(overrides)
    return body


def _ipv4_bootstrap() -> Dict[str, Any]:
    return {
        "version": "1.0",
        "publication": "2026-07-01T00:00:00Z",
        "services": [
            [["203.0.0.0/8"], ["https://rdap.wrong.invalid/"]],
            [["203.0.113.0/24"], [RIR_BASE]],
        ],
    }


def _ipv6_bootstrap() -> Dict[str, Any]:
    return {
        "version": "1.0",
        "publication": "2026-07-01T00:00:00Z",
        "services": [[["2001:db8::/32"], [RIR_BASE]]],
    }


def _asn_bootstrap() -> Dict[str, Any]:
    return {
        "version": "1.0",
        "publication": "2026-07-01T00:00:00Z",
        "services": [
            [["64496-65551"], ["https://rdap.wrong.invalid/"]],
            [["64500-64510"], [RIR_BASE]],
        ],
    }


def _domain_body(**overrides: Any) -> Dict[str, Any]:
    """A domain response with the members a gTLD registry actually sends.

    The abuse entity is NESTED inside the registrar entity, which is the shape RFC 9083's own
    example uses and the shape a flat entity scan misses entirely.
    """
    body: Dict[str, Any] = {
        "objectClassName": "domain",
        "rdapConformance": ["rdap_level_0", "icann_rdap_response_profile_0"],
        "handle": "2026-EXAMPLE",
        "ldhName": "phish-login.invalid",
        "status": ["client transfer prohibited", "clientHold"],
        "events": [
            {"eventAction": "registration", "eventDate": NINE_DAYS_AGO},
            {"eventAction": "expiration", "eventDate": "2027-07-30T12:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2026-08-01T09:30:00Z"},
            {"eventAction": "last update of RDAP database", "eventDate": "2026-08-08T11:00:00Z"},
        ],
        "nameservers": [
            {"objectClassName": "nameserver", "ldhName": "NS1.BULLETPROOF.INVALID"},
            {
                "objectClassName": "nameserver",
                "ldhName": "ns2.bulletproof.invalid",
                "ipAddresses": {"v4": ["203.0.113.9"], "v6": ["2001:db8::9"]},
            },
        ],
        "secureDNS": {"delegationSigned": False},
        "entities": [
            {
                "objectClassName": "entity",
                "handle": "1234",
                "roles": ["registrar"],
                "publicIds": [{"type": "IANA Registrar ID", "identifier": "1234"}],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Cheap Names LLC"],
                        ["email", {}, "text", "info@cheapnames.invalid"],
                    ],
                ],
                "entities": [
                    {
                        "objectClassName": "entity",
                        "handle": "abuse-1234",
                        "roles": ["abuse"],
                        "vcardArray": [
                            "vcard",
                            [
                                ["version", {}, "text", "4.0"],
                                ["fn", {}, "text", "Abuse Desk"],
                                ["email", {}, "text", "abuse@cheapnames.invalid"],
                                ["tel", {"type": ["fax"]}, "uri", "tel:+1-555-0199"],
                                ["tel", {"type": ["voice"]}, "uri", "tel:+1-555-0100"],
                            ],
                        ],
                    }
                ],
            },
            {
                "objectClassName": "entity",
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "REDACTED FOR PRIVACY"],
                        ["org", {}, "text", "Privacy Proxy Ltd"],
                    ],
                ],
            },
        ],
        "notices": [{"title": "Terms of Use"}],
    }
    body.update(overrides)
    return body


def _network_body() -> Dict[str, Any]:
    return {
        "objectClassName": "ip network",
        "handle": "NET-203-0-113-0-1",
        "name": "EXAMPLE-NET",
        "type": "ALLOCATION",
        "startAddress": "203.0.113.0",
        "endAddress": "203.0.113.255",
        "ipVersion": "v4",
        "country": "US",
        "parentHandle": "NET-203-0-0-0-0",
        "cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}],
        "status": ["active"],
        "events": [{"eventAction": "registration", "eventDate": TEN_YEARS_AGO}],
        "entities": [
            {
                "roles": ["abuse"],
                "vcardArray": ["vcard", [["fn", {}, "text", "NOC"], ["email", {}, "text", "abuse@rir.invalid"]]],
            }
        ],
    }


def _autnum_body() -> Dict[str, Any]:
    return {
        "objectClassName": "autnum",
        "handle": "AS64505",
        "name": "EXAMPLE-AS",
        "type": "DIRECT ALLOCATION",
        "startAutnum": 64505,
        "endAutnum": 64505,
        "country": "NL",
        "status": ["active"],
        "events": [{"eventAction": "registration", "eventDate": TEN_YEARS_AGO}],
        "entities": [
            {
                "roles": ["abuse"],
                "vcardArray": ["vcard", [["email", {}, "text", "abuse@as-holder.invalid"]]],
            }
        ],
    }


# --------------------------------------------------------------------------------------
# 1. Domain extraction
# --------------------------------------------------------------------------------------


@respx.mock
async def test_domain_extracts_the_fields_a_triage_turns_on(client: httpx.AsyncClient) -> None:
    """Creation date, age, registrar, IANA ID, abuse contact -- the reason this provider exists."""
    respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))
    respx.get(f"{REGISTRY_BASE}domain/phish-login.invalid").mock(return_value=httpx.Response(200, json=_domain_body()))

    result = await rdap_domain(client=client, domain="phish-login.invalid", allowed_hosts=ALLOWED, now=NOW)

    assert result["ok"] is True
    data = result["data"]
    assert data["rdap_registration_date"] == NINE_DAYS_AGO
    assert data["rdap_age_days"] == pytest.approx(9.0)
    assert data["rdap_is_newly_registered"] is True
    assert data["rdap_newly_registered_threshold_days"] == NEWLY_REGISTERED_DAYS
    assert data["rdap_expiration_date"] == "2027-07-30T12:00:00Z"
    assert data["rdap_last_changed_date"] == "2026-08-01T09:30:00Z"
    assert data["rdap_last_update_of_rdap_db"] == "2026-08-08T11:00:00Z"
    assert data["rdap_registrar_name"] == "Cheap Names LLC"
    assert data["rdap_registrar_iana_id"] == 1234
    assert data["rdap_abuse_email"] == "abuse@cheapnames.invalid"
    assert data["rdap_abuse_contact_source"] == "abuse_role"


@respx.mock
async def test_the_abuse_contact_is_found_nested_inside_the_registrar_entity(client: httpx.AsyncClient) -> None:
    """A flat scan of ``domain.entities`` finds the registrar and no abuse address at all.

    This is the single most common way an RDAP parser silently produces nothing useful, and it
    is invisible against a hand-written flat fixture. The fixture here nests, as the registries
    do.
    """
    respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))
    respx.get(f"{REGISTRY_BASE}domain/phish-login.invalid").mock(return_value=httpx.Response(200, json=_domain_body()))

    data = (await rdap_domain(client=client, domain="phish-login.invalid", allowed_hosts=ALLOWED, now=NOW))["data"]

    top_level_roles = [e.get("roles") for e in _domain_body()["entities"]]
    assert ["abuse"] not in top_level_roles, "fixture regression: the abuse entity must stay nested"
    assert data["rdap_abuse_email"] == "abuse@cheapnames.invalid"
    assert data["rdap_abuse_handle"] == "abuse-1234"


@respx.mock
async def test_the_voice_number_wins_over_the_fax_number(client: httpx.AsyncClient) -> None:
    """An abuse report sent to a fax line is a failed report."""
    respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))
    respx.get(f"{REGISTRY_BASE}domain/phish-login.invalid").mock(return_value=httpx.Response(200, json=_domain_body()))

    data = (await rdap_domain(client=client, domain="phish-login.invalid", allowed_hosts=ALLOWED, now=NOW))["data"]

    assert data["rdap_abuse_phone"] == "+1-555-0100"


@respx.mock
async def test_status_is_normalized_from_both_the_epp_and_the_rdap_spelling(client: httpx.AsyncClient) -> None:
    """RFC 8056 says ``client hold``; registries send ``clientHold``. Both must reach one form.

    Without this, an adverse-status check written against one spelling silently passes a domain
    the registrar has already pulled out of DNS.
    """
    respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))
    respx.get(f"{REGISTRY_BASE}domain/phish-login.invalid").mock(return_value=httpx.Response(200, json=_domain_body()))

    data = (await rdap_domain(client=client, domain="phish-login.invalid", allowed_hosts=ALLOWED, now=NOW))["data"]

    assert data["rdap_status"] == ["client transfer prohibited", "client hold"]
    assert data["rdap_status_raw"] == ["client transfer prohibited", "clientHold"]
    assert data["rdap_adverse_status"] == ["client hold"]
    assert data["rdap_has_adverse_status"] is True


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("clientHold", "client hold"),
        ("client hold", "client hold"),
        ("serverDeleteProhibited", "server delete prohibited"),
        ("pendingDelete", "pending delete"),
        ("  ACTIVE  ", "active"),
        ("redemption_period", "redemption period"),
        ("pending-restore", "pending restore"),
    ],
)
def test_normalize_status_reaches_the_rfc_8056_form(raw: str, expected: str) -> None:
    assert _normalize_status(raw) == expected


def test_every_adverse_status_is_already_in_normal_form() -> None:
    """The set is compared against normalised values, so an entry that is not normal never matches."""
    assert {_normalize_status(value) for value in ADVERSE_STATUSES} == set(ADVERSE_STATUSES)


@respx.mock
async def test_nameservers_and_dnssec_are_carried(client: httpx.AsyncClient) -> None:
    respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))
    respx.get(f"{REGISTRY_BASE}domain/phish-login.invalid").mock(return_value=httpx.Response(200, json=_domain_body()))

    data = (await rdap_domain(client=client, domain="phish-login.invalid", allowed_hosts=ALLOWED, now=NOW))["data"]

    assert data["rdap_nameserver_names"] == ["ns1.bulletproof.invalid", "ns2.bulletproof.invalid"]
    assert data["rdap_nameserver_count"] == 2
    assert data["rdap_nameserver_glue_addresses"] == ["203.0.113.9", "2001:db8::9"]
    assert data["rdap_dnssec_delegation_signed"] is False
    assert data["rdap_dnssec_ds_count"] == 0


@respx.mock
async def test_an_absent_field_reads_as_absent_and_never_as_a_benign_value(client: httpx.AsyncClient) -> None:
    """A registry that sends almost nothing must produce ``None``, not zeros and empty strings.

    ``rdap_is_newly_registered`` is the one that matters: ``False`` would say "this domain is
    old", which is a claim the response did not make.
    """
    respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))
    respx.get(f"{REGISTRY_BASE}domain/sparse.invalid").mock(
        return_value=httpx.Response(200, json={"objectClassName": "domain", "ldhName": "sparse.invalid"})
    )

    data = (await rdap_domain(client=client, domain="sparse.invalid", allowed_hosts=ALLOWED, now=NOW))["data"]

    assert data["rdap_registration_date"] is None
    assert data["rdap_age_days"] is None
    assert data["rdap_is_newly_registered"] is None
    assert data["rdap_registrar_name"] is None
    assert data["rdap_registrar_iana_id"] is None
    assert data["rdap_abuse_email"] is None
    assert data["rdap_abuse_contact_source"] is None
    assert data["rdap_dnssec_delegation_signed"] is None
    assert data["rdap_status"] == []
    assert data["rdap_nameservers"] == []


@respx.mock
async def test_a_hostile_response_shape_does_not_raise(client: httpx.AsyncClient) -> None:
    """Every member replaced with the wrong type. The parser must degrade, not explode."""
    respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))
    respx.get(f"{REGISTRY_BASE}domain/junk.invalid").mock(
        return_value=httpx.Response(
            200,
            json={
                "objectClassName": 7,
                "ldhName": ["junk.invalid"],
                "status": "clientHold",
                "events": {"eventAction": "registration"},
                "entities": ["not-an-entity", {"roles": "registrar", "vcardArray": "vcard"}],
                "nameservers": [None, 3, {"ldhName": ""}],
                "secureDNS": [],
            },
        )
    )

    result = await rdap_domain(client=client, domain="junk.invalid", allowed_hosts=ALLOWED, now=NOW)

    assert result["ok"] is True
    data = result["data"]
    assert data["rdap_ldh_name"] is None
    assert data["rdap_status"] == []
    assert data["rdap_events"] == []
    assert data["rdap_nameservers"] == []
    assert data["rdap_abuse_email"] is None


@respx.mock
async def test_a_future_dated_registration_is_reported_not_floored(client: httpx.AsyncClient) -> None:
    """A negative age is clock skew or a broken record. Flooring it would read as brand new."""
    respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))
    respx.get(f"{REGISTRY_BASE}domain/skewed.invalid").mock(
        return_value=httpx.Response(
            200,
            json={"events": [{"eventAction": "registration", "eventDate": "2026-08-18T12:00:00Z"}]},
        )
    )

    data = (await rdap_domain(client=client, domain="skewed.invalid", allowed_hosts=ALLOWED, now=NOW))["data"]

    assert data["rdap_age_days"] == pytest.approx(-10.0)


@respx.mock
async def test_an_unparseable_registration_date_is_unknown_not_old(client: httpx.AsyncClient) -> None:
    respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))
    respx.get(f"{REGISTRY_BASE}domain/baddate.invalid").mock(
        return_value=httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": "yesterday"}]})
    )

    data = (await rdap_domain(client=client, domain="baddate.invalid", allowed_hosts=ALLOWED, now=NOW))["data"]

    assert data["rdap_registration_date"] == "yesterday"
    assert data["rdap_age_days"] is None
    assert data["rdap_is_newly_registered"] is None


@respx.mock
async def test_the_registrar_address_is_a_labelled_fallback_not_an_abuse_contact(client: httpx.AsyncClient) -> None:
    """A registrar's general queue and its abuse queue are different obligations. Say which."""
    body = _domain_body()
    body["entities"][0]["entities"] = []
    respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))
    respx.get(f"{REGISTRY_BASE}domain/phish-login.invalid").mock(return_value=httpx.Response(200, json=body))

    data = (await rdap_domain(client=client, domain="phish-login.invalid", allowed_hosts=ALLOWED, now=NOW))["data"]

    assert data["rdap_abuse_email"] == "info@cheapnames.invalid"
    assert data["rdap_abuse_contact_source"] == "registrar_entity_fallback"


# --------------------------------------------------------------------------------------
# 2. A 404 is UNKNOWN, never clean
# --------------------------------------------------------------------------------------


@respx.mock
async def test_a_404_is_not_found_and_carries_no_data(client: httpx.AsyncClient) -> None:
    """The registry holds no such object. That is not a registry vouching for the name."""
    respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))
    route = respx.get(f"{REGISTRY_BASE}domain/never-registered.invalid").mock(
        return_value=httpx.Response(404, json={"errorCode": 404, "title": "Domain not found"})
    )

    result = await rdap_domain(client=client, domain="never-registered.invalid", allowed_hosts=ALLOWED, now=NOW)

    assert result == {
        "ok": False,
        "error": ERROR_NOT_FOUND,
        "rdap_server": REGISTRY_BASE,
        "rdap_server_host": REGISTRY_HOST,
        "rdap_query_name": "never-registered.invalid",
    }
    assert "data" not in result
    assert route.call_count == 1, "a 404 must not be retried -- it is permanent for this name"


@respx.mock
async def test_a_subdomain_404_says_which_name_was_actually_queried(client: httpx.AsyncClient) -> None:
    """A registry holds the registrable domain, not every name under it.

    This module does not carry the Public Suffix List and will not guess the boundary, so a
    caller that passes ``login.secure.example.invalid`` gets a 404 the registry genuinely
    returned. The envelope has to say what was asked, or the miss is unreadable.
    """
    respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))
    respx.get(f"{REGISTRY_BASE}domain/login.secure.example.invalid").mock(return_value=httpx.Response(404))

    result = await rdap_domain(client=client, domain="login.secure.example.invalid", allowed_hosts=ALLOWED, now=NOW)

    assert result["error"] == ERROR_NOT_FOUND
    assert result["rdap_query_name"] == "login.secure.example.invalid"


@respx.mock
async def test_a_400_is_a_terminal_invalid_request(client: httpx.AsyncClient) -> None:
    respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))
    route = respx.get(f"{REGISTRY_BASE}domain/weird.invalid").mock(return_value=httpx.Response(400))

    result = await rdap_domain(client=client, domain="weird.invalid", allowed_hosts=ALLOWED, now=NOW)

    assert result["ok"] is False
    assert result["error"] == ERROR_INVALID_REQUEST
    assert route.call_count == 1


@respx.mock
async def test_a_non_json_body_is_invalid_response_not_a_clean_domain(client: httpx.AsyncClient) -> None:
    respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))
    respx.get(f"{REGISTRY_BASE}domain/html.invalid").mock(
        return_value=httpx.Response(200, text="<html>maintenance</html>")
    )

    result = await rdap_domain(client=client, domain="html.invalid", allowed_hosts=ALLOWED, now=NOW)

    assert result["ok"] is False
    assert result["error"] == ERROR_INVALID_RESPONSE


# --------------------------------------------------------------------------------------
# 3. The passive boundary
# --------------------------------------------------------------------------------------


@respx.mock
async def test_an_unlisted_registry_host_produces_an_envelope_and_no_request(client: httpx.AsyncClient) -> None:
    """The destination is dynamic, so the provider checks it before a request is ever built.

    The runtime hook in ``utils/http.py`` is the enforcement and would raise
    ``PassiveBoundaryViolation`` here -- which aborts the run rather than reporting a gap. A
    provider that knows its host comes from a data file owes the caller a clean UNKNOWN instead.
    """
    respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))
    registry = respx.get(url__startswith=REGISTRY_BASE).mock(return_value=httpx.Response(200, json={}))

    result = await rdap_domain(
        client=client,
        domain="phish-login.invalid",
        allowed_hosts=frozenset({"somewhere.else.invalid"}),
        now=NOW,
    )

    assert result["ok"] is False
    assert result["error"] == ERROR_REGISTRY_NOT_ALLOWLISTED
    assert result["rdap_server_host"] == REGISTRY_HOST
    assert registry.call_count == 0, "no request may be built for a host nobody reviewed"


@respx.mock
async def test_a_registry_redirect_is_reported_and_never_followed(client: httpx.AsyncClient) -> None:
    """A redirect names a host chosen at runtime. Following it is the hole the allowlist closes."""
    respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))
    first = respx.get(f"{REGISTRY_BASE}domain/moved.invalid").mock(
        return_value=httpx.Response(302, headers={"Location": "https://registrar.elsewhere.invalid/rdap/domain/moved"})
    )
    onward = respx.get(url__startswith="https://registrar.elsewhere.invalid/").mock(
        return_value=httpx.Response(200, json=_domain_body())
    )

    result = await rdap_domain(client=client, domain="moved.invalid", allowed_hosts=ALLOWED, now=NOW)

    assert result["ok"] is False
    assert result["error"] == ERROR_UNEXPECTED_REDIRECT
    assert result["rdap_redirect_host"] == "registrar.elsewhere.invalid"
    assert first.call_count == 1
    assert onward.call_count == 0, "the redirect target must not be fetched"


def test_the_module_names_exactly_one_egress_host_in_a_url_literal() -> None:
    """Static assertion on the module's own source.

    Every other destination this provider reaches is resolved from IANA's bootstrap file at
    runtime, which is why the runtime allowlist hook -- not the static URL scan in
    ``tests/test_passivity.py`` -- is the control that matters here. The one literal is IANA's,
    and it must stay the only one: a hard-coded registry or aggregator host would be a
    destination reviewed here instead of in the allowlist.
    """
    source = Path(rdap_module.__file__).read_text(encoding="utf-8")
    # The bare ``"https://"`` scheme test used by the bootstrap parser matches nothing here,
    # because a host has to have at least one character.
    literals = {host.lower().rstrip(".") for host in re.findall(r"https?://([A-Za-z0-9.-]+)", source)}

    assert literals == {"data.iana.org"}, f"unexpected URL-literal hosts in providers/rdap.py: {sorted(literals)}"
    assert IANA_BOOTSTRAP_BASE.startswith("https://data.iana.org/")


def test_the_module_never_switches_redirect_following_on() -> None:
    """A behavioural test only proves the paths it exercised. This is about the paths it did not.

    ``docs/OPSEC.md`` section 7 forbids redirect expansion outright and
    ``tests/test_passivity.py`` greps the package for the enabling keyword. Asserted here as
    well because this is the one module with a reason to want it.
    """
    source = Path(rdap_module.__file__).read_text(encoding="utf-8")

    assert "follow_redirects=False" in source
    assert "follow_redirects=True" not in source.replace(" ", "")
    assert ".head(" not in source


def test_the_module_defaults_to_the_real_egress_allowlist() -> None:
    """The ``allowed_hosts`` argument is a test seam. Production must read one list, not a copy."""
    from tripper_recon.utils.http import ALLOWED_EGRESS_HOSTS

    assert rdap_module._allowed(None) is ALLOWED_EGRESS_HOSTS
    assert rdap_module._allowed(ALLOWED) is ALLOWED


# --------------------------------------------------------------------------------------
# 4. Bootstrap routing
# --------------------------------------------------------------------------------------


@respx.mock
async def test_the_longest_suffix_wins(client: httpx.AsyncClient) -> None:
    """``deep.invalid`` beats ``invalid`` for ``a.b.deep.invalid`` (RFC 9224 longest match)."""
    respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))
    shallow = respx.get(url__startswith=REGISTRY_BASE).mock(return_value=httpx.Response(200, json={}))
    deep = respx.get(f"{DEEP_BASE}domain/a.b.deep.invalid").mock(return_value=httpx.Response(200, json=_domain_body()))

    result = await rdap_domain(client=client, domain="a.b.deep.invalid", allowed_hosts=ALLOWED, now=NOW)

    assert result["ok"] is True
    assert result["data"]["rdap_server_host"] == DEEP_HOST
    assert result["data"]["rdap_bootstrap_entry"] == "deep.invalid"
    assert deep.call_count == 1
    assert shallow.call_count == 0


@respx.mock
async def test_a_tld_with_no_service_is_no_authoritative_server(client: httpx.AsyncClient) -> None:
    """Not a 404. Nothing was asked, so nothing may be inferred."""
    respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))

    result = await rdap_domain(client=client, domain="example.nosuchtld", allowed_hosts=ALLOWED, now=NOW)

    assert result["ok"] is False
    assert result["error"] == ERROR_NO_AUTHORITATIVE_SERVER


@respx.mock
async def test_a_cleartext_only_service_is_refused(client: httpx.AsyncClient) -> None:
    """The query path carries the indicator. It never goes out over http."""
    respx.get(BOOTSTRAP_DNS_URL).mock(
        return_value=httpx.Response(
            200,
            json={"version": "1.0", "services": [[["invalid"], ["http://rdap.plain.invalid/"]]]},
        )
    )

    result = await rdap_domain(client=client, domain="thing.invalid", allowed_hosts=ALLOWED, now=NOW)

    assert result["ok"] is False
    # A row whose only URL is cleartext is dropped at parse time, so the file ends up with no
    # usable service rows at all. Either slug is the honest answer; both are UNKNOWN.
    assert result["error"] in {ERROR_NO_SECURE_URL, ERROR_BOOTSTRAP_UNAVAILABLE}


@respx.mock
async def test_a_base_url_without_a_trailing_slash_still_resolves(client: httpx.AsyncClient) -> None:
    """RFC 9082 resolves the path against the base. Registries publish it both ways."""
    respx.get(BOOTSTRAP_DNS_URL).mock(
        return_value=httpx.Response(
            200,
            json={"version": "1.0", "services": [[["invalid"], ["https://rdap.registry.invalid/rdap"]]]},
        )
    )
    route = respx.get(f"{REGISTRY_BASE}domain/thing.invalid").mock(
        return_value=httpx.Response(200, json=_domain_body())
    )

    result = await rdap_domain(client=client, domain="thing.invalid", allowed_hosts=ALLOWED, now=NOW)

    assert result["ok"] is True
    assert route.call_count == 1


@respx.mock
async def test_the_bootstrap_file_is_fetched_once_for_many_lookups(client: httpx.AsyncClient) -> None:
    """A bulk run must not re-download the routing table per indicator."""
    bootstrap = respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))
    respx.get(url__startswith=f"{REGISTRY_BASE}domain/").mock(return_value=httpx.Response(200, json=_domain_body()))

    for name in ("one.invalid", "two.invalid", "three.invalid"):
        assert (await rdap_domain(client=client, domain=name, allowed_hosts=ALLOWED, now=NOW))["ok"] is True

    assert bootstrap.call_count == 1


@respx.mock
async def test_concurrent_lookups_share_one_bootstrap_fetch(client: httpx.AsyncClient) -> None:
    """Without the per-loop lock every concurrent lookup would fetch the same file."""
    import asyncio

    bootstrap = respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))
    respx.get(url__startswith=f"{REGISTRY_BASE}domain/").mock(return_value=httpx.Response(200, json=_domain_body()))

    results = await asyncio.gather(
        *(rdap_domain(client=client, domain=f"host{n}.invalid", allowed_hosts=ALLOWED, now=NOW) for n in range(6))
    )

    assert all(r["ok"] for r in results)
    assert bootstrap.call_count == 1


@respx.mock
async def test_an_unreachable_bootstrap_is_its_own_error(client: httpx.AsyncClient) -> None:
    """An unreachable IANA and a domain with no record are different answers. Keep them apart."""
    respx.get(BOOTSTRAP_DNS_URL).mock(side_effect=httpx.ConnectError("no route"))

    result = await rdap_domain(client=client, domain="thing.invalid", allowed_hosts=ALLOWED, now=NOW)

    assert result["ok"] is False
    assert result["error"] == ERROR_BOOTSTRAP_UNAVAILABLE


@respx.mock
async def test_a_malformed_bootstrap_file_does_not_route_anywhere(client: httpx.AsyncClient) -> None:
    respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json={"version": "1.0"}))

    result = await rdap_domain(client=client, domain="thing.invalid", allowed_hosts=ALLOWED, now=NOW)

    assert result["ok"] is False
    assert result["error"] == ERROR_BOOTSTRAP_UNAVAILABLE


# --------------------------------------------------------------------------------------
# 5. Indicator normalisation
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.INVALID", "example.invalid"),
        ("example.invalid.", "example.invalid"),
        ("a.b.example.invalid", "a.b.example.invalid"),
        ("_dmarc.example.invalid", "_dmarc.example.invalid"),
        ("münchen.invalid", "xn--mnchen-3ya.invalid"),
        ("xn--mnchen-3ya.invalid", "xn--mnchen-3ya.invalid"),
    ],
)
def test_query_name_produces_the_a_label_form(raw: str, expected: str) -> None:
    assert _query_name(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", ".", "invalid", "a..b.invalid", "ex ample.invalid", "a" * 64 + ".invalid"])
def test_query_name_refuses_what_cannot_be_a_domain_query(raw: str) -> None:
    """A bare TLD has no domain object; the rest cannot be encoded. Refusing costs no request."""
    assert _query_name(raw) is None


@respx.mock
async def test_an_unusable_domain_never_reaches_the_network(client: httpx.AsyncClient) -> None:
    bootstrap = respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))

    result = await rdap_domain(client=client, domain="invalid", allowed_hosts=ALLOWED, now=NOW)

    assert result["ok"] is False
    assert result["error"] == ERROR_INVALID_INDICATOR
    assert bootstrap.call_count == 0


@respx.mock
async def test_an_idn_is_queried_in_its_a_label_form(client: httpx.AsyncClient) -> None:
    respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))
    route = respx.get(f"{REGISTRY_BASE}domain/xn--mnchen-3ya.invalid").mock(
        return_value=httpx.Response(200, json=_domain_body())
    )

    result = await rdap_domain(client=client, domain="münchen.invalid", allowed_hosts=ALLOWED, now=NOW)

    assert result["ok"] is True
    assert result["data"]["rdap_query_name"] == "xn--mnchen-3ya.invalid"
    assert route.call_count == 1


# --------------------------------------------------------------------------------------
# 6. IP and AS number
# --------------------------------------------------------------------------------------


@respx.mock
async def test_ip_lookup_uses_the_longest_matching_prefix(client: httpx.AsyncClient) -> None:
    respx.get(BOOTSTRAP_IPV4_URL).mock(return_value=httpx.Response(200, json=_ipv4_bootstrap()))
    wrong = respx.get(url__startswith="https://rdap.wrong.invalid/").mock(return_value=httpx.Response(200, json={}))
    route = respx.get(f"{RIR_BASE}ip/203.0.113.9").mock(return_value=httpx.Response(200, json=_network_body()))

    result = await rdap_ip(client=client, ip="203.0.113.9", allowed_hosts=ALLOWED, now=NOW)

    assert result["ok"] is True
    data = result["data"]
    assert data["rdap_network_handle"] == "NET-203-0-113-0-1"
    assert data["rdap_network_cidr"] == ["203.0.113.0/24"]
    assert data["rdap_network_country"] == "US"
    assert data["rdap_abuse_email"] == "abuse@rir.invalid"
    assert data["rdap_bootstrap_entry"] == "203.0.113.0/24"
    assert route.call_count == 1
    assert wrong.call_count == 0


@respx.mock
async def test_an_ipv6_address_reads_the_ipv6_bootstrap_file(client: httpx.AsyncClient) -> None:
    v4 = respx.get(BOOTSTRAP_IPV4_URL).mock(return_value=httpx.Response(200, json=_ipv4_bootstrap()))
    respx.get(BOOTSTRAP_IPV6_URL).mock(return_value=httpx.Response(200, json=_ipv6_bootstrap()))
    route = respx.get(url__startswith=f"{RIR_BASE}ip/").mock(return_value=httpx.Response(200, json=_network_body()))

    result = await rdap_ip(client=client, ip="2001:db8::1", allowed_hosts=ALLOWED, now=NOW)

    assert result["ok"] is True
    assert route.call_count == 1
    assert v4.call_count == 0


@pytest.mark.parametrize("raw", ["not-an-ip", "", "999.1.1.1"])
@respx.mock
async def test_a_non_address_never_reaches_the_network(client: httpx.AsyncClient, raw: str) -> None:
    bootstrap = respx.get(BOOTSTRAP_IPV4_URL).mock(return_value=httpx.Response(200, json=_ipv4_bootstrap()))

    result = await rdap_ip(client=client, ip=raw, allowed_hosts=ALLOWED, now=NOW)

    assert result["error"] == ERROR_INVALID_INDICATOR
    assert bootstrap.call_count == 0


@respx.mock
async def test_asn_lookup_uses_the_narrowest_matching_range(client: httpx.AsyncClient) -> None:
    respx.get(BOOTSTRAP_ASN_URL).mock(return_value=httpx.Response(200, json=_asn_bootstrap()))
    wrong = respx.get(url__startswith="https://rdap.wrong.invalid/").mock(return_value=httpx.Response(200, json={}))
    route = respx.get(f"{RIR_BASE}autnum/64505").mock(return_value=httpx.Response(200, json=_autnum_body()))

    result = await rdap_asn(client=client, asn=64505, allowed_hosts=ALLOWED, now=NOW)

    assert result["ok"] is True
    data = result["data"]
    assert data["rdap_autnum_handle"] == "AS64505"
    assert data["rdap_autnum_start"] == 64505
    assert data["rdap_autnum_country"] == "NL"
    assert data["rdap_abuse_email"] == "abuse@as-holder.invalid"
    assert data["rdap_bootstrap_entry"] == "64500-64510"
    assert route.call_count == 1
    assert wrong.call_count == 0


@respx.mock
async def test_an_asn_outside_every_range_is_no_authoritative_server(client: httpx.AsyncClient) -> None:
    respx.get(BOOTSTRAP_ASN_URL).mock(return_value=httpx.Response(200, json=_asn_bootstrap()))

    result = await rdap_asn(client=client, asn=4200000000, allowed_hosts=ALLOWED, now=NOW)

    assert result["ok"] is False
    assert result["error"] == ERROR_NO_AUTHORITATIVE_SERVER


@pytest.mark.parametrize("raw", [-1, 4294967296])
@respx.mock
async def test_an_out_of_range_asn_never_reaches_the_network(client: httpx.AsyncClient, raw: int) -> None:
    bootstrap = respx.get(BOOTSTRAP_ASN_URL).mock(return_value=httpx.Response(200, json=_asn_bootstrap()))

    result = await rdap_asn(client=client, asn=raw, allowed_hosts=ALLOWED, now=NOW)

    assert result["error"] == ERROR_INVALID_INDICATOR
    assert bootstrap.call_count == 0


# --------------------------------------------------------------------------------------
# 7. Envelope conformance
# --------------------------------------------------------------------------------------


@respx.mock
async def test_every_failure_is_an_envelope_and_never_an_exception(client: httpx.AsyncClient) -> None:
    """The provider contract: failure returns ``{"ok": False, "error": ...}``.

    Nothing here takes an API key, so ``missing_api_key`` has no analogue -- RDAP is keyless,
    which is what makes it usable when the paid providers are unconfigured.
    """
    respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))
    respx.get(f"{REGISTRY_BASE}domain/gone.invalid").mock(return_value=httpx.Response(404))

    calls: List[Dict[str, Any]] = [
        await rdap_domain(client=client, domain="gone.invalid", allowed_hosts=ALLOWED, now=NOW),
        await rdap_domain(client=client, domain="nope", allowed_hosts=ALLOWED, now=NOW),
        await rdap_domain(client=client, domain="x.nosuchtld", allowed_hosts=ALLOWED, now=NOW),
        await rdap_ip(client=client, ip="junk", allowed_hosts=ALLOWED, now=NOW),
        await rdap_asn(client=client, asn=-5, allowed_hosts=ALLOWED, now=NOW),
    ]

    for result in calls:
        assert result["ok"] is False
        assert isinstance(result["error"], str) and result["error"]
        assert "data" not in result


@respx.mock
async def test_a_success_envelope_carries_its_routing_provenance(client: httpx.AsyncClient) -> None:
    """Which server answered, which bootstrap row chose it, and when that row was published."""
    respx.get(BOOTSTRAP_DNS_URL).mock(return_value=httpx.Response(200, json=_dns_bootstrap()))
    respx.get(f"{REGISTRY_BASE}domain/phish-login.invalid").mock(return_value=httpx.Response(200, json=_domain_body()))

    data = (await rdap_domain(client=client, domain="phish-login.invalid", allowed_hosts=ALLOWED, now=NOW))["data"]

    assert data["rdap_server"] == REGISTRY_BASE
    assert data["rdap_server_host"] == REGISTRY_HOST
    assert data["rdap_bootstrap_entry"] == "invalid"
    assert data["rdap_bootstrap_publication"] == "2026-07-01T00:00:00Z"
