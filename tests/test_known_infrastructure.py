"""Tests for the Tier A/B/C override catalogue (roadmap 5.6).

The tests are organised around the failure modes rather than around the API surface, because the
API is small and the failure modes are what actually matter here:

* Tier B must not behave like Tier A. A CDN match caps and annotates; it never concludes benign.
  Every naive version of this feature gets that wrong in one direction or the other and the
  consequence is either "every phishing site on Cloudflare reads clean" or "every CDN address
  reads suspicious".
* Domain-level scoring must be untouched by an address match.
* Precedence must be deterministic where tiers overlap, and they genuinely do overlap --
  ``2606:4700:4700::1111`` is a Tier A resolver inside the Tier B range ``2606:4700::/32``.
* Provenance and staleness must reach the decision, because a stale allowlist that suppresses a
  reassigned range is the worst outcome available and detectability is the only defence.
* The catalogue must refuse to load rather than half-load.

No network access, no fixtures beyond in-line YAML, and the shipped catalogue is asserted against
directly so that an edit to it that breaks an invariant fails here.
"""

from __future__ import annotations

import ipaddress
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from tripper_recon.verdict.known_infrastructure import (
    CATALOGUE_PATH_ENV,
    DEFAULT_CATALOGUE_PATH,
    AsnRange,
    CatalogueError,
    InfraTier,
    KnownInfrastructure,
    catalogue_path,
    clear_cache,
    evaluate_indicator,
    load_catalogue,
)

# The catalogue's own assembly date, so age-sensitive assertions do not rot as the clock moves.
AS_OF = date(2026, 8, 8)


@pytest.fixture(scope="module")
def catalogue() -> KnownInfrastructure:
    return load_catalogue(DEFAULT_CATALOGUE_PATH, use_cache=False)


@pytest.fixture
def raw_document() -> Dict[str, Any]:
    return yaml.safe_load(DEFAULT_CATALOGUE_PATH.read_text(encoding="utf-8"))


def write_catalogue(tmp_path: Path, document: Dict[str, Any]) -> Path:
    path = tmp_path / "known_infrastructure.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def minimal_document(**overrides: Any) -> Dict[str, Any]:
    """A valid two-entry catalogue, for tests that need to break exactly one thing."""
    document: Dict[str, Any] = {
        "version": "test.1",
        "retrieved": date(2026, 8, 1),
        "max_age_days": 180,
        "tiers": {
            "A": {
                "label": "absolute",
                "forces_verdict": "KNOWN_INFRASTRUCTURE",
                "applies_to": ["ip"],
                "note": "absolute",
            },
            "B": {
                "label": "cdn",
                "caps_verdict": "SUSPICIOUS",
                "zeroed_signals": ["asn.reputation"],
                "applies_to": ["ip"],
                "attribution_warning": "shared",
                "note": "cdn",
            },
            "C": {
                "label": "scanner",
                "suppressed_signals": ["abuseipdb.confidence"],
                "applies_to": ["ip"],
                "note": "scanner",
            },
        },
        "entries": [
            {
                "id": "allowlist.test_resolver",
                "tier": "A",
                "name": "Test resolver",
                "operator": "Test",
                "category": "public_resolver",
                "source": "https://example.invalid/resolver",
                "source_type": "publisher_doc",
                "retrieved": date(2026, 8, 1),
                "cidrs": ["192.0.2.53"],
                "asns": [],
            },
            {
                "id": "cdn.test",
                "tier": "B",
                "name": "Test CDN",
                "operator": "Test",
                "category": "cdn",
                "source": "https://example.invalid/cdn",
                "source_type": "publisher_endpoint",
                "retrieved": date(2026, 8, 1),
                "cidrs": ["192.0.2.0/24"],
                "asns": [64500],
            },
        ],
    }
    document.update(overrides)
    return document


# ---------------------------------------------------------------------------------------------
# Tier A -- the only path to a benign verdict
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        "8.8.8.8",
        "8.8.4.4",
        "2001:4860:4860::8888",
        "1.1.1.1",
        "1.0.0.1",
        "1.1.1.3",
        "2606:4700:4700::1111",
        "9.9.9.9",
        "149.112.112.112",
        "2620:fe::fe",
        "208.67.222.222",
        "208.67.220.123",
        "198.41.0.4",  # a.root-servers.net
        "170.247.170.2",  # b.root-servers.net, moved in 2023
        "202.12.27.33",  # m.root-servers.net
        "2001:7fd::1",  # k.root-servers.net
    ],
)
def test_tier_a_addresses_force_known_infrastructure(catalogue: KnownInfrastructure, address: str) -> None:
    """The whole point of Tier A: these never come back as anything but KNOWN_INFRASTRUCTURE."""
    decision = catalogue.evaluate(indicator=address, indicator_type="ip", as_of=AS_OF)
    assert decision.forced_verdict == "KNOWN_INFRASTRUCTURE"
    assert decision.capped_verdict is None
    assert any(match.tier is InfraTier.A for match in decision.matches)


def test_tier_a_is_the_only_tier_that_forces_a_verdict(catalogue: KnownInfrastructure) -> None:
    for tier, policy in catalogue.tiers.items():
        if tier is InfraTier.A:
            assert policy.forces_verdict == "KNOWN_INFRASTRUCTURE"
        else:
            assert policy.forces_verdict is None


def test_tier_a_entries_are_small_and_specific(catalogue: KnownInfrastructure) -> None:
    """An allowlist is a false-negative generator by construction, so it must not contain a
    broad prefix. Anything wider than a /24 or a /48 in Tier A is a bug, not a tuning choice."""
    for entry in catalogue.entries:
        if entry.tier is not InfraTier.A:
            continue
        assert not entry.asns, f"{entry.id} allowlists a whole ASN; Tier A is address-scoped"
        for raw in entry.cidrs:
            network = ipaddress.ip_network(raw, strict=True)
            floor = 24 if network.version == 4 else 48
            assert network.prefixlen >= floor, f"{entry.id} allowlists {raw}, which is too broad for Tier A"


# ---------------------------------------------------------------------------------------------
# Tier B -- cap and annotate, never conclude
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("address", "expected_entry"),
    [
        ("104.16.1.1", "cdn.cloudflare"),
        ("172.64.5.5", "cdn.cloudflare"),
        ("2606:4700:1234::1", "cdn.cloudflare"),
        ("151.101.1.1", "cdn.fastly"),
        ("2a04:4e40::1", "cdn.fastly"),
    ],
)
def test_tier_b_caps_and_never_forces(catalogue: KnownInfrastructure, address: str, expected_entry: str) -> None:
    """A CDN address is capped at SUSPICIOUS and is emphatically not called benign.

    This is the test that stops the phishing-site-on-Cloudflare failure. If ``forced_verdict``
    ever becomes non-None here, every tenant behind that edge reads clean.
    """
    decision = catalogue.evaluate(indicator=address, indicator_type="ip", as_of=AS_OF)
    assert decision.forced_verdict is None
    assert decision.capped_verdict == "SUSPICIOUS"
    assert expected_entry in {match.entry_id for match in decision.matches}
    assert decision.attribution_warning


def test_tier_b_zeroes_only_the_operator_scoped_signals(catalogue: KnownInfrastructure) -> None:
    """ASN reputation and Shodan exposure describe the CDN. VirusTotal and AbuseIPDB describe the
    address and must survive, or a compromised tenant stops scoring at all."""
    decision = catalogue.evaluate(indicator="104.16.1.1", indicator_type="ip", as_of=AS_OF)
    assert set(decision.zeroed_signals) == {"asn.reputation", "asn.bgp_incidents", "shodan.exposure"}
    for signal in ("vt.weighted_detections", "abuseipdb.confidence", "otx.pulse_quality"):
        assert signal not in decision.zeroed_signals
        assert signal not in decision.suppressed_signals


@pytest.mark.parametrize(
    ("asn", "expected_entry"),
    [
        (13335, "cdn.cloudflare"),
        (54113, "cdn.fastly"),
        (16509, "cdn.aws"),
        (14618, "cdn.aws"),
        (15169, "cdn.gcp"),
        (396982, "cdn.gcp"),
        (16625, "cdn.akamai"),
        (20940, "cdn.akamai"),
        (8068, "cdn.azure"),
        (8075, "cdn.azure"),
        (8072, "cdn.azure"),
    ],
)
def test_tier_b_matches_by_asn_when_no_ranges_are_shipped(
    catalogue: KnownInfrastructure, asn: int, expected_entry: str
) -> None:
    """AWS, GCP and Azure ship ASN-only on purpose, so ASN matching is the only thing that
    catches them. An address outside every shipped range still caps via its ASN."""
    decision = catalogue.evaluate(indicator="198.51.100.7", indicator_type="ip", asn=asn, as_of=AS_OF)
    assert expected_entry in {match.entry_id for match in decision.matches}
    assert decision.capped_verdict == "SUSPICIOUS"
    assert decision.forced_verdict is None


def test_asn_outside_every_published_range_does_not_match(catalogue: KnownInfrastructure) -> None:
    """8067 and 8076 sit either side of the Microsoft block. Off-by-one here would cap a
    stranger's network."""
    for asn in (8067, 8076, 13334, 13336):
        decision = catalogue.evaluate(indicator="198.51.100.7", indicator_type="ip", asn=asn, as_of=AS_OF)
        assert decision.matches == []
        assert decision.capped_verdict is None


# ---------------------------------------------------------------------------------------------
# Tier C -- suppress with a note, force nothing
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("address", ["162.142.125.1", "167.94.138.9", "206.168.35.200", "2602:80d:1003::5"])
def test_tier_c_scanner_suppresses_abuse_signals_only(catalogue: KnownInfrastructure, address: str) -> None:
    decision = catalogue.evaluate(indicator=address, indicator_type="ip", as_of=AS_OF)
    assert decision.forced_verdict is None
    assert decision.capped_verdict is None
    assert set(decision.suppressed_signals) == {"abuseipdb.confidence", "abuseipdb.volume_recency"}
    # A scanner range that starts serving malware must still score.
    assert "vt.weighted_detections" not in decision.suppressed_signals
    assert "otx.pulse_quality" not in decision.suppressed_signals


def test_tier_c_crawler_matches_and_composes_with_tier_b(catalogue: KnownInfrastructure) -> None:
    """A bingbot prefix inside Azure gets both: the Tier B cap and the Tier C suppression."""
    decision = catalogue.evaluate(indicator="157.55.39.10", indicator_type="ip", asn=8075, as_of=AS_OF)
    entry_ids = {match.entry_id for match in decision.matches}
    assert {"crawler.bingbot", "cdn.azure"} <= entry_ids
    assert decision.capped_verdict == "SUSPICIOUS"
    assert "abuseipdb.confidence" in decision.suppressed_signals
    assert decision.forced_verdict is None


def test_no_tier_c_entry_can_produce_a_benign_verdict(catalogue: KnownInfrastructure) -> None:
    for tier, policy in catalogue.tiers.items():
        if tier is InfraTier.C:
            assert policy.forces_verdict is None
            assert policy.caps_verdict is None


# ---------------------------------------------------------------------------------------------
# Precedence
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("address", "asn"),
    [
        ("1.1.1.1", 13335),  # Tier A address, Tier B ASN
        ("2606:4700:4700::1111", 13335),  # Tier A address inside the Tier B range 2606:4700::/32
        ("8.8.8.8", 15169),  # Google Public DNS inside Google's own AS
    ],
)
def test_tier_a_outranks_tier_b_on_the_same_indicator(catalogue: KnownInfrastructure, address: str, asn: int) -> None:
    """The overlap is real and deliberate. Tier A wins, the cap is dropped rather than applied,
    and the superseded match stays visible so the conflict is auditable."""
    decision = catalogue.evaluate(indicator=address, indicator_type="ip", asn=asn, as_of=AS_OF)
    assert decision.forced_verdict == "KNOWN_INFRASTRUCTURE"
    assert decision.capped_verdict is None
    assert decision.zeroed_signals == []
    assert decision.suppressed_signals == []
    assert decision.attribution_warning is None

    tiers_matched = {match.tier for match in decision.matches}
    assert InfraTier.A in tiers_matched and InfraTier.B in tiers_matched
    superseded = [match for match in decision.matches if match.tier is InfraTier.B]
    assert superseded and all(not match.effects_applied for match in superseded)
    assert any("outranks" in note for note in decision.notes)


def test_matches_are_ordered_by_tier_then_specificity(catalogue: KnownInfrastructure) -> None:
    decision = catalogue.evaluate(indicator="1.1.1.1", indicator_type="ip", asn=13335, as_of=AS_OF)
    assert [match.tier for match in decision.matches] == sorted(
        [match.tier for match in decision.matches], key=lambda tier: tier.value
    )
    assert decision.matches[0].tier is InfraTier.A


def test_one_entry_matching_twice_is_reported_once(catalogue: KnownInfrastructure) -> None:
    """Cloudflare matches 104.16.1.1 by CIDR and by AS13335. Two matches would double every
    downstream count for no added information."""
    decision = catalogue.evaluate(indicator="104.16.1.1", indicator_type="ip", asn=13335, as_of=AS_OF)
    entry_ids = [match.entry_id for match in decision.matches]
    assert entry_ids.count("cdn.cloudflare") == 1
    # The more specific match wins, so the CIDR is what is reported.
    cloudflare = next(match for match in decision.matches if match.entry_id == "cdn.cloudflare")
    assert cloudflare.matched_on == "cidr"
    assert cloudflare.matched_value == "104.16.0.0/13"


# ---------------------------------------------------------------------------------------------
# Indicator-type scoping -- domain scoring is untouched
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("indicator_type", ["domain", "url", "asn"])
def test_no_effects_are_applied_off_the_ip_path(catalogue: KnownInfrastructure, indicator_type: str) -> None:
    """A phishing domain behind Cloudflare must score exactly as it would anywhere else. This is
    the other half of the Tier B design and it is the half that is easy to lose in a refactor."""
    decision = catalogue.evaluate(
        indicator="phish.example",
        indicator_type=indicator_type,
        ip="104.16.1.1",
        asn=13335,
        as_of=AS_OF,
    )
    assert decision.forced_verdict is None
    assert decision.capped_verdict is None
    assert decision.zeroed_signals == []
    assert decision.suppressed_signals == []
    assert decision.attribution_warning is None
    assert decision.override_records() == []


def test_hosting_context_is_still_reported_off_the_ip_path(catalogue: KnownInfrastructure) -> None:
    """No effect is not the same as no information: the analyst should still see the CDN."""
    decision = catalogue.evaluate(
        indicator="phish.example",
        indicator_type="domain",
        ip="104.16.1.1",
        as_of=AS_OF,
    )
    assert [match.entry_id for match in decision.matches] == ["cdn.cloudflare"]
    assert all(not match.effects_applied for match in decision.matches)
    assert any("context only" in note for note in decision.notes)


def test_tier_a_on_a_domain_does_not_force_a_verdict(catalogue: KnownInfrastructure) -> None:
    """A domain resolving to 8.8.8.8 is not thereby a public resolver."""
    decision = catalogue.evaluate(
        indicator="lookalike.example",
        indicator_type="domain",
        ip="8.8.8.8",
        as_of=AS_OF,
    )
    assert decision.forced_verdict is None
    assert any(match.tier is InfraTier.A for match in decision.matches)


# ---------------------------------------------------------------------------------------------
# The absent-data rule
# ---------------------------------------------------------------------------------------------


def test_an_unmatched_address_produces_nothing(catalogue: KnownInfrastructure) -> None:
    """No match is no information. It must not be expressible as a clean result."""
    decision = catalogue.evaluate(indicator="203.0.113.10", indicator_type="ip", asn=64496, as_of=AS_OF)
    assert decision.is_empty
    assert decision.forced_verdict is None
    assert decision.capped_verdict is None
    assert decision.zeroed_signals == []
    assert decision.suppressed_signals == []
    assert decision.override_records() == []


def test_missing_asn_still_evaluates(catalogue: KnownInfrastructure) -> None:
    """The ASN comes from IPinfo, which needs a token. An unconfigured IPinfo must degrade to
    CIDR-only matching, never to an error and never to a wider match."""
    decision = catalogue.evaluate(indicator="104.16.1.1", indicator_type="ip", asn=None, as_of=AS_OF)
    assert decision.capped_verdict == "SUSPICIOUS"
    assert decision.asn is None


def test_unparseable_address_is_a_note_not_a_crash(catalogue: KnownInfrastructure) -> None:
    """A bulk run over an analyst's paste must not abort on one bad line."""
    decision = catalogue.evaluate(indicator="not-an-address", indicator_type="ip", as_of=AS_OF)
    assert decision.is_empty
    assert decision.forced_verdict is None
    assert any("not matched" in note for note in decision.notes)


def test_match_ip_raises_on_a_bad_address(catalogue: KnownInfrastructure) -> None:
    with pytest.raises(ValueError):
        catalogue.match_ip("999.1.1.1")


# ---------------------------------------------------------------------------------------------
# Provenance and staleness
# ---------------------------------------------------------------------------------------------


def test_every_entry_carries_a_source_and_a_retrieval_date(catalogue: KnownInfrastructure) -> None:
    for entry in catalogue.entries:
        assert entry.source.startswith("http"), f"{entry.id} has no retrievable source"
        assert entry.source_type in {"publisher_endpoint", "publisher_doc", "rir_rdap"}
        assert isinstance(entry.retrieved, date)
        assert entry.retrieved <= catalogue.retrieved


def test_provenance_reaches_the_decision(catalogue: KnownInfrastructure) -> None:
    decision = catalogue.evaluate(indicator="104.16.1.1", indicator_type="ip", as_of=AS_OF)
    match = decision.matches[0]
    assert match.source.startswith("http")
    assert match.source_retrieved == date(2026, 8, 8)
    assert decision.list_version == catalogue.version
    assert decision.list_retrieved == match.source_retrieved


def test_override_records_carry_the_retrieval_date(catalogue: KnownInfrastructure) -> None:
    """A verdict must be able to say which list suppressed what, and how old that list was."""
    decision = catalogue.evaluate(indicator="104.16.1.1", indicator_type="ip", as_of=AS_OF)
    records = decision.override_records()
    assert records
    for record in records:
        assert record["rule_id"] == "cdn.cloudflare"
        assert record["tier"] == "B"
        assert record["source_list"].startswith("http")
        assert record["source_retrieved_at"] == "2026-08-08"
    assert {record["effect"] for record in records} == {"verdict_capped", "signal_zeroed"}


def test_tier_a_override_record_names_the_forced_effect(catalogue: KnownInfrastructure) -> None:
    decision = catalogue.evaluate(indicator="9.9.9.9", indicator_type="ip", as_of=AS_OF)
    records = decision.override_records()
    assert [record["effect"] for record in records] == ["verdict_forced"]
    assert records[0]["tier"] == "A"


def test_staleness_is_flagged_once_the_refresh_age_passes(catalogue: KnownInfrastructure) -> None:
    fresh = catalogue.evaluate(indicator="104.16.1.1", indicator_type="ip", as_of=AS_OF)
    assert fresh.stale is False
    assert "days old" in fresh.staleness_note

    late = AS_OF + timedelta(days=catalogue.max_age_days + 1)
    stale = catalogue.evaluate(indicator="104.16.1.1", indicator_type="ip", as_of=late)
    assert stale.stale is True
    assert "unverified" in stale.staleness_note
    # Staleness never changes the effect. It changes what the analyst is told about it.
    assert stale.capped_verdict == fresh.capped_verdict


def test_staleness_is_reported_even_when_nothing_matched(catalogue: KnownInfrastructure) -> None:
    """An old catalogue is invisible on a miss unless the miss reports the catalogue date."""
    late = AS_OF + timedelta(days=catalogue.max_age_days + 1)
    decision = catalogue.evaluate(indicator="203.0.113.10", indicator_type="ip", as_of=late)
    assert decision.is_empty
    assert decision.stale is True
    assert decision.list_retrieved == catalogue.retrieved


def test_deliberate_omissions_are_documented_with_reasons(catalogue: KnownInfrastructure) -> None:
    """The omissions list is load-bearing: it is what stops a future session re-adding an
    unsourced range because the gap looked like an oversight."""
    assert catalogue.deliberately_omitted
    for item in catalogue.deliberately_omitted:
        assert item.get("what")
        assert item.get("why")


def test_no_accuracy_claim_anywhere_in_the_catalogue() -> None:
    """The engine is a heuristic tuned against fixtures, not a validated classifier. No file in
    this lane may say otherwise."""
    banned = ("accurate", "accuracy", "precision", "recall", "false positive rate")
    for path in (DEFAULT_CATALOGUE_PATH, Path(__file__).parents[1] / "tripper_recon/verdict/known_infrastructure.py"):
        text = path.read_text(encoding="utf-8").lower()
        for term in banned:
            assert term not in text, f"{path.name} makes an accuracy claim: {term!r}"


def test_no_named_virustotal_engine_denylist(catalogue: KnownInfrastructure) -> None:
    """Explicitly out of scope and explicitly refused: no measured basis exists for one."""
    text = DEFAULT_CATALOGUE_PATH.read_text(encoding="utf-8").lower()
    assert "engine_weights" not in text
    for entry in catalogue.entries:
        assert entry.category in {"public_resolver", "root_nameserver", "cdn", "cloud", "scanner", "crawler"}


# ---------------------------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------------------------


def test_decision_serialises_to_json_safe_primitives(catalogue: KnownInfrastructure) -> None:
    """``model_dump()`` output is handed to ``rich.print_json`` elsewhere in the package, which
    cannot serialise a ``date``."""
    import json

    decision = catalogue.evaluate(indicator="104.16.1.1", indicator_type="ip", asn=13335, as_of=AS_OF)
    dumped = decision.model_dump()
    json.dumps(dumped)  # raises TypeError if a date leaked through
    assert dumped["list_retrieved"] == "2026-08-08"
    assert dumped["matches"][0]["source_retrieved"] == "2026-08-08"
    assert dumped["matches"][0]["tier"] == "B"


# ---------------------------------------------------------------------------------------------
# ASN range parsing
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "start", "end"),
    [
        (13335, 13335, 13335),
        ("13335", 13335, 13335),
        ("AS13335", 13335, 13335),
        ("as13335", 13335, 13335),
        ("8068-8075", 8068, 8075),
        ("AS8068-AS8075", 8068, 8075),
    ],
)
def test_asn_range_parsing(value: Any, start: int, end: int) -> None:
    parsed = AsnRange.parse(value)
    assert (parsed.start, parsed.end) == (start, end)
    assert parsed.contains(start) and parsed.contains(end)


@pytest.mark.parametrize("value", ["", "AS", "not-an-asn", "1-", "-1", True, None, 1.5, "10-5"])
def test_asn_range_parsing_refuses_junk(value: Any) -> None:
    with pytest.raises(ValueError):
        AsnRange.parse(value)


# ---------------------------------------------------------------------------------------------
# Loading, validation, and refusing to half-load
# ---------------------------------------------------------------------------------------------


def test_shipped_catalogue_loads_and_is_non_trivial(catalogue: KnownInfrastructure) -> None:
    assert catalogue.version
    assert catalogue.max_age_days > 0
    assert len(catalogue.entries) >= 10
    assert {entry.tier for entry in catalogue.entries} == {InfraTier.A, InfraTier.B, InfraTier.C}


def test_entry_ids_are_unique(catalogue: KnownInfrastructure) -> None:
    ids = [entry.id for entry in catalogue.entries]
    assert len(ids) == len(set(ids))


def test_duplicate_entry_id_is_rejected(tmp_path: Path) -> None:
    document = minimal_document()
    duplicate = dict(document["entries"][0])
    document["entries"].append(duplicate)
    with pytest.raises(CatalogueError, match="duplicate entry id"):
        load_catalogue(write_catalogue(tmp_path, document), use_cache=False)


def test_entry_matching_nothing_is_rejected(tmp_path: Path) -> None:
    """An entry with no ranges and no ASNs is dead config that reads as coverage."""
    document = minimal_document()
    document["entries"][0]["cidrs"] = []
    with pytest.raises(CatalogueError, match="matches nothing"):
        load_catalogue(write_catalogue(tmp_path, document), use_cache=False)


def test_host_bits_in_a_prefix_are_rejected(tmp_path: Path) -> None:
    """``104.16.0.1/13`` is a typo. Masking it off silently would widen a suppression range by
    half a million addresses."""
    document = minimal_document()
    document["entries"][1]["cidrs"] = ["192.0.2.1/24"]
    with pytest.raises(CatalogueError):
        load_catalogue(write_catalogue(tmp_path, document), use_cache=False)


def test_unknown_verdict_label_is_rejected(tmp_path: Path) -> None:
    document = minimal_document()
    document["tiers"]["A"]["forces_verdict"] = "BENIGN"
    with pytest.raises(CatalogueError, match="unknown verdict label"):
        load_catalogue(write_catalogue(tmp_path, document), use_cache=False)


def test_a_non_a_tier_may_not_force_a_verdict(tmp_path: Path) -> None:
    """The single most dangerous edit anyone could make to this file."""
    document = minimal_document()
    document["tiers"]["B"]["forces_verdict"] = "KNOWN_INFRASTRUCTURE"
    with pytest.raises(CatalogueError, match="only tier A may force"):
        load_catalogue(write_catalogue(tmp_path, document), use_cache=False)


def test_a_cap_may_not_be_a_benign_label(tmp_path: Path) -> None:
    document = minimal_document()
    document["tiers"]["B"]["caps_verdict"] = "NO_ADVERSE_FINDINGS"
    with pytest.raises(CatalogueError, match="cap may not be a benign label"):
        load_catalogue(write_catalogue(tmp_path, document), use_cache=False)


def test_tier_a_may_not_also_cap(tmp_path: Path) -> None:
    document = minimal_document()
    document["tiers"]["A"]["caps_verdict"] = "SUSPICIOUS"
    with pytest.raises(CatalogueError, match="must not also set caps_verdict"):
        load_catalogue(write_catalogue(tmp_path, document), use_cache=False)


def test_entry_naming_an_undefined_tier_is_rejected(tmp_path: Path) -> None:
    document = minimal_document()
    del document["tiers"]["C"]
    document["entries"][1]["tier"] = "C"
    with pytest.raises(CatalogueError):
        load_catalogue(write_catalogue(tmp_path, document), use_cache=False)


@pytest.mark.parametrize("key", ["version", "retrieved", "max_age_days"])
def test_missing_header_key_is_rejected(tmp_path: Path, key: str) -> None:
    document = minimal_document()
    del document[key]
    with pytest.raises(CatalogueError, match="missing required key"):
        load_catalogue(write_catalogue(tmp_path, document), use_cache=False)


def test_non_positive_max_age_is_rejected(tmp_path: Path) -> None:
    """Staleness must always be computable; a zero or negative refresh age disables the flag."""
    document = minimal_document(max_age_days=0)
    with pytest.raises(CatalogueError, match="must be positive"):
        load_catalogue(write_catalogue(tmp_path, document), use_cache=False)


def test_missing_file_raises_rather_than_loading_empty(tmp_path: Path) -> None:
    """A silently-empty allowlist is indistinguishable from a working one until it lets a false
    positive through."""
    with pytest.raises(CatalogueError, match="cannot read"):
        load_catalogue(tmp_path / "absent.yaml", use_cache=False)


def test_malformed_yaml_raises(tmp_path: Path) -> None:
    path = tmp_path / "broken.yaml"
    path.write_text("entries: [\n  - id: x\n", encoding="utf-8")
    with pytest.raises(CatalogueError, match="not valid YAML"):
        load_catalogue(path, use_cache=False)


def test_quoted_and_unquoted_dates_both_parse(tmp_path: Path) -> None:
    """PyYAML gives a ``date`` for ``2026-08-08`` and a ``str`` for ``"2026-08-08"``. Both
    spellings occur in a hand-edited file."""
    document = minimal_document()
    document["retrieved"] = "2026-08-01"
    document["entries"][0]["retrieved"] = "2026-08-01"
    loaded = load_catalogue(write_catalogue(tmp_path, document), use_cache=False)
    assert loaded.retrieved == date(2026, 8, 1)
    assert loaded.entries[0].retrieved == date(2026, 8, 1)


# ---------------------------------------------------------------------------------------------
# Path resolution and caching
# ---------------------------------------------------------------------------------------------


def test_catalogue_path_prefers_explicit_then_env_then_package(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(CATALOGUE_PATH_ENV, raising=False)
    assert catalogue_path() == DEFAULT_CATALOGUE_PATH
    assert catalogue_path("/tmp/x.yaml") == Path("/tmp/x.yaml")
    monkeypatch.setenv(CATALOGUE_PATH_ENV, "/tmp/env.yaml")
    assert catalogue_path() == Path("/tmp/env.yaml")
    assert catalogue_path("/tmp/x.yaml") == Path("/tmp/x.yaml")


def test_cache_returns_the_same_object_and_notices_an_edit(tmp_path: Path) -> None:
    clear_cache()
    try:
        path = write_catalogue(tmp_path, minimal_document())
        first = load_catalogue(path)
        assert load_catalogue(path) is first

        edited = minimal_document(version="test.2")
        write_catalogue(tmp_path, edited)
        # Size differs, so the mtime-plus-size key changes even at coarse filesystem timestamps.
        assert load_catalogue(path).version == "test.2"
    finally:
        clear_cache()


def test_evaluate_indicator_wrapper_uses_the_packaged_catalogue(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(CATALOGUE_PATH_ENV, raising=False)
    decision = evaluate_indicator(indicator="1.1.1.1", indicator_type="ip", as_of=AS_OF)
    assert decision.forced_verdict == "KNOWN_INFRASTRUCTURE"


# ---------------------------------------------------------------------------------------------
# Bulk-run cost
# ---------------------------------------------------------------------------------------------


def test_lookup_is_cheap_enough_for_a_bulk_run(catalogue: KnownInfrastructure) -> None:
    """Not a benchmark with a threshold -- a shape check. Lookup cost is bounded by the number of
    distinct prefix lengths in the catalogue, not by the number of prefixes, so a thousand
    addresses must not become a thousand linear scans."""
    addresses: List[str] = [str(ipaddress.IPv4Address(0x68100000 + index)) for index in range(1000)]
    decisions = [catalogue.evaluate(indicator=address, indicator_type="ip", as_of=AS_OF) for address in addresses]
    assert all(decision.capped_verdict == "SUSPICIOUS" for decision in decisions)
    # 104.16.0.0/13 is one dict probe at prefix length 13, whatever else is in the catalogue.
    # Reaching into the index is deliberate: its shape is the property under test, not an
    # implementation detail incidental to it.
    distinct_prefix_lengths = len(catalogue._v4._buckets)
    assert 0 < distinct_prefix_lengths < 32


def test_raw_document_and_loaded_catalogue_agree(raw_document: Dict[str, Any], catalogue: KnownInfrastructure) -> None:
    """Guards against a loader that silently drops entries it cannot parse."""
    assert len(raw_document["entries"]) == len(catalogue.entries)
    assert {entry["id"] for entry in raw_document["entries"]} == {entry.id for entry in catalogue.entries}
