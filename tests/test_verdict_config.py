"""Tests for the verdict ruleset loader (roadmap 5.2).

Most of these are assertions about REFUSAL. A scoring config fails in a particular way: it does
not crash, it quietly changes the answer. A misspelled signal name, a band that overlaps its
neighbour, a decay factor that grows with age, an override rule that depends on a provider nobody
wrote -- every one of those loads fine and produces a verdict that looks exactly like a correct
one. So the tests below are mostly "this config must not load", and each names the wrong verdict
the config would otherwise have produced.

Three groups are load-bearing beyond ordinary validation:

* **The absent-data rule.** ``require_affirmative_negative`` cannot be switched off, a
  score-reachable band cannot be ``KNOWN_INFRASTRUCTURE`` or ``INSUFFICIENT_DATA``, and a domain
  whose age is unknown cannot score the same as a domain that is comfortably old.
* **The shipped defaults.** No VirusTotal engine denylist, no ASN reputation list, no accuracy
  figure. These are absences that a well-meaning later commit will want to fill in, and the tests
  say why they are empty.
* **Dead config.** An enabled override rule that can never fire reads to a maintainer as an
  active control.

No network, no credentials, no provider payloads: this is a file loader and a validator.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping

import pytest
import yaml
from pydantic import ValidationError

from tripper_recon.verdict import config as config_module
from tripper_recon.verdict.config import (
    CONFIG_ENV_VAR,
    PACKAGED_CONFIG_NAME,
    ConfidenceBand,
    IndicatorScope,
    OverrideTier,
    ScoringConfig,
    ScoringConfigError,
    SignalId,
    VerdictLabelName,
    clear_config_cache,
    default_config,
    load_scoring_config,
    resolve_config_source,
)

PACKAGED_PATH = Path(config_module.__file__).with_name(PACKAGED_CONFIG_NAME)

# An environment with nothing in it. Passed explicitly wherever a test resolves a config, so a
# TRIPPER_RECON_SCORING_CONFIG or XDG_CONFIG_HOME set on the developer's machine cannot change
# what the test loads -- the same isolation reasoning as conftest.clear_provider_env.
EMPTY_ENV: Dict[str, str] = {}


@pytest.fixture(autouse=True)
def isolate_config_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Keep the real environment out of every load, including the cached ``default_config``."""
    monkeypatch.delenv(CONFIG_ENV_VAR, raising=False)
    empty_home = tmp_path / "no-user-config"
    empty_home.mkdir()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(empty_home))
    clear_config_cache()
    yield
    clear_config_cache()


def _raw() -> Dict[str, Any]:
    """The packaged ruleset as plain data, for mutation by the rejection tests."""
    loaded = yaml.safe_load(PACKAGED_PATH.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return copy.deepcopy(loaded)


def _write(tmp_path: Path, mutate: Callable[[Dict[str, Any]], None], *, name: str = "scoring.yaml") -> Path:
    """Apply ``mutate`` to a copy of the packaged ruleset and write it to ``tmp_path``."""
    payload = _raw()
    mutate(payload)
    target = tmp_path / name
    target.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return target


def _rejects(tmp_path: Path, mutate: Callable[[Dict[str, Any]], None], fragment: str) -> str:
    """Assert the mutated ruleset fails to load, and that the message explains why."""
    path = _write(tmp_path, mutate)
    with pytest.raises(ScoringConfigError) as excinfo:
        load_scoring_config(path, env=EMPTY_ENV)
    message = str(excinfo.value)
    assert fragment in message, f"expected {fragment!r} in:\n{message}"
    return message


# --------------------------------------------------------------------------------------
# The packaged default must always work with no configuration at all
# --------------------------------------------------------------------------------------


def test_packaged_default_loads_with_no_configuration() -> None:
    """Tier 3 of the precedence chain is the one that must never need setup."""
    cfg = load_scoring_config(env=EMPTY_ENV)
    assert isinstance(cfg, ScoringConfig)
    assert cfg.source_origin == "packaged"
    assert cfg.version
    assert cfg.ruleset_name == "tripper-recon-default"


def test_default_config_is_cached_and_clearable() -> None:
    first = default_config()
    assert default_config() is first
    clear_config_cache()
    assert default_config() is not first


def test_version_is_the_string_stamped_into_every_verdict() -> None:
    """``Verdict.ruleset_version`` comes from here; an empty one makes old verdicts unreadable."""
    assert load_scoring_config(env=EMPTY_ENV).version.strip()


def test_weight_source_names_the_file_and_the_key() -> None:
    cfg = load_scoring_config(env=EMPTY_ENV)
    source = cfg.weight_source(SignalId.VT_WEIGHTED_DETECTIONS)
    assert source.endswith("#signals.vt.weighted_detections")
    assert cfg.source_label in source


def test_config_is_frozen() -> None:
    """A cached, shared ruleset that a caller can mutate changes verdicts already produced."""
    cfg = load_scoring_config(env=EMPTY_ENV)
    with pytest.raises(ValidationError):
        cfg.version = "tampered"  # type: ignore[misc]


# --------------------------------------------------------------------------------------
# Loading precedence
# --------------------------------------------------------------------------------------


def test_explicit_path_beats_the_environment(tmp_path: Path) -> None:
    explicit = _write(tmp_path, lambda raw: raw.update(version="explicit"), name="explicit.yaml")
    from_env = _write(tmp_path, lambda raw: raw.update(version="from-env"), name="env.yaml")
    cfg = load_scoring_config(explicit, env={CONFIG_ENV_VAR: str(from_env)})
    assert cfg.version == "explicit"
    assert cfg.source_origin == "explicit"


def test_environment_beats_the_user_override(tmp_path: Path) -> None:
    from_env = _write(tmp_path, lambda raw: raw.update(version="from-env"), name="env.yaml")
    user_home = tmp_path / "xdg"
    user_dir = user_home / "tripper_recon"
    user_dir.mkdir(parents=True)
    (user_dir / PACKAGED_CONFIG_NAME).write_text(
        yaml.safe_dump({**_raw(), "version": "from-user"}, sort_keys=False), encoding="utf-8"
    )
    cfg = load_scoring_config(env={CONFIG_ENV_VAR: str(from_env), "XDG_CONFIG_HOME": str(user_home)})
    assert cfg.version == "from-env"
    assert cfg.source_origin == "environment"


def test_user_override_beats_the_packaged_default(tmp_path: Path) -> None:
    user_home = tmp_path / "xdg"
    user_dir = user_home / "tripper_recon"
    user_dir.mkdir(parents=True)
    (user_dir / PACKAGED_CONFIG_NAME).write_text(
        yaml.safe_dump({**_raw(), "version": "from-user"}, sort_keys=False), encoding="utf-8"
    )
    cfg = load_scoring_config(env={"XDG_CONFIG_HOME": str(user_home)})
    assert cfg.version == "from-user"
    assert cfg.source_origin == "user"
    assert cfg.source_label.endswith(PACKAGED_CONFIG_NAME)


def test_user_override_falls_back_to_dot_config_when_xdg_is_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    user_dir = tmp_path / ".config" / "tripper_recon"
    user_dir.mkdir(parents=True)
    (user_dir / PACKAGED_CONFIG_NAME).write_text(
        yaml.safe_dump({**_raw(), "version": "dot-config"}, sort_keys=False), encoding="utf-8"
    )
    origin, label, _ = resolve_config_source(env=EMPTY_ENV)
    assert origin == "user"
    assert label == str(user_dir / PACKAGED_CONFIG_NAME)


def test_a_named_path_that_does_not_exist_is_an_error_not_a_fallback(tmp_path: Path) -> None:
    """Falling back would score the indicator under a ruleset the operator did not choose."""
    with pytest.raises(ScoringConfigError, match="not found"):
        load_scoring_config(tmp_path / "absent.yaml", env=EMPTY_ENV)


def test_environment_pointing_at_a_missing_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ScoringConfigError, match=CONFIG_ENV_VAR):
        load_scoring_config(env={CONFIG_ENV_VAR: str(tmp_path / "absent.yaml")})


def test_source_provenance_cannot_be_forged_by_the_file(tmp_path: Path) -> None:
    """Otherwise "you have a stale override" is unfalsifiable when a verdict surprises someone."""
    _rejects(tmp_path, lambda raw: raw.update(source_origin="packaged"), "set by the loader")


# --------------------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------------------


def test_yaml_is_loaded_safely(tmp_path: Path) -> None:
    """A ruleset is data. ``yaml.load`` would let a config file construct Python objects."""
    hostile = tmp_path / "hostile.yaml"
    hostile.write_text("!!python/object/apply:os.system ['true']\n", encoding="utf-8")
    with pytest.raises(ScoringConfigError, match="not valid YAML"):
        load_scoring_config(hostile, env=EMPTY_ENV)


def test_empty_file_is_rejected(tmp_path: Path) -> None:
    empty = tmp_path / "empty.yaml"
    empty.write_text("\n", encoding="utf-8")
    with pytest.raises(ScoringConfigError, match="empty"):
        load_scoring_config(empty, env=EMPTY_ENV)


def test_non_mapping_file_is_rejected(tmp_path: Path) -> None:
    listy = tmp_path / "list.yaml"
    listy.write_text("- one\n- two\n", encoding="utf-8")
    with pytest.raises(ScoringConfigError, match="must be a mapping"):
        load_scoring_config(listy, env=EMPTY_ENV)


def test_missing_pyyaml_reports_the_undeclared_dependency(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """pyyaml is imported here and is not yet in pyproject.toml; the failure must say so."""
    monkeypatch.setattr(config_module, "yaml", None)
    with pytest.raises(ScoringConfigError, match="pyproject.toml"):
        load_scoring_config(env=EMPTY_ENV)


def test_a_typo_in_a_key_is_rejected_rather_than_ignored(tmp_path: Path) -> None:
    """``extra="forbid"`` is the highest-value setting in the loader: a silently-ignored override
    means the operator believes they changed something they did not."""
    _rejects(tmp_path, lambda raw: raw["confidence"].update(coverage_flooor=0.9), "coverage_flooor")


def test_unknown_signal_name_is_rejected_with_the_known_names(tmp_path: Path) -> None:
    def mutate(raw: Dict[str, Any]) -> None:
        raw["signals"]["vt.weighted_detection"] = raw["signals"].pop("vt.weighted_detections")

    message = _rejects(tmp_path, mutate, "unknown signal id")
    assert "vt.weighted_detections" in message  # the list of valid names is in the message


# --------------------------------------------------------------------------------------
# The absent-data rule: config cannot switch it off
# --------------------------------------------------------------------------------------


def test_affirmative_negative_requirement_cannot_be_disabled(tmp_path: Path) -> None:
    """A zero score is not a clean verdict. This is the rule everything else defends."""
    _rejects(
        tmp_path,
        lambda raw: raw["verdict_rules"].update(require_affirmative_negative=False),
        "Absent data never",
    )


@pytest.mark.parametrize("label", ["KNOWN_INFRASTRUCTURE", "INSUFFICIENT_DATA"])
def test_a_score_cannot_reach_known_infrastructure_or_insufficient_data(tmp_path: Path, label: str) -> None:
    """The engine earns its way up to MALICIOUS; it never earns its way down to safe."""
    _rejects(
        tmp_path,
        lambda raw: raw["bands"].__setitem__(2, {"label": label, "min_score": 0}),
        "not score-reachable",
    )


def test_a_domain_of_unknown_age_cannot_score_like_an_old_one(tmp_path: Path) -> None:
    """``unknown_points: 0`` makes "no whois date" identical to "comfortably old", which is the
    clean end of the signal. Absent data, scoring as clean, in the least visible place."""
    _rejects(tmp_path, lambda raw: raw["domain_age"].update(unknown_points=0), "unknown_points")


def test_shipped_default_scores_an_unknown_domain_age_above_zero() -> None:
    cfg = load_scoring_config(env=EMPTY_ENV)
    assert cfg.domain_age.unknown_points > cfg.domain_age.bands[-1].points


def test_undated_evidence_is_not_discounted_as_though_it_were_stale() -> None:
    """A missing timestamp must not discount what a provider actually reported.

    This test previously asserted the opposite -- that an undated observation takes the
    profile's open-ended tail, on the reasoning that treating it as old is the cautious call.
    It is not. Decay multiplies scored signals, every signal in the weight table is
    adverse-capable, and the affirmative negatives carry zero points and are not weighted at
    all. The tail factor therefore has nothing to reduce on the exculpatory side and can only
    ever move an indicator toward clean.

    Measured on the real engine before the fix: an AbuseIPDB payload of 100% confidence, 500
    reports and 40 distinct reporters scored 35 with ``lastReportedAt`` present and 5 with the
    same field absent. Identical provider finding, sevenfold collapse of adverse evidence, from
    one missing metadata field. That is the absent-data rule running backwards, and it produces
    a false negative an analyst acts on.
    """
    cfg = load_scoring_config(env=EMPTY_ENV)
    for profile, bands in cfg.decay_profiles.items():
        tail = bands[-1].factor
        assert cfg.decay_factor(profile, None) == cfg.undated_evidence.factor
        assert cfg.decay_factor(profile, None) > tail, (
            f"profile {profile!r} discounts an undated observation to {cfg.decay_factor(profile, None)}, "
            f"below its own stale tail {tail}. Absent metadata is arguing the indicator clean."
        )
    # Dating evidence still matters: a fresh observation outscores a genuinely old one.
    assert cfg.decay_factor("standard", 0) > cfg.decay_factor("standard", 10_000)


def test_the_shipped_undated_factor_neither_rewards_nor_punishes_a_missing_date() -> None:
    """1.0: the engine declines to guess an age in either direction, and says so instead."""
    cfg = load_scoring_config(env=EMPTY_ENV)
    assert cfg.undated_evidence.factor == 1.0
    assert cfg.undated_evidence.note.strip()


# --------------------------------------------------------------------------------------
# Bands
# --------------------------------------------------------------------------------------


def test_overlapping_bands_are_rejected(tmp_path: Path) -> None:
    _rejects(tmp_path, lambda raw: raw["bands"][1].update(min_score=70), "overlap")


def test_ascending_bands_are_rejected(tmp_path: Path) -> None:
    def mutate(raw: Dict[str, Any]) -> None:
        raw["bands"][0]["min_score"] = 10
        raw["bands"][1]["min_score"] = 50

    _rejects(tmp_path, mutate, "overlap")


def test_a_gap_below_the_lowest_band_is_rejected(tmp_path: Path) -> None:
    """A score with no label is a verdict the engine cannot name."""
    _rejects(tmp_path, lambda raw: raw["bands"][2].update(min_score=5), "clamp_min")


def test_a_top_band_above_the_clamp_is_rejected(tmp_path: Path) -> None:
    _rejects(tmp_path, lambda raw: raw["bands"][0].update(min_score=140), "never be reached")


def test_duplicate_band_labels_are_rejected(tmp_path: Path) -> None:
    _rejects(tmp_path, lambda raw: raw["bands"][1].update(label="MALICIOUS"), "duplicate verdict band")


def test_band_for_score_clamps_and_maps_every_score() -> None:
    cfg = load_scoring_config(env=EMPTY_ENV)
    assert cfg.band_for_score(1000) is VerdictLabelName.MALICIOUS
    assert cfg.band_for_score(cfg.malicious_threshold) is VerdictLabelName.MALICIOUS
    assert cfg.band_for_score(cfg.malicious_threshold - 1) is VerdictLabelName.SUSPICIOUS
    assert cfg.band_for_score(cfg.suspicious_threshold - 1) is VerdictLabelName.NO_ADVERSE_FINDINGS
    assert cfg.band_for_score(-50) is VerdictLabelName.NO_ADVERSE_FINDINGS


# --------------------------------------------------------------------------------------
# Weights that cannot reach a threshold, and weights that reach it alone
# --------------------------------------------------------------------------------------


def test_weights_that_cannot_reach_the_malicious_band_are_rejected(tmp_path: Path) -> None:
    """A band no sum of enabled signals can reach is a verdict the engine can never return."""

    def mutate(raw: Dict[str, Any]) -> None:
        for signal in raw["signals"].values():
            signal["max_points"] = 1

    _rejects(tmp_path, mutate, "below the")


def test_a_single_signal_that_reaches_malicious_alone_is_rejected(tmp_path: Path) -> None:
    """Corroboration is structural: no one provider family may carry a block on its own."""
    _rejects(
        tmp_path,
        lambda raw: raw["signals"]["vt.weighted_detections"].update(max_points=80),
        "alone",
    )


def test_the_corroboration_requirement_can_be_turned_off_deliberately(tmp_path: Path) -> None:
    """It is a loud default, not an unchangeable one -- unlike the absent-data rule."""

    def mutate(raw: Dict[str, Any]) -> None:
        raw["signals"]["vt.weighted_detections"]["max_points"] = 80
        raw["verdict_rules"]["require_corroboration_for_malicious"] = False

    path = _write(tmp_path, mutate)
    assert load_scoring_config(path, env=EMPTY_ENV).signals[SignalId.VT_WEIGHTED_DETECTIONS].max_points == 80


def test_shipped_weights_keep_every_signal_below_the_malicious_threshold() -> None:
    cfg = load_scoring_config(env=EMPTY_ENV)
    heaviest = max(signal.max_points for signal in cfg.signals.values())
    assert heaviest < cfg.malicious_threshold


def test_sub_check_points_cannot_exceed_their_signal_ceiling(tmp_path: Path) -> None:
    _rejects(tmp_path, lambda raw: raw["certificate"].update(points_cn_mismatch=40), "exceeds signals")


# --------------------------------------------------------------------------------------
# Confidence
# --------------------------------------------------------------------------------------


def test_coverage_floor_is_present_and_in_range() -> None:
    """The floor is the input to ``Coverage.is_sufficient``; LOW is forced below it."""
    cfg = load_scoring_config(env=EMPTY_ENV)
    assert 0.0 < cfg.confidence.coverage_floor <= 1.0


def test_a_medium_band_below_the_coverage_floor_is_rejected(tmp_path: Path) -> None:
    """MEDIUM reachable while confidence is forced LOW is two rules disagreeing silently."""
    _rejects(tmp_path, lambda raw: raw["confidence"]["medium"].update(min_coverage=0.2), "coverage floor")


def test_confidence_bands_out_of_order_are_rejected(tmp_path: Path) -> None:
    _rejects(tmp_path, lambda raw: raw["confidence"]["high"].update(min_coverage=0.3), "overlap")


@pytest.mark.parametrize("value", [-0.1, 1.5])
def test_a_coverage_floor_outside_zero_to_one_is_rejected(tmp_path: Path, value: float) -> None:
    _rejects(tmp_path, lambda raw: raw["confidence"].update(coverage_floor=value), "coverage_floor")


# --------------------------------------------------------------------------------------
# Decay
# --------------------------------------------------------------------------------------


def test_a_negative_decay_constant_is_rejected(tmp_path: Path) -> None:
    """A negative multiplier would turn stale adverse evidence into exculpatory evidence."""
    _rejects(tmp_path, lambda raw: raw["decay_profiles"]["standard"][0].update(factor=-0.5), "factor")


def test_a_decay_factor_that_rises_with_age_is_rejected(tmp_path: Path) -> None:
    _rejects(tmp_path, lambda raw: raw["decay_profiles"]["standard"][2].update(factor=0.9), "rises with age")


def test_a_profile_without_an_open_ended_tail_is_rejected(tmp_path: Path) -> None:
    """Otherwise an observation older than the last band has no factor and the caller invents one."""
    _rejects(
        tmp_path,
        lambda raw: raw["decay_profiles"]["standard"][-1].update(max_age_days=3650),
        "open-ended",
    )


def test_non_ascending_decay_ages_are_rejected(tmp_path: Path) -> None:
    _rejects(tmp_path, lambda raw: raw["decay_profiles"]["standard"][0].update(max_age_days=400), "non-ascending")


def test_a_reference_to_an_undefined_decay_profile_is_rejected(tmp_path: Path) -> None:
    _rejects(tmp_path, lambda raw: raw["otx"].update(recency_profile="nonexistent"), "not defined")


def test_decay_factor_selects_the_right_band() -> None:
    cfg = load_scoring_config(env=EMPTY_ENV)
    assert cfg.decay_factor("standard", 10) == 1.0
    assert cfg.decay_factor("standard", 90) == 1.0
    assert cfg.decay_factor("standard", 91) == 0.6
    assert cfg.decay_factor("standard", 5000) == 0.25
    with pytest.raises(ScoringConfigError, match="unknown decay profile"):
        cfg.decay_factor("no-such-profile", 1)


# --------------------------------------------------------------------------------------
# Provider families -- the independence model (5.5)
# --------------------------------------------------------------------------------------


def test_a_provider_in_two_families_is_rejected(tmp_path: Path) -> None:
    """Families are the independence model; a provider in two of them corroborates itself."""
    _rejects(
        tmp_path,
        lambda raw: raw["provider_families"]["exposure"].append("virustotal"),
        "appears in families",
    )


def test_a_signal_drawing_on_a_provider_outside_its_family_is_rejected(tmp_path: Path) -> None:
    _rejects(
        tmp_path,
        lambda raw: raw["signals"]["shodan.exposure"].update(providers=["shodan", "abuseipdb"]),
        "declared family",
    )


def test_a_family_naming_an_unknown_provider_is_rejected(tmp_path: Path) -> None:
    _rejects(tmp_path, lambda raw: raw["provider_families"]["exposure"].append("censys"), "censys")


def test_network_metadata_never_corroborates() -> None:
    """Knowing an address is in AS13335 says where it lives, not what it did."""
    cfg = load_scoring_config(env=EMPTY_ENV)
    assert cfg.counts_toward_corroboration("network_meta") is False
    assert cfg.counts_toward_corroboration("multiscanner") is True
    assert cfg.counts_toward_corroboration("no-such-family") is False


def test_family_lookup_covers_the_orchestrator_provider_names() -> None:
    """The family map is checked against the names the orchestrator actually emits.

    ``provider_status`` is keyed by these strings. A family map using display names instead
    would silently classify every provider as unknown and corroboration would always be zero.
    """
    from tripper_recon.orchestrators import ASN_PROVIDERS, DOMAIN_PROVIDERS, IP_PROVIDERS

    cfg = load_scoring_config(env=EMPTY_ENV)
    unmapped: List[str] = []
    for name in {*IP_PROVIDERS, *DOMAIN_PROVIDERS, *ASN_PROVIDERS}:
        if cfg.family_of(name) is None:
            unmapped.append(name)
    assert not unmapped, f"orchestrator providers with no declared family: {sorted(unmapped)}"


def test_every_known_signal_is_weighted_in_the_shipped_ruleset() -> None:
    """An implemented extractor with no entry in the table contributes nothing, silently."""
    cfg = load_scoring_config(env=EMPTY_ENV)
    assert set(cfg.signals) == set(SignalId)


def test_signals_for_scope_splits_ip_and_domain() -> None:
    cfg = load_scoring_config(env=EMPTY_ENV)
    ip_signals = cfg.signals_for(IndicatorScope.IP)
    domain_signals = cfg.signals_for(IndicatorScope.DOMAIN)
    assert SignalId.ABUSEIPDB_CONFIDENCE in ip_signals
    assert SignalId.ABUSEIPDB_CONFIDENCE not in domain_signals
    assert SignalId.DOMAIN_AGE in domain_signals
    assert SignalId.DOMAIN_AGE not in ip_signals


def test_signals_for_scope_can_include_disabled_signals(tmp_path: Path) -> None:
    path = _write(tmp_path, lambda raw: raw["signals"]["shodan.exposure"].update(enabled=False))
    cfg = load_scoring_config(path, env=EMPTY_ENV)
    assert SignalId.SHODAN_EXPOSURE not in cfg.signals_for(IndicatorScope.IP)
    assert SignalId.SHODAN_EXPOSURE in cfg.signals_for(IndicatorScope.IP, enabled_only=False)


# --------------------------------------------------------------------------------------
# Override tiers (5.6)
# --------------------------------------------------------------------------------------


def test_tier_a_is_the_only_route_to_known_infrastructure(tmp_path: Path) -> None:
    _rejects(tmp_path, lambda raw: raw["overrides"]["tier_a"].update(verdict="NO_ADVERSE_FINDINGS"), "tier_a.verdict")


def test_tier_a_must_short_circuit(tmp_path: Path) -> None:
    _rejects(tmp_path, lambda raw: raw["overrides"]["tier_a"].update(short_circuit=False), "short_circuit")


def test_tier_b_may_not_cap_domain_or_url_scoring(tmp_path: Path) -> None:
    """A phishing kit on Cloudflare Pages must still render red at the domain level."""
    _rejects(
        tmp_path,
        lambda raw: raw["overrides"]["tier_b"].update(scopes_capped=["ip", "domain"]),
        "exculpate the tenant",
    )


def test_tier_b_cannot_force_benign(tmp_path: Path) -> None:
    """It caps and annotates. A cap of NO_ADVERSE_FINDINGS would be a benign-forcing allowlist."""
    cfg = load_scoring_config(env=EMPTY_ENV)
    assert cfg.overrides.tier_b.cap_verdict is VerdictLabelName.SUSPICIOUS
    assert cfg.overrides.tier_b.attribution_warning


def test_tier_b_zero_signals_must_be_known_signals(tmp_path: Path) -> None:
    _rejects(tmp_path, lambda raw: raw["overrides"]["tier_b"].update(zero_signals=["asn.rep"]), "zero_signals")


def test_tier_b_zeroes_the_signals_that_describe_the_edge_not_the_tenant() -> None:
    cfg = load_scoring_config(env=EMPTY_ENV)
    assert set(cfg.overrides.tier_b.zero_signals) == {
        SignalId.ASN_REPUTATION,
        SignalId.ASN_BGP_INCIDENTS,
        SignalId.SHODAN_EXPOSURE,
    }


def test_tier_c_may_only_demote(tmp_path: Path) -> None:
    """A vendor whitelist flag is one opinion and may not short-circuit scoring."""
    _rejects(tmp_path, lambda raw: raw["overrides"]["tier_c"].update(effect="force_verdict"), "may not short-circuit")


def test_an_unparseable_cidr_is_rejected(tmp_path: Path) -> None:
    _rejects(
        tmp_path,
        lambda raw: raw["overrides"]["tier_a"]["rules"][0].update(cidrs=["8.8.8.0/33"]),
        "unusable CIDR",
    )


def test_a_host_bit_cidr_is_rejected(tmp_path: Path) -> None:
    """``strict=True``: ``10.0.0.5/24`` almost always means the author meant something else."""
    _rejects(
        tmp_path,
        lambda raw: raw["overrides"]["tier_a"]["rules"][0].update(cidrs=["8.8.8.5/24"]),
        "unusable CIDR",
    )


def test_public_resolvers_are_allowlisted_by_default() -> None:
    """A tool that returns MALICIOUS for 1.1.1.1 even once stops being believed on everything."""
    cfg = load_scoring_config(env=EMPTY_ENV)
    allowlisted = {cidr for rule in cfg.overrides.tier_a.rules if rule.enabled for cidr in rule.cidrs}
    assert "1.1.1.1/32" in allowlisted
    assert "8.8.8.8/32" in allowlisted
    assert "9.9.9.9/32" in allowlisted


def test_cdn_ranges_ship_empty_and_carry_a_publisher_source() -> None:
    """Hard-coding CDN ranges here would silently suppress a reassigned range with no way to
    notice. The fetcher writes the ranges and the retrieval timestamp together."""
    cfg = load_scoring_config(env=EMPTY_ENV)
    for rule in cfg.overrides.tier_b.rules:
        assert rule.cidrs == [], f"{rule.id} ships with hard-coded ranges"
        assert rule.source.startswith("http")


def test_precedence_must_list_every_tier_once(tmp_path: Path) -> None:
    _rejects(tmp_path, lambda raw: raw["overrides"].update(precedence=["tier_a", "score"]), "exactly once")


def test_precedence_must_start_with_tier_a(tmp_path: Path) -> None:
    _rejects(
        tmp_path,
        lambda raw: raw["overrides"].update(precedence=["escalation", "tier_a", "tier_b", "score"]),
        "must start with tier_a",
    )


def test_precedence_must_end_with_score(tmp_path: Path) -> None:
    _rejects(
        tmp_path,
        lambda raw: raw["overrides"].update(precedence=["tier_a", "escalation", "score", "tier_b"]),
        "must end with 'score'",
    )


def test_shipped_precedence_matches_the_design() -> None:
    cfg = load_scoring_config(env=EMPTY_ENV)
    assert cfg.overrides.precedence == [
        OverrideTier.TIER_A,
        OverrideTier.ESCALATION,
        OverrideTier.TIER_B,
        OverrideTier.SCORE,
    ]


def test_duplicate_override_rule_ids_are_rejected(tmp_path: Path) -> None:
    """Rule ids are recorded in the verdict so the call can be defended; sharing one is unauditable."""
    _rejects(
        tmp_path,
        lambda raw: raw["overrides"]["tier_b"]["rules"][1].update(id="cdn.cloudflare"),
        "duplicate override rule id",
    )


# --------------------------------------------------------------------------------------
# Dead config
# --------------------------------------------------------------------------------------


def test_an_escalation_rule_needing_an_unimplemented_provider_must_be_disabled(tmp_path: Path) -> None:
    """urlhaus and threatfox do not exist in this package. An enabled rule reading them reads to a
    maintainer as an active control and can never fire."""
    _rejects(
        tmp_path,
        lambda raw: raw["overrides"]["escalation"]["rules"][0].update(enabled=True),
        "has not implemented",
    )


def test_the_vt_consensus_rule_must_be_disabled_while_the_engine_list_is_empty(tmp_path: Path) -> None:
    _rejects(
        tmp_path,
        lambda raw: raw["overrides"]["escalation"]["rules"][1].update(enabled=True),
        "inert",
    )


def test_the_vt_consensus_rule_may_be_enabled_once_the_list_is_populated(tmp_path: Path) -> None:
    def mutate(raw: Dict[str, Any]) -> None:
        raw["virustotal"]["high_confidence_engines"] = ["ExampleEngine"]
        raw["overrides"]["escalation"]["rules"][1]["enabled"] = True

    path = _write(tmp_path, mutate)
    cfg = load_scoring_config(path, env=EMPTY_ENV)
    assert cfg.overrides.escalation.rules[1].enabled


def test_escalation_may_only_force_malicious(tmp_path: Path) -> None:
    _rejects(
        tmp_path,
        lambda raw: raw["overrides"]["escalation"]["rules"][2].update(verdict="SUSPICIOUS"),
        "Escalation exists",
    )


def test_escalation_at_low_confidence_is_rejected(tmp_path: Path) -> None:
    """The demotion rule would immediately render it SUSPICIOUS; state the real confidence."""
    _rejects(
        tmp_path,
        lambda raw: raw["overrides"]["escalation"]["rules"][2].update(confidence="LOW"),
        "LOW confidence",
    )


def test_a_tier_c_rule_reading_an_unimplemented_provider_must_be_disabled(tmp_path: Path) -> None:
    _rejects(
        tmp_path,
        lambda raw: raw["overrides"]["tier_c"]["rules"][0].update(provider="urlhaus"),
        "unimplemented provider",
    )


def test_tier_c_rules_name_the_payload_key_the_extractor_reads() -> None:
    """W4.6 landed these fields; the config carries the exact spelling so nobody guesses."""
    cfg = load_scoring_config(env=EMPTY_ENV)
    keys = {rule.payload_key for rule in cfg.overrides.tier_c.rules}
    assert "abuseipdb_is_whitelisted" in keys
    assert "abuseipdb_is_tor" in keys


# --------------------------------------------------------------------------------------
# Contradictions (5.7)
# --------------------------------------------------------------------------------------


def test_contradictions_cap_confidence_below_high(tmp_path: Path) -> None:
    """An unresolved disagreement is precisely the state in which HIGH is unwarranted."""
    cfg = load_scoring_config(env=EMPTY_ENV)
    assert cfg.contradictions.cap_confidence is ConfidenceBand.MEDIUM
    _rejects(tmp_path, lambda raw: raw["contradictions"].update(cap_confidence="HIGH"), "caps nothing")


def test_every_contradiction_rule_carries_an_analyst_hint() -> None:
    """A review flag with no hint is a nag. The hint is what goes in the ticket."""
    cfg = load_scoring_config(env=EMPTY_ENV)
    assert cfg.contradictions.rules
    for rule in cfg.contradictions.rules:
        assert rule.analyst_hint.strip()


def test_an_unknown_contradiction_rule_id_is_rejected(tmp_path: Path) -> None:
    _rejects(tmp_path, lambda raw: raw["contradictions"]["rules"][0].update(id="vt_vs_shodan"), "id")


def test_stale_must_be_older_than_fresh(tmp_path: Path) -> None:
    """Otherwise the rule fires on every indicator and the analyst learns to ignore it."""
    _rejects(
        tmp_path,
        lambda raw: raw["contradictions"]["rules"][1].update(stale_days=10, fresh_days=30),
        "must exceed",
    )


def test_the_four_designed_contradiction_rules_are_present() -> None:
    cfg = load_scoring_config(env=EMPTY_ENV)
    ids = {rule.id.value for rule in cfg.contradictions.rules}
    assert ids == {"vt_vs_abuseipdb", "stale_vs_fresh", "cdn_vs_detection", "age_vs_reputation"}


# --------------------------------------------------------------------------------------
# No accuracy claim, no unsourced lists
# --------------------------------------------------------------------------------------


def test_the_shipped_ruleset_makes_no_accuracy_claim() -> None:
    """No validated corpus exists. "Tuned against N fixtures, not validated on a held-out set" is
    defensible; a precision figure is not."""
    cfg = load_scoring_config(env=EMPTY_ENV)
    assert cfg.calibration.status.value == "unvalidated"
    assert cfg.calibration.precision is None
    assert cfg.calibration.recall is None
    assert cfg.calibration.fixture_count == 0
    assert cfg.calibration.held_out is False


def test_an_accuracy_figure_without_validation_is_rejected(tmp_path: Path) -> None:
    _rejects(tmp_path, lambda raw: raw["calibration"].update(precision=0.97), "status 'unvalidated'")


def test_an_accuracy_figure_without_a_held_out_condition_is_rejected(tmp_path: Path) -> None:
    """A corpus labelled from a feed the engine reads grades the engine on its own answer key."""

    def mutate(raw: Dict[str, Any]) -> None:
        raw["calibration"].update(status="validated", fixture_count=500, precision=0.97, held_out=False)

    _rejects(tmp_path, mutate, "answer key")


def test_no_virustotal_engine_denylist_ships(tmp_path: Path) -> None:
    """Shipping an unsourced list of named vendors as low-quality is both wrong and a liability.
    The mechanism is the deliverable; the table is filled in by measurement."""
    cfg = load_scoring_config(env=EMPTY_ENV)
    assert cfg.virustotal.engine_weights == {}
    assert cfg.virustotal.high_confidence_engines == []
    assert cfg.virustotal.default_engine_weight == 1.0


def test_no_asn_reputation_list_ships() -> None:
    """ASN-level guilt-by-association is where naive scorers manufacture false positives."""
    cfg = load_scoring_config(env=EMPTY_ENV)
    assert cfg.asn.bulletproof_asns == []


def test_negative_engine_weights_are_rejected(tmp_path: Path) -> None:
    """A negative weight would make an engine's detection exculpatory."""
    _rejects(tmp_path, lambda raw: raw["virustotal"].update(engine_weights={"SomeEngine": -1.0}), "negative")


# --------------------------------------------------------------------------------------
# Per-provider block sanity
# --------------------------------------------------------------------------------------


def test_the_abuseipdb_max_age_moved_out_of_the_provider_module() -> None:
    """It was a hard-coded ``maxAgeInDays=365`` query parameter: a scoring parameter in a
    provider-module costume. It decides how much history the confidence score reflects."""
    cfg = load_scoring_config(env=EMPTY_ENV)
    assert cfg.abuseipdb.max_age_days == 365


def test_abuseipdb_split_weights_must_sum_to_one(tmp_path: Path) -> None:
    _rejects(tmp_path, lambda raw: raw["abuseipdb"].update(volume_weight=0.9), "sum to 1.0")


def test_abuseipdb_floor_below_saturation(tmp_path: Path) -> None:
    _rejects(tmp_path, lambda raw: raw["abuseipdb"].update(confidence_floor=90), "must be below")


def test_shodan_ports_must_be_ports(tmp_path: Path) -> None:
    _rejects(tmp_path, lambda raw: raw["shodan"].update(risky_ports=[70000]), "1-65535")


def test_shodan_exposure_is_ceiling_only() -> None:
    """Exposed services describe what a host IS, not whether it is hostile."""
    cfg = load_scoring_config(env=EMPTY_ENV)
    assert cfg.signals[SignalId.SHODAN_EXPOSURE].ceiling_only is True
    assert cfg.verdict_rules.ceiling_only_cap is VerdictLabelName.SUSPICIOUS


def test_a_ceiling_only_cap_of_malicious_is_rejected(tmp_path: Path) -> None:
    _rejects(tmp_path, lambda raw: raw["verdict_rules"].update(ceiling_only_cap="MALICIOUS"), "no-op")


def test_domain_age_never_rewards_being_old(tmp_path: Path) -> None:
    """An old domain is not clean, it is compromise-eligible; it never earns a discount."""
    _rejects(tmp_path, lambda raw: raw["domain_age"]["bands"][3].update(points=12), "older band")


def test_vt_category_terms_are_normalised(tmp_path: Path) -> None:
    """Matching is case-folded; a capitalised term in the file would never match."""
    _rejects(tmp_path, lambda raw: raw["vt_categories"].update(adverse_terms=["Malware"]), "lowercase")


def test_providers_cannot_be_both_implemented_and_planned(tmp_path: Path) -> None:
    _rejects(tmp_path, lambda raw: raw["providers"]["planned"].append("shodan"), "both implemented and planned")


def test_planned_providers_are_the_ones_the_design_names() -> None:
    cfg = load_scoring_config(env=EMPTY_ENV)
    assert {"urlhaus", "threatfox"}.issubset(set(cfg.providers.planned))
    assert "urlhaus" not in cfg.providers.implemented


# --------------------------------------------------------------------------------------
# Packaging
# --------------------------------------------------------------------------------------


def test_the_ruleset_is_not_gitignored() -> None:
    """A blanket ignore rule swallowing this file is exactly the trap that bit the JSON schema in
    roadmap 7.1: the packaged default would be absent from a fresh clone and every install."""
    import subprocess

    repo_root = Path(config_module.__file__).resolve().parents[2]
    relative = PACKAGED_PATH.resolve().relative_to(repo_root)
    result = subprocess.run(
        ["git", "check-ignore", "-q", str(relative)],
        cwd=repo_root,
        capture_output=True,
    )
    assert result.returncode != 0, f"{relative} is gitignored and would never be committed"


def test_the_packaged_ruleset_sits_beside_the_loader() -> None:
    """``importlib.resources`` reads it from the package; it is package data, not a repo file."""
    assert PACKAGED_PATH.is_file()
    assert PACKAGED_PATH.parent.name == "verdict"


def test_resolve_returns_a_readable_label_for_the_packaged_default() -> None:
    origin, label, text = resolve_config_source(env=EMPTY_ENV)
    assert origin == "packaged"
    assert PACKAGED_CONFIG_NAME in label
    assert "version:" in text


def test_module_exports_are_importable_from_the_package() -> None:
    """Other lanes import from ``tripper_recon.verdict``; the names must be there."""
    import tripper_recon.verdict as verdict_pkg

    for name in verdict_pkg.__all__:
        assert hasattr(verdict_pkg, name), name


def test_mapping_input_is_accepted_for_env(tmp_path: Path) -> None:
    """``env`` is typed as a Mapping so a test can pass a plain dict without touching os.environ."""
    env: Mapping[str, str] = {"XDG_CONFIG_HOME": str(tmp_path)}
    assert load_scoring_config(env=env).source_origin == "packaged"
