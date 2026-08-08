"""Tests for :mod:`tripper_recon.verdict.engine` and :mod:`tripper_recon.verdict.models`.

Organised around the rules the engine exists to enforce rather than around its functions. A test
named after a function does not fail loudly enough when the rule underneath it breaks, and the
rules are the reason a verdict is safe to act on:

* ``TestAbsentDataNeverScoresAsClean`` -- rule 1, the one every other rule defends.
* ``TestConfidenceIsASeparateAxis`` -- rule 2: the coverage floor, and the top-band-at-LOW render.
* ``TestNoInventedNumbers`` -- rule 3, checked against the module's own syntax tree.
* ``TestNoAccuracyClaimAndNoVendorDenylist`` -- rules 4 and 5, checked against the source text.
* ``TestProviderFamilyIndependence`` -- roadmap 5.5.
* ``TestContradictions`` -- rule 6, one test per rule id plus the never-cancels-points guarantee.
* ``TestOverrideTiers`` -- roadmap 5.6, against the real shipped catalogue.
* ``TestCollectionModeDisclosure`` -- roadmap 5.10.

Everything runs against the **shipped ruleset and the shipped catalogue**, so a tuning change
that breaks an engine assumption fails here rather than in front of an analyst. Where a test
needs a different number it writes a modified copy of the real ruleset to a temporary file and
loads it, which also proves the value came from config rather than from Python.

``now`` and ``as_of`` are always injected and always fixed. Nothing in the engine may read a
clock, and :meth:`TestPurity.test_the_engine_reads_no_clock_and_no_file` keeps it that way.
"""

from __future__ import annotations

import ast
import datetime as dt
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import pytest
import yaml
from pydantic import ValidationError

from tripper_recon.types.models import Coverage
from tripper_recon.verdict import engine as eng
from tripper_recon.verdict import signals as sig
from tripper_recon.verdict.config import (
    ConfidenceBand,
    ContradictionRuleId,
    IndicatorScope,
    ScoringConfig,
    SignalId,
    default_config,
    load_scoring_config,
)
from tripper_recon.verdict.known_infrastructure import InfraDecision, load_catalogue
from tripper_recon.verdict.models import (
    Confidence,
    Contradiction,
    OverrideApplied,
    Signal,
    SignalDirection,
    Verdict,
    VerdictLabel,
    cap_label,
    demote_label,
    weaken_confidence,
    weakest_confidence,
)

NOW = dt.datetime(2026, 8, 8, 12, 0, 0, tzinfo=dt.timezone.utc)
AS_OF = NOW.date()

#: The provider set the IP path consults. Used to build honest coverage denominators.
PANEL = ["virustotal", "ipinfo", "shodan", "abuseipdb", "otx", "cloudflare_asn"]


@pytest.fixture(scope="module")
def cfg() -> ScoringConfig:
    """The shipped ruleset. Tests assert against what actually ships, not against a mock."""
    return default_config()


@pytest.fixture(scope="module")
def engine_source() -> str:
    return Path(eng.__file__).read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def models_source() -> str:
    from tripper_recon.verdict import models as mod

    return Path(mod.__file__).read_text(encoding="utf-8")


# --------------------------------------------------------------------------------------
# Builders
# --------------------------------------------------------------------------------------


def scored(
    cfg: ScoringConfig,
    signal_id: SignalId,
    provider: str,
    *,
    magnitude: float = 1.0,
    direction: SignalDirection = SignalDirection.ADVERSE,
    observed_at: Optional[str] = None,
    evidence: Optional[Dict[str, Any]] = None,
) -> Signal:
    """One weighted signal, with its ceiling taken from the ruleset rather than invented."""
    wiring = cfg.signals[signal_id]
    return Signal(
        id=signal_id.value,
        provider=provider,
        family=cfg.family_of(provider) or sig.UNKNOWN_FAMILY,
        direction=direction,
        magnitude=magnitude,
        points=round(magnitude * wiring.max_points, 4),
        max_points=wiring.max_points,
        observation=f"test fixture for {signal_id.value}",
        evidence=evidence or {},
        weight_source=cfg.weight_source(signal_id),
        observed_at=observed_at,
        ceiling_only=wiring.ceiling_only,
    )


def observed(
    cfg: ScoringConfig,
    signal_id: str,
    provider: str,
    *,
    direction: SignalDirection = SignalDirection.EXCULPATORY,
    evidence: Optional[Dict[str, Any]] = None,
    observed_at: Optional[str] = None,
) -> Signal:
    """One zero-weight observation: an affirmative negative or a context note."""
    return Signal(
        id=signal_id,
        provider=provider,
        family=cfg.family_of(provider) or sig.UNKNOWN_FAMILY,
        direction=direction,
        magnitude=0.0,
        points=0.0,
        max_points=0.0,
        observation=f"test fixture for {signal_id}",
        evidence=evidence or {},
        weight_source=f"{cfg.source_label}#test",
        observed_at=observed_at,
    )


def coverage(answered: Sequence[str], missing: Sequence[str] = ()) -> Coverage:
    """Answered over applicable, with the missing providers named rather than dropped."""
    return Coverage(answered=list(answered), errored=list(missing))


def full_coverage() -> Coverage:
    return coverage(PANEL)


def half_coverage() -> Coverage:
    """Exactly at the shipped 0.5 floor: three of six."""
    return coverage(PANEL[:3], PANEL[3:])


def thin_coverage() -> Coverage:
    """Below the floor: two of six."""
    return coverage(PANEL[:2], PANEL[2:])


def run(
    cfg: ScoringConfig,
    signals: Sequence[Signal],
    *,
    cov: Optional[Coverage] = None,
    indicator: str = "203.0.113.10",
    scope: IndicatorScope = IndicatorScope.IP,
    infrastructure: Optional[InfraDecision] = None,
    passive_only: bool = True,
    active_collection: Sequence[str] = (),
) -> Verdict:
    return eng.evaluate(
        indicator=indicator,
        scope=scope,
        signals=list(signals),
        coverage=cov if cov is not None else full_coverage(),
        cfg=cfg,
        now=NOW,
        infrastructure=infrastructure,
        passive_only=passive_only,
        active_collection=active_collection,
    )


def iso(days_ago: float) -> str:
    return (NOW - dt.timedelta(days=days_ago)).isoformat()


def malicious_signals(cfg: ScoringConfig, **kwargs: Any) -> List[Signal]:
    """Two families summing to the MALICIOUS band without tripping the escalation rule.

    35 + 25 + 10 = 70, which is the shipped ``bands[0].min_score``. Two decisive families, and
    the multi-family escalation rule needs three, so this exercises the score path rather than
    the override path.
    """
    return [
        scored(cfg, SignalId.VT_WEIGHTED_DETECTIONS, "virustotal", **kwargs),
        scored(cfg, SignalId.ABUSEIPDB_CONFIDENCE, "abuseipdb", **kwargs),
        scored(cfg, SignalId.ABUSEIPDB_VOLUME_RECENCY, "abuseipdb", **kwargs),
    ]


def clean_signals(cfg: ScoringConfig) -> List[Signal]:
    """Three families that were asked and affirmatively reported nothing adverse."""
    return [
        observed(cfg, sig.VT_NO_DETECTIONS, "virustotal"),
        observed(cfg, sig.ABUSE_NO_REPORTS, "abuseipdb"),
        observed(cfg, sig.OTX_NO_PULSES, "otx"),
    ]


def ruleset_with(tmp_path: Path, mutate: Any) -> ScoringConfig:
    """Load a copy of the shipped ruleset with one edit applied.

    Editing the real file and loading it back is deliberate: it proves the value the engine used
    came from the ruleset, which a hand-built config object could not.
    """
    source = Path(sig.__file__).with_name("scoring.yaml")
    document = yaml.safe_load(source.read_text(encoding="utf-8"))
    mutate(document)
    target = tmp_path / "scoring.yaml"
    target.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return load_scoring_config(target)


# --------------------------------------------------------------------------------------
# Rule 1
# --------------------------------------------------------------------------------------


class TestAbsentDataNeverScoresAsClean:
    def test_nothing_answered_is_insufficient_data_not_clean(self, cfg: ScoringConfig) -> None:
        verdict = run(cfg, [], cov=coverage([], PANEL))

        assert verdict.verdict is VerdictLabel.INSUFFICIENT_DATA
        assert verdict.score == 0
        assert verdict.confidence is Confidence.LOW
        assert verdict.coverage.headline == "0 of 6 providers answered"

    def test_no_coverage_at_all_is_insufficient_data(self, cfg: ScoringConfig) -> None:
        """The zero ``Coverage`` -- what ``coverage_or_unknown`` returns when nothing measured."""
        verdict = run(cfg, [], cov=Coverage())

        assert verdict.verdict is VerdictLabel.INSUFFICIENT_DATA

    def test_full_coverage_without_an_affirmative_negative_is_not_clean(self, cfg: ScoringConfig) -> None:
        """Six providers answered, none of them said anything either way. Not a clean result."""
        context_only = [observed(cfg, sig.ASN_IDENTITY, "ipinfo", direction=SignalDirection.CONTEXT)]

        verdict = run(cfg, context_only, cov=full_coverage())

        assert verdict.verdict is VerdictLabel.INSUFFICIENT_DATA
        assert any("affirmative negative" in reason for reason in verdict.adjustment_reasons)

    def test_an_affirmative_negative_with_coverage_earns_no_adverse_findings(self, cfg: ScoringConfig) -> None:
        verdict = run(cfg, clean_signals(cfg), cov=full_coverage())

        assert verdict.verdict is VerdictLabel.NO_ADVERSE_FINDINGS
        assert verdict.score == 0
        assert len(verdict.affirmative_negatives) == 3

    def test_a_clean_panel_below_the_coverage_floor_is_insufficient_data(self, cfg: ScoringConfig) -> None:
        """Two providers said "nothing here" and four never answered. That is a gap, not a clean bill."""
        verdict = run(cfg, clean_signals(cfg)[:2], cov=thin_coverage())

        assert verdict.verdict is VerdictLabel.INSUFFICIENT_DATA
        assert any("coverage floor" in reason for reason in verdict.adjustment_reasons)

    def test_missing_providers_are_named_in_the_rationale(self, cfg: ScoringConfig) -> None:
        verdict = run(cfg, clean_signals(cfg)[:2], cov=thin_coverage())

        gap_lines = [line for line in verdict.rationale if line.startswith("contributed nothing:")]
        assert gap_lines, verdict.rationale
        for name in PANEL[2:]:
            assert name in gap_lines[0]

    def test_adverse_evidence_below_the_band_is_never_labelled_clean(self, cfg: ScoringConfig) -> None:
        """The regression this rule exists for: five VirusTotal detections printing green.

        A weighted 21.9 points does not reach the 35-point SUSPICIOUS band, and the floor band is
        ``NO_ADVERSE_FINDINGS``. Printing that over a live detection is a false sentence -- the
        label is a statement about what the panel reported, and the panel reported something.
        """
        signals = [
            scored(cfg, SignalId.VT_WEIGHTED_DETECTIONS, "virustotal", magnitude=0.625),
            observed(cfg, sig.ABUSE_REPORTS_NO_CONFIDENCE, "abuseipdb", evidence={"reports": 5}),
            observed(cfg, sig.OTX_NO_PULSES, "otx"),
        ]

        verdict = run(cfg, signals, cov=full_coverage())

        assert verdict.score < cfg.suspicious_threshold
        assert verdict.score_band is VerdictLabel.NO_ADVERSE_FINDINGS
        assert verdict.verdict is VerdictLabel.SUSPICIOUS
        assert verdict.adjusted_from is VerdictLabel.NO_ADVERSE_FINDINGS
        assert any("reported something" in reason for reason in verdict.adjustment_reasons)

    def test_the_committed_ip_example_case_is_not_green(self, cfg: ScoringConfig) -> None:
        """End to end over the shape of the repo's own committed example output.

        VirusTotal flags it, AbuseIPDB holds five reports and declines to score them, and half
        the panel has no key. The old renderer printed red and green side by side; the answer is
        SUSPICIOUS with the disagreement named.
        """
        entry = {
            "ip": "185.220.101.5",
            "virustotal": {
                "vt_last_analysis_stats": {"malicious": 5, "suspicious": 0, "harmless": 86},
                "vt_reputation": -37,
                "vt_last_analysis_date": int((NOW - dt.timedelta(days=20)).timestamp()),
            },
            "abuseipdb": {
                "abuseipdb_confidence_score": 0,
                "abuseipdb_reports": 5,
                "abuseipdb_last_reported_at": iso(10),
            },
            "otx": {"otx_pulse_count": 0},
            "provider_status": {
                **{name: {"outcome": "ok"} for name in ("virustotal", "abuseipdb", "otx")},
                **{name: {"outcome": "not_configured"} for name in ("shodan", "ipinfo", "cloudflare_asn")},
            },
        }

        verdict = eng.evaluate_ip_analysis(entry, cfg=cfg, now=NOW)

        assert verdict.verdict is VerdictLabel.SUSPICIOUS
        assert verdict.coverage.headline == "3 of 6 providers answered"
        assert ContradictionRuleId.VT_VS_ABUSEIPDB.value in [item.rule_id for item in verdict.contradictions]
        assert verdict.requires_analyst_review is True

    def test_absent_data_never_lowers_an_adverse_score(self, cfg: ScoringConfig) -> None:
        """Thin coverage discounts the confidence, never the points."""
        wide = run(cfg, malicious_signals(cfg), cov=full_coverage())
        thin = run(cfg, malicious_signals(cfg), cov=thin_coverage())

        assert thin.score == wide.score == 70
        assert thin.raw_score == wide.raw_score

    def test_the_model_refuses_a_clean_verdict_with_no_affirmative_negative(self, cfg: ScoringConfig) -> None:
        """A second line of defence: the rule cannot be routed around by hand-building a Verdict."""
        template = run(cfg, clean_signals(cfg), cov=full_coverage())
        payload = template.model_dump(mode="json")
        payload["signals"] = []

        with pytest.raises(ValidationError, match="affirmative negative"):
            Verdict.model_validate(payload)

    def test_the_model_refuses_a_clean_verdict_below_the_floor(self, cfg: ScoringConfig) -> None:
        template = run(cfg, clean_signals(cfg), cov=full_coverage())
        payload = template.model_dump(mode="json")
        payload["coverage"] = thin_coverage().model_dump(mode="json")

        with pytest.raises(ValidationError, match="below the floor"):
            Verdict.model_validate(payload)

    def test_the_model_refuses_known_infrastructure_without_an_allowlist_record(self, cfg: ScoringConfig) -> None:
        template = run(cfg, clean_signals(cfg), cov=full_coverage())
        payload = template.model_dump(mode="json")
        payload["verdict"] = VerdictLabel.KNOWN_INFRASTRUCTURE.value

        with pytest.raises(ValidationError, match="Tier A override record"):
            Verdict.model_validate(payload)

    def test_the_model_refuses_a_clean_verdict_over_adverse_evidence(self, cfg: ScoringConfig) -> None:
        adverse = run(cfg, [*clean_signals(cfg), scored(cfg, SignalId.VT_COMMUNITY_REPUTATION, "virustotal")])
        payload = adverse.model_dump(mode="json")
        payload["verdict"] = VerdictLabel.NO_ADVERSE_FINDINGS.value

        with pytest.raises(ValidationError, match="carr\\(y\\) adverse points"):
            Verdict.model_validate(payload)


# --------------------------------------------------------------------------------------
# Rule 2
# --------------------------------------------------------------------------------------


class TestConfidenceIsASeparateAxis:
    def test_coverage_below_the_floor_forces_low(self, cfg: ScoringConfig) -> None:
        """Three corroborating families and a decisive signal do not rescue thin coverage."""
        signals = [
            *malicious_signals(cfg),
            scored(cfg, SignalId.OTX_PULSE_QUALITY, "otx"),
        ]

        verdict = run(cfg, signals, cov=thin_coverage())

        assert verdict.coverage.ratio < cfg.confidence.coverage_floor
        assert verdict.confidence is Confidence.LOW
        assert len(verdict.corroborating_families) >= 3

    def test_coverage_exactly_at_the_floor_is_sufficient(self, cfg: ScoringConfig) -> None:
        verdict = run(cfg, malicious_signals(cfg), cov=half_coverage())

        assert verdict.coverage.ratio == cfg.confidence.coverage_floor
        assert verdict.confidence is not Confidence.LOW

    def test_the_floor_comes_from_the_ruleset(self, cfg: ScoringConfig, tmp_path: Path) -> None:
        """Raise the floor in the file and the same inputs fall below it."""

        def raise_floor(document: Dict[str, Any]) -> None:
            document["confidence"]["coverage_floor"] = 0.9
            document["confidence"]["medium"]["min_coverage"] = 0.9
            document["confidence"]["high"]["min_coverage"] = 0.95
            document["version"] = "test-raised-floor"

        strict = ruleset_with(tmp_path, raise_floor)

        assert run(cfg, malicious_signals(cfg), cov=half_coverage()).confidence is not Confidence.LOW
        raised = eng.evaluate(
            indicator="203.0.113.10",
            scope=IndicatorScope.IP,
            signals=malicious_signals(strict),
            coverage=half_coverage(),
            cfg=strict,
            now=NOW,
        )
        assert raised.confidence is Confidence.LOW
        assert raised.coverage_floor == 0.9
        assert raised.ruleset_version == "test-raised-floor"

    def test_malicious_at_low_confidence_renders_as_suspicious_with_the_score_intact(self, cfg: ScoringConfig) -> None:
        """The analyst is told the engine thinks it is bad and cannot stand behind it."""
        verdict = run(cfg, malicious_signals(cfg), cov=thin_coverage())

        assert verdict.score_band is VerdictLabel.MALICIOUS
        assert verdict.verdict is VerdictLabel.SUSPICIOUS
        assert verdict.adjusted_from is VerdictLabel.MALICIOUS
        assert verdict.score == 70
        assert verdict.raw_score == 70.0
        assert verdict.confidence is Confidence.LOW
        assert verdict.requires_analyst_review is True
        assert any("MALICIOUS band at LOW confidence" in reason for reason in verdict.adjustment_reasons)

    def test_high_confidence_needs_coverage_and_two_families(self, cfg: ScoringConfig) -> None:
        verdict = run(cfg, malicious_signals(cfg), cov=coverage(PANEL[:5], PANEL[5:]))

        assert verdict.coverage.ratio >= cfg.confidence.high.min_coverage
        assert verdict.confidence is Confidence.HIGH
        assert verdict.verdict is VerdictLabel.MALICIOUS

    def test_one_family_at_medium_coverage_is_not_high(self, cfg: ScoringConfig) -> None:
        one_family = [scored(cfg, SignalId.VT_WEIGHTED_DETECTIONS, "virustotal")]

        verdict = run(cfg, one_family, cov=half_coverage())

        assert verdict.confidence is Confidence.MEDIUM
        assert verdict.corroborating_families == ["multiscanner"]

    def test_a_fully_answered_clean_panel_is_not_low_confidence(self, cfg: ScoringConfig) -> None:
        """Absence of adverse evidence is not absence of corroboration when everyone answered."""
        verdict = run(cfg, clean_signals(cfg), cov=full_coverage())

        assert verdict.confidence is Confidence.HIGH
        assert set(verdict.corroborating_families) == {"multiscanner", "abuse_reports", "community_ti"}

    def test_confidence_score_is_the_fraction_of_criteria_met(self, cfg: ScoringConfig) -> None:
        verdict = run(cfg, malicious_signals(cfg), cov=full_coverage())

        met = sum(1 for criterion in verdict.confidence_criteria if criterion.met)
        assert verdict.confidence_score == pytest.approx(met / len(verdict.confidence_criteria), abs=1e-4)
        assert {criterion.name for criterion in verdict.confidence_criteria} >= {
            "coverage_floor",
            "coverage_high",
            "corroboration_medium",
            "corroboration_high",
            "decisive_signal",
            "no_unresolved_contradiction",
        }

    def test_confidence_does_not_move_with_the_score(self, cfg: ScoringConfig) -> None:
        """Two verdicts, same panel and same families, very different scores, same confidence."""
        strong = run(cfg, malicious_signals(cfg), cov=full_coverage())
        weak = run(cfg, malicious_signals(cfg, magnitude=0.9), cov=full_coverage())

        assert strong.score != weak.score
        assert strong.confidence is weak.confidence


# --------------------------------------------------------------------------------------
# Roadmap 5.5
# --------------------------------------------------------------------------------------


class TestProviderFamilyIndependence:
    def test_two_providers_in_one_family_corroborate_once(self, cfg: ScoringConfig) -> None:
        """``otx`` and ``otx_domain`` are one family in the shipped ruleset and count once."""
        signals = [
            scored(cfg, SignalId.OTX_PULSE_QUALITY, "otx"),
            scored(cfg, SignalId.OTX_MALWARE_COUNT, "otx_domain"),
        ]

        verdict = run(cfg, signals, cov=full_coverage(), scope=IndicatorScope.DOMAIN)

        assert cfg.family_of("otx") == cfg.family_of("otx_domain") == "community_ti"
        assert verdict.corroborating_families == ["community_ti"]

    def test_two_signals_from_one_provider_corroborate_once(self, cfg: ScoringConfig) -> None:
        signals = [
            scored(cfg, SignalId.VT_WEIGHTED_DETECTIONS, "virustotal"),
            scored(cfg, SignalId.VT_COMMUNITY_REPUTATION, "virustotal"),
        ]

        verdict = run(cfg, signals, cov=full_coverage())

        assert verdict.corroborating_families == ["multiscanner"]

    def test_vt_and_otx_do_not_double_count_when_declared_one_family(self, cfg: ScoringConfig, tmp_path: Path) -> None:
        """The independence model is the ruleset's, not the engine's.

        VirusTotal and OTX re-ingest overlapping public feeds. Whether that makes them one source
        is a judgement recorded in ``provider_families``; the engine's job is to count whatever
        the ruleset declares and never to count providers.
        """

        def merge_families(document: Dict[str, Any]) -> None:
            document["provider_families"]["multiscanner"] = ["virustotal", "otx", "otx_domain"]
            del document["provider_families"]["community_ti"]
            document["signals"]["otx.pulse_quality"]["family"] = "multiscanner"
            document["signals"]["otx.malware_count"]["family"] = "multiscanner"
            document["version"] = "test-merged-families"

        merged = ruleset_with(tmp_path, merge_families)
        signals = [
            scored(merged, SignalId.VT_WEIGHTED_DETECTIONS, "virustotal"),
            scored(merged, SignalId.OTX_PULSE_QUALITY, "otx"),
        ]

        verdict = eng.evaluate(
            indicator="203.0.113.10",
            scope=IndicatorScope.IP,
            signals=signals,
            coverage=full_coverage(),
            cfg=merged,
            now=NOW,
        )

        assert verdict.corroborating_families == ["multiscanner"]
        assert verdict.confidence is not Confidence.HIGH

    def test_network_metadata_never_corroborates(self, cfg: ScoringConfig) -> None:
        """Knowing an address is in AS13335 says where it lives, not what it did."""
        signals = [
            scored(cfg, SignalId.VT_WEIGHTED_DETECTIONS, "virustotal"),
            scored(cfg, SignalId.ASN_REPUTATION, "ipinfo"),
            scored(cfg, SignalId.ASN_BGP_INCIDENTS, "cloudflare_bgp"),
        ]

        verdict = run(cfg, signals, cov=full_coverage())

        assert verdict.corroborating_families == ["multiscanner"]
        assert verdict.confidence is not Confidence.HIGH

    def test_escalation_needs_distinct_families_not_distinct_signals(self, cfg: ScoringConfig) -> None:
        """Three decisive signals from two families do not reach the three-family escalation."""
        two_families = run(cfg, malicious_signals(cfg), cov=full_coverage())
        three_families = run(
            cfg,
            [*malicious_signals(cfg), scored(cfg, SignalId.OTX_PULSE_QUALITY, "otx")],
            cov=full_coverage(),
        )

        assert [override.rule_id for override in two_families.overrides_applied] == []
        assert "escalation.multi_family_corroboration" in [
            override.rule_id for override in three_families.overrides_applied
        ]
        assert three_families.verdict is VerdictLabel.MALICIOUS


# --------------------------------------------------------------------------------------
# Rule 6
# --------------------------------------------------------------------------------------


class TestContradictions:
    def test_vt_vs_abuseipdb(self, cfg: ScoringConfig) -> None:
        """The committed ``ip_example.md`` case: VT flags it, AbuseIPDB declines to."""
        signals = [
            scored(cfg, SignalId.VT_WEIGHTED_DETECTIONS, "virustotal"),
            observed(cfg, sig.ABUSE_REPORTS_NO_CONFIDENCE, "abuseipdb", evidence={"reports": 5}),
        ]

        verdict = run(cfg, signals, cov=full_coverage())

        ids = [item.rule_id for item in verdict.contradictions]
        assert ContradictionRuleId.VT_VS_ABUSEIPDB.value in ids
        assert verdict.requires_analyst_review is True
        assert verdict.verdict is VerdictLabel.SUSPICIOUS

    def test_stale_vs_fresh(self, cfg: ScoringConfig) -> None:
        signals = [
            scored(cfg, SignalId.VT_WEIGHTED_DETECTIONS, "virustotal", observed_at=iso(400)),
            scored(cfg, SignalId.ABUSEIPDB_CONFIDENCE, "abuseipdb", observed_at=iso(5)),
        ]

        verdict = run(cfg, signals, cov=full_coverage())

        found = [item for item in verdict.contradictions if item.rule_id == ContradictionRuleId.STALE_VS_FRESH.value]
        assert found, verdict.contradictions
        assert found[0].left == SignalId.VT_WEIGHTED_DETECTIONS.value
        assert found[0].right == SignalId.ABUSEIPDB_CONFIDENCE.value

    def test_stale_vs_fresh_needs_two_families(self, cfg: ScoringConfig) -> None:
        """One provider reporting both old and recent activity is a history, not a conflict."""
        signals = [
            scored(cfg, SignalId.ABUSEIPDB_CONFIDENCE, "abuseipdb", observed_at=iso(400)),
            scored(cfg, SignalId.ABUSEIPDB_VOLUME_RECENCY, "abuseipdb", observed_at=iso(5)),
        ]

        verdict = run(cfg, signals, cov=full_coverage())

        assert ContradictionRuleId.STALE_VS_FRESH.value not in [item.rule_id for item in verdict.contradictions]

    def test_undated_evidence_does_not_fire_the_staleness_rule(self, cfg: ScoringConfig) -> None:
        verdict = run(cfg, malicious_signals(cfg), cov=full_coverage())

        assert ContradictionRuleId.STALE_VS_FRESH.value not in [item.rule_id for item in verdict.contradictions]

    def test_cdn_vs_detection(self, cfg: ScoringConfig) -> None:
        decision = load_catalogue().evaluate(indicator="104.16.1.1", indicator_type="ip", asn=13335, as_of=AS_OF)

        verdict = run(cfg, malicious_signals(cfg), cov=full_coverage(), infrastructure=decision)

        found = [item for item in verdict.contradictions if item.rule_id == ContradictionRuleId.CDN_VS_DETECTION.value]
        assert found, verdict.contradictions
        assert "cdn.cloudflare" in found[0].right
        assert verdict.attribution_warning is not None

    def test_age_vs_reputation(self, cfg: ScoringConfig) -> None:
        """A domain registered last week with a clean VirusTotal record."""
        signals = [
            scored(cfg, SignalId.DOMAIN_AGE, "virustotal", evidence={"age_days": 4.0}),
            observed(cfg, sig.VT_NO_DETECTIONS, "virustotal"),
        ]

        verdict = run(cfg, signals, cov=full_coverage(), scope=IndicatorScope.DOMAIN)

        found = [item for item in verdict.contradictions if item.rule_id == ContradictionRuleId.AGE_VS_REPUTATION.value]
        assert found, verdict.contradictions
        assert "Too new" in found[0].summary

    def test_an_old_domain_with_a_clean_record_is_not_a_contradiction(self, cfg: ScoringConfig) -> None:
        signals = [
            scored(cfg, SignalId.DOMAIN_AGE, "virustotal", magnitude=0.0, evidence={"age_days": 900.0}),
            observed(cfg, sig.VT_NO_DETECTIONS, "virustotal"),
        ]

        verdict = run(cfg, signals, cov=full_coverage(), scope=IndicatorScope.DOMAIN)

        assert ContradictionRuleId.AGE_VS_REPUTATION.value not in [item.rule_id for item in verdict.contradictions]

    def test_a_contradiction_never_cancels_points(self, cfg: ScoringConfig) -> None:
        """The score keeps its full raw value; the disagreement lands on the other axis."""
        quiet = run(cfg, [scored(cfg, SignalId.VT_WEIGHTED_DETECTIONS, "virustotal")], cov=full_coverage())
        conflicted = run(
            cfg,
            [
                scored(cfg, SignalId.VT_WEIGHTED_DETECTIONS, "virustotal"),
                observed(cfg, sig.ABUSE_REPORTS_NO_CONFIDENCE, "abuseipdb", evidence={"reports": 5}),
            ],
            cov=full_coverage(),
        )

        assert conflicted.score == quiet.score == 35
        assert conflicted.raw_score == quiet.raw_score
        assert conflicted.contradictions and not quiet.contradictions

    def test_a_contradiction_caps_confidence_at_medium(self, cfg: ScoringConfig) -> None:
        base = run(cfg, malicious_signals(cfg), cov=full_coverage())
        conflicted = run(
            cfg,
            [*malicious_signals(cfg), observed(cfg, sig.ABUSE_REPORTS_NO_CONFIDENCE, "abuseipdb")],
            cov=full_coverage(),
        )

        assert base.confidence is Confidence.HIGH
        assert conflicted.confidence is cfg.contradictions.cap_confidence is ConfidenceBand.MEDIUM

    def test_two_material_signals_in_conflict_demote_one_band(self, cfg: ScoringConfig) -> None:
        signals = [
            scored(cfg, SignalId.VT_WEIGHTED_DETECTIONS, "virustotal", observed_at=iso(400)),
            scored(cfg, SignalId.ABUSEIPDB_CONFIDENCE, "abuseipdb", observed_at=iso(5)),
            scored(cfg, SignalId.ABUSEIPDB_VOLUME_RECENCY, "abuseipdb", observed_at=iso(5)),
        ]

        verdict = run(cfg, signals, cov=full_coverage())

        assert verdict.score_band is VerdictLabel.MALICIOUS
        assert verdict.verdict is VerdictLabel.SUSPICIOUS
        assert verdict.adjusted_from is VerdictLabel.MALICIOUS
        assert any(item.both_material for item in verdict.contradictions)

    def test_demotion_can_never_reach_a_clean_verdict(self, cfg: ScoringConfig) -> None:
        """A disagreement is a reason to look harder, never a reason to clear an indicator."""
        signals = [
            scored(cfg, SignalId.VT_WEIGHTED_DETECTIONS, "virustotal", observed_at=iso(400)),
            scored(cfg, SignalId.ABUSEIPDB_CONFIDENCE, "abuseipdb", observed_at=iso(5)),
        ]

        verdict = run(cfg, signals, cov=full_coverage())

        assert verdict.score == 60
        assert verdict.verdict is VerdictLabel.SUSPICIOUS
        assert demote_label(VerdictLabel.SUSPICIOUS, floor=VerdictLabel.SUSPICIOUS) is VerdictLabel.SUSPICIOUS


# --------------------------------------------------------------------------------------
# Roadmap 5.6
# --------------------------------------------------------------------------------------


class TestOverrideTiers:
    def test_tier_a_forces_known_infrastructure_and_short_circuits(self, cfg: ScoringConfig) -> None:
        """A tool that returns MALICIOUS for a public resolver once is never believed again."""
        decision = load_catalogue().evaluate(indicator="8.8.8.8", indicator_type="ip", as_of=AS_OF)

        verdict = run(cfg, malicious_signals(cfg), cov=full_coverage(), infrastructure=decision, indicator="8.8.8.8")

        assert verdict.verdict is VerdictLabel.KNOWN_INFRASTRUCTURE
        assert verdict.score_band is VerdictLabel.MALICIOUS
        assert verdict.forced_by_allowlist is True
        assert verdict.allowlist is not None
        assert verdict.allowlist.list_retrieved == "2026-08-08"

    def test_tier_a_conflict_is_surfaced_not_swallowed(self, cfg: ScoringConfig) -> None:
        decision = load_catalogue().evaluate(indicator="8.8.8.8", indicator_type="ip", as_of=AS_OF)

        verdict = run(cfg, malicious_signals(cfg), cov=full_coverage(), infrastructure=decision, indicator="8.8.8.8")

        ids = [item.rule_id for item in verdict.contradictions]
        assert eng.ALLOWLIST_CONFLICT_RULE_ID in ids
        assert verdict.requires_analyst_review is True

    def test_tier_a_with_no_adverse_evidence_raises_no_conflict(self, cfg: ScoringConfig) -> None:
        decision = load_catalogue().evaluate(indicator="8.8.8.8", indicator_type="ip", as_of=AS_OF)

        verdict = run(cfg, clean_signals(cfg), cov=full_coverage(), infrastructure=decision, indicator="8.8.8.8")

        assert verdict.verdict is VerdictLabel.KNOWN_INFRASTRUCTURE
        assert verdict.contradictions == []

    def test_tier_b_caps_at_suspicious_and_zeroes_operator_signals(self, cfg: ScoringConfig) -> None:
        decision = load_catalogue().evaluate(indicator="104.16.1.1", indicator_type="ip", asn=13335, as_of=AS_OF)
        signals = [
            *malicious_signals(cfg),
            scored(cfg, SignalId.SHODAN_EXPOSURE, "shodan", direction=SignalDirection.CONTEXT),
            scored(cfg, SignalId.ASN_REPUTATION, "ipinfo"),
        ]

        verdict = run(cfg, signals, cov=full_coverage(), infrastructure=decision, indicator="104.16.1.1")

        assert verdict.verdict is VerdictLabel.SUSPICIOUS
        assert verdict.score == 70, "the operator's own signals were zeroed, the tenant's were not"
        zeroed = {item.id for item in verdict.signals if item.evidence.get("zeroed_by_known_infrastructure")}
        assert zeroed == {SignalId.SHODAN_EXPOSURE.value, SignalId.ASN_REPUTATION.value}
        assert "signal_zeroed" in {item.effect for item in verdict.overrides_applied}

    def test_tier_b_keeps_the_zeroed_signal_visible(self, cfg: ScoringConfig) -> None:
        """The analyst needs to see that Shodan found the port *and* that it was not counted."""
        decision = load_catalogue().evaluate(indicator="104.16.1.1", indicator_type="ip", asn=13335, as_of=AS_OF)
        exposure = scored(cfg, SignalId.SHODAN_EXPOSURE, "shodan", direction=SignalDirection.CONTEXT)

        verdict = run(cfg, [exposure], cov=full_coverage(), infrastructure=decision, indicator="104.16.1.1")

        kept = [item for item in verdict.signals if item.id == SignalId.SHODAN_EXPOSURE.value]
        assert len(kept) == 1
        assert kept[0].points == 0.0
        assert kept[0].evidence["points_before_override"] == exposure.points

    def test_tier_b_never_forces_benign(self, cfg: ScoringConfig) -> None:
        decision = load_catalogue().evaluate(indicator="104.16.1.1", indicator_type="ip", asn=13335, as_of=AS_OF)

        assert decision.forced_verdict is None
        verdict = run(cfg, malicious_signals(cfg), cov=full_coverage(), infrastructure=decision)
        assert verdict.verdict is not VerdictLabel.NO_ADVERSE_FINDINGS
        assert verdict.verdict is not VerdictLabel.KNOWN_INFRASTRUCTURE

    def test_tier_b_does_not_touch_a_domain_verdict(self, cfg: ScoringConfig) -> None:
        """A phishing kit on a CDN is a malicious domain on a shared address. Both are true."""
        decision = load_catalogue().evaluate(indicator="evil.example", indicator_type="domain", asn=13335, as_of=AS_OF)

        assert decision.capped_verdict is None
        assert decision.zeroed_signals == []

    def test_catalogue_tier_c_suppresses_the_abuse_signals(self, cfg: ScoringConfig) -> None:
        """A declared scanner attracts abuse reports as a property of scanning."""
        decision = load_catalogue().evaluate(indicator="162.142.125.1", indicator_type="ip", as_of=AS_OF)
        signals = [
            scored(cfg, SignalId.VT_WEIGHTED_DETECTIONS, "virustotal"),
            scored(cfg, SignalId.ABUSEIPDB_CONFIDENCE, "abuseipdb"),
        ]

        verdict = run(cfg, signals, cov=full_coverage(), infrastructure=decision, indicator="162.142.125.1")

        assert SignalId.ABUSEIPDB_CONFIDENCE.value in decision.suppressed_signals
        assert verdict.score == 35
        assert "signal_suppressed" in {item.effect for item in verdict.overrides_applied}

    def test_ruleset_tier_c_demotes_confidence(self, cfg: ScoringConfig) -> None:
        """A vendor's whitelist flag is one opinion: it lowers confidence, it clears nothing."""
        base = run(cfg, malicious_signals(cfg), cov=full_coverage())
        flagged = run(
            cfg,
            [*malicious_signals(cfg), observed(cfg, sig.ABUSE_WHITELISTED, "abuseipdb")],
            cov=full_coverage(),
        )

        assert base.confidence is Confidence.HIGH
        assert flagged.confidence is Confidence.MEDIUM
        assert flagged.verdict is VerdictLabel.MALICIOUS
        assert "vendor.abuseipdb_whitelisted" in {item.rule_id for item in flagged.overrides_applied}

    def test_every_enabled_tier_c_rule_is_wired(self, cfg: ScoringConfig) -> None:
        """A ruleset rule with no signal behind it is dead config wearing an active costume."""
        for rule in cfg.overrides.tier_c.rules:
            if rule.enabled:
                assert rule.payload_key in eng.TIER_C_SIGNAL_FOR_PAYLOAD_KEY, rule.id

    def test_an_unparseable_forced_label_is_not_granted(self, cfg: ScoringConfig) -> None:
        """A malformed catalogue may not declare an indicator fine."""
        decision = load_catalogue().evaluate(indicator="8.8.8.8", indicator_type="ip", as_of=AS_OF)
        broken = decision.model_copy(update={"forced_verdict": "TOTALLY_FINE"})

        verdict = run(cfg, malicious_signals(cfg), cov=full_coverage(), infrastructure=broken, indicator="8.8.8.8")

        assert verdict.verdict is VerdictLabel.MALICIOUS
        assert any("not a verdict label" in line for line in verdict.rationale)

    def test_no_infrastructure_decision_means_no_overrides(self, cfg: ScoringConfig) -> None:
        verdict = run(cfg, malicious_signals(cfg), cov=full_coverage(), infrastructure=None)

        assert verdict.allowlist is None
        assert verdict.overrides_applied == []


# --------------------------------------------------------------------------------------
# Ceiling-only signals
# --------------------------------------------------------------------------------------


class TestCeilingOnlySignals:
    def test_exposure_is_context_and_does_not_block_the_clean_label(self, cfg: ScoringConfig) -> None:
        """An exposed RDP box on a panel that reported nothing adverse is a risk, not a finding."""
        signals = [
            *clean_signals(cfg),
            scored(cfg, SignalId.SHODAN_EXPOSURE, "shodan", direction=SignalDirection.CONTEXT),
        ]

        verdict = run(cfg, signals, cov=full_coverage())

        assert verdict.score == 10
        assert verdict.verdict is VerdictLabel.NO_ADVERSE_FINDINGS
        assert verdict.adverse_signals == []

    def test_exposure_alone_can_never_reach_the_top_band(self, cfg: ScoringConfig, tmp_path: Path) -> None:
        """Even weighted past the MALICIOUS threshold, a ceiling-only signal stops at the cap."""

        def inflate_exposure(document: Dict[str, Any]) -> None:
            document["signals"]["shodan.exposure"]["max_points"] = 80
            document["shodan"]["max_points_from_cves"] = 80
            document["verdict_rules"]["require_corroboration_for_malicious"] = False
            document["version"] = "test-inflated-exposure"

        loud = ruleset_with(tmp_path, inflate_exposure)
        exposure = scored(loud, SignalId.SHODAN_EXPOSURE, "shodan", direction=SignalDirection.CONTEXT)

        verdict = eng.evaluate(
            indicator="203.0.113.10",
            scope=IndicatorScope.IP,
            signals=[exposure],
            coverage=full_coverage(),
            cfg=loud,
            now=NOW,
        )

        assert verdict.score == 80
        assert verdict.score_band is VerdictLabel.SUSPICIOUS
        assert loud.verdict_rules.ceiling_only_cap is VerdictLabel.SUSPICIOUS

    def test_a_ceiling_only_signal_does_not_block_an_earned_top_band(self, cfg: ScoringConfig) -> None:
        signals = [
            *malicious_signals(cfg),
            scored(cfg, SignalId.SHODAN_EXPOSURE, "shodan", direction=SignalDirection.CONTEXT),
        ]

        verdict = run(cfg, signals, cov=full_coverage())

        assert verdict.score == 80
        assert verdict.score_band is VerdictLabel.MALICIOUS

    def test_a_ceiling_only_signal_is_never_the_decisive_one(self, cfg: ScoringConfig) -> None:
        exposure = scored(cfg, SignalId.SHODAN_EXPOSURE, "shodan", direction=SignalDirection.CONTEXT)

        verdict = run(cfg, [exposure], cov=half_coverage())

        decisive = [item for item in verdict.confidence_criteria if item.name == "decisive_signal"]
        assert decisive and decisive[0].met is False


# --------------------------------------------------------------------------------------
# Roadmap 5.10
# --------------------------------------------------------------------------------------


class TestCollectionModeDisclosure:
    def test_a_passive_verdict_says_so(self, cfg: ScoringConfig) -> None:
        verdict = run(cfg, clean_signals(cfg), cov=full_coverage())

        assert verdict.passive_only is True
        assert verdict.active_collection == []

    def test_active_collection_is_named(self, cfg: ScoringConfig) -> None:
        verdict = run(
            cfg,
            clean_signals(cfg),
            cov=full_coverage(),
            passive_only=False,
            active_collection=[eng.ACTIVE_DNS_RESOLUTION],
        )

        assert verdict.passive_only is False
        assert verdict.active_collection == [eng.ACTIVE_DNS_RESOLUTION]

    def test_declaring_active_steps_overrides_a_passive_claim(self, cfg: ScoringConfig) -> None:
        """A caller cannot claim passive while naming an active step."""
        verdict = run(
            cfg,
            clean_signals(cfg),
            cov=full_coverage(),
            passive_only=True,
            active_collection=[eng.ACTIVE_DNS_RESOLUTION],
        )

        assert verdict.passive_only is False

    @pytest.mark.parametrize(
        ("source", "expected_passive"),
        [("passive", True), ("active", False), ("active+passive", False), (None, True)],
    )
    def test_collection_mode_reads_the_address_source_tag(self, source: Optional[str], expected_passive: bool) -> None:
        entry: Dict[str, Any] = {"ip": "203.0.113.10"}
        if source is not None:
            entry["source"] = source

        passive, active = eng.collection_for_ip_entry(entry)

        assert passive is expected_passive
        assert bool(active) is not expected_passive

    def test_active_collection_from_data_reads_the_resolved_addresses(self) -> None:
        passive_only = {"ips": [{"ip": "203.0.113.10", "source": "passive"}]}
        mixed = {"ips": [{"ip": "203.0.113.10", "source": "passive"}, {"ip": "203.0.113.11", "source": "active"}]}

        assert eng.active_collection_from_data(passive_only) == []
        assert eng.active_collection_from_data(mixed) == [eng.ACTIVE_DNS_RESOLUTION]

    def test_the_ip_front_door_discloses_the_resolver(self, cfg: ScoringConfig) -> None:
        entry = {"ip": "203.0.113.10", "source": "active", "provider_status": {}}

        verdict = eng.evaluate_ip_analysis(entry, cfg=cfg, now=NOW)

        assert verdict.passive_only is False
        assert verdict.active_collection == [eng.ACTIVE_DNS_RESOLUTION]


# --------------------------------------------------------------------------------------
# Front doors over the orchestrator shapes
# --------------------------------------------------------------------------------------


class TestFrontDoors:
    def test_an_empty_ip_entry_is_insufficient_data(self, cfg: ScoringConfig) -> None:
        verdict = eng.evaluate_ip_analysis({"ip": "203.0.113.10"}, cfg=cfg, now=NOW)

        assert verdict.verdict is VerdictLabel.INSUFFICIENT_DATA
        assert verdict.coverage.applicable_count == 0

    def test_the_recorded_coverage_is_preferred(self, cfg: ScoringConfig) -> None:
        entry = {"ip": "203.0.113.10", "coverage": full_coverage().model_dump(mode="json")}

        assert eng.coverage_for_ip_entry(entry).headline == "6 of 6 providers answered"

    def test_a_broken_coverage_block_falls_back_to_the_status_map(self, cfg: ScoringConfig) -> None:
        entry = {
            "ip": "203.0.113.10",
            "coverage": {"answered": "not-a-list"},
            "provider_status": {"virustotal": {"outcome": "ok"}, "shodan": {"outcome": "not_configured"}},
        }

        result = eng.coverage_for_ip_entry(entry)

        assert result.headline == "1 of 2 providers answered"

    def test_a_missing_coverage_block_never_reads_as_full(self, cfg: ScoringConfig) -> None:
        assert eng.coverage_for_ip_entry({"ip": "203.0.113.10"}).ratio == 0.0

    def test_an_ip_entry_scores_from_real_provider_payloads(self, cfg: ScoringConfig) -> None:
        """End to end over the orchestrator's own shape, extractors included."""
        entry = {
            "ip": "203.0.113.10",
            "virustotal": {"vt_last_analysis_stats": {"malicious": 0, "harmless": 70}},
            "abuseipdb": {"abuseipdb_confidence_score": 0, "abuseipdb_reports": 0},
            "otx": {"otx_pulse_count": 0},
            "provider_status": {name: {"outcome": "ok"} for name in PANEL},
        }

        verdict = eng.evaluate_ip_analysis(entry, cfg=cfg, now=NOW)

        assert verdict.verdict is VerdictLabel.NO_ADVERSE_FINDINGS
        assert verdict.indicator == "203.0.113.10"
        assert verdict.indicator_type == "ip"

    def test_the_domain_front_door_scores_the_domain_alone(self, cfg: ScoringConfig) -> None:
        data = {
            "domain": "evil.example",
            "domain_provider_status": {"virustotal": {"outcome": "ok"}, "otx": {"outcome": "ok"}},
            "domain_intel": {"virustotal": {"vt_last_analysis_stats": {"malicious": 0, "harmless": 70}}},
            "ips": [{"ip": "203.0.113.10", "source": "active"}],
        }

        verdict = eng.evaluate_domain_intel(data, cfg=cfg, now=NOW)

        assert verdict.indicator == "evil.example"
        assert verdict.indicator_type == "domain"
        assert verdict.coverage.headline == "2 of 2 providers answered"


# --------------------------------------------------------------------------------------
# Rule 3
# --------------------------------------------------------------------------------------


class TestNoInventedNumbers:
    #: 0 and 1 are identity and arity, not tuning. ``_ROUND_DP`` is how many decimal places the
    #: pre-clamp score keeps in the JSON. Nothing else may be a bare number in this module: a
    #: threshold, weight or band written here would be invisible to the ruleset version stamp and
    #: a verdict in an old ticket would stop being interpretable.
    ALLOWED_LITERALS = {0, 1, eng._ROUND_DP}

    def test_the_engine_holds_no_scoring_constants(self, engine_source: str) -> None:
        tree = ast.parse(engine_source)
        found = {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, (int, float))
        }
        found -= {value for value in found if isinstance(value, bool)}

        assert found <= self.ALLOWED_LITERALS, f"unexplained numeric literal(s) in engine.py: {sorted(found)}"

    def test_the_models_hold_no_scoring_constants(self, models_source: str) -> None:
        tree = ast.parse(models_source)
        found = {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, (int, float))
        }
        found -= {value for value in found if isinstance(value, bool)}

        assert found <= self.ALLOWED_LITERALS, f"unexplained numeric literal(s) in models.py: {sorted(found)}"

    def test_thresholds_come_from_the_ruleset(self, cfg: ScoringConfig, tmp_path: Path) -> None:
        """Move the bands in the file and the same score lands in a different one."""

        def lower_bands(document: Dict[str, Any]) -> None:
            document["bands"] = [
                {"label": "MALICIOUS", "min_score": 30},
                {"label": "SUSPICIOUS", "min_score": 10},
                {"label": "NO_ADVERSE_FINDINGS", "min_score": 0},
            ]
            document["verdict_rules"]["require_corroboration_for_malicious"] = False
            document["version"] = "test-lowered-bands"

        jumpy = ruleset_with(tmp_path, lower_bands)
        signals = [scored(jumpy, SignalId.VT_WEIGHTED_DETECTIONS, "virustotal")]

        assert run(cfg, [scored(cfg, SignalId.VT_WEIGHTED_DETECTIONS, "virustotal")]).score_band is (
            VerdictLabel.SUSPICIOUS
        )
        hot = eng.evaluate(
            indicator="203.0.113.10",
            scope=IndicatorScope.IP,
            signals=signals,
            coverage=full_coverage(),
            cfg=jumpy,
            now=NOW,
        )
        assert hot.score_band is VerdictLabel.MALICIOUS

    def test_every_verdict_carries_the_ruleset_it_was_computed_under(self, cfg: ScoringConfig) -> None:
        verdict = run(cfg, malicious_signals(cfg), cov=full_coverage())

        assert verdict.ruleset_version == cfg.version
        assert verdict.ruleset_source == cfg.source_label
        assert verdict.engine_version == eng.ENGINE_VERSION
        assert verdict.evaluated_at == NOW


# --------------------------------------------------------------------------------------
# Rules 4 and 5
# --------------------------------------------------------------------------------------


class TestNoAccuracyClaimAndNoVendorDenylist:
    #: No corpus exists and nothing has been measured on a held-out set, so none of these words
    #: may appear anywhere in this workstream's output or its prose.
    BANNED = (
        r"\baccurate\b",
        r"\baccuracy\b",
        r"\bprecision\b",
        r"\brecall\b",
        r"\bf1\b",
        r"\bfalse[- ]positive rate\b",
    )

    @pytest.mark.parametrize("pattern", BANNED)
    def test_the_engine_makes_no_accuracy_claim(self, engine_source: str, pattern: str) -> None:
        assert not re.search(pattern, engine_source, re.IGNORECASE), pattern

    @pytest.mark.parametrize("pattern", BANNED)
    def test_the_models_make_no_accuracy_claim(self, models_source: str, pattern: str) -> None:
        assert not re.search(pattern, models_source, re.IGNORECASE), pattern

    def test_the_honest_claim_travels_with_every_verdict(self, cfg: ScoringConfig) -> None:
        verdict = run(cfg, malicious_signals(cfg), cov=full_coverage())

        assert verdict.calibration_statement == cfg.calibration.statement
        assert "Heuristic" in verdict.calibration_statement
        assert verdict.calibration_statement in verdict.rationale[-1]

    def test_no_named_virustotal_engines_are_hard_coded(self, engine_source: str) -> None:
        """Engine-quality weighting comes from a corpus or it does not exist.

        The engine reads ``high_confidence_engines`` from the ruleset -- where it ships empty and
        the loader refuses to let the rule depending on it be enabled -- and never names a vendor.
        """
        assert "engine_weights" not in engine_source
        assert "cfg.virustotal.high_confidence_engines" not in engine_source

        # No module-level list of vendor names, under any name. ``__all__`` is the one exported
        # string list a module is allowed to have.
        for node in ast.parse(engine_source).body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            names = [node.target] if isinstance(node, ast.AnnAssign) else list(node.targets)
            if any(isinstance(name, ast.Name) and name.id == "__all__" for name in names):
                continue
            value = node.value
            if isinstance(value, (ast.List, ast.Set, ast.Tuple)) and any(
                isinstance(item, ast.Constant) and isinstance(item.value, str) for item in value.elts
            ):
                raise AssertionError(f"engine.py declares a literal list of names at line {node.lineno}")

    def test_the_shipped_high_confidence_engine_list_is_still_empty(self, cfg: ScoringConfig) -> None:
        assert cfg.virustotal.high_confidence_engines == []
        assert cfg.virustotal.engine_weights == {}


# --------------------------------------------------------------------------------------
# Purity
# --------------------------------------------------------------------------------------


class TestPurity:
    def test_the_engine_reads_no_clock_and_no_file(self, engine_source: str) -> None:
        for forbidden in (
            "datetime.now(",
            "dt.datetime.now(",
            "date.today(",
            "time.time(",
            "open(",
            "read_text(",
            "load_catalogue(",
            "default_config(",
            "httpx",
            "requests",
        ):
            assert forbidden not in engine_source, forbidden

    def test_the_same_inputs_produce_the_same_verdict(self, cfg: ScoringConfig) -> None:
        signals = malicious_signals(cfg)
        first = run(cfg, signals, cov=full_coverage())
        second = run(cfg, signals, cov=full_coverage())

        assert first.model_dump(mode="json") == second.model_dump(mode="json")

    def test_the_input_signals_are_not_mutated(self, cfg: ScoringConfig) -> None:
        decision = load_catalogue().evaluate(indicator="104.16.1.1", indicator_type="ip", asn=13335, as_of=AS_OF)
        exposure = scored(cfg, SignalId.SHODAN_EXPOSURE, "shodan", direction=SignalDirection.CONTEXT)
        before = exposure.points

        run(cfg, [exposure], cov=full_coverage(), infrastructure=decision)

        assert exposure.points == before

    def test_a_naive_now_is_refused(self, cfg: ScoringConfig) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            eng.evaluate(
                indicator="203.0.113.10",
                scope=IndicatorScope.IP,
                signals=[],
                coverage=full_coverage(),
                cfg=cfg,
                now=dt.datetime(2026, 8, 8, 12, 0, 0),
            )


# --------------------------------------------------------------------------------------
# The record itself
# --------------------------------------------------------------------------------------


class TestVerdictRecord:
    def test_it_serialises_to_json_cleanly(self, cfg: ScoringConfig) -> None:
        import json

        verdict = run(cfg, malicious_signals(cfg), cov=half_coverage())
        payload = verdict.to_json_dict()

        assert json.loads(json.dumps(payload))["verdict"] == verdict.verdict.value
        assert payload["evaluated_at"] == "2026-08-08T12:00:00Z"
        assert payload["coverage"]["headline"] == "3 of 6 providers answered"

    def test_it_round_trips(self, cfg: ScoringConfig) -> None:
        verdict = run(cfg, malicious_signals(cfg), cov=full_coverage())

        assert Verdict.model_validate(verdict.to_json_dict()).model_dump(mode="json") == verdict.to_json_dict()

    def test_the_summary_leads_with_the_verdict_word(self, cfg: ScoringConfig) -> None:
        verdict = run(cfg, malicious_signals(cfg), cov=thin_coverage())

        assert verdict.summary.startswith("203.0.113.10: SUSPICIOUS")
        assert "score 70/100" in verdict.summary
        assert "confidence LOW" in verdict.summary
        assert "2 of 6 providers answered" in verdict.summary

    def test_the_rationale_puts_the_biggest_contributor_first(self, cfg: ScoringConfig) -> None:
        verdict = run(cfg, malicious_signals(cfg), cov=full_coverage())

        contributions = [line for line in verdict.rationale if line.startswith("+")]
        assert contributions[0].startswith(f"+35.0 {SignalId.VT_WEIGHTED_DETECTIONS.value}")

    def test_top_signals_are_ordered_by_contribution(self, cfg: ScoringConfig) -> None:
        verdict = run(cfg, malicious_signals(cfg), cov=full_coverage())

        assert [item.points for item in verdict.top_signals(2)] == [35.0, 25.0]

    def test_raw_score_keeps_the_pre_clamp_value(self, cfg: ScoringConfig) -> None:
        signals = [
            *malicious_signals(cfg),
            scored(cfg, SignalId.OTX_PULSE_QUALITY, "otx"),
            scored(cfg, SignalId.SHODAN_EXPOSURE, "shodan", direction=SignalDirection.CONTEXT),
            scored(cfg, SignalId.ASN_REPUTATION, "ipinfo"),
            scored(cfg, SignalId.VT_COMMUNITY_REPUTATION, "virustotal"),
        ]

        verdict = run(cfg, signals, cov=full_coverage())

        assert verdict.raw_score == 110.0
        assert verdict.score == cfg.score.clamp_max

    def test_a_malicious_verdict_at_low_confidence_must_be_flagged(self, cfg: ScoringConfig) -> None:
        template = run(cfg, malicious_signals(cfg), cov=full_coverage())
        payload = template.model_dump(mode="json")
        payload["confidence"] = Confidence.LOW.value
        payload["requires_analyst_review"] = False

        with pytest.raises(ValidationError, match="LOW confidence"):
            Verdict.model_validate(payload)


# --------------------------------------------------------------------------------------
# Label arithmetic
# --------------------------------------------------------------------------------------


class TestLabelHelpers:
    def test_a_cap_never_raises_a_verdict(self) -> None:
        assert cap_label(VerdictLabel.NO_ADVERSE_FINDINGS, VerdictLabel.SUSPICIOUS) is (
            VerdictLabel.NO_ADVERSE_FINDINGS
        )
        assert cap_label(VerdictLabel.MALICIOUS, VerdictLabel.SUSPICIOUS) is VerdictLabel.SUSPICIOUS

    def test_a_cap_leaves_a_forced_label_alone(self) -> None:
        assert cap_label(VerdictLabel.KNOWN_INFRASTRUCTURE, VerdictLabel.SUSPICIOUS) is (
            VerdictLabel.KNOWN_INFRASTRUCTURE
        )

    def test_demotion_stops_at_its_floor(self) -> None:
        assert demote_label(VerdictLabel.MALICIOUS, floor=VerdictLabel.SUSPICIOUS) is VerdictLabel.SUSPICIOUS
        assert demote_label(VerdictLabel.SUSPICIOUS, floor=VerdictLabel.SUSPICIOUS) is VerdictLabel.SUSPICIOUS

    def test_confidence_only_ever_weakens(self) -> None:
        assert weakest_confidence(Confidence.HIGH, Confidence.LOW) is Confidence.LOW
        assert weaken_confidence(Confidence.HIGH) is Confidence.MEDIUM
        assert weaken_confidence(Confidence.LOW) is Confidence.LOW

    def test_contradictions_and_overrides_are_plain_records(self) -> None:
        contradiction = Contradiction(rule_id="vt_vs_abuseipdb", summary="s", left="a", right="b", analyst_hint="look")
        override = OverrideApplied(rule_id="cdn.cloudflare", tier="B", effect="verdict_capped")

        assert contradiction.both_material is False
        assert override.source_retrieved_at is None
