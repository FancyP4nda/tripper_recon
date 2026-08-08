"""Load and validate the verdict ruleset (roadmap 5.2).

This module is the contract every other part of the verdict engine builds on, and it holds no
scoring constants of its own. Weights, thresholds, bands, decay curves, family maps and override
tiers all live in ``scoring.yaml``; what lives here is the *shape* of that file and the rules for
rejecting one that is internally incoherent.

Three ideas do the work:

**A silently-wrong config produces silently-wrong verdicts.** A misspelled signal name, a band
that overlaps its neighbour, a decay factor that grows with age, an override rule that can never
fire -- none of those raises anything at scoring time. They just quietly change the answer. So
:class:`ScoringConfig` refuses to load rather than degrade: ``extra="forbid"`` on every model
catches typo'd keys, and the coherence validator at the bottom of this file catches the
relationships pydantic cannot express field by field.

**Absent data never scores as clean, and config cannot switch that off.** Two settings are
validated to a fixed value rather than merely defaulted -- ``verdict_rules.require_affirmative_
negative`` and ``overrides.tier_a.verdict`` -- because they are the rule, not a preference. Two
more validators exist only to serve it: score-reachable bands may not include
``KNOWN_INFRASTRUCTURE`` or ``INSUFFICIENT_DATA``, and ``domain_age.unknown_points`` may not be
zero, which would make "no whois date" score identically to "comfortably old".

**Dead config is a defect, not a placeholder.** An override rule that depends on a provider this
package has not implemented, or a VirusTotal consensus rule with an empty high-confidence engine
list, can never fire. Left enabled it reads to a maintainer as an active control. The loader
rejects that state and makes you write ``enabled: false``, so the inertness is on the page.

Loading precedence, highest first:

1. an explicit path -- the ``path`` argument, then ``$TRIPPER_RECON_SCORING_CONFIG``
2. a user override -- ``$XDG_CONFIG_HOME/tripper_recon/scoring.yaml``, else
   ``~/.config/tripper_recon/scoring.yaml``
3. the packaged ``scoring.yaml`` beside this module, which must always work with no
   configuration at all

Every loaded config records where it came from (:attr:`ScoringConfig.source_origin` /
:attr:`ScoringConfig.source_label`), because "the operator has a stale override in their home
directory" is otherwise an unfalsifiable explanation for a surprising verdict.

.. warning::
   ``PyYAML`` is imported here and is **not** currently declared in ``pyproject.toml``. It must
   be added to ``[project] dependencies`` before this package ships. The import is guarded so
   that importing :mod:`tripper_recon` still works without it; the failure surfaces at load time
   with an actionable message instead of at import time with a traceback.
"""

from __future__ import annotations

import ipaddress
import os
from enum import Enum
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

try:  # pragma: no cover - exercised by the ImportError test via monkeypatching
    import yaml
except ImportError:  # pragma: no cover - see the module docstring warning
    yaml = None

__all__ = [
    "CONFIG_ENV_VAR",
    "PACKAGED_CONFIG_NAME",
    "AllowlistRule",
    "AsnConfig",
    "AbuseIpdbConfig",
    "Band",
    "CalibrationConfig",
    "CertificateConfig",
    "ConfidenceBand",
    "ConfidenceConfig",
    "ContradictionRule",
    "ContradictionRuleId",
    "ContradictionsConfig",
    "DecayBand",
    "DomainAgeBand",
    "DomainAgeConfig",
    "EscalationConfig",
    "EscalationRule",
    "IndicatorScope",
    "OverrideTier",
    "OverridesConfig",
    "ProvidersConfig",
    "ScoreConfig",
    "ScoringConfig",
    "ScoringConfigError",
    "ShodanConfig",
    "SignalConfig",
    "SignalId",
    "OtxConfig",
    "TierAConfig",
    "TierBConfig",
    "TierCConfig",
    "UndatedEvidenceConfig",
    "VendorSuppressionRule",
    "VerdictLabelName",
    "VerdictRules",
    "VirusTotalConfig",
    "VtCategoriesConfig",
    "clear_config_cache",
    "default_config",
    "load_scoring_config",
    "resolve_config_source",
]

#: Environment variable holding an explicit ruleset path. Beaten only by an argument.
CONFIG_ENV_VAR = "TRIPPER_RECON_SCORING_CONFIG"

#: The filename in the user override directory and in this package.
PACKAGED_CONFIG_NAME = "scoring.yaml"

#: Directory under ``$XDG_CONFIG_HOME`` / ``~/.config`` searched for an override.
USER_CONFIG_SUBDIR = "tripper_recon"


class ScoringConfigError(Exception):
    """A ruleset could not be found, parsed, or validated.

    Every failure in this module raises this one type with the source label in the message. A
    caller catching it knows the engine has no usable ruleset, which is a hard stop -- there is
    no defensible fallback to "score it with something".
    """


# --------------------------------------------------------------------------------------
# Vocabulary -- names, not numbers
# --------------------------------------------------------------------------------------
#
# These enums are code, and that is deliberate. A signal id corresponds to an extractor function
# and a verdict label corresponds to a branch in the engine, so both are part of the program, not
# of its tuning. The rule "no scoring constants in Python" is about *numbers*: nothing in this
# section is a weight, a threshold or a decay constant.


class SignalId(str, Enum):
    """Every signal the engine knows how to compute.

    A key in ``scoring.yaml``'s ``signals:`` table that is not listed here is rejected. Weighting
    a signal nobody implemented is a config that looks like it is doing something and is not, and
    it is the exact defect class that survives review because the file reads fine.
    """

    VT_WEIGHTED_DETECTIONS = "vt.weighted_detections"
    VT_COMMUNITY_REPUTATION = "vt.community_reputation"
    VT_CATEGORIES = "vt.categories"
    ABUSEIPDB_CONFIDENCE = "abuseipdb.confidence"
    ABUSEIPDB_VOLUME_RECENCY = "abuseipdb.volume_recency"
    OTX_PULSE_QUALITY = "otx.pulse_quality"
    OTX_MALWARE_COUNT = "otx.malware_count"
    SHODAN_EXPOSURE = "shodan.exposure"
    ASN_REPUTATION = "asn.reputation"
    ASN_BGP_INCIDENTS = "asn.bgp_incidents"
    DOMAIN_AGE = "domain.age"
    CERT_ANOMALY = "cert.anomaly"


class IndicatorScope(str, Enum):
    """What kind of indicator a signal or an override applies to."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    ASN = "asn"


class VerdictLabelName(str, Enum):
    """The five verdict states, by wire name.

    Defined here rather than imported because the ``Verdict`` model (roadmap 5.1) is owned by
    another lane and does not exist yet. **These wire strings are the contract**: when
    ``types.models.VerdictLabel`` lands it must use exactly these values, and this enum should
    then become an alias of it rather than a second definition.
    """

    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    NO_ADVERSE_FINDINGS = "NO_ADVERSE_FINDINGS"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    KNOWN_INFRASTRUCTURE = "KNOWN_INFRASTRUCTURE"


#: The only labels a score may produce, in descending severity.
#:
#: ``INSUFFICIENT_DATA`` and ``KNOWN_INFRASTRUCTURE`` are excluded and the band validator rejects
#: them. Coverage produces the first; the Tier A allowlist -- a human decision with a citation --
#: produces the second. The engine can earn its way up to ``MALICIOUS`` and can never earn its way
#: down to safe, and this tuple is where that asymmetry is enforced.
SCORE_REACHABLE_LABELS: Tuple[VerdictLabelName, ...] = (
    VerdictLabelName.MALICIOUS,
    VerdictLabelName.SUSPICIOUS,
    VerdictLabelName.NO_ADVERSE_FINDINGS,
)


class ConfidenceBand(str, Enum):
    """Confidence is a separate axis from score and has its own three states."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class OverrideTier(str, Enum):
    """Override precedence tokens, plus ``SCORE`` for "fall through to the bands"."""

    TIER_A = "tier_a"
    ESCALATION = "escalation"
    TIER_B = "tier_b"
    SCORE = "score"


class ContradictionRuleId(str, Enum):
    """Contradiction rules the engine implements. Same unknown-name rejection as signals."""

    VT_VS_ABUSEIPDB = "vt_vs_abuseipdb"
    STALE_VS_FRESH = "stale_vs_fresh"
    CDN_VS_DETECTION = "cdn_vs_detection"
    AGE_VS_REPUTATION = "age_vs_reputation"


class CalibrationStatus(str, Enum):
    """How much measurement stands behind the numbers in a ruleset."""

    UNVALIDATED = "unvalidated"
    TUNED = "tuned"
    VALIDATED = "validated"


class AuthorDiversityMode(str, Enum):
    """How repeated pulses from one OTX author are discounted."""

    HARMONIC = "harmonic"
    NONE = "none"


# --------------------------------------------------------------------------------------
# Base model
# --------------------------------------------------------------------------------------


class _Base(BaseModel):
    """``extra="forbid"`` plus immutability for every config model.

    Forbidding extras is the single highest-value setting in this file. ``suspicious_treshold:
    40`` in a hand-edited override is otherwise silently ignored and the operator believes they
    changed something. Frozen because a loaded ruleset is shared and cached: a caller mutating it
    would change the meaning of verdicts already produced under the same ``ruleset_version``.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)


# --------------------------------------------------------------------------------------
# Sections
# --------------------------------------------------------------------------------------


class CalibrationConfig(_Base):
    """The honesty block. No accuracy claim without a held-out evaluation behind it."""

    status: CalibrationStatus
    fixture_count: int = Field(ge=0)
    held_out: bool = False
    precision: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    recall: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    statement: str = Field(min_length=1)

    @model_validator(mode="after")
    def _no_unearned_accuracy_claim(self) -> CalibrationConfig:
        """A precision or recall figure requires ``status: validated`` and ``held_out: true``.

        The circularity is the reason. A corpus labelled from a feed the engine also reads grades
        the engine on its own answer key, so a number produced without the held-out condition is
        not merely unverified -- it is knowably inflated. Rejecting it here means the figure
        cannot reach a report by way of a config edit.
        """
        has_figure = self.precision is not None or self.recall is not None
        if has_figure and self.status is not CalibrationStatus.VALIDATED:
            raise ValueError(
                "calibration carries a precision/recall figure with status "
                f"'{self.status.value}'. Accuracy figures require status 'validated'."
            )
        if has_figure and not self.held_out:
            raise ValueError(
                "calibration carries a precision/recall figure with held_out=false. A figure "
                "measured without a held-out feed grades the engine on its own answer key."
            )
        if self.status is CalibrationStatus.VALIDATED and self.fixture_count <= 0:
            raise ValueError("calibration status 'validated' with fixture_count 0 is not a validation.")
        return self


class ScoreConfig(_Base):
    """Where the summed points are clamped. ``raw_score`` keeps the pre-clamp value."""

    clamp_min: int = Field(ge=0)
    clamp_max: int = Field(gt=0)

    @model_validator(mode="after")
    def _ordered(self) -> ScoreConfig:
        if self.clamp_max <= self.clamp_min:
            raise ValueError(f"score.clamp_max ({self.clamp_max}) must exceed clamp_min ({self.clamp_min})")
        return self


class Band(_Base):
    """One verdict band: the lowest score that reaches ``label``."""

    label: VerdictLabelName
    min_score: int = Field(ge=0)


class VerdictRules(_Base):
    """The switches that turn the absolute rules into checkable settings."""

    #: Validated to ``True``. A zero score is not a clean verdict; coverage plus at least one
    #: affirmative negative is required. This is the rule the workstream exists to enforce and a
    #: config file must not be able to switch it off.
    require_affirmative_negative: bool
    #: No single signal may be worth enough to reach the top band alone.
    require_corroboration_for_malicious: bool
    #: A MALICIOUS score at LOW confidence renders as SUSPICIOUS with the raw score beside it.
    demote_malicious_when_confidence_low: bool
    #: The highest label a ``ceiling_only`` signal may produce.
    ceiling_only_cap: VerdictLabelName

    @model_validator(mode="after")
    def _absent_data_rule_is_not_optional(self) -> VerdictRules:
        if not self.require_affirmative_negative:
            raise ValueError(
                "verdict_rules.require_affirmative_negative must be true. Absent data never "
                "scores as clean; a benign verdict requires a provider that answered."
            )
        if self.ceiling_only_cap not in SCORE_REACHABLE_LABELS:
            raise ValueError(
                f"verdict_rules.ceiling_only_cap must be a score-reachable label, got {self.ceiling_only_cap.value}"
            )
        if self.ceiling_only_cap is VerdictLabelName.MALICIOUS:
            raise ValueError(
                "verdict_rules.ceiling_only_cap of MALICIOUS makes the ceiling_only flag a no-op. "
                "A ceiling-only signal exists precisely so it cannot reach MALICIOUS."
            )
        return self


class ConfidenceThresholds(_Base):
    """The requirements for one confidence band."""

    min_coverage: float = Field(ge=0.0, le=1.0)
    min_families: int = Field(ge=1)
    allow_unresolved_contradiction: Optional[bool] = None
    decisive_signal_substitutes_for_family: Optional[bool] = None


class ConfidenceConfig(_Base):
    """Confidence, computed without reference to the score."""

    #: The coverage floor. Below this, confidence is forced LOW and the verdict cannot be
    #: NO_ADVERSE_FINDINGS. Predicate: ``types.models.Coverage.is_sufficient(coverage_floor)``.
    coverage_floor: float = Field(ge=0.0, le=1.0)
    high: ConfidenceThresholds
    medium: ConfidenceThresholds
    decisive_signal_fraction: float = Field(gt=0.0, le=1.0)

    @model_validator(mode="after")
    def _bands_are_ordered_and_above_the_floor(self) -> ConfidenceConfig:
        if self.high.min_coverage < self.medium.min_coverage:
            raise ValueError(
                f"confidence.high.min_coverage ({self.high.min_coverage}) is below "
                f"medium.min_coverage ({self.medium.min_coverage}); the bands overlap backwards."
            )
        if self.medium.min_coverage < self.coverage_floor:
            raise ValueError(
                f"confidence.medium.min_coverage ({self.medium.min_coverage}) is below the "
                f"coverage floor ({self.coverage_floor}); MEDIUM would be reachable while "
                "confidence is forced LOW."
            )
        return self


class DecayBand(_Base):
    """One step of a decay curve. ``max_age_days: null`` is the open-ended tail."""

    max_age_days: Optional[int] = Field(default=None, gt=0)
    #: A multiplier, never an addend, so decay can only move a score toward zero. Negative is
    #: rejected by the bound rather than by a validator, because a negative decay constant would
    #: turn stale evidence into exculpatory evidence.
    factor: float = Field(ge=0.0, le=1.0)


class UndatedEvidenceConfig(_Base):
    """What to multiply an observation by when the provider reported no date for it.

    This block exists because the obvious answer is the wrong one. Treating undated evidence as
    old -- taking the open-ended tail of the decay profile -- reads as the cautious choice, and
    it is exactly backwards here.

    Decay is applied to *scored* signals, and every signal in the ``signals:`` weight table is
    adverse-capable. The affirmative negatives (``vt.no_detections``, ``abuseipdb.no_reports``,
    ``otx.no_pulses``) carry zero points by construction and are not in that table at all, so a
    decay multiplier has nothing to reduce on the exculpatory side. The tail factor can
    therefore only ever move an indicator *toward* clean.

    Measured on the real engine: an AbuseIPDB payload reporting 100% confidence, 500 reports and
    40 distinct reporters scores 35 with ``lastReportedAt`` present and 5 with the same field
    absent -- a sevenfold collapse of adverse evidence produced by one missing metadata field,
    with the provider's actual finding unchanged. That is the absent-data rule inverted, and it
    is a false negative an analyst acts on.

    So the factor is 1.0: a missing timestamp neither strengthens nor weakens what the provider
    reported. What it does do is get said out loud -- the signal's observation string states the
    date was not reported, so the analyst can weigh the staleness the engine refuses to guess at.

    Kept as config rather than a literal because it is a tuning number and belongs in the
    ruleset with everything else. Lowering it below 1.0 is a decision to let absent metadata
    discount adverse evidence; the ruleset comment says so, and it is bumped with ``version``.
    """

    factor: float = Field(ge=0.0, le=1.0)
    #: Why this value, in the ruleset's own words. Surfaces wherever the choice needs defending.
    note: str = Field(min_length=1)


class SignalConfig(_Base):
    """The ceiling and the wiring for one signal. How it computes lives in a provider block."""

    family: str = Field(min_length=1)
    providers: List[str] = Field(min_length=1)
    applies_to: List[IndicatorScope] = Field(min_length=1)
    max_points: float = Field(ge=0.0)
    enabled: bool = True
    #: May raise a verdict at most to ``verdict_rules.ceiling_only_cap``, whatever its points.
    ceiling_only: bool = False
    notes: str = ""


class ProvidersConfig(_Base):
    """What exists versus what is merely designed. Used to detect dead config."""

    implemented: List[str] = Field(min_length=1)
    planned: List[str] = Field(default_factory=list)

    @property
    def known(self) -> FrozenSet[str]:
        return frozenset(self.implemented) | frozenset(self.planned)

    @model_validator(mode="after")
    def _disjoint(self) -> ProvidersConfig:
        overlap = sorted(set(self.implemented) & set(self.planned))
        if overlap:
            raise ValueError(f"providers listed as both implemented and planned: {', '.join(overlap)}")
        return self


class VirusTotalConfig(_Base):
    """Weighted detection ratio parameters."""

    saturation: float = Field(gt=0.0)
    suspicious_multiplier: float = Field(ge=0.0, le=1.0)
    default_engine_weight: float = Field(ge=0.0)
    #: Per-engine overrides. Ships empty and must stay empty until a corpus fills it: engine
    #: quality comes from measurement or it does not exist.
    engine_weights: Dict[str, float] = Field(default_factory=dict)
    #: Also ships empty. While it is empty the ``escalation.vt_consensus`` rule is inert, and the
    #: coherence validator requires that rule to be disabled so the inertness is visible.
    high_confidence_engines: List[str] = Field(default_factory=list)
    consensus_threshold: int = Field(ge=1)
    recency_profile: str = Field(min_length=1)

    @model_validator(mode="after")
    def _weights_non_negative(self) -> VirusTotalConfig:
        bad = sorted(name for name, weight in self.engine_weights.items() if weight < 0)
        if bad:
            raise ValueError(f"virustotal.engine_weights has negative weights: {', '.join(bad)}")
        return self


class AbuseIpdbConfig(_Base):
    """Confidence, volume, reporter-diversity and recency parameters."""

    #: Was a hard-coded ``maxAgeInDays=365`` in ``providers/abuseipdb.py``. It is a scoring
    #: parameter: it decides how much history the vendor's confidence score reflects.
    max_age_days: int = Field(ge=1)
    confidence_saturation: float = Field(gt=0.0, le=100.0)
    confidence_floor: float = Field(ge=0.0, le=100.0)
    volume_saturation: float = Field(gt=0.0)
    distinct_users_saturation: float = Field(gt=0.0)
    volume_weight: float = Field(ge=0.0, le=1.0)
    diversity_weight: float = Field(ge=0.0, le=1.0)
    recency_profile: str = Field(min_length=1)

    @model_validator(mode="after")
    def _coherent(self) -> AbuseIpdbConfig:
        if self.confidence_floor >= self.confidence_saturation:
            raise ValueError(
                f"abuseipdb.confidence_floor ({self.confidence_floor}) must be below "
                f"confidence_saturation ({self.confidence_saturation}); otherwise the signal has "
                "no range in which it varies."
            )
        total = self.volume_weight + self.diversity_weight
        if abs(total - 1.0) > 1e-9:
            raise ValueError(
                f"abuseipdb.volume_weight + diversity_weight must sum to 1.0, got {total}. They "
                "split one signal's points; a sum below 1 makes the ceiling unreachable and a sum "
                "above 1 lets the signal exceed its own max_points."
            )
        return self


class OtxConfig(_Base):
    """Quality adjustment for the pulse count."""

    author_diversity: AuthorDiversityMode
    title_novelty_factor: float = Field(ge=0.0, le=1.0)
    near_duplicate_ratio: float = Field(gt=0.0, le=1.0)
    unattributed_author_key: str = Field(min_length=1)
    effective_pulse_saturation: float = Field(gt=0.0)
    recency_profile: str = Field(min_length=1)


class ShodanConfig(_Base):
    """Exposure severity. Ceiling-only by the flag on the signal, not by these numbers."""

    risky_ports: List[int] = Field(default_factory=list)
    points_per_risky_port: float = Field(ge=0.0)
    points_per_cve: float = Field(ge=0.0)
    max_points_from_cves: float = Field(ge=0.0)
    recency_profile: str = Field(min_length=1)

    @model_validator(mode="after")
    def _ports_are_ports(self) -> ShodanConfig:
        bad = sorted(port for port in self.risky_ports if not 1 <= port <= 65535)
        if bad:
            raise ValueError(f"shodan.risky_ports contains values outside 1-65535: {bad}")
        return self


class AsnConfig(_Base):
    """ASN-level prior. Ships inert on purpose -- no cited list, no points."""

    #: Empty by design. An uncited hosting-reputation list is invented evidence, and ASN-level
    #: guilt-by-association is the most likely source of systematic bias in the whole model.
    bulletproof_asns: List[int] = Field(default_factory=list)
    points_if_bulletproof: float = Field(ge=0.0)
    hijack_saturation: int = Field(ge=1)

    @model_validator(mode="after")
    def _asns_are_asns(self) -> AsnConfig:
        bad = sorted(asn for asn in self.bulletproof_asns if not 0 <= asn <= 4294967295)
        if bad:
            raise ValueError(f"asn.bulletproof_asns contains values outside the 32-bit AS range: {bad}")
        return self


class DomainAgeBand(_Base):
    """One age band. ``max_age_days: null`` is the open-ended tail."""

    max_age_days: Optional[int] = Field(default=None, gt=0)
    points: float = Field(ge=0.0)


class DomainAgeConfig(_Base):
    """Age bands, plus the score for a domain whose age could not be established."""

    bands: List[DomainAgeBand] = Field(min_length=1)
    #: Must be greater than zero. A missing whois creation date is absence of evidence, and
    #: scoring it zero makes it identical to "comfortably old", which is the clean end of this
    #: signal. That is the absent-data rule in its most easily-overlooked form.
    unknown_points: float = Field(gt=0.0)


class VtCategoriesConfig(_Base):
    """Adverse vendor category terms, matched case-folded as substrings."""

    adverse_terms: List[str] = Field(min_length=1)
    points_per_term: float = Field(gt=0.0)

    @model_validator(mode="after")
    def _terms_are_normalised(self) -> VtCategoriesConfig:
        bad = [term for term in self.adverse_terms if term != term.strip().casefold() or not term]
        if bad:
            raise ValueError(
                f"vt_categories.adverse_terms must be lowercase and stripped (matching is case-folded): {bad}"
            )
        return self


class CertificateConfig(_Base):
    """Per-sub-check points for the ``cert.anomaly`` composite."""

    short_validity_days: int = Field(gt=0)
    points_short_validity: float = Field(ge=0.0)
    points_cn_mismatch: float = Field(ge=0.0)
    points_self_signed: float = Field(ge=0.0)
    points_expired_but_serving: float = Field(ge=0.0)

    @property
    def total_points(self) -> float:
        """The most the composite can emit, validated against the signal's ``max_points``."""
        return (
            self.points_short_validity
            + self.points_cn_mismatch
            + self.points_self_signed
            + self.points_expired_but_serving
        )


class AllowlistRule(_Base):
    """One CIDR-based allowlist or cap rule, with its provenance."""

    id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    #: Where the ranges come from. Required: a suppression list with no provenance is an
    #: assertion, and a stale one silently suppresses a reassigned range.
    source: str = Field(min_length=1)
    #: When the ranges were last fetched, stamped into every verdict that used them. ``None`` is
    #: permitted only for a rule whose ranges are hand-entered and stable (public resolvers) or
    #: for one shipped empty pending a fetcher.
    source_retrieved_at: Optional[str] = None
    enabled: bool = True
    cidrs: List[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _cidrs_parse(self) -> AllowlistRule:
        for cidr in self.cidrs:
            try:
                ipaddress.ip_network(cidr, strict=True)
            except ValueError as exc:
                raise ValueError(f"override rule '{self.id}' has an unusable CIDR {cidr!r}: {exc}") from exc
        return self


class TierAConfig(_Base):
    """The absolute allowlist. The only path to ``KNOWN_INFRASTRUCTURE``."""

    enabled: bool
    verdict: VerdictLabelName
    short_circuit: bool
    rules: List[AllowlistRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _tier_a_is_the_only_benign_path(self) -> TierAConfig:
        if self.verdict is not VerdictLabelName.KNOWN_INFRASTRUCTURE:
            raise ValueError(
                "overrides.tier_a.verdict must be KNOWN_INFRASTRUCTURE. The allowlist is the only "
                "mechanism permitted to declare an indicator fine, and it may not be repointed at "
                "another label."
            )
        if not self.short_circuit:
            raise ValueError(
                "overrides.tier_a.short_circuit must be true. A public resolver that also scores "
                "must not fall through to the bands."
            )
        return self


class TierBConfig(_Base):
    """CDN and cloud ranges. Caps and annotates; never forces benign."""

    enabled: bool
    cap_verdict: VerdictLabelName
    scopes_capped: List[IndicatorScope] = Field(min_length=1)
    zero_signals: List[SignalId] = Field(default_factory=list)
    attribution_warning: str = Field(min_length=1)
    rules: List[AllowlistRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _cap_does_not_exculpate_the_tenant(self) -> TierBConfig:
        if self.cap_verdict not in SCORE_REACHABLE_LABELS:
            raise ValueError(f"overrides.tier_b.cap_verdict must be score-reachable, got {self.cap_verdict.value}")
        if self.cap_verdict is VerdictLabelName.MALICIOUS:
            raise ValueError("overrides.tier_b.cap_verdict of MALICIOUS caps nothing.")
        forbidden = sorted(
            scope.value for scope in self.scopes_capped if scope in (IndicatorScope.DOMAIN, IndicatorScope.URL)
        )
        if forbidden:
            raise ValueError(
                f"overrides.tier_b.scopes_capped includes {', '.join(forbidden)}. A phishing kit "
                "on a CDN must still render red at the domain and URL level; capping there would "
                "exculpate the tenant along with the shared address."
            )
        return self


class VendorSuppressionRule(_Base):
    """One Tier C rule: a vendor's own "we consider this fine" flag."""

    id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    #: The key on the provider payload, so the extractor lane does not have to guess a spelling.
    payload_key: str = Field(min_length=1)
    enabled: bool = True


class TierCConfig(_Base):
    """Vendor suppression. Weak, so it demotes rather than short-circuits."""

    enabled: bool
    effect: str = Field(min_length=1)
    rules: List[VendorSuppressionRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _effect_is_a_demotion(self) -> TierCConfig:
        allowed = {"demote_confidence", "demote_verdict"}
        if self.effect not in allowed:
            raise ValueError(
                f"overrides.tier_c.effect must be one of {sorted(allowed)}, got {self.effect!r}. A "
                "vendor whitelist flag is one opinion and may not short-circuit scoring."
            )
        return self


class EscalationRule(_Base):
    """One rule that forces a verdict upward, short-circuiting the bands."""

    id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    enabled: bool
    #: Providers this rule reads. An enabled rule naming an unimplemented provider is dead config
    #: and is rejected by the coherence validator.
    requires_providers: List[str] = Field(default_factory=list)
    requires_high_confidence_engines: bool = False
    min_families: Optional[int] = Field(default=None, ge=1)
    verdict: VerdictLabelName
    confidence: ConfidenceBand

    @model_validator(mode="after")
    def _escalation_only_goes_up(self) -> EscalationRule:
        if self.verdict is not VerdictLabelName.MALICIOUS:
            raise ValueError(
                f"escalation rule '{self.id}' sets verdict {self.verdict.value}. Escalation exists "
                "to force MALICIOUS; a rule that forces anything else is a cap or a suppression "
                "and belongs in Tier B or Tier C."
            )
        if self.confidence is ConfidenceBand.LOW:
            raise ValueError(
                f"escalation rule '{self.id}' forces MALICIOUS at LOW confidence, which the "
                "demotion rule would immediately render as SUSPICIOUS. State the confidence the "
                "evidence actually supports."
            )
        return self


class EscalationConfig(_Base):
    enabled: bool
    rules: List[EscalationRule] = Field(default_factory=list)


class OverridesConfig(_Base):
    """The four tiers plus their precedence."""

    precedence: List[OverrideTier] = Field(min_length=1)
    tier_a: TierAConfig
    tier_b: TierBConfig
    tier_c: TierCConfig
    escalation: EscalationConfig

    @model_validator(mode="after")
    def _precedence_is_total(self) -> OverridesConfig:
        expected = list(OverrideTier)
        if sorted(tier.value for tier in self.precedence) != sorted(tier.value for tier in expected):
            raise ValueError(
                "overrides.precedence must list every tier exactly once "
                f"({', '.join(tier.value for tier in expected)}); got "
                f"{', '.join(tier.value for tier in self.precedence)}"
            )
        if self.precedence[0] is not OverrideTier.TIER_A:
            raise ValueError(
                "overrides.precedence must start with tier_a. A feed reporting malware on a public "
                "resolver is wrong far more often than the resolver is compromised, and an engine "
                "that flips on feed error is worse than one that is stubborn. The conflict is "
                "reported as a contradiction, not resolved by reordering this list."
            )
        if self.precedence[-1] is not OverrideTier.SCORE:
            raise ValueError("overrides.precedence must end with 'score'; the bands are the fallthrough.")
        return self


class ContradictionRule(_Base):
    """One pairwise contradiction rule."""

    id: ContradictionRuleId
    enabled: bool
    description: str = Field(min_length=1)
    #: The sentence the analyst reads. Required: a flag with no hint is a nag.
    analyst_hint: str = Field(min_length=1)
    stale_days: Optional[int] = Field(default=None, gt=0)
    fresh_days: Optional[int] = Field(default=None, gt=0)
    max_age_days: Optional[int] = Field(default=None, gt=0)

    @model_validator(mode="after")
    def _stale_is_older_than_fresh(self) -> ContradictionRule:
        if self.stale_days is not None and self.fresh_days is not None and self.stale_days <= self.fresh_days:
            raise ValueError(
                f"contradiction rule '{self.id.value}': stale_days ({self.stale_days}) must exceed "
                f"fresh_days ({self.fresh_days}), or the rule fires on every indicator."
            )
        return self


class ContradictionsConfig(_Base):
    """Contradictions are surfaced, never averaged away."""

    enabled: bool
    cap_confidence: ConfidenceBand
    demote_verdict_when_both_material: bool
    material_fraction: float = Field(gt=0.0, le=1.0)
    rules: List[ContradictionRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _cap_actually_caps_and_ids_are_unique(self) -> ContradictionsConfig:
        if self.cap_confidence is ConfidenceBand.HIGH:
            raise ValueError(
                "contradictions.cap_confidence of HIGH caps nothing. An unresolved disagreement "
                "between providers is precisely the state in which HIGH is unwarranted."
            )
        seen: Dict[ContradictionRuleId, int] = {}
        for rule in self.rules:
            seen[rule.id] = seen.get(rule.id, 0) + 1
        duplicates = sorted(rule_id.value for rule_id, count in seen.items() if count > 1)
        if duplicates:
            raise ValueError(f"duplicate contradiction rule ids: {', '.join(duplicates)}")
        return self


# --------------------------------------------------------------------------------------
# The root model
# --------------------------------------------------------------------------------------


class ScoringConfig(_Base):
    """A validated ruleset.

    :attr:`version` is stamped into every verdict as ``ruleset_version``. Change any number in
    the file and bump it: two verdicts produced by different tunings are different claims.
    """

    version: str = Field(min_length=1)
    ruleset_name: str = Field(min_length=1)
    calibration: CalibrationConfig
    score: ScoreConfig
    bands: List[Band] = Field(min_length=1)
    verdict_rules: VerdictRules
    confidence: ConfidenceConfig
    decay_profiles: Dict[str, List[DecayBand]]
    undated_evidence: UndatedEvidenceConfig
    signals: Dict[SignalId, SignalConfig]
    provider_families: Dict[str, List[str]]
    non_corroborating_families: List[str] = Field(default_factory=list)
    providers: ProvidersConfig
    virustotal: VirusTotalConfig
    abuseipdb: AbuseIpdbConfig
    otx: OtxConfig
    shodan: ShodanConfig
    asn: AsnConfig
    domain_age: DomainAgeConfig
    vt_categories: VtCategoriesConfig
    certificate: CertificateConfig
    overrides: OverridesConfig
    contradictions: ContradictionsConfig

    #: Where this ruleset was loaded from: ``explicit``, ``environment``, ``user`` or
    #: ``packaged``. Set by the loader and rejected as an input key -- "the operator has a stale
    #: override in their home directory" must not be an unfalsifiable explanation for a
    #: surprising verdict.
    source_origin: str = "packaged"
    source_label: str = f"package:tripper_recon.verdict/{PACKAGED_CONFIG_NAME}"

    # -- pre-validation ------------------------------------------------------------------

    @model_validator(mode="before")
    @classmethod
    def _reject_injected_provenance_and_name_typos(cls, data: Any) -> Any:
        """Give an actionable message for the two mistakes pydantic reports opaquely.

        An unknown key under ``signals:`` otherwise surfaces as an enum coercion failure on a
        dict key, which does not tell the author which name they misspelled or what the valid
        names are. And a ruleset file must not be able to claim it came from somewhere it did not.
        """
        if not isinstance(data, Mapping):
            return data
        injected = [key for key in ("source_origin", "source_label") if key in data]
        if injected:
            raise ValueError(f"{', '.join(injected)} is set by the loader and must not appear in a ruleset file.")
        signals = data.get("signals")
        if isinstance(signals, Mapping):
            known = {member.value for member in SignalId}
            unknown = sorted(str(key) for key in signals if str(key) not in known)
            if unknown:
                raise ValueError(
                    f"unknown signal id(s): {', '.join(unknown)}. Known signals: "
                    f"{', '.join(sorted(known))}. Weighting a signal no extractor implements is a "
                    "config that looks active and is not."
                )
        return data

    # -- coherence -----------------------------------------------------------------------

    @model_validator(mode="after")
    def _coherent(self) -> ScoringConfig:
        """Every cross-section rule. Each raises with the reason, not just the rule name."""
        self._check_bands()
        self._check_decay_profiles()
        self._check_families()
        self._check_signal_wiring()
        self._check_reachability()
        self._check_sub_point_ceilings()
        self._check_profile_references()
        self._check_overrides()
        return self

    def _check_bands(self) -> None:
        labels = [band.label for band in self.bands]
        duplicates = sorted({label.value for label in labels if labels.count(label) > 1})
        if duplicates:
            raise ValueError(f"duplicate verdict band label(s): {', '.join(duplicates)}")

        unreachable = sorted(label.value for label in labels if label not in SCORE_REACHABLE_LABELS)
        if unreachable:
            raise ValueError(
                f"verdict band(s) {', '.join(unreachable)} are not score-reachable. "
                "INSUFFICIENT_DATA comes from the coverage floor and KNOWN_INFRASTRUCTURE only "
                "from the Tier A allowlist; neither may be earned by a score."
            )

        for upper, lower in zip(self.bands, self.bands[1:], strict=False):
            if upper.min_score <= lower.min_score:
                raise ValueError(
                    f"verdict bands overlap: {upper.label.value} at min_score {upper.min_score} is "
                    f"not above {lower.label.value} at {lower.min_score}. Bands must be strictly "
                    "descending so every score maps to exactly one label."
                )

        if self.bands[-1].min_score != self.score.clamp_min:
            raise ValueError(
                f"the lowest verdict band must sit at score.clamp_min ({self.score.clamp_min}); "
                f"{self.bands[-1].label.value} starts at {self.bands[-1].min_score}, leaving scores "
                "below it with no label."
            )
        if self.bands[0].min_score > self.score.clamp_max:
            raise ValueError(
                f"the top band {self.bands[0].label.value} starts at {self.bands[0].min_score}, "
                f"above score.clamp_max ({self.score.clamp_max}); it can never be reached."
            )
        if self.bands[0].label is not VerdictLabelName.MALICIOUS:
            raise ValueError(f"the top verdict band must be MALICIOUS, got {self.bands[0].label.value}")
        if self.bands[-1].label is not VerdictLabelName.NO_ADVERSE_FINDINGS:
            raise ValueError(f"the floor verdict band must be NO_ADVERSE_FINDINGS, got {self.bands[-1].label.value}")

    def _check_decay_profiles(self) -> None:
        if not self.decay_profiles:
            raise ValueError("decay_profiles must define at least one profile")
        for name, bands in self.decay_profiles.items():
            if not bands:
                raise ValueError(f"decay profile '{name}' is empty")
            open_ended = [index for index, band in enumerate(bands) if band.max_age_days is None]
            if len(open_ended) != 1 or open_ended[0] != len(bands) - 1:
                raise ValueError(
                    f"decay profile '{name}' must end with exactly one open-ended band "
                    "(max_age_days: null); otherwise an observation older than the last band has "
                    "no factor and the caller has to invent one."
                )
            ages = [band.max_age_days for band in bands[:-1]]
            for older, newer in zip(ages, ages[1:], strict=False):
                if older is None or newer is None or older >= newer:
                    raise ValueError(f"decay profile '{name}' has non-ascending max_age_days: {ages}")
            factors = [band.factor for band in bands]
            for fresher, staler in zip(factors, factors[1:], strict=False):
                if staler > fresher:
                    raise ValueError(
                        f"decay profile '{name}' has a factor that rises with age ({fresher} then "
                        f"{staler}). Older evidence may never weigh more than fresher evidence."
                    )

    def _check_families(self) -> None:
        seen: Dict[str, str] = {}
        for family, members in self.provider_families.items():
            if not members:
                raise ValueError(f"provider family '{family}' has no members")
            for provider in members:
                if provider in seen:
                    raise ValueError(
                        f"provider '{provider}' appears in families '{seen[provider]}' and "
                        f"'{family}'. Families are the independence model; a provider in two of "
                        "them would corroborate itself."
                    )
                seen[provider] = family
        undeclared = sorted(set(seen) - self.providers.known)
        if undeclared:
            raise ValueError(
                f"provider_families names provider(s) not listed under providers.implemented or "
                f"providers.planned: {', '.join(undeclared)}"
            )
        unknown_families = sorted(set(self.non_corroborating_families) - set(self.provider_families))
        if unknown_families:
            raise ValueError(f"non_corroborating_families names undeclared families: {', '.join(unknown_families)}")

    def _check_signal_wiring(self) -> None:
        for signal_id, signal in self.signals.items():
            members = self.provider_families.get(signal.family)
            if members is None:
                raise ValueError(
                    f"signal '{signal_id.value}' declares family '{signal.family}', which is not in provider_families"
                )
            stray = sorted(set(signal.providers) - set(members))
            if stray:
                raise ValueError(
                    f"signal '{signal_id.value}' lists provider(s) {', '.join(stray)} that are not "
                    f"in its declared family '{signal.family}'. Corroboration counts families, so a "
                    "signal drawing on a provider outside its family would be counted under the "
                    "wrong one."
                )

    def _check_reachability(self) -> None:
        malicious_min = self.bands[0].min_score
        for scope in IndicatorScope:
            applicable = [signal for signal in self.signals.values() if signal.enabled and scope in signal.applies_to]
            if not applicable:
                # A scope with no signals is not yet implemented (url, asn today). That is a
                # missing feature, not an incoherent config, and failing here would block the
                # ruleset on work that has not started.
                continue
            total = sum(signal.max_points for signal in applicable)
            if total < malicious_min:
                raise ValueError(
                    f"the enabled signals for scope '{scope.value}' sum to {total} points, below the "
                    f"MALICIOUS band at {malicious_min}. The band is unreachable, so the engine "
                    "could never return MALICIOUS for that indicator type."
                )
            if self.verdict_rules.require_corroboration_for_malicious:
                overweight = sorted(
                    signal_id.value
                    for signal_id, signal in self.signals.items()
                    if signal.enabled and scope in signal.applies_to and signal.max_points >= malicious_min
                )
                if overweight:
                    raise ValueError(
                        f"signal(s) {', '.join(overweight)} can reach the MALICIOUS band at "
                        f"{malicious_min} alone, while verdict_rules."
                        "require_corroboration_for_malicious is true. Lower the weight or turn the "
                        "requirement off deliberately."
                    )

    def _check_sub_point_ceilings(self) -> None:
        """Sub-check points must fit inside the signal ceiling they roll up to."""
        checks: Sequence[Tuple[SignalId, float, str]] = (
            (SignalId.CERT_ANOMALY, self.certificate.total_points, "certificate sub-checks"),
            (
                SignalId.DOMAIN_AGE,
                max([band.points for band in self.domain_age.bands] + [self.domain_age.unknown_points]),
                "domain_age bands",
            ),
            (SignalId.SHODAN_EXPOSURE, self.shodan.max_points_from_cves, "shodan.max_points_from_cves"),
            (SignalId.ASN_REPUTATION, self.asn.points_if_bulletproof, "asn.points_if_bulletproof"),
        )
        for signal_id, sub_total, label in checks:
            signal = self.signals.get(signal_id)
            if signal is None or not signal.enabled:
                continue
            if sub_total > signal.max_points:
                raise ValueError(
                    f"{label} total {sub_total} exceeds signals['{signal_id.value}'].max_points "
                    f"({signal.max_points}); the signal could emit more than its own ceiling."
                )
        self._check_domain_age_bands()

    def _check_domain_age_bands(self) -> None:
        bands = self.domain_age.bands
        open_ended = [index for index, band in enumerate(bands) if band.max_age_days is None]
        if len(open_ended) != 1 or open_ended[0] != len(bands) - 1:
            raise ValueError("domain_age.bands must end with exactly one open-ended band (max_age_days: null)")
        ages = [band.max_age_days for band in bands[:-1]]
        for younger, older in zip(ages, ages[1:], strict=False):
            if younger is None or older is None or younger >= older:
                raise ValueError(f"domain_age.bands has non-ascending max_age_days: {ages}")
        points = [band.points for band in bands]
        for younger_points, older_points in zip(points, points[1:], strict=False):
            if older_points > younger_points:
                raise ValueError(
                    f"domain_age.bands awards more points to an older band ({younger_points} then "
                    f"{older_points}). Age is adverse in one direction only -- an old domain is not "
                    "clean, it is compromise-eligible, and it never earns a discount."
                )

    def _check_profile_references(self) -> None:
        references = (
            ("virustotal.recency_profile", self.virustotal.recency_profile),
            ("abuseipdb.recency_profile", self.abuseipdb.recency_profile),
            ("otx.recency_profile", self.otx.recency_profile),
            ("shodan.recency_profile", self.shodan.recency_profile),
        )
        for key, profile in references:
            if profile not in self.decay_profiles:
                raise ValueError(
                    f"{key} refers to decay profile '{profile}', which is not defined. Available: "
                    f"{', '.join(sorted(self.decay_profiles))}"
                )

    def _check_overrides(self) -> None:
        implemented = frozenset(self.providers.implemented)

        for escalation_rule in self.overrides.escalation.rules:
            if not escalation_rule.enabled:
                continue
            missing = sorted(set(escalation_rule.requires_providers) - implemented)
            if missing:
                raise ValueError(
                    f"escalation rule '{escalation_rule.id}' is enabled but requires provider(s) "
                    f"{', '.join(missing)} that this package has not implemented. A rule that can "
                    "never fire reads to a maintainer as an active control; set enabled: false."
                )
            if escalation_rule.requires_high_confidence_engines and not self.virustotal.high_confidence_engines:
                raise ValueError(
                    f"escalation rule '{escalation_rule.id}' is enabled and depends on "
                    "virustotal.high_confidence_engines, which is empty. The rule is inert; set "
                    "enabled: false until the list is populated from a corpus."
                )

        for vendor_rule in self.overrides.tier_c.rules:
            if vendor_rule.enabled and vendor_rule.provider not in implemented:
                raise ValueError(
                    f"tier_c rule '{vendor_rule.id}' is enabled but reads unimplemented provider "
                    f"'{vendor_rule.provider}'"
                )

        ids = [rule.id for tier in (self.overrides.tier_a, self.overrides.tier_b) for rule in tier.rules]
        ids += [rule.id for rule in self.overrides.tier_c.rules]
        ids += [rule.id for rule in self.overrides.escalation.rules]
        duplicates = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
        if duplicates:
            raise ValueError(
                f"duplicate override rule id(s): {', '.join(duplicates)}. Rule ids are recorded in "
                "the verdict so an analyst can defend the call; two rules sharing one is "
                "unauditable."
            )

    # -- accessors -----------------------------------------------------------------------

    @property
    def malicious_threshold(self) -> int:
        """The lowest score reaching the top band."""
        return self.bands[0].min_score

    @property
    def suspicious_threshold(self) -> int:
        """The lowest score reaching the second band, or the top band in a two-band ruleset."""
        return self.bands[1].min_score if len(self.bands) > 1 else self.bands[0].min_score

    def band_for_score(self, score: float) -> VerdictLabelName:
        """The score-reachable label for ``score``.

        Callers must still apply the coverage floor and the override tiers: this answers "what do
        the points say", never "what is the verdict". A score alone cannot produce
        NO_ADVERSE_FINDINGS -- see ``verdict_rules.require_affirmative_negative``.
        """
        clamped = max(self.score.clamp_min, min(self.score.clamp_max, score))
        for band in self.bands:
            if clamped >= band.min_score:
                return band.label
        return self.bands[-1].label

    def signals_for(self, scope: IndicatorScope, *, enabled_only: bool = True) -> Dict[SignalId, SignalConfig]:
        """The signals that apply to one indicator type, in declaration order."""
        return {
            signal_id: signal
            for signal_id, signal in self.signals.items()
            if scope in signal.applies_to and (signal.enabled or not enabled_only)
        }

    def family_of(self, provider: str) -> Optional[str]:
        """The declared family for a provider name, or ``None`` if it is not in the map."""
        for family, members in self.provider_families.items():
            if provider in members:
                return family
        return None

    def counts_toward_corroboration(self, family: str) -> bool:
        """Whether a family may count as an independent corroborating source."""
        return family in self.provider_families and family not in self.non_corroborating_families

    def decay_factor(self, profile: str, age_days: Optional[float]) -> float:
        """The multiplier for an observation ``age_days`` old under a named profile.

        An unknown age returns :attr:`undated_evidence`'s factor, **not** the profile's
        open-ended tail. Taking the tail looks like the cautious reading and is the opposite of
        one: decay only ever multiplies adverse points, so discounting an undated observation
        moves the indicator toward clean on the strength of a missing metadata field. See
        :class:`UndatedEvidenceConfig` for the measurement behind that.
        """
        bands = self.decay_profiles.get(profile)
        if bands is None:
            raise ScoringConfigError(f"unknown decay profile {profile!r}")
        if age_days is None:
            return self.undated_evidence.factor
        age = max(0.0, float(age_days))
        for band in bands:
            if band.max_age_days is None or age <= band.max_age_days:
                return band.factor
        return bands[-1].factor

    def weight_source(self, signal_id: SignalId) -> str:
        """The ``Signal.weight_source`` string: which file and key set this signal's ceiling."""
        return f"{self.source_label}#signals.{signal_id.value}"


# --------------------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------------------


def _user_config_path(env: Mapping[str, str]) -> Path:
    """``$XDG_CONFIG_HOME/tripper_recon/scoring.yaml``, falling back to ``~/.config``."""
    xdg = env.get("XDG_CONFIG_HOME", "").strip()
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / USER_CONFIG_SUBDIR / PACKAGED_CONFIG_NAME


def _packaged_text() -> str:
    """Read the in-package default, preferring the real file so the label is a usable path."""
    beside = Path(__file__).with_name(PACKAGED_CONFIG_NAME)
    if beside.is_file():
        return beside.read_text(encoding="utf-8")
    try:
        return (resources.files(__package__) / PACKAGED_CONFIG_NAME).read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError) as exc:
        raise ScoringConfigError(
            f"the packaged {PACKAGED_CONFIG_NAME} is missing. It is package data and needs an "
            "explicit setuptools package-data entry to survive an install; see the interface "
            f"notes for roadmap 5.2. ({exc})"
        ) from exc


def resolve_config_source(
    path: Optional[Path] = None,
    *,
    env: Optional[Mapping[str, str]] = None,
) -> Tuple[str, str, str]:
    """Resolve the ruleset to load, returning ``(origin, label, text)``.

    Precedence, highest first: the ``path`` argument, ``$TRIPPER_RECON_SCORING_CONFIG``, the user
    override directory, then the packaged default. Only the last is allowed to be absent -- an
    explicitly named file that does not exist is an error, never a silent fallback, because
    falling back would score an indicator under a ruleset the operator did not choose.
    """
    environ = os.environ if env is None else env

    if path is not None:
        candidate = Path(path).expanduser()
        if not candidate.is_file():
            raise ScoringConfigError(f"scoring config not found at the requested path: {candidate}")
        return "explicit", str(candidate), candidate.read_text(encoding="utf-8")

    from_env = environ.get(CONFIG_ENV_VAR, "").strip()
    if from_env:
        candidate = Path(from_env).expanduser()
        if not candidate.is_file():
            raise ScoringConfigError(f"{CONFIG_ENV_VAR} points at a file that does not exist: {candidate}")
        return "environment", str(candidate), candidate.read_text(encoding="utf-8")

    user = _user_config_path(environ)
    if user.is_file():
        return "user", str(user), user.read_text(encoding="utf-8")

    return "packaged", f"package:{__package__}/{PACKAGED_CONFIG_NAME}", _packaged_text()


def _parse_yaml(text: str, label: str) -> Mapping[str, Any]:
    """``yaml.safe_load`` only. A ruleset is data and must never construct Python objects."""
    if yaml is None:
        raise ScoringConfigError(
            "PyYAML is required to load a scoring ruleset and is not installed. It is not yet "
            "declared in pyproject.toml; add 'pyyaml>=6.0' to [project] dependencies."
        )
    try:
        parsed = yaml.safe_load(text)
    except Exception as exc:  # yaml.YAMLError, but the guarded import makes the name conditional
        raise ScoringConfigError(f"{label}: not valid YAML: {exc}") from exc
    if parsed is None:
        raise ScoringConfigError(f"{label}: the ruleset is empty")
    if not isinstance(parsed, Mapping):
        raise ScoringConfigError(f"{label}: the ruleset must be a mapping, got {type(parsed).__name__}")
    return parsed


def load_scoring_config(
    path: Optional[Path] = None,
    *,
    env: Optional[Mapping[str, str]] = None,
) -> ScoringConfig:
    """Load, parse and validate a ruleset.

    Raises :class:`ScoringConfigError` for every failure -- missing file, unparseable YAML, or a
    config that does not cohere. There is deliberately no partial-load or best-effort mode: an
    engine running on a ruleset it could not fully validate produces verdicts nobody can defend,
    and a hard stop is the only honest behaviour.
    """
    origin, label, text = resolve_config_source(path, env=env)
    payload = dict(_parse_yaml(text, label))
    try:
        config = ScoringConfig.model_validate(payload)
    except ValidationError as exc:
        raise ScoringConfigError(f"{label}: invalid scoring config\n{exc}") from exc
    except ValueError as exc:  # raised directly by the before-validator
        raise ScoringConfigError(f"{label}: invalid scoring config: {exc}") from exc
    return config.model_copy(update={"source_origin": origin, "source_label": label})


@lru_cache(maxsize=1)
def default_config() -> ScoringConfig:
    """The ruleset for this process, resolved once by :func:`load_scoring_config`.

    Cached because the config is immutable and every signal extractor takes it as an argument.
    Call :func:`clear_config_cache` in a test that changes the environment or writes an override.
    """
    return load_scoring_config()


def clear_config_cache() -> None:
    """Drop the :func:`default_config` cache."""
    default_config.cache_clear()
