"""The verdict object (roadmap 5.1): what the engine concluded and why.

A verdict is a *record*, not a rendering. Everything an analyst needs to defend the call six
months later has to be reconstructable from the serialised form alone: the signals that
contributed, what each was worth and where its weight came from, the providers that never
answered, the disagreements nobody resolved, the allowlist entry that suppressed a score and when
that list was last fetched, and the ruleset version the whole thing was computed under. A verdict
whose reasoning lives only in the console output is not defensible.

Three structural rules are enforced here rather than left to the engine, because a model is the
one place a hand-constructed object cannot route around:

* **A benign verdict requires an affirmative negative and nothing adverse.**
  ``NO_ADVERSE_FINDINGS`` is rejected unless coverage cleared the floor that was in force, at
  least one provider was asked and reported nothing adverse, and no signal carries adverse
  points. "Nobody answered" and "everybody answered clean" produce the same zero score, and only
  one of them is evidence; and adverse evidence too thin to reach the ``SUSPICIOUS`` band is
  still adverse evidence, so the label -- which is a statement about what the panel reported --
  would be false.
* **Only an allowlist can produce ``KNOWN_INFRASTRUCTURE``.** The label is rejected without a
  Tier A override record behind it, so the one state that means "this is fine" is always
  traceable to a curated list entry with a citation and a retrieval date.
* **A top-band verdict at ``LOW`` confidence is flagged for review.** The engine normally demotes
  it (``verdict_rules.demote_malicious_when_confidence_low``); a ruleset that switches the
  demotion off may still not produce an unflagged ``MALICIOUS`` that the panel cannot stand
  behind.

Naming. ``NO_ADVERSE_FINDINGS`` is deliberately not ``BENIGN``. Six feeds agreeing they have
never seen an indicator is exactly what a purpose-built C2 domain looks like on its first day;
what the tool actually knows is what the panel said, and the label says that and nothing more.

Vocabulary reuse rather than redefinition. :data:`VerdictLabel` and :data:`Confidence` are
aliases of the enums the ruleset loader already validates against
(:class:`~tripper_recon.verdict.config.VerdictLabelName`,
:class:`~tripper_recon.verdict.config.ConfidenceBand`), and :class:`Signal` is re-exported from
:mod:`tripper_recon.verdict.signals`. Each of those is defined exactly once in the package. When
the extractor lane next touches ``signals.py`` the :class:`Signal` definition should move here
and ``signals.py`` should import it; until then, importing it *from* here keeps the single
definition intact instead of creating a second one that can drift.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator, model_validator

from tripper_recon.types.models import Coverage
from tripper_recon.verdict.config import SCORE_REACHABLE_LABELS, ConfidenceBand, VerdictLabelName
from tripper_recon.verdict.signals import AFFIRMATIVE_NEGATIVE_SIGNAL_IDS, Signal, SignalDirection

__all__ = [
    "AllowlistProvenance",
    "Confidence",
    "ConfidenceCriterion",
    "Contradiction",
    "OverrideApplied",
    "Signal",
    "SignalDirection",
    "VERDICT_SCHEMA_VERSION",
    "Verdict",
    "VerdictLabel",
    "cap_label",
    "confidence_rank",
    "demote_label",
    "is_score_reachable",
    "severity_rank",
    "weaken_confidence",
    "weakest_confidence",
]

#: The five verdict states. An alias, not a second enum: the ruleset loader validates band labels
#: and override targets against this same type, so the wire strings cannot drift apart.
VerdictLabel = VerdictLabelName

#: The three confidence bands, likewise aliased from the ruleset vocabulary.
Confidence = ConfidenceBand

#: Bumped when the *shape* of :class:`Verdict` changes. Distinct from ``ruleset_version`` (which
#: tuning changes) and from ``engine_version`` (which algorithm changes). A consumer parsing an
#: archived verdict reads this to know which fields it can expect.
VERDICT_SCHEMA_VERSION = "1.0"

#: Confidence bands strongest first, taken from the enum's declaration order rather than restated,
#: so there is one place the ordering lives.
CONFIDENCE_ORDER: Tuple[ConfidenceBand, ...] = tuple(ConfidenceBand)


def confidence_rank(band: ConfidenceBand) -> int:
    """Position in :data:`CONFIDENCE_ORDER`. Lower is stronger."""
    return CONFIDENCE_ORDER.index(band)


def weakest_confidence(*bands: ConfidenceBand) -> ConfidenceBand:
    """The weakest of the given bands.

    Used wherever two rules both have an opinion. Confidence is a claim about how much the panel
    supports the answer, so where two rules disagree the tool asserts the smaller claim.
    """
    if not bands:
        raise ValueError("weakest_confidence needs at least one band")
    return max(bands, key=confidence_rank)


def weaken_confidence(band: ConfidenceBand, steps: int = 1) -> ConfidenceBand:
    """Move ``band`` down the ladder, floored at ``LOW``."""
    index = min(confidence_rank(band) + max(steps, 0), len(CONFIDENCE_ORDER) - 1)
    return CONFIDENCE_ORDER[index]


def is_score_reachable(label: VerdictLabelName) -> bool:
    """Whether a score alone can produce this label.

    ``INSUFFICIENT_DATA`` comes from the coverage floor and ``KNOWN_INFRASTRUCTURE`` only from the
    Tier A allowlist. Neither participates in the cap-and-demote arithmetic below, which is why
    every helper here refuses them rather than ordering them.
    """
    return label in SCORE_REACHABLE_LABELS


def severity_rank(label: VerdictLabelName) -> int:
    """Position in ``SCORE_REACHABLE_LABELS``, most severe first.

    Raises for a label no score can reach: comparing ``KNOWN_INFRASTRUCTURE`` against
    ``SUSPICIOUS`` has no defensible answer, and inventing one is how an allowlisted resolver
    ends up demoted by a cap.
    """
    if not is_score_reachable(label):
        raise ValueError(
            f"{label.value} is not score-reachable and has no severity rank. Only "
            f"{', '.join(item.value for item in SCORE_REACHABLE_LABELS)} are ordered."
        )
    return SCORE_REACHABLE_LABELS.index(label)


def cap_label(label: VerdictLabelName, ceiling: VerdictLabelName) -> VerdictLabelName:
    """``label``, lowered to ``ceiling`` when it is above it. Never raises a verdict.

    A cap that could raise a verdict would let a CDN membership *add* severity, which inverts the
    reason Tier B exists.
    """
    if not is_score_reachable(label):
        return label
    return label if severity_rank(label) >= severity_rank(ceiling) else ceiling


def demote_label(label: VerdictLabelName, *, floor: VerdictLabelName) -> VerdictLabelName:
    """One step down the severity ladder, never below ``floor``.

    ``floor`` exists because demotion must never manufacture a clean answer. A contradiction
    between two providers is a reason to look harder, not a reason to clear an indicator, and a
    demotion chain that could reach ``NO_ADVERSE_FINDINGS`` would turn disagreement into
    exculpation.
    """
    if not is_score_reachable(label):
        return label
    index = min(severity_rank(label) + 1, severity_rank(floor))
    return SCORE_REACHABLE_LABELS[index]


def _rfc3339(value: dt.datetime) -> str:
    """RFC 3339 in UTC with a ``Z`` designator, which ``isoformat()`` renders as ``+00:00``."""
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


class _Record(BaseModel):
    """``extra="forbid"`` for every model here.

    A verdict is archived and read back. A typo'd key that pydantic silently accepts today is a
    field a future reader looks for and does not find, with nothing in between to say it was ever
    misspelled.
    """

    model_config = ConfigDict(extra="forbid")


class Contradiction(_Record):
    """Two sources disagreeing, reported rather than reconciled.

    The score keeps its full value. Averaging VirusTotal's five detections with AbuseIPDB's 0%
    confidence produces a number describing neither provider, and the analyst loses the one fact
    that actually directs the next step: that the panel is split, and which way each half points.
    """

    #: A ``ContradictionRuleId`` value for the config-driven rules, or an engine-structural id.
    rule_id: str
    #: One sentence naming both sides, for the console and the ticket.
    summary: str
    #: The adverse side: a :attr:`Signal.id`, or an override rule id where the conflict is with a
    #: list rather than with a provider.
    left: str
    #: The exculpatory or contradicting side, same convention.
    right: str
    #: What the analyst should do about it. Required at the config level: a flag with no hint is
    #: a nag.
    analyst_hint: str
    #: True only when *both* sides are scored signals at or above the ruleset's materiality
    #: fraction. Only then does the contradiction demote the verdict; otherwise it caps confidence
    #: and flags review, which is the weaker and far more common case.
    both_material: bool = False


class OverrideApplied(_Record):
    """One override that actually changed the outcome, with its provenance.

    Only applied effects are recorded. A catalogue entry that matched but whose tier does not act
    on this indicator type is visible in the match list on the decision object and is not an
    override, because reporting it as one would suggest a suppression that never happened.
    """

    rule_id: str
    #: ``A`` / ``B`` / ``C`` for catalogue tiers, ``escalation`` for a ruleset escalation rule.
    tier: str
    #: ``verdict_forced`` | ``verdict_capped`` | ``signal_zeroed`` | ``signal_suppressed`` |
    #: ``confidence_demoted``.
    effect: str
    source_list: Optional[str] = None
    #: When the list behind this rule was last fetched. The field that makes a stale suppression
    #: detectable instead of invisible.
    source_retrieved_at: Optional[str] = None
    note: Optional[str] = None


class AllowlistProvenance(_Record):
    """Which allowlist answered, when it was fetched, and whether that was too long ago."""

    list_version: str
    list_retrieved: str
    stale: bool
    #: Written whether the list is stale or not. A reader who only ever sees the sentence on a
    #: stale list has no way to calibrate what its absence means.
    staleness_note: str


class ConfidenceCriterion(_Record):
    """One named, config-derived question the confidence calculation asked.

    These exist so :attr:`Verdict.confidence_score` is reconstructable. A bare 0.66 is an
    assertion; the list of criteria that produced it is an argument.
    """

    name: str
    met: bool
    detail: str


class Verdict(_Record):
    """One adjudicated answer about one indicator.

    Read :attr:`verdict` with :attr:`confidence` beside it, never alone. "Score 71, confidence
    LOW, 2 of 6 providers answered" is a real and common state and the two axes are computed
    independently: the score says how much adverse evidence turned up, the confidence says how
    much of the panel was heard from and whether it agreed.

    The engine makes no claim about how often it is right. The weights behind
    :attr:`score` are informed priors and nothing has been measured against a held-out set;
    :attr:`calibration_statement` carries the ruleset's own words on that into every verdict, so
    the caveat travels with the artefact instead of living in a README nobody pastes.
    """

    schema_version: str = VERDICT_SCHEMA_VERSION

    indicator: str
    #: ``ip`` | ``domain`` | ``url`` | ``asn``: the ``IndicatorScope`` this was scored under.
    indicator_type: str

    #: The answer. Five states; see the module docstring on why the clean one is not "benign".
    verdict: VerdictLabel
    #: Clamped to the ruleset's score bounds. The number an analyst quotes.
    score: int = Field(ge=0)
    #: Pre-clamp sum, so ceiling saturation stays visible: 140 points and 100 points are different
    #: findings that clamp to the same score.
    raw_score: float = Field(ge=0.0)
    #: The label the points alone reached, before any override, cap or adjustment.
    score_band: VerdictLabel
    #: The label the engine started from when :attr:`verdict` is not what the score said. Almost
    #: always a demotion; the one adjustment that goes the other way is the clean label being
    #: unavailable because a provider did report something adverse.
    adjusted_from: Optional[VerdictLabel] = None
    #: Why, in order of application. Empty when the score band stood.
    adjustment_reasons: List[str] = Field(default_factory=list)

    confidence: Confidence
    #: The fraction of :attr:`confidence_criteria` that were met. A transparency aid for ordering
    #: and diffing verdicts -- **not** a probability, and not a claim that the answer is right
    #: this often. :attr:`confidence` is the axis to act on.
    confidence_score: float = Field(ge=0.0, le=1.0)
    confidence_criteria: List[ConfidenceCriterion] = Field(default_factory=list)

    #: Who answered and who did not, by name. The negative space is the point.
    coverage: Coverage
    #: The floor in force when this verdict was computed, so the coverage decision stays
    #: interpretable after the ruleset is retuned.
    coverage_floor: float = Field(ge=0.0, le=1.0)
    #: Distinct provider families supporting the conclusion: the families carrying adverse
    #: evidence, or -- where there is none -- the families that were asked and affirmatively
    #: reported nothing. Families, never providers: two feeds re-ingesting one upstream is one
    #: observation wearing two hats.
    corroborating_families: List[str] = Field(default_factory=list)

    signals: List[Signal] = Field(default_factory=list)
    contradictions: List[Contradiction] = Field(default_factory=list)
    overrides_applied: List[OverrideApplied] = Field(default_factory=list)
    allowlist: Optional[AllowlistProvenance] = None

    requires_analyst_review: bool = False
    attribution_warning: Optional[str] = None

    #: One line for the ticket.
    summary: str
    #: The reasoning, ordered: the decision, the coverage, then each signal by contribution.
    rationale: List[str] = Field(default_factory=list)

    #: False when any evidence behind this verdict came from touching the target's own
    #: infrastructure. A verdict built partly on active collection is a different artefact --
    #: legally, operationally, and in terms of what it told the adversary -- and the analyst must
    #: see which one they are holding before it goes in a report.
    passive_only: bool = True
    #: The active steps that contributed, by name, e.g. ``system_dns_resolution``.
    active_collection: List[str] = Field(default_factory=list)

    #: ``scoring.yaml``'s ``version``. Two verdicts under different tunings are different claims.
    ruleset_version: str
    #: Which file that version was loaded from, so a stale override in a home directory is not an
    #: unfalsifiable explanation for a surprising verdict.
    ruleset_source: str
    #: The ruleset's own statement of what stands behind its numbers.
    calibration_statement: str
    engine_version: str
    evaluated_at: dt.datetime

    @field_validator("evaluated_at")
    @classmethod
    def _require_aware_utc(cls, value: dt.datetime) -> dt.datetime:
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            raise ValueError("evaluated_at must be timezone-aware; a naive datetime has no defensible meaning")
        return value.astimezone(dt.timezone.utc)

    @field_serializer("evaluated_at")
    def _serialise_evaluated_at(self, value: dt.datetime) -> str:
        return _rfc3339(value)

    @model_validator(mode="after")
    def _absent_data_never_scores_as_clean(self) -> Verdict:
        """The three structural rules from the module docstring, enforced on construction."""
        if self.verdict is VerdictLabel.NO_ADVERSE_FINDINGS:
            if not self.coverage.is_sufficient(self.coverage_floor):
                raise ValueError(
                    f"NO_ADVERSE_FINDINGS with coverage {self.coverage.headline} below the floor "
                    f"{self.coverage_floor}. Below the floor the honest label is INSUFFICIENT_DATA: "
                    "a panel that was not heard from has not reported anything clean."
                )
            if not self.affirmative_negatives:
                raise ValueError(
                    "NO_ADVERSE_FINDINGS with no affirmative negative among the signals. A clean "
                    "verdict requires a provider that was asked and answered -- 'VirusTotal holds a "
                    "record and no engine flags it' is evidence; a failed call, a missing key and a "
                    "404 are not."
                )
            reported = [signal.id for signal in self.adverse_signals]
            if reported:
                raise ValueError(
                    f"NO_ADVERSE_FINDINGS while {', '.join(reported)} carr(y) adverse points. The "
                    "label is a statement about what the panel reported, and a provider did report "
                    "something. Evidence too thin to reach the SUSPICIOUS band is still evidence, "
                    "and printing it green is the failure this workstream exists to remove."
                )
        if self.verdict is VerdictLabel.KNOWN_INFRASTRUCTURE and not self.forced_by_allowlist:
            raise ValueError(
                "KNOWN_INFRASTRUCTURE without a Tier A override record. The only state that means "
                "'this is fine' must always be traceable to a curated list entry with a citation."
            )
        if (
            self.verdict is VerdictLabel.MALICIOUS
            and self.confidence is Confidence.LOW
            and not self.requires_analyst_review
        ):
            raise ValueError(
                "MALICIOUS at LOW confidence without requires_analyst_review. The engine normally "
                "renders this as SUSPICIOUS with the raw score beside it; a ruleset that disables "
                "the demotion may still not emit a top-band verdict the panel cannot stand behind "
                "without telling the analyst to look."
            )
        return self

    @property
    def affirmative_negatives(self) -> List[Signal]:
        """Signals that constitute "asked, and reported nothing adverse".

        An empty signal list is not an affirmative negative, and neither is a provider that
        errored. This is the list the clean verdict is gated on.
        """
        return [signal for signal in self.signals if signal.id in AFFIRMATIVE_NEGATIVE_SIGNAL_IDS]

    @property
    def adverse_signals(self) -> List[Signal]:
        """Signals that reported something against the indicator and were worth points.

        Direction and points are independent axes, so this is deliberately both conditions: a
        context signal worth ten points describes what the host is, and an adverse signal worth
        zero was zeroed by an override and no longer counts against it.
        """
        return [
            signal for signal in self.signals if signal.direction is SignalDirection.ADVERSE and signal.points > 0.0
        ]

    @property
    def forced_by_allowlist(self) -> bool:
        """Whether a Tier A allowlist entry produced this verdict."""
        return any(
            override.tier.strip().upper() == "A" and override.effect == "verdict_forced"
            for override in self.overrides_applied
        )

    @property
    def scored_signals(self) -> List[Signal]:
        """Signals that contributed points, ordered by contribution."""
        return sorted(
            (signal for signal in self.signals if signal.points > 0.0),
            key=lambda signal: signal.points,
            reverse=True,
        )

    @property
    def evaluated_at_rfc3339(self) -> str:
        """The evaluation timestamp as ``2026-08-08T14:03:11Z``."""
        return _rfc3339(self.evaluated_at)

    def top_signals(self, limit: int) -> List[Signal]:
        """The ``limit`` highest-contribution signals, for a console that cannot show them all."""
        return self.scored_signals[:limit]

    def to_json_dict(self) -> Dict[str, Any]:
        """A JSON-ready dict, the same shape ``-o json`` emits."""
        return self.model_dump(mode="json")
