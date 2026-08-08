"""The verdict engine (roadmap 5.1, 5.4, 5.5, 5.7, 5.10): signals in, one defensible answer out.

The tool has always collected and rendered. It printed VirusTotal red when ``malicious > 0`` and
AbuseIPDB green when its confidence score was ``0``, on the same screen, and left the analyst to
arbitrate between them under time pressure. This module is the arbitration.

**It is a pure function of (signals, coverage, ruleset, now).** No clock read, no file read, no
network, no global state. The allowlist decision and the ruleset are loaded by the caller and
passed in. That is what makes the whole thing exhaustively testable offline, and what lets a
saved case be re-scored months later under the ruleset that produced the original answer.

Four rules bind every line here, and they are absolute because a confident wrong verdict is
acted on:

1. **Absent data never scores as clean.** A provider that was not asked, failed, or has no key
   contributes nothing toward a benign conclusion. ``NO_ADVERSE_FINDINGS`` requires coverage
   above the floor, an affirmative negative, *and* nothing adverse reported at all -- evidence
   too thin to reach the ``SUSPICIOUS`` band is still evidence. ``KNOWN_INFRASTRUCTURE`` requires
   an allowlist entry. The engine can earn its way up to ``MALICIOUS`` and can never earn its way
   down to safe.
2. **Confidence is a separate axis from score.** It is computed without reference to the score,
   and it is forced ``LOW`` whenever coverage is below ``confidence.coverage_floor`` -- whatever
   else agrees. A top-band score at ``LOW`` confidence renders as ``SUSPICIOUS`` with the raw
   score beside it, so the analyst sees the strength and the discount as two separate facts.
3. **No invented numbers.** Every weight, threshold, decay constant, band and materiality
   fraction is read from the ruleset. There is not one scoring constant in this file, and
   ``ruleset_version`` plus ``ruleset_source`` are stamped into every verdict so a six-month-old
   ticket stays interpretable.
4. **Contradictions are surfaced, never averaged.** A disagreement caps confidence and sets
   ``requires_analyst_review``; it never cancels points. Cancelling would reproduce the averaging
   failure in slower motion.

**No claim is made about how often this engine is right.** The weights are informed priors, no
labelled corpus exists, and nothing has been measured on a held-out set. The ruleset's
``calibration.statement`` says so in its own words and is copied into every verdict.

Precedence, from ``overrides.precedence``::

    tier A allowlist  >  escalation  >  tier B cap  >  score bands

Tier A beating escalation is deliberate and is a choice about predictability: when a feed reports
malware on a public resolver, the feed is wrong far more often than the resolver is compromised,
and an engine that flips on feed error is worse than one that is stubborn. It is never silent
about it -- the conflict is emitted as a contradiction and sets ``requires_analyst_review``.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from pydantic import ValidationError

from tripper_recon.types.models import Coverage
from tripper_recon.verdict import signals as sig
from tripper_recon.verdict.config import (
    ConfidenceBand,
    ContradictionRule,
    ContradictionRuleId,
    EscalationRule,
    IndicatorScope,
    OverrideTier,
    ScoringConfig,
    SignalId,
    VerdictLabelName,
)
from tripper_recon.verdict.known_infrastructure import InfraDecision
from tripper_recon.verdict.models import (
    AllowlistProvenance,
    Confidence,
    ConfidenceCriterion,
    Contradiction,
    OverrideApplied,
    Signal,
    SignalDirection,
    Verdict,
    VerdictLabel,
    cap_label,
    demote_label,
    is_score_reachable,
    severity_rank,
    weaken_confidence,
    weakest_confidence,
)

__all__ = [
    "ACTIVE_DNS_RESOLUTION",
    "ALLOWLIST_CONFLICT_RULE_ID",
    "ENGINE_VERSION",
    "TIER_C_SIGNAL_FOR_PAYLOAD_KEY",
    "active_collection_from_data",
    "collection_for_ip_entry",
    "coverage_for_ip_entry",
    "evaluate",
    "evaluate_domain_intel",
    "evaluate_ip_analysis",
]

#: Bumped when the adjudication *algorithm* changes. Orthogonal to ``ruleset_version``, which
#: moves when the numbers change, and to the verdict schema version, which moves when the record
#: shape changes. Three things change independently and each needs its own stamp.
ENGINE_VERSION = "1.0.0"

#: The one active-collection step this tool performs today: ``investigate_domain`` resolves the
#: domain through the system resolver, which terminates at the target's own authoritative
#: nameservers. Named rather than described so a consumer can match on it.
ACTIVE_DNS_RESOLUTION = "system_dns_resolution"

#: Emitted when the Tier A allowlist outranks adverse evidence. Not a ruleset-tunable rule: it
#: reports a precedence decision the engine made, so it is not gated by ``contradictions.rules``
#: and cannot be switched off. Being predictable and being loud are compatible; being predictable
#: and being quiet is not.
ALLOWLIST_CONFLICT_RULE_ID = "allowlist_vs_detection"

#: Wiring for the ruleset's Tier C vendor-suppression rules: which observational signal stands
#: for which provider payload key. Names, not numbers -- the ruleset owns whether a rule is
#: enabled and what it does; this table only says where to look for the flag. A rule whose
#: ``payload_key`` is missing here cannot fire, which is why the test suite asserts that every
#: enabled Tier C rule in the shipped ruleset appears in this map.
TIER_C_SIGNAL_FOR_PAYLOAD_KEY: Dict[str, str] = {
    "abuseipdb_is_whitelisted": sig.ABUSE_WHITELISTED,
    "abuseipdb_is_tor": sig.ABUSE_TOR_EXIT,
}

#: Decimal places kept on the pre-clamp score. A display concern, not a scoring parameter: the
#: sum of several decayed floats otherwise trails seventeen digits into the JSON.
_ROUND_DP = 4


# --------------------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------------------


def _require_aware(now: dt.datetime) -> dt.datetime:
    """Reject a naive ``now``.

    Provider timestamps are third-party data and are tolerated in any shape. ``now`` comes from
    this codebase, and this module never reads a clock, so a caller passing a naive value is a
    caller who has not decided what time it is.
    """
    if not isinstance(now, dt.datetime):
        raise TypeError("now must be a datetime")
    if now.tzinfo is None or now.tzinfo.utcoffset(now) is None:
        raise ValueError("now must be timezone-aware; a naive datetime has no defensible meaning")
    return now.astimezone(dt.timezone.utc)


def _parse_observed_at(value: Any) -> Optional[dt.datetime]:
    """Parse a :attr:`Signal.observed_at` into aware UTC, or ``None``.

    Deliberately narrow: it reads the shapes the extractors put on the model -- an ISO-8601
    string, with or without a ``Z``, and a Unix epoch. Anything else returns ``None`` and the
    caller treats the observation as undated, which for every rule here means the rule does not
    fire. Undated evidence is never assumed fresh and never assumed stale.

    A near-duplicate of the extractor lane's parser lives there for provider payloads. This one
    exists so the engine does not reach into a sibling module's private surface; when
    :class:`Signal` moves into ``models.py`` both should collapse into one helper beside it.
    """
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return dt.datetime.fromtimestamp(float(value), tz=dt.timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = dt.datetime.fromisoformat(candidate)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def _age_days(signal: Signal, now: dt.datetime) -> Optional[float]:
    """Age of a signal's observation in days, or ``None`` when it carries no usable timestamp."""
    observed = _parse_observed_at(signal.observed_at)
    if observed is None:
        return None
    return max((now - observed) / dt.timedelta(days=1), 0.0)


def _is_adverse(signal: Signal) -> bool:
    return signal.direction is SignalDirection.ADVERSE


def _contributes_points(signal: Signal) -> bool:
    """Whether a signal's points count toward the score.

    Direction and points are independent axes. ``shodan.exposure`` is ``CONTEXT`` and carries
    points by design: exposure describes what a host *is*, and the ruleset's ``ceiling_only`` flag
    -- not its direction -- is what stops it reaching the top band. Only ``EXCULPATORY`` signals
    are excluded, because adding points for good news would let an affirmative negative raise a
    score.
    """
    return signal.direction is not SignalDirection.EXCULPATORY


def _materiality(signal: Signal) -> float:
    """Fraction of its own ceiling a signal reached. ``0.0`` for a zero-weight observation."""
    if signal.max_points <= 0.0:
        return 0.0
    return signal.points / signal.max_points


def _is_material(signal: Signal, cfg: ScoringConfig) -> bool:
    return _materiality(signal) >= cfg.contradictions.material_fraction


def _is_decisive(signal: Signal, cfg: ScoringConfig) -> bool:
    """Whether one signal is strong enough to stand in for a second corroborating family.

    Restricted to adverse, non-ceiling-only signals. A ceiling-only signal exists precisely
    because it may not carry a severe verdict, so letting it act as the decisive evidence for one
    would route around the flag.
    """
    if not _is_adverse(signal) or signal.ceiling_only:
        return False
    return _materiality(signal) >= cfg.confidence.decisive_signal_fraction


def _first(signals: Iterable[Signal], signal_id: str) -> Optional[Signal]:
    return next((signal for signal in signals if signal.id == signal_id), None)


def _families(signals: Iterable[Signal], cfg: ScoringConfig) -> List[str]:
    """Distinct corroborating families among the given signals, in first-seen order.

    Families, never providers (roadmap 5.5). VirusTotal and OTX both re-ingest overlapping public
    feeds, so counting them as two independent confirmations manufactures confidence the evidence
    does not support; the ruleset's ``provider_families`` map is the declaration of who is
    independent of whom, and ``non_corroborating_families`` removes network metadata entirely --
    knowing an address is in AS13335 says where it lives, not what it did.
    """
    seen: Dict[str, None] = {}
    for signal in signals:
        if cfg.counts_toward_corroboration(signal.family):
            seen.setdefault(signal.family, None)
    return list(seen)


# --------------------------------------------------------------------------------------
# Overrides from the known-infrastructure catalogue
# --------------------------------------------------------------------------------------


def _label_or_none(value: Optional[str]) -> Optional[VerdictLabelName]:
    """Parse a catalogue label, returning ``None`` rather than raising on an unknown string.

    Both callers fail safe on ``None``: an unparseable *force* is not granted (so a malformed
    catalogue cannot declare something fine) and an unparseable *cap* is not applied (so it
    cannot lower a verdict either). A bulk run must not abort on one bad catalogue row, and
    neither failure mode may quietly exculpate.
    """
    if value is None:
        return None
    try:
        return VerdictLabelName(value)
    except ValueError:
        return None


def _apply_infrastructure(
    signals: Sequence[Signal],
    decision: Optional[InfraDecision],
) -> Tuple[List[Signal], List[OverrideApplied], List[str]]:
    """Zero and suppress the signals the catalogue says do not describe this target.

    Tier B zeroes the ASN and exposure signals: behind a CDN edge you are scoring the operator,
    not the tenant, and an ASN reputation for Cloudflare says nothing at all about the phishing
    kit behind it. Tier C suppresses the signals a declared scanner is expected to trip.

    A zeroed signal is kept in the list with its original points recorded in ``evidence``. It is
    not deleted: the analyst needs to see that Shodan found an open RDP port *and* that the
    verdict did not count it, and a signal that silently vanishes teaches nobody anything.
    """
    notes: List[str] = []
    if decision is None:
        return list(signals), [], notes

    zeroed = set(decision.zeroed_signals)
    suppressed = set(decision.suppressed_signals)
    adjusted: List[Signal] = []
    for signal in signals:
        reason = "zeroed" if signal.id in zeroed else ("suppressed" if signal.id in suppressed else None)
        if reason is None or signal.points <= 0.0:
            adjusted.append(signal)
            continue
        adjusted.append(
            signal.model_copy(
                update={
                    "points": 0.0,
                    "magnitude": 0.0,
                    "evidence": {
                        **signal.evidence,
                        f"{reason}_by_known_infrastructure": True,
                        "points_before_override": signal.points,
                        "magnitude_before_override": signal.magnitude,
                    },
                }
            )
        )
        notes.append(f"{signal.id} {reason} by the known-infrastructure catalogue; its points were not counted")

    overrides = [OverrideApplied.model_validate(record) for record in decision.override_records()]
    notes.extend(decision.notes)
    return adjusted, overrides, notes


def _allowlist_provenance(decision: Optional[InfraDecision]) -> Optional[AllowlistProvenance]:
    if decision is None:
        return None
    return AllowlistProvenance(
        list_version=decision.list_version,
        list_retrieved=decision.list_retrieved.isoformat(),
        stale=decision.stale,
        staleness_note=decision.staleness_note,
    )


# --------------------------------------------------------------------------------------
# Score
# --------------------------------------------------------------------------------------


def _score(signals: Sequence[Signal], cfg: ScoringConfig) -> Tuple[float, int, VerdictLabelName]:
    """Sum, clamp and band the points.

    Additive and bounded, which keeps the arithmetic something an analyst can re-derive on a
    whiteboard. Averaging was rejected because it destroys the information the analyst needs;
    a Bayesian combination was rejected because it needs per-provider likelihood ratios this repo
    has no data to estimate.

    ``ceiling_only`` signals are summed like any other and then fenced: the band they can reach
    is capped at ``verdict_rules.ceiling_only_cap`` unless the remaining signals already reach a
    higher one on their own. An exposed RDP box is a risk, not a threat, and a tool that calls it
    a threat teaches its analysts to ignore the colour red.
    """
    contributing = [signal for signal in signals if _contributes_points(signal)]
    raw = sum(signal.points for signal in contributing)
    clamped = max(float(cfg.score.clamp_min), min(float(cfg.score.clamp_max), raw))
    score = int(round(clamped))
    band = cfg.band_for_score(score)

    ceiling_points = sum(signal.points for signal in contributing if signal.ceiling_only)
    if ceiling_points > 0.0 and is_score_reachable(band):
        without = max(float(cfg.score.clamp_min), min(float(cfg.score.clamp_max), raw - ceiling_points))
        earned = cfg.band_for_score(int(round(without)))
        ceiling = cfg.verdict_rules.ceiling_only_cap
        # The ceiling-only signals may raise the verdict to the cap and no further; anything above
        # the cap has to be earned by the rest of the panel.
        allowed = earned if _more_severe(earned, ceiling) else ceiling
        band = cap_label(band, allowed)

    return round(raw, _ROUND_DP), score, band


def _more_severe(left: VerdictLabelName, right: VerdictLabelName) -> bool:
    """True when ``left`` outranks ``right``. Both must be score-reachable.

    ``severity_rank`` counts down from the most severe label, so the more severe of two labels is
    the one with the *lower* rank.
    """
    return severity_rank(left) < severity_rank(right)


# --------------------------------------------------------------------------------------
# Contradictions (roadmap 5.7)
# --------------------------------------------------------------------------------------


def _enabled_contradiction_rules(cfg: ScoringConfig) -> Dict[ContradictionRuleId, ContradictionRule]:
    if not cfg.contradictions.enabled:
        return {}
    return {rule.id: rule for rule in cfg.contradictions.rules if rule.enabled}


def _detect_contradictions(
    signals: Sequence[Signal],
    cfg: ScoringConfig,
    now: dt.datetime,
    *,
    tier_b_rule_ids: Sequence[str],
) -> List[Contradiction]:
    """Pairwise disagreements between different sources, reported and never reconciled.

    Each rule fires on two sides that point opposite ways. The score is untouched: a
    contradiction moves the confidence and raises the review flag, because "these two providers
    disagree" is a fact the analyst acts on and a number cannot carry it.
    """
    rules = _enabled_contradiction_rules(cfg)
    found: List[Contradiction] = []

    vt_abuse = rules.get(ContradictionRuleId.VT_VS_ABUSEIPDB)
    if vt_abuse is not None:
        found.extend(_vt_vs_abuseipdb(signals, cfg, vt_abuse))

    stale_fresh = rules.get(ContradictionRuleId.STALE_VS_FRESH)
    if stale_fresh is not None:
        found.extend(_stale_vs_fresh(signals, cfg, now, stale_fresh))

    cdn = rules.get(ContradictionRuleId.CDN_VS_DETECTION)
    if cdn is not None:
        found.extend(_cdn_vs_detection(signals, cfg, cdn, tier_b_rule_ids=tier_b_rule_ids))

    age = rules.get(ContradictionRuleId.AGE_VS_REPUTATION)
    if age is not None:
        found.extend(_age_vs_reputation(signals, age))

    return found


def _vt_vs_abuseipdb(signals: Sequence[Signal], cfg: ScoringConfig, rule: ContradictionRule) -> List[Contradiction]:
    """Signature detections on one side, a vendor declining to call it abusive on the other.

    This is the committed ``ip_example.md`` case: five VirusTotal engines flag the address while
    AbuseIPDB holds five reports and still assigns 0% confidence. One of them is wrong. The tool
    used to print red and green side by side and walk away.
    """
    detections = _first(signals, SignalId.VT_WEIGHTED_DETECTIONS.value)
    declined = _first(signals, sig.ABUSE_REPORTS_NO_CONFIDENCE)
    if detections is None or declined is None or not _is_material(detections, cfg):
        return []
    reports = declined.evidence.get("reports")
    return [
        Contradiction(
            rule_id=rule.id.value,
            summary=(
                f"VirusTotal scores {detections.points:.1f} of {detections.max_points:.0f} points "
                f"for its detections while AbuseIPDB holds {reports} report(s) and assigns 0% "
                "confidence. The two providers disagree and neither is averaged away"
            ),
            left=detections.id,
            right=declined.id,
            analyst_hint=rule.analyst_hint,
            both_material=_is_material(detections, cfg) and _is_material(declined, cfg),
        )
    ]


def _stale_vs_fresh(
    signals: Sequence[Signal],
    cfg: ScoringConfig,
    now: dt.datetime,
    rule: ContradictionRule,
) -> List[Contradiction]:
    """Historical badness beside current activity, from two different families.

    Usually means the address was re-used or reassigned, so the old finding may describe a
    previous tenant. Requires both thresholds in the ruleset; without them there is no defensible
    line between old and current and the rule stays silent rather than inventing one.
    """
    if rule.stale_days is None or rule.fresh_days is None:
        return []
    dated = [
        (signal, age)
        for signal, age in ((item, _age_days(item, now)) for item in signals if _is_adverse(item) and item.points > 0)
        if age is not None
    ]
    stale = sorted((item for item in dated if item[1] > rule.stale_days), key=lambda item: item[0].points, reverse=True)
    fresh = sorted((item for item in dated if item[1] < rule.fresh_days), key=lambda item: item[0].points, reverse=True)
    for old_signal, old_age in stale:
        for new_signal, new_age in fresh:
            if old_signal.family == new_signal.family:
                continue
            return [
                Contradiction(
                    rule_id=rule.id.value,
                    summary=(
                        f"{old_signal.id} was observed {old_age:.0f} days ago while {new_signal.id} "
                        f"reports activity {new_age:.0f} days ago, from a different provider family"
                    ),
                    left=old_signal.id,
                    right=new_signal.id,
                    analyst_hint=rule.analyst_hint,
                    both_material=_is_material(old_signal, cfg) and _is_material(new_signal, cfg),
                )
            ]
    return []


def _cdn_vs_detection(
    signals: Sequence[Signal],
    cfg: ScoringConfig,
    rule: ContradictionRule,
    *,
    tier_b_rule_ids: Sequence[str],
) -> List[Contradiction]:
    """Adverse evidence on an address that belongs to shared infrastructure.

    The detection is about a tenant; the address is not the tenant. Blocking it hits everyone
    else behind the same edge, which is why this fires as a contradiction rather than being
    folded into the score.
    """
    if not tier_b_rule_ids:
        return []
    adverse = sorted(
        (signal for signal in signals if _is_adverse(signal) and signal.points > 0),
        key=lambda signal: signal.points,
        reverse=True,
    )
    if not adverse:
        return []
    strongest = adverse[0]
    return [
        Contradiction(
            rule_id=rule.id.value,
            summary=(
                f"{strongest.id} carries adverse evidence on an address matched by "
                f"{', '.join(tier_b_rule_ids)}, which is shared infrastructure"
            ),
            left=strongest.id,
            right=tier_b_rule_ids[0],
            analyst_hint=rule.analyst_hint,
            both_material=False,
        )
    ]


def _age_vs_reputation(signals: Sequence[Signal], rule: ContradictionRule) -> List[Contradiction]:
    """A very new domain with a clean multi-scanner record.

    Converts the single most common triage error -- "VirusTotal is clean, moving on" -- into an
    explicit warning, for the cost of one comparison. A domain registered last week has not been
    evaluated by anyone yet, so the absence of a detection is expected rather than reassuring.
    """
    if rule.max_age_days is None:
        return []
    age_signal = _first(signals, SignalId.DOMAIN_AGE.value)
    clean = _first(signals, sig.VT_NO_DETECTIONS)
    if age_signal is None or clean is None:
        return []
    age_days = age_signal.evidence.get("age_days")
    if not isinstance(age_days, (int, float)) or isinstance(age_days, bool):
        return []
    if age_days > rule.max_age_days:
        return []
    return [
        Contradiction(
            rule_id=rule.id.value,
            summary=(
                f"The domain was registered {float(age_days):.0f} days ago and VirusTotal reports no "
                "detections. Too new to have been evaluated"
            ),
            left=age_signal.id,
            right=clean.id,
            analyst_hint=rule.analyst_hint,
            both_material=False,
        )
    ]


# --------------------------------------------------------------------------------------
# Confidence (roadmap 5.4)
# --------------------------------------------------------------------------------------


def _confidence(
    *,
    cfg: ScoringConfig,
    coverage: Coverage,
    signals: Sequence[Signal],
    contradictions: Sequence[Contradiction],
    now: dt.datetime,
) -> Tuple[ConfidenceBand, float, List[ConfidenceCriterion], List[str]]:
    """How much of the panel was heard from, and did it agree.

    Computed **without reference to the score**, which is the whole point of the second axis: a
    high score with low confidence is a real state and the analyst has to be able to see both
    numbers at once.

    ``LOW`` is forced whenever coverage is below ``confidence.coverage_floor``, ahead of every
    other consideration. Three providers agreeing out of a panel of six that were only asked
    twice is not agreement, it is a small sample presented as one.

    Returns the band, a criteria-met fraction, the criteria themselves and the corroborating
    family names. The fraction is a transparency aid -- it makes two verdicts comparable and it
    can be re-derived from the criteria list -- and it is never a probability that the answer is
    right.
    """
    adverse = [signal for signal in signals if _is_adverse(signal) and signal.points > 0]
    # Corroboration counts the families that support the conclusion. Where adverse evidence
    # exists, those are the adverse families and nothing else -- an affirmative negative from a
    # sixth provider does not make a detection better corroborated. Where none exists, the
    # supporting families are the ones that were asked and answered "nothing here", because
    # otherwise a fully-covered panel unanimously reporting nothing adverse would score LOW
    # confidence for the absence of the very evidence that would have contradicted it.
    families = _families(adverse, cfg) or _families(
        [signal for signal in signals if signal.id in sig.AFFIRMATIVE_NEGATIVE_SIGNAL_IDS], cfg
    )
    decisive = [signal for signal in signals if _is_decisive(signal, cfg)]
    ratio = coverage.ratio
    floor_met = coverage.is_sufficient(cfg.confidence.coverage_floor)
    high = cfg.confidence.high
    medium = cfg.confidence.medium

    criteria: List[ConfidenceCriterion] = [
        ConfidenceCriterion(
            name="coverage_floor",
            met=floor_met,
            detail=f"{coverage.headline}; ratio {ratio} against floor {cfg.confidence.coverage_floor}",
        ),
        ConfidenceCriterion(
            name="coverage_high",
            met=ratio >= high.min_coverage,
            detail=f"ratio {ratio} against {high.min_coverage} required for HIGH",
        ),
        ConfidenceCriterion(
            name="corroboration_medium",
            met=len(families) >= medium.min_families,
            detail=f"{len(families)} corroborating famil(ies) against {medium.min_families} required for MEDIUM",
        ),
        ConfidenceCriterion(
            name="corroboration_high",
            met=len(families) >= high.min_families,
            detail=f"{len(families)} corroborating famil(ies) against {high.min_families} required for HIGH",
        ),
        ConfidenceCriterion(
            name="decisive_signal",
            met=bool(decisive),
            detail=(
                f"{len(decisive)} signal(s) at or above {cfg.confidence.decisive_signal_fraction} of their own ceiling"
            ),
        ),
        ConfidenceCriterion(
            name="no_unresolved_contradiction",
            met=not contradictions,
            detail=f"{len(contradictions)} unresolved contradiction(s)",
        ),
    ]

    fresh_days = _fresh_days(cfg)
    if fresh_days is not None:
        ages = [age for age in (_age_days(signal, now) for signal in adverse) if age is not None]
        criteria.append(
            ConfidenceCriterion(
                name="fresh_adverse_evidence",
                met=any(age <= fresh_days for age in ages),
                detail=(
                    f"{len(ages)} of {len(adverse)} adverse signal(s) carry a timestamp; "
                    f"freshness window {fresh_days} days"
                ),
            )
        )

    band = _confidence_band(
        cfg=cfg,
        floor_met=floor_met,
        ratio=ratio,
        families=len(families),
        decisive=bool(decisive),
        contradictions=bool(contradictions),
    )
    score = sum(1 for criterion in criteria if criterion.met) / len(criteria)
    return band, round(score, _ROUND_DP), criteria, families


def _fresh_days(cfg: ScoringConfig) -> Optional[int]:
    """The freshness window, borrowed from the ``stale_vs_fresh`` rule when the ruleset sets one.

    There is no separate freshness threshold in the ruleset, and adding one in Python would be
    exactly the invented number this engine is not allowed to contain. Where the ruleset declines
    to define "recent", the criterion is simply not evaluated.
    """
    for rule in cfg.contradictions.rules:
        if rule.id is ContradictionRuleId.STALE_VS_FRESH and rule.enabled:
            return rule.fresh_days
    return None


def _confidence_band(
    *,
    cfg: ScoringConfig,
    floor_met: bool,
    ratio: float,
    families: int,
    decisive: bool,
    contradictions: bool,
) -> ConfidenceBand:
    if not floor_met:
        return Confidence.LOW

    high = cfg.confidence.high
    medium = cfg.confidence.medium
    # `allow_unresolved_contradiction` unset reads as false: HIGH means the panel agreed, and an
    # absent setting is not permission.
    high_ok = (
        ratio >= high.min_coverage
        and families >= high.min_families
        and (bool(high.allow_unresolved_contradiction) or not contradictions)
    )
    if high_ok:
        band = Confidence.HIGH
    else:
        substitutes = bool(medium.decisive_signal_substitutes_for_family) and decisive
        medium_ok = ratio >= medium.min_coverage and (families >= medium.min_families or substitutes)
        band = Confidence.MEDIUM if medium_ok else Confidence.LOW

    if contradictions:
        band = weakest_confidence(band, cfg.contradictions.cap_confidence)
    return band


# --------------------------------------------------------------------------------------
# Escalation
# --------------------------------------------------------------------------------------


def _escalation(
    signals: Sequence[Signal],
    cfg: ScoringConfig,
) -> Tuple[Optional[EscalationRule], List[str]]:
    """The first enabled escalation rule whose conditions are met, if any.

    A rule with no conditions at all is refused rather than fired. An unconditional escalation
    would force the top band on every indicator the tool ever looks at, and a ruleset that
    expresses one is a mistake, not an instruction.
    """
    notes: List[str] = []
    if not cfg.overrides.escalation.enabled:
        return None, notes

    adverse = [signal for signal in signals if _is_adverse(signal) and signal.points > 0]
    providers = {signal.provider for signal in adverse}
    decisive_families = _families([signal for signal in adverse if _is_decisive(signal, cfg)], cfg)

    for rule in cfg.overrides.escalation.rules:
        if not rule.enabled:
            continue
        conditioned = bool(rule.requires_providers) or rule.requires_high_confidence_engines or rule.min_families
        if not conditioned:
            notes.append(
                f"escalation rule '{rule.id}' states no condition and was not applied; an "
                "unconditional escalation would force the top band on every indicator"
            )
            continue
        if not set(rule.requires_providers) <= providers:
            continue
        if rule.requires_high_confidence_engines and not _vt_consensus_reached(signals, cfg):
            continue
        if rule.min_families is not None and len(decisive_families) < rule.min_families:
            continue
        return rule, notes
    return None, notes


def _vt_consensus_reached(signals: Sequence[Signal], cfg: ScoringConfig) -> bool:
    """Whether enough high-confidence engines flagged the indicator.

    The set of high-confidence engines ships empty and must stay empty until a corpus fills it:
    engine quality comes from measurement or it does not exist. While it is empty no hit can be
    recorded, this returns ``False``, and the ruleset loader separately refuses to let the rule
    that depends on it be enabled.
    """
    detections = _first(signals, SignalId.VT_WEIGHTED_DETECTIONS.value)
    if detections is None:
        return False
    hits = detections.evidence.get("high_confidence_hits")
    if not isinstance(hits, list):
        return False
    return len(hits) >= cfg.virustotal.consensus_threshold


# --------------------------------------------------------------------------------------
# Tier C -- vendor suppression from the ruleset
# --------------------------------------------------------------------------------------


def _tier_c(signals: Sequence[Signal], cfg: ScoringConfig) -> List[OverrideApplied]:
    """Vendor "we consider this fine" flags. They demote; they never short-circuit.

    AbuseIPDB's ``isWhitelisted`` is one vendor's opinion. Treated as a clearance it would be the
    absent-data failure with a vendor's name on it; ignored entirely it would be evidence the tool
    collected and hid. Demoting confidence is the honest middle: the opinion is visible in the
    verdict and cannot decide it.
    """
    tier_c = cfg.overrides.tier_c
    if not tier_c.enabled:
        return []
    applied: List[OverrideApplied] = []
    for rule in tier_c.rules:
        if not rule.enabled:
            continue
        signal_id = TIER_C_SIGNAL_FOR_PAYLOAD_KEY.get(rule.payload_key)
        if signal_id is None or _first(signals, signal_id) is None:
            continue
        applied.append(
            OverrideApplied(
                rule_id=rule.id,
                tier="C",
                effect="confidence_demoted" if tier_c.effect == "demote_confidence" else "verdict_demoted",
                source_list=cfg.source_label,
                source_retrieved_at=None,
                note=rule.description,
            )
        )
    return applied


# --------------------------------------------------------------------------------------
# The engine
# --------------------------------------------------------------------------------------


def evaluate(
    *,
    indicator: str,
    scope: IndicatorScope,
    signals: Sequence[Signal],
    coverage: Coverage,
    cfg: ScoringConfig,
    now: dt.datetime,
    infrastructure: Optional[InfraDecision] = None,
    passive_only: bool = True,
    active_collection: Sequence[str] = (),
) -> Verdict:
    """Adjudicate one indicator. Pure: same inputs, same verdict, forever.

    ``coverage`` is the honest denominator -- every provider that was *applicable*, not every
    provider that happened to have a key. Pass
    :attr:`~tripper_recon.types.models.InvestigationResult.coverage_or_unknown` rather than
    ``coverage``: it returns zero coverage when coverage was never computed, so "we did not
    measure" and "nobody answered" reach this function as the same conservative value.

    ``infrastructure`` is the known-infrastructure catalogue's decision for this indicator, loaded
    by the caller because loading is I/O. Its effect fields are read directly and never
    re-derived from its match list, which may hold context-only entries the tier does not act on.
    """
    now = _require_aware(now)
    adjusted, infra_overrides, notes = _apply_infrastructure(signals, infrastructure)
    raw_score, score, score_band = _score(adjusted, cfg)

    tier_b_rule_ids = [override.rule_id for override in infra_overrides if override.tier.strip().upper() == "B"]
    contradictions = _detect_contradictions(adjusted, cfg, now, tier_b_rule_ids=tier_b_rule_ids)

    confidence, confidence_score, criteria, families = _confidence(
        cfg=cfg,
        coverage=coverage,
        signals=adjusted,
        contradictions=contradictions,
        now=now,
    )

    overrides: List[OverrideApplied] = list(infra_overrides)
    tier_c_overrides = _tier_c(adjusted, cfg)
    overrides.extend(tier_c_overrides)
    for override in tier_c_overrides:
        if override.effect == "confidence_demoted":
            confidence = weaken_confidence(confidence)

    forced = _label_or_none(infrastructure.forced_verdict) if infrastructure is not None else None
    if infrastructure is not None and infrastructure.forced_verdict is not None and forced is None:
        notes.append(
            f"the catalogue asked to force {infrastructure.forced_verdict!r}, which is not a verdict "
            "label this engine knows; the force was not applied"
        )

    escalation_rule: Optional[EscalationRule] = None
    adjustments: List[str] = []
    adjusted_from: Optional[VerdictLabelName] = None

    if forced is not None:
        label = forced
        decision_line = (
            f"Tier A allowlist rule matched: verdict forced to {label.value} and the score was not consulted"
        )
        adverse_present = [signal for signal in adjusted if _is_adverse(signal) and signal.points > 0]
        if adverse_present:
            strongest = max(adverse_present, key=lambda signal: signal.points)
            contradictions.append(
                Contradiction(
                    rule_id=ALLOWLIST_CONFLICT_RULE_ID,
                    summary=(
                        f"{strongest.id} reports adverse evidence on an address the Tier A allowlist "
                        "declares to be known infrastructure. The allowlist was applied"
                    ),
                    left=strongest.id,
                    right=next(
                        (override.rule_id for override in overrides if override.effect == "verdict_forced"),
                        "overrides.tier_a",
                    ),
                    analyst_hint=(
                        "A feed reporting badness on allowlisted infrastructure is wrong far more "
                        "often than the infrastructure is compromised, so the allowlist wins by "
                        "design -- but verify this one manually before dismissing it"
                    ),
                    both_material=False,
                )
            )
            # Recompute the band: the conflict is itself an unresolved contradiction.
            confidence, confidence_score, criteria, families = _confidence(
                cfg=cfg,
                coverage=coverage,
                signals=adjusted,
                contradictions=contradictions,
                now=now,
            )
    else:
        escalation_rule, escalation_notes = _escalation(adjusted, cfg)
        notes.extend(escalation_notes)
        if escalation_rule is not None:
            label = escalation_rule.verdict
            decision_line = f"escalation rule '{escalation_rule.id}' forced {label.value}"
            overrides.append(
                OverrideApplied(
                    rule_id=escalation_rule.id,
                    tier=OverrideTier.ESCALATION.value,
                    effect="verdict_forced",
                    source_list=cfg.source_label,
                    source_retrieved_at=None,
                    note=escalation_rule.description,
                )
            )
            # An escalation rule states the confidence its evidence deserves; it may lower the
            # computed band and never raise it. Raising it would let a rule assert agreement the
            # panel never produced, which is the phantom confidence the family model exists to
            # prevent.
            confidence = weakest_confidence(confidence, escalation_rule.confidence)
        else:
            label = score_band
            decision_line = (
                f"score {score} of {cfg.score.clamp_max} falls in the {label.value} band "
                f"(MALICIOUS at {cfg.malicious_threshold}, SUSPICIOUS at {cfg.suspicious_threshold})"
            )

        capped = _label_or_none(infrastructure.capped_verdict) if infrastructure is not None else None
        if capped is not None and is_score_reachable(label):
            lowered = cap_label(label, capped)
            if lowered is not label:
                adjusted_from = adjusted_from or label
                adjustments.append(f"capped at {capped.value} by the known-infrastructure catalogue (shared hosting)")
                label = lowered

        if cfg.contradictions.demote_verdict_when_both_material:
            material = [item for item in contradictions if item.both_material]
            if material and is_score_reachable(label):
                lowered = demote_label(label, floor=VerdictLabel.SUSPICIOUS)
                if lowered is not label:
                    adjusted_from = adjusted_from or label
                    adjustments.append(
                        f"demoted one band: {material[0].rule_id} puts two material signals in direct conflict"
                    )
                    label = lowered

        # The absent-data gate. A zero score is not a clean verdict: the panel has to have been
        # heard from, and at least one provider has to have answered rather than merely not
        # failed. Below the floor the honest label is INSUFFICIENT_DATA.
        if label is VerdictLabel.NO_ADVERSE_FINDINGS:
            resolved = _resolve_clean_label(adjusted, coverage, cfg)
            if resolved is not None:
                replacement, reason = resolved
                adjusted_from = adjusted_from or label
                adjustments.append(reason)
                label = replacement

        if (
            cfg.verdict_rules.demote_malicious_when_confidence_low
            and label is VerdictLabel.MALICIOUS
            and confidence is Confidence.LOW
        ):
            adjusted_from = adjusted_from or label
            adjustments.append(
                f"rendered as SUSPICIOUS: the score reached the MALICIOUS band at LOW confidence "
                f"({coverage.headline}). The raw score is shown beside it"
            )
            label = VerdictLabel.SUSPICIOUS

    # A stale allowlist that actually changed this verdict is a review trigger: a reassigned
    # range still matches an out-of-date list, and the suppression it produced is unverified.
    stale_suppression = infrastructure is not None and infrastructure.stale and bool(infra_overrides)
    requires_review = bool(contradictions) or stale_suppression
    if label is VerdictLabel.MALICIOUS and confidence is Confidence.LOW:
        requires_review = True
    if adjusted_from is VerdictLabel.MALICIOUS:
        # The engine found top-band evidence and declined to assert it. That is precisely the
        # state where a human has to look: the tool is saying "probably bad, cannot stand behind
        # it", and a demotion the analyst never notices is the same as no finding at all.
        requires_review = True

    rationale = _rationale(
        decision_line=decision_line,
        coverage=coverage,
        cfg=cfg,
        confidence=confidence,
        signals=adjusted,
        contradictions=contradictions,
        overrides=overrides,
        adjustments=adjustments,
        notes=notes,
        infrastructure=infrastructure,
    )

    return Verdict(
        indicator=indicator,
        indicator_type=scope.value,
        verdict=label,
        score=score,
        raw_score=raw_score,
        score_band=score_band,
        adjusted_from=adjusted_from if adjustments else None,
        adjustment_reasons=adjustments,
        confidence=confidence,
        confidence_score=confidence_score,
        confidence_criteria=criteria,
        coverage=coverage,
        coverage_floor=cfg.confidence.coverage_floor,
        corroborating_families=families,
        signals=list(adjusted),
        contradictions=contradictions,
        overrides_applied=overrides,
        allowlist=_allowlist_provenance(infrastructure),
        requires_analyst_review=requires_review,
        attribution_warning=infrastructure.attribution_warning if infrastructure is not None else None,
        summary=_summary(
            indicator=indicator,
            label=label,
            score=score,
            cfg=cfg,
            confidence=confidence,
            coverage=coverage,
            adjustments=adjustments,
            contradictions=contradictions,
            requires_review=requires_review,
        ),
        rationale=rationale,
        passive_only=passive_only and not active_collection,
        active_collection=list(active_collection),
        ruleset_version=cfg.version,
        ruleset_source=cfg.source_label,
        calibration_statement=cfg.calibration.statement,
        engine_version=ENGINE_VERSION,
        evaluated_at=now,
    )


def _resolve_clean_label(
    signals: Sequence[Signal],
    coverage: Coverage,
    cfg: ScoringConfig,
) -> Optional[Tuple[VerdictLabelName, str]]:
    """What to say instead of ``NO_ADVERSE_FINDINGS``, or ``None`` when the label stands.

    Three independent gates, and all three have to pass before the tool prints the clean label.

    * **Something adverse was reported.** Checked first, and it is the one gate that raises the
      label rather than lowering it. Evidence below the SUSPICIOUS threshold is still evidence,
      and "no adverse findings" printed over five VirusTotal detections is a false sentence --
      the exact failure this workstream exists to remove. The design's own definition of the
      clean label is that *every* answering provider returned an affirmative negative.
    * **Enough of the panel spoke.** Below the coverage floor there is no panel to make a
      statement about.
    * **Somebody actually answered.** An affirmative negative is a provider saying "asked, and
      nothing here". A run in which every provider errored has none.
    """
    reported = [signal for signal in signals if _is_adverse(signal) and signal.points > 0]
    if reported:
        loudest = max(reported, key=lambda signal: signal.points)
        return (
            VerdictLabel.SUSPICIOUS,
            f"SUSPICIOUS rather than NO_ADVERSE_FINDINGS: {loudest.id} and "
            f"{len(reported) - 1} other adverse signal(s) reported something, below the "
            f"{cfg.suspicious_threshold}-point band but not nothing. NO_ADVERSE_FINDINGS would "
            "claim the panel reported nothing adverse; it did.",
        )
    if not coverage.is_sufficient(cfg.confidence.coverage_floor):
        return (
            VerdictLabel.INSUFFICIENT_DATA,
            f"INSUFFICIENT_DATA rather than NO_ADVERSE_FINDINGS: {coverage.headline}, below the "
            f"{cfg.confidence.coverage_floor} coverage floor. Absent data is not a clean result",
        )
    if cfg.verdict_rules.require_affirmative_negative and not any(
        signal.id in sig.AFFIRMATIVE_NEGATIVE_SIGNAL_IDS for signal in signals
    ):
        return (
            VerdictLabel.INSUFFICIENT_DATA,
            "INSUFFICIENT_DATA rather than NO_ADVERSE_FINDINGS: no provider returned an "
            "affirmative negative. A clean verdict needs a provider that was asked and answered, "
            "not merely a provider that reported nothing",
        )
    return None


def _summary(
    *,
    indicator: str,
    label: VerdictLabelName,
    score: int,
    cfg: ScoringConfig,
    confidence: ConfidenceBand,
    coverage: Coverage,
    adjustments: Sequence[str],
    contradictions: Sequence[Contradiction],
    requires_review: bool,
) -> str:
    """The one line that goes in the ticket. Verdict word first, everything else qualifying it."""
    parts = [
        f"{indicator}: {label.value}",
        f"score {score}/{cfg.score.clamp_max}",
        f"confidence {confidence.value}",
        coverage.headline,
    ]
    if adjustments:
        parts.append(f"{len(adjustments)} adjustment(s) applied")
    if contradictions:
        parts.append(f"{len(contradictions)} contradiction(s)")
    if requires_review:
        parts.append("analyst review required")
    return " -- ".join([parts[0], ", ".join(parts[1:])])


def _rationale(
    *,
    decision_line: str,
    coverage: Coverage,
    cfg: ScoringConfig,
    confidence: ConfidenceBand,
    signals: Sequence[Signal],
    contradictions: Sequence[Contradiction],
    overrides: Sequence[OverrideApplied],
    adjustments: Sequence[str],
    notes: Sequence[str],
    infrastructure: Optional[InfraDecision],
) -> List[str]:
    """The reasoning, ordered so the first three lines answer the analyst's first three questions.

    What did it decide, how much of the panel did it hear from, and which evidence carried the
    most weight. The negative space -- who did not answer, by name -- comes before the signals,
    because a strong-looking score from two of six providers is a different finding from the same
    score out of six.
    """
    lines: List[str] = [decision_line, f"coverage: {coverage.headline}; confidence {confidence.value}"]
    if coverage.missing:
        lines.append(f"contributed nothing: {', '.join(coverage.missing)}")
    for reason in adjustments:
        lines.append(reason)
    for signal in sorted(signals, key=lambda item: item.points, reverse=True):
        if signal.points > 0:
            lines.append(f"+{signal.points:.1f} {signal.id}: {signal.observation}")
    for signal in signals:
        if signal.points <= 0:
            lines.append(f"+0 {signal.id}: {signal.observation}")
    for contradiction in contradictions:
        lines.append(f"contradiction {contradiction.rule_id}: {contradiction.summary}. {contradiction.analyst_hint}")
    for override in overrides:
        retrieved = f", list retrieved {override.source_retrieved_at}" if override.source_retrieved_at else ""
        lines.append(f"override {override.rule_id} ({override.tier}, {override.effect}){retrieved}")
    if infrastructure is not None and infrastructure.stale:
        lines.append(infrastructure.staleness_note)
    lines.extend(notes)
    lines.append(f"ruleset {cfg.version} from {cfg.source_label}; {cfg.calibration.statement}")
    return lines


# --------------------------------------------------------------------------------------
# Front doors over the orchestrator's own shapes
# --------------------------------------------------------------------------------------


def coverage_for_ip_entry(entry: Mapping[str, Any]) -> Coverage:
    """Coverage for one per-address analysis dict.

    Prefers the ``coverage`` the orchestrator already computed, because that one knows the full
    expected provider list and therefore the honest denominator. Falls back to the per-address
    status map, and finally to zero coverage -- never to "everything answered".
    """
    recorded = entry.get("coverage")
    if isinstance(recorded, Mapping):
        try:
            return Coverage.model_validate(dict(recorded))
        except ValidationError:
            pass
    status = entry.get("provider_status")
    if isinstance(status, Mapping):
        return Coverage.from_status_map(status)
    return Coverage()


def collection_for_ip_entry(entry: Mapping[str, Any]) -> Tuple[bool, List[str]]:
    """``(passive_only, active_collection)`` for one address, from how the address was obtained.

    The domain path tags each address ``active``, ``passive`` or ``active+passive``
    (``orchestrators._tag_ip_sources``). An address that only the system resolver produced was
    obtained by a recursive lookup terminating at the target's own nameservers, and a verdict
    resting on it is a different artefact from one built entirely on third-party records. An
    entry with no ``source`` key is the standalone IP path, where the address came from the
    operator.
    """
    source = entry.get("source")
    if isinstance(source, str) and "active" in source:
        return False, [ACTIVE_DNS_RESOLUTION]
    return True, []


def active_collection_from_data(data: Mapping[str, Any]) -> List[str]:
    """The active-collection steps behind a whole investigation, by name.

    Reads the per-address ``source`` tags rather than inferring from the presence of a resolver
    in the codebase: whether the resolver ran on *this* investigation is a property of the run.
    """
    for entry in data.get("ips") or []:
        if isinstance(entry, Mapping) and not collection_for_ip_entry(entry)[0]:
            return [ACTIVE_DNS_RESOLUTION]
    return []


def evaluate_ip_analysis(
    analysis: Mapping[str, Any],
    *,
    cfg: ScoringConfig,
    now: dt.datetime,
    coverage: Optional[Coverage] = None,
    infrastructure: Optional[InfraDecision] = None,
    passive_only: Optional[bool] = None,
    active_collection: Optional[Sequence[str]] = None,
) -> Verdict:
    """Adjudicate one address from the orchestrator's per-IP analysis dict.

    Collection mode defaults to whatever the entry's ``source`` tag says, so the domain path
    discloses its resolver use without the caller having to remember to.
    """
    now = _require_aware(now)
    entry_passive, entry_active = collection_for_ip_entry(analysis)
    return evaluate(
        indicator=str(analysis.get("ip") or ""),
        scope=IndicatorScope.IP,
        signals=sig.extract_ip_signals(analysis, cfg, now),
        coverage=coverage if coverage is not None else coverage_for_ip_entry(analysis),
        cfg=cfg,
        now=now,
        infrastructure=infrastructure,
        passive_only=entry_passive if passive_only is None else passive_only,
        active_collection=entry_active if active_collection is None else active_collection,
    )


def evaluate_domain_intel(
    data: Mapping[str, Any],
    *,
    cfg: ScoringConfig,
    now: dt.datetime,
    coverage: Optional[Coverage] = None,
    passive_only: bool = True,
    active_collection: Sequence[str] = (),
) -> Verdict:
    """Adjudicate the domain itself, from a domain investigation's ``data``.

    The domain and its resolved addresses are scored **separately and never merged**. A phishing
    kit on a CDN is a malicious domain on a shared address; both statements are true at once, and
    any merge either indicts every other tenant behind that address or clears the phishing kit.
    Score the addresses with :func:`evaluate_ip_analysis` over ``data['ips']``.

    Collection mode defaults to passive for this verdict specifically: the domain-level evidence
    is VirusTotal and OTX records, and the actively-resolved addresses feed the *per-address*
    verdicts rather than this one.
    """
    now = _require_aware(now)
    domain = str(data.get("domain") or "")
    status = data.get("domain_provider_status")
    if coverage is None:
        coverage = Coverage.from_status_map(status) if isinstance(status, Mapping) else Coverage()
    return evaluate(
        indicator=domain,
        scope=IndicatorScope.DOMAIN,
        signals=sig.extract_domain_intel_signals(data.get("domain_intel"), cfg, now, domain=domain),
        coverage=coverage,
        cfg=cfg,
        now=now,
        infrastructure=None,
        passive_only=passive_only,
        active_collection=active_collection,
    )
