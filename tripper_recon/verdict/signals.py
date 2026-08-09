"""Signal extraction: turning one provider's payload into evidence a verdict can be built from.

Roadmap W5.3 and W5.11. Everything in this module is a **pure function**. No I/O, no network,
no filesystem, no clock read -- the current time arrives as an injected ``now`` argument and
nothing in here can observe it any other way. That purity is not stylistic: it is what lets the
whole engine be tested offline against committed fixtures, with no API keys, and with no
possibility of a test accidentally touching a target.

Every extractor has the shape ``(payload, cfg, now) -> List[Signal]``, with two keyword
arguments -- ``scope`` and ``indicator`` -- that carry which kind of indicator is being scored
and what it is called. Neither changes the arithmetic; ``scope`` selects which signals the
ruleset says apply, and ``indicator`` only builds the deep link.

The rules this module is built to enforce
-----------------------------------------

**1. Absent data never scores as clean.** An extractor handed a payload the provider never
filled -- ``{}`` from a failed call, an unconfigured provider, a ``None``, or a list where a
dict belonged -- returns an **empty list**. It does not return a zero-magnitude "looks fine"
signal, because downstream a zero-magnitude signal is indistinguishable from an answer, and
that is exactly how "never asked" starts rendering as "came back clean".

A benign reading has to be *earned* by an affirmative negative. VirusTotal answering that 0 of
94 engines flagged the indicator is evidence, and emits :data:`VT_NO_DETECTIONS`. VirusTotal
404ing is not evidence, and emits nothing at all. The ids that count as affirmative negatives
are enumerated in :data:`AFFIRMATIVE_NEGATIVE_SIGNAL_IDS` so the engine's
``verdict_rules.require_affirmative_negative`` check does not have to re-derive them.

**2. Confidence is not score.** Nothing here computes confidence. Extractors report what a
provider said and how strongly; how much of the panel answered is :class:`Coverage`'s job and
weighing the two apart is the engine's. No signal carries an opinion about panel completeness.

**3. No invented numbers.** There is not one scoring constant in this file. Every weight,
saturation point, decay band and threshold is read from
:class:`~tripper_recon.verdict.config.ScoringConfig`, and every emitted signal records the
ruleset key it came from in :attr:`Signal.weight_source`. Where the ruleset has no knob for
something, the signal is binary rather than scaled -- see :data:`VT_COMMUNITY_REPUTATION` --
because inventing a saturation constant to make a curve look sophisticated is the defect this
rule exists to prevent.

**4. No accuracy claim.** This is a heuristic. No statement about how often it is right appears
in this module, its output, or its docstrings, because no labelled corpus exists to support one.

**5. No denylist of named VirusTotal engines.** ``virustotal.engine_weights`` and
``virustotal.high_confidence_engines`` are config-driven mechanisms and both ship **empty**.
With an empty ``engine_weights`` every engine carries ``default_engine_weight``, which is an
honest stated assumption. There is no measurement here that would justify naming vendors as low
quality, and shipping an unsourced list would be both wrong and a liability.

**6. Contradictions are surfaced, not averaged.** No extractor cancels another's points and none
ever emits negative points. AbuseIPDB returning 0% while VirusTotal shows detections produces
*two* signals pointing opposite ways -- :data:`ABUSE_REPORTS_NO_CONFIDENCE` and
``vt.weighted_detections`` -- which is precisely the input the ``vt_vs_abuseipdb``
contradiction rule needs. Averaging them here would destroy the finding before the engine saw
it.

Two notes for the engine lane
-----------------------------

**Direction and points are independent axes.** :attr:`Signal.direction` is the evidentiary
claim; :attr:`Signal.points` is the contribution to the risk score. Shodan exposure is the case
that forces them apart: an exposed RDP box is a real risk and worth points, and it is *not*
evidence that its owner is hostile, so it is emitted as
:attr:`SignalDirection.CONTEXT` with points and with ``ceiling_only`` set from the ruleset. An
engine that sums only :attr:`SignalDirection.ADVERSE` points will under-score exposure, which
is the safe direction to be wrong in; an engine that reads CONTEXT as evidence of malice will
label every badly-run business in the country malicious, which is not.

**Observational signals carry ids outside ``SignalId``.** The ruleset's ``signals:`` table
weights the twelve scored signals. The affirmative negatives and context notes below have no
weight, always carry ``points == 0.0`` and ``max_points == 0.0``, and use the ids in
:data:`OBSERVATIONAL_SIGNAL_IDS`. They exist because ``require_affirmative_negative`` cannot be
satisfied without them.

Interface note
--------------

:class:`Signal` is defined here because the models lane (roadmap 5.1) had not landed when this
was written, and an extractor cannot be written against a type that does not exist. When
``types.models.Signal`` arrives it should own the definition and this module should import it;
the field names below are the contract to preserve. :class:`ScoringConfig` is **not**
redefined -- it is imported from the config lane, which is the single source of every number
here.
"""

from __future__ import annotations

import datetime as dt
import difflib
import re
from collections import Counter
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple

from pydantic import BaseModel, Field

from tripper_recon.verdict.config import (
    TRANCO_HISTORY_WINDOW_DAYS,
    AuthorDiversityMode,
    IndicatorScope,
    ScoringConfig,
    SignalConfig,
    SignalId,
)

__all__ = [
    "AFFIRMATIVE_NEGATIVE_SIGNAL_IDS",
    "OBSERVATIONAL_SIGNAL_IDS",
    "Signal",
    "SignalDirection",
    "extract_abusech_signals",
    "extract_abuseipdb_signals",
    "extract_asn_metadata_signals",
    "extract_domain_intel_signals",
    "extract_domain_signals",
    "extract_internetdb_signals",
    "extract_ip_signals",
    "extract_ipinfo_signals",
    "extract_otx_signals",
    "extract_rdap_signals",
    "extract_shodan_signals",
    "extract_tranco_signals",
    "extract_url_signals",
    "extract_virustotal_signals",
]


# --------------------------------------------------------------------------------------
# Observational signal ids. Zero-weight, outside the ruleset's `signals:` table.
# --------------------------------------------------------------------------------------

#: VirusTotal answered and no engine flagged the indicator.
VT_NO_DETECTIONS = "vt.no_detections"
#: AbuseIPDB answered and holds no reports.
ABUSE_NO_REPORTS = "abuseipdb.no_reports"
#: AbuseIPDB holds reports and still assigns zero confidence -- the ``vt_vs_abuseipdb`` input.
ABUSE_REPORTS_NO_CONFIDENCE = "abuseipdb.reports_without_confidence"
#: AbuseIPDB's own whitelist flag. A Tier C vendor suppression input, not a clearance.
ABUSE_WHITELISTED = "abuseipdb.whitelisted"
#: A Tor node. Not "malicious": abuse traffic is expected and is not attributable to the host.
ABUSE_TOR_EXIT = "abuseipdb.tor_exit"
#: Hosting versus residential versus mobile. Changes what a report about the address means.
ABUSE_USAGE_TYPE = "abuseipdb.usage_type"
#: OTX answered and holds no pulses.
OTX_NO_PULSES = "otx.no_pulses"
#: Shodan holds a record with no risky ports and no CVEs.
SHODAN_NO_EXPOSURE = "shodan.no_exposure"
#: Who announces the address and where it geolocates.
ASN_IDENTITY = "asn.identity"
#: Registry-level ASN description from Cloudflare Radar.
ASN_METADATA = "asn.metadata"
#: Who registered the object and when, as the registry itself reports it. The incident-report
#: facts: registrar, registration and expiry dates, delegation, network or AS handle.
RDAP_REGISTRATION = "rdap.registration"
#: A published abuse address. The single field this provider exists to put in a ticket.
RDAP_ABUSE_CONTACT = "rdap.abuse_contact"
#: Tranco lists the domain. Suppression-only: it lowers how much suspicion a *reputation*
#: argument deserves and never clears an indicator, so it carries no points and is deliberately
#: NOT an affirmative negative -- a popularity rank is not a provider saying "asked, nothing
#: here".
TRANCO_RANK = "tranco.rank"
#: Tranco does not list the domain. **Not adverse**, and emitted precisely so nobody reads the
#: silence as one: the list holds about a million domains and the honest web holds hundreds of
#: millions, so almost every legitimate small site is unranked.
TRANCO_UNRANKED = "tranco.unranked"

#: Every id emitted by this module that is not in the ruleset's weight table. All carry zero
#: points. An engine may render them and must not score them.
OBSERVATIONAL_SIGNAL_IDS: FrozenSet[str] = frozenset(
    {
        VT_NO_DETECTIONS,
        ABUSE_NO_REPORTS,
        ABUSE_REPORTS_NO_CONFIDENCE,
        ABUSE_WHITELISTED,
        ABUSE_TOR_EXIT,
        ABUSE_USAGE_TYPE,
        OTX_NO_PULSES,
        SHODAN_NO_EXPOSURE,
        ASN_IDENTITY,
        ASN_METADATA,
        RDAP_REGISTRATION,
        RDAP_ABUSE_CONTACT,
        TRANCO_RANK,
        TRANCO_UNRANKED,
    }
)

#: The subset that constitutes an *affirmative negative*: a provider that was asked and reported
#: nothing adverse. ``verdict_rules.require_affirmative_negative`` is satisfied by these and by
#: nothing else -- not by an empty signal list, and not by a provider that failed to answer.
#:
#: Four sources added in the 0.2.0 ruleset are deliberately absent from this set, and each
#: omission is load-bearing:
#:
#: * :data:`TRANCO_RANK` -- "this domain is popular" is not "no provider reported anything
#:   adverse". Admitting it would let a Tranco rank alone unlock the clean verdict.
#: * :data:`RDAP_REGISTRATION` / :data:`RDAP_ABUSE_CONTACT` -- registration data says who owns a
#:   name, not whether anybody has complained about it.
#: * abuse.ch -- a miss returns a *failure* envelope from the provider module, so the extractor
#:   never sees a payload to build a signal from. "abuse.ch holds no record" is the state of the
#:   overwhelming majority of the internet and carries no exculpatory weight at all.
AFFIRMATIVE_NEGATIVE_SIGNAL_IDS: FrozenSet[str] = frozenset(
    {
        VT_NO_DETECTIONS,
        ABUSE_NO_REPORTS,
        ABUSE_REPORTS_NO_CONFIDENCE,
        OTX_NO_PULSES,
    }
)

#: Upper bound on pairwise title comparisons in the OTX novelty check. A compute bound, not a
#: scoring parameter: it caps how many previously-seen titles a new one is compared against so a
#: pathological pulse list cannot make extraction quadratic in the thousands.
_MAX_TITLE_COMPARISONS = 200

#: Deep links, built only when the caller passes ``indicator``. The same URLs
#: ``reporting.console`` already puts on the screen; attaching them to the evidence is what makes
#: a pasted incident-report line clickable. They carry no scoring meaning.
_ABUSEIPDB_LINK = "https://www.abuseipdb.com/check/{indicator}"
_OTX_IP_LINK = "https://otx.alienvault.com/indicator/ip/{indicator}"
_OTX_DOMAIN_LINK = "https://otx.alienvault.com/indicator/domain/{indicator}"
_SHODAN_LINK = "https://www.shodan.io/host/{indicator}"

#: Family for a provider the ruleset does not place. Not a scoring value: corroboration is
#: counted by family, and an unplaced provider corroborating nothing is the conservative reading.
UNKNOWN_FAMILY = "unknown"

#: Provider keys, matching ``orchestrators.IP_PROVIDERS`` and the ruleset's family map.
_VIRUSTOTAL = "virustotal"
_ABUSEIPDB = "abuseipdb"
_OTX = "otx"
_OTX_DOMAIN = "otx_domain"
_SHODAN = "shodan"
_IPINFO = "ipinfo"
_CLOUDFLARE_ASN = "cloudflare_asn"
_CLOUDFLARE_BGP = "cloudflare_bgp"
#: The keyless Shodan InternetDB extract. A DIFFERENT provider name for the same signal slot, so
#: a report says which dataset answered -- InternetDB drops the per-service banners, the network
#: owner and, decisively, the observation date.
_INTERNETDB = "internetdb"
_RDAP = "rdap"
_TRANCO = "tranco"
#: abuse.ch. ONE provider key, because it is one composed call filling one coverage slot --
#: ``providers.abusech.abusech_host_summary`` asks URLhaus and ThreatFox and merges the two.
#: Which platform saw the thing is carried by the signal id (``urlhaus.listing`` /
#: ``threatfox.ioc``) and by its observation sentence, not by a second provider name that would
#: imply a second thing to have coverage of.
_ABUSECH = "abusech"

#: The provider ``data`` key that says an exposure payload came from InternetDB rather than the
#: paid Shodan record (``providers/internetdb.INTERNETDB_SOURCE``). Compared rather than
#: imported to keep this module free of provider imports; the value is pinned by a test.
INTERNETDB_SOURCE_VALUE = "shodan_internetdb"


# --------------------------------------------------------------------------------------
# The Signal
# --------------------------------------------------------------------------------------


class SignalDirection(str, Enum):
    """Which way a signal points, independently of what it is worth.

    Direction may not be inferred from ``points`` and points may not be inferred from
    direction. A signal worth zero can be strongly exculpatory (AbuseIPDB explicitly holds no
    reports); a signal worth ten can be purely descriptive (the host exposes RDP).
    """

    #: Evidence that the indicator is hostile.
    ADVERSE = "adverse"
    #: An affirmative negative: a provider that was asked and reported nothing adverse.
    EXCULPATORY = "exculpatory"
    #: Describes what the indicator *is*. Never evidence of hostility, whatever it is worth.
    CONTEXT = "context"


class Signal(BaseModel):
    """One provider observation, normalised, with the sentence an analyst can paste.

    :attr:`magnitude` is the normalised strength in ``[0.0, 1.0]`` and :attr:`points` is
    ``magnitude * max_points``. Both are carried because they answer different questions:
    magnitude is comparable across signals, points is what the engine sums.

    :attr:`observation` is the deliverable half of this model. A verdict has to be explainable
    entirely from its signals, which means each signal explains itself in one line without the
    reader holding the payload. "VirusTotal: 5 of 91 engines adverse (weighted 5.00 of 8.00);
    observed 412 days ago (recency x0.50); no high-confidence engine flagged it" survives being
    read back at a review board six months later. "5/91" does not.
    """

    #: Stable identifier. Either a ``SignalId`` value or one of :data:`OBSERVATIONAL_SIGNAL_IDS`.
    id: str
    #: The orchestrator's provider key, e.g. ``virustotal``, ``otx_domain``.
    provider: str
    #: The independence family from ``provider_families``. Corroboration counts these, not
    #: providers, so two feeds re-ingesting one upstream cannot corroborate each other.
    family: str
    direction: SignalDirection
    #: Normalised strength, ``0.0``-``1.0``.
    magnitude: float = Field(ge=0.0, le=1.0)
    #: Contribution to the score. Never negative: a signal cannot cancel another's evidence.
    points: float = Field(ge=0.0)
    #: This signal's ceiling, from the ruleset. ``0.0`` for an observational signal.
    max_points: float = Field(ge=0.0)
    #: One line, report-pasteable, self-contained.
    observation: str
    #: The values the signal was computed from, so the arithmetic can be re-derived.
    evidence: Dict[str, Any] = Field(default_factory=dict)
    #: The untransformed provider value at the centre of the signal, when there is one.
    raw_value: Any = None
    #: Which ruleset and key set this signal's weight, e.g.
    #: ``package:tripper_recon.verdict/scoring.yaml#signals.vt.weighted_detections``.
    weight_source: str
    #: When the provider made the observation, as the provider reported it.
    observed_at: Optional[str] = None
    #: Deep link for the analyst, when one is derivable without inventing it.
    source_url: Optional[str] = None
    #: From ``SignalConfig.ceiling_only``: may raise a verdict at most to
    #: ``verdict_rules.ceiling_only_cap``, whatever its points.
    ceiling_only: bool = False


# --------------------------------------------------------------------------------------
# Defensive readers. Every provider field goes through one of these.
# --------------------------------------------------------------------------------------


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _as_str(value: Any) -> Optional[str]:
    """A non-empty string, or ``None``. Never ``str(value)``: coercion manufactures evidence."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _as_int(value: Any) -> Optional[int]:
    """An int, or ``None``. ``bool`` is rejected -- ``True`` is not a count."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _as_float(value: Any) -> Optional[float]:
    """A finite float from an int or a float, or ``None``. NaN and infinities are rejected."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    if result != result or result in (float("inf"), float("-inf")):
        return None
    return result


def _as_bool(value: Any) -> Optional[bool]:
    """A real bool, or ``None``. ``bool(value)`` would assert a negative nobody made."""
    return value if isinstance(value, bool) else None


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


_ISO_FRACTION = re.compile(r"\.(\d+)")
_FALLBACK_DATE_FORMATS: Tuple[str, ...] = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d",
    "%d-%b-%Y",
    "%d.%m.%Y",
    "%Y/%m/%d",
)


def _parse_timestamp(value: Any) -> Optional[dt.datetime]:
    """Parse a provider timestamp into aware UTC, or ``None``.

    Handles the three shapes the providers in this package emit: a Unix epoch (VirusTotal), an
    offset-bearing ISO-8601 string (AbuseIPDB), and a naive ISO-8601 string documented as UTC
    (Shodan, OTX). A naive value is read as UTC because that is what those providers document;
    guessing a local offset would silently move an evidence timestamp.

    Anything unparseable returns ``None``, which every caller routes into
    ``ScoringConfig.decay_factor(profile, None)`` -- the open-ended tail, the most conservative
    factor in the profile. Undated evidence is treated as old rather than as fresh. This
    function never raises and never guesses.
    """
    epoch = _as_float(value)
    if epoch is not None:
        try:
            return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None

    text = _as_str(value)
    if text is None:
        return None

    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    # fromisoformat before 3.11 accepts only 3- or 6-digit fractional seconds.
    match = _ISO_FRACTION.search(candidate)
    if match is not None and len(match.group(1)) not in (3, 6):
        candidate = candidate[: match.start()] + candidate[match.end() :]
    parsed: Optional[dt.datetime]
    try:
        parsed = dt.datetime.fromisoformat(candidate)
    except ValueError:
        parsed = None
    if parsed is None:
        for fmt in _FALLBACK_DATE_FORMATS:
            try:
                parsed = dt.datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _require_aware(now: dt.datetime) -> dt.datetime:
    """Reject a naive ``now``.

    Provider fields are tolerated in any shape because they are third-party data. ``now`` comes
    from this codebase, and a naive one has no defensible meaning in an artefact whose whole job
    is to date evidence.
    """
    if not isinstance(now, dt.datetime):
        raise TypeError("now must be a datetime")
    if now.tzinfo is None or now.tzinfo.utcoffset(now) is None:
        raise ValueError("now must be timezone-aware; a naive datetime has no defensible meaning")
    return now.astimezone(dt.timezone.utc)


def _age_days(observed: Optional[dt.datetime], now: dt.datetime) -> Optional[float]:
    """Age in days, or ``None`` when there is no timestamp. Never negative."""
    if observed is None:
        return None
    return max((now - observed).total_seconds() / 86400.0, 0.0)


def _age_phrase(age_days: Optional[float], factor: float) -> str:
    """The recency clause of an observation, naming the discount rather than hiding it.

    An undated observation says the age is unknown rather than asserting it is stale. That is
    the honest reading -- the engine does not know whether the evidence is a day or a decade
    old -- and it is the safe one: discounting an undated adverse finding argues the indicator
    clean on the strength of a missing field. See
    :class:`~tripper_recon.verdict.config.UndatedEvidenceConfig`.
    """
    if age_days is None:
        return f"observation date not reported, so its age is unknown and undiscounted (recency x{factor:.2f})"
    return f"observed {age_days:.0f} days ago (recency x{factor:.2f})"


def _link(template: str, indicator: Optional[str]) -> Optional[str]:
    return template.format(indicator=indicator) if indicator else None


def _wiring(cfg: ScoringConfig, signal_id: SignalId, scope: IndicatorScope) -> Optional[SignalConfig]:
    """The ruleset entry for a signal, or ``None`` if it is disabled or out of scope.

    Returning ``None`` makes the extractor emit nothing for that signal. That is a config
    decision the operator made, distinct from absent data, and the ruleset records it.
    """
    entry = cfg.signals.get(signal_id)
    if entry is None or not entry.enabled or scope not in entry.applies_to:
        return None
    return entry


def _scored(
    *,
    signal_id: SignalId,
    wiring: SignalConfig,
    provider: str,
    cfg: ScoringConfig,
    direction: SignalDirection,
    magnitude: float,
    observation: str,
    evidence: Optional[Dict[str, Any]] = None,
    raw_value: Any = None,
    observed_at: Optional[str] = None,
    source_url: Optional[str] = None,
) -> Signal:
    """Build a weighted signal, deriving points from magnitude so the two cannot disagree."""
    clamped = _clamp01(magnitude)
    return Signal(
        id=signal_id.value,
        provider=provider,
        family=cfg.family_of(provider) or UNKNOWN_FAMILY,
        direction=direction,
        magnitude=round(clamped, 6),
        points=round(clamped * wiring.max_points, 4),
        max_points=wiring.max_points,
        observation=observation,
        evidence=evidence or {},
        raw_value=raw_value,
        weight_source=cfg.weight_source(signal_id),
        observed_at=observed_at,
        source_url=source_url,
        ceiling_only=wiring.ceiling_only,
    )


def _observational(
    *,
    signal_id: str,
    provider: str,
    cfg: ScoringConfig,
    direction: SignalDirection,
    observation: str,
    block: str,
    evidence: Optional[Dict[str, Any]] = None,
    raw_value: Any = None,
    observed_at: Optional[str] = None,
    source_url: Optional[str] = None,
) -> Signal:
    """Build a zero-weight signal: an affirmative negative or a context note.

    These are the only signals whose id is outside ``SignalId``, and they are structurally
    incapable of moving a score -- ``max_points`` is zero, so ``points`` is zero whatever the
    engine does with them.
    """
    return Signal(
        id=signal_id,
        provider=provider,
        family=cfg.family_of(provider) or UNKNOWN_FAMILY,
        direction=direction,
        magnitude=0.0,
        points=0.0,
        max_points=0.0,
        observation=observation,
        evidence=evidence or {},
        raw_value=raw_value,
        weight_source=f"{cfg.source_label}#{block}",
        observed_at=observed_at,
        source_url=source_url,
    )


# --------------------------------------------------------------------------------------
# VirusTotal
# --------------------------------------------------------------------------------------


def _vt_engine_verdicts(payload: Mapping[str, Any]) -> List[Tuple[str, str]]:
    """``(engine, category)`` for every adverse engine, from whichever field carries it.

    Prefers the compact ``vt_detecting_engines`` list the provider module derives, and falls
    back to the full ``vt_security_results`` map. Both are read defensively: an entry that is
    not a dict, or that carries no usable category, is skipped rather than partially trusted.
    """
    verdicts: List[Tuple[str, str]] = []
    for entry in _as_list(payload.get("vt_detecting_engines")):
        if not isinstance(entry, dict):
            continue
        name = _as_str(entry.get("engine"))
        category = _as_str(entry.get("category"))
        if name and category and category.lower() in ("malicious", "suspicious"):
            verdicts.append((name, category.lower()))
    if verdicts:
        return sorted(verdicts)

    for key, verdict in _as_dict(payload.get("vt_security_results")).items():
        if not isinstance(verdict, dict):
            continue
        category = _as_str(verdict.get("category"))
        name = _as_str(key)
        if name and category and category.lower() in ("malicious", "suspicious"):
            verdicts.append((name, category.lower()))
    return sorted(verdicts)


def _vt_stats(payload: Mapping[str, Any]) -> Tuple[Dict[str, int], int]:
    """The ``last_analysis_stats`` counts and the engine total, ignoring non-int members."""
    stats: Dict[str, int] = {}
    for key, value in _as_dict(payload.get("vt_last_analysis_stats")).items():
        count = _as_int(value)
        if count is not None and count >= 0:
            stats[str(key)] = count
    return stats, sum(stats.values())


def _vt_analysis_time(payload: Mapping[str, Any]) -> Tuple[Optional[dt.datetime], Optional[str]]:
    parsed = _parse_timestamp(payload.get("vt_last_analysis_date"))
    if parsed is None:
        parsed = _parse_timestamp(payload.get("vt_last_analysis_date_iso"))
    reported = _as_str(payload.get("vt_last_analysis_date_iso"))
    if reported is None and parsed is not None:
        reported = parsed.isoformat()
    return parsed, reported


def extract_virustotal_signals(
    payload: Any,
    cfg: ScoringConfig,
    now: dt.datetime,
    *,
    scope: IndicatorScope = IndicatorScope.IP,
    indicator: Optional[str] = None,
) -> List[Signal]:
    """Signals from a VirusTotal IP or domain summary.

    The count alone is a weak signal that reads as a strong one: ``5/91`` is not a measurement,
    it is 91 measurements with a lossy aggregation applied. So the detection signal is built
    from ``last_analysis_results`` -- retained by roadmap W4.6 -- as a weighted total over the
    engines that actually flagged the indicator, decayed by the age of the analysis, and it
    carries the engine names in its evidence so the observation can say which ones.

    Per-engine weights come from ``virustotal.engine_weights``, which **ships empty**: with no
    corpus there is no measured basis for calling any vendor low quality, and this module will
    not assert one. When the payload has no per-engine data at all the signal falls back to the
    aggregate counts and says so in the observation, rather than presenting a coarser number as
    though it were the finer one.

    Returns ``[]`` for a payload VirusTotal never filled. A clean answer -- stats present, no
    adverse engine -- emits :data:`VT_NO_DETECTIONS`, which is the affirmative negative the
    engine needs before any benign reading is available to it.
    """
    now = _require_aware(now)
    data = _as_dict(payload)
    if not data:
        return []

    stats, total_engines = _vt_stats(data)
    verdicts = _vt_engine_verdicts(data)
    if not verdicts and not stats:
        # VirusTotal is present in the payload but said nothing measurable. Not an observation.
        return []

    analysis_at, observed_at = _vt_analysis_time(data)
    age = _age_days(analysis_at, now)
    link = _as_str(data.get("vt_link"))
    signals: List[Signal] = []

    signals.extend(
        _vt_detection_signals(
            data,
            cfg,
            scope,
            stats=stats,
            total_engines=total_engines,
            verdicts=verdicts,
            age=age,
            observed_at=observed_at,
            link=link,
        )
    )
    signals.extend(_vt_reputation_signals(data, cfg, scope, observed_at=observed_at, link=link))
    signals.extend(_vt_category_signals(data, cfg, scope, observed_at=observed_at, link=link))
    _ = indicator  # the deep link comes from the payload's own vt_link; nothing is constructed
    return signals


def _vt_detection_signals(
    data: Mapping[str, Any],
    cfg: ScoringConfig,
    scope: IndicatorScope,
    *,
    stats: Mapping[str, int],
    total_engines: int,
    verdicts: Sequence[Tuple[str, str]],
    age: Optional[float],
    observed_at: Optional[str],
    link: Optional[str],
) -> List[Signal]:
    vt = cfg.virustotal
    recency = cfg.decay_factor(vt.recency_profile, age)
    malicious = [name for name, category in verdicts if category == "malicious"]
    suspicious = [name for name, category in verdicts if category == "suspicious"]
    per_engine = bool(verdicts)

    if per_engine:
        weighted = sum(vt.engine_weights.get(name, vt.default_engine_weight) for name in malicious)
        weighted += vt.suspicious_multiplier * sum(
            vt.engine_weights.get(name, vt.default_engine_weight) for name in suspicious
        )
        adverse_count = len(malicious) + len(suspicious)
    else:
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        weighted = vt.default_engine_weight * (malicious_count + vt.suspicious_multiplier * suspicious_count)
        adverse_count = malicious_count + suspicious_count

    if adverse_count <= 0:
        if not stats:
            return []
        return [
            _observational(
                signal_id=VT_NO_DETECTIONS,
                provider=_VIRUSTOTAL,
                cfg=cfg,
                direction=SignalDirection.EXCULPATORY,
                observation=(
                    f"VirusTotal: 0 of {total_engines} engines flagged this indicator; "
                    f"{_age_phrase(age, recency)}. An answer, not an absence"
                ),
                block="virustotal",
                evidence={"total_engines": total_engines, "analysis_age_days": age},
                raw_value=dict(stats),
                observed_at=observed_at,
                source_url=link,
            )
        ]

    wiring = _wiring(cfg, SignalId.VT_WEIGHTED_DETECTIONS, scope)
    if wiring is None:
        return []

    high_confidence = {name.casefold() for name in vt.high_confidence_engines}
    hc_hits = sorted({name for name in [*malicious, *suspicious] if name.casefold() in high_confidence})
    if not high_confidence:
        hc_clause = "no high-confidence engine set is configured, so no single engine hit is decisive"
    elif hc_hits:
        hc_clause = f"high-confidence engines flagged it: {', '.join(hc_hits)}"
    else:
        hc_clause = "no high-confidence engine flagged it"
    denominator = str(total_engines) if total_engines else "an unreported number of"
    weighting_clause = f"weighted {weighted:.2f} of {vt.saturation:.2f}"
    if not per_engine:
        weighting_clause += " from aggregate counts only, per-engine results absent from the payload"

    # The malicious/suspicious lists hold NAMED engines and are empty when the payload carried
    # only aggregate counts. Printing "(0 malicious, 0 suspicious)" one clause after "5 engines
    # adverse" reads as a contradiction, so the breakdown appears only when it is real.
    breakdown = f" ({len(malicious)} malicious, {len(suspicious)} suspicious)" if per_engine else ""
    observation = (
        f"VirusTotal: {adverse_count} of {denominator} engines adverse"
        f"{breakdown}; {weighting_clause}; "
        f"{_age_phrase(age, recency)}; {hc_clause}"
    )
    return [
        _scored(
            signal_id=SignalId.VT_WEIGHTED_DETECTIONS,
            wiring=wiring,
            provider=_VIRUSTOTAL,
            cfg=cfg,
            direction=SignalDirection.ADVERSE,
            magnitude=_clamp01(weighted / vt.saturation) * recency,
            observation=observation,
            evidence={
                "malicious_engines": malicious,
                "suspicious_engines": suspicious,
                "adverse_engine_count": adverse_count,
                "total_engines": total_engines,
                "weighted_detections": round(weighted, 4),
                "saturation": vt.saturation,
                "recency_factor": recency,
                "analysis_age_days": age,
                "high_confidence_hits": hc_hits,
                "consensus_threshold": vt.consensus_threshold,
                "per_engine_results_available": per_engine,
            },
            raw_value=dict(stats) or None,
            observed_at=observed_at,
            source_url=link,
        )
    ]


def _vt_reputation_signals(
    data: Mapping[str, Any],
    cfg: ScoringConfig,
    scope: IndicatorScope,
    *,
    observed_at: Optional[str],
    link: Optional[str],
) -> List[Signal]:
    """The community score. Binary, and deliberately so.

    The ruleset gives this signal a ceiling and no scale, and inventing a saturation constant
    to turn ``-37`` into a curve would be exactly the manufactured number the no-invented-numbers
    rule forbids. The ruleset's own note calls it "directional colour only", so it fires at full
    weight on any negative score and not at all otherwise.
    """
    reputation = _as_float(data.get("vt_reputation"))
    if reputation is None or reputation >= 0:
        return []
    wiring = _wiring(cfg, SignalId.VT_COMMUNITY_REPUTATION, scope)
    if wiring is None:
        return []
    return [
        _scored(
            signal_id=SignalId.VT_COMMUNITY_REPUTATION,
            wiring=wiring,
            provider=_VIRUSTOTAL,
            cfg=cfg,
            direction=SignalDirection.ADVERSE,
            magnitude=1.0,
            observation=(
                f"VirusTotal community score {reputation:.0f}. Crowd-sourced, gameable and "
                "unversioned, so this is directional colour and scores as a flag, not a curve"
            ),
            evidence={"reputation": reputation},
            raw_value=data.get("vt_reputation"),
            observed_at=observed_at,
            source_url=link,
        )
    ]


def _vt_category_signals(
    data: Mapping[str, Any],
    cfg: ScoringConfig,
    scope: IndicatorScope,
    *,
    observed_at: Optional[str],
    link: Optional[str],
) -> List[Signal]:
    """Vendor categorisation hitting an adverse term (domain payloads only)."""
    wiring = _wiring(cfg, SignalId.VT_CATEGORIES, scope)
    if wiring is None:
        return []
    raw = _as_dict(data.get("vt_categories"))
    if not raw:
        return []

    terms = cfg.vt_categories.adverse_terms
    matched_terms: Dict[str, List[str]] = {}
    labelled: Dict[str, str] = {}
    for vendor, category in raw.items():
        label = _as_str(category)
        if label is None:
            continue
        labelled[str(vendor)] = label
        folded = label.casefold()
        for term in terms:
            if term in folded:
                matched_terms.setdefault(term, []).append(str(vendor))
    if not matched_terms:
        return []

    if wiring.max_points <= 0:
        return []
    points = min(wiring.max_points, len(matched_terms) * cfg.vt_categories.points_per_term)
    rendered = "; ".join(f"{term} ({', '.join(sorted(vendors))})" for term, vendors in sorted(matched_terms.items()))
    return [
        _scored(
            signal_id=SignalId.VT_CATEGORIES,
            wiring=wiring,
            provider=_VIRUSTOTAL,
            cfg=cfg,
            direction=SignalDirection.ADVERSE,
            magnitude=points / wiring.max_points,
            observation=(
                f"VirusTotal: {len(matched_terms)} adverse category terms applied by named vendors -- {rendered}"
            ),
            evidence={
                "matched_terms": {term: sorted(vendors) for term, vendors in sorted(matched_terms.items())},
                "categorising_vendors": len(labelled),
                "points_per_term": cfg.vt_categories.points_per_term,
            },
            raw_value=labelled,
            observed_at=observed_at,
            source_url=link,
        )
    ]


# --------------------------------------------------------------------------------------
# AbuseIPDB
# --------------------------------------------------------------------------------------


def extract_abuseipdb_signals(
    payload: Any,
    cfg: ScoringConfig,
    now: dt.datetime,
    *,
    scope: IndicatorScope = IndicatorScope.IP,
    indicator: Optional[str] = None,
) -> List[Signal]:
    """Signals from an AbuseIPDB ``/check`` response.

    The vendor confidence score is decayed by ``lastReportedAt``: a 100% score from 2019 and a
    100% score from yesterday are the same number and completely different findings, and the
    tool previously could not tell an analyst which one it was holding.

    Report volume is scored separately and is discounted by reporter diversity, because one
    reporter filing fifty reports is one observation and not fifty. The split between volume and
    diversity is ``abuseipdb.volume_weight`` and ``diversity_weight``, which the ruleset
    validates to sum to one.

    ``isWhitelisted`` and ``isTor`` are separate signals with separate meanings, not modifiers
    on the score. A Tor node is not "malicious": it is a host where abuse traffic is expected
    and is not attributable to the operator of the host. That is a different sentence and it
    leads to a different action.

    A confidence of zero alongside a non-zero report count is AbuseIPDB affirmatively declining
    to call the address abusive. It is emitted as :data:`ABUSE_REPORTS_NO_CONFIDENCE` so the
    ``vt_vs_abuseipdb`` contradiction rule has something to point at when VirusTotal disagrees,
    and so that the disagreement reaches the analyst instead of being averaged into a number
    that describes neither provider.
    """
    now = _require_aware(now)
    data = _as_dict(payload)
    if not data:
        return []

    confidence = _as_int(data.get("abuseipdb_confidence_score"))
    reports = _as_int(data.get("abuseipdb_reports"))
    whitelisted = _as_bool(data.get("abuseipdb_is_whitelisted"))
    is_tor = _as_bool(data.get("abuseipdb_is_tor"))
    usage_type = _as_str(data.get("abuseipdb_usage_type"))
    distinct_users = _as_int(data.get("abuseipdb_num_distinct_users"))
    last_reported = _as_str(data.get("abuseipdb_last_reported_at"))

    if confidence is None and reports is None and whitelisted is None and is_tor is None and usage_type is None:
        return []

    ab = cfg.abuseipdb
    age = _age_days(_parse_timestamp(last_reported), now)
    recency = cfg.decay_factor(ab.recency_profile, age)
    link = _link(_ABUSEIPDB_LINK, indicator)
    window = f"the provider's {ab.max_age_days}-day reporting window"
    signals: List[Signal] = []

    confidence_wiring = _wiring(cfg, SignalId.ABUSEIPDB_CONFIDENCE, scope)
    if confidence_wiring is not None and confidence is not None and confidence > ab.confidence_floor:
        span = ab.confidence_saturation - ab.confidence_floor
        magnitude = _clamp01((confidence - ab.confidence_floor) / span) * recency
        signals.append(
            _scored(
                signal_id=SignalId.ABUSEIPDB_CONFIDENCE,
                wiring=confidence_wiring,
                provider=_ABUSEIPDB,
                cfg=cfg,
                direction=SignalDirection.ADVERSE,
                magnitude=magnitude,
                observation=(
                    f"AbuseIPDB: {confidence}% abuse confidence, scaled from a floor of "
                    f"{ab.confidence_floor:.0f}% to saturation at {ab.confidence_saturation:.0f}%; "
                    f"{_age_phrase(age, recency)}"
                ),
                evidence={
                    "confidence_score": confidence,
                    "confidence_floor": ab.confidence_floor,
                    "confidence_saturation": ab.confidence_saturation,
                    "recency_factor": recency,
                    "last_reported_age_days": age,
                    "reports": reports,
                },
                raw_value=confidence,
                observed_at=last_reported,
                source_url=link,
            )
        )

    volume_wiring = _wiring(cfg, SignalId.ABUSEIPDB_VOLUME_RECENCY, scope)
    if volume_wiring is not None and reports is not None and reports > 0:
        # A report implies at least one reporter. Using one rather than zero when the provider
        # omitted numDistinctUsers keeps the discount honest without inventing a reporter count.
        effective_users = distinct_users if distinct_users is not None else 1
        volume_component = ab.volume_weight * _clamp01(reports / ab.volume_saturation)
        diversity_component = ab.diversity_weight * _clamp01(effective_users / ab.distinct_users_saturation)
        reporters = (
            f"{distinct_users} distinct reporters"
            if distinct_users is not None
            else "reporter count not reported, counted as one"
        )
        signals.append(
            _scored(
                signal_id=SignalId.ABUSEIPDB_VOLUME_RECENCY,
                wiring=volume_wiring,
                provider=_ABUSEIPDB,
                cfg=cfg,
                direction=SignalDirection.ADVERSE,
                magnitude=(volume_component + diversity_component) * recency,
                observation=(
                    f"AbuseIPDB: {reports} reports within {window} from {reporters}; "
                    f"{_age_phrase(age, recency)}. Fifty reports from one reporter is one observation"
                ),
                evidence={
                    "reports": reports,
                    "distinct_users": distinct_users,
                    "effective_distinct_users": effective_users,
                    "volume_component": round(volume_component, 4),
                    "diversity_component": round(diversity_component, 4),
                    "recency_factor": recency,
                    "last_reported_age_days": age,
                    "max_age_days": ab.max_age_days,
                },
                raw_value=reports,
                observed_at=last_reported,
                source_url=link,
            )
        )

    if confidence == 0 and reports is not None and reports > 0:
        signals.append(
            _observational(
                signal_id=ABUSE_REPORTS_NO_CONFIDENCE,
                provider=_ABUSEIPDB,
                cfg=cfg,
                direction=SignalDirection.EXCULPATORY,
                observation=(
                    f"AbuseIPDB holds {reports} reports and still assigns 0% confidence -- the provider "
                    "is declining to call this address abusive, which is an answer and not a gap"
                ),
                block="abuseipdb",
                evidence={"reports": reports, "confidence_score": 0, "distinct_users": distinct_users},
                raw_value=0,
                observed_at=last_reported,
                source_url=link,
            )
        )
    elif confidence == 0:
        signals.append(
            _observational(
                signal_id=ABUSE_NO_REPORTS,
                provider=_ABUSEIPDB,
                cfg=cfg,
                direction=SignalDirection.EXCULPATORY,
                observation=f"AbuseIPDB was asked and holds no abuse reports for this address within {window}",
                block="abuseipdb",
                evidence={"reports": reports, "confidence_score": 0, "max_age_days": ab.max_age_days},
                raw_value=0,
                observed_at=last_reported,
                source_url=link,
            )
        )

    if whitelisted is True:
        signals.append(
            _observational(
                signal_id=ABUSE_WHITELISTED,
                provider=_ABUSEIPDB,
                cfg=cfg,
                direction=SignalDirection.EXCULPATORY,
                observation=(
                    "AbuseIPDB marks this address as whitelisted infrastructure. A vendor opinion, weak "
                    "on its own -- it demotes a verdict, it does not clear an address"
                ),
                block="overrides.tier_c",
                evidence={"is_whitelisted": True},
                raw_value=True,
                source_url=link,
            )
        )

    if is_tor is True:
        signals.append(
            _observational(
                signal_id=ABUSE_TOR_EXIT,
                provider=_ABUSEIPDB,
                cfg=cfg,
                direction=SignalDirection.CONTEXT,
                observation=(
                    "AbuseIPDB reports this address as a Tor node. Abuse traffic from it is expected and "
                    "is not attributable to the host operator -- treat any reports here as unattributed"
                ),
                block="abuseipdb",
                evidence={"is_tor": True},
                raw_value=True,
                source_url=link,
            )
        )

    if usage_type is not None:
        signals.append(
            _observational(
                signal_id=ABUSE_USAGE_TYPE,
                provider=_ABUSEIPDB,
                cfg=cfg,
                direction=SignalDirection.CONTEXT,
                observation=(f"AbuseIPDB usage type: {usage_type}. Changes what a report about this address means"),
                block="abuseipdb",
                evidence={"usage_type": usage_type},
                raw_value=usage_type,
                source_url=link,
            )
        )

    return signals


# --------------------------------------------------------------------------------------
# OTX
# --------------------------------------------------------------------------------------

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def _normalise_title(title: str) -> str:
    """Fold a pulse title to a comparison form: case-folded, punctuation to single spaces.

    ``jan2,2025 clone Auto-generated Pulse`` and ``jan 2 25 clone Auto-generated Pulse`` are one
    bulk import wearing two names, and they only survive comparison once punctuation stops
    distinguishing them.
    """
    return _NON_ALNUM.sub(" ", title.casefold()).strip()


class _PulseWeighting(BaseModel):
    """The arithmetic behind ``otx.pulse_quality``, kept inspectable rather than inline."""

    effective: float
    detailed: int
    synthesised: int
    distinct_authors: int
    top_author: Optional[str]
    top_author_pulses: int
    duplicate_titles: int
    unattributed: int
    newest_age_days: Optional[float]
    oldest_age_days: Optional[float]


def _weigh_pulses(
    records: Sequence[Any],
    synthesised: int,
    cfg: ScoringConfig,
    now: dt.datetime,
) -> _PulseWeighting:
    """Quality-adjust a pulse list: author diversity, recency, and title novelty.

    Three multiplicative factors per pulse:

    * **author diversity** -- harmonic when ``otx.author_diversity`` is ``harmonic``: the n-th
      pulse from one author is worth ``1/n``. Fifty pulses from one bulk-importing account
      collapse toward the weight of a handful, which is what they are.
    * **recency** -- from the pulse's own ``modified``, falling back to ``created``, through the
      ruleset's ``otx.recency_profile``. An undated pulse takes the profile's tail factor.
    * **title novelty** -- a title similar to one already counted, at or above
      ``otx.near_duplicate_ratio``, is worth ``otx.title_novelty_factor``.

    Pulses OTX counted but did not detail are synthesised as unattributed, undated records under
    ``otx.unattributed_author_key``. They share one harmonic bucket rather than counting as one
    author each: counting an unattributed pulse as its own author is precisely the error a
    diversity measure exists to prevent, and it would let a payload that dropped its author
    fields score higher than one that kept them.
    """
    otx = cfg.otx
    harmonic = otx.author_diversity is AuthorDiversityMode.HARMONIC
    author_counts: Counter[str] = Counter()
    seen_titles: List[str] = []
    effective = 0.0
    detailed = 0
    duplicates = 0
    unattributed = 0
    ages: List[float] = []

    def author_factor(key: str) -> float:
        author_counts[key] += 1
        return 1.0 / float(author_counts[key]) if harmonic else 1.0

    for record in records:
        if not isinstance(record, dict):
            continue
        detailed += 1

        author = _as_str(record.get("author"))
        if author is None:
            unattributed += 1
        factor = author_factor(author if author is not None else otx.unattributed_author_key)

        observed = _parse_timestamp(record.get("modified")) or _parse_timestamp(record.get("created"))
        age = _age_days(observed, now)
        if age is not None:
            ages.append(age)
        factor *= cfg.decay_factor(otx.recency_profile, age)

        title = _as_str(record.get("name"))
        if title is not None:
            normalised = _normalise_title(title)
            if normalised:
                if any(
                    difflib.SequenceMatcher(None, normalised, other).ratio() >= otx.near_duplicate_ratio
                    for other in seen_titles
                ):
                    factor *= otx.title_novelty_factor
                    duplicates += 1
                elif len(seen_titles) < _MAX_TITLE_COMPARISONS:
                    seen_titles.append(normalised)

        effective += factor

    undated_factor = cfg.decay_factor(otx.recency_profile, None)
    for _ in range(max(synthesised, 0)):
        unattributed += 1
        effective += author_factor(otx.unattributed_author_key) * undated_factor

    named = [(author, count) for author, count in author_counts.items() if author != otx.unattributed_author_key]
    top_author, top_count = max(named, key=lambda item: (item[1], item[0]), default=(None, 0))
    return _PulseWeighting(
        effective=round(effective, 4),
        detailed=detailed,
        synthesised=max(synthesised, 0),
        distinct_authors=len(named),
        top_author=top_author,
        top_author_pulses=top_count,
        duplicate_titles=duplicates,
        unattributed=unattributed,
        newest_age_days=min(ages) if ages else None,
        oldest_age_days=max(ages) if ages else None,
    )


def extract_otx_signals(
    payload: Any,
    cfg: ScoringConfig,
    now: dt.datetime,
    *,
    scope: IndicatorScope = IndicatorScope.IP,
    indicator: Optional[str] = None,
) -> List[Signal]:
    """Signals from an OTX ``general`` response, IP or domain.

    ``otx_pulse_count`` is replaced by a quality-adjusted count. The operator's own committed
    output is the case this exists for: fifty pulses whose sampled titles are near-identical
    auto-generated clones from a single author, a year old. Fifty is the wrong unit. After
    author-diversity and duplicate-title adjustment the count collapses to roughly three, and
    the year of age takes it lower still, so the signal correctly stops shouting.

    Pulses counted but not detailed in the payload are scored as unattributed, undated pulses
    rather than dropped or credited in full -- see :func:`_weigh_pulses`. A payload carrying
    only a count, which is the pre-W4.6 shape, therefore still produces a signal, at the weight
    the ruleset gives to evidence nobody can date or attribute.
    """
    now = _require_aware(now)
    data = _as_dict(payload)
    if not data:
        return []

    count = _as_int(data.get("otx_pulse_count"))
    records = [record for record in _as_list(data.get("otx_pulses")) if isinstance(record, dict)]
    malware_count = _as_int(data.get("otx_malware_count"))
    if count is None and not records and malware_count is None:
        return []

    domain_scope = scope is IndicatorScope.DOMAIN
    provider = _OTX_DOMAIN if domain_scope else _OTX
    link = _link(_OTX_DOMAIN_LINK if domain_scope else _OTX_IP_LINK, indicator)
    signals: List[Signal] = []

    reported = count if count is not None else len(records)
    if reported > 0:
        wiring = _wiring(cfg, SignalId.OTX_PULSE_QUALITY, scope)
        if wiring is not None:
            synthesised = max(reported - len(records), 0)
            weighting = _weigh_pulses(records, synthesised, cfg, now)
            clauses = [
                f"OTX: {reported} pulses reported, {weighting.effective:.2f} effective after "
                "author-diversity, recency and duplicate-title adjustment"
            ]
            if weighting.top_author is not None and weighting.top_author_pulses > 1:
                clauses.append(f"{weighting.top_author_pulses} of them are from one author ({weighting.top_author})")
            if weighting.duplicate_titles:
                clauses.append(f"{weighting.duplicate_titles} near-duplicate titles discounted")
            if weighting.synthesised:
                clauses.append(
                    f"{weighting.synthesised} pulses were counted but not detailed in the payload and "
                    "are weighed as unattributed and undated"
                )
            elif weighting.unattributed:
                clauses.append(f"{weighting.unattributed} pulses carry no author")
            signals.append(
                _scored(
                    signal_id=SignalId.OTX_PULSE_QUALITY,
                    wiring=wiring,
                    provider=provider,
                    cfg=cfg,
                    direction=SignalDirection.ADVERSE,
                    magnitude=_clamp01(weighting.effective / cfg.otx.effective_pulse_saturation),
                    observation="; ".join(clauses),
                    evidence={
                        "reported_pulse_count": reported,
                        "detailed_pulse_count": weighting.detailed,
                        "undetailed_pulse_count": weighting.synthesised,
                        "effective_pulses": weighting.effective,
                        "effective_pulse_saturation": cfg.otx.effective_pulse_saturation,
                        "distinct_authors": weighting.distinct_authors,
                        "top_author": weighting.top_author,
                        "top_author_pulses": weighting.top_author_pulses,
                        "duplicate_titles": weighting.duplicate_titles,
                        "unattributed_pulses": weighting.unattributed,
                        "newest_pulse_age_days": weighting.newest_age_days,
                        "oldest_pulse_age_days": weighting.oldest_age_days,
                    },
                    raw_value=count,
                    source_url=link,
                )
            )
    elif count == 0:
        signals.append(
            _observational(
                signal_id=OTX_NO_PULSES,
                provider=provider,
                cfg=cfg,
                direction=SignalDirection.EXCULPATORY,
                observation="OTX was asked and holds no pulses referencing this indicator",
                block="otx",
                evidence={"reported_pulse_count": 0},
                raw_value=0,
                source_url=link,
            )
        )

    malware_wiring = _wiring(cfg, SignalId.OTX_MALWARE_COUNT, scope)
    if malware_wiring is not None and malware_count is not None and malware_count > 0:
        signals.append(
            _scored(
                signal_id=SignalId.OTX_MALWARE_COUNT,
                wiring=malware_wiring,
                provider=provider,
                cfg=cfg,
                direction=SignalDirection.ADVERSE,
                magnitude=1.0,
                observation=(
                    f"OTX associates {malware_count} malware samples with this indicator. The payload "
                    "carries no date for the association, so it cannot be decayed"
                ),
                evidence={"malware_count": malware_count, "decayable": False},
                raw_value=malware_count,
                source_url=link,
            )
        )

    return signals


# --------------------------------------------------------------------------------------
# Shodan
# --------------------------------------------------------------------------------------


def extract_shodan_signals(
    payload: Any,
    cfg: ScoringConfig,
    now: dt.datetime,
    *,
    scope: IndicatorScope = IndicatorScope.IP,
    indicator: Optional[str] = None,
) -> List[Signal]:
    """Signals from a Shodan host record. Exposure is context, never malice.

    A host with open ports is not hostile; it is a host. Three things keep that from turning
    into false positives:

    * Only ports on ``shodan.risky_ports`` score at all, so 80 and 443 contribute nothing and an
      ordinary web server produces no points.
    * The signal is emitted as :attr:`SignalDirection.CONTEXT`. It describes what the host is.
    * ``ceiling_only`` comes straight from the ruleset, where it is ``true``: this signal may
      push a verdict to SUSPICIOUS and may never contribute to MALICIOUS.

    CVEs are folded into the same signal at ``shodan.points_per_cve``, capped by
    ``shodan.max_points_from_cves``. They are a patching finding about the host, not an
    attribution claim about its operator, and the observation says so.
    """
    return _exposure_signals(payload, cfg, now, scope=scope, indicator=indicator, provider=_SHODAN, label="Shodan")


def extract_internetdb_signals(
    payload: Any,
    cfg: ScoringConfig,
    now: dt.datetime,
    *,
    scope: IndicatorScope = IndicatorScope.IP,
    indicator: Optional[str] = None,
) -> List[Signal]:
    """The same exposure signal, from the keyless Shodan InternetDB extract (roadmap 8.1).

    InternetDB carries the five fields this extractor reads under the paid provider's own key
    names, so the arithmetic is identical and shares one ceiling: the two are alternative
    implementations of one slot and exactly one of them can ever answer for an address.

    **One difference matters and is not smoothed over.** InternetDB returns no observation date,
    so the age is genuinely unknown and ``undated_evidence`` prices it at 1.0 -- the finding is
    not discounted for a metadata field the dataset does not carry, and the observation string
    says the date was not reported instead of implying freshness. That is the same rule
    :class:`~tripper_recon.verdict.config.UndatedEvidenceConfig` states at length, applied to a
    provider that will hit it on every single call rather than occasionally.
    """
    return _exposure_signals(
        payload,
        cfg,
        now,
        scope=scope,
        indicator=indicator,
        provider=_INTERNETDB,
        label="Shodan InternetDB",
    )


def _exposure_signals(
    payload: Any,
    cfg: ScoringConfig,
    now: dt.datetime,
    *,
    scope: IndicatorScope,
    indicator: Optional[str],
    provider: str,
    label: str,
) -> List[Signal]:
    """Shared body for the paid and keyless exposure providers.

    ``provider`` decides which name the signal is attributed to -- and therefore what a report
    says answered -- while ``label`` is the display name in the observation sentence. Nothing
    else differs, deliberately: two copies of this arithmetic would drift, and the thing they
    would drift on is which ports count.
    """
    now = _require_aware(now)
    data = _as_dict(payload)
    if not data:
        return []

    ports = sorted({port for port in (_as_int(item) for item in _as_list(data.get("ports"))) if port is not None})
    vulns = sorted({text for text in (_as_str(item) for item in _as_list(data.get("vulns"))) if text})
    hostnames = sorted({text for text in (_as_str(item) for item in _as_list(data.get("hostnames"))) if text})
    last_update = _as_str(data.get("last_update"))
    org = _as_str(data.get("org"))
    if not (ports or vulns or hostnames or last_update or org or _as_list(data.get("tags"))):
        return []

    sh = cfg.shodan
    age = _age_days(_parse_timestamp(last_update), now)
    recency = cfg.decay_factor(sh.recency_profile, age)
    link = _link(_SHODAN_LINK, indicator)
    risky = [port for port in ports if port in set(sh.risky_ports)]

    wiring = _wiring(cfg, SignalId.SHODAN_EXPOSURE, scope)
    if wiring is None or wiring.max_points <= 0 or (not risky and not vulns):
        return [
            _observational(
                signal_id=SHODAN_NO_EXPOSURE,
                provider=provider,
                cfg=cfg,
                direction=SignalDirection.CONTEXT,
                observation=(
                    f"{label} holds a record for this host: {len(ports)} open ports, none on the risky-port "
                    f"list, and {len(vulns)} associated CVEs; {_age_phrase(age, recency)}. "
                    "Says nothing about intent either way"
                ),
                block="shodan",
                evidence={
                    "ports": ports,
                    "risky_ports": [],
                    "vulns": vulns,
                    "hostnames": hostnames,
                    "org": org,
                    "last_update_age_days": age,
                },
                observed_at=last_update,
                source_url=link,
            )
        ]

    cve_points = min(len(vulns) * sh.points_per_cve, sh.max_points_from_cves)
    raw_points = len(risky) * sh.points_per_risky_port + cve_points
    magnitude = _clamp01(raw_points / wiring.max_points) * recency
    port_clause = (
        f"{len(risky)} of {len(ports)} open ports are on the risky-port list ({', '.join(str(p) for p in risky)})"
        if risky
        else f"{len(ports)} open ports, none on the risky-port list"
    )
    cve_clause = (
        f"{len(vulns)} associated CVEs ({', '.join(vulns[:5])}{'...' if len(vulns) > 5 else ''})"
        if vulns
        else "no associated CVEs"
    )
    return [
        _scored(
            signal_id=SignalId.SHODAN_EXPOSURE,
            wiring=wiring,
            provider=provider,
            cfg=cfg,
            direction=SignalDirection.CONTEXT,
            magnitude=magnitude,
            observation=(
                f"{label}: {port_clause}; {cve_clause}; {_age_phrase(age, recency)}. "
                "Exposure describes what the host is, not whether it is hostile"
            ),
            evidence={
                "ports": ports,
                "risky_ports": risky,
                "vulns": vulns,
                "hostnames": hostnames,
                "org": org,
                "points_before_decay": round(raw_points, 4),
                "cve_points": round(cve_points, 4),
                "recency_factor": recency,
                "last_update_age_days": age,
            },
            raw_value=ports,
            observed_at=last_update,
            source_url=link,
        )
    ]


# --------------------------------------------------------------------------------------
# IPinfo and ASN metadata
# --------------------------------------------------------------------------------------


def extract_ipinfo_signals(
    payload: Any,
    cfg: ScoringConfig,
    now: dt.datetime,
    *,
    scope: IndicatorScope = IndicatorScope.IP,
    indicator: Optional[str] = None,
) -> List[Signal]:
    """Network metadata: who announces this address, and where it geolocates.

    This is the ``network_meta`` family, which the ruleset lists as non-corroborating: however
    many of its providers answer, they never add a family to the corroboration count. Identity
    is emitted as a zero-weight context note.

    The only scoring path is an ASN on ``asn.bulletproof_asns``, which **ships empty**.
    ASN-level guilt by association is the most likely source of systematic bias in the whole
    model -- a hosting ASN contains both the C2 and the victim -- so nothing here fires unless
    the ruleset names the network explicitly, with a citation behind it.
    """
    _require_aware(now)
    data = _as_dict(payload)
    if not data:
        return []

    asn = _as_int(data.get("asn"))
    org = _as_str(data.get("org"))
    country = _as_str(data.get("country"))
    city = _as_str(data.get("city"))
    hostname = _as_str(data.get("hostname"))
    if asn is None and org is None and country is None:
        return []

    descriptor = org or (f"AS{asn}" if asn is not None else "an unnamed network")
    location = ", ".join(part for part in (city, country) if part) or "an unreported location"
    signals: List[Signal] = [
        _observational(
            signal_id=ASN_IDENTITY,
            provider=_IPINFO,
            cfg=cfg,
            direction=SignalDirection.CONTEXT,
            observation=f"Announced by {descriptor}, geolocated to {location}",
            block="provider_families.network_meta",
            evidence={"asn": asn, "org": org, "country": country, "city": city, "hostname": hostname},
            raw_value=asn,
        )
    ]

    wiring = _wiring(cfg, SignalId.ASN_REPUTATION, scope)
    if wiring is not None and wiring.max_points > 0 and asn is not None and asn in cfg.asn.bulletproof_asns:
        points = min(cfg.asn.points_if_bulletproof, wiring.max_points)
        signals.append(
            _scored(
                signal_id=SignalId.ASN_REPUTATION,
                wiring=wiring,
                provider=_IPINFO,
                cfg=cfg,
                direction=SignalDirection.ADVERSE,
                magnitude=points / wiring.max_points,
                observation=(
                    f"AS{asn} ({descriptor}) is on the ruleset's bulletproof-hosting list. An ASN-level "
                    "prior describing the neighbourhood, not this address -- hosting networks contain "
                    "the adversary and the victim alike"
                ),
                evidence={"asn": asn, "org": org, "points_if_bulletproof": cfg.asn.points_if_bulletproof},
                raw_value=asn,
            )
        )

    _ = indicator
    return signals


def extract_asn_metadata_signals(
    payload: Any,
    cfg: ScoringConfig,
    now: dt.datetime,
    *,
    scope: IndicatorScope = IndicatorScope.IP,
    indicator: Optional[str] = None,
    bgp: Any = None,
) -> List[Signal]:
    """Cloudflare Radar ASN metadata, plus BGP hijack involvement when it was collected.

    Only the **hijacker** count is scored, and only when the provider supplied it directly.
    ``total_incidents - as_hijacker`` is not a victim count and this module will not re-derive
    one: that subtraction across two different denominators is the defect
    ``providers/cloudflare_rest.py`` was rewritten to remove, and reintroducing it here would put
    the same manufactured attribution claim back into an incident report. Counting victim
    involvement would also penalise the party that was attacked, which inverts the signal.
    """
    _require_aware(now)
    data = _as_dict(payload)
    signals: List[Signal] = []

    if data:
        asn = _as_int(data.get("asn"))
        name = _as_str(data.get("name"))
        organisation = data.get("organization")
        org_name = _as_str(_as_dict(organisation).get("name")) or _as_str(organisation)
        country = _as_str(data.get("countryCode"))
        rir = _as_str(data.get("rir"))
        caida_rank = _as_int(data.get("caidaRank"))
        if asn is not None or name is not None or org_name is not None:
            label = org_name or name or (f"AS{asn}" if asn is not None else "an unnamed network")
            parts = [f"Radar ASN metadata: {label}"]
            if country:
                parts.append(f"registered in {country}")
            if rir:
                parts.append(f"allocated by {rir.upper()}")
            if caida_rank is not None:
                parts.append(f"CAIDA rank {caida_rank}")
            signals.append(
                _observational(
                    signal_id=ASN_METADATA,
                    provider=_CLOUDFLARE_ASN,
                    cfg=cfg,
                    direction=SignalDirection.CONTEXT,
                    observation=", ".join(parts),
                    block="provider_families.network_meta",
                    evidence={
                        "asn": asn,
                        "name": name,
                        "organization": org_name,
                        "country": country,
                        "rir": rir,
                        "caida_rank": caida_rank,
                    },
                    raw_value=asn,
                )
            )

    hijacks = _as_dict(_as_dict(bgp).get("hijacks")) or _as_dict(bgp)
    as_hijacker = _as_int(hijacks.get("as_hijacker"))
    wiring = _wiring(cfg, SignalId.ASN_BGP_INCIDENTS, scope)
    if wiring is not None and as_hijacker is not None and as_hijacker > 0:
        total = _as_int(hijacks.get("total_incidents"))
        denominator = f" of {total} recorded incidents" if total is not None else ""
        signals.append(
            _scored(
                signal_id=SignalId.ASN_BGP_INCIDENTS,
                wiring=wiring,
                provider=_CLOUDFLARE_BGP,
                cfg=cfg,
                direction=SignalDirection.ADVERSE,
                magnitude=_clamp01(as_hijacker / cfg.asn.hijack_saturation),
                observation=(
                    f"Cloudflare Radar: this network was the hijacker in {as_hijacker}{denominator} BGP "
                    "incidents. Weak evidence about the network that tolerates abuse, not about this address"
                ),
                evidence={
                    "as_hijacker": as_hijacker,
                    "total_incidents": total,
                    "hijack_saturation": cfg.asn.hijack_saturation,
                },
                raw_value=as_hijacker,
            )
        )

    _ = indicator
    return signals


# --------------------------------------------------------------------------------------
# Domain-level
# --------------------------------------------------------------------------------------

_WHOIS_CREATION_KEYS = frozenset(
    {
        "created",
        "created date",
        "created on",
        "creation date",
        "domain registration date",
        "record created",
        "registered",
        "registered on",
        "registration date",
        "registration time",
    }
)
_WHOIS_LINE = re.compile(r"^\s*([A-Za-z][A-Za-z ./_-]{2,40})\s*[:=]\s*(\S.*?)\s*$")


def _whois_creation_date(whois: Any) -> Optional[dt.datetime]:
    """The earliest creation date named anywhere in a whois blob, or ``None``.

    Whois is free text from hundreds of registrars, so this reads defensively and gives up
    rather than guessing. Where several creation-like keys disagree -- registry and registrar
    records routinely do -- the **earliest** wins. That is the conservative direction: it makes
    the domain older, which lowers the score, so a parse ambiguity cannot inflate a verdict.
    """
    text = _as_str(whois)
    if text is None:
        return None
    found: List[dt.datetime] = []
    for line in text.splitlines():
        match = _WHOIS_LINE.match(line)
        if match is None:
            continue
        key = " ".join(match.group(1).lower().replace("_", " ").split())
        if key not in _WHOIS_CREATION_KEYS:
            continue
        parsed = _parse_timestamp(match.group(2))
        if parsed is not None:
            found.append(parsed)
    return min(found) if found else None


def _cert_common_name(section: Any) -> Optional[str]:
    """The ``CN`` from a certificate subject or issuer section, in whichever casing VT used."""
    data = _as_dict(section)
    return _as_str(data.get("CN")) or _as_str(data.get("cn")) or _as_str(data.get("common_name"))


def _hostname_matches(pattern: str, domain: str) -> bool:
    """Whether a certificate CN covers a domain, honouring a single leading wildcard label."""
    cn = pattern.strip().rstrip(".").casefold()
    host = domain.strip().rstrip(".").casefold()
    if not cn or not host:
        return False
    if cn == host:
        return True
    if cn.startswith("*."):
        suffix = cn[1:]  # ".example.com"
        return host.endswith(suffix) and host[: -len(suffix)].count(".") == 0
    return False


def extract_domain_signals(
    payload: Any,
    cfg: ScoringConfig,
    now: dt.datetime,
    *,
    scope: IndicatorScope = IndicatorScope.DOMAIN,
    indicator: Optional[str] = None,
    age_reported: bool = False,
) -> List[Signal]:
    """Domain-level signals from the VirusTotal domain payload: age and certificate anomalies.

    ``age_reported`` suppresses the whois-derived age when a better source already answered the
    same question. See :func:`extract_domain_intel_signals`: RDAP is the registry's own
    structured record and this path parses free-text whois from hundreds of registrars, so when
    RDAP reported an age -- including reporting that it does not know one -- letting both fire
    would score one registration date twice.

    Domain age is the highest-value single signal in phishing triage and the one an analyst is
    most likely to skip. It is never negative: an old domain is not clean, it is
    compromise-eligible, so the oldest band is worth zero rather than earning credit.

    When the whois blob yields no creation date the signal still fires, at
    ``domain_age.unknown_points``. That is the absent-data rule in its least obvious form:
    scoring an unknown registration date as zero would make it identical to "comfortably old",
    which is the clean end of this signal, so absence of evidence would read as evidence of age.

    Certificate sub-checks each emit their own ``cert.anomaly`` signal so the console can name
    which one fired rather than reporting an unexplained ten points. The ruleset validates that
    their points sum within the signal's ceiling.
    """
    now = _require_aware(now)
    data = _as_dict(payload)
    if not data:
        return []

    link = _as_str(data.get("vt_link"))
    signals: List[Signal] = []
    if not age_reported:
        signals.extend(_domain_age_signals(data, cfg, now, scope=scope, link=link))
    signals.extend(_certificate_signals(data, cfg, now, scope=scope, indicator=indicator, link=link))
    return signals


def _domain_age_band_points(cfg: ScoringConfig, age_days: Optional[float]) -> float:
    """Points for a domain of this age, from ``domain_age.bands``.

    One curve, shared by the whois-derived and the RDAP-derived age signals. "How suspicious is
    a fourteen-day-old domain" has one answer, and which registry surface reported the fourteen
    days does not change it -- what it changes is the provider on the signal, and therefore the
    family, which is why the two are separate signal ids reading one band table.
    """
    band_points = cfg.domain_age.bands[-1].points
    for band in cfg.domain_age.bands:
        if band.max_age_days is None or (age_days is not None and age_days <= band.max_age_days):
            band_points = band.points
            break
    return band_points


def _domain_age_signals(
    data: Mapping[str, Any],
    cfg: ScoringConfig,
    now: dt.datetime,
    *,
    scope: IndicatorScope,
    link: Optional[str],
) -> List[Signal]:
    wiring = _wiring(cfg, SignalId.DOMAIN_AGE, scope)
    if wiring is None or wiring.max_points <= 0:
        return []
    whois_present = _as_str(data.get("vt_whois")) is not None
    created = _whois_creation_date(data.get("vt_whois"))
    if not whois_present and created is None:
        # No whois at all: VirusTotal did not answer this part. Not an observation.
        return []

    if created is None:
        points = min(cfg.domain_age.unknown_points, wiring.max_points)
        observation = (
            "Domain registration date could not be read from the whois record. Age unknown is not "
            f"age fine -- scored at the ruleset's unknown-age weight ({points:.0f} points). "
            "Establish the registration date manually before clearing this domain"
        )
        evidence: Dict[str, Any] = {"whois_available": True, "creation_date": None, "age_days": None}
        raw_value: Any = None
    else:
        age = _age_days(created, now)
        points = min(_domain_age_band_points(cfg, age), wiring.max_points)
        observation = (
            f"Domain registered {age:.0f} days ago ({created.date().isoformat()}); age band worth {points:.0f} points"
        )
        evidence = {"whois_available": True, "creation_date": created.isoformat(), "age_days": age}
        raw_value = created.isoformat()

    direction = SignalDirection.ADVERSE if points > 0 else SignalDirection.CONTEXT
    return [
        _scored(
            signal_id=SignalId.DOMAIN_AGE,
            wiring=wiring,
            provider=_VIRUSTOTAL,
            cfg=cfg,
            direction=direction,
            magnitude=points / wiring.max_points,
            observation=observation,
            evidence=evidence,
            raw_value=raw_value,
            observed_at=_as_str(data.get("vt_whois_timestamp")),
            source_url=link,
        )
    ]


def _cert_signal(
    cfg: ScoringConfig,
    wiring: SignalConfig,
    *,
    check: str,
    points: float,
    observation: str,
    evidence: Dict[str, Any],
    observed_at: Optional[str],
    link: Optional[str],
) -> Optional[Signal]:
    """One firing certificate sub-check, as its own ``cert.anomaly`` signal.

    ``max_points`` on each is the sub-check's own budget, not the composite ceiling, so the
    emitted points sum to at most the ceiling the ruleset validated.
    """
    if points <= 0:
        return None
    return Signal(
        id=SignalId.CERT_ANOMALY.value,
        provider=_VIRUSTOTAL,
        family=cfg.family_of(_VIRUSTOTAL) or UNKNOWN_FAMILY,
        direction=SignalDirection.ADVERSE,
        magnitude=1.0,
        points=round(points, 4),
        max_points=points,
        observation=observation,
        evidence={"check": check, **evidence},
        raw_value=check,
        weight_source=f"{cfg.weight_source(SignalId.CERT_ANOMALY)} via certificate.{check}",
        observed_at=observed_at,
        source_url=link,
        ceiling_only=wiring.ceiling_only,
    )


def _certificate_signals(
    data: Mapping[str, Any],
    cfg: ScoringConfig,
    now: dt.datetime,
    *,
    scope: IndicatorScope,
    indicator: Optional[str],
    link: Optional[str],
) -> List[Signal]:
    wiring = _wiring(cfg, SignalId.CERT_ANOMALY, scope)
    if wiring is None:
        return []
    cert = _as_dict(data.get("vt_last_https_certificate"))
    if not cert:
        return []

    conf = cfg.certificate
    validity = _as_dict(cert.get("validity"))
    not_before = _parse_timestamp(validity.get("not_before"))
    not_after = _parse_timestamp(validity.get("not_after"))
    subject_cn = _cert_common_name(cert.get("subject"))
    issuer_cn = _cert_common_name(cert.get("issuer"))
    candidates: List[Optional[Signal]] = []

    if not_before is not None and not_after is not None:
        window_days = (not_after - not_before).total_seconds() / 86400.0
        if 0 < window_days <= conf.short_validity_days:
            candidates.append(
                _cert_signal(
                    cfg,
                    wiring,
                    check="short_validity",
                    points=conf.points_short_validity,
                    observation=(
                        f"TLS certificate validity window is {window_days:.0f} days, at or under the "
                        f"{conf.short_validity_days}-day threshold"
                    ),
                    evidence={
                        "not_before": not_before.isoformat(),
                        "not_after": not_after.isoformat(),
                        "validity_days": round(window_days, 2),
                    },
                    observed_at=not_before.isoformat(),
                    link=link,
                )
            )

    if not_after is not None and not_after < now:
        candidates.append(
            _cert_signal(
                cfg,
                wiring,
                check="expired_but_serving",
                points=conf.points_expired_but_serving,
                observation=(
                    f"TLS certificate expired {(now - not_after).days} days ago "
                    f"({not_after.date().isoformat()}) and was still being served"
                ),
                evidence={"not_after": not_after.isoformat()},
                observed_at=not_after.isoformat(),
                link=link,
            )
        )

    if subject_cn is not None and issuer_cn is not None and subject_cn.casefold() == issuer_cn.casefold():
        candidates.append(
            _cert_signal(
                cfg,
                wiring,
                check="self_signed",
                points=conf.points_self_signed,
                observation=f"TLS certificate is self-signed: issuer and subject CN are both {subject_cn}",
                evidence={"subject_cn": subject_cn, "issuer_cn": issuer_cn},
                observed_at=None,
                link=link,
            )
        )

    if indicator and subject_cn is not None and not _hostname_matches(subject_cn, indicator):
        candidates.append(
            _cert_signal(
                cfg,
                wiring,
                check="cn_mismatch",
                points=conf.points_cn_mismatch,
                observation=(
                    f"TLS certificate subject CN ({subject_cn}) does not cover the queried domain ({indicator})"
                ),
                evidence={"subject_cn": subject_cn, "queried_domain": indicator},
                observed_at=None,
                link=link,
            )
        )

    return [signal for signal in candidates if signal is not None]


# --------------------------------------------------------------------------------------
# RDAP -- registration data from the registry that holds it (roadmap 8.2)
# --------------------------------------------------------------------------------------


def _newest(*values: Any) -> Tuple[Optional[dt.datetime], Optional[str]]:
    """The most recent parseable timestamp among ``values``, with the string it came from.

    Newest rather than oldest because these are *observation* dates, and decay asks how long
    ago the evidence was last true. Taking the oldest would age a currently-live finding by the
    date it was first reported, which discounts adverse evidence for having a long history.
    """
    best: Optional[dt.datetime] = None
    best_raw: Optional[str] = None
    for value in values:
        parsed = _parse_timestamp(value)
        if parsed is None:
            continue
        if best is None or parsed > best:
            best = parsed
            best_raw = _as_str(value)
    return best, best_raw


def extract_rdap_signals(
    payload: Any,
    cfg: ScoringConfig,
    now: dt.datetime,
    *,
    scope: IndicatorScope = IndicatorScope.DOMAIN,
    indicator: Optional[str] = None,
) -> List[Signal]:
    """Registration data: age, registry status, and who to send the abuse report to.

    **Age is the reason this provider exists.** A domain registered days ago is the strongest
    cheap phishing signal available, and RDAP is the registry's own structured answer rather
    than free-text whois parsed by pattern. It reads ``domain_age.bands`` -- the same curve as
    the whois-derived ``domain.age`` -- so the two cannot disagree about what fourteen days is
    worth, and :func:`extract_domain_intel_signals` suppresses the whois one when this path
    reported anything, so a new domain is never counted twice.

    **An unknown age is not a safe age.** A registry that answered and published no registration
    event scores ``domain_age.unknown_points``, which the ruleset forbids being zero. Scoring it
    zero would make "we could not establish when this was registered" identical to "comfortably
    old", which is the clean end of the signal.

    **The registry acting is a fact, not an opinion.** ``client hold`` is what a registrar sets
    when it has accepted an abuse report and pulled the name out of DNS; ``pending delete`` and
    ``redemption period`` say the name is on its way out of the zone. Those score. They sit in
    the non-corroborating ``registry_meta`` family, so they can raise a score and can never
    stand in for an independent second source confirming a detection.

    **A missing abuse contact is mildly notable, never damning.** Privacy proxying is legal,
    routine, and used by an enormous number of entirely ordinary domains, so the weight is
    near-zero by design; scoring it hard would be a false-positive engine aimed at the honest
    long tail. Its *presence* is the more valuable half and is emitted as a zero-weight
    observation, because "abuse@registrar.example, +1-555-0100" is the line that makes a report
    actionable.

    Scope decides what scores: the ruleset declares all three weighted RDAP signals
    ``applies_to: [domain]``, so an IP or ASN payload produces observations only -- the
    allocation record and the netblock's abuse contact -- and no points. Nothing here needs a
    scope test of its own; :func:`_wiring` returns ``None`` and the scored branches do not run.
    """
    now = _require_aware(now)
    data = _as_dict(payload)
    # A payload must carry at least one ``rdap_`` field before anything here fires. Every other
    # extractor is guarded by looking for a specific field it needs; this one is not, because the
    # unknown-age branch deliberately fires on a record with no registration date -- so without
    # this check a FAILURE envelope (``{"ok": false, "error": "missing_api_key"}``) would be a
    # non-empty dict with no date and would score the unknown-age weight. That is the absent-data
    # rule running backwards: a provider that was never asked would score points.
    if not any(isinstance(key, str) and key.startswith("rdap_") for key in data):
        return []

    signals: List[Signal] = []
    signals.extend(_rdap_age_signals(data, cfg, now, scope=scope))
    signals.extend(_rdap_status_signals(data, cfg, scope=scope))
    signals.extend(_rdap_contact_signals(data, cfg, scope=scope))
    signals.extend(_rdap_registration_note(data, cfg, indicator=indicator))
    return signals


def _rdap_registration_date(data: Mapping[str, Any]) -> Optional[dt.datetime]:
    return _parse_timestamp(data.get("rdap_registration_date"))


def _rdap_age_signals(
    data: Mapping[str, Any],
    cfg: ScoringConfig,
    now: dt.datetime,
    *,
    scope: IndicatorScope,
) -> List[Signal]:
    wiring = _wiring(cfg, SignalId.RDAP_DOMAIN_AGE, scope)
    if wiring is None or wiring.max_points <= 0:
        return []

    created = _rdap_registration_date(data)
    # The age is recomputed here from the registration date against the INJECTED clock rather
    # than trusting the provider's own `rdap_age_days`, which was computed against whatever the
    # provider thought the time was. Purity is the point: the same payload and the same `now`
    # must always produce the same signal, including when a saved case is re-scored later.
    age = _age_days(created, now)

    if created is None:
        points = min(cfg.domain_age.unknown_points, wiring.max_points)
        observation = (
            "RDAP answered and the registry published no registration date for this domain. Age "
            f"unknown is not age fine -- scored at the ruleset's unknown-age weight ({points:.0f} "
            "points). Establish the registration date before clearing this domain"
        )
        evidence: Dict[str, Any] = {"rdap_available": True, "registration_date": None, "age_days": None}
        raw_value: Any = None
    else:
        points = min(_domain_age_band_points(cfg, age), wiring.max_points)
        observation = (
            f"RDAP: domain registered {age:.0f} days ago ({created.date().isoformat()}) with "
            f"{_as_str(data.get('rdap_registrar_name')) or 'an unnamed registrar'}; age band worth "
            f"{points:.0f} points"
        )
        evidence = {
            "rdap_available": True,
            "registration_date": created.isoformat(),
            "age_days": age,
            "registrar": _as_str(data.get("rdap_registrar_name")),
        }
        raw_value = created.isoformat()

    return [
        _scored(
            signal_id=SignalId.RDAP_DOMAIN_AGE,
            wiring=wiring,
            provider=_RDAP,
            cfg=cfg,
            # Never EXCULPATORY, whatever the age. An old domain is not clean, it is
            # compromise-eligible: the oldest band is worth zero, which is not the same as
            # earning a discount.
            direction=SignalDirection.ADVERSE if points > 0 else SignalDirection.CONTEXT,
            magnitude=points / wiring.max_points,
            observation=observation,
            evidence=evidence,
            raw_value=raw_value,
            observed_at=_as_str(data.get("rdap_registration_date")),
            source_url=None,
        )
    ]


def _rdap_status_signals(
    data: Mapping[str, Any],
    cfg: ScoringConfig,
    *,
    scope: IndicatorScope,
) -> List[Signal]:
    wiring = _wiring(cfg, SignalId.RDAP_ADVERSE_STATUS, scope)
    if wiring is None or wiring.max_points <= 0:
        return []
    adverse = [text for text in (_as_str(item) for item in _as_list(data.get("rdap_adverse_status"))) if text]
    if not adverse:
        return []

    conf = cfg.rdap
    points = min(len(adverse) * conf.points_per_adverse_status, conf.max_adverse_status_points, wiring.max_points)
    return [
        _scored(
            signal_id=SignalId.RDAP_ADVERSE_STATUS,
            wiring=wiring,
            provider=_RDAP,
            cfg=cfg,
            direction=SignalDirection.ADVERSE,
            magnitude=points / wiring.max_points,
            observation=(
                f"RDAP: the registry reports status {', '.join(adverse)}. A hold is a registrar or "
                "registry acting against the registration -- typically after accepting an abuse "
                "report -- and the name is out of, or leaving, the zone"
            ),
            evidence={
                "adverse_status": adverse,
                "all_status": [text for text in (_as_str(item) for item in _as_list(data.get("rdap_status"))) if text],
            },
            raw_value=adverse,
            observed_at=_as_str(data.get("rdap_last_changed_date")),
            source_url=None,
        )
    ]


def _rdap_contact_signals(
    data: Mapping[str, Any],
    cfg: ScoringConfig,
    *,
    scope: IndicatorScope,
) -> List[Signal]:
    """The abuse contact: its content when there is one, its absence when there is not."""
    source = _as_str(data.get("rdap_abuse_contact_source"))
    email = _as_str(data.get("rdap_abuse_email"))
    phone = _as_str(data.get("rdap_abuse_phone"))
    reachable = ", ".join(part for part in (email, phone) if part)

    if source == "abuse_role" and reachable:
        return [
            _observational(
                signal_id=RDAP_ABUSE_CONTACT,
                provider=_RDAP,
                cfg=cfg,
                direction=SignalDirection.CONTEXT,
                observation=(
                    f"RDAP abuse contact: {reachable}. Published by an entity holding the abuse "
                    "role, which is the queue with the reporting obligation"
                ),
                block="rdap",
                evidence={"abuse_email": email, "abuse_phone": phone, "source": source},
                raw_value=email or phone,
            )
        ]

    wiring = _wiring(cfg, SignalId.RDAP_ABUSE_CONTACT_MISSING, scope)
    if wiring is None or wiring.max_points <= 0:
        # Out of scope for scoring (IP and ASN payloads). Report a fallback contact anyway --
        # a netblock's registrar address is still the line that makes a report actionable.
        if reachable:
            return [
                _observational(
                    signal_id=RDAP_ABUSE_CONTACT,
                    provider=_RDAP,
                    cfg=cfg,
                    direction=SignalDirection.CONTEXT,
                    observation=(
                        f"RDAP abuse contact: {reachable}. Taken from the registrar entity; no "
                        "entity holds the abuse role for this object"
                    ),
                    block="rdap",
                    evidence={"abuse_email": email, "abuse_phone": phone, "source": source},
                    raw_value=email or phone,
                )
            ]
        return []

    conf = cfg.rdap
    if reachable:
        points = min(conf.fallback_abuse_contact_points, wiring.max_points)
        observation = (
            f"RDAP: no entity holds the abuse role; the only published address is the registrar's "
            f"general contact ({reachable}). Somebody can be told, but not through the queue that "
            "carries the obligation"
        )
    else:
        points = min(conf.missing_abuse_contact_points, wiring.max_points)
        observation = (
            "RDAP: no abuse contact published at all -- privacy-proxied or omitted. Mildly "
            "notable and not damning: proxying is routine and the great majority of proxied "
            "domains are ordinary. It does mean there is nobody to send a report to"
        )
    return [
        _scored(
            signal_id=SignalId.RDAP_ABUSE_CONTACT_MISSING,
            wiring=wiring,
            provider=_RDAP,
            cfg=cfg,
            direction=SignalDirection.ADVERSE if points > 0 else SignalDirection.CONTEXT,
            magnitude=points / wiring.max_points,
            observation=observation,
            evidence={"abuse_email": email, "abuse_phone": phone, "source": source},
            raw_value=source,
            source_url=None,
        )
    ]


def _rdap_registration_note(
    data: Mapping[str, Any],
    cfg: ScoringConfig,
    *,
    indicator: Optional[str],
) -> List[Signal]:
    """The registration facts, as one zero-weight line an analyst can paste into a ticket.

    Emitted for every scope, because the ASN and netblock forms of this record are exactly as
    useful in an incident report as the domain form and carry no weight in any of them.
    """
    parts: List[str] = []
    evidence: Dict[str, Any] = {}

    registrar = _as_str(data.get("rdap_registrar_name"))
    if registrar:
        parts.append(f"registrar {registrar}")
        evidence["registrar"] = registrar
    network_name = _as_str(data.get("rdap_network_name")) or _as_str(data.get("rdap_autnum_name"))
    if network_name:
        parts.append(f"allocated as {network_name}")
        evidence["network_name"] = network_name
    handle = (
        _as_str(data.get("rdap_handle"))
        or _as_str(data.get("rdap_network_handle"))
        or _as_str(data.get("rdap_autnum_handle"))
    )
    if handle:
        evidence["handle"] = handle
    registered = _as_str(data.get("rdap_registration_date"))
    if registered:
        parts.append(f"registered {registered}")
        evidence["registration_date"] = registered
    expires = _as_str(data.get("rdap_expiration_date"))
    if expires:
        parts.append(f"expires {expires}")
        evidence["expiration_date"] = expires
    nameserver_count = _as_int(data.get("rdap_nameserver_count"))
    if nameserver_count is not None:
        parts.append(f"{nameserver_count} nameserver(s)")
        evidence["nameserver_count"] = nameserver_count
        evidence["nameservers"] = [
            text for text in (_as_str(item) for item in _as_list(data.get("rdap_nameserver_names"))) if text
        ]
    signed = _as_bool(data.get("rdap_dnssec_delegation_signed"))
    if signed is not None:
        parts.append("DNSSEC signed" if signed else "DNSSEC unsigned")
        evidence["dnssec_delegation_signed"] = signed
    server = _as_str(data.get("rdap_server_host"))
    if server:
        evidence["rdap_server_host"] = server

    if not parts:
        return []
    subject = indicator or "this object"
    return [
        _observational(
            signal_id=RDAP_REGISTRATION,
            provider=_RDAP,
            cfg=cfg,
            direction=SignalDirection.CONTEXT,
            observation=f"RDAP record for {subject}: {'; '.join(parts)}. Registry facts, not a judgement",
            block="rdap",
            evidence=evidence,
            raw_value=handle,
            observed_at=registered,
        )
    ]


# --------------------------------------------------------------------------------------
# Tranco -- popularity, and the one direction it may be read in (roadmap 8.3)
# --------------------------------------------------------------------------------------


def extract_tranco_signals(
    payload: Any,
    cfg: ScoringConfig,
    now: dt.datetime,
    *,
    scope: IndicatorScope = IndicatorScope.DOMAIN,
    indicator: Optional[str] = None,
) -> List[Signal]:
    """Tranco rank. **Suppression only: this function can never emit an adverse signal.**

    Getting this backwards would flag every small legitimate site on the internet. The list
    holds roughly a million domains and the honest web holds hundreds of millions, so "not
    ranked" is the ordinary state of essentially every regional supplier, internal service and
    small business, and treating it as suspicious would be a tautology rather than a detection.
    Both branches below emit zero points and neither carries
    :attr:`SignalDirection.ADVERSE`; there is no code path that could.

    **What a rank is worth, honestly.** A domain in the global top tier for a month is unlikely
    to be what an analyst is hunting, which caps how much suspicion a *reputation* argument
    deserves. It never clears the indicator -- popular sites are compromised, and popular
    file-sharing services carry payloads daily -- and it must never override a provider that
    actually observed something. That is why the ranked branch is not in
    :data:`AFFIRMATIVE_NEGATIVE_SIGNAL_IDS`: it may not unlock the clean verdict on its own.

    **What this does NOT do, stated rather than papered over.** The engine has no
    negative-points mechanism and no suppression tier keyed on a provider payload, so a high
    rank does not currently reduce any other signal's contribution. It is an observation the
    analyst reads and weighs. Wiring a real cap needs an engine-side suppressor tier; inventing
    a weight here to look like it does something would be worse than saying so.
    """
    now = _require_aware(now)
    data = _as_dict(payload)
    if not data:
        return []
    in_list = _as_bool(data.get("tranco_in_list"))
    if in_list is None:
        return []

    conf = cfg.tranco
    days_ranked = _as_int(data.get("tranco_days_ranked")) or 0
    if not in_list:
        note = _as_str(data.get("tranco_absence_note")) or (
            "Not in the Tranco list. This is NOT adverse: the list holds about a million domains "
            "while the public web holds hundreds of millions, so the overwhelming majority of "
            "legitimate domains are unranked"
        )
        return [
            _observational(
                signal_id=TRANCO_UNRANKED,
                provider=_TRANCO,
                cfg=cfg,
                direction=SignalDirection.CONTEXT,
                observation=f"Tranco: {note} No popularity-based suppression is available for this domain",
                block="tranco",
                evidence={"tranco_in_list": False, "days_ranked": days_ranked},
                raw_value=None,
            )
        ]

    rank = _as_int(data.get("tranco_rank"))
    best = _as_int(data.get("tranco_best_rank"))
    strong = rank is not None and rank <= conf.strong_rank
    steady = days_ranked >= conf.steady_days
    strength = (
        "well-established popular infrastructure"
        if strong and steady
        else "ranked, but not steadily enough or highly enough to carry much weight"
    )
    return [
        _observational(
            signal_id=TRANCO_RANK,
            provider=_TRANCO,
            cfg=cfg,
            # EXCULPATORY, and worth zero. Direction and points are independent axes: this says
            # which way the evidence points without claiming it settles anything.
            direction=SignalDirection.EXCULPATORY,
            observation=(
                f"Tranco: ranked {rank if rank is not None else 'unknown'} "
                f"(best {best if best is not None else 'unknown'}) on {days_ranked} of the last "
                f"{TRANCO_HISTORY_WINDOW_DAYS} daily lists -- {strength}. Popularity caps how much "
                "suspicion a reputation argument deserves; it never clears an indicator and never "
                "outweighs a provider that observed something"
            ),
            block="tranco",
            evidence={
                "tranco_in_list": True,
                "rank": rank,
                "best_rank": best,
                "days_ranked": days_ranked,
                "strong_rank_threshold": conf.strong_rank,
                "steady_days_threshold": conf.steady_days,
                "is_strong": strong,
                "is_steady": steady,
            },
            raw_value=rank,
            observed_at=_as_str(data.get("tranco_rank_date")),
        )
    ]


# --------------------------------------------------------------------------------------
# abuse.ch -- URLhaus and ThreatFox (roadmap 8.7)
# --------------------------------------------------------------------------------------


def extract_abusech_signals(
    payload: Any,
    cfg: ScoringConfig,
    now: dt.datetime,
    *,
    scope: IndicatorScope = IndicatorScope.IP,
    indicator: Optional[str] = None,
) -> List[Signal]:
    """URLhaus and ThreatFox: the only observations in this panel, as opposed to opinions.

    Every other reputation input here aggregates somebody's judgement. A URLhaus record means a
    file was retrieved from that URL and its SHA-256 published; a ThreatFox record means somebody
    attributed the indicator to a named malware family and said how confident they were. That
    difference in kind is why the ruleset weights these above VirusTotal and why the escalation
    rules name them.

    **A miss is never a clean signal.** The provider module returns a *failure* envelope on a
    miss (``no_results`` / ``not_found`` / ``lookup_failed``), so this extractor is handed
    nothing and emits nothing. There is no abuse.ch affirmative negative and there must not be:
    "abuse.ch holds no record" is the state of the overwhelming majority of the internet.

    **Two ways the evidence is less than it looks, both priced in the ruleset.** A host-level
    URLhaus record says something happened *somewhere* on that host, which on shared hosting is
    a fact about the hoster and not the tenant, so it is discounted and -- with no payload detail
    in a host response -- cannot reach the decisiveness threshold on its own. And a ThreatFox row
    carries abuse.ch's own confidence in the attribution, which drives the magnitude directly, so
    a low-confidence row lands short of decisive and cannot escalate.

    **Volume is deliberately not counted.** ``urlhaus_url_count`` on a shared hoster measures the
    hoster; presence and liveness are read instead, exactly as the provider module's own notes
    ask. ``urlhaus_online_urls_in_response`` is used only as the liveness floor it is named for.
    """
    now = _require_aware(now)
    data = _as_dict(payload)
    if not data:
        return []
    signals: List[Signal] = []
    signals.extend(_urlhaus_signals(data, cfg, now, scope=scope))
    signals.extend(_threatfox_signals(data, cfg, now, scope=scope))
    return signals


def _urlhaus_shape(data: Mapping[str, Any]) -> Optional[str]:
    """``"url"``, ``"host"`` or ``None`` -- which URLhaus lookup produced this payload.

    Keyed on fields only one of the two shapes carries. ``None`` means URLhaus contributed
    nothing to the merged payload, which is what a miss or a platform failure looks like; the
    reason is in ``abusech_urlhaus_error``.
    """
    if _as_str(data.get("urlhaus_url")) or _as_str(data.get("urlhaus_url_status")):
        return "url"
    if data.get("urlhaus_url_count") is not None or data.get("urlhaus_urls_returned") is not None:
        return "host"
    return None


def _urlhaus_signals(
    data: Mapping[str, Any],
    cfg: ScoringConfig,
    now: dt.datetime,
    *,
    scope: IndicatorScope,
) -> List[Signal]:
    wiring = _wiring(cfg, SignalId.URLHAUS_LISTING, scope)
    if wiring is None or wiring.max_points <= 0:
        return []
    shape = _urlhaus_shape(data)
    if shape is None:
        return []

    conf = cfg.abusech
    online = _as_bool(data.get("urlhaus_online"))
    signatures = [text for text in (_as_str(item) for item in _as_list(data.get("urlhaus_signatures"))) if text]
    payload_count = _as_int(data.get("urlhaus_payload_count")) or 0
    url_count = _as_int(data.get("urlhaus_url_count"))
    online_urls = _as_int(data.get("urlhaus_online_urls_in_response")) or 0

    if shape == "url":
        match_factor = conf.urlhaus_exact_match_factor
        match_clause = "an exact record for this URL"
        has_payload = payload_count > 0 or bool(signatures)
    else:
        match_factor = conf.urlhaus_host_match_factor
        counted = url_count if url_count is not None else _as_int(data.get("urlhaus_urls_returned")) or 0
        match_clause = f"a host record covering {counted} known malware URL(s) on this host"
        # A host response carries no payload detail at all, so there is no retrieved file behind
        # this reading. Discounted rather than assumed either way -- which is also what keeps a
        # host-level hit below the decisiveness threshold and therefore out of the escalation.
        has_payload = False

    if online is True:
        liveness_factor = conf.urlhaus_online_factor
        liveness_clause = "serving now" if shape == "url" else f"{online_urls} of them serving now"
    elif online is False:
        liveness_factor = conf.urlhaus_offline_factor
        liveness_clause = "not currently serving"
    else:
        liveness_factor = conf.urlhaus_unknown_liveness_factor
        liveness_clause = "liveness not reported"

    payload_factor = conf.urlhaus_payload_factor if has_payload else conf.urlhaus_no_payload_factor
    payload_clause = (
        f"{payload_count} payload record(s) retrieved" + (f" ({', '.join(signatures[:3])})" if signatures else "")
        if has_payload
        else "no retrieved payload in this response"
    )

    observed, observed_raw = _newest(
        data.get("urlhaus_payload_last_seen"),
        data.get("urlhaus_last_online"),
        data.get("urlhaus_date_added"),
        data.get("urlhaus_firstseen"),
    )
    age = _age_days(observed, now)
    recency = cfg.decay_factor(conf.urlhaus_recency_profile, age)

    blacklists = _as_dict(data.get("urlhaus_blacklists"))
    dbl = _as_str(blacklists.get("spamhaus_dbl"))
    compromised_hint = (
        ". Spamhaus DBL classifies this as abused legitimate infrastructure, which usually means a "
        "compromised site rather than an attacker-owned one"
        if dbl and "legit" in dbl.lower()
        else ""
    )

    magnitude = match_factor * liveness_factor * payload_factor * recency
    return [
        _scored(
            signal_id=SignalId.URLHAUS_LISTING,
            wiring=wiring,
            provider=_ABUSECH,
            cfg=cfg,
            direction=SignalDirection.ADVERSE,
            magnitude=magnitude,
            observation=(
                f"URLhaus holds {match_clause}, {liveness_clause}; {payload_clause}; "
                f"{_age_phrase(age, recency)}{compromised_hint}"
            ),
            evidence={
                "shape": shape,
                "online": online,
                "url_count": url_count,
                "online_urls_in_response": online_urls,
                "payload_count": payload_count,
                "signatures": signatures,
                "blacklists": {key: value for key, value in blacklists.items() if value is not None},
                "reference": _as_str(data.get("urlhaus_reference")),
                "match_factor": match_factor,
                "liveness_factor": liveness_factor,
                "payload_factor": payload_factor,
                "recency_factor": recency,
                "observation_age_days": age,
            },
            raw_value=signatures or _as_str(data.get("urlhaus_reference")),
            observed_at=observed_raw,
            source_url=_as_str(data.get("urlhaus_reference")),
        )
    ]


def _threatfox_signals(
    data: Mapping[str, Any],
    cfg: ScoringConfig,
    now: dt.datetime,
    *,
    scope: IndicatorScope,
) -> List[Signal]:
    wiring = _wiring(cfg, SignalId.THREATFOX_IOC, scope)
    if wiring is None or wiring.max_points <= 0:
        return []
    count = _as_int(data.get("threatfox_ioc_count")) or 0
    if count <= 0:
        return []

    conf = cfg.abusech
    families = [text for text in (_as_str(item) for item in _as_list(data.get("threatfox_malware_families"))) if text]
    threat_types = [text for text in (_as_str(item) for item in _as_list(data.get("threatfox_threat_types"))) if text]
    confidence = _as_float(data.get("threatfox_confidence_max"))
    discarded = _as_int(data.get("threatfox_discarded_partial_matches")) or 0

    if confidence is None:
        # No confidence level reported. Treated as full strength rather than discounted, for the
        # reason UndatedEvidenceConfig sets out for missing timestamps: a multiplier below 1.0
        # would let a provider that omitted a metadata field argue the indicator cleaner than the
        # evidence it actually supplied. The gap is stated in the observation instead.
        confidence_factor = 1.0
        confidence_clause = "abuse.ch reported no confidence level, which is not the same as low confidence"
    else:
        confidence_factor = _clamp01(confidence / conf.threatfox_confidence_saturation)
        confidence_clause = f"abuse.ch confidence {confidence:.0f} of {conf.threatfox_confidence_saturation:.0f}"

    attribution_factor = conf.threatfox_attributed_factor if families else conf.threatfox_unattributed_factor
    attribution_clause = f"attributed to {', '.join(families[:3])}" if families else "with no malware family named"

    observed, observed_raw = _newest(data.get("threatfox_last_seen"), data.get("threatfox_first_seen"))
    age = _age_days(observed, now)
    recency = cfg.decay_factor(conf.threatfox_recency_profile, age)

    collision_clause = (
        f". {discarded} wildcard result(s) were discarded as substring collisions; a large share "
        "there means the search term was too short to search broadly"
        if discarded > 0
        else ""
    )

    magnitude = confidence_factor * attribution_factor * recency
    return [
        _scored(
            signal_id=SignalId.THREATFOX_IOC,
            wiring=wiring,
            provider=_ABUSECH,
            cfg=cfg,
            direction=SignalDirection.ADVERSE,
            magnitude=magnitude,
            observation=(
                f"ThreatFox holds {count} IOC record(s) for this indicator, {attribution_clause}"
                + (f" as {', '.join(threat_types[:2])}" if threat_types else "")
                + f"; {confidence_clause}; {_age_phrase(age, recency)}{collision_clause}"
            ),
            evidence={
                "ioc_count": count,
                "malware_families": families,
                "threat_types": threat_types,
                "confidence_max": confidence,
                "confidence_min": _as_float(data.get("threatfox_confidence_min")),
                "discarded_partial_matches": discarded,
                "first_seen": _as_str(data.get("threatfox_first_seen")),
                "confidence_factor": confidence_factor,
                "attribution_factor": attribution_factor,
                "recency_factor": recency,
                "observation_age_days": age,
            },
            raw_value=families or count,
            observed_at=observed_raw,
            source_url=None,
        )
    ]


# --------------------------------------------------------------------------------------
# Dispatchers over a whole analysis dict
# --------------------------------------------------------------------------------------


def extract_ip_signals(analysis: Any, cfg: ScoringConfig, now: dt.datetime) -> List[Signal]:
    """Every signal available from one per-IP analysis dict.

    Consumes the shape ``orchestrators._ip_entry`` builds. A provider key that is missing, or
    that holds the empty dict the orchestrator writes for a failed or unconfigured call,
    contributes nothing -- which is the whole point. ``Coverage`` is what records the gap; this
    function does not manufacture a signal to stand in for one.
    """
    now = _require_aware(now)
    data = _as_dict(analysis)
    indicator = _as_str(data.get("ip"))
    scope = IndicatorScope.IP
    signals: List[Signal] = []
    signals.extend(extract_virustotal_signals(data.get("virustotal"), cfg, now, scope=scope, indicator=indicator))
    signals.extend(extract_abuseipdb_signals(data.get("abuseipdb"), cfg, now, scope=scope, indicator=indicator))
    signals.extend(extract_otx_signals(data.get("otx"), cfg, now, scope=scope, indicator=indicator))
    signals.extend(_extract_exposure_for_entry(data.get("shodan"), cfg, now, scope=scope, indicator=indicator))
    signals.extend(extract_abusech_signals(data.get("abusech"), cfg, now, scope=scope, indicator=indicator))
    signals.extend(extract_rdap_signals(data.get("rdap"), cfg, now, scope=scope, indicator=indicator))
    signals.extend(extract_ipinfo_signals(data.get("ipinfo"), cfg, now, scope=scope, indicator=indicator))
    signals.extend(
        extract_asn_metadata_signals(
            data.get("asn_meta"), cfg, now, scope=scope, indicator=indicator, bgp=data.get("bgp")
        )
    )
    return signals


def _extract_exposure_for_entry(
    payload: Any,
    cfg: ScoringConfig,
    now: dt.datetime,
    *,
    scope: IndicatorScope,
    indicator: Optional[str],
) -> List[Signal]:
    """Attribute the exposure payload to whichever Shodan surface actually produced it.

    The orchestrator publishes both the paid host record and the keyless InternetDB extract
    under one ``shodan`` key, because they are alternative implementations of one provider slot
    and counting them as two would permanently understate coverage by one for every operator.
    The payload itself says which one answered -- ``source`` is present only on the InternetDB
    shape -- so the signal can name the dataset without the orchestrator having to pass a flag
    down. A report with no CVE ages should say which dataset it came from.
    """
    data = _as_dict(payload)
    if _as_str(data.get("source")) == INTERNETDB_SOURCE_VALUE:
        return extract_internetdb_signals(data, cfg, now, scope=scope, indicator=indicator)
    return extract_shodan_signals(data, cfg, now, scope=scope, indicator=indicator)


def extract_domain_intel_signals(
    domain_intel: Any,
    cfg: ScoringConfig,
    now: dt.datetime,
    *,
    domain: Optional[str] = None,
) -> List[Signal]:
    """Every signal available from ``data['domain_intel']`` for a domain investigation.

    The domain and its resolved addresses are scored **separately** and never merged. A phishing
    kit on a CDN is a malicious domain on a shared address, and both statements are true at
    once; merging them either indicts every other tenant behind that address or clears the
    phishing kit, and there is no averaging that avoids both.
    """
    now = _require_aware(now)
    data = _as_dict(domain_intel)
    scope = IndicatorScope.DOMAIN
    vt = data.get("virustotal")
    signals: List[Signal] = []
    signals.extend(extract_virustotal_signals(vt, cfg, now, scope=scope, indicator=domain))

    # RDAP first, because it decides whether the whois-derived age still has a job. Both answer
    # "how old is this domain" and RDAP answers it from the registry's structured record rather
    # than by pattern-matching free text, so when RDAP reported anything -- a date, or the fact
    # that it has none -- the whois age is suppressed and the registration is scored once.
    rdap_signals = extract_rdap_signals(data.get("rdap"), cfg, now, scope=scope, indicator=domain)
    age_reported = any(signal.id == SignalId.RDAP_DOMAIN_AGE.value for signal in rdap_signals)
    signals.extend(rdap_signals)
    signals.extend(extract_domain_signals(vt, cfg, now, scope=scope, indicator=domain, age_reported=age_reported))

    signals.extend(extract_otx_signals(data.get("otx"), cfg, now, scope=scope, indicator=domain))
    signals.extend(extract_abusech_signals(data.get("abusech"), cfg, now, scope=scope, indicator=domain))
    signals.extend(extract_tranco_signals(data.get("tranco"), cfg, now, scope=scope, indicator=domain))
    return signals


def extract_url_signals(
    url_intel: Any,
    cfg: ScoringConfig,
    now: dt.datetime,
    *,
    url: Optional[str] = None,
) -> List[Signal]:
    """Every signal available from ``data['url_intel']`` for a URL investigation.

    One source today. URLhaus is a database *of malware distribution URLs*, so the URL scope is
    where it is at its strongest: an exact-URL record carries a retrieved file and its hash, with
    none of the shared-hosting ambiguity a host-level hit inherits.

    VirusTotal's URL report is collected and rendered but is **not** scored here: the ruleset
    declares no ``vt.*`` signal whose ``applies_to`` includes ``url``, and inventing weights for
    one in this function would put scoring constants in a ``.py`` file. Until they land in the
    ruleset, a URL verdict rests on abuse.ch or on nothing, and the coverage line says which.
    """
    now = _require_aware(now)
    data = _as_dict(url_intel)
    return extract_abusech_signals(data.get("abusech"), cfg, now, scope=IndicatorScope.URL, indicator=url)
