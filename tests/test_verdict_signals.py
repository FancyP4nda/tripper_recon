"""Tests for :mod:`tripper_recon.verdict.signals` (roadmap W5.3, W5.11).

The suite is organised around the six absolute rules of the verdict workstream rather than
around the functions, because the rules are what makes the engine safe to act on and a test
named after a function does not fail loudly enough when one of them is broken:

* ``TestAbsentDataNeverScoresAsClean`` -- rule 1, the one everything else defends.
* ``TestNoInventedNumbers`` -- rule 3: every number traces to the ruleset.
* ``TestNoAccuracyClaimAndNoVendorDenylist`` -- rules 4 and 5, enforced against the source text.
* ``TestContradictionsAreSurfaced`` -- rule 6.
* Per-provider classes for the extraction arithmetic itself.

Every test runs against the **packaged ruleset** (``default_config()``) rather than a
hand-built one, so a tuning change in ``scoring.yaml`` that breaks an extractor's assumptions
fails here instead of in production. Where a test needs a different number it copies the real
config and changes one field, which also proves the value came from config and not from Python.

``now`` is always injected and always fixed. Nothing in the module under test may read a clock,
and :meth:`TestPurity.test_no_clock_read` is the check that keeps it that way.
"""

from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from typing import Any, Callable, Dict, List

import pytest

from tripper_recon.verdict import signals as sig
from tripper_recon.verdict.config import IndicatorScope, ScoringConfig, SignalId, default_config

NOW = dt.datetime(2026, 8, 8, 12, 0, 0, tzinfo=dt.timezone.utc)

Extractor = Callable[..., List[sig.Signal]]

#: Every extractor that takes a single provider payload. Used by the absent-data and
#: hostile-input sweeps so a new extractor cannot be added without being covered by both.
PAYLOAD_EXTRACTORS: Dict[str, Extractor] = {
    "virustotal": sig.extract_virustotal_signals,
    "abuseipdb": sig.extract_abuseipdb_signals,
    "otx": sig.extract_otx_signals,
    "shodan": sig.extract_shodan_signals,
    "ipinfo": sig.extract_ipinfo_signals,
    "asn_metadata": sig.extract_asn_metadata_signals,
    "domain": sig.extract_domain_signals,
}


@pytest.fixture(scope="module")
def cfg() -> ScoringConfig:
    """The shipped ruleset. Tests assert against what actually ships, not against a mock."""
    return default_config()


@pytest.fixture(scope="module")
def source() -> str:
    """The module's own source text, for the two rules that are about what somebody writes."""
    return Path(sig.__file__).read_text(encoding="utf-8")


def _iso(days_ago: float) -> str:
    return (NOW - dt.timedelta(days=days_ago)).isoformat()


def _epoch(days_ago: float) -> int:
    return int((NOW - dt.timedelta(days=days_ago)).timestamp())


def _by_id(signals: List[sig.Signal], signal_id: str) -> List[sig.Signal]:
    return [signal for signal in signals if signal.id == signal_id]


def _one(signals: List[sig.Signal], signal_id: str) -> sig.Signal:
    matches = _by_id(signals, signal_id)
    assert len(matches) == 1, f"expected exactly one {signal_id}, got {[s.id for s in signals]}"
    return matches[0]


def _vt_payload(**overrides: Any) -> Dict[str, Any]:
    """A VirusTotal IP summary with detections, shaped like ``providers.virustotal``."""
    payload: Dict[str, Any] = {
        "vt_last_analysis_stats": {"harmless": 60, "malicious": 5, "suspicious": 0, "undetected": 26},
        "vt_reputation": 0,
        "vt_security_results": {},
        "vt_detecting_engines": [
            {"engine": f"Engine{index}", "category": "malicious", "result": "malware", "method": "blacklist"}
            for index in range(5)
        ],
        "vt_last_analysis_date": _epoch(10),
        "vt_last_analysis_date_iso": _iso(10),
        "vt_link": "https://www.virustotal.com/gui/ip-address/198.51.100.7",
    }
    payload.update(overrides)
    return payload


def _pulse(name: str, author: str | None, days_ago: float) -> Dict[str, Any]:
    stamp = _iso(days_ago)
    return {"name": name, "author": author, "created": stamp, "modified": stamp}


# --------------------------------------------------------------------------------------
# Rule 1 -- absent data never scores as clean
# --------------------------------------------------------------------------------------


class TestAbsentDataNeverScoresAsClean:
    """The rule everything else defends.

    A provider that was not asked, failed, or has no key must contribute **nothing**. Not a
    zero-magnitude benign signal: downstream, a zero-magnitude signal is indistinguishable from
    an answer, and that is exactly how "never asked" starts rendering as "came back clean".
    """

    @pytest.mark.parametrize("name", sorted(PAYLOAD_EXTRACTORS))
    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param({}, id="empty-dict-as-orchestrator-writes-for-a-failed-call"),
            pytest.param(None, id="none"),
            pytest.param([], id="empty-list"),
            pytest.param("not_found", id="error-string"),
            pytest.param(0, id="zero"),
            pytest.param({"ok": False, "error": "missing_api_key"}, id="unconfigured-envelope"),
        ],
    )
    def test_absent_payload_emits_nothing(self, name: str, payload: Any, cfg: ScoringConfig) -> None:
        assert PAYLOAD_EXTRACTORS[name](payload, cfg, NOW) == []

    def test_ip_dispatcher_with_no_providers_emits_nothing(self, cfg: ScoringConfig) -> None:
        analysis = {
            "ip": "198.51.100.7",
            "virustotal": {},
            "abuseipdb": {},
            "otx": {},
            "shodan": {},
            "ipinfo": {},
            "asn_meta": {},
        }
        assert sig.extract_ip_signals(analysis, cfg, NOW) == []

    def test_domain_dispatcher_with_no_providers_emits_nothing(self, cfg: ScoringConfig) -> None:
        assert sig.extract_domain_intel_signals({"virustotal": {}, "otx": {}}, cfg, NOW, domain="example.com") == []

    def test_a_clean_virustotal_answer_is_an_affirmative_negative(self, cfg: ScoringConfig) -> None:
        """The other half of the rule: an answer of "nothing" IS evidence, and must be emitted.

        Without this the engine can never reach NO_ADVERSE_FINDINGS, because
        ``verdict_rules.require_affirmative_negative`` has nothing to be satisfied by.
        """
        clean = _vt_payload(
            vt_last_analysis_stats={"harmless": 68, "malicious": 0, "suspicious": 0, "undetected": 26},
            vt_detecting_engines=[],
        )
        signals = sig.extract_virustotal_signals(clean, cfg, NOW)
        negative = _one(signals, sig.VT_NO_DETECTIONS)
        assert negative.direction is sig.SignalDirection.EXCULPATORY
        assert negative.points == 0.0
        assert negative.id in sig.AFFIRMATIVE_NEGATIVE_SIGNAL_IDS
        assert "0 of 94 engines" in negative.observation

    def test_virustotal_present_but_unmeasurable_emits_nothing(self, cfg: ScoringConfig) -> None:
        """A payload with only a link is not an answer about detections."""
        assert sig.extract_virustotal_signals({"vt_link": "https://example.invalid"}, cfg, NOW) == []

    def test_affirmative_negative_ids_are_a_subset_of_the_observational_ids(self) -> None:
        assert sig.AFFIRMATIVE_NEGATIVE_SIGNAL_IDS <= sig.OBSERVATIONAL_SIGNAL_IDS

    def test_observational_signals_can_never_move_a_score(self, cfg: ScoringConfig) -> None:
        payload = {
            "abuseipdb_reports": 0,
            "abuseipdb_confidence_score": 0,
            "abuseipdb_is_whitelisted": True,
            "abuseipdb_is_tor": True,
            "abuseipdb_usage_type": "Data Center/Web Hosting",
        }
        signals = sig.extract_abuseipdb_signals(payload, cfg, NOW)
        assert signals, "an answering provider must emit something"
        for signal in signals:
            assert signal.id in sig.OBSERVATIONAL_SIGNAL_IDS
            assert signal.points == 0.0
            assert signal.max_points == 0.0


# --------------------------------------------------------------------------------------
# Rule 3 -- no invented numbers
# --------------------------------------------------------------------------------------


class TestNoInventedNumbers:
    """Every number in a signal traces to the ruleset, and moves when the ruleset moves."""

    def test_weight_source_names_the_ruleset_key(self, cfg: ScoringConfig) -> None:
        signal = _one(sig.extract_virustotal_signals(_vt_payload(), cfg, NOW), SignalId.VT_WEIGHTED_DETECTIONS.value)
        assert signal.weight_source.endswith("#signals.vt.weighted_detections")
        assert signal.max_points == cfg.signals[SignalId.VT_WEIGHTED_DETECTIONS].max_points

    def test_points_follow_max_points_from_config(self, cfg: ScoringConfig) -> None:
        wiring = cfg.signals[SignalId.VT_WEIGHTED_DETECTIONS]
        halved = cfg.model_copy(
            update={
                "signals": {
                    **cfg.signals,
                    SignalId.VT_WEIGHTED_DETECTIONS: wiring.model_copy(update={"max_points": wiring.max_points / 2}),
                }
            }
        )
        original = _one(sig.extract_virustotal_signals(_vt_payload(), cfg, NOW), SignalId.VT_WEIGHTED_DETECTIONS.value)
        reduced = _one(
            sig.extract_virustotal_signals(_vt_payload(), halved, NOW), SignalId.VT_WEIGHTED_DETECTIONS.value
        )
        assert reduced.points == pytest.approx(original.points / 2)
        assert reduced.magnitude == pytest.approx(original.magnitude)

    def test_points_equal_magnitude_times_max_points(self, cfg: ScoringConfig) -> None:
        for signal in sig.extract_ip_signals(_full_ip_analysis(), cfg, NOW):
            assert signal.points == pytest.approx(signal.magnitude * signal.max_points, abs=1e-4)
            assert signal.points >= 0.0
            assert 0.0 <= signal.magnitude <= 1.0

    def test_saturation_comes_from_config(self, cfg: ScoringConfig) -> None:
        """Doubling ``virustotal.saturation`` halves the magnitude of the same evidence."""
        doubled = cfg.model_copy(
            update={"virustotal": cfg.virustotal.model_copy(update={"saturation": cfg.virustotal.saturation * 2})}
        )
        base = _one(sig.extract_virustotal_signals(_vt_payload(), cfg, NOW), SignalId.VT_WEIGHTED_DETECTIONS.value)
        wide = _one(sig.extract_virustotal_signals(_vt_payload(), doubled, NOW), SignalId.VT_WEIGHTED_DETECTIONS.value)
        assert wide.magnitude == pytest.approx(base.magnitude / 2)

    def test_a_disabled_signal_emits_nothing(self, cfg: ScoringConfig) -> None:
        wiring = cfg.signals[SignalId.VT_WEIGHTED_DETECTIONS]
        disabled = cfg.model_copy(
            update={
                "signals": {
                    **cfg.signals,
                    SignalId.VT_WEIGHTED_DETECTIONS: wiring.model_copy(update={"enabled": False}),
                }
            }
        )
        signals = sig.extract_virustotal_signals(_vt_payload(), disabled, NOW)
        assert _by_id(signals, SignalId.VT_WEIGHTED_DETECTIONS.value) == []

    def test_out_of_scope_signals_are_not_emitted(self, cfg: ScoringConfig) -> None:
        """``vt.categories`` applies to domains only; an IP-scope call must not emit it."""
        payload = _vt_payload(vt_categories={"Vendor A": "phishing", "Vendor B": "malware"})
        ip_signals = sig.extract_virustotal_signals(payload, cfg, NOW, scope=IndicatorScope.IP)
        assert _by_id(ip_signals, SignalId.VT_CATEGORIES.value) == []
        domain_signals = sig.extract_virustotal_signals(payload, cfg, NOW, scope=IndicatorScope.DOMAIN)
        assert _by_id(domain_signals, SignalId.VT_CATEGORIES.value)


# --------------------------------------------------------------------------------------
# Rules 4 and 5 -- no accuracy claim, no vendor denylist
# --------------------------------------------------------------------------------------


class TestNoAccuracyClaimAndNoVendorDenylist:
    """Enforced against the source text, because both defects are things somebody *writes*."""

    #: Claim-shaped phrasings only. The module is allowed -- required, in fact -- to say that it
    #: makes no accuracy claim, so a bare search for "accuracy" would fail on its own disclaimer.
    ACCURACY_CLAIM_PATTERNS = (
        r"\bis accurate\b",
        r"\bhighly accurate\b",
        r"\baccuracy of\s+\d",
        r"\b(precision|recall|accuracy|f1)\s*(of|=|:)\s*\d",
        r"\d+(\.\d+)?\s*%?\s*(precision|recall|accuracy)",
        r"\bfalse[- ]positive rate\b",
    )

    #: A sample of real multiscanner vendors. None may appear in the module: engine quality comes
    #: from a corpus or it does not exist, and an unsourced list of named vendors is a liability.
    VENDOR_NAMES = (
        "Kaspersky",
        "ESET",
        "Sophos",
        "BitDefender",
        "Fortinet",
        "CrowdStrike",
        "Symantec",
        "McAfee",
        "TrendMicro",
        "Webroot",
        "Avira",
        "ClamAV",
    )

    @pytest.mark.parametrize("pattern", ACCURACY_CLAIM_PATTERNS)
    def test_source_makes_no_accuracy_claim(self, pattern: str, source: str) -> None:
        assert re.search(pattern, source, re.IGNORECASE) is None, (
            f"source matches {pattern!r}. No validated corpus exists; the honest claim is "
            '"heuristic, tuned against fixtures, not validated on a held-out set".'
        )

    @pytest.mark.parametrize("vendor", VENDOR_NAMES)
    def test_source_names_no_antivirus_vendor(self, vendor: str, source: str) -> None:
        # Word-bounded: "ruleset" legitimately contains one of these names as a substring, and a
        # naive `in` check would fail on the very prose that explains why the list is empty.
        assert re.search(rf"\b{re.escape(vendor)}\b", source, re.IGNORECASE) is None

    def test_shipped_ruleset_has_no_engine_denylist(self, cfg: ScoringConfig) -> None:
        assert cfg.virustotal.engine_weights == {}
        assert cfg.virustotal.high_confidence_engines == []

    def test_engine_weighting_is_available_as_a_mechanism(self, cfg: ScoringConfig) -> None:
        """Empty by default, but the mechanism works the moment a corpus fills it."""
        weighted = cfg.model_copy(
            update={"virustotal": cfg.virustotal.model_copy(update={"engine_weights": {"Engine0": 0.0}})}
        )
        base = _one(sig.extract_virustotal_signals(_vt_payload(), cfg, NOW), SignalId.VT_WEIGHTED_DETECTIONS.value)
        tuned = _one(
            sig.extract_virustotal_signals(_vt_payload(), weighted, NOW), SignalId.VT_WEIGHTED_DETECTIONS.value
        )
        assert tuned.evidence["weighted_detections"] == pytest.approx(base.evidence["weighted_detections"] - 1.0)

    def test_no_high_confidence_set_is_reported_honestly(self, cfg: ScoringConfig) -> None:
        signal = _one(sig.extract_virustotal_signals(_vt_payload(), cfg, NOW), SignalId.VT_WEIGHTED_DETECTIONS.value)
        assert "no high-confidence engine set is configured" in signal.observation
        assert signal.evidence["high_confidence_hits"] == []


# --------------------------------------------------------------------------------------
# Purity
# --------------------------------------------------------------------------------------


class TestPurity:
    """No I/O and no clock. The whole engine's offline testability rests on this."""

    def test_no_clock_read(self, cfg: ScoringConfig) -> None:
        """Two calls one hour of wall-clock apart with the same injected ``now`` must agree.

        Simulated by calling twice with an identical ``now``: if anything inside consulted the
        real clock, the recency factors would differ between the calls run at different real
        instants during the suite. Determinism against a fixed ``now`` is the observable form of
        "nothing in here reads a clock".
        """
        analysis = _full_ip_analysis()
        first = sig.extract_ip_signals(analysis, cfg, NOW)
        second = sig.extract_ip_signals(analysis, cfg, NOW)
        assert [signal.model_dump() for signal in first] == [signal.model_dump() for signal in second]

    def test_moving_now_moves_the_decay(self, cfg: ScoringConfig) -> None:
        payload = _vt_payload(vt_last_analysis_date=_epoch(10), vt_last_analysis_date_iso=_iso(10))
        fresh = _one(sig.extract_virustotal_signals(payload, cfg, NOW), SignalId.VT_WEIGHTED_DETECTIONS.value)
        later = _one(
            sig.extract_virustotal_signals(payload, cfg, NOW + dt.timedelta(days=1500)),
            SignalId.VT_WEIGHTED_DETECTIONS.value,
        )
        assert later.points < fresh.points

    def test_naive_now_is_rejected(self, cfg: ScoringConfig) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            sig.extract_virustotal_signals(_vt_payload(), cfg, dt.datetime(2026, 8, 8))

    def test_non_datetime_now_is_rejected(self, cfg: ScoringConfig) -> None:
        with pytest.raises(TypeError):
            sig.extract_virustotal_signals(_vt_payload(), cfg, "2026-08-08")  # type: ignore[arg-type]

    @pytest.mark.parametrize("name", sorted(PAYLOAD_EXTRACTORS))
    def test_hostile_field_types_do_not_raise(self, name: str, cfg: ScoringConfig) -> None:
        """Every field the wrong type at once. Third-party bodies are not to be trusted."""
        hostile: Dict[str, Any] = {
            "vt_last_analysis_stats": ["not", "a", "dict"],
            "vt_detecting_engines": {"not": "a list"},
            "vt_security_results": 17,
            "vt_reputation": "minus thirty seven",
            "vt_last_analysis_date": float("nan"),
            "vt_last_analysis_date_iso": 12345,
            "vt_categories": [["Vendor", "phishing"]],
            "vt_whois": {"Creation Date": "1997-09-15"},
            "vt_last_https_certificate": "not a cert",
            "vt_link": ["https://example.invalid"],
            "abuseipdb_reports": "many",
            "abuseipdb_confidence_score": None,
            "abuseipdb_last_reported_at": 0,
            "abuseipdb_is_whitelisted": "yes",
            "abuseipdb_is_tor": 1,
            "abuseipdb_usage_type": "   ",
            "abuseipdb_num_distinct_users": True,
            "otx_pulse_count": "50",
            "otx_pulses": "not a list",
            "otx_malware_count": [1, 2],
            "ports": {"22": True},
            "vulns": "CVE-2021-1234",
            "hostnames": None,
            "last_update": ["2026-01-01"],
            "org": 42,
            "tags": "cloud",
            "asn": "AS15133",
            "country": 7,
            "name": [],
            "organization": ["Edgecast"],
            "caidaRank": "412",
        }
        assert isinstance(PAYLOAD_EXTRACTORS[name](hostile, cfg, NOW), list)

    def test_a_pulse_list_of_junk_does_not_raise(self, cfg: ScoringConfig) -> None:
        payload = {"otx_pulse_count": 3, "otx_pulses": [None, "string", 7, {"name": None, "author": None}]}
        signals = sig.extract_otx_signals(payload, cfg, NOW)
        assert all(isinstance(signal, sig.Signal) for signal in signals)


# --------------------------------------------------------------------------------------
# VirusTotal
# --------------------------------------------------------------------------------------


class TestVirusTotal:
    def test_weighted_detections_use_the_per_engine_map(self, cfg: ScoringConfig) -> None:
        signal = _one(sig.extract_virustotal_signals(_vt_payload(), cfg, NOW), SignalId.VT_WEIGHTED_DETECTIONS.value)
        assert signal.evidence["per_engine_results_available"] is True
        assert signal.evidence["malicious_engines"] == [f"Engine{index}" for index in range(5)]
        assert signal.evidence["adverse_engine_count"] == 5
        assert signal.evidence["total_engines"] == 91
        assert signal.evidence["weighted_detections"] == pytest.approx(5.0)

    def test_suspicious_engines_are_discounted(self, cfg: ScoringConfig) -> None:
        payload = _vt_payload(
            vt_last_analysis_stats={"harmless": 60, "malicious": 0, "suspicious": 4, "undetected": 27},
            vt_detecting_engines=[
                {"engine": f"Engine{index}", "category": "suspicious", "result": None, "method": "blacklist"}
                for index in range(4)
            ],
        )
        signal = _one(sig.extract_virustotal_signals(payload, cfg, NOW), SignalId.VT_WEIGHTED_DETECTIONS.value)
        assert signal.evidence["weighted_detections"] == pytest.approx(4 * cfg.virustotal.suspicious_multiplier)

    def test_security_results_map_is_used_when_the_compact_list_is_absent(self, cfg: ScoringConfig) -> None:
        payload = _vt_payload(
            vt_detecting_engines=[],
            vt_security_results={
                "Engine0": {"category": "malicious", "result": "trojan"},
                "Engine1": {"category": "harmless", "result": None},
                "Engine2": {"category": "suspicious", "result": None},
                "Engine3": "not a dict",
            },
        )
        signal = _one(sig.extract_virustotal_signals(payload, cfg, NOW), SignalId.VT_WEIGHTED_DETECTIONS.value)
        assert signal.evidence["malicious_engines"] == ["Engine0"]
        assert signal.evidence["suspicious_engines"] == ["Engine2"]

    def test_falls_back_to_aggregate_counts_and_says_so(self, cfg: ScoringConfig) -> None:
        payload = _vt_payload(vt_detecting_engines=[], vt_security_results={})
        signal = _one(sig.extract_virustotal_signals(payload, cfg, NOW), SignalId.VT_WEIGHTED_DETECTIONS.value)
        assert signal.evidence["per_engine_results_available"] is False
        assert "per-engine results absent from the payload" in signal.observation

    def test_recency_decay_uses_last_analysis_date(self, cfg: ScoringConfig) -> None:
        fresh = _vt_payload(vt_last_analysis_date=_epoch(5), vt_last_analysis_date_iso=_iso(5))
        stale = _vt_payload(vt_last_analysis_date=_epoch(2000), vt_last_analysis_date_iso=_iso(2000))
        fresh_signal = _one(sig.extract_virustotal_signals(fresh, cfg, NOW), SignalId.VT_WEIGHTED_DETECTIONS.value)
        stale_signal = _one(sig.extract_virustotal_signals(stale, cfg, NOW), SignalId.VT_WEIGHTED_DETECTIONS.value)
        assert stale_signal.points < fresh_signal.points
        assert stale_signal.evidence["recency_factor"] < fresh_signal.evidence["recency_factor"]

    def test_an_undated_analysis_is_reported_as_undated_not_discounted_as_stale(self, cfg: ScoringConfig) -> None:
        """VirusTotal reporting detections without a date must not lose points for the gap.

        Inverted from its original assertion, which required the undated signal to score BELOW
        the dated one. That rule discounted adverse evidence for a missing metadata field --
        absence arguing an indicator clean, which is the one thing this engine may never do.
        The gap is surfaced in the observation instead of priced into the score.
        """
        undated = _vt_payload(vt_last_analysis_date=None, vt_last_analysis_date_iso=None)
        fresh = _vt_payload()
        stale = _vt_payload(vt_last_analysis_date=_epoch(2000), vt_last_analysis_date_iso=_iso(2000))
        undated_signal = _one(sig.extract_virustotal_signals(undated, cfg, NOW), SignalId.VT_WEIGHTED_DETECTIONS.value)
        fresh_signal = _one(sig.extract_virustotal_signals(fresh, cfg, NOW), SignalId.VT_WEIGHTED_DETECTIONS.value)
        stale_signal = _one(sig.extract_virustotal_signals(stale, cfg, NOW), SignalId.VT_WEIGHTED_DETECTIONS.value)

        assert undated_signal.points >= fresh_signal.points
        assert undated_signal.points > stale_signal.points, (
            "an undated VirusTotal analysis scored no better than a demonstrably old one, so a "
            "provider omitting a timestamp still discounts its own detections"
        )
        assert undated_signal.evidence["recency_factor"] == cfg.undated_evidence.factor
        assert undated_signal.observed_at is None
        # The analyst is told what the engine does not know rather than silently charged for it.
        assert "date not reported" in undated_signal.observation
        assert "age is unknown" in undated_signal.observation

    def test_the_observation_carries_the_numbers_an_analyst_would_paste(self, cfg: ScoringConfig) -> None:
        signal = _one(sig.extract_virustotal_signals(_vt_payload(), cfg, NOW), SignalId.VT_WEIGHTED_DETECTIONS.value)
        assert "5 of 91 engines adverse" in signal.observation
        assert "weighted 5.00 of 8.00" in signal.observation
        assert signal.source_url == "https://www.virustotal.com/gui/ip-address/198.51.100.7"

    def test_community_reputation_is_a_flag_not_a_curve(self, cfg: ScoringConfig) -> None:
        """The ruleset gives this signal a ceiling and no scale, so scaling it would be invented."""
        mild = _one(
            sig.extract_virustotal_signals(_vt_payload(vt_reputation=-1), cfg, NOW),
            SignalId.VT_COMMUNITY_REPUTATION.value,
        )
        severe = _one(
            sig.extract_virustotal_signals(_vt_payload(vt_reputation=-370), cfg, NOW),
            SignalId.VT_COMMUNITY_REPUTATION.value,
        )
        assert mild.points == severe.points == cfg.signals[SignalId.VT_COMMUNITY_REPUTATION].max_points

    @pytest.mark.parametrize("reputation", [0, 5, None, "negative"])
    def test_non_negative_reputation_emits_nothing(self, reputation: Any, cfg: ScoringConfig) -> None:
        signals = sig.extract_virustotal_signals(_vt_payload(vt_reputation=reputation), cfg, NOW)
        assert _by_id(signals, SignalId.VT_COMMUNITY_REPUTATION.value) == []

    def test_categories_count_distinct_adverse_terms(self, cfg: ScoringConfig) -> None:
        payload = _vt_payload(
            vt_categories={
                "Vendor A": "phishing",
                "Vendor B": "Phishing and fraud",
                "Vendor C": "malware distribution",
                "Vendor D": "business",
                "Vendor E": None,
            }
        )
        signal = _one(
            sig.extract_virustotal_signals(payload, cfg, NOW, scope=IndicatorScope.DOMAIN),
            SignalId.VT_CATEGORIES.value,
        )
        assert sorted(signal.evidence["matched_terms"]) == ["malware", "phishing"]
        assert signal.points == pytest.approx(2 * cfg.vt_categories.points_per_term)
        assert "Vendor A" in signal.observation

    def test_benign_categories_emit_nothing(self, cfg: ScoringConfig) -> None:
        payload = _vt_payload(vt_categories={"Vendor A": "business", "Vendor B": "news"})
        signals = sig.extract_virustotal_signals(payload, cfg, NOW, scope=IndicatorScope.DOMAIN)
        assert _by_id(signals, SignalId.VT_CATEGORIES.value) == []


# --------------------------------------------------------------------------------------
# AbuseIPDB
# --------------------------------------------------------------------------------------


class TestAbuseIpdb:
    def test_confidence_scales_between_floor_and_saturation(self, cfg: ScoringConfig) -> None:
        payload = {
            "abuseipdb_reports": 40,
            "abuseipdb_confidence_score": int(cfg.abuseipdb.confidence_saturation),
            "abuseipdb_last_reported_at": _iso(1),
            "abuseipdb_num_distinct_users": 20,
        }
        signal = _one(sig.extract_abuseipdb_signals(payload, cfg, NOW), SignalId.ABUSEIPDB_CONFIDENCE.value)
        assert signal.magnitude == pytest.approx(1.0)
        assert signal.points == cfg.signals[SignalId.ABUSEIPDB_CONFIDENCE].max_points

    def test_confidence_below_the_floor_does_not_score(self, cfg: ScoringConfig) -> None:
        payload = {
            "abuseipdb_reports": 3,
            "abuseipdb_confidence_score": int(cfg.abuseipdb.confidence_floor),
            "abuseipdb_last_reported_at": _iso(1),
        }
        signals = sig.extract_abuseipdb_signals(payload, cfg, NOW)
        assert _by_id(signals, SignalId.ABUSEIPDB_CONFIDENCE.value) == []

    def test_confidence_decays_with_last_reported_at(self, cfg: ScoringConfig) -> None:
        base = {"abuseipdb_reports": 40, "abuseipdb_confidence_score": 90, "abuseipdb_num_distinct_users": 20}
        recent = _one(
            sig.extract_abuseipdb_signals({**base, "abuseipdb_last_reported_at": _iso(2)}, cfg, NOW),
            SignalId.ABUSEIPDB_CONFIDENCE.value,
        )
        ancient = _one(
            sig.extract_abuseipdb_signals({**base, "abuseipdb_last_reported_at": _iso(900)}, cfg, NOW),
            SignalId.ABUSEIPDB_CONFIDENCE.value,
        )
        assert ancient.points < recent.points
        assert "observed 900 days ago" in ancient.observation

    def test_one_reporter_filing_many_is_not_many_reporters(self, cfg: ScoringConfig) -> None:
        """The reporter-diversity discount, stated as the case that motivates it."""
        base = {"abuseipdb_reports": 50, "abuseipdb_confidence_score": 90, "abuseipdb_last_reported_at": _iso(1)}
        lone = _one(
            sig.extract_abuseipdb_signals({**base, "abuseipdb_num_distinct_users": 1}, cfg, NOW),
            SignalId.ABUSEIPDB_VOLUME_RECENCY.value,
        )
        crowd = _one(
            sig.extract_abuseipdb_signals({**base, "abuseipdb_num_distinct_users": 50}, cfg, NOW),
            SignalId.ABUSEIPDB_VOLUME_RECENCY.value,
        )
        assert lone.points < crowd.points
        assert lone.evidence["diversity_component"] < crowd.evidence["diversity_component"]
        assert lone.evidence["volume_component"] == pytest.approx(crowd.evidence["volume_component"])

    def test_an_unreported_reporter_count_is_treated_as_one(self, cfg: ScoringConfig) -> None:
        payload = {"abuseipdb_reports": 50, "abuseipdb_confidence_score": 90, "abuseipdb_last_reported_at": _iso(1)}
        signal = _one(sig.extract_abuseipdb_signals(payload, cfg, NOW), SignalId.ABUSEIPDB_VOLUME_RECENCY.value)
        assert signal.evidence["effective_distinct_users"] == 1
        assert signal.evidence["distinct_users"] is None
        assert "counted as one" in signal.observation

    def test_tor_is_an_attribution_caveat_not_a_detection(self, cfg: ScoringConfig) -> None:
        signals = sig.extract_abuseipdb_signals(
            {"abuseipdb_reports": 12, "abuseipdb_confidence_score": 40, "abuseipdb_is_tor": True}, cfg, NOW
        )
        tor = _one(signals, sig.ABUSE_TOR_EXIT)
        assert tor.direction is sig.SignalDirection.CONTEXT
        assert tor.points == 0.0
        assert "not attributable to the host operator" in tor.observation

    def test_whitelist_demotes_rather_than_clears(self, cfg: ScoringConfig) -> None:
        signals = sig.extract_abuseipdb_signals(
            {"abuseipdb_reports": 0, "abuseipdb_confidence_score": 0, "abuseipdb_is_whitelisted": True}, cfg, NOW
        )
        whitelisted = _one(signals, sig.ABUSE_WHITELISTED)
        assert whitelisted.direction is sig.SignalDirection.EXCULPATORY
        assert whitelisted.points == 0.0
        assert "does not clear an address" in whitelisted.observation
        assert whitelisted.id not in sig.AFFIRMATIVE_NEGATIVE_SIGNAL_IDS

    def test_false_whitelist_and_false_tor_emit_nothing(self, cfg: ScoringConfig) -> None:
        signals = sig.extract_abuseipdb_signals(
            {
                "abuseipdb_reports": 0,
                "abuseipdb_confidence_score": 0,
                "abuseipdb_is_whitelisted": False,
                "abuseipdb_is_tor": False,
            },
            cfg,
            NOW,
        )
        assert _by_id(signals, sig.ABUSE_WHITELISTED) == []
        assert _by_id(signals, sig.ABUSE_TOR_EXIT) == []

    def test_no_reports_is_an_affirmative_negative(self, cfg: ScoringConfig) -> None:
        signals = sig.extract_abuseipdb_signals(
            {"abuseipdb_reports": 0, "abuseipdb_confidence_score": 0}, cfg, NOW, indicator="198.51.100.7"
        )
        negative = _one(signals, sig.ABUSE_NO_REPORTS)
        assert negative.id in sig.AFFIRMATIVE_NEGATIVE_SIGNAL_IDS
        assert negative.source_url == "https://www.abuseipdb.com/check/198.51.100.7"


# --------------------------------------------------------------------------------------
# Rule 6 -- contradictions are surfaced, never averaged
# --------------------------------------------------------------------------------------


class TestContradictionsAreSurfaced:
    """The operator's own committed output is the case this adjudicates.

    ``ip_example.md`` shows VirusTotal at 5/91 beside AbuseIPDB at 0% with five reports. One of
    them is wrong. The extractors must hand the engine BOTH claims, pointing opposite ways, so
    the ``vt_vs_abuseipdb`` rule has two signals to name -- not one averaged number that
    describes neither provider.
    """

    def test_vt_detections_and_abuseipdb_zero_confidence_both_survive(self, cfg: ScoringConfig) -> None:
        analysis = {
            "ip": "123.123.123.123",
            "virustotal": _vt_payload(),
            "abuseipdb": {
                "abuseipdb_reports": 5,
                "abuseipdb_confidence_score": 0,
                "abuseipdb_last_reported_at": _iso(30),
                "abuseipdb_num_distinct_users": 2,
            },
        }
        signals = sig.extract_ip_signals(analysis, cfg, NOW)
        adverse = _one(signals, SignalId.VT_WEIGHTED_DETECTIONS.value)
        exculpatory = _one(signals, sig.ABUSE_REPORTS_NO_CONFIDENCE)
        assert adverse.direction is sig.SignalDirection.ADVERSE
        assert adverse.points > 0
        assert exculpatory.direction is sig.SignalDirection.EXCULPATORY
        assert "declining to call this address abusive" in exculpatory.observation

    def test_no_extractor_emits_negative_points(self, cfg: ScoringConfig) -> None:
        """Cancelling points would reproduce the averaging failure in slower motion."""
        for signal in sig.extract_ip_signals(_full_ip_analysis(), cfg, NOW):
            assert signal.points >= 0.0

    def test_exculpatory_evidence_does_not_reduce_the_adverse_signal(self, cfg: ScoringConfig) -> None:
        with_denial = {
            "ip": "123.123.123.123",
            "virustotal": _vt_payload(),
            "abuseipdb": {"abuseipdb_reports": 5, "abuseipdb_confidence_score": 0},
        }
        without = {"ip": "123.123.123.123", "virustotal": _vt_payload()}
        left = _one(sig.extract_ip_signals(with_denial, cfg, NOW), SignalId.VT_WEIGHTED_DETECTIONS.value)
        right = _one(sig.extract_ip_signals(without, cfg, NOW), SignalId.VT_WEIGHTED_DETECTIONS.value)
        assert left.points == right.points


# --------------------------------------------------------------------------------------
# OTX
# --------------------------------------------------------------------------------------


def _ip_example_pulses(days_ago: float) -> List[Dict[str, Any]]:
    """The ``ip_example.md`` shape: 50 pulses, one real, 49 clones from a single author.

    The titles are the operator's own committed output. They differ only in punctuation and
    date formatting, which is precisely why a raw count reads them as fifty observations.
    """
    clones = [
        "jan2,2025 clone Auto-generated Pulse CREATED 1 YEAR AGO MODIFIED 1 YEAR AGO by AlessandroFiori",
        "jan2.2025clone-Auto-generated Pulse CREATED 1 YEAR AGO MODIFIED 1 YEAR AGO by AlessandroFiori",
        "jan 2 25 clone Auto-generated Pulse CREATED 1 YEAR AGO MODIFIED 1 YEAR AGO by AlessandroFiori",
    ]
    pulses = [_pulse("IOC Records Provided by @NextRayAI", "NextRayAI", days_ago)]
    pulses.extend(_pulse(clones[index % len(clones)], "AlessandroFiori", days_ago) for index in range(49))
    return pulses


class TestOtxPulseQuality:
    def test_the_ip_example_case_collapses(self, cfg: ScoringConfig) -> None:
        """Fifty pulses, four clone variants, one author, a year old.

        The design target is "roughly three effective pulses" from the author-diversity and
        duplicate-title adjustment. Recency then takes it lower again, which is correct: the
        pulses are a year old. What matters operationally is that fifty stops being the unit.
        """
        payload = {"otx_pulse_count": 50, "otx_pulses": _ip_example_pulses(400)}
        signal = _one(sig.extract_otx_signals(payload, cfg, NOW), SignalId.OTX_PULSE_QUALITY.value)
        effective = signal.evidence["effective_pulses"]
        assert effective < 5.0
        assert effective < 0.1 * 50
        assert signal.evidence["top_author"] == "AlessandroFiori"
        assert signal.evidence["top_author_pulses"] == 49
        assert signal.evidence["duplicate_titles"] >= 45
        assert signal.points < 0.5 * cfg.signals[SignalId.OTX_PULSE_QUALITY].max_points
        assert "50 pulses reported" in signal.observation
        assert "AlessandroFiori" in signal.observation

    def test_the_ip_example_case_without_the_age_discount_is_roughly_three(self, cfg: ScoringConfig) -> None:
        """Isolating the quality adjustment from recency, to pin the design's stated figure."""
        payload = {"otx_pulse_count": 50, "otx_pulses": _ip_example_pulses(1)}
        signal = _one(sig.extract_otx_signals(payload, cfg, NOW), SignalId.OTX_PULSE_QUALITY.value)
        assert 2.0 <= signal.evidence["effective_pulses"] <= 4.0

    def test_author_diversity_is_harmonic(self, cfg: ScoringConfig) -> None:
        """Five fresh pulses with unrelated titles, four from one author: 1 + 1 + 1/2 + 1/3 + 1/4."""
        pulses = [
            _pulse("Cobalt Strike C2 infrastructure", "researcher_a", 1),
            _pulse("Mass scanning hosts July", "bulk_importer", 1),
            _pulse("Credential stuffing sources", "bulk_importer", 1),
            _pulse("Ransomware affiliate staging", "bulk_importer", 1),
            _pulse("Phishing kit distribution nodes", "bulk_importer", 1),
        ]
        signal = _one(
            sig.extract_otx_signals({"otx_pulse_count": 5, "otx_pulses": pulses}, cfg, NOW),
            SignalId.OTX_PULSE_QUALITY.value,
        )
        assert signal.evidence["duplicate_titles"] == 0
        assert signal.evidence["effective_pulses"] == pytest.approx(1 + 1 + 1 / 2 + 1 / 3 + 1 / 4, abs=0.01)

    def test_five_authors_outweigh_one_author_with_five_pulses(self, cfg: ScoringConfig) -> None:
        titles = ["Alpha staging", "Beta relay hosts", "Gamma loader nodes", "Delta proxy set", "Epsilon drop zone"]
        diverse = [_pulse(title, f"author_{index}", 1) for index, title in enumerate(titles)]
        concentrated = [_pulse(title, "one_author", 1) for title in titles]
        left = _one(
            sig.extract_otx_signals({"otx_pulse_count": 5, "otx_pulses": diverse}, cfg, NOW),
            SignalId.OTX_PULSE_QUALITY.value,
        )
        right = _one(
            sig.extract_otx_signals({"otx_pulse_count": 5, "otx_pulses": concentrated}, cfg, NOW),
            SignalId.OTX_PULSE_QUALITY.value,
        )
        assert left.evidence["effective_pulses"] > right.evidence["effective_pulses"]
        assert left.points > right.points

    def test_recency_discounts_old_pulses(self, cfg: ScoringConfig) -> None:
        titles = ["Alpha staging", "Beta relay hosts", "Gamma loader nodes"]
        fresh = [_pulse(title, f"author_{index}", 1) for index, title in enumerate(titles)]
        old = [_pulse(title, f"author_{index}", 900) for index, title in enumerate(titles)]
        left = _one(
            sig.extract_otx_signals({"otx_pulse_count": 3, "otx_pulses": fresh}, cfg, NOW),
            SignalId.OTX_PULSE_QUALITY.value,
        )
        right = _one(
            sig.extract_otx_signals({"otx_pulse_count": 3, "otx_pulses": old}, cfg, NOW),
            SignalId.OTX_PULSE_QUALITY.value,
        )
        assert right.evidence["effective_pulses"] < left.evidence["effective_pulses"]

    def test_undetailed_pulses_are_weighed_as_unattributed_and_undated(self, cfg: ScoringConfig) -> None:
        """The pre-W4.6 payload shape: a count and nothing else.

        They are neither dropped nor credited in full. Dropping would let a payload that lost
        its detail understate; crediting would let it outscore a payload that kept it.
        """
        count_only = {"otx_pulse_count": 50}
        signal = _one(sig.extract_otx_signals(count_only, cfg, NOW), SignalId.OTX_PULSE_QUALITY.value)
        assert signal.evidence["detailed_pulse_count"] == 0
        assert signal.evidence["undetailed_pulse_count"] == 50
        assert 0 < signal.evidence["effective_pulses"] < 50
        assert "counted but not detailed" in signal.observation

    def test_detailed_pulses_outrank_the_same_count_undetailed(self, cfg: ScoringConfig) -> None:
        titles = ["Alpha staging", "Beta relay hosts", "Gamma loader nodes"]
        detailed = [_pulse(title, f"author_{index}", 1) for index, title in enumerate(titles)]
        left = _one(
            sig.extract_otx_signals({"otx_pulse_count": 3, "otx_pulses": detailed}, cfg, NOW),
            SignalId.OTX_PULSE_QUALITY.value,
        )
        right = _one(sig.extract_otx_signals({"otx_pulse_count": 3}, cfg, NOW), SignalId.OTX_PULSE_QUALITY.value)
        assert left.evidence["effective_pulses"] > right.evidence["effective_pulses"]

    def test_zero_pulses_is_an_affirmative_negative(self, cfg: ScoringConfig) -> None:
        signal = _one(sig.extract_otx_signals({"otx_pulse_count": 0}, cfg, NOW), sig.OTX_NO_PULSES)
        assert signal.direction is sig.SignalDirection.EXCULPATORY
        assert signal.id in sig.AFFIRMATIVE_NEGATIVE_SIGNAL_IDS
        assert signal.points == 0.0

    def test_malware_count_is_domain_only(self, cfg: ScoringConfig) -> None:
        payload = {"otx_pulse_count": 0, "otx_malware_count": 4}
        assert (
            _by_id(
                sig.extract_otx_signals(payload, cfg, NOW, scope=IndicatorScope.IP), SignalId.OTX_MALWARE_COUNT.value
            )
            == []
        )
        domain = sig.extract_otx_signals(payload, cfg, NOW, scope=IndicatorScope.DOMAIN, indicator="evil.example")
        signal = _one(domain, SignalId.OTX_MALWARE_COUNT.value)
        assert signal.provider == "otx_domain"
        assert signal.family == "community_ti"
        assert signal.source_url == "https://otx.alienvault.com/indicator/domain/evil.example"


# --------------------------------------------------------------------------------------
# Shodan
# --------------------------------------------------------------------------------------


class TestShodan:
    def test_an_ordinary_web_server_scores_nothing(self, cfg: ScoringConfig) -> None:
        """The failure mode this guard exists for: open ports are not evidence of hostility."""
        payload = {"ports": [80, 443], "org": "Example Hosting LLC", "last_update": _iso(5), "vulns": []}
        signal = _one(sig.extract_shodan_signals(payload, cfg, NOW), sig.SHODAN_NO_EXPOSURE)
        assert signal.direction is sig.SignalDirection.CONTEXT
        assert signal.points == 0.0
        assert "none on the risky-port list" in signal.observation

    def test_risky_ports_score_but_stay_context(self, cfg: ScoringConfig) -> None:
        risky = cfg.shodan.risky_ports[:2]
        payload = {"ports": [80, 443, *risky], "last_update": _iso(5), "org": "Example Hosting LLC"}
        signal = _one(sig.extract_shodan_signals(payload, cfg, NOW), SignalId.SHODAN_EXPOSURE.value)
        assert signal.direction is sig.SignalDirection.CONTEXT
        assert signal.ceiling_only is True
        assert signal.evidence["risky_ports"] == sorted(risky)
        assert signal.points == pytest.approx(len(risky) * cfg.shodan.points_per_risky_port)
        assert "not whether it is hostile" in signal.observation

    def test_the_ruleset_keeps_exposure_ceiling_only(self, cfg: ScoringConfig) -> None:
        """A guard on the guard: exposure must never be able to drive a MALICIOUS verdict."""
        assert cfg.signals[SignalId.SHODAN_EXPOSURE].ceiling_only is True

    def test_cve_points_are_capped(self, cfg: ScoringConfig) -> None:
        many = [f"CVE-2021-{1000 + index}" for index in range(40)]
        payload = {"ports": [80], "vulns": many, "last_update": _iso(5)}
        signal = _one(sig.extract_shodan_signals(payload, cfg, NOW), SignalId.SHODAN_EXPOSURE.value)
        assert signal.evidence["cve_points"] == pytest.approx(cfg.shodan.max_points_from_cves)

    def test_exposure_decays_with_last_update(self, cfg: ScoringConfig) -> None:
        risky = cfg.shodan.risky_ports[:3]
        fresh = _one(
            sig.extract_shodan_signals({"ports": risky, "last_update": _iso(5)}, cfg, NOW),
            SignalId.SHODAN_EXPOSURE.value,
        )
        stale = _one(
            sig.extract_shodan_signals({"ports": risky, "last_update": _iso(900)}, cfg, NOW),
            SignalId.SHODAN_EXPOSURE.value,
        )
        assert stale.points < fresh.points

    def test_a_naive_shodan_timestamp_parses(self, cfg: ScoringConfig) -> None:
        payload = {"ports": cfg.shodan.risky_ports[:1], "last_update": "2026-08-01T00:00:00.000000"}
        signal = _one(sig.extract_shodan_signals(payload, cfg, NOW), SignalId.SHODAN_EXPOSURE.value)
        assert signal.evidence["last_update_age_days"] == pytest.approx(7.5, abs=0.1)


# --------------------------------------------------------------------------------------
# IPinfo and ASN metadata
# --------------------------------------------------------------------------------------


class TestAsnMetadata:
    def test_identity_is_context_worth_nothing(self, cfg: ScoringConfig) -> None:
        payload = {"asn": 15133, "org": "AS15133 Edgecast Inc.", "country": "US", "city": "Los Angeles"}
        signal = _one(sig.extract_ipinfo_signals(payload, cfg, NOW), sig.ASN_IDENTITY)
        assert signal.direction is sig.SignalDirection.CONTEXT
        assert signal.points == 0.0
        assert signal.family == "network_meta"
        assert "Los Angeles, US" in signal.observation

    def test_the_shipped_ruleset_names_no_bulletproof_asns(self, cfg: ScoringConfig) -> None:
        """An uncited hosting-reputation list is invented evidence. It must ship empty."""
        assert cfg.asn.bulletproof_asns == []
        payload = {"asn": 15133, "org": "AS15133 Edgecast Inc.", "country": "US"}
        assert _by_id(sig.extract_ipinfo_signals(payload, cfg, NOW), SignalId.ASN_REPUTATION.value) == []

    def test_a_named_bulletproof_asn_scores(self, cfg: ScoringConfig) -> None:
        listed = cfg.model_copy(update={"asn": cfg.asn.model_copy(update={"bulletproof_asns": [15133]})})
        payload = {"asn": 15133, "org": "AS15133 Edgecast Inc.", "country": "US"}
        signal = _one(sig.extract_ipinfo_signals(payload, listed, NOW), SignalId.ASN_REPUTATION.value)
        assert signal.direction is sig.SignalDirection.ADVERSE
        assert signal.points == pytest.approx(
            min(listed.asn.points_if_bulletproof, listed.signals[SignalId.ASN_REPUTATION].max_points)
        )
        assert "the adversary and the victim alike" in signal.observation

    def test_radar_metadata_is_context(self, cfg: ScoringConfig) -> None:
        payload = {
            "asn": 15133,
            "name": "EDGECAST",
            "organization": {"name": "Edgecast Inc."},
            "countryCode": "US",
            "rir": "arin",
            "caidaRank": 412,
        }
        signal = _one(sig.extract_asn_metadata_signals(payload, cfg, NOW), sig.ASN_METADATA)
        assert signal.points == 0.0
        assert "Edgecast Inc." in signal.observation
        assert "ARIN" in signal.observation

    def test_a_string_organisation_does_not_crash(self, cfg: ScoringConfig) -> None:
        signal = _one(
            sig.extract_asn_metadata_signals({"asn": 15133, "organization": "Edgecast Inc."}, cfg, NOW),
            sig.ASN_METADATA,
        )
        assert signal.evidence["organization"] == "Edgecast Inc."

    def test_hijacker_involvement_scores(self, cfg: ScoringConfig) -> None:
        bgp = {"hijacks": {"total_incidents": 12, "as_hijacker": cfg.asn.hijack_saturation, "as_victim": 9}}
        signal = _one(sig.extract_asn_metadata_signals({}, cfg, NOW, bgp=bgp), SignalId.ASN_BGP_INCIDENTS.value)
        assert signal.magnitude == pytest.approx(1.0)
        assert signal.provider == "cloudflare_bgp"

    def test_victim_involvement_is_never_derived(self, cfg: ScoringConfig) -> None:
        """``total_incidents - as_hijacker`` is the manufactured attribution claim W4.7 removed."""
        bgp = {"hijacks": {"total_incidents": 40, "as_hijacker": None, "split_unavailable_reason": "paging limit"}}
        assert _by_id(sig.extract_asn_metadata_signals({}, cfg, NOW, bgp=bgp), SignalId.ASN_BGP_INCIDENTS.value) == []

    def test_zero_hijacks_emits_nothing(self, cfg: ScoringConfig) -> None:
        bgp = {"hijacks": {"total_incidents": 4, "as_hijacker": 0, "as_victim": 4}}
        assert _by_id(sig.extract_asn_metadata_signals({}, cfg, NOW, bgp=bgp), SignalId.ASN_BGP_INCIDENTS.value) == []


# --------------------------------------------------------------------------------------
# Domain-level
# --------------------------------------------------------------------------------------


def _whois(created: str) -> str:
    return (
        "Domain Name: EVIL.EXAMPLE\n"
        "Registrar: Example Registrar, Inc.\n"
        f"Creation Date: {created}\n"
        "Registry Expiry Date: 2027-01-01T00:00:00Z\n"
    )


class TestDomainAge:
    @pytest.mark.parametrize(
        ("days_ago", "expected_points"),
        [(3, 15.0), (20, 10.0), (60, 5.0), (400, 0.0)],
    )
    def test_age_bands_come_from_the_ruleset(self, days_ago: int, expected_points: float, cfg: ScoringConfig) -> None:
        payload = {"vt_whois": _whois(_iso(days_ago))}
        signal = _one(sig.extract_domain_signals(payload, cfg, NOW), SignalId.DOMAIN_AGE.value)
        assert signal.points == pytest.approx(expected_points)

    def test_an_old_domain_earns_no_credit(self, cfg: ScoringConfig) -> None:
        """Never negative: an old domain is not clean, it is compromise-eligible."""
        signal = _one(
            sig.extract_domain_signals({"vt_whois": _whois("1997-09-15T04:00:00Z")}, cfg, NOW),
            SignalId.DOMAIN_AGE.value,
        )
        assert signal.points == 0.0
        assert signal.direction is sig.SignalDirection.CONTEXT

    def test_an_unreadable_creation_date_still_scores(self, cfg: ScoringConfig) -> None:
        """Age unknown is not age fine. Scoring it zero would make it identical to "old"."""
        payload = {"vt_whois": "Domain Name: EVIL.EXAMPLE\nRegistrar: Example Registrar, Inc.\n"}
        signal = _one(sig.extract_domain_signals(payload, cfg, NOW), SignalId.DOMAIN_AGE.value)
        assert signal.points == pytest.approx(cfg.domain_age.unknown_points)
        assert signal.direction is sig.SignalDirection.ADVERSE
        assert signal.evidence["creation_date"] is None
        assert "Age unknown is not age fine" in signal.observation

    def test_no_whois_at_all_emits_nothing(self, cfg: ScoringConfig) -> None:
        assert _by_id(sig.extract_domain_signals({"vt_link": "x"}, cfg, NOW), SignalId.DOMAIN_AGE.value) == []

    def test_conflicting_creation_dates_take_the_earliest(self, cfg: ScoringConfig) -> None:
        """Registry and registrar records disagree routinely; the older reading cannot inflate."""
        whois = f"Creation Date: {_iso(3)}\nRegistered on: 2001-04-05\n"
        signal = _one(sig.extract_domain_signals({"vt_whois": whois}, cfg, NOW), SignalId.DOMAIN_AGE.value)
        assert signal.evidence["creation_date"].startswith("2001-04-05")
        assert signal.points == 0.0

    @pytest.mark.parametrize("rendered", ["1997-09-15T04:00:00Z", "1997-09-15 04:00:00", "1997-09-15", "15-sep-1997"])
    def test_common_whois_date_formats_parse(self, rendered: str, cfg: ScoringConfig) -> None:
        signal = _one(
            sig.extract_domain_signals({"vt_whois": f"Creation Date: {rendered}"}, cfg, NOW),
            SignalId.DOMAIN_AGE.value,
        )
        assert signal.evidence["creation_date"].startswith("1997-09-15")

    def test_domain_age_is_domain_scope_only(self, cfg: ScoringConfig) -> None:
        payload = {"vt_whois": _whois(_iso(3))}
        assert sig.extract_domain_signals(payload, cfg, NOW, scope=IndicatorScope.IP) == []


class TestCertificateAnomalies:
    @staticmethod
    def _cert(**overrides: Any) -> Dict[str, Any]:
        cert: Dict[str, Any] = {
            "issuer": {"CN": "Example Root CA"},
            "subject": {"CN": "evil.example"},
            "validity": {"not_before": _iso(10), "not_after": _iso(-355)},
        }
        cert.update(overrides)
        return {"vt_last_https_certificate": cert}

    def test_short_validity_fires(self, cfg: ScoringConfig) -> None:
        payload = self._cert(validity={"not_before": _iso(10), "not_after": _iso(-40)})
        signals = _by_id(
            sig.extract_domain_signals(payload, cfg, NOW, indicator="evil.example"), SignalId.CERT_ANOMALY.value
        )
        checks = {signal.evidence["check"]: signal for signal in signals}
        assert checks["short_validity"].points == pytest.approx(cfg.certificate.points_short_validity)

    def test_expired_but_serving_fires(self, cfg: ScoringConfig) -> None:
        payload = self._cert(validity={"not_before": _iso(400), "not_after": _iso(30)})
        signals = _by_id(
            sig.extract_domain_signals(payload, cfg, NOW, indicator="evil.example"), SignalId.CERT_ANOMALY.value
        )
        checks = {signal.evidence["check"]: signal for signal in signals}
        assert "expired_but_serving" in checks
        assert "still being served" in checks["expired_but_serving"].observation

    def test_self_signed_fires(self, cfg: ScoringConfig) -> None:
        payload = self._cert(issuer={"CN": "evil.example"})
        checks = {
            signal.evidence["check"]
            for signal in _by_id(
                sig.extract_domain_signals(payload, cfg, NOW, indicator="evil.example"), SignalId.CERT_ANOMALY.value
            )
        }
        assert "self_signed" in checks

    def test_cn_mismatch_fires(self, cfg: ScoringConfig) -> None:
        payload = self._cert(subject={"CN": "unrelated.example"})
        checks = {
            signal.evidence["check"]
            for signal in _by_id(
                sig.extract_domain_signals(payload, cfg, NOW, indicator="evil.example"), SignalId.CERT_ANOMALY.value
            )
        }
        assert "cn_mismatch" in checks

    @pytest.mark.parametrize("cn", ["evil.example", "*.evil.example"])
    def test_a_covering_cn_does_not_fire(self, cn: str, cfg: ScoringConfig) -> None:
        domain = "evil.example" if cn == "evil.example" else "www.evil.example"
        payload = self._cert(subject={"CN": cn})
        checks = {
            signal.evidence["check"]
            for signal in _by_id(
                sig.extract_domain_signals(payload, cfg, NOW, indicator=domain), SignalId.CERT_ANOMALY.value
            )
        }
        assert "cn_mismatch" not in checks

    def test_a_wildcard_does_not_cover_a_deeper_label(self, cfg: ScoringConfig) -> None:
        payload = self._cert(subject={"CN": "*.evil.example"})
        checks = {
            signal.evidence["check"]
            for signal in _by_id(
                sig.extract_domain_signals(payload, cfg, NOW, indicator="a.b.evil.example"),
                SignalId.CERT_ANOMALY.value,
            )
        }
        assert "cn_mismatch" in checks

    def test_all_sub_checks_together_stay_within_the_signal_ceiling(self, cfg: ScoringConfig) -> None:
        """The ruleset validates the sum; this proves the extractor honours it."""
        payload = self._cert(
            issuer={"CN": "unrelated.example"},
            subject={"CN": "unrelated.example"},
            validity={"not_before": _iso(60), "not_after": _iso(30)},
        )
        signals = _by_id(
            sig.extract_domain_signals(payload, cfg, NOW, indicator="evil.example"), SignalId.CERT_ANOMALY.value
        )
        assert {signal.evidence["check"] for signal in signals} == {
            "short_validity",
            "expired_but_serving",
            "self_signed",
            "cn_mismatch",
        }
        total = sum(signal.points for signal in signals)
        assert total <= cfg.signals[SignalId.CERT_ANOMALY].max_points

    def test_a_missing_certificate_emits_nothing(self, cfg: ScoringConfig) -> None:
        assert (
            _by_id(sig.extract_domain_signals({"vt_whois": _whois(_iso(3))}, cfg, NOW), SignalId.CERT_ANOMALY.value)
            == []
        )


# --------------------------------------------------------------------------------------
# Dispatchers
# --------------------------------------------------------------------------------------


def _full_ip_analysis() -> Dict[str, Any]:
    """One per-IP analysis dict with every provider answering, as ``_ip_entry`` builds it."""
    return {
        "ip": "198.51.100.7",
        "virustotal": _vt_payload(vt_reputation=-37),
        "abuseipdb": {
            "abuseipdb_reports": 47,
            "abuseipdb_confidence_score": 92,
            "abuseipdb_last_reported_at": _iso(3),
            "abuseipdb_num_distinct_users": 19,
            "abuseipdb_usage_type": "Data Center/Web Hosting",
            "abuseipdb_is_whitelisted": False,
            "abuseipdb_is_tor": False,
        },
        "otx": {
            "otx_pulse_count": 3,
            "otx_pulses": [
                _pulse("Cobalt Strike C2 infrastructure", "researcher_a", 5),
                _pulse("Mass scanning hosts July", "researcher_b", 20),
                _pulse("Credential stuffing sources", "researcher_c", 200),
            ],
        },
        "shodan": {
            "ports": [22, 80, 443, 3389],
            "org": "Example Hosting LLC",
            "vulns": ["CVE-2021-44228"],
            "hostnames": ["host.example"],
            "last_update": _iso(9),
        },
        "ipinfo": {"ip": "198.51.100.7", "asn": 64500, "org": "AS64500 Example Networks", "country": "NL"},
        "asn_meta": {"asn": 64500, "name": "EXAMPLE", "organization": {"name": "Example Networks"}, "rir": "ripe"},
        "bgp": {"hijacks": {"total_incidents": 5, "as_hijacker": 2, "as_victim": 3}},
    }


class TestDispatchers:
    def test_ip_dispatcher_covers_every_provider(self, cfg: ScoringConfig) -> None:
        signals = sig.extract_ip_signals(_full_ip_analysis(), cfg, NOW)
        emitted = {signal.id for signal in signals}
        assert SignalId.VT_WEIGHTED_DETECTIONS.value in emitted
        assert SignalId.VT_COMMUNITY_REPUTATION.value in emitted
        assert SignalId.ABUSEIPDB_CONFIDENCE.value in emitted
        assert SignalId.ABUSEIPDB_VOLUME_RECENCY.value in emitted
        assert SignalId.OTX_PULSE_QUALITY.value in emitted
        assert SignalId.SHODAN_EXPOSURE.value in emitted
        assert SignalId.ASN_BGP_INCIDENTS.value in emitted
        assert sig.ASN_IDENTITY in emitted
        assert sig.ASN_METADATA in emitted

    def test_every_signal_resolves_to_a_declared_family(self, cfg: ScoringConfig) -> None:
        for signal in sig.extract_ip_signals(_full_ip_analysis(), cfg, NOW):
            assert signal.family != sig.UNKNOWN_FAMILY, signal.id
            assert signal.family in cfg.provider_families

    def test_scored_signal_ids_are_all_known_to_the_ruleset(self, cfg: ScoringConfig) -> None:
        known = {member.value for member in SignalId}
        for signal in sig.extract_ip_signals(_full_ip_analysis(), cfg, NOW):
            assert signal.id in known or signal.id in sig.OBSERVATIONAL_SIGNAL_IDS

    def test_every_observation_is_a_single_line(self, cfg: ScoringConfig) -> None:
        """The observation goes on one console row and into one ticket line."""
        for signal in sig.extract_ip_signals(_full_ip_analysis(), cfg, NOW):
            assert "\n" not in signal.observation
            assert signal.observation.strip() == signal.observation
            assert len(signal.observation) > 20

    def test_domain_dispatcher_uses_domain_scope(self, cfg: ScoringConfig) -> None:
        domain_intel = {
            "virustotal": {
                **_vt_payload(),
                "vt_categories": {"Vendor A": "phishing"},
                "vt_whois": _whois(_iso(4)),
                "vt_last_https_certificate": {
                    "issuer": {"CN": "Example Root CA"},
                    "subject": {"CN": "evil.example"},
                    "validity": {"not_before": _iso(5), "not_after": _iso(-25)},
                },
            },
            "otx": {"otx_pulse_count": 2, "otx_pulses": [], "otx_malware_count": 3},
        }
        signals = sig.extract_domain_intel_signals(domain_intel, cfg, NOW, domain="evil.example")
        emitted = {signal.id for signal in signals}
        assert SignalId.DOMAIN_AGE.value in emitted
        assert SignalId.VT_CATEGORIES.value in emitted
        assert SignalId.CERT_ANOMALY.value in emitted
        assert SignalId.OTX_MALWARE_COUNT.value in emitted
        # IP-only signals must not appear on the domain path.
        assert SignalId.SHODAN_EXPOSURE.value not in emitted
        assert SignalId.ABUSEIPDB_CONFIDENCE.value not in emitted
