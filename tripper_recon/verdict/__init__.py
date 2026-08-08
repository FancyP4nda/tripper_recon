"""The verdict engine: turn six providers' worth of evidence into an adjudicated answer.

The tool collects and renders; it has never adjudicated. VirusTotal prints red when
``malicious > 0`` and AbuseIPDB prints green when its confidence score is ``0``, on the same
screen, with no arbitration between them -- and the analyst does the correlation in their head,
under time pressure, every time. This package is roadmap W5, the part that does the arbitration.

Four rules bind everything in here, and they are absolute because a confident wrong verdict is
acted on:

1. **Absent data never scores as clean.** A provider that was not asked, failed, or has no key
   contributes nothing toward a benign conclusion. Only the Tier A allowlist can produce
   ``KNOWN_INFRASTRUCTURE``. The engine can earn its way up to ``MALICIOUS`` and can never earn
   its way down to safe.
2. **Confidence is a separate axis from score.** "Score 71, confidence LOW, 2 of 6 providers
   answered" is a real state, it must be expressible, and it must be on the screen. Confidence is
   forced LOW whenever coverage is below ``confidence.coverage_floor``.
3. **No invented numbers.** Every weight, threshold, decay constant and band lives in
   :mod:`tripper_recon.verdict.config`'s ``scoring.yaml``. A scoring constant in a ``.py`` file
   is a defect. Every verdict carries ``ruleset_version`` so a verdict in a six-month-old ticket
   stays interpretable.
4. **Contradictions are surfaced, never averaged.** Averaging VT 5/91 with AbuseIPDB 0% produces
   a number that describes neither. The disagreement goes in the confidence and the review flag;
   the score keeps its full raw value.

The engine makes **no accuracy claim**. It is a heuristic whose weights are informed priors, not
measurements: no labelled corpus exists yet and nothing has been validated on a held-out set. The
``calibration`` block in ``scoring.yaml`` says so in the file itself, and the loader rejects a
ruleset that carries a precision or recall figure it has not earned.

Currently exported: the configuration layer only (roadmap 5.2). The models, signal extractors,
overrides and contradiction rules land in sibling modules.
"""

from __future__ import annotations

from tripper_recon.verdict.config import (
    CONFIG_ENV_VAR,
    PACKAGED_CONFIG_NAME,
    ConfidenceBand,
    ContradictionRuleId,
    IndicatorScope,
    OverrideTier,
    ScoringConfig,
    ScoringConfigError,
    SignalConfig,
    SignalId,
    VerdictLabelName,
    clear_config_cache,
    default_config,
    load_scoring_config,
    resolve_config_source,
)

__all__ = [
    "CONFIG_ENV_VAR",
    "PACKAGED_CONFIG_NAME",
    "ConfidenceBand",
    "ContradictionRuleId",
    "IndicatorScope",
    "OverrideTier",
    "ScoringConfig",
    "ScoringConfigError",
    "SignalConfig",
    "SignalId",
    "VerdictLabelName",
    "clear_config_cache",
    "default_config",
    "load_scoring_config",
    "resolve_config_source",
]
