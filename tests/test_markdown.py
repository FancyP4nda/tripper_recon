"""Tests for ``tripper_recon.reporting.markdown`` — roadmap 7.2.

The markdown report is the artefact that leaves the terminal. It gets pasted into a Jira ticket,
a GitHub issue, a Slack thread and an incident ``.md`` file, and it is read back weeks later by
somebody who was not there. Four properties have to hold for that to be safe, and this file is
organised around them:

1. **Structure.** Verdict, ``> Why:``, review flags, evidence, *Not established*, appendix — in
   that order, because that is the reading order under time pressure and the sections after the
   third are the ones a hurried reader skips.
2. **Timestamps are the product.** A cached fact must never claim to have been queried now. The
   provider's observation date, the collection time, the evaluation time and the render time are
   four different facts, and the renderer may never substitute one for another. It reads no clock
   at all — the only "now" it has is injected.
3. **Absence never reads as safety.** *Not established* names every provider that did not answer
   and says what its silence means, and no section may quietly omit a gap.
4. **Provider strings cannot inject markdown.** This is the markdown analogue of the rich-markup
   injection defect already fixed in ``reporting/console.py`` (W0.3). A provider that returns a
   pipe must not split a table row; one that returns backticks, an image tag, a heading or a
   newline must not restructure the document. Every hostile value below is one a third party can
   actually put in a field this tool renders.
"""

from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from typing import Any, Dict, List

import pytest

from tripper_recon.reporting import markdown as md
from tripper_recon.reporting.console import defang_indicator
from tripper_recon.reporting.markdown import (
    MarkdownOptions,
    md_code,
    md_escape,
    md_link,
    md_table,
    render_markdown,
)
from tripper_recon.types.models import Coverage, InvestigationResult, RunMetadata
from tripper_recon.verdict.models import (
    AllowlistProvenance,
    Confidence,
    ConfidenceCriterion,
    Contradiction,
    Signal,
    SignalDirection,
    Verdict,
    VerdictLabel,
)

# A globally routable address, so ``defang_indicator`` actually engages. The documentation ranges
# (198.51.100.0/24 and friends) are not ``is_global`` and are deliberately left literal by the
# shared helper, which would make a defanging assertion pass for the wrong reason.
IP = "93.184.216.34"

EVALUATED_AT = dt.datetime(2026, 8, 8, 14, 3, 11, tzinfo=dt.timezone.utc)
STARTED_AT = "2026-08-08T14:03:00Z"
RENDERED_AT = dt.datetime(2026, 8, 9, 9, 30, 0, tzinfo=dt.timezone.utc)
OBSERVED_AT = "2026-08-01T00:00:00+00:00"
RUN_ID = "20260808T140300Z-ab12"

COVERAGE = Coverage(
    answered=["virustotal", "abuseipdb"],
    errored=["ipinfo"],
    unconfigured=["shodan", "otx"],
    skipped=["urlscan"],
)


def _signal(**overrides: Any) -> Signal:
    """One scored signal, in the shape the extractors emit."""
    fields: Dict[str, Any] = {
        "id": "vt.weighted_detections",
        "provider": "virustotal",
        "family": "multiscanner",
        "direction": SignalDirection.ADVERSE,
        "magnitude": 0.4,
        "points": 14.0,
        "max_points": 35.0,
        "observation": "VirusTotal: 5 of 91 engines adverse; weighted 2.10 of 8.00",
        "evidence": {"adverse_engine_count": 5, "total_engines": 91},
        "weight_source": "package:tripper_recon.verdict/scoring.yaml#signals.vt.weighted_detections",
        "observed_at": OBSERVED_AT,
    }
    fields.update(overrides)
    return Signal(**fields)


def _verdict(**overrides: Any) -> Verdict:
    """A verdict in the shape the engine emits. Every structural rule is still enforced."""
    fields: Dict[str, Any] = {
        "indicator": IP,
        "indicator_type": "ip",
        "verdict": VerdictLabel.SUSPICIOUS,
        "score": 71,
        "raw_score": 71.5,
        "score_band": VerdictLabel.MALICIOUS,
        "adjusted_from": VerdictLabel.MALICIOUS,
        "adjustment_reasons": ["demoted from MALICIOUS: coverage below the 0.5 floor"],
        "confidence": Confidence.LOW,
        "confidence_score": 0.25,
        "confidence_criteria": [ConfidenceCriterion(name="coverage_floor", met=False, detail="2 of 6")],
        "coverage": COVERAGE,
        "coverage_floor": 0.5,
        "corroborating_families": ["multiscanner"],
        "signals": [_signal()],
        "summary": f"{IP}: SUSPICIOUS -- score 71, confidence LOW, 2 of 6 providers answered",
        "rationale": ["score 71 falls in the MALICIOUS band"],
        "ruleset_version": "0.1.0-draft",
        "ruleset_source": "package:tripper_recon.verdict/scoring.yaml",
        "calibration_statement": "Heuristic. Informed priors, not measurements; no held-out evaluation was run.",
        "engine_version": "1.0.0",
        "evaluated_at": EVALUATED_AT,
    }
    fields.update(overrides)
    return Verdict(**fields)


def _data(**overrides: Any) -> Dict[str, Any]:
    """The ``result.data`` mapping the orchestrators publish for an IP lookup."""
    payload: Dict[str, Any] = {
        "ip": IP,
        "verdict": _verdict().to_json_dict(),
        "coverage": COVERAGE.model_dump(),
        "run": {
            "tool": "tripper-recon",
            "tool_version": "0.1.0",
            "run_id": RUN_ID,
            "started_at": STARTED_AT,
        },
        "skipped_ips": [{"ip": "10.0.0.5", "source": "active", "reason": "private"}],
        "warnings": ["caida: request failed"],
    }
    payload.update(overrides)
    return payload


def _render(payload: Any = None, **option_overrides: Any) -> str:
    options = MarkdownOptions(now=RENDERED_AT, **option_overrides)
    return render_markdown(_data() if payload is None else payload, options)


def _table_rows(text: str) -> List[str]:
    """Every pipe-table row in the document, delimiter rows included."""
    return [line for line in text.splitlines() if line.startswith("|")]


def _cell_count(row: str) -> int:
    """Columns in one table row, counting only pipes markdown will actually act on.

    ``\\|`` is an escaped pipe and belongs to the cell it sits in. Counting it would make the
    injection test pass on a document a renderer splits anyway.
    """
    return len(re.findall(r"(?<!\\)\|", row))


# --------------------------------------------------------------------------------------
# 1. Structure — the order a report is read in
# --------------------------------------------------------------------------------------


def test_sections_appear_in_reading_order() -> None:
    """Verdict, why, review, evidence, not established, appendix. Fixed, and in that order.

    A reader under time pressure stops after the first screen. The answer and what stands behind
    it have to be above everything that qualifies them.
    """
    out = _render(_data(verdict=_contradiction_verdict().to_json_dict()))
    order = [
        out.index("## Verdict:"),
        out.index("> **Why:**"),
        out.index("## Analyst review"),
        out.index("## Evidence"),
        out.index("## Not established"),
        out.index("## Appendix: run metadata"),
    ]

    assert order == sorted(order)


def test_the_verdict_word_leads_and_carries_score_confidence_and_coverage() -> None:
    """One fact, not three: "SUSPICIOUS at LOW confidence on 2 of 6 providers"."""
    out = _render()

    assert "## Verdict: SUSPICIOUS" in out
    assert "**Score:** 71 (raw 71.5)" in out
    assert "**Confidence:** LOW" in out
    assert "**Coverage:** 2 of 6 providers answered" in out


def test_the_verdict_word_is_never_carried_by_formatting_alone() -> None:
    """The reason this format exists. ``rich`` strips colour on redirect; markdown has none.

    Strip every emphasis marker and the answer must still be readable, because that is what a
    Slack paste and a plain-text ``.md`` file look like.
    """
    plain = _render().replace("*", "").replace("`", "")

    assert "Verdict: SUSPICIOUS" in plain


def test_providers_that_did_not_answer_are_named_beside_the_verdict() -> None:
    out = _render()

    assert "**Did not answer:**" in out
    for name in ("ipinfo", "shodan", "otx", "urlscan"):
        assert f"`{name}`" in out


def test_adjustments_are_shown_where_the_tool_overruled_its_own_arithmetic() -> None:
    out = _render()

    assert "**Adjusted:** demoted from MALICIOUS: coverage below the 0.5 floor" in out


def test_active_collection_is_declared_in_the_verdict_section() -> None:
    """A verdict built partly on active collection is a different artefact, and the analyst must
    see which one they are holding before it goes in a report."""
    verdict = _verdict(passive_only=False, active_collection=["system_dns_resolution"])
    out = _render(_data(verdict=verdict.to_json_dict()))

    assert "**ACTIVE COLLECTION contributed:**" in out
    assert "system_dns_resolution" in out


# --------------------------------------------------------------------------------------
# 2. The `> Why:` block
# --------------------------------------------------------------------------------------


def test_why_block_carries_each_signal_with_its_evidence_and_observation_date() -> None:
    out = _render()

    assert "> **Why:**" in out
    assert "adverse +14.0 of 35.0" in out
    assert "VirusTotal: 5 of 91 engines adverse" in out
    assert "adverse\\_engine\\_count = 5" in out
    assert f"> - observed: `{OBSERVED_AT}`".replace("> - ", ">   - ") in out


def test_every_line_of_the_why_block_is_quoted() -> None:
    """A block quote that ends on the first soft break stops being visually distinct, which is
    the only thing separating the justification from the evidence table below it."""
    out = _render()
    lines = out.splitlines()
    start = lines.index("> **Why:**")
    block = []
    for line in lines[start:]:
        if not line.startswith(">"):
            break
        block.append(line)

    assert len(block) > 1
    assert all(line.startswith(">") for line in block)


def test_why_block_is_capped_and_says_how_many_signals_it_left_out() -> None:
    """Three above the fold; the rest are in the evidence table, and the report says so rather
    than letting the reader assume they saw everything."""
    signals = [
        _signal(id=f"sig.{n}", provider=f"provider{n}", points=float(20 - n), observation=f"observation {n}")
        for n in range(5)
    ]
    out = _render(_data(verdict=_verdict(signals=signals).to_json_dict()), why_limit=2)

    assert "3 further scoring signal(s) are listed in the evidence table below." in out


def test_a_verdict_with_no_scored_signal_says_so_rather_than_printing_nothing() -> None:
    """An empty ``> Why:`` block and a missing one look identical to a reader, and only one of
    them is a fact about the indicator."""
    out = _render(_data(verdict=_verdict(signals=[]).to_json_dict()))

    assert "No signal was extracted from the panel" in out
    assert "absence of evidence and not evidence of absence" in out


# --------------------------------------------------------------------------------------
# 3. Contradictions and the review flag
# --------------------------------------------------------------------------------------


def _contradiction_verdict(**overrides: Any) -> Verdict:
    return _verdict(
        requires_analyst_review=True,
        contradictions=[
            Contradiction(
                rule_id="vt_vs_abuseipdb",
                summary="VirusTotal flags it while AbuseIPDB holds no report",
                left="vt.weighted_detections",
                right="abuseipdb.reports",
                analyst_hint="check which VirusTotal engines flagged it and how recently",
                both_material=True,
            )
        ],
        attribution_warning="the ASN is shared hosting; findings may not attribute to this tenant",
        **overrides,
    )


def test_analyst_review_flag_is_prominent_and_above_the_evidence() -> None:
    out = _render(_data(verdict=_contradiction_verdict().to_json_dict()))

    assert "**ANALYST REVIEW REQUIRED.**" in out
    assert out.index("ANALYST REVIEW REQUIRED") < out.index("## Evidence")


def test_contradictions_are_reported_with_both_sides_and_the_next_step() -> None:
    """Never averaged. Splitting the difference produces a number describing neither provider and
    discards the fact that actually directs the next step: the panel is split."""
    out = _render(_data(verdict=_contradiction_verdict().to_json_dict()))

    assert "`vt_vs_abuseipdb` (material)" in out
    assert "`vt.weighted_detections` vs `abuseipdb.reports`" in out
    assert "check which VirusTotal engines flagged it" in out


def test_attribution_warning_is_surfaced() -> None:
    out = _render(_data(verdict=_contradiction_verdict().to_json_dict()))

    assert "**Attribution:**" in out
    assert "shared hosting" in out


def test_review_section_is_omitted_when_there_is_nothing_to_review() -> None:
    """A standing empty section teaches the eye to skip the heading, which is the one heading
    that must never be skipped when it does appear."""
    out = _render(_data(verdict=_verdict().to_json_dict()))

    assert "## Analyst review" not in out
    assert "ANALYST REVIEW REQUIRED" not in out


# --------------------------------------------------------------------------------------
# 4. The evidence table
# --------------------------------------------------------------------------------------


def test_evidence_table_names_the_provider_what_it_said_and_when_it_observed_it() -> None:
    out = _render()

    assert "| provider | what it reported | observed | weight |" in out
    assert "`virustotal` (multiscanner)" in out
    assert f"`{OBSERVED_AT}`" in out


def test_every_signal_reaches_the_evidence_table_including_the_unscored_ones() -> None:
    """A signal worth zero is still something a provider said. Dropping it would make this a
    summary of the score rather than a record of the evidence."""
    zero = _signal(
        id="abuseipdb.reports",
        provider="abuseipdb",
        family="abuse_feed",
        direction=SignalDirection.EXCULPATORY,
        magnitude=0.0,
        points=0.0,
        max_points=0.0,
        observation="AbuseIPDB: no report in 365 days",
        observed_at=None,
    )
    out = _render(_data(verdict=_verdict(signals=[_signal(), zero]).to_json_dict()))

    assert "AbuseIPDB: no report in 365 days" in out
    assert "observational (carries no weight)" in out


def test_direction_travels_with_the_points() -> None:
    """Direction and points are independent axes on this model. A ten-point context signal that
    printed only its number would read as an accusation."""
    context = _signal(direction=SignalDirection.CONTEXT, points=10.0, observation="host exposes RDP")
    out = _render(_data(verdict=_verdict(signals=[context]).to_json_dict()))

    assert "context +10.0 of 35.0" in out


def test_a_provider_that_answered_without_producing_an_observation_is_named() -> None:
    """``abuseipdb`` answered and no signal came out of it. Saying so is what stops the reader
    inferring that the whole panel is represented in the table."""
    out = _render()

    assert "Answered, but no scored observation was extracted: `abuseipdb`." in out


def test_pivot_links_stay_live_and_clickable() -> None:
    """The one thing in this report that is not defanged. They point at the provider, never at
    the target, and their entire value is being clickable."""
    url = "https://www.virustotal.com/gui/ip-address/" + IP
    out = _render(_data(verdict=_verdict(signals=[_signal(source_url=url)]).to_json_dict()))

    assert f"[source]({url})" in out


# --------------------------------------------------------------------------------------
# 5. Timestamps — the governing rule of this workstream
# --------------------------------------------------------------------------------------


def test_a_provider_that_reported_no_date_is_not_given_the_run_time() -> None:
    """**The rule.** A cached fact must never claim to have been queried now.

    The failure this forbids is silent: substitute the run time for a missing observation date
    and a three-week-old answer acquires the appearance of a fresh lookup, in a document whose
    entire purpose is to be defensible weeks later.
    """
    out = _render(_data(verdict=_verdict(signals=[_signal(observed_at=None)]).to_json_dict()))

    evidence = out[out.index("## Evidence") : out.index("## Not established")]

    assert "*not reported by the provider*" in evidence
    assert STARTED_AT not in evidence
    assert "2026-08-09" not in evidence


def test_the_four_times_are_labelled_as_times_of_different_things() -> None:
    out = _render()

    assert f"| collection started | `{STARTED_AT}` |" in out
    assert "| report rendered | `2026-08-09T09:30:00Z` |" in out
    assert "| verdict evaluated | `2026-08-08T14:03:11Z` |" in out
    assert f"`{OBSERVED_AT}`" in out


def test_the_observed_column_is_explained_as_the_providers_own_date() -> None:
    out = _render()

    assert "is the date the **provider** says it made the observation, not the time of this lookup" in out


def test_no_render_time_supplied_is_reported_as_such_and_never_invented() -> None:
    """The renderer has no clock. A render time invented here would be indistinguishable from a
    collection time at read-back."""
    out = render_markdown(_data(), MarkdownOptions())

    assert "*not recorded - no render time was supplied*" in out


def test_rendering_is_deterministic() -> None:
    """Two renders of one payload are byte-identical, so a report can be diffed. Anything that
    read a clock, a random or an environment variable would break this."""
    assert render_markdown(_data(), MarkdownOptions()) == render_markdown(_data(), MarkdownOptions())


def test_the_module_reads_no_clock_and_performs_no_io() -> None:
    """A static gate on the purity claim.

    Purity here is not a style preference: it is what lets the case-directory artefact reuse this
    renderer offline, and what makes it structurally incapable of stamping "now" onto a cached
    fact. A future edit that reaches for ``datetime.now()`` because a field was missing is exactly
    the change this test exists to stop.
    """
    source = Path(md.__file__).read_text(encoding="utf-8")
    body = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))

    for forbidden in (".now(", ".utcnow(", ".today(", "time.time(", "open(", "Path(", "print("):
        assert forbidden not in body, f"markdown.py must stay pure; found {forbidden!r}"


# --------------------------------------------------------------------------------------
# 6. "Not established" — the section that makes it a report rather than a claim
# --------------------------------------------------------------------------------------


def test_not_established_names_every_provider_that_did_not_answer_and_what_that_means() -> None:
    out = _render()
    section = out[out.index("## Not established") : out.index("## Appendix")]

    assert "| provider | status | what that means |" in section
    assert "never asked - no API key configured" in section
    assert "absence of data from this provider means nothing at all" in section
    assert "query failed" in section
    assert "never asked - deliberately not consulted" in section


def test_the_most_misleading_gap_is_listed_first() -> None:
    """An unconfigured provider is the absence an analyst is likeliest to read as a clean answer."""
    out = _render()
    section = out[out.index("## Not established") :]

    assert section.index("no API key configured") < section.index("query failed")


def test_skipped_addresses_are_reported_with_the_reason_they_were_refused() -> None:
    """Verified gap: addresses the private/reserved guard drops otherwise vanish from the output,
    and silently disappearing evidence is indistinguishable from evidence that came back clean."""
    out = _render()

    assert "### Addresses resolved but not investigated (1)" in out
    assert "private addressing - never sent to a provider" in out
    assert "No provider was asked about these addresses." in out


def test_collector_warnings_reach_the_report() -> None:
    out = _render()

    assert "### Collector warnings (1)" in out
    assert "caida: request failed" in out


def test_unknown_coverage_is_stated_loudly_rather_than_left_blank() -> None:
    """Sparse output reads as a clean indicator. A report that cannot say who was asked has to
    say that it cannot say."""
    payload = _data()
    payload.pop("coverage")
    payload["verdict"] = _verdict(coverage=Coverage()).to_json_dict()
    out = render_markdown(payload, MarkdownOptions(now=RENDERED_AT))

    assert "**No provider status was recorded for this lookup.**" in out


def test_no_verdict_renders_as_not_computed_and_says_nothing_was_adjudicated() -> None:
    """A report with no verdict line at all is one an analyst reads as unremarkable."""
    payload = _data()
    payload["verdict"] = None
    payload["verdict_error"] = "the ruleset failed to load"
    out = render_markdown(payload, MarkdownOptions(now=RENDERED_AT))

    assert "## Verdict: NOT COMPUTED" in out
    assert "the ruleset failed to load" in out
    assert "the absence of a verdict is not a clean verdict" in out


def test_the_closing_sentence_forbids_the_inference_the_section_exists_to_prevent() -> None:
    out = _render()

    assert "No conclusion may be drawn from the absence of a finding above." in out


# --------------------------------------------------------------------------------------
# 7. Appendix and calibration
# --------------------------------------------------------------------------------------


def test_appendix_carries_the_provenance_needed_to_re_derive_the_report() -> None:
    out = _render()

    for expected in (
        "| tool version | `0.1.0` |",
        f"| run id | `{RUN_ID}` |",
        "| ruleset version | `0.1.0-draft` |",
        "| ruleset source | `package:tripper_recon.verdict/scoring.yaml` |",
        "| engine version | `1.0.0` |",
        "| verdict schema | `1.0` |",
    ):
        assert expected in out


def test_collection_mode_is_declared_in_the_appendix() -> None:
    out = _render()

    assert "passive only - no traffic was sent to the target" in out


def test_missing_run_metadata_is_reported_as_not_recorded() -> None:
    payload = _data()
    payload.pop("run")
    out = render_markdown(payload, MarkdownOptions(now=RENDERED_AT))

    assert "| run id | *not recorded* |" in out
    assert "| collection started | *not recorded* |" in out


def test_allowlist_provenance_reaches_the_appendix_with_its_retrieval_date() -> None:
    """A suppression traceable to a list nobody has refetched in a year is the one that has to be
    detectable, so the retrieval date and the staleness note travel with the verdict."""
    verdict = _verdict(
        allowlist=AllowlistProvenance(
            list_version="2026-07-01",
            list_retrieved="2026-07-01",
            stale=True,
            staleness_note="fetched 39 days ago, past the 30-day freshness window",
        )
    )
    out = _render(_data(verdict=verdict.to_json_dict()))

    assert "| allowlist |" in out
    assert "retrieved 2026-07-01" in out
    assert "past the 30-day freshness window" in out


def test_the_calibration_statement_travels_with_the_artefact() -> None:
    """The caveat has to be on the face of the document, not in a README nobody pastes."""
    out = _render()

    assert "**Calibration.**" in out
    assert "Informed priors, not measurements" in out
    assert "unvalidated priors" in out
    assert "states no accuracy figure" in out


def test_the_calibration_floor_survives_a_verdict_that_carries_no_statement() -> None:
    payload = _data()
    payload["verdict"] = None
    out = render_markdown(payload, MarkdownOptions(now=RENDERED_AT))

    assert "unvalidated priors" in out


def test_the_report_never_claims_the_tool_is_accurate() -> None:
    """No accuracy claim exists to make: the corpus has not been captured and no held-out
    evaluation has been run."""
    out = _render().lower()

    for banned in ("is accurate", "accuracy of", "highly accurate", "proven", "reliable verdict"):
        assert banned not in out


# --------------------------------------------------------------------------------------
# 8. Format — it has to survive being pasted anywhere
# --------------------------------------------------------------------------------------


def test_headings_are_atx_only() -> None:
    out = _render()
    headings = [line for line in out.splitlines() if line.lstrip().startswith("#")]

    assert headings
    assert all(re.match(r"^#{1,6} \S", line) for line in headings)
    # No setext underlines, which would turn the line above them into a heading.
    assert not any(re.match(r"^(=+|-{3,})$", line) for line in out.splitlines())


def test_no_html_no_box_drawing_and_no_ansi() -> None:
    out = _render()

    assert "<" not in out.replace("\\<", "")
    assert ">" not in "\n".join(line for line in out.splitlines() if not line.startswith(">")).replace("\\>", "")
    assert not re.search(r"[─-╿]", out)
    assert "\x1b" not in out


def test_every_table_row_has_the_same_column_count_as_its_header() -> None:
    out = _render()
    tables = _tables(out)

    assert _table_rows(out)
    assert tables
    for table in tables:
        widths = {_cell_count(row) for row in table}
        assert len(widths) == 1, f"ragged table: {table}"


def _tables(text: str) -> List[List[str]]:
    """Each pipe table in the document, as a list of its rows."""
    tables: List[List[str]] = []
    current: List[str] = []
    for line in text.splitlines():
        if line.startswith("|"):
            current.append(line)
        elif current:
            tables.append(current)
            current = []
    if current:
        tables.append(current)
    return tables


def test_heading_level_can_be_nested_under_a_larger_document() -> None:
    out = _render(heading_level=2)

    assert out.startswith("## Tripper Recon report")
    assert "### Verdict: SUSPICIOUS" in out


# --------------------------------------------------------------------------------------
# 9. Markdown injection — hostile provider values
# --------------------------------------------------------------------------------------
#
# Every value below is one a third party controls: an OTX pulse title, a Shodan org string, a
# WHOIS field, a signal observation built from any of them. The rich-markup analogue of this was
# a live crash and a live display spoof in the console renderer (W0.3).

HOSTILE = "evil | pipe `backtick` ![img](x) [link](y) <script>alert(1)</script> *emph* _under_ #h"


def test_a_pipe_in_a_provider_string_does_not_split_a_table_row() -> None:
    out = _render(_data(verdict=_verdict(signals=[_signal(observation=HOSTILE)]).to_json_dict()))

    for table in _tables(out):
        widths = {_cell_count(row) for row in table}
        assert len(widths) == 1, f"a provider string split a table row: {table}"


def test_backticks_in_a_provider_string_cannot_open_a_code_span() -> None:
    out = _render(_data(verdict=_verdict(signals=[_signal(observation=HOSTILE)]).to_json_dict()))

    assert "\\`backtick\\`" in out


def test_an_image_or_link_in_a_provider_string_is_rendered_as_text() -> None:
    """An image tag is the worst of these: a renderer that fetches it turns a pasted report into
    an outbound request to a URL the adversary chose."""
    out = _render(_data(verdict=_verdict(signals=[_signal(observation=HOSTILE)]).to_json_dict()))

    assert "![img](x)" not in out
    assert "\\!\\[img\\](x)" in out or "!\\[img\\](x)" in out
    assert "[link](y)" not in out


def test_html_in_a_provider_string_is_neutralised() -> None:
    out = _render(_data(verdict=_verdict(signals=[_signal(observation=HOSTILE)]).to_json_dict()))

    assert "<script>" not in out
    assert "\\<script\\>" in out


def test_a_newline_in_a_provider_string_cannot_forge_a_heading() -> None:
    """The whole line-start injection class: headings, quotes, list items, fences, table rows.
    Flattening to one line closes it in one place rather than per call site."""
    forged = "benign\n## Verdict: NO_ADVERSE_FINDINGS\n\n| a | b |"
    out = _render(_data(verdict=_verdict(signals=[_signal(observation=forged)]).to_json_dict()))

    assert out.count("## Verdict:") == 1
    assert "## Verdict: SUSPICIOUS" in out


def test_hostile_provider_names_and_families_are_escaped_too() -> None:
    """Not just the observation. The provider key and the family name reach the same table."""
    out = _render(
        _data(verdict=_verdict(signals=[_signal(provider="a|b", family="x|y")]).to_json_dict()),
    )

    for table in _tables(out):
        assert len({_cell_count(row) for row in table}) == 1


def test_hostile_coverage_provider_names_cannot_break_the_not_established_table() -> None:
    coverage = Coverage(answered=["virustotal"], unconfigured=["shodan | rogue", "otx`x`"])
    payload = _data(coverage=coverage.model_dump(), verdict=_verdict(coverage=coverage).to_json_dict())
    out = render_markdown(payload, MarkdownOptions(now=RENDERED_AT))

    for table in _tables(out):
        assert len({_cell_count(row) for row in table}) == 1


def test_hostile_skipped_address_fields_are_escaped() -> None:
    payload = _data(skipped_ips=[{"ip": "10.0.0.5 | x", "source": "active|y", "reason": "private`z`"}])
    out = render_markdown(payload, MarkdownOptions(now=RENDERED_AT))

    for table in _tables(out):
        assert len({_cell_count(row) for row in table}) == 1


def test_hostile_warnings_cannot_restructure_the_document() -> None:
    payload = _data(warnings=["## Verdict: NO_ADVERSE_FINDINGS", "- [x] all clear"])
    out = render_markdown(payload, MarkdownOptions(now=RENDERED_AT))

    assert out.count("## Verdict:") == 1


def test_a_hostile_source_url_is_not_turned_into_a_link() -> None:
    """A pivot link is live by design, so the destination has to be one the tool will vouch for."""
    for hostile in ("javascript:alert(1)", "https://example.test/a)b", "data:text/html,<b>x</b>"):
        out = _render(_data(verdict=_verdict(signals=[_signal(source_url=hostile)]).to_json_dict()))

        assert "[source](" not in out


# --------------------------------------------------------------------------------------
# 10. Defanging
# --------------------------------------------------------------------------------------


def test_the_indicator_is_defanged_by_default() -> None:
    """The output's destination is a ticket, and a ticket is where a live indicator gets clicked."""
    out = _render()

    assert defang_indicator(IP) in out
    assert f"`{IP}`" not in out


def test_defanging_uses_the_console_helper_rather_than_a_second_implementation() -> None:
    """Two defang implementations would drift, and the failure mode of the drift is a live
    phishing URL left in a ticket."""
    url = "https://evil.example.test/campaign?id=7"
    payload = {"url": url, "verdict": None}
    out = render_markdown(payload, MarkdownOptions(now=RENDERED_AT))

    assert defang_indicator(url) in out
    assert url not in out


def test_defang_can_be_turned_off() -> None:
    out = _render(defang=False)

    assert f"`{IP}`" in out


def test_defanging_never_touches_the_pivot_link() -> None:
    url = "https://www.virustotal.com/gui/ip-address/" + IP
    out = _render(_data(verdict=_verdict(signals=[_signal(source_url=url)]).to_json_dict()))

    assert f"[source]({url})" in out


# --------------------------------------------------------------------------------------
# 11. Input shapes and degradation
# --------------------------------------------------------------------------------------


def test_the_three_payload_shapes_produce_the_same_report() -> None:
    """``cli.py`` holds the model, ``-o json`` emits its dump, and every console renderer is
    handed ``result.data`` alone. One entry point has to take all three."""
    data = _data()
    run = RunMetadata(run_id=RUN_ID, started_at=dt.datetime(2026, 8, 8, 14, 3, 0, tzinfo=dt.timezone.utc))
    result = InvestigationResult(ok=True, data=data, warnings=data["warnings"], run=run, coverage=COVERAGE)

    from_data = render_markdown(data, MarkdownOptions(now=RENDERED_AT))
    from_model = render_markdown(result, MarkdownOptions(now=RENDERED_AT))
    from_dump = render_markdown(result.model_dump(mode="json"), MarkdownOptions(now=RENDERED_AT))

    assert from_data == from_model == from_dump


@pytest.mark.parametrize("payload", [None, [], "", 7, {"data": None}, {"verdict": "not-a-verdict"}])
def test_an_unreadable_payload_degrades_instead_of_raising(payload: Any) -> None:
    """A renderer that raises on a malformed payload takes the report down with it, and the
    report is the artefact that is supposed to survive things going wrong."""
    out = render_markdown(payload, MarkdownOptions(now=RENDERED_AT))

    assert "## Verdict: NOT COMPUTED" in out
    assert "## Not established" in out
    assert "unvalidated priors" in out


def test_a_malformed_verdict_is_reported_as_not_computed_rather_than_dropped() -> None:
    """Reusing ``console.verdict_from_payload`` buys the model's own invariants on this path:
    a truncated or hand-edited verdict fails to parse instead of printing a word it never earned."""
    broken = _verdict().to_json_dict()
    broken["verdict"] = "NO_ADVERSE_FINDINGS"  # no affirmative negative behind it
    out = render_markdown(_data(verdict=broken), MarkdownOptions(now=RENDERED_AT))

    assert "## Verdict: NOT COMPUTED" in out
    assert "NO_ADVERSE_FINDINGS" not in out


def test_the_indicator_falls_back_through_the_payload_keys() -> None:
    for key, value, kind in (("domain", "evil.example.test", "domain"), ("asn", 15133, "asn")):
        out = render_markdown({key: value}, MarkdownOptions(now=RENDERED_AT, defang=False))

        assert f"`{value}`" in out
        assert f"({kind})" in out


def test_an_explicit_title_overrides_the_default() -> None:
    out = _render(title="Case 4412 - initial triage")

    assert out.startswith("# Case 4412")


# --------------------------------------------------------------------------------------
# 12. The escaping primitives
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("a|b", "a\\|b"),
        ("*emph*", "\\*emph\\*"),
        ("[link](x)", "\\[link\\](x)"),
        ("<b>", "\\<b\\>"),
        ("`code`", "\\`code\\`"),
        ("# heading", "\\# heading"),
        ("- bullet", "\\- bullet"),
        ("1. item", "1\\. item"),
        ("&amp;", "\\&amp;"),
        ("a\nb", "a b"),
        ("a\x00b", "a b"),
        (None, ""),
    ],
)
def test_md_escape_neutralises_every_metacharacter_that_matters(raw: Any, expected: str) -> None:
    assert md_escape(raw) == expected


def test_md_code_grows_its_fence_past_backticks_in_the_content() -> None:
    assert md_code("a`b") == "``a`b``"
    assert md_code("a``b") == "```a``b```"
    assert md_code("`x`") == "`` `x` ``"


def test_md_code_escapes_the_pipe_only_inside_a_table() -> None:
    assert md_code("a|b", in_table=True) == "`a\\|b`"
    assert md_code("a|b") == "`a|b`"


def test_md_code_of_nothing_is_a_dash_not_an_empty_span() -> None:
    assert md_code("") == "-"
    assert md_code(None) == "-"


def test_md_link_declines_a_destination_it_cannot_vouch_for() -> None:
    assert md_link("source", "https://example.test/a") == "[source](https://example.test/a)"
    assert md_link("source", "javascript:alert(1)").startswith("`")
    assert md_link("source", "https://example.test/a b").startswith("`")
    assert md_link("source", "https://example.test/a)b").startswith("`")


def test_md_table_returns_nothing_for_no_rows() -> None:
    """A header with nothing under it states a shape rather than a fact."""
    assert md_table(["a", "b"], []) == []


def test_md_table_fills_an_empty_cell_rather_than_leaving_it_blank() -> None:
    assert md_table(["a"], [[""]])[-1] == "| - |"
