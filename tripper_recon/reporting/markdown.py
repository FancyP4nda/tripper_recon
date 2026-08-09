"""Markdown rendering (roadmap 7.2): the four lines an analyst pastes into a ticket.

``-o console`` paints a terminal and ``-o json`` feeds a machine. Neither survives the workflow
this tool actually exists for -- an analyst copying the answer into a Jira ticket, a GitHub
issue, a Slack thread, or an incident ``.md`` file that somebody reads three weeks later. This
module is that third form: a **pure** function from a result payload to a markdown string.

Pure is load-bearing, not stylistic. There is no I/O here, no console, no file handle, and no
clock read -- the only "now" this module knows is the one the caller injects through
:attr:`MarkdownOptions.now`. That is what makes the output byte-for-byte testable, what makes it
reusable by the case-directory report artifact (7.7) without dragging a terminal along, and what
stops the renderer from being able to stamp a fresh timestamp onto a cached fact.

**The rule this file serves: a cached fact must never claim to have been queried now.** Four
different times can appear in one report and they mean four different things, so each is
labelled with the thing it is a time *of*:

============================  =========================================================
``collection started``        ``RunMetadata.started_at`` -- when this run began
``verdict evaluated``         ``Verdict.evaluated_at`` -- when the engine adjudicated
``observed``                  ``Signal.observed_at`` -- when the PROVIDER saw the thing
``report rendered``           ``MarkdownOptions.now`` -- when this text was produced
============================  =========================================================

A provider that reported no observation date renders as "not reported by the provider". It never
falls back to the run time, because that substitution is precisely how a three-week-old cached
answer acquires the appearance of a fresh lookup.

Format constraints, all driven by where this output goes:

* **ATX headings (``##``) and pipe tables only.** No HTML, no box drawing, no ANSI. Slack renders
  no tables at all, so every table must still read as plain text when it is not rendered.
* **Indicators are defanged** (:func:`console.defang_indicator`, imported rather than
  reimplemented -- two defang implementations would drift and one of them would be the one that
  leaves a live phishing URL in a ticket). **Third-party pivot links stay live**, because their
  entire value is being clickable and they point at VirusTotal or urlscan, never at the target.
* **Provider-controlled strings are escaped for markdown, not for rich.** ``console.esc`` is the
  wrong tool here: it neutralises ``[green]`` for a terminal and does nothing about a pipe
  character that splits a table row, a backtick that opens a code span, or a ``![alt](url)``
  image that a renderer will happily fetch. :func:`md_escape` and :func:`md_code` are the
  markdown analogue of the rich-markup injection fix already in the console renderer.

Everything provider-controlled is additionally **flattened to a single line** before escaping.
That single step removes the whole class of line-start injections -- a pulse title containing
``\\n## Verdict: NO_ADVERSE_FINDINGS`` cannot become a heading if it cannot contain a newline.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, NamedTuple, Optional, Sequence, Tuple

from tripper_recon import __version__

# Imported from the console renderer rather than reimplemented, in every case for the same
# reason: a second copy is a copy that drifts, and each of these drifting is a defect with a
# direction. Two defang implementations means one of them eventually leaves a live indicator in
# a ticket. Two coverage summarisers means the screen and the report state different ratios for
# one run. `_ANSWERED_OUTCOMES` is private and imported anyway, because a local copy that fell
# behind would let a newly-added outcome be counted as coverage -- absence rendering as safety,
# which is the one failure this whole workstream exists to remove.
from tripper_recon.reporting.console import (
    _ANSWERED_OUTCOMES,
    CoverageSummary,
    defang_indicator,
    run_fields,
    summarize_coverage,
    verdict_from_payload,
)
from tripper_recon.verdict.models import Signal, Verdict

__all__ = [
    "MarkdownOptions",
    "md_code",
    "md_escape",
    "md_link",
    "md_table",
    "render_markdown",
]


# --------------------------------------------------------------------------------------
# Escaping. Every string a third party can influence goes through one of these.
# --------------------------------------------------------------------------------------
#
# The console renderer's equivalent is `esc()`, which escapes rich markup. It is not reusable
# here and must not be reached for: the two formats have disjoint metacharacters. `[green]` is
# inert in markdown; `|`, backtick, `![`, and a leading `#` are inert in rich. Using the wrong
# one is worse than using none, because it looks like the field was handled.

#: C0 and C1 control characters. Replaced with a space rather than dropped: deleting them can
#: silently join two tokens ("evil" + "\x00" + "example" -> "evilexample"), which changes the
#: value the report is quoting. NUL through backspace, the vertical tab/form feed pair, the
#: shift codes, and DEL onward. Tab, newline and carriage return are absent because they are
#: whitespace and the collapse below already handles them.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

_WHITESPACE_RE = re.compile(r"\s+")

#: Inline markdown metacharacters. Backslash first, or the escapes get escaped.
#:
#: ``.`` and ``-`` are deliberately absent: escaping them would render ``1\.2\.3\.4`` in the
#: source of every report for no gain, since neither means anything mid-line. Their line-start
#: forms are handled by :data:`_LEADING_ORDERED_RE` and the leading-marker guard instead.
_ESCAPE_RE = re.compile(r"([\\`*_\[\]<>|~#&])")

#: An ordered-list marker at the start of a value: ``1.`` or ``1)``. Escaped by backslashing the
#: delimiter, never the digits.
_LEADING_ORDERED_RE = re.compile(r"^(\d{1,9})([.)])")

#: Bullet and setext-underline markers, which only mean anything as the first character.
_LEADING_MARKERS = frozenset({"-", "+", "="})

#: Schemes a value may carry and still be emitted as a clickable link.
_LINKABLE_SCHEMES = frozenset({"http", "https"})

#: Characters that make a link destination ambiguous or dangerous inside ``[label](dest)``.
#: A URL containing any of them is rendered as literal text instead of as a link -- the tool
#: declines to guess at an encoding on a third party's behalf.
_UNSAFE_IN_URL = frozenset(" \t\n<>()[]`\"'\\|")

#: Cell content for a value that is absent. One string, so "nothing here" is greppable and can
#: never be confused with a zero.
_EMPTY_CELL = "-"


def _flatten(value: Any) -> str:
    """One line of printable text from any value: controls neutralised, whitespace collapsed.

    Every escaping helper below starts here, so no provider string can carry a newline into the
    output. That is the whole line-start injection class -- headings, block quotes, list items,
    fenced code, table rows -- closed in one place rather than defended against per call site.
    """
    if value is None:
        return ""
    text = _CONTROL_RE.sub(" ", str(value))
    return _WHITESPACE_RE.sub(" ", text).strip()


def md_escape(value: Any) -> str:
    """Render a provider-controlled value as literal markdown text.

    Safe in prose, in a list item, in a block quote and in a table cell -- ``|`` is escaped
    unconditionally, so one function covers all four rather than a table-only variant that
    somebody eventually forgets to use.
    """
    text = _flatten(value)
    if not text:
        return ""
    text = _ESCAPE_RE.sub(r"\\\1", text)
    text = _LEADING_ORDERED_RE.sub(lambda match: f"{match.group(1)}\\{match.group(2)}", text)
    if text[0] in _LEADING_MARKERS:
        text = f"\\{text}"
    return text


def md_code(value: Any, *, in_table: bool = False) -> str:
    """Render a value as a code span, which is how indicators and identifiers are presented.

    A code span is the strongest containment markdown offers and the most readable: ``evil[.]com``
    inside backticks needs no escaping at all, survives a plain-text paste, and cannot open
    emphasis, a link, or an image. The fence grows past the longest backtick run in the content,
    per CommonMark, so a value that is *itself* backticks cannot break out.

    ``in_table`` escapes the pipe, which GFM strips before the code span is parsed and which
    would otherwise split the row. It is a parameter rather than the default because ``\\|``
    outside a table renders as a literal backslash-pipe.
    """
    text = _flatten(value)
    if not text:
        return _EMPTY_CELL
    if in_table:
        text = text.replace("|", "\\|")
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    # CommonMark strips one leading and one trailing space when both are present, so this pad
    # keeps a value that starts or ends with a backtick from fusing with its own fence.
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def md_link(label: str, url: Any, *, in_table: bool = False) -> str:
    """A clickable pivot link, or the URL as literal text when it cannot be linked safely.

    Pivot links are the one thing in this report that stays live: they point at VirusTotal,
    urlscan, Shodan and AbuseIPDB -- parties that already hold the intelligence -- and never at
    the target. See the defanging section of ``reporting/console.py`` for why that distinction is
    a per-field decision and not a pass over the finished document.

    A destination this function will not vouch for is rendered as a code span rather than
    dropped. The analyst still sees what the provider supplied; it just is not armed.
    """
    text = _flatten(url)
    scheme, mark, rest = text.partition("://")
    linkable = bool(mark) and scheme.lower() in _LINKABLE_SCHEMES and bool(rest)
    if not linkable or any(char in _UNSAFE_IN_URL for char in text):
        return md_code(text, in_table=in_table)
    return f"[{md_escape(label)}]({text})"


def md_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> List[str]:
    """A GFM pipe table. Cells arrive already escaped; this only assembles them.

    Returns ``[]`` for no rows. A header with nothing under it states a shape rather than a fact,
    and the sections here would rather say nothing than imply an empty panel was consulted.
    """
    if not rows:
        return []
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        cells = [cell if cell else _EMPTY_CELL for cell in row]
        lines.append("| " + " | ".join(cells) + " |")
    return lines


# --------------------------------------------------------------------------------------
# Options and input normalisation
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class MarkdownOptions:
    """Everything the renderer is allowed to know that is not in the payload.

    Frozen because a renderer that mutates its own options is no longer pure, and the purity is
    what lets a caller render the same result twice and diff the two strings.
    """

    #: The indicator this report is about. Falls back to the verdict's, then to the payload's
    #: ``ip`` / ``domain`` / ``url`` / ``asn`` key. Never invented.
    indicator: Optional[str] = None
    #: ``ip`` | ``domain`` | ``url`` | ``asn``. Same fallback chain.
    indicator_type: Optional[str] = None
    #: Document title. Defaults to the tool name and the indicator.
    title: Optional[str] = None
    #: Bracket the indicator wherever this report states it. On by default: the output's
    #: destination is a ticket, and a ticket is exactly where a live indicator gets clicked.
    defang: bool = True
    #: When this text was produced. **The only clock this module has.** ``None`` renders as
    #: "not recorded" -- the renderer will not read the wall clock to fill the gap, because a
    #: render time invented here is indistinguishable from a collection time.
    now: Optional[dt.datetime] = None
    #: Heading depth of the document title, so a report can be nested inside a larger one.
    heading_level: int = 1
    #: How many signals the ``> Why:`` block shows. The evidence table always shows all of them.
    why_limit: int = 3


class _View(NamedTuple):
    """The four payload shapes this renderer accepts, normalised to one."""

    data: Mapping[str, Any]
    warnings: List[str]
    run: Mapping[str, Any]
    coverage: Any
    skipped: List[Any]


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _as_sequence(value: Any) -> List[Any]:
    if isinstance(value, (list, tuple)):
        return list(value)
    return []


def _view(source: Any) -> _View:
    """Accept an ``InvestigationResult``, its dump, or a bare ``result.data`` mapping.

    All three are in circulation: ``cli.py`` holds the model, ``-o json`` emits the dump, and
    every console renderer is handed ``result.data`` alone. Normalising here rather than making
    the caller choose is what lets the report artifact and the CLI share one entry point.

    Anything else -- ``None``, a list, a string -- degrades to an empty view. A renderer that
    raises on a malformed payload takes the report down with it, and a report is the artefact
    that is supposed to survive things going wrong.
    """
    if hasattr(source, "model_dump"):
        try:
            source = source.model_dump(mode="json")
        except Exception:  # pragma: no cover - defensive; a pydantic model always dumps
            source = None

    outer: Mapping[str, Any] = {}
    data: Mapping[str, Any] = {}
    if isinstance(source, Mapping):
        if isinstance(source.get("data"), Mapping):
            outer, data = source, source["data"]
        else:
            data = source

    warnings = [str(item) for item in _as_sequence(outer.get("warnings") or data.get("warnings")) if str(item).strip()]
    run = _as_mapping(outer.get("run") or data.get("run"))
    coverage = outer.get("coverage") or data.get("coverage") or data.get("provider_status")
    skipped = _as_sequence(outer.get("skipped_addresses") or data.get("skipped_ips"))
    return _View(data=data, warnings=warnings, run=run, coverage=coverage, skipped=skipped)


# --------------------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------------------

#: Keys the orchestrators use for the indicator, in the order they are looked for.
_INDICATOR_KEYS: Tuple[str, ...] = ("ip", "domain", "url", "asn")

#: What each non-answering outcome means for the reader, in report words.
#:
#: ``console._OUTCOME_LABELS`` is the terse screen wording and is deliberately not shared: a
#: table cell has room for "never asked - no API key configured" and the report has room for the
#: consequence, which is the half that stops absence reading as safety.
_GAP_MEANING: Dict[str, Tuple[str, str]] = {
    "not_configured": (
        "never asked - no API key configured",
        "absence of data from this provider means nothing at all",
    ),
    "skipped": (
        "never asked - deliberately not consulted",
        "no opinion was sought and none is recorded here",
    ),
    "error": (
        "query failed",
        "the provider may or may not hold a record; this lookup did not find out",
    ),
    "unrecorded": (
        "outcome not recorded",
        "the tool did not record what happened to this call; treat it as unanswered",
    ),
}

#: Order the gaps are listed in: the most misleading absence first. An unconfigured provider is
#: the one an analyst is likeliest to read as a clean answer, so it leads.
_GAP_ORDER: Tuple[str, ...] = ("not_configured", "skipped", "error", "unrecorded")

_UNKNOWN_GAP_MEANING = "unrecognised outcome; counted as a gap rather than as coverage"

_NOT_ESTABLISHED_INTRO = (
    "What this lookup did **not** determine. Nothing in this section is evidence that the "
    "indicator is clean -- a provider that was never asked has contributed nothing, and a "
    "provider that failed has contributed nothing either."
)

_NOT_ESTABLISHED_CLOSE = (
    "No conclusion may be drawn from the absence of a finding above. To close any of these gaps, "
    "configure the missing credential or re-run the lookup and check the result changed."
)

_OBSERVED_NOTE = (
    "`observed` is the date the **provider** says it made the observation, not the time of this "
    "lookup. Where it reads *not reported by the provider*, the provider supplied no date and the "
    "age of that evidence is unknown."
)

_CALIBRATION_FLOOR = (
    "The scoring weights behind this verdict are unvalidated priors. No held-out evaluation has "
    "been run against a labelled corpus, so this report states no accuracy figure and none may be "
    "inferred from it."
)

_NO_VERDICT_NOTE = (
    "No verdict was computed for this indicator. Nothing below has been adjudicated, and the "
    "absence of a verdict is not a clean verdict."
)

_PASSIVE_LINE = "passive only - no traffic was sent to the target or to its infrastructure"


def _heading(level: int, base: int, text: str) -> str:
    """An ATX heading, clamped to the six levels markdown actually has."""
    depth = max(1, min(6, base + level - 1))
    return f"{'#' * depth} {text}"


def _blank(lines: List[str]) -> None:
    """One blank line between blocks, never two, never a leading one."""
    if lines and lines[-1] != "":
        lines.append("")


def _points(value: float) -> str:
    """One decimal place. Points are weighted sums, not counts, and ``int()`` hides the work."""
    return f"{value:.1f}"


def _stamp(value: Any) -> Optional[str]:
    """An RFC 3339 UTC string for a datetime, or the caller's own string, or ``None``.

    A naive datetime is read as UTC, matching ``console._utc_stamp``. ``None`` means the caller
    supplied nothing, and the caller is told that rather than given a substitute.
    """
    if isinstance(value, dt.datetime):
        moment = value if value.tzinfo is not None else value.replace(tzinfo=dt.timezone.utc)
        return moment.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    text = _flatten(value)
    return text or None


def _indicator_of(data: Mapping[str, Any], verdict: Optional[Verdict], options: MarkdownOptions) -> Tuple[str, str]:
    """``(indicator, indicator_type)``, from the caller, then the verdict, then the payload."""
    indicator = _flatten(options.indicator)
    kind = _flatten(options.indicator_type)
    if verdict is not None:
        indicator = indicator or _flatten(verdict.indicator)
        kind = kind or _flatten(verdict.indicator_type)
    for key in _INDICATOR_KEYS:
        if indicator and kind:
            break
        value = data.get(key)
        if value is None or _flatten(value) == "":
            continue
        indicator = indicator or _flatten(value)
        kind = kind or key
    return indicator, kind


def _indicator_cell(value: Any, *, defang: bool, in_table: bool = False) -> str:
    """One indicator field, defanged if asked, always inside a code span.

    ``defang_indicator`` is imported from the console renderer rather than reimplemented. Two
    defang implementations would drift, and the failure mode of the drift is a live phishing URL
    in a ticket somebody clicks.
    """
    return md_code(defang_indicator(value) if defang else value, in_table=in_table)


# --------------------------------------------------------------------------------------
# Sections
# --------------------------------------------------------------------------------------


def _verdict_section(
    verdict: Optional[Verdict],
    data: Mapping[str, Any],
    summary: CoverageSummary,
    options: MarkdownOptions,
) -> List[str]:
    """The answer, first, in words: the verdict WORD, the score, the confidence, the coverage.

    Written as a heading plus a definition list rather than a banner, because the heading is what
    a ticket's table of contents picks up and what a reader's eye lands on first. The word is
    never carried by colour -- there is no colour in markdown, which is the whole reason this
    format exists (``console.py`` measured ``rich`` stripping ANSI on redirect).
    """
    base = options.heading_level
    if verdict is None:
        reason = _flatten(data.get("verdict_error"))
        lines = [_heading(2, base, "Verdict: NOT COMPUTED"), ""]
        if reason:
            lines.append(f"- **Why not:** {md_escape(reason)}")
        lines.append(f"- **Coverage:** {md_escape(_coverage_headline(summary))}")
        lines.append("")
        lines.append(_NO_VERDICT_NOTE)
        return lines

    label = verdict.verdict.value
    lines = [_heading(2, base, f"Verdict: {md_escape(label)}"), ""]
    lines.append(f"- **Verdict:** **{md_escape(label)}**")
    lines.append(f"- **Score:** {verdict.score} (raw {_points(verdict.raw_score)})")
    lines.append(f"- **Confidence:** {md_escape(verdict.confidence.value)}")
    lines.append(f"- **Coverage:** {md_escape(verdict.coverage.headline)}")
    if verdict.coverage.missing:
        names = ", ".join(md_code(name) for name in verdict.coverage.missing)
        lines.append(f"- **Did not answer:** {names}")
    for reason in verdict.adjustment_reasons:
        lines.append(f"- **Adjusted:** {md_escape(reason)}")
    if not verdict.passive_only:
        named = ", ".join(md_code(step) for step in verdict.active_collection) or "unnamed active steps"
        lines.append(f"- **ACTIVE COLLECTION contributed:** {named}")
    return lines


def _signal_evidence(signal: Signal) -> List[str]:
    """The ``key = value`` pairs behind one signal, escaped. Empty when it carries none."""
    return [f"{md_escape(key)} = {md_escape(repr(value))}" for key, value in signal.evidence.items()]


def _why_block(verdict: Optional[Verdict], options: MarkdownOptions) -> List[str]:
    """The ``> Why:`` block: the two or three signals that justify the call, with their evidence.

    A block quote rather than a list, because it has to stay visually distinct from the evidence
    table below it after being pasted somewhere with no CSS. Every line carries its own ``>`` so
    the quote does not end on the first soft break.

    The honest empty case is rendered, never omitted. A verdict with nothing behind it and a
    verdict whose reasoning was dropped by the renderer look identical to a reader, and only one
    of them is a fact about the indicator.
    """
    if verdict is None:
        return []

    lines = ["> **Why:**", ">"]
    top = verdict.top_signals(max(0, options.why_limit))
    if top:
        for signal in top:
            lines.append(f"> - {_signal_headline(signal)}")
            evidence = _signal_evidence(signal)
            if evidence:
                lines.append(f">   - evidence: {'; '.join(evidence)}")
            observed = _flatten(signal.observed_at)
            lines.append(f">   - observed: {md_code(observed) if observed else 'not reported by the provider'}")
        hidden = len(verdict.scored_signals) - len(top)
        if hidden > 0:
            lines.append(">")
            lines.append(f"> {hidden} further scoring signal(s) are listed in the evidence table below.")
        return lines

    if verdict.affirmative_negatives:
        lines.append("> Nothing scored against this indicator. What was affirmatively reported:")
        lines.append(">")
        for signal in verdict.affirmative_negatives:
            lines.append(f"> - {md_code(signal.provider)}: {md_escape(signal.observation)}")
        return lines

    lines.append(
        "> No signal was extracted from the panel, so nothing scored either way. That is an "
        "absence of evidence and not evidence of absence."
    )
    return lines


def _signal_headline(signal: Signal) -> str:
    """One signal as a sentence: what it is worth, out of what, and what the provider said."""
    return f"{md_code(signal.provider)} {_weight_cell(signal)} - {md_escape(signal.observation)}"


def _weight_cell(signal: Signal, *, in_table: bool = False) -> str:
    """A signal's contribution, with its direction, which points alone do not carry.

    Direction and points are independent axes on this model: a zero-point signal can be strongly
    exculpatory and a ten-point one purely descriptive. Printing the number without the direction
    would let a context signal read as an accusation.
    """
    direction = md_escape(signal.direction.value)
    if signal.max_points > 0.0:
        cell = f"{direction} +{_points(signal.points)} of {_points(signal.max_points)}"
    else:
        cell = f"{direction}, observational (carries no weight)"
    if signal.ceiling_only:
        cell += " (ceiling-only)"
    return cell


def _review_section(verdict: Optional[Verdict], options: MarkdownOptions) -> List[str]:
    """Contradictions and the analyst-review flag, above the evidence rather than under it.

    Contradictions are reported and never averaged. Splitting the difference between VirusTotal's
    detections and AbuseIPDB's zero reports produces a number describing neither provider and
    discards the one fact that actually directs the next step: that the panel is split.
    """
    if verdict is None:
        return []
    if not (verdict.requires_analyst_review or verdict.contradictions or verdict.attribution_warning):
        return []

    base = options.heading_level
    lines = [_heading(2, base, "Analyst review"), ""]
    if verdict.requires_analyst_review:
        lines.append(
            "**ANALYST REVIEW REQUIRED.** This verdict was flagged for a human decision and "
            "must not be actioned automatically."
        )
        lines.append("")
    if verdict.attribution_warning:
        lines.append(f"**Attribution:** {md_escape(verdict.attribution_warning)}")
        lines.append("")

    rows: List[Sequence[str]] = []
    for contradiction in verdict.contradictions:
        rule = md_code(contradiction.rule_id, in_table=True)
        if contradiction.both_material:
            rule += " (material)"
        sides = f"{md_code(contradiction.left, in_table=True)} vs {md_code(contradiction.right, in_table=True)}"
        rows.append([rule, sides, md_escape(contradiction.summary), md_escape(contradiction.analyst_hint)])
    if rows:
        lines.append(f"Contradictions ({len(rows)}), reported and not reconciled:")
        lines.append("")
        lines.extend(md_table(["rule", "sides", "disagreement", "what to do"], rows))
    while lines and lines[-1] == "":
        lines.pop()
    return lines


def _answered_names(summary: CoverageSummary) -> List[str]:
    """Every provider the coverage summary counts as having answered, deduped, in bucket order."""
    names: List[str] = []
    for outcome, bucket in summary.groups.items():
        if outcome in _ANSWERED_OUTCOMES:
            names.extend(bucket)
    return list(dict.fromkeys(names))


def _evidence_section(
    verdict: Optional[Verdict],
    summary: CoverageSummary,
    options: MarkdownOptions,
) -> List[str]:
    """One row per provider observation: who said it, what they said, when they saw it.

    Every signal appears, including the ones worth nothing. A signal that scored zero is still
    something a provider said, and dropping it would make this a summary of the score rather than
    a record of the evidence.
    """
    base = options.heading_level
    lines = [_heading(2, base, "Evidence"), ""]

    signals = sorted(verdict.signals, key=lambda item: (-item.points, item.id)) if verdict else []
    rows: List[Sequence[str]] = []
    for signal in signals:
        what = md_escape(signal.observation)
        if signal.source_url:
            what = f"{what} ({md_link('source', signal.source_url, in_table=True)})"
        observed = _flatten(signal.observed_at)
        rows.append(
            [
                f"{md_code(signal.provider, in_table=True)} ({md_escape(signal.family)})",
                what,
                md_code(observed, in_table=True) if observed else "*not reported by the provider*",
                _weight_cell(signal, in_table=True),
            ]
        )

    if rows:
        lines.extend(md_table(["provider", "what it reported", "observed", "weight"], rows))
        lines.append("")
        lines.append(_OBSERVED_NOTE)
        silent = [name for name in _answered_names(summary) if name not in {s.provider for s in signals}]
        if silent:
            lines.append("")
            lines.append(
                "Answered, but no scored observation was extracted: "
                + ", ".join(md_code(name) for name in silent)
                + "."
            )
        return lines

    answered = _answered_names(summary)
    if answered:
        lines.append(
            "No observation was extracted from any provider. The following answered and their "
            "replies carried nothing this ruleset scores: " + ", ".join(md_code(name) for name in answered) + "."
        )
    else:
        lines.append("No provider observation is recorded for this indicator.")
    lines.append("")
    lines.append(_OBSERVED_NOTE)
    return lines


def _coverage_headline(summary: CoverageSummary) -> str:
    """The published headline where there is one, or the count, or an honest "unknown"."""
    if summary.headline:
        return summary.headline
    if not summary.known:
        return "unknown - no provider status was recorded for this lookup"
    noun = "provider" if summary.total == 1 else "providers"
    return f"{summary.answered} of {summary.total} {noun} answered"


def _skipped_rows(skipped: Iterable[Any], *, defang: bool) -> List[Sequence[str]]:
    """Addresses that were resolved and then deliberately never sent to a provider."""
    rows: List[Sequence[str]] = []
    for entry in skipped:
        if isinstance(entry, Mapping):
            address = entry.get("ip") or entry.get("address")
            source = entry.get("source")
            reason = _flatten(entry.get("reason")) or _flatten(entry.get("detail"))
        else:
            address, source, reason = entry, None, ""
        explanation = f"{reason} addressing - never sent to a provider" if reason else "no reason recorded"
        rows.append(
            [
                _indicator_cell(address, defang=defang, in_table=True),
                md_escape(source) or _EMPTY_CELL,
                md_escape(explanation),
            ]
        )
    return rows


def _not_established_section(
    verdict: Optional[Verdict],
    summary: CoverageSummary,
    view: _View,
    options: MarkdownOptions,
) -> List[str]:
    """The negative space, stated as plainly as the findings. This is the section that makes the
    document a report rather than a claim.

    Three kinds of gap land here and they are not interchangeable: providers that did not answer
    (and why, and what that means), addresses that were resolved but refused before any provider
    saw them, and collector warnings that qualify what the rest of the report says.
    """
    base = options.heading_level
    lines = [_heading(2, base, "Not established"), "", _NOT_ESTABLISHED_INTRO, ""]
    lines.append(f"**Coverage:** {md_escape(_coverage_headline(summary))}")

    if not summary.known:
        lines.append("")
        lines.append(
            "**No provider status was recorded for this lookup.** The report cannot say which "
            "providers were asked, so it cannot say what was established and what was not."
        )

    rows: List[Sequence[str]] = []
    ordered = [outcome for outcome in _GAP_ORDER if outcome in summary.groups]
    ordered.extend(
        sorted(o for o in summary.groups if o not in _ANSWERED_OUTCOMES and o not in ordered),
    )
    for outcome in ordered:
        status, meaning = _GAP_MEANING.get(outcome, (outcome, _UNKNOWN_GAP_MEANING))
        for name in summary.groups.get(outcome) or []:
            rows.append([md_code(name, in_table=True), md_escape(status), md_escape(meaning)])
    if rows:
        lines.append("")
        lines.extend(md_table(["provider", "status", "what that means"], rows))

    if verdict is None:
        lines.append("")
        lines.append(f"**Verdict:** {md_escape(_NO_VERDICT_NOTE)}")

    skipped_rows = _skipped_rows(view.skipped, defang=options.defang)
    if skipped_rows:
        lines.append("")
        lines.append(_heading(3, base, f"Addresses resolved but not investigated ({len(skipped_rows)})"))
        lines.append("")
        lines.extend(md_table(["address", "source", "reason"], skipped_rows))
        lines.append("")
        lines.append("No provider was asked about these addresses. Nothing here is evidence that they are clean.")

    if view.warnings:
        lines.append("")
        lines.append(_heading(3, base, f"Collector warnings ({len(view.warnings)})"))
        lines.append("")
        for warning in view.warnings:
            lines.append(f"- {md_escape(warning)}")

    lines.append("")
    lines.append(_NOT_ESTABLISHED_CLOSE)
    return lines


def _appendix_section(
    verdict: Optional[Verdict],
    view: _View,
    indicator: str,
    indicator_type: str,
    options: MarkdownOptions,
) -> List[str]:
    """Run metadata and the calibration statement.

    Everything needed to re-derive this report six months later, and nothing that pretends to be
    a measurement. The four timestamps are labelled separately on purpose -- see the module
    docstring. The calibration paragraph is not optional and is never softened: the engine makes
    no accuracy claim, and an artefact that omits that sentence implies one.
    """
    base = options.heading_level
    run_id, started_at, tool_version = run_fields(view.run)
    tool = _flatten(view.run.get("tool")) or "tripper-recon"

    rows: List[Sequence[str]] = [
        ["tool", md_code(tool, in_table=True)],
        ["tool version", md_code(tool_version or __version__, in_table=True)],
        ["run id", md_code(run_id, in_table=True) if run_id else "*not recorded*"],
        ["indicator", _indicator_cell(indicator, defang=options.defang, in_table=True) if indicator else _EMPTY_CELL],
        ["indicator type", md_escape(indicator_type) or "*not recorded*"],
        ["collection started", md_code(_stamp(started_at), in_table=True) if started_at else "*not recorded*"],
    ]

    rendered = _stamp(options.now)
    rows.append(
        [
            "report rendered",
            md_code(rendered, in_table=True) if rendered else "*not recorded - no render time was supplied*",
        ]
    )

    if verdict is not None:
        if verdict.passive_only:
            collection = _PASSIVE_LINE
        else:
            named = ", ".join(verdict.active_collection) or "unnamed active steps"
            collection = f"ACTIVE COLLECTION contributed: {named}"
        rows.extend(
            [
                ["collection mode", md_escape(collection)],
                ["verdict evaluated", md_code(verdict.evaluated_at_rfc3339, in_table=True)],
                ["ruleset version", md_code(verdict.ruleset_version, in_table=True)],
                ["ruleset source", md_code(verdict.ruleset_source, in_table=True)],
                ["engine version", md_code(verdict.engine_version, in_table=True)],
                ["verdict schema", md_code(verdict.schema_version, in_table=True)],
            ]
        )
        if verdict.allowlist is not None:
            allowlist = verdict.allowlist
            detail = f"{allowlist.list_version}, retrieved {allowlist.list_retrieved} - {allowlist.staleness_note}"
            rows.append(["allowlist", md_escape(detail)])
    else:
        rows.append(["collection mode", "*not recorded - no verdict was computed*"])

    lines = [_heading(2, base, "Appendix: run metadata"), ""]
    lines.extend(md_table(["field", "value"], rows))
    lines.append("")
    if verdict is not None and _flatten(verdict.calibration_statement):
        lines.append(f"**Calibration.** {md_escape(verdict.calibration_statement)}")
        lines.append("")
    lines.append(_CALIBRATION_FLOOR)
    return lines


# --------------------------------------------------------------------------------------
# The entry point
# --------------------------------------------------------------------------------------


def render_markdown(result: Any, options: Optional[MarkdownOptions] = None) -> str:
    """Render one investigation result as a markdown report. Pure: no I/O, no clock.

    ``result`` is an ``InvestigationResult``, its ``model_dump()``, or the bare ``result.data``
    mapping every console renderer receives. Anything unrecognised produces a report that says it
    knows nothing, which is the honest output for a payload the renderer could not read.

    Section order is the reading order under time pressure, and it is fixed:

    1. **the verdict** -- the word, the score, the confidence and the coverage ratio, because
       "SUSPICIOUS at LOW confidence on 2 of 6 providers" is one fact rather than three;
    2. **``> Why:``** -- the two or three signals that justify it, each with its evidence and the
       date the provider observed it;
    3. **analyst review** -- contradictions and the review flag, above the evidence, because they
       are the reason to stop rather than a footnote to it;
    4. **evidence** -- every provider observation, with the provider's own observation date;
    5. **not established** -- who did not answer, what was refused, and what that means. The
       section that makes this a report rather than a claim;
    6. **appendix** -- run metadata, ruleset provenance, and the calibration statement.

    Domain reports whose per-address blocks each carry their own verdict are rendered by calling
    this function once per entry of ``data['ips']``: those entries have the same shape as an IP
    payload, and composing them is the caller's decision rather than this module's.
    """
    opts = options or MarkdownOptions()
    view = _view(result)
    verdict = verdict_from_payload(view.data.get("verdict"))
    summary = summarize_coverage(view.coverage)
    indicator, indicator_type = _indicator_of(view.data, verdict, opts)

    if opts.title is not None:
        title = md_escape(opts.title)
    elif indicator:
        subject = _indicator_cell(indicator, defang=opts.defang)
        title = f"Tripper Recon report: {subject}"
        if indicator_type:
            title += f" ({md_escape(indicator_type)})"
    else:
        title = "Tripper Recon report"

    lines: List[str] = [_heading(1, opts.heading_level, title)]

    for block in (
        _verdict_section(verdict, view.data, summary, opts),
        _why_block(verdict, opts),
        _review_section(verdict, opts),
        _evidence_section(verdict, summary, opts),
        _not_established_section(verdict, summary, view, opts),
        _appendix_section(verdict, view, indicator, indicator_type, opts),
    ):
        if not block:
            continue
        _blank(lines)
        lines.extend(block)

    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines) + "\n"
