from __future__ import annotations

import re
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Dict, Iterable, List, Mapping, NamedTuple, Optional, Sequence, Tuple, Union

from pydantic import ValidationError
from rich.console import Group, RenderableType
from rich.markup import escape
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

from tripper_recon import __version__
from tripper_recon.verdict.models import Signal, Verdict, VerdictLabel

# --------------------------------------------------------------------------------------
# Defanging (roadmap 6.2) -- the indicator, never the document
#
# A recon report is pasted into tickets, chat and email, and every one of those turns a live
# indicator into something clickable. Defanging is what stops a colleague scrolling past a
# phishing URL in a ticket and resolving it by accident -- which is both a compromise risk and,
# for a single-use link, the tell that burns the investigation the tool was careful not to burn.
#
# **This is a per-field transform and there is deliberately no document-wide pass.** A regex
# sweep over rendered output cannot tell the indicator from the pivot links beside it: it would
# mangle `radar.cloudflare.com/ip/1.2.3.4` into something unclickable and destroy the part of
# the report an analyst actually uses. So each function below takes ONE field whose entire
# content is one indicator, and the call sites are individually chosen.
#
# Three standing rules, each the inverse of a way this could go wrong:
#
# * **Third-party pivot links stay live.** They point at VirusTotal, Shodan, AbuseIPDB and
#   Cloudflare Radar -- never at the target -- and their whole value is being clickable.
# * **The JSON export is never defanged.** Machines consume it, and `evil[.]com` is not a
#   hostname. `cli.py`'s `-o json` branch does not route through this module at all.
# * **Non-public addressing is not defanged.** `10.0.0.5` is the operator's own internal
#   addressing rather than a hostile indicator; bracketing it adds noise to the one table --
#   addresses resolved but not investigated -- that exists to be read carefully.
# --------------------------------------------------------------------------------------

#: Scheme rewrites. `hxxp` is the convention every ticketing system and SOC analyst already
#: reads; inventing a different mangling would make the output less legible, not safer.
_DEFANG_SCHEMES: Dict[str, str] = {"http": "hxxp", "https": "hxxps", "ftp": "fxp", "ftps": "fxps"}

_SCHEME_MARK = "://"


#: A scheme token immediately in front of ``://``, per RFC 3986 section 3.1.
_EMBEDDED_SCHEME_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*)://")


def _defang_scheme_markers(text: str) -> str:
    """Neutralise every ``scheme://`` inside one field, leaving all other bytes alone."""

    def _rewrite(match: re.Match[str]) -> str:
        scheme = match.group(1).lower()
        return f"{_DEFANG_SCHEMES.get(scheme, scheme)}[{_SCHEME_MARK}]"

    return _EMBEDDED_SCHEME_RE.sub(_rewrite, text)


def defang_host(host: str) -> str:
    """Bracket the dots in a hostname. ``evil.example`` -> ``evil[.]example``."""
    return host.replace(".", "[.]")


def defang_address(address: str) -> str:
    """Defang a public IPv4 literal. Everything else comes back verbatim.

    Three deliberate non-actions:

    * **Non-public addressing is untouched** -- see the module rule above.
    * **IPv6 is untouched.** Nothing linkifies a bare IPv6 literal, so bracketing its colons
      buys no safety, and ``2606[:]4700[:][:]1111`` is materially harder to read and to paste
      back than the address it came from. Cost with no benefit is not a security control.
    * **An unparsable string is untouched**, rather than guessed at. A renderer that mangles a
      value it did not understand is asserting a reading it does not have.
    """
    try:
        parsed = ip_address(address)
    except ValueError:
        return address
    if parsed.version != 4 or not parsed.is_global:
        return address
    return address.replace(".", "[.]")


def _defang_bare_host(value: str) -> str:
    """One host with no userinfo and no port: an address literal, or a name."""
    try:
        ip_address(value)
    except ValueError:
        return defang_host(value)
    return defang_address(value)


def defang_indicator(value: Any) -> str:
    """Defang one whole field that holds exactly one indicator: a URL, a host, or an address.

    Only the scheme and the host are touched. The path and query keep every byte, because they
    routinely carry the campaign identifier an analyst is pivoting on and because nothing in a
    path is clickable on its own.
    """
    text = str(value or "")
    if not text:
        return text

    head, mark, tail = text.partition(_SCHEME_MARK)
    if mark:
        scheme = head.lower()
        authority, slash, rest = tail.partition("/")
        # The path and query keep every byte -- they routinely carry the campaign identifier an
        # analyst is pivoting on -- except for any scheme marker inside them. An open-redirect
        # parameter (`?next=hxxp://evil.example`, written defanged because tests/test_passivity.py
        # fails the build on a URL literal naming a non-allowlisted host) is a second live link,
        # and a terminal will happily linkify it out of a "defanged" report.
        return (
            f"{_DEFANG_SCHEMES.get(scheme, scheme)}[{_SCHEME_MARK}]"
            f"{defang_indicator(authority)}{slash}{_defang_scheme_markers(rest)}"
        )

    # An authority: optional userinfo, a host, an optional port. Only the host is defanged.
    credentials, at, hostport = text.rpartition("@")
    prefix = f"{credentials}{at}" if at else ""
    if hostport.startswith("[") and "]" in hostport:
        return f"{prefix}{hostport}"  # a bracketed IPv6 literal; left literal, see defang_address
    host, colon, port = hostport.rpartition(":")
    # `":" not in host` is what keeps an unbracketed IPv6 literal out of this branch: the last
    # group of `2606:4700::1111` is all digits and would otherwise be read as a port.
    if colon and port.isdigit() and ":" not in host:
        return f"{prefix}{_defang_bare_host(host)}{colon}{port}"
    return f"{prefix}{_defang_bare_host(hostport)}"


def indicator_text(value: Any, *, defang: bool) -> str:
    """The escaped, optionally-defanged form of one indicator field.

    The single call every renderer in this module uses, so the ``defang`` flag cannot be
    honoured in one row and forgotten in the next.
    """
    return esc(defang_indicator(value) if defang else value)


#: How each `source` tag produced by ``orchestrators._tag_ip_sources`` is explained on screen.
#:
#: The tag itself is machine vocabulary; the parenthetical is the evidentiary claim, and the
#: claim is the point. "Resolved now" means this address answers for the domain at the moment
#: of the lookup. "Seen historically" means VirusTotal recorded the mapping at some past date
#: this tool does not currently retain -- the address may have moved on years ago. An analyst
#: pivoting on a passive-only address is making a weaker statement than one pivoting on an
#: active answer, and the report has to say which one they are holding.
_SOURCE_EXPLANATIONS: Dict[str, str] = {
    "active": "active - resolved now by the system resolver",
    "passive": "passive - seen historically in VirusTotal DNS records, may be stale",
    "active+passive": "active+passive - resolved now, and corroborated by VirusTotal DNS history",
}

#: The same distinction, carried by colour so it survives a skim.
#:
#: Only tags this module recognises are styled. An unrecognised tag is echoed unstyled, for the
#: same reason ``_fmt_source`` echoes it unglossed: a tag the renderer does not understand must
#: not be dressed up as one it does. A passive-only address is the weakest claim on the screen
#: and is the one that gets the warning colour.
_SOURCE_STYLES: Dict[str, str] = {
    "passive": "yellow",
}


def esc(value: Any) -> str:
    """Render a provider-controlled value as literal text.

    Every string in this module's output originates with a third party -- an OTX pulse title, a
    Shodan org name, a WHOIS field. `rich` parses square brackets as markup, so an attacker-named
    pulse such as ``evil [/] campaign`` raises MarkupError, and ``[green]0/94[/]`` renders as a
    green zero. Escaping is both a crash guard and a display-spoof guard.
    """
    if value is None:
        return ""
    return escape(str(value))


# --------------------------------------------------------------------------------------
# Coverage -- how much of the picture the analyst is actually holding
#
# This is the section that closes the tool's most dangerous gap. Run it with two of six
# credentials set and the old renderer showed a VirusTotal score, one Shodan error, and no
# indication whatsoever that four providers were never asked. Sparse output reads as a clean
# indicator, and nothing on the screen contradicted that reading.
#
# ``orchestrators._status_map`` already records the truth per provider. Everything here is
# about getting it onto the screen where it cannot be skipped.
# --------------------------------------------------------------------------------------

#: Outcomes in which the provider was reached and said something.
#:
#: ``not_found`` counts as answered deliberately: a provider that was asked and holds no record
#: has contributed evidence of absence. A provider that was never asked has contributed nothing,
#: and the whole point of this module is that those two must never look alike. The set carries
#: spellings this renderer does not emit itself (``answered``, ``no_record``) because the data
#: model is being extended in parallel and an unrecognised outcome must fail closed -- counted
#: as a gap and named on screen, never silently counted as coverage.
_ANSWERED_OUTCOMES: frozenset = frozenset({"ok", "answered", "not_found", "no_record"})

#: Outcome value -> the phrase an analyst can act on. Unknown outcomes fall back to the raw
#: value, which is a fact the collector recorded even when this renderer cannot gloss it.
_OUTCOME_LABELS: Dict[str, str] = {
    "ok": "answered",
    "answered": "answered",
    "not_found": "answered, holds no record",
    "no_record": "answered, holds no record",
    "error": "query failed",
    "not_configured": "never asked - no API key configured",
    "skipped": "never asked - skipped",
    "unrecorded": "outcome not recorded",
}

#: Gaps are listed before answers, and the most misleading gap is listed first.
_GAP_ORDER: Tuple[str, ...] = ("not_configured", "skipped", "error", "unrecorded", "not_found", "no_record")

#: Every "the provider did not answer" cell contains this substring, whatever the outcome was.
#: One invariant string is what lets a reader -- and a test -- ask "did anything render as an
#: absence?" without enumerating the reasons.
_NO_DATA_PREFIX = "no data"

_NO_DATA_BY_OUTCOME: Dict[str, str] = {
    "error": f"{_NO_DATA_PREFIX} - query failed",
    "not_configured": f"{_NO_DATA_PREFIX} - not configured, no API key",
    "skipped": f"{_NO_DATA_PREFIX} - not queried",
    "not_found": f"{_NO_DATA_PREFIX} - provider holds no record",
    "no_record": f"{_NO_DATA_PREFIX} - provider holds no record",
}

#: Used when nothing was recorded about the provider at all, which is itself unknown coverage.
_NO_DATA_UNKNOWN = f"{_NO_DATA_PREFIX} - not queried or query failed"


class CoverageSummary(NamedTuple):
    """How many providers answered, out of how many were considered, and who did what.

    ``groups`` maps an outcome value to the provider names that ended in it, so the renderer
    can name the unconfigured providers rather than leaving the analyst to infer them from an
    empty screen.
    """

    answered: int
    total: int
    groups: Dict[str, List[str]]
    #: The published ``Coverage.headline`` when the caller supplied one, so the screen and the
    #: JSON export state the ratio in identical words rather than in two computations of it.
    headline: Optional[str] = None

    @property
    def known(self) -> bool:
        """False when no provider status was recorded, i.e. coverage itself is unknown."""
        return self.total > 0

    @property
    def complete(self) -> bool:
        return self.total > 0 and self.answered == self.total


def _as_names(value: Any) -> List[str]:
    """Coerce a published bucket to a list of names, tolerating anything else."""
    if isinstance(value, (list, tuple)):
        return [str(name) for name in value]
    return []


def _as_count(value: Any, fallback: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return fallback
    return value


def _summarize_published_coverage(coverage: Dict[str, Any]) -> CoverageSummary:
    """Read a dumped ``types.models.Coverage`` -- the authoritative figure on ``data['coverage']``.

    Preferring the published object over a second computation from ``provider_status`` is not
    a shortcut: the model knows things the raw status map does not, notably which providers
    were *expected* and never attempted at all. Recomputing here would let the console quietly
    report better coverage than the JSON export of the same run.
    """
    not_found = _as_names(coverage.get("not_found"))
    not_found_set = set(not_found)
    answered_names = _as_names(coverage.get("answered"))
    groups: Dict[str, List[str]] = {
        "ok": [name for name in answered_names if name not in not_found_set],
        "not_found": not_found,
        "error": _as_names(coverage.get("errored")),
        "not_configured": _as_names(coverage.get("unconfigured")),
        "skipped": _as_names(coverage.get("skipped")),
    }
    groups = {outcome: names for outcome, names in groups.items() if names}

    answered = _as_count(coverage.get("answered_count"), len(answered_names))
    total = _as_count(
        coverage.get("applicable_count"),
        answered + sum(len(groups.get(o, [])) for o in ("error", "not_configured", "skipped")),
    )
    headline = coverage.get("headline")
    return CoverageSummary(
        answered=answered,
        total=total,
        groups=groups,
        headline=str(headline) if isinstance(headline, str) and headline.strip() else None,
    )


def summarize_coverage(source: Any) -> CoverageSummary:
    """Fold coverage input into an answered/total count plus per-outcome names.

    Accepts either shape the package produces: a dumped ``Coverage`` (``data['coverage']``,
    preferred) or a raw ``provider_status`` map. Also accepts anything else -- a missing key,
    a non-mapping, entries that are bare strings rather than the ``{"outcome": ...}`` dicts the
    orchestrator emits. Coverage reporting is the control that stops absence reading as safety,
    so it must not be the thing that raises.
    """
    if not isinstance(source, dict) or not source:
        return CoverageSummary(answered=0, total=0, groups={})

    if "applicable_count" in source or "headline" in source:
        return _summarize_published_coverage(source)

    groups: Dict[str, List[str]] = {}
    answered = 0
    for name, entry in source.items():
        raw: Any = entry.get("outcome") if isinstance(entry, dict) else entry
        outcome = str(raw).strip() if raw is not None else ""
        if not outcome:
            outcome = "unrecorded"
        if outcome in _ANSWERED_OUTCOMES:
            answered += 1
        groups.setdefault(outcome, []).append(str(name))

    for names in groups.values():
        names.sort()
    return CoverageSummary(answered=answered, total=len(source), groups=groups)


def no_data_text(outcome: Optional[str]) -> str:
    """The cell text for a provider that did not answer, given its recorded outcome.

    A provider that was never asked is never rendered as a zero and never in green -- that
    equivalence is the defect W0.2 removed from the VirusTotal row, and this function is how
    the same rule reaches every other row.

    Public because ``cli.py`` renders the domain-level VirusTotal and OTX rows itself, outside
    any table this module builds. One sentence for "the provider did not answer", written once,
    is what stops the domain path from growing its own vocabulary for absence -- which is how
    it kept a green ``0/0`` for two workstreams after the IP path lost one.
    """
    if not outcome:
        return _NO_DATA_UNKNOWN
    known = _NO_DATA_BY_OUTCOME.get(outcome)
    if known:
        return known
    return f"{_NO_DATA_PREFIX} - provider outcome {outcome}"


def _no_data_cell(outcome: Optional[str]) -> str:
    """``no_data_text`` as a table cell: yellow, escaped, never green and never a zero."""
    return f"[yellow]{esc(no_data_text(outcome))}[/]"


def _confidence_score(value: Any) -> Optional[int]:
    """Read an AbuseIPDB confidence score, or ``None`` when the provider supplied no usable one.

    The predecessor was ``int(conf_val)`` inside a bare ``except`` that fell back to ``0`` --
    so a missing key, a null, or a malformed value all rendered as a green ``0%``. ``bool`` is
    rejected for the same reason ``_incident_count`` rejects it.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return max(0, min(100, value))
    if isinstance(value, float):
        return max(0, min(100, int(value)))
    text = str(value).strip()
    if not text.isdigit():
        return None
    return max(0, min(100, int(text)))


def provider_outcome(provider_status: Any, *names: str) -> Optional[str]:
    """The recorded outcome for the first of ``names`` present, or ``None`` if none was recorded.

    ``None`` means "nothing is known about this provider call", which is not the same as
    "the provider did not answer" and renders differently.

    Public for the same reason :func:`no_data_text` is: ``cli.py`` reads
    ``data['domain_provider_status']`` when it renders the domain-level intelligence rows.
    """
    if not isinstance(provider_status, dict):
        return None
    for name in names:
        entry = provider_status.get(name)
        if entry is None:
            continue
        raw: Any = entry.get("outcome") if isinstance(entry, dict) else entry
        if raw is None:
            continue
        text = str(raw).strip()
        if text:
            return text
    return None


def _answered(outcome: Optional[str]) -> bool:
    """True when the provider was reached. ``None`` (nothing recorded) is not a claim either way."""
    return outcome is not None and outcome in _ANSWERED_OUTCOMES


def render_coverage(source: Any, *, label: str = "provider_coverage") -> Text:
    """The coverage line: "N of M providers answered", with every gap named.

    ``source`` is either a dumped ``types.models.Coverage`` (``data['coverage']``) or a raw
    ``provider_status`` map; see :func:`summarize_coverage`.

    Built as a ``Text`` rather than a markup string on purpose -- provider names arrive as
    dictionary keys and ``Text`` never parses markup, so there is no injection surface here at
    all. Colour is a coverage claim, not a safety claim: green means the picture is complete,
    not that the indicator is clean.
    """
    summary = summarize_coverage(source)
    if not summary.known:
        return Text(
            f"{label}: unknown - no provider status was recorded for this lookup",
            style="bold yellow",
        )

    if summary.complete:
        style = "bold green"
    elif summary.answered == 0:
        style = "bold red"
    else:
        style = "bold yellow"

    noun = "provider" if summary.total == 1 else "providers"
    headline = summary.headline or f"{summary.answered} of {summary.total} {noun} answered"
    line = Text(f"{label}: {headline}", style=style)

    ordered: List[str] = [outcome for outcome in _GAP_ORDER if outcome in summary.groups]
    ordered.extend(
        sorted(o for o in summary.groups if o not in _GAP_ORDER and o not in _ANSWERED_OUTCOMES and o not in ordered)
    )
    for outcome in ordered:
        names = summary.groups.get(outcome) or []
        if not names:
            continue
        gloss = _OUTCOME_LABELS.get(outcome, outcome)
        line.append("\n")
        line.append(f"  {gloss}: {', '.join(names)}", style="yellow")
    return line


def _utc_stamp(value: Any = None) -> str:
    """Format a run timestamp as UTC, or produce one now when the caller has none.

    A caller-supplied value wins so the timestamp can be the moment collection started rather
    than the moment the screen was painted -- and so tests can pin it.
    """
    if isinstance(value, datetime):
        moment = value.astimezone(timezone.utc) if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return moment.strftime("%Y-%m-%dT%H:%M:%SZ")
    if value is not None:
        text = str(value).strip()
        if text:
            return text
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_fields(run: Any) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Read ``(run_id, started_at, tool_version)`` out of a dumped ``types.models.RunMetadata``.

    Returns ``(None, None, None)`` for anything that is not one, so a renderer handed an older
    payload falls back to its own defaults instead of failing.
    """
    if not isinstance(run, dict):
        return None, None, None

    def _field(key: str) -> Optional[str]:
        value = run.get(key)
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    return _field("run_id"), _field("started_at"), _field("tool_version")


def render_run_header(
    title: str,
    *,
    run_id: Any = None,
    generated_at: Any = None,
    version: Optional[str] = None,
    show_run_line: bool = True,
) -> Text:
    """Report title plus the provenance of the run that produced it.

    A report that outlives its terminal has to say which build of the tool produced it and
    when; ``--- IP lookup for 1.2.3.4 ---`` told a reader neither. The run id ties a console
    block to the JSON export of the same run, and is reported as unrecorded rather than
    omitted when the caller does not supply one.
    """
    header = Text(title, style="bold white")
    if not show_run_line:
        return header

    rid = str(run_id).strip() if run_id is not None else ""
    parts = [
        f"tripper-recon {version or __version__}",
        _utc_stamp(generated_at),
        f"run {rid}" if rid else "run id not recorded",
    ]
    header.append("\n")
    header.append(" • ".join(parts), style="dim")
    return header


def compose_report(
    header: RenderableType,
    body: Iterable[RenderableType],
    *,
    verdict: Optional[RenderableType] = None,
    coverage: Optional[RenderableType] = None,
    notices: Optional[Iterable[RenderableType]] = None,
) -> Group:
    """Assemble one report block in the fixed vertical order every renderer here uses.

    Order: header, verdict, coverage, notices, body. The verdict comes before the coverage line
    and both come before the body, because a reader who stops after the first screen must have
    seen the answer and how much of the panel stands behind it. See :func:`render_verdict` for
    why the answer is a word and not a colour.
    """
    parts: List[RenderableType] = [header]
    if verdict is not None:
        parts.append(verdict)
    if coverage is not None:
        parts.append(coverage)
    if notices is not None:
        parts.extend(notices)
    parts.extend(body)
    return Group(*parts)


def render_warnings(warnings: Any, *, title: str = "warnings") -> Optional[RenderableType]:
    """Render collector warnings, or ``None`` when there are none.

    The ASN and domain orchestrators compute these and the console branch has never printed
    them, so a failed CAIDA or PeeringDB lookup degraded the panel silently. ``Text`` again:
    a warning line can quote a provider string.
    """
    if not isinstance(warnings, (list, tuple)):
        return None
    items = [str(w) for w in warnings if str(w).strip()]
    if not items:
        return None

    block = Text(f"{title} ({len(items)}):", style="bold yellow")
    for item in items:
        block.append("\n")
        block.append(f"  - {item}", style="yellow")
    return block


#: Warning sentences whose content the coverage line already carries, verbatim.
#:
#: ``orchestrators._coverage_warnings`` writes these from the same ``Coverage`` object the
#: coverage line is rendered from, so printing both says the same thing twice, two lines apart.
#: Matching on a prefix couples this filter to that wording -- deliberately in the safe
#: direction: a wording change upstream costs one duplicated line, and can never hide one.
_COVERAGE_WARNING_PREFIXES: Tuple[str, ...] = (
    "partial coverage:",
    "no provider answered (",
    "never asked, no API key configured:",
    "never attempted:",
)


#: The sentence fragment ``types.models.SkippedAddress.explanation`` builds. Same coupling and
#: same safe direction as ``_COVERAGE_WARNING_PREFIXES``: a wording change upstream costs one
#: duplicated line and can never hide one, because the match also requires the address to be
#: listed in the skipped-address table that is about to be rendered anyway.
_SKIP_WARNING_MARKER = "was not investigated:"


def _skipped_addresses_named(skipped: Any) -> List[str]:
    """The addresses a skipped-address block is about to name in full."""
    if not isinstance(skipped, (list, tuple)):
        return []
    names: List[str] = []
    for entry in skipped:
        address = str(entry.get("ip") or entry.get("address") or "") if isinstance(entry, dict) else str(entry)
        if address.strip():
            names.append(address.strip())
    return names


def _warnings_beyond_coverage(warnings: Any, *, skipped: Any = None) -> List[str]:
    """Warnings that say something the rest of the report does not already say.

    Two sources of duplication, both from the orchestrator writing warnings out of the same
    objects the header renders directly: the coverage sentences (deduped against the coverage
    line) and one per-address sentence for every skipped address (deduped against the
    skipped-address table). A domain resolving to twenty internal addresses otherwise prints
    forty lines for twenty facts, and volume is how a reader learns to skim past the block this
    workstream exists to make unskippable.
    """
    if not isinstance(warnings, (list, tuple)):
        return []
    addresses = _skipped_addresses_named(skipped)
    kept: List[str] = []
    for warning in warnings:
        text = str(warning)
        if not text.strip() or text.startswith(_COVERAGE_WARNING_PREFIXES):
            continue
        if _SKIP_WARNING_MARKER in text and any(text.startswith(address) for address in addresses):
            continue
        kept.append(text)
    return kept


def render_skipped_ips(skipped: Any, *, defang: bool = False) -> Optional[RenderableType]:
    """Render addresses that were resolved but deliberately never sent to a provider.

    On the domain path the private/reserved guard drops these before enrichment, and until now
    they vanished from the output entirely: an analyst who resolved four addresses and saw one
    investigated was given no way to learn what happened to the other three. Silently
    disappearing evidence is indistinguishable from evidence that came back clean.

    ``defang`` is honoured but is almost always a no-op here: every address in this table was
    refused for being non-public, and :func:`defang_address` leaves non-public addressing
    literal. The parameter exists so the flag is threaded uniformly rather than special-cased.
    """
    if not isinstance(skipped, (list, tuple)) or not skipped:
        return None

    heading = Text(f"addresses resolved but not investigated ({len(skipped)}):", style="bold yellow")
    table = Table(show_header=True, box=None, padding=(0, 2), header_style="bold yellow")
    table.add_column("address")
    table.add_column("source")
    table.add_column("reason")

    for entry in skipped:
        if isinstance(entry, dict):
            address = str(entry.get("ip") or "")
            source = str(entry.get("source") or "")
            reason = str(entry.get("reason") or "")
        else:
            address = str(entry)
            source = ""
            reason = ""
        reason_text = f"{reason} addressing - never sent to a provider" if reason else "no reason recorded"
        table.add_row(indicator_text(address, defang=defang), esc(source) or "-", esc(reason_text))

    note = Text(
        "  no provider was asked about these addresses; nothing here is evidence that they are clean",
        style="dim",
    )
    return Group(heading, table, note)


# --------------------------------------------------------------------------------------
# The verdict block (roadmap 5.8) -- the answer, first, in words
#
# The layout below is driven by one measured failure. `rich` strips ANSI the moment stdout is
# not a terminal, which is exactly the `tripper-recon ip X > incident.md` workflow this tool
# exists to feed. A renderer whose only malice signal is colour says nothing at all on that
# path, and a flat key/value table gives `virustotal_detections 5/91` no more weight than
# `postal_code 100000` two rows above it.
#
# So: the verdict WORD is text, on the first line, before anything else. Colour reinforces it
# and never carries it. Everything in this section is built as `rich.text.Text` rather than a
# markup string -- Text never parses markup, so an OTX pulse title quoted inside a signal
# observation or an analyst hint has no injection surface at all, which is a stronger guarantee
# than remembering to call `esc` on each one.
# --------------------------------------------------------------------------------------

#: Five verdict states folded to three colours, because a screen that uses five is a screen
#: nobody reads at 02:00. The fold is deliberate and errs one way: ``INSUFFICIENT_DATA`` shares
#: the warning colour with ``SUSPICIOUS`` rather than the clean colour, because "we do not know"
#: must never look like "we looked and it was fine". Only the two states an allowlist or an
#: affirmative negative can produce are green.
_VERDICT_STYLES: Dict[str, str] = {
    VerdictLabel.MALICIOUS.value: "bold red",
    VerdictLabel.SUSPICIOUS.value: "bold yellow",
    VerdictLabel.INSUFFICIENT_DATA.value: "bold yellow",
    VerdictLabel.NO_ADVERSE_FINDINGS.value: "bold green",
    VerdictLabel.KNOWN_INFRASTRUCTURE.value: "bold green",
}

#: Fallback for a label this renderer does not recognise. Yellow, never green: an unknown
#: verdict string is unknown coverage of the verdict vocabulary, and the safe reading of
#: unknown is "look at it".
_VERDICT_STYLE_UNKNOWN = "bold yellow"

#: How many justifying signals the banner shows before the analyst has to ask for ``--explain``.
#: Three is the number that fits above the fold beside the coverage line; the full ordered list
#: is always one flag away and always in the JSON.
_TOP_SIGNALS = 3

#: Printed in place of the banner when the engine could not produce a verdict at all. It is a
#: statement of ignorance, in the warning colour, and it is never omitted -- a panel with no
#: verdict line reads as a panel whose verdict was fine.
_VERDICT_UNAVAILABLE = "VERDICT: NOT COMPUTED"


def verdict_from_payload(value: Any) -> Optional[Verdict]:
    """Coerce ``data['verdict']`` into a :class:`Verdict`, or ``None`` when it is not one.

    The orchestrators publish the verdict onto ``data`` as its JSON dump, because the console
    renderers are handed ``result.data`` and nothing else. Parsing it back here rather than
    reading raw keys buys the model's own invariants -- notably that a benign label cannot exist
    without an affirmative negative behind it -- on the rendering path too, so a hand-edited or
    truncated payload fails to parse instead of printing a clean word it did not earn.

    Returns ``None`` rather than raising. A malformed verdict must degrade to "not computed",
    which the caller renders as a warning; it must never take the rest of the report down.
    """
    if isinstance(value, Verdict):
        return value
    if not isinstance(value, Mapping):
        return None
    try:
        return Verdict.model_validate(dict(value))
    except ValidationError:
        return None


def _fmt_points(value: float) -> str:
    """One decimal place. Points are weighted sums, not counts, and rounding to int hides work."""
    return f"{value:.1f}"


def _signal_line(signal: Signal) -> str:
    """One justifying signal: what it was worth, out of what, and the evidence for it."""
    return f"+{_fmt_points(signal.points)} of {_fmt_points(signal.max_points)}  {signal.id}: {signal.observation}"


class _IndentedBlock:
    """A verdict block whose indentation survives line wrapping.

    A single ``rich.Text`` carrying embedded newlines wraps every over-long line back to column
    zero. At width 100 the demotion reason for a real verdict rendered like this::

        ! SUSPICIOUS rather than NO_ADVERSE_FINDINGS: vt.weighted_detections and 3 other adverse
        reported something, below the 35-point band but not nothing. The clean label is a ...

    -- and the continuation, sitting flush left with no ``!`` in front of it, reads as a new
    top-level statement rather than as the rest of the one above. Redirect to a file, drop the
    colour, hand it to somebody at 3am, and the block structure that makes the panel scannable
    is gone exactly when it is needed most.

    So each logical line becomes its own renderable under a ``Padding`` left offset. Rich
    re-applies the offset to every wrapped row, so a continuation lands under its own bullet
    instead of under the margin. The trade is one ``Group`` where there used to be one ``Text``;
    callers already accept either, because ``--explain`` has always returned a ``Group``.
    """

    def __init__(self, first: Text) -> None:
        self._rows: List[RenderableType] = [first]

    def append(self, text: str, *, style: str = "") -> None:
        """Extend the most recent row in place, for the headline's trailing detail."""
        head = self._rows[-1]
        if isinstance(head, Text):
            head.append(text, style=style)
            return
        self._rows.append(Text(text, style=style))

    def add(self, line: str, *, indent: str = "  ", style: str = "") -> None:
        """One logical line, indented by ``indent`` on its first row and on every wrapped row.

        Any bullet in ``indent`` (``"    - "``) stays in the text so it prints once; only the
        leading whitespace becomes the padding, so wrapped rows align under the bullet rather
        than repeating it.
        """
        marker = indent.lstrip()
        offset = len(indent) - len(marker)
        self._rows.append(Padding(Text(f"{marker}{line}", style=style), (0, 0, 0, offset)))

    def renderable(self) -> RenderableType:
        return Group(*self._rows)


def _append_lines(
    block: Union[_IndentedBlock, Text], lines: Iterable[str], *, indent: str = "  ", style: str = ""
) -> None:
    """Append one logical line per entry, to either block flavour.

    ``_IndentedBlock`` keeps the indent through wrapping; a plain ``Text`` does not. Both are in
    use: the verdict banner is the block an analyst reads under time pressure and has been
    converted, while the renderers that emit short lines still build a ``Text`` and gain nothing
    from the change. Accepting both keeps that a per-renderer decision rather than a flag day.
    """
    if isinstance(block, Text):
        for line in lines:
            block.append("\n")
            block.append(f"{indent}{line}", style=style)
        return
    for line in lines:
        block.add(line, indent=indent, style=style)


def render_verdict_explanation(verdict: Verdict) -> Text:
    """The full audit trail behind one verdict: every signal, every weight, every criterion.

    This is what ``--explain`` prints, and it is the difference between a verdict a SOC will
    act on and a black box they will learn to ignore. Every number on screen is traceable to
    the ruleset key that set it (``weight_source``), the provider value it was computed from
    (``evidence``), and the date the provider observed it -- so an analyst can disagree with the
    tool specifically rather than generally.

    Zero-point observations are listed too. A signal that scored nothing is still a thing a
    provider said, and omitting it would make the breakdown a summary of the score rather than
    a record of the evidence.
    """
    block = Text("verdict explanation (--explain)", style="bold white")

    block.append("\n")
    block.append(f"  indicator: {verdict.indicator} ({verdict.indicator_type})", style="dim")
    block.append("\n")
    block.append(
        f"  score {verdict.score} (raw {_fmt_points(verdict.raw_score)}), "
        f"band from score alone: {verdict.score_band.value}",
        style="dim",
    )

    if verdict.signals:
        block.append("\n")
        block.append(f"  signals ({len(verdict.signals)}), highest contribution first:", style="bold")
        for signal in sorted(verdict.signals, key=lambda item: item.points, reverse=True):
            block.append("\n")
            block.append(
                f"    {signal.id}  [{signal.direction.value}]  {signal.provider} / {signal.family}",
                style="bold",
            )
            _append_lines(
                block,
                [
                    f"points {_fmt_points(signal.points)} of {_fmt_points(signal.max_points)} "
                    f"(magnitude {signal.magnitude:.4f})" + ("  [ceiling-only]" if signal.ceiling_only else ""),
                    f"observation: {signal.observation}",
                    f"weight from: {signal.weight_source}",
                    f"observed at: {signal.observed_at or 'not reported by the provider'}",
                ],
                indent="      ",
                style="dim",
            )
            if signal.evidence:
                _append_lines(
                    block,
                    [f"evidence: {key} = {value!r}" for key, value in signal.evidence.items()],
                    indent="        ",
                    style="dim",
                )
            if signal.source_url:
                _append_lines(block, [f"source: {signal.source_url}"], indent="      ", style="dim")
    else:
        block.append("\n")
        block.append("  signals: none were extracted; nothing scored either way", style="yellow")

    if verdict.confidence_criteria:
        block.append("\n")
        block.append(
            f"  confidence criteria (score {verdict.confidence_score:.4f} -- a transparency aid, not a probability):",
            style="bold",
        )
        _append_lines(
            block,
            [
                f"[{'x' if criterion.met else ' '}] {criterion.name}: {criterion.detail}"
                for criterion in verdict.confidence_criteria
            ],
            indent="    ",
            style="dim",
        )

    if verdict.overrides_applied:
        block.append("\n")
        block.append(f"  overrides applied ({len(verdict.overrides_applied)}):", style="bold")
        for override in verdict.overrides_applied:
            detail = f"tier {override.tier}, effect {override.effect}"
            if override.source_list:
                detail += f", list {override.source_list}"
            if override.source_retrieved_at:
                detail += f", retrieved {override.source_retrieved_at}"
            _append_lines(block, [f"{override.rule_id}: {detail}"], indent="    ", style="dim")
            if override.note:
                _append_lines(block, [override.note], indent="      ", style="dim")

    if verdict.rationale:
        block.append("\n")
        block.append("  rationale, in order:", style="bold")
        _append_lines(block, verdict.rationale, indent="    - ", style="dim")

    block.append("\n")
    block.append(
        f"  ruleset {verdict.ruleset_version} from {verdict.ruleset_source} • "
        f"engine {verdict.engine_version} • schema {verdict.schema_version} • "
        f"evaluated {verdict.evaluated_at_rfc3339}",
        style="dim",
    )
    return block


def render_verdict_unavailable(reason: Any = None) -> Text:
    """The banner for a verdict that could not be computed.

    Rendered instead of, never in addition to, silence. A missing verdict is a gap in the
    report; a report with no verdict line at all is one an analyst reads as unremarkable.
    """
    block = Text(_VERDICT_UNAVAILABLE, style="bold yellow")
    detail = str(reason).strip() if reason is not None else ""
    block.append("\n")
    block.append(
        f"  {detail}" if detail else "  the scoring engine did not produce a verdict for this indicator",
        style="yellow",
    )
    block.append("\n")
    block.append(
        "  nothing below has been adjudicated; absence of a verdict is not a clean verdict",
        style="yellow",
    )
    return block


def render_verdict(
    verdict: Any,
    *,
    explain: bool = False,
    show_calibration: bool = True,
) -> Optional[RenderableType]:
    """The answer, first, in words: verdict, confidence, coverage, and what justifies them.

    ``verdict`` takes a :class:`Verdict` or the dumped mapping the orchestrators publish on
    ``data['verdict']``. Returns ``None`` for ``None`` -- a caller with no verdict at all
    renders nothing here and says so elsewhere -- and the "not computed" banner for a payload
    that is present but unparseable.

    Section order is fixed and is the reading order under time pressure:

    1. the verdict word, with the score, the confidence band and the coverage ratio beside it,
       because "MALICIOUS at LOW confidence on 2 of 6 providers" is one fact, not three;
    2. the adjustments, each marked ``!`` -- these are the places the tool overruled its own
       arithmetic, and an analyst who disagrees needs to see them before the evidence;
    3. the two or three signals that justify the call, each with its own evidence sentence;
    4. contradictions and the analyst-review flag, which are the reason to stop and look;
    5. provenance -- collection mode, allowlist freshness, ruleset version, calibration.

    ``show_calibration`` exists for nested per-address panels under a domain report that has
    already printed the statement once. The statement itself is not optional anywhere: the
    engine makes no accuracy claim and the artefact has to say so on its face.
    """
    if verdict is None:
        return None
    parsed = verdict_from_payload(verdict)
    if parsed is None:
        return render_verdict_unavailable("the recorded verdict could not be read back")

    label = parsed.verdict.value
    style = _VERDICT_STYLES.get(label, _VERDICT_STYLE_UNKNOWN)

    block = _IndentedBlock(Text(f"VERDICT: {label}", style=style))
    block.append(
        f"   score {parsed.score} (raw {_fmt_points(parsed.raw_score)})"
        f"   confidence {parsed.confidence.value}"
        f"   {parsed.coverage.headline}",
        style=style,
    )

    # 2 -- where the tool overruled its own arithmetic.
    _append_lines(block, [f"! {reason}" for reason in parsed.adjustment_reasons], style="yellow")
    if parsed.coverage.missing:
        _append_lines(block, ["not answered: " + ", ".join(parsed.coverage.missing)], style="yellow")

    # 3 -- the evidence, ordered by contribution.
    top = parsed.top_signals(_TOP_SIGNALS)
    if top:
        block.add("why:", style="bold")
        _append_lines(block, [_signal_line(signal) for signal in top], indent="    - ")
        hidden = len(parsed.scored_signals) - len(top)
        if hidden > 0:
            _append_lines(
                block,
                [f"and {hidden} more scoring signal(s); run with --explain for the full breakdown"],
                indent="    ",
                style="dim",
            )
    elif parsed.affirmative_negatives:
        block.add("why:", style="bold")
        _append_lines(
            block,
            [signal.observation for signal in parsed.affirmative_negatives],
            indent="    - ",
        )

    # 4 -- the disagreements, never averaged away.
    if parsed.requires_analyst_review:
        block.add("ANALYST REVIEW REQUIRED", style="bold red")
    if parsed.contradictions:
        block.add(f"contradictions ({len(parsed.contradictions)}), reported and not reconciled:", style="bold")
        for contradiction in parsed.contradictions:
            _append_lines(block, [f"{contradiction.rule_id}: {contradiction.summary}"], indent="    - ")
            _append_lines(block, [f"what to do: {contradiction.analyst_hint}"], indent="      ", style="yellow")
    if parsed.attribution_warning:
        _append_lines(block, [f"attribution: {parsed.attribution_warning}"], style="yellow")

    # 5 -- provenance. A verdict whose ruleset and collection mode are unrecorded is a verdict
    # nobody can re-derive six months later, which is the whole point of stamping them.
    if parsed.passive_only:
        collection = "passive only - no traffic was sent to the target or its infrastructure"
    else:
        named = ", ".join(parsed.active_collection) or "unnamed active steps"
        collection = f"ACTIVE COLLECTION contributed: {named}"
    _append_lines(block, [f"collection: {collection}"], style="" if parsed.passive_only else "yellow")

    if parsed.allowlist is not None:
        provenance = (
            f"allowlist {parsed.allowlist.list_version} retrieved {parsed.allowlist.list_retrieved}"
            f" - {parsed.allowlist.staleness_note}"
        )
        _append_lines(block, [provenance], style="yellow" if parsed.allowlist.stale else "dim")

    _append_lines(
        block,
        [
            f"ruleset {parsed.ruleset_version} ({parsed.ruleset_source}) • engine {parsed.engine_version}"
            f" • evaluated {parsed.evaluated_at_rfc3339}"
        ],
        style="dim",
    )
    if show_calibration:
        _append_lines(block, [f"calibration: {parsed.calibration_statement}"], style="dim")

    if not explain:
        return block.renderable()
    return Group(block.renderable(), Text(""), render_verdict_explanation(parsed))


def _verdict_slot(data: Any, *, explain: bool, show_calibration: bool = True) -> Optional[RenderableType]:
    """The verdict renderable for a payload, including the honest failure case.

    Three states, and the third is the one that matters: a verdict was computed (render it), no
    verdict was attempted (render nothing -- this payload predates the engine or came from a
    caller that does not score), or the engine was asked and failed (say so loudly). Only the
    middle case is silent, and it is silent because a stub payload with no verdict key has made
    no claim either way.
    """
    if not isinstance(data, Mapping):
        return None
    if data.get("verdict") is not None:
        return render_verdict(data.get("verdict"), explain=explain, show_calibration=show_calibration)
    error = data.get("verdict_error")
    if error:
        return render_verdict_unavailable(error)
    return None


def _fmt_ports(ports: Iterable[int]) -> str:
    return ", ".join(str(p) for p in sorted({int(p) for p in ports if isinstance(p, int) or str(p).isdigit()}))


def _fmt_source(source: Any) -> Optional[str]:
    """Explain an address-provenance tag, or return ``None`` when there is nothing to say.

    An unrecognised tag is echoed verbatim rather than dropped or guessed at: a tag this
    renderer does not know about is still a fact the collector recorded, and inventing a gloss
    for it would be the same class of error as the hijack split this module stopped printing.
    """
    if source is None:
        return None
    text = str(source).strip()
    if not text:
        return None
    return _SOURCE_EXPLANATIONS.get(text, text)


def _fmt_source_cell(source: Any) -> Optional[str]:
    """The address-provenance cell: the gloss from ``_fmt_source``, coloured by strength.

    "Resolved now" and "seen historically by VirusTotal" are different evidentiary claims, so
    they must not look alike at a glance. Only recognised tags are styled -- an unknown tag is
    echoed plain, because colouring a tag this renderer cannot interpret would assert a
    strength it has not established.
    """
    line = _fmt_source(source)
    if line is None:
        return None
    style = _SOURCE_STYLES.get(str(source).strip())
    cell = esc(line)
    return f"[{style}]{cell}[/]" if style else cell


def _incident_count(value: Any) -> Optional[int]:
    """Read an incident count, mapping anything that is not a real count to ``None``.

    ``None`` means the provider did not report a total. Zero means it reported none. Collapsing
    the two -- which ``hj.get("total") or 0`` did -- is the defect this whole path exists to
    remove, so the coercion must never invent a zero. ``bool`` is excluded because ``True`` is
    an ``int`` to Python and is not an incident count to anyone else.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _fmt_coords(coords: Dict[str, Any] | None) -> str:
    if not coords:
        return ""
    lat = coords.get("lat")
    lon = coords.get("lon")
    if lat is None or lon is None:
        return ""
    return f"{lat}, {lon}"


#: What a missing timestamp renders as. Never blank, never a zero, never omitted.
#:
#: A score with no date beside it is the same failure this module exists to remove, one level
#: down: ``5/94`` from last week and ``5/94`` from 2019 support very different claims, and a
#: reader shown neither date will assume the first. The providers lane retained
#: ``vt_last_analysis_date_iso``, ``abuseipdb_last_reported_at`` and Shodan's ``last_update``
#: precisely so the qualifier could be printed; until now nothing printed them.
_UNKNOWN_DATE = "unknown - provider supplied no date"


def _fmt_timestamp(value: Any) -> str:
    """A provider's own timestamp string, or an explicit statement that there is none."""
    if value is None:
        return _UNKNOWN_DATE
    text = str(value).strip()
    return esc(text) if text else _UNKNOWN_DATE


def _fmt_detecting_engines(engines: Any, *, limit: int = 8) -> Optional[str]:
    """Name the engines that actually flagged the indicator, or ``None`` when none did.

    ``vt_detecting_engines`` is the compact, malicious-first derivation the providers lane
    added beside the ~94-entry ``vt_security_results`` map. A bare ``12/94`` does not say
    whether twelve no-name engines or twelve major vendors flagged the address, and those are
    not the same evidence.
    """
    if not isinstance(engines, (list, tuple)) or not engines:
        return None
    parts: List[str] = []
    for entry in engines[:limit]:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("engine") or "").strip()
        if not name:
            continue
        category = str(entry.get("category") or "").strip()
        result = str(entry.get("result") or "").strip()
        detail = " ".join(bit for bit in (category, f"({result})" if result else "") if bit)
        parts.append(esc(f"{name}: {detail}" if detail else name))
    if not parts:
        return None
    hidden = len(engines) - limit
    joined = "; ".join(parts)
    return f"{joined} ... and {hidden} more" if hidden > 0 else joined


def _fmt_str_list(values: Any, *, limit: int = 12, defang: bool = False) -> Optional[str]:
    """Join a provider's string list for display, or ``None`` when it is empty.

    ``defang`` is for lists whose every entry is an indicator -- Shodan's hostnames -- and is
    off for lists that are not, such as CVE identifiers.
    """
    if not isinstance(values, (list, tuple)) or not values:
        return None
    items = [str(v).strip() for v in values if str(v).strip()]
    if not items:
        return None
    shown = items[:limit]
    joined = ", ".join(indicator_text(v, defang=defang) for v in shown)
    hidden = len(items) - len(shown)
    return f"{joined} ... and {hidden} more" if hidden > 0 else joined


def render_ip_analysis(
    ip: str,
    data: Dict[str, Any],
    *,
    ports_limit: str = "25",
    run_id: Any = None,
    generated_at: Any = None,
    show_run_line: bool = True,
    explain: bool = False,
    defang: bool = False,
) -> RenderableType:
    """Render one IP analysis block: header, verdict, coverage, then the field table.

    ``data`` is the mapping ``orchestrators.investigate_ip`` builds, or one element of
    ``investigate_domain``'s ``data['ips']``. Both carry ``provider_status``, which is what
    drives every "did not answer" cell below -- the renderer no longer infers a provider's fate
    from an empty payload, because ``{}`` means "never asked" and "asked, found nothing"
    equally and only one of those is evidence.

    **Row order is part of the output, not an accident of when each block was written.** The
    adjudicated evidence -- VirusTotal, AbuseIPDB, OTX, Shodan -- comes first, then network
    identity, and geolocation goes last. A city and a postal code almost never decide an
    escalation, and printing them two rows above the detection count taught the eye that the
    two carry the same weight.

    ``show_run_line=False`` suppresses the version/timestamp/run-id line for blocks nested
    under a report that has already printed one, and suppresses the calibration sentence for
    the same reason; the coverage line and the verdict are never suppressible.

    ``explain=True`` appends the full signal breakdown -- every weight, its ruleset key and the
    provider values behind it -- under the verdict banner.

    ``defang=True`` brackets the address wherever this block states it as the indicator (the
    title, the ``ip`` row, Shodan's hostnames). The pivot links are untouched and stay
    clickable, which is the whole reason defanging is a per-field transform here rather than a
    pass over the finished text -- see the module's defanging section. It defaults to ``False``
    so that a direct caller gets literal output; ``cli.py`` turns it on unless ``--fanged``.
    """
    vt = data.get("virustotal", {})
    vt_stats = vt.get("vt_last_analysis_stats", {})
    vt_reputation = vt.get("vt_reputation")
    vt_link = vt.get("vt_link")
    shodan = data.get("shodan", {})
    ports = shodan.get("ports", []) if isinstance(shodan, dict) else []
    abuse = data.get("abuseipdb", {})
    ipinfo = data.get("ipinfo", {})
    asn_meta = data.get("asn_meta", {})
    otx = data.get("otx", {})
    provider_status = data.get("provider_status")

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold cyan")
    table.add_column("Value", style="none")

    table.add_row("ip", indicator_text(ip, defang=defang))

    # Provenance, when the caller recorded one. The `ip` subcommand does not: the operator typed
    # the address, so there is no resolution claim to qualify. The domain path always does.
    source_cell = _fmt_source_cell(data.get("source"))
    if source_cell:
        table.add_row("address_source", source_cell)

    # Absence is not safety. When VirusTotal was never asked, or answered with an error, there
    # are no stats to sum -- rendering the resulting 0/0 in green makes an unset API key look
    # identical to a clean verdict. Say "no data" instead.
    malicious = int(vt_stats.get("malicious", 0) or 0) if isinstance(vt_stats, dict) else 0
    total_engines = 0
    if isinstance(vt_stats, dict):
        try:
            total_engines = sum(int(v or 0) for v in vt_stats.values())
        except Exception:
            total_engines = 0

    if total_engines <= 0:
        table.add_row("virustotal_detections", _no_data_cell(provider_outcome(provider_status, "virustotal")))
    else:
        vt_color = "red" if malicious > 0 else "green"
        table.add_row("virustotal_detections", f"[{vt_color}]{malicious}/{total_engines}[/]")
        # The score's own freshness, immediately beside it. Only rendered when there is a score
        # to qualify -- an unasked provider already says "no data" above and does not need a
        # second row saying its date is unknown too.
        table.add_row("virustotal_last_analysis", _fmt_timestamp(vt.get("vt_last_analysis_date_iso")))
        detecting = _fmt_detecting_engines(vt.get("vt_detecting_engines"))
        if detecting:
            table.add_row("virustotal_detecting_engines", detecting)

    if vt_reputation is not None:
        table.add_row("virustotal_community_score", esc(vt_reputation))
    if vt_link:
        table.add_row("virustotal_analysis_link", esc(vt_link))

    # AbuseIPDB's confidence score is the row most likely to be read as a verdict, so it is the
    # row least allowed to invent one. Pre-fix, a payload without a usable score fell through
    # `int(conf_val)`'s except-branch to a green `0%` -- a provider that never answered rendered
    # identically to a provider that answered "nobody has ever reported this address".
    abuse_outcome = provider_outcome(provider_status, "abuseipdb")
    abuse_data = abuse if isinstance(abuse, dict) else {}
    confidence = _confidence_score(abuse_data.get("abuseipdb_confidence_score"))
    reports = abuse_data.get("abuseipdb_reports")
    abuse_answered = abuse_outcome is None or _answered(abuse_outcome)

    if abuse_answered and confidence is not None:
        if reports is not None:
            table.add_row("abuseipdb_reports", esc(reports))
        distinct = abuse_data.get("abuseipdb_num_distinct_users")
        if distinct is not None:
            # 200 reports from one reporter is not 200 observations, and the confidence score
            # alone cannot tell the analyst which of the two they are looking at.
            table.add_row("abuseipdb_distinct_reporters", esc(distinct))
        ab_color = "red" if confidence > 0 else "green"
        table.add_row("abuseipdb_confidence_score", f"[{ab_color}]{confidence}%[/]")
        table.add_row("abuseipdb_last_reported", _fmt_timestamp(abuse_data.get("abuseipdb_last_reported_at")))
        if abuse_data.get("abuseipdb_is_whitelisted") is True:
            table.add_row("abuseipdb_whitelisted", "yes - AbuseIPDB lists this address as whitelisted")
    else:
        if abuse_answered and reports is not None:
            table.add_row("abuseipdb_reports", esc(reports))
        table.add_row("abuseipdb_confidence_score", _no_data_cell(abuse_outcome))

    table.add_row("abuseipdb_analysis_link", f"https://www.abuseipdb.com/check/{ip}")

    otx_outcome = provider_outcome(provider_status, "otx")
    if otx:
        try:
            pulse_count = int(otx.get("otx_pulse_count", 0) or 0)
        except Exception:
            pulse_count = 0
        table.add_row("otx_pulse_count", esc(pulse_count))
        table.add_row("otx_pulse_link", f"https://otx.alienvault.com/indicator/ip/{ip}")
        titles = otx.get("otx_pulse_titles") or []
        if isinstance(titles, list) and titles:
            joined = "; ".join(esc(t) for t in titles[:5] if t)
            if joined:
                table.add_row("otx_pulse_titles", joined)
    else:
        # Zero pulses and no OTX answer are not the same statement, and the old renderer made
        # the second one invisible: it dropped the count row and printed the pivot link, which
        # reads as "OTX had nothing on this".
        table.add_row("otx_pulse_count", _no_data_cell(otx_outcome))
        table.add_row("otx_pulse_link", f"https://otx.alienvault.com/indicator/ip/{ip}")

    shodan_outcome = provider_outcome(provider_status, "shodan")
    shodan_answered = _answered(shodan_outcome) or (shodan_outcome is None and bool(shodan))
    shodan_data = shodan if isinstance(shodan, dict) else {}

    if ports:
        ports_sorted = sorted({int(p) for p in ports if isinstance(p, int) or str(p).isdigit()})
        if str(ports_limit).lower() == "all":
            max_show = len(ports_sorted)
        else:
            try:
                limit = int(ports_limit)
                max_show = limit if limit > 0 else 25
            except (ValueError, TypeError):
                max_show = 25
        shown = ports_sorted[:max_show]
        more = len(ports_sorted) - len(shown)
        ports_str = ", ".join(str(p) for p in shown)
        if more > 0:
            ports_str += f" ... and {more} more"
        table.add_row("open_ports", ports_str)
    elif shodan_answered:
        # An empty port list from a Shodan that answered is a finding ("none exposed on the
        # ports Shodan indexes"). An empty port list because Shodan was never asked is not.
        table.add_row("open_ports", "none reported by Shodan")
    else:
        table.add_row("open_ports", _no_data_cell(shodan_outcome))

    if shodan_answered:
        # The date qualifies everything else Shodan supplied: the ports, the CPEs and the CVEs
        # are all "as of" this observation, and a two-year-old banner read as current state is
        # how an analyst reports a service that was decommissioned last spring.
        table.add_row("shodan_last_update", _fmt_timestamp(shodan_data.get("last_update")))
        vulns = _fmt_str_list(shodan_data.get("vulns"))
        if vulns:
            table.add_row("shodan_vulns", f"[red]{vulns}[/]")
        hostnames = _fmt_str_list(shodan_data.get("hostnames"), defang=defang)
        if hostnames:
            table.add_row("shodan_hostnames", hostnames)

    table.add_row("shodan_link", f"https://www.shodan.io/host/{ip}")

    # Network identity: who announces this address. Below the evidence, above the map.
    isp_line = None
    asn_id = asn_meta.get("asn")
    asn_name = asn_meta.get("name")
    if asn_id and asn_name:
        isp_line = f"AS{asn_id} {asn_name}"
    elif ipinfo.get("org"):
        isp_line = ipinfo.get("org")
    if isp_line:
        table.add_row("isp", esc(isp_line))

    # Cloudflare Radar's GraphQL asks for `organization { name }`, so this value is a DICT
    # whenever a Cloudflare token is configured -- rendering it raw put a Python dict repr
    # (`{'name': 'Google LLC'}`) in front of the analyst. render_asn_header already unwrapped it;
    # this path did not.
    org = asn_meta.get("organization") or ipinfo.get("org")
    org_name = org.get("name") if isinstance(org, dict) else org
    if org_name:
        table.add_row("organization", esc(org_name))

    table.add_row("cloudflare_radar_link", f"https://radar.cloudflare.com/ip/{ip}")

    # Below the fold. Geolocation is IPinfo's guess about where a registry says an address
    # lives; it is context for a report and it is almost never what decides an escalation.
    city = ipinfo.get("city")
    country = ipinfo.get("country")
    coords = _fmt_coords(ipinfo.get("coordinates"))
    postal = ipinfo.get("postal")
    if city or country or coords or postal:
        table.add_row("geolocation", "[dim]IPinfo registry data - context, not evidence[/]")
    if city:
        table.add_row("city", esc(city))
    if country:
        table.add_row("country", esc(country))
    if coords:
        table.add_row("coordinates", esc(coords))
    if postal:
        table.add_row("postal_code", esc(postal))

    errors = data.get("errors") or {}
    if errors:
        error_table = Table(show_header=False, box=None, padding=(0, 2))
        error_table.add_column("Provider", style="bold red")
        error_table.add_column("Error")
        for name, detail in errors.items():
            if not isinstance(detail, dict):
                error_table.add_row(esc(name), esc(detail))
                continue
            parts: List[str] = []
            status = detail.get("status_code") or detail.get("status")
            if status is not None:
                parts.append(f"status={esc(status)}")
            reason = detail.get("reason")
            if reason:
                parts.append(f"reason={esc(reason)}")
            message = detail.get("message")
            if message:
                parts.append(f"message={esc(message)}")
            url = detail.get("url")
            if url:
                parts.append(f"url={esc(url)}")
            body = detail.get("body")
            if body:
                parts.append(f"body={esc(body)}")
            joined = " | ".join(parts) if parts else "error"
            error_table.add_row(esc(name), joined)
        table.add_row("provider_errors", error_table)

    # The orchestrator publishes run metadata, coverage and warnings onto `data` precisely
    # because the console renderers are handed `result.data` and nothing else. Prefer them:
    # recomputing coverage here would let the screen and the JSON export of the same run
    # disagree, and the published object knows which providers were expected and never
    # attempted, which a raw status map cannot show.
    published_run_id, published_started_at, published_version = run_fields(data.get("run"))
    header = render_run_header(
        f"--- IP lookup for {defang_indicator(ip) if defang else ip} ---",
        run_id=run_id if run_id is not None else (published_run_id or data.get("run_id")),
        generated_at=(generated_at if generated_at is not None else (published_started_at or data.get("generated_at"))),
        version=published_version,
        show_run_line=show_run_line,
    )
    notices = [n for n in (render_warnings(_warnings_beyond_coverage(data.get("warnings"))),) if n is not None]
    return compose_report(
        header,
        [table, Text("")],
        # The calibration sentence rides with the run line: a nested per-address panel sits
        # under a domain report that has already stated it once, and repeating three sentences
        # of caveat per address is how a reader learns to skip the caveat.
        verdict=_verdict_slot(data, explain=explain, show_calibration=show_run_line),
        coverage=render_coverage(data.get("coverage") or provider_status),
        notices=notices,
    )


def render_domain_header(
    domain: str,
    *,
    coverage: Any = None,
    coverage_label: str = "domain_provider_coverage",
    warnings: Any = None,
    skipped_ips: Any = None,
    run_id: Any = None,
    generated_at: Any = None,
    version: Optional[str] = None,
    show_run_line: bool = True,
    verdict: Any = None,
    verdict_error: Any = None,
    explain: bool = False,
    defang: bool = False,
) -> RenderableType:
    """The domain report's opening block: run provenance, verdict, coverage, warnings, skips.

    ``verdict`` is the **domain's own** verdict, never a merge of its addresses'. A phishing kit
    on a CDN is a malicious domain on a shared address and both statements are true at once;
    merging them would either indict every other tenant behind that address or clear the
    phishing kit. Each address carries its own verdict on its own panel.

    ``verdict_error`` is the honest alternative when the engine could not produce one: it
    renders the "not computed" banner instead of nothing, because a domain report with no
    verdict line reads as a domain report with nothing to report.

    Feed it ``result.data['coverage']`` (or ``result.data['domain_provider_status']``),
    ``result.warnings`` and ``result.data.get('skipped_ips')``. Each IP panel below carries its
    own coverage figure too, because a domain lookup with VirusTotal configured and Shodan
    absent has a different gap at each level.

    ``coverage_label`` names the scope of whatever was passed. ``cli.py`` passes the whole-run
    ``data['coverage']`` -- the same object the JSON export carries, namespaced ``domain:`` and
    ``<address>:`` -- and relabels it ``provider_coverage`` accordingly. Getting this wrong is
    not cosmetic: ``_warnings_beyond_coverage`` suppresses the ``partial coverage:`` warning on
    the assumption that the coverage line above already states that ratio, so a header showing
    a *narrower* coverage figure than the warnings were computed from would delete the
    whole-run ratio from the screen instead of duplicating it.

    The skipped-address block rides in the header on purpose: those addresses are the ones the
    analyst would otherwise never learn about, and a reader who stops after the first screen
    must still have seen them.
    """
    header = render_run_header(
        f"--- Domain lookup for {defang_indicator(domain) if defang else domain} ---",
        run_id=run_id,
        generated_at=generated_at,
        version=version,
        show_run_line=show_run_line,
    )
    notices = [
        n
        for n in (
            render_warnings(_warnings_beyond_coverage(warnings, skipped=skipped_ips)),
            render_skipped_ips(skipped_ips, defang=defang),
        )
        if n is not None
    ]
    return compose_report(
        header,
        [Text("")],
        verdict=_verdict_slot({"verdict": verdict, "verdict_error": verdict_error}, explain=explain),
        coverage=render_coverage(coverage, label=coverage_label),
        notices=notices,
    )


def render_asn_header(
    asn: int,
    meta: Dict[str, Any],
    use_color: bool = False,
    *,
    coverage: Any = None,
    warnings: Any = None,
    run_id: Any = None,
    generated_at: Any = None,
    version: Optional[str] = None,
    show_run_line: bool = True,
) -> RenderableType:
    """Render the ASN identity block, headed by run provenance and coverage.

    ``coverage`` takes ``result.data['coverage']`` (preferred) or a raw ``provider_status``
    map, and ``warnings`` takes ``result.warnings``. Both are optional so this stays callable
    from anywhere, but omitting ``coverage`` renders coverage as *unknown* rather than as
    nothing: an ASN panel assembled from four of ten providers looks
    exactly like one assembled from ten, and the analyst has no other way to tell.
    """
    org = meta.get("organization")
    org_name = org.get("name") if isinstance(org, dict) else org
    # IPInfo returns `org` as a plain string, so this must not assume a dict -- doing so raised
    # AttributeError whenever nothing else supplied a name.
    name = meta.get("name") or org_name or ""
    rir = meta.get("rir")
    rir_desc_map = {
        "ARIN": "ARIN (USA, Canada, many Caribbean and North Atlantic islands)",
        "RIPE": "RIPE NCC (Europe, Middle East, parts of Central Asia)",
        "APNIC": "APNIC (Asia Pacific)",
        "LACNIC": "LACNIC (Latin America and parts of Caribbean)",
        "AFRINIC": "AFRINIC (Africa)",
    }
    rir_line = rir_desc_map.get(rir.upper(), rir) if isinstance(rir, str) and rir else None

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold cyan")
    table.add_column("Arrow", style="none")
    table.add_column("Value", style="none")

    table.add_row("AS Number", "──>", str(asn))
    if name:
        table.add_row("AS Name", "──>", esc(name))
    if org_name:
        table.add_row("Organization", "──>", esc(org_name))
    if meta.get("caidaRank"):
        table.add_row("CAIDA AS Rank", "──>", f"#{esc(meta.get('caidaRank'))}")
    if meta.get("abuseContacts"):
        table.add_row("Abuse contact", "──>", esc(meta["abuseContacts"][0]))
    alloc = meta.get("allocationDate") or meta.get("allocated") or meta.get("allocation")
    if alloc:
        table.add_row("AS Reg. date", "──>", esc(alloc))
    if rir_line:
        table.add_row("RIR (Region)", "──>", esc(rir_line))

    ixps = meta.get("ixps") or []
    if isinstance(ixps, list) and ixps:
        ixp_names = [i.get("name") for i in ixps if isinstance(i, dict) and i.get("name")]
        if ixp_names:
            table.add_row("Peering @IXPs", "──>", " • ".join(esc(n) for n in ixp_names))
    else:
        table.add_row("Peering @IXPs", "──>", "NONE")

    title_str = f"--- ASN lookup for AS{asn} ({name}) ---" if name else f"--- ASN lookup for AS{asn} ---"
    header = render_run_header(
        title_str, run_id=run_id, generated_at=generated_at, version=version, show_run_line=show_run_line
    )
    notices = [n for n in (render_warnings(_warnings_beyond_coverage(warnings)),) if n is not None]
    return compose_report(
        header,
        [table, Text("")],
        coverage=render_coverage(coverage),
        notices=notices,
    )


def _join_asns(asns: Sequence[Any] | None, limit: int = 60, *, total: Optional[int] = None) -> str:
    """Join a peer list, reporting how many peers are not on screen.

    ``total`` is the size of the *unabridged* list. Without it the count came from the list
    that had already been truncated upstream -- ``orchestrators`` cuts ``ripe_*_named`` to
    ``--neighbors N`` before the renderer ever sees it -- so ``len(asns) - len(shown)`` was
    always zero and the "and N more" marker never fired. An analyst reading eight upstreams had
    no way to know there were two hundred.

    Entries are escaped: with ``--neighbors`` the list holds RIPE holder names, which are
    third-party strings on the same footing as an OTX pulse title.
    """
    if not asns:
        return "NONE"
    shown = [esc(x) for x in asns[:limit]]
    more = max(total if total is not None else len(asns), len(asns)) - len(shown)
    s = "  ".join(shown)
    if more > 0:
        s += f"\nand {more} more"
    return s


def _peer_list(bgp: Dict[str, Any], named_key: str, asns_key: str) -> Tuple[Sequence[Any], int]:
    """Return the peer list to display and the size of the unabridged list behind it.

    Prefers the resolved-name list when the operator asked for names, and always reports the
    raw ASN list's length as the total, because that is the list the display is an excerpt of.
    """
    named = bgp.get(named_key) if isinstance(bgp, dict) else None
    raw = bgp.get(asns_key) if isinstance(bgp, dict) else None
    named_list: Sequence[Any] = named if isinstance(named, (list, tuple)) else []
    raw_list: Sequence[Any] = raw if isinstance(raw, (list, tuple)) else []
    shown = named_list or raw_list
    return shown, max(len(raw_list), len(shown))


def _hijack_line(hj: Dict[str, Any]) -> str:
    """Render the BGP hijack envelope from ``providers.cloudflare_rest.bgp_incidents``.

    This function used to manufacture an attribution claim. It read a page-1 hijacker count,
    subtracted it from an all-pages total, called the remainder the victim count, and printed
    the result as the sentence "always as a victim" -- into a report an analyst pastes into a
    ticket. The provider module now refuses to supply a split it cannot substantiate, and this
    renderer's job is to say so out loud instead of filling the gap.

    Three rules follow, and each one is the inverse of a bug that shipped:

    * ``None`` is not zero. ``total_incidents``, ``as_hijacker`` and ``as_victim`` are each
      ``int | None``; ``None`` means unknown, ``0`` means counted and found none. No ``or 0``.
    * The victim figure is never recomputed here. ``total_incidents - as_hijacker`` is exactly
      the arithmetic that was removed upstream and it must not come back downstream.
    * The prose forms ("always as a victim", "always as a hijacker") assert that one role
      accounts for every incident. That is only true over a complete enumeration, so they are
      reachable only when the provider module reports ``split_available``.
    """
    total = _incident_count(hj.get("total_incidents"))
    if total is None:
        return "unavailable (Cloudflare reported no total)"
    if total == 0:
        return "None"

    base = f"Involved in {total} incident{'' if total == 1 else 's'}"

    if hj.get("split_available") is True:
        as_hijacker = _incident_count(hj.get("as_hijacker"))
        as_victim = _incident_count(hj.get("as_victim"))
        # split_available is the provider's assertion that both counts exist. Verify rather
        # than trust: a hand-edited or cached envelope could claim the split and omit a number,
        # and printing "None as hijacker" is precisely the affirmative-looking nonsense this
        # rewrite removes.
        if as_hijacker is None or as_victim is None:
            return f"{base} (role split unavailable: split_available set without both counts)"
        if as_hijacker == 0:
            return f"{base} (always as a victim)"
        if as_victim == 0:
            return f"{base} (always as a hijacker)"
        return f"{base} ({as_hijacker} as hijacker • {as_victim} as victim)"

    reason = hj.get("split_unavailable_reason") or "unspecified"
    examined = _incident_count(hj.get("events_examined"))
    examined_text = "an unreported number of" if examined is None else str(examined)
    return f"{base} (role split unavailable: {esc(reason)}; {examined_text} of {total} incidents examined)"


def render_asn_bgp_panels(
    asn: int, meta: Dict[str, Any], bgp: Dict[str, Any], use_color: bool = False
) -> RenderableType:
    panels: List[RenderableType] = []

    # Panel 1: BGP informations
    t1 = Table(show_header=False, box=None, padding=(0, 2))
    t1.add_column("Key", style="bold cyan")
    t1.add_column("Value")
    total = meta.get("degree_total")
    prov = meta.get("degree_provider")
    peer = meta.get("degree_peer")
    cust = meta.get("degree_customer")
    if total is not None:
        t1.add_row("BGP Neighbors", f"{total} ({prov or 0} Transits • {peer or 0} Peers • {cust or 0} Customers)")
    cone = meta.get("customer_cone_asns")
    if cone is not None:
        t1.add_row("Customer cone", f"{cone} (# of ASNs observed in the customer cone)")

    hj = bgp.get("hijacks", {}) if isinstance(bgp, dict) else {}
    leaks = bgp.get("leaks", {}) if isinstance(bgp, dict) else {}
    if isinstance(hj, dict) and hj:
        t1.add_row("BGP Hijacks (past 1y)", _hijack_line(hj))
    if isinstance(leaks, dict) and leaks:
        total_l = _incident_count(leaks.get("total_incidents"))
        if total_l is None:
            leak_text = "unavailable (Cloudflare reported no total)"
        elif total_l == 0:
            leak_text = "None"
        else:
            leak_text = str(total_l)
        t1.add_row("BGP Route leaks (past 1y)", leak_text)
    t1.add_row("In-depth BGP info", f"https://radar.cloudflare.com/routing/as{asn}?dateRange=52w")
    panels.append(Text(f"--- BGP informations for AS{asn} ---", style="bold cyan"))
    panels.append(t1)
    panels.append(Text(""))

    # Panel 2: Prefix informations
    t2 = Table(show_header=False, box=None, padding=(0, 2))
    v4c = bgp.get("ripe_announced_prefixes_v4")
    v6c = bgp.get("ripe_announced_prefixes_v6")
    if v4c is not None:
        t2.add_row("IPv4 Prefixes announced", str(v4c))
    if v6c is not None:
        t2.add_row("IPv6 Prefixes announced", str(v6c))
    if v4c is not None or v6c is not None:
        panels.append(Text(f"--- Prefix informations for AS{asn} ---", style="bold cyan"))
        panels.append(t2)
        panels.append(Text(""))

    # Panel 3: Peering informations
    #
    # `ripe_*_named` is already cut to `--neighbors N` by the orchestrator, while
    # `ripe_*_asns` holds the full list from RIPEstat. The unabridged length has to travel with
    # the shortened list or the "and N more" marker can never fire -- which is exactly what it
    # did before: eight named upstreams out of two hundred rendered as eight upstreams.
    up, up_total = _peer_list(bgp, "ripe_upstream_named", "ripe_upstream_asns")
    dn, dn_total = _peer_list(bgp, "ripe_downstream_named", "ripe_downstream_asns")
    un, un_total = _peer_list(bgp, "ripe_uncertain_named", "ripe_uncertain_asns")
    t3 = Table(show_header=False, box=None, padding=(0, 2))
    t3.add_column("Category", style="bold green")
    t3.add_column("Peers")
    t3.add_row("Upstream", _join_asns(up, total=up_total))
    t3.add_row("Downstream", _join_asns(dn, total=dn_total))
    t3.add_row("Uncertain", _join_asns(un, total=un_total))
    panels.append(Text(f"--- Peering informations for AS{asn} ---", style="bold cyan"))
    panels.append(t3)
    panels.append(Text(""))

    # Panel 4: Aggregated IP resources
    v4_list = bgp.get("ripe_prefixes_v4") or []
    v6_list = bgp.get("ripe_prefixes_v6") or []
    if v4_list or v6_list:
        t4 = Table(show_header=False, box=None, padding=(0, 2))
        t4.add_column("Protocol", style="bold yellow")
        t4.add_column("Prefixes")

        v4_str = "NONE"
        if v4_list:
            v4_str = "\n".join(esc(p) for p in v4_list[:50])
            if len(v4_list) > 50:
                v4_str += f"\n… and {len(v4_list) - 50} more"
        t4.add_row("IPv4", v4_str)

        v6_str = "NONE"
        if v6_list:
            v6_str = "\n".join(esc(p) for p in v6_list[:50])
            if len(v6_list) > 50:
                v6_str += f"\n… and {len(v6_list) - 50} more"
        t4.add_row("IPv6", v6_str)
        panels.append(Text(f"--- Aggregated IP resources for AS{asn} ---", style="bold cyan"))
        panels.append(t4)
        panels.append(Text(""))

    return Group(*panels)


# --------------------------------------------------------------------------------------
# URL (roadmap 6.8) and indicator triage (6.9, 6.10)
#
# The rule that shapes every renderer below: a URL report must never let a reader infer that
# the tool followed the link. `redirect_chain` therefore always states its resolution word
# first -- "NOT RESOLVED" or "FROM PASSIVE RECORD (<provider>:<field>, observed <date>)" -- and
# a chain that came from somebody else's scan is printed with that party's name and the date
# they saw it attached, because a cached chain is a claim about the past. A redirector that
# served a kit last month may serve a parked page today, and the date is the only thing on
# screen that lets a reader tell which claim they are holding.
# --------------------------------------------------------------------------------------

#: What the report says about the registrable domain, per ``utils.urls.RegistrableDomainStatus``.
#:
#: Spelled out rather than left blank, because a blank reads as "the tool checked and there is
#: no registrable domain". ``utils.urls`` never guesses an eTLD+1: a last-two-labels rule is
#: right on ``a.evil.com`` and silently wrong on ``evil.co.uk``, and a wrong one pivots the
#: whole investigation onto the wrong entity while looking exactly as confident as a right one.
#: The four not-derived states are worded separately because "no list is vendored" is a gap in
#: this tool and "the host is an IP literal" is not a gap at all.
_REGISTRABLE_DOMAIN_STATUS: Dict[str, str] = {
    "unavailable_no_public_suffix_list": "not derived - no public suffix list is vendored, so pivot on the full host",
    "not_applicable_ip_literal": "not applicable - the host is an IP literal, so there is no domain to pivot on",
    "not_applicable_single_label": "not applicable - the host is a single label",
    "not_applicable_no_host": "not applicable - there is no host",
}
_REGISTRABLE_DOMAIN_UNKNOWN = "not derived - the parser reported no status"

#: The row for a URL VirusTotal holds no report on. Never "0/0", never green, and deliberately
#: distinct from "the query failed": no report means nobody ever submitted the link, which is
#: the ordinary state of one that went live an hour ago and is not exculpatory.
_NO_VT_URL_REPORT = "no report exists - nobody has submitted this URL to VirusTotal; UNKNOWN, not clean"

#: Said beside a URL whose scheme this tool supplied. The assumption is not cosmetic: it changes
#: the VirusTotal URL identifier, and therefore whether a report is found at all.
_SCHEME_ASSUMED_NOTE = "assumed by this tool - it was NOT in the input, and it changes which report is looked up"

#: Said beside a URL carrying embedded credentials, which are a routine phishing disguise.
_USERINFO_NOTE = "credentials embedded before the @ - a display trick as often as a real login"


def _collection_line(collection: Any) -> str:
    """How the evidence was gathered, in the words the verdict block uses."""
    if not isinstance(collection, Mapping):
        return "not recorded"
    if collection.get("passive_only", True):
        return "passive only - no traffic was sent to the target or its infrastructure"
    steps = collection.get("active_steps") or []
    named = ", ".join(str(step) for step in steps if str(step).strip()) or "unnamed active steps"
    return f"ACTIVE COLLECTION contributed: {named}"


def render_url_anomalies(anomalies: Any) -> Optional[RenderableType]:
    """The parser's observations about the URL string itself.

    These are signals, never a verdict. Several are individually unremarkable -- plenty of
    benign sites use IDN -- and the interesting thing is the combination, which is why they are
    listed for a reader to weigh rather than folded into a score the ruleset cannot yet justify.
    """
    if not isinstance(anomalies, (list, tuple)) or not anomalies:
        return None
    block = Text(
        f"url_anomalies ({len(anomalies)}), observations about the string, not a verdict:", style="bold yellow"
    )
    for anomaly in anomalies:
        if isinstance(anomaly, Mapping):
            code = str(anomaly.get("code") or "")
            component = str(anomaly.get("component") or "")
            detail = str(anomaly.get("detail") or "")
            line = f"  - {code} ({component}): {detail}" if component else f"  - {code}: {detail}"
        else:
            line = f"  - {anomaly}"
        block.append("\n")
        block.append(line, style="yellow")
    return block


def _redirect_chain_text(chain: Any, *, defang: bool) -> str:
    """The redirect-chain line, with every hop defanged when the rest of the report is.

    ``RedirectChain.render`` owns the wording -- the resolution word first, then the source and
    the observation date -- and this function does not second-guess it. What it does is defang
    the hop URLs *inside* that wording.

    That was missing, and it mattered more here than anywhere else on the page. Every other
    indicator field goes through ``indicator_text``, so a URL report pasted into a ticket or a
    chat window carries ``hxxps[://]evil[.]example`` and nothing in it is clickable. The
    redirect chain went out live -- and the two URLs in a redirect chain are the landing page
    and the kit, which is to say the two most dangerous strings in the whole report. One
    hyperlink-happy chat client turns a passive investigation into a visit.

    Hops are substituted longest-first: a chain frequently contains one URL that is a prefix of
    the next, and replacing the shorter one first would corrupt the longer.
    """
    if not isinstance(chain, Mapping):
        return "NOT RESOLVED"
    rendered = str(chain.get("rendered") or "") or "NOT RESOLVED"
    if not defang:
        return rendered

    hops = chain.get("hops")
    urls = [str(hop) for hop in hops if str(hop)] if isinstance(hops, (list, tuple)) else []
    final_url = chain.get("final_url")
    if isinstance(final_url, str) and final_url:
        urls.append(final_url)

    for url in sorted(set(urls), key=len, reverse=True):
        rendered = rendered.replace(url, defang_indicator(url))
    return rendered


def render_url_analysis(
    data: Dict[str, Any],
    *,
    explain: bool = False,
    defang: bool = True,
    show_run_line: bool = True,
) -> RenderableType:
    """Render the URL-level block of a URL investigation.

    ``data`` is what ``orchestrators.investigate_url`` returns. This renders the URL scope only;
    the host's own verdict and each address's panel are separate blocks, printed by ``cli.py``
    below this one, because a phishing page on a compromised site is a malicious URL on a host
    that is itself a victim and merging the two loses one of those facts.

    ``defang`` defaults to ``True`` here, unlike the older renderers. A URL is the indicator most
    likely to be clicked out of a pasted report, and this renderer is new, so there is no
    caller relying on literal output.
    """
    display = data.get("url_display") or data.get("url") or ""
    provider_status = data.get("url_provider_status")
    intel = data.get("url_intel") if isinstance(data.get("url_intel"), Mapping) else {}
    vt = intel.get("virustotal") if isinstance(intel, Mapping) else None
    vt_data: Dict[str, Any] = vt if isinstance(vt, dict) else {}

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold cyan")
    table.add_column("Value", style="none")

    table.add_row("url", indicator_text(display, defang=defang))
    if data.get("url_raw") and str(data.get("url_raw")) != str(data.get("url")):
        # The analyst's string exactly as pasted. A tool that silently rewrites its input
        # produces output that cannot be defended in a case write-up.
        table.add_row("url_as_pasted", esc(data.get("url_raw")))

    scheme = str(data.get("scheme") or "")
    if scheme:
        suffix = f"  [yellow]{_SCHEME_ASSUMED_NOTE}[/]" if data.get("scheme_assumed") else ""
        table.add_row("scheme", f"{esc(scheme)}{suffix}")

    table.add_row("host", indicator_text(data.get("host"), defang=defang))
    if data.get("host_kind"):
        table.add_row("host_kind", esc(data.get("host_kind")))
    if data.get("host_ascii") and data.get("host_ascii") != data.get("host"):
        # The two forms of the same host disagree, so the label a resolver sees is not the
        # label a human reads. That is the homograph case and it belongs on screen.
        table.add_row("host_ascii", indicator_text(data.get("host_ascii"), defang=defang))
    if data.get("port") is not None:
        table.add_row("port", esc(data.get("port")))

    registrable = data.get("registrable_domain")
    if registrable:
        table.add_row("registrable_domain", indicator_text(registrable, defang=defang))
    else:
        status = str(data.get("registrable_domain_status") or "")
        table.add_row(
            "registrable_domain",
            f"[yellow]{esc(_REGISTRABLE_DOMAIN_STATUS.get(status, _REGISTRABLE_DOMAIN_UNKNOWN))}[/]",
        )
    table.add_row("pivot_host", indicator_text(data.get("pivot_host") or data.get("host"), defang=defang))

    if data.get("path"):
        table.add_row("path", esc(data.get("path")))
    if data.get("query"):
        table.add_row("query", esc(data.get("query")))
    if data.get("userinfo_present"):
        table.add_row("userinfo", f"[yellow]{_USERINFO_NOTE}[/]")

    chain = data.get("redirect_chain")
    chain_text = esc(_redirect_chain_text(chain, defang=defang))
    resolved = bool(chain.get("resolution") == "FROM PASSIVE RECORD") if isinstance(chain, Mapping) else False
    table.add_row("redirect_chain", chain_text if resolved else f"[yellow]{chain_text}[/]")

    # VirusTotal's URL report. Absence is stated, never rendered as a zero: a URL with no report
    # has not been scanned by zero engines, it has not been scanned, and that is the ordinary
    # state of a link that went live an hour ago.
    stats = vt_data.get("vt_last_analysis_stats")
    total = sum(int(v or 0) for v in stats.values() if str(v).isdigit()) if isinstance(stats, dict) else 0
    if total <= 0:
        cell = (
            f"[yellow]{esc(_NO_VT_URL_REPORT)}[/]"
            if data.get("url_report_missing")
            else _no_data_cell(provider_outcome(provider_status, "virustotal_url"))
        )
        table.add_row("virustotal_detections", cell)
    else:
        malicious = int(stats.get("malicious", 0) or 0) if isinstance(stats, dict) else 0
        table.add_row("virustotal_detections", f"[{'red' if malicious > 0 else 'green'}]{malicious}/{total}[/]")
        table.add_row("virustotal_last_analysis", _fmt_timestamp(vt_data.get("vt_last_analysis_date_iso")))
        detecting = _fmt_detecting_engines(vt_data.get("vt_detecting_engines"))
        if detecting:
            table.add_row("virustotal_detecting_engines", detecting)
    if vt_data.get("vt_link"):
        table.add_row("virustotal_analysis_link", esc(vt_data.get("vt_link")))

    table.add_row("depth", esc(data.get("depth") or "unknown"))
    table.add_row("collection", esc(_collection_line(data.get("collection"))))

    header = render_run_header(
        f"--- URL lookup for {defang_indicator(display) if defang else display} ---",
        run_id=data.get("run", {}).get("run_id") if isinstance(data.get("run"), Mapping) else None,
        generated_at=data.get("run", {}).get("started_at") if isinstance(data.get("run"), Mapping) else None,
        version=data.get("run", {}).get("tool_version") if isinstance(data.get("run"), Mapping) else None,
        show_run_line=show_run_line,
    )
    notices = [
        n
        for n in (
            render_warnings(_warnings_beyond_coverage(data.get("warnings"), skipped=data.get("skipped_ips"))),
            render_url_anomalies(data.get("url_anomalies")),
            render_skipped_ips(data.get("skipped_ips"), defang=defang),
        )
        if n is not None
    ]
    return compose_report(
        header,
        [table, Text("")],
        verdict=_verdict_slot(data, explain=explain, show_calibration=show_run_line),
        coverage=render_coverage(data.get("coverage") or provider_status),
        notices=notices,
    )


# --------------------------------------------------------------------------------------
# Detection and triage output (6.9 `check`, 6.10 `bulk`)
# --------------------------------------------------------------------------------------

#: Printed above any list of extracted indicators. Bulk extraction reads attacker-authored
#: prose, so the list is a set of *readings* of that text, not a set of established facts.
TRIAGE_CAVEAT = "extracted from pasted text and classified locally; no provider was consulted for this list"


def render_detection(indicator: Any, *, defang: bool = True, explain: bool = False) -> RenderableType:
    """One classified indicator: what it is, how firm the reading is, and what was uncertain.

    Every field comes from :func:`tripper_recon.types.indicators.detect`, which is pure -- so
    this block costs no provider quota and can be produced for a target the analyst has not
    decided to look up yet.
    """
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold cyan")
    table.add_column("Value", style="none")

    table.add_row("input", esc(getattr(indicator, "raw", "")))
    table.add_row("type", esc(getattr(getattr(indicator, "type", None), "value", "unknown")))
    confidence = getattr(getattr(indicator, "confidence", None), "value", "none")
    table.add_row("confidence", esc(confidence) if confidence == "certain" else f"[yellow]{esc(confidence)}[/]")
    table.add_row("value", indicator_text(getattr(indicator, "value", ""), defang=defang))

    if getattr(indicator, "defanged_input", False):
        table.add_row("refanged_for_lookup", esc(", ".join(getattr(indicator, "refang_transforms", ()))))
    alternatives = getattr(indicator, "alternatives", ())
    if alternatives:
        table.add_row(
            "also_parses_as",
            f"[yellow]{esc(', '.join(alternative.value for alternative in alternatives))}[/]",
        )

    block: List[RenderableType] = [Text("--- detection only, no provider was consulted ---", style="bold white"), table]

    notes = getattr(indicator, "notes", ())
    if notes:
        note_block = Text(f"notes ({len(notes)}):", style="bold yellow")
        for note in notes:
            note_block.append("\n")
            note_block.append(f"  - {note}", style="yellow")
        block.extend([Text(""), note_block])

    if explain:
        block.extend([Text(""), Text(str(indicator.explain()), style="dim")])
    return Group(*block)


def render_triage_table(rows: Sequence[Mapping[str, Any]], *, defang: bool = True) -> RenderableType:
    """The bulk-paste triage list: every distinct indicator, ordered by what to look at first.

    ``rows`` are the mappings ``cli._triage`` builds. The occurrence count travels with each
    entry because "this address appears once in the alert" and "this address appears in every
    header" are different starting points, and deduplication would otherwise destroy the
    difference on its way to the screen.
    """
    heading = Text(f"indicators ({len(rows)}) - {TRIAGE_CAVEAT}", style="bold white")
    if not rows:
        return Group(heading, Text("  none found in the supplied text", style="yellow"))

    table = Table(show_header=True, box=None, padding=(0, 2), header_style="bold cyan")
    table.add_column("#", justify="right")
    table.add_column("type")
    # Folded, never truncated. An indicator with an ellipsis through the middle of it is one an
    # analyst cannot copy into the next tool, which is the only thing this table is for.
    table.add_column("indicator", overflow="fold")
    table.add_column("seen", justify="right")
    table.add_column("confidence")
    table.add_column("note")

    for position, row in enumerate(rows, start=1):
        confidence = str(row.get("confidence") or "")
        table.add_row(
            str(position),
            esc(row.get("type")),
            indicator_text(row.get("value"), defang=defang),
            str(row.get("occurrences") or 1),
            esc(confidence) if confidence == "certain" else f"[yellow]{esc(confidence)}[/]",
            esc(row.get("note") or ""),
        )
    return Group(heading, table)


def render_filtered_indicators(rows: Sequence[Mapping[str, Any]]) -> Optional[RenderableType]:
    """Indicators that were extracted and then deliberately withheld from the triage list.

    Printed rather than dropped, for the same reason ``render_skipped_ips`` exists one level
    down: a filter that removes evidence silently is indistinguishable from evidence that was
    never there, and the analyst has no way to notice that their own mail relay -- or the
    RFC1918 address that is actually the pivot -- was quietly binned.
    """
    if not rows:
        return None
    heading = Text(f"withheld from triage ({len(rows)}), extracted but not investigated:", style="bold yellow")
    table = Table(show_header=True, box=None, padding=(0, 2), header_style="bold yellow")
    table.add_column("type")
    table.add_column("indicator", overflow="fold")
    table.add_column("seen", justify="right")
    table.add_column("reason")
    for row in rows:
        # Deliberately not defanged: everything reaching this table was withheld for being
        # non-public or infrastructure the operator owns, and bracketing it adds noise.
        table.add_row(
            esc(row.get("type")),
            esc(row.get("value")),
            str(row.get("occurrences") or 1),
            esc(row.get("reason") or ""),
        )
    return Group(heading, table)
