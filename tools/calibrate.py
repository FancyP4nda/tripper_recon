"""Calibration recording harness (roadmap W5.9). **The operator runs this by hand.**

This is the only thing in the repository that deliberately contacts real providers with real
credentials outside an investigation the analyst asked for. It exists because the verdict
engine's weights are informed priors and nothing has been measured against a labelled set
(``verdict/scoring.yaml`` ``calibration.status: unvalidated``), and the only way to change that
is to record real provider answers for indicators whose ground truth is already known.

Running it costs quota and writes the operator's egress address and every indicator into the
providers' own logs, under the operator's own API keys. That is a deliberate, disclosed act, so
the harness is built to make it one:

* ``record`` refuses to start without ``--i-understand-this-spends-quota``.
* It prints the full cost and disclosure plan **before** anything is loaded or contacted, then
  requires a typed confirmation phrase on an interactive terminal.
* :func:`main` refuses outright inside a test runner or CI (:func:`assert_not_test_environment`),
  and :class:`LiveRecorder` -- the only class that reaches the network -- re-checks that guard in
  its constructor *and* on every call. No flag bypasses it.
* Every recorded byte goes through ``tripper_recon.utils.redact`` and is then verified to hold no
  credential value before it is written.

**The methodological trap, which matters more than the code.** Measuring precision on a
URLhaus-labelled set against a scorer that reads URLhaus is the engine grading its own answer key
(``docs/ROADMAP.md`` section 4, "Publishing any accuracy figure before the held-out corpus
exists"). The ``evaluate`` subcommand therefore supports **hold-one-feed-out**: it disables the
provider that supplied the labels before replaying, so the score is tested against labels that
source did not provide. It also supports a **temporal split**, because a scorer tested on
indicators it has already seen reported measures memory rather than judgement.

Two consequences are enforced rather than documented:

* Precision and recall are emitted **only** for a run that is genuinely held out -- every
  evaluated row labelled by a held-out feed, and at least one fixture where that feed actually
  answered. Otherwise the report carries confusion counts and states plainly that they are
  in-sample agreement, not accuracy.
* This harness never writes ``scoring.yaml``. Moving ``calibration.status`` off ``unvalidated``
  is the operator's own edit, made after reading a held-out report.

**The rule that governs the whole workstream: a cached fact must never claim to have been queried
now.** Every fixture carries ``recorded_at``; every replay carries ``replayed_at`` and the age of
the evidence it rests on. A replayed verdict is never presented as a fresh lookup.

Usage is in ``tools/README.md``.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import csv
import datetime as dt
import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, TextIO, Tuple

from tripper_recon import __version__ as TOOL_VERSION
from tripper_recon.orchestrators import (
    DOMAIN_PROVIDERS,
    IP_PROVIDERS,
    URL_DEPTHS,
    URL_PROVIDERS,
    investigate_domain,
    investigate_ip,
    investigate_url,
)
from tripper_recon.types.indicators import IndicatorType, detect
from tripper_recon.types.models import Coverage, InvestigationResult
from tripper_recon.utils.env import load_env
from tripper_recon.utils.redact import _SECRET_ENV_VARS as SECRET_ENV_VARS
from tripper_recon.utils.redact import REDACTED, redact_text
from tripper_recon.verdict import engine as verdict_engine
from tripper_recon.verdict import signals as verdict_signals
from tripper_recon.verdict.config import IndicatorScope, ScoringConfig, default_config
from tripper_recon.verdict.known_infrastructure import KnownInfrastructure, load_catalogue
from tripper_recon.verdict.models import Verdict

# --------------------------------------------------------------------------------------
# Identity and schemas
# --------------------------------------------------------------------------------------

#: Bumped when the fixture envelope or the report shape changes in a way a reader must notice.
HARNESS_VERSION = "1"

FIXTURE_SCHEMA = "tripper-recon.calibration-fixture/1"
REPORT_SCHEMA = "tripper-recon.calibration-report/1"

#: The flag without which ``record`` refuses to do anything at all.
QUOTA_FLAG = "--i-understand-this-spends-quota"

#: Typed verbatim at the prompt. Deliberately not "y": a reflex keystroke is not a decision.
CONFIRMATION_PHRASE = "spend my quota"

#: Fixtures default here because ``.gitignore`` blanket-ignores ``*.json`` and negates exactly two
#: paths, ``tests/**/*.json`` and ``schema/**/*.json`` (``.gitignore`` "Source data that must stay
#: committable"). A fixture written anywhere else is silently untracked -- it looks recorded and
#: will never reach a remote. Committable is not the same as "commit it": see ``tools/README.md``
#: on what a fixture discloses.
DEFAULT_FIXTURE_DIR = Path("tests/fixtures/calibration")

LEDGER_NAME = "MANIFEST.jsonl"
RECORDS_DIRNAME = "records"

#: Seconds between indicators. Deliberately slow: this is a background recording pass, not an
#: investigation anybody is waiting on, and every provider on the list publishes a rate limit that
#: a burst would sit near. Sleeping is free; a 429 storm under the operator's key is not.
DEFAULT_MIN_INTERVAL = 5.0

#: Wall-clock ceiling handed to each orchestrator call, so one wedged provider cannot stall a
#: 200-indicator run indefinitely.
DEFAULT_DEADLINE = 120.0

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_REFUSED = 2
EXIT_GUARD = 3


# --------------------------------------------------------------------------------------
# Scopes, feeds and credentials
# --------------------------------------------------------------------------------------


class Scope(str, Enum):
    """Which orchestrator answers for this indicator, and therefore which providers are asked."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"


class Label(str, Enum):
    """Ground truth as the labelling feed states it."""

    MALICIOUS = "malicious"
    BENIGN = "benign"


_LABEL_ALIASES: Dict[str, Label] = {
    "malicious": Label.MALICIOUS,
    "bad": Label.MALICIOUS,
    "known-bad": Label.MALICIOUS,
    "known_bad": Label.MALICIOUS,
    "positive": Label.MALICIOUS,
    "benign": Label.BENIGN,
    "good": Label.BENIGN,
    "known-good": Label.BENIGN,
    "known_good": Label.BENIGN,
    "clean": Label.BENIGN,
    "negative": Label.BENIGN,
}

_SCOPE_BY_INDICATOR_TYPE: Dict[IndicatorType, Scope] = {
    IndicatorType.IPV4: Scope.IP,
    IndicatorType.IPV6: Scope.IP,
    IndicatorType.DOMAIN: Scope.DOMAIN,
    IndicatorType.URL: Scope.URL,
}

#: The provider set consulted for each scope. These are the orchestrator's own keys, taken from
#: the orchestrator rather than copied, so adding a provider there changes the disclosure here on
#: the same commit.
SCOPE_PROVIDERS: Dict[Scope, Tuple[str, ...]] = {
    Scope.IP: IP_PROVIDERS,
    Scope.DOMAIN: DOMAIN_PROVIDERS,
    Scope.URL: URL_PROVIDERS,
}

#: Which orchestrator key each labelling feed's evidence arrives under. This is what
#: hold-one-feed-out disables.
#:
#: ``urlhaus`` and ``threatfox`` both map to ``abusech`` because they are one provider call: the
#: orchestrator asks abuse.ch once and the signal id says which platform observed the record
#: (``scoring.yaml`` ``provider_families``). Holding out either holds out both, which is the
#: conservative reading and the correct one -- they share submitters and an operator.
FEED_PROVIDERS: Dict[str, Tuple[str, ...]] = {
    "abusech": ("abusech",),
    "urlhaus": ("abusech",),
    "threatfox": ("abusech",),
    "virustotal": ("virustotal", "virustotal_url"),
    "vt": ("virustotal", "virustotal_url"),
    "otx": ("otx",),
    "alienvault": ("otx",),
    "abuseipdb": ("abuseipdb",),
    "shodan": ("shodan",),
    "tranco": ("tranco",),
    "rdap": ("rdap",),
    # Operator-curated ground truth. No provider supplied the label, so there is nothing to hold
    # out -- which makes these rows the only ones that are non-circular without a hold-out, and
    # the report says so rather than treating "no feed" as "held out".
    "operator": (),
    "manual": (),
}

#: Environment variable behind each provider, for the disclosure. ``None`` means keyless: the
#: provider is contacted anonymously, so the request is logged against the operator's egress
#: address but not against a named account.
PROVIDER_CREDENTIALS: Dict[str, Optional[str]] = {
    "virustotal": "VT_API_KEY",
    "virustotal_url": "VT_API_KEY",
    "ipinfo": "IPINFO_TOKEN",
    "shodan": "SHODAN_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "otx": "OTX_API_KEY",
    "cloudflare_asn": "CLOUDFLARE_API_TOKEN",
    "abusech": "ABUSECH_AUTH_KEY",
    "rdap": None,
    "tranco": None,
}

#: Where each scope's provider payloads and status map live inside ``InvestigationResult.data``.
#: The payload key is not always the provider key: the URL path files ``virustotal_url``'s answer
#: under ``url_intel['virustotal']``, and the IP path files ``cloudflare_asn``'s under
#: ``asn_meta``.
_STATUS_KEY: Dict[Scope, str] = {
    Scope.IP: "provider_status",
    Scope.DOMAIN: "domain_provider_status",
    Scope.URL: "url_provider_status",
}
_INTEL_KEY: Dict[Scope, Optional[str]] = {
    Scope.IP: None,  # provider payloads sit at the top level of ``data``
    Scope.DOMAIN: "domain_intel",
    Scope.URL: "url_intel",
}
_PAYLOAD_KEYS: Dict[Scope, Dict[str, str]] = {
    Scope.IP: {
        "virustotal": "virustotal",
        "ipinfo": "ipinfo",
        "shodan": "shodan",
        "abuseipdb": "abuseipdb",
        "otx": "otx",
        "rdap": "rdap",
        "abusech": "abusech",
        "cloudflare_asn": "asn_meta",
    },
    Scope.DOMAIN: {
        "virustotal": "virustotal",
        "otx": "otx",
        "rdap": "rdap",
        "tranco": "tranco",
        "abusech": "abusech",
    },
    Scope.URL: {
        "virustotal_url": "virustotal",
        "abusech": "abusech",
    },
}

#: Stated on every report, held out or not. Holding out abuse.ch does not make VirusTotal an
#: independent witness of an abuse.ch record: VT re-ingests public feeds including abuse.ch, so a
#: VT detection may itself be an echo of the label. ``scoring.yaml``'s ``provider_families`` block
#: records the same asymmetry from the other direction.
RESIDUAL_CIRCULARITY_NOTE = (
    "Residual circularity survives every hold-out available here: VirusTotal and OTX re-ingest "
    "public feeds including abuse.ch, so a detection they report may be an echo of the same "
    "record that supplied the label. Holding out a feed removes its direct signal, not its "
    "downstream reflections."
)


# --------------------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------------------


class CalibrationError(RuntimeError):
    """Anything this harness refuses to do, with the reason attached."""


class GuardError(CalibrationError):
    """The harness was invoked somewhere it must never run: a test runner, or CI."""


class ConfirmationError(CalibrationError):
    """The operator did not confirm, or could not be asked."""


class LabelSetError(CalibrationError):
    """The labelled indicator file could not be read as one."""


class RedactionError(CalibrationError):
    """A credential survived redaction. Nothing is written when this is raised."""


# --------------------------------------------------------------------------------------
# The test-environment guard
# --------------------------------------------------------------------------------------

#: Environment variables that, when set to anything non-empty, mean a build system is driving.
CI_ENV_VARS: Tuple[str, ...] = (
    "CI",
    "CONTINUOUS_INTEGRATION",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "JENKINS_URL",
    "BUILDKITE",
    "TEAMCITY_VERSION",
    "TF_BUILD",
    "CIRCLECI",
)

#: Set by pytest for the duration of each test. Its presence is conclusive.
PYTEST_ENV_VAR = "PYTEST_CURRENT_TEST"

_TEST_RUNNER_MODULES: Tuple[str, ...] = ("pytest", "_pytest", "unittest")


def test_environment_reasons(
    *,
    modules: Optional[Iterable[str]] = None,
    argv: Optional[Sequence[str]] = None,
    env: Optional[Mapping[str, str]] = None,
) -> List[str]:
    """Every reason to believe this process is a test run or a CI job, in order of certainty.

    Empty means none was found. The arguments exist so the guard itself can be tested from
    inside a test run -- which is exactly the environment where the real answer is always
    "refuse" -- and default to the live process when omitted.

    ``unittest`` is on the module list beside ``pytest``: this harness must not run under any
    test runner, and naming only the one this project happens to use would leave the check
    silently narrower than the rule it enforces.
    """
    modules = sys.modules if modules is None else modules
    argv = sys.argv if argv is None else argv
    env = os.environ if env is None else env

    reasons: List[str] = []
    if PYTEST_ENV_VAR in env:
        reasons.append(f"{PYTEST_ENV_VAR} is set: a pytest test is executing")
    loaded = sorted(name for name in _TEST_RUNNER_MODULES if name in modules)
    for name in loaded:
        reasons.append(f"the {name} module is imported: a test runner is driving this process")
    program = Path(argv[0]).name if argv else ""
    if program in {"pytest", "py.test", "unittest"}:
        reasons.append(f"argv[0] is {program!r}: a test runner is driving this process")
    for name in CI_ENV_VARS:
        if (env.get(name) or "").strip():
            reasons.append(f"{name} is set: a CI system is driving this process")
    return reasons


def assert_not_test_environment(
    *,
    modules: Optional[Iterable[str]] = None,
    argv: Optional[Sequence[str]] = None,
    env: Optional[Mapping[str, str]] = None,
) -> None:
    """Raise :class:`GuardError` if this process is a test run or a CI job.

    There is no override, no flag and no environment variable that disables this. The harness
    spends the operator's quota and writes indicators into provider logs under his keys; a test
    suite or a CI job doing that on his behalf is not a bug to be fixed after the fact, because
    the provider-side log entry cannot be withdrawn.

    Called from :func:`main` for every subcommand, and again inside :class:`LiveRecorder` -- both
    in its constructor and on every call -- so that neither importing this module nor holding a
    recorder object is enough to reach a socket.
    """
    reasons = test_environment_reasons(modules=modules, argv=argv, env=env)
    if not reasons:
        return
    raise GuardError(
        "the calibration harness refuses to run here. It spends the operator's API quota and "
        "logs every indicator with the providers under his own keys, which is a deliberate act "
        "and never an automated one. Reasons:\n  - " + "\n  - ".join(reasons)
    )


# --------------------------------------------------------------------------------------
# The labelled indicator set
# --------------------------------------------------------------------------------------

REQUIRED_COLUMNS: Tuple[str, ...] = ("indicator", "label", "label_source")
OPTIONAL_COLUMNS: Tuple[str, ...] = ("first_seen", "note")


@dataclass(frozen=True)
class LabelledIndicator:
    """One row of ground truth: what it is, what it is known to be, and who says so."""

    raw: str
    value: str
    scope: Scope
    indicator_type: IndicatorType
    label: Label
    #: The feed that supplied the label. Hold-one-feed-out keys off this.
    label_source: str
    #: When the labelling feed first reported it, if the row says. Required for a temporal split.
    first_seen: Optional[dt.datetime]
    note: str
    line_number: int

    @property
    def fixture_id(self) -> str:
        """Filesystem-safe, deterministic, and derived from the canonical value only.

        The indicator is never used as a filename. Attacker-authored text reaches this harness by
        design -- a URLhaus row is a live malware URL -- and building a path out of it invites
        traversal, control characters and a 4KB filename. The value is recorded inside the file
        instead, where it is data rather than a path.
        """
        digest = hashlib.sha256(self.value.encode("utf-8")).hexdigest()
        return f"{self.scope.value}-{digest[:16]}"

    @property
    def indicator_sha256(self) -> str:
        return hashlib.sha256(self.value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class LabelSetProblem:
    """A row that could not be used, with the reason. Never silently dropped."""

    line_number: int
    raw: str
    reason: str


@dataclass(frozen=True)
class LabelSet:
    rows: Tuple[LabelledIndicator, ...]
    problems: Tuple[LabelSetProblem, ...]

    @property
    def duplicates_removed(self) -> int:
        return sum(1 for problem in self.problems if problem.reason.startswith("duplicate"))


def _parse_timestamp(text: str) -> dt.datetime:
    """Parse an RFC 3339 / ISO 8601 date or datetime as UTC.

    A bare date is read as midnight UTC. A naive datetime is **rejected** rather than assumed to
    be UTC: assuming is how a temporal split silently moves by the operator's offset, which is
    the one error a temporal split exists to avoid.
    """
    cleaned = text.strip().replace("Z", "+00:00")
    if not cleaned:
        raise ValueError("empty timestamp")
    try:
        parsed = dt.datetime.fromisoformat(cleaned)
    except ValueError as exc:
        raise ValueError(f"{text!r} is not an RFC 3339 date or datetime") from exc
    if parsed.tzinfo is None:
        if len(cleaned) == 10:  # a bare YYYY-MM-DD
            return parsed.replace(tzinfo=dt.timezone.utc)
        raise ValueError(f"{text!r} has no timezone; a naive datetime has no defensible meaning")
    return parsed.astimezone(dt.timezone.utc)


def parse_label_row(row: Mapping[str, str], line_number: int) -> LabelledIndicator:
    """Turn one CSV row into a :class:`LabelledIndicator`, or raise :class:`ValueError`.

    Classification goes through :func:`tripper_recon.types.indicators.detect`, so a defanged
    indicator (``hxxp://evil[.]com``) is refanged on the way in and the harness records the
    canonical form the tool would actually investigate.
    """
    raw = (row.get("indicator") or "").strip()
    if not raw:
        raise ValueError("no indicator")

    label_text = (row.get("label") or "").strip().lower()
    label = _LABEL_ALIASES.get(label_text)
    if label is None:
        raise ValueError(f"label {label_text!r} is not one of {sorted(set(_LABEL_ALIASES))}")

    source = (row.get("label_source") or "").strip().lower()
    if not source:
        raise ValueError("no label_source; hold-one-feed-out cannot work without knowing who labelled the row")
    if source not in FEED_PROVIDERS:
        raise ValueError(f"label_source {source!r} is unknown; known feeds are {sorted(FEED_PROVIDERS)}")

    indicator = detect(raw)
    scope = _SCOPE_BY_INDICATOR_TYPE.get(indicator.type)
    if scope is None:
        raise ValueError(
            f"detected as {indicator.type.value}, which this harness does not record. "
            "Recordable scopes are ip, domain and url"
        )

    first_seen_text = (row.get("first_seen") or "").strip()
    first_seen = _parse_timestamp(first_seen_text) if first_seen_text else None

    return LabelledIndicator(
        raw=raw,
        value=indicator.value,
        scope=scope,
        indicator_type=indicator.type,
        label=label,
        label_source=source,
        first_seen=first_seen,
        note=(row.get("note") or "").strip(),
        line_number=line_number,
    )


def load_label_set(path: Path) -> LabelSet:
    """Read a labelled indicator CSV. Header required; unusable rows are reported, never dropped.

    Columns: ``indicator``, ``label``, ``label_source`` are required; ``first_seen`` and ``note``
    are optional. ``first_seen`` is what a temporal split needs, so a set without it can be
    recorded but cannot be split.

    Duplicate indicators are collapsed to the first occurrence and reported, because recording the
    same indicator twice spends quota twice and biases any count computed over the corpus.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise LabelSetError(f"cannot read the labelled indicator file {path}: {exc}") from exc

    reader = csv.DictReader(text.splitlines())
    if reader.fieldnames is None:
        raise LabelSetError(f"{path} is empty; expected a header row of {','.join(REQUIRED_COLUMNS)}")
    header = [name.strip().lower() for name in reader.fieldnames]
    missing = [name for name in REQUIRED_COLUMNS if name not in header]
    if missing:
        raise LabelSetError(
            f"{path} is missing required column(s) {', '.join(missing)}. "
            f"Required: {', '.join(REQUIRED_COLUMNS)}; optional: {', '.join(OPTIONAL_COLUMNS)}"
        )

    rows: List[LabelledIndicator] = []
    problems: List[LabelSetProblem] = []
    seen: Dict[str, int] = {}
    for offset, raw_row in enumerate(reader, start=2):  # line 1 is the header
        normalised = {(key or "").strip().lower(): (value or "") for key, value in raw_row.items()}
        try:
            parsed = parse_label_row(normalised, offset)
        except ValueError as exc:
            problems.append(LabelSetProblem(offset, (normalised.get("indicator") or "").strip(), str(exc)))
            continue
        first = seen.get(parsed.fixture_id)
        if first is not None:
            problems.append(
                LabelSetProblem(offset, parsed.raw, f"duplicate of the indicator already read at line {first}")
            )
            continue
        seen[parsed.fixture_id] = offset
        rows.append(parsed)

    if not rows:
        raise LabelSetError(
            f"{path} yielded no usable rows out of {len(problems)} read. "
            "Every row is reported with its reason; fix the file rather than lowering the bar"
        )
    return LabelSet(rows=tuple(rows), problems=tuple(problems))


# --------------------------------------------------------------------------------------
# The disclosure plan
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ProviderDisclosure:
    provider: str
    credential_env_var: Optional[str]
    configured: bool

    @property
    def line(self) -> str:
        if self.credential_env_var is None:
            return f"{self.provider:<16} keyless -- logged against your egress address, not a named account"
        if self.configured:
            return f"{self.provider:<16} {self.credential_env_var} IS set -- logged against YOUR account"
        return f"{self.provider:<16} {self.credential_env_var} is not set -- this provider will not be asked"


@dataclass(frozen=True)
class RecordingPlan:
    """Everything the operator is agreeing to, computed before anything is contacted."""

    counts: Dict[Scope, int]
    already_recorded: int
    to_record: int
    minimum_calls: int
    per_address_calls: int
    unbounded: bool
    providers: Dict[Scope, Tuple[ProviderDisclosure, ...]]
    resolves_dns: bool
    url_depth: str
    min_interval: float
    fixture_dir: Path
    label_problems: Tuple[LabelSetProblem, ...]

    @property
    def total_indicators(self) -> int:
        return sum(self.counts.values())

    @property
    def estimated_minutes(self) -> float:
        return round((self.to_record * self.min_interval) / 60.0, 1)


def credential_status(provider: str, env: Mapping[str, str]) -> ProviderDisclosure:
    """Whether the credential behind ``provider`` is present. Never reads or prints the value."""
    var = PROVIDER_CREDENTIALS.get(provider)
    configured = bool((env.get(var) or "").strip()) if var else True
    return ProviderDisclosure(provider=provider, credential_env_var=var, configured=configured)


def build_plan(
    rows: Sequence[LabelledIndicator],
    *,
    env: Mapping[str, str],
    fixture_dir: Path,
    already_recorded: int = 0,
    url_depth: str = "full",
    min_interval: float = DEFAULT_MIN_INTERVAL,
    label_problems: Sequence[LabelSetProblem] = (),
) -> RecordingPlan:
    """Compute the cost and disclosure plan. Pure: reads a mapping, contacts nothing.

    The call estimate is a **minimum** and says so. A domain resolves to an unknown number of
    addresses and each one is enriched by the full IP provider set, so the true figure is not
    knowable before the lookup -- a domain with eight A records costs 5 domain-level calls plus
    8 x 8 address-level ones. Presenting a single confident number here would understate what the
    operator is agreeing to, which is the one direction this disclosure must not err in.
    """
    counts: Dict[Scope, int] = {scope: 0 for scope in Scope}
    for row in rows:
        counts[row.scope] += 1

    per_address = len(IP_PROVIDERS)
    minimum = (
        counts[Scope.IP] * len(IP_PROVIDERS)
        + counts[Scope.DOMAIN] * (len(DOMAIN_PROVIDERS) + per_address)
        + counts[Scope.URL] * (len(URL_PROVIDERS) + (len(DOMAIN_PROVIDERS) if url_depth != "url" else 0))
    )
    unbounded = bool(counts[Scope.DOMAIN]) or (bool(counts[Scope.URL]) and url_depth == "full")
    resolves_dns = bool(counts[Scope.DOMAIN]) or (bool(counts[Scope.URL]) and url_depth == "full")

    providers: Dict[Scope, Tuple[ProviderDisclosure, ...]] = {}
    for scope in Scope:
        if not counts[scope]:
            continue
        names = list(SCOPE_PROVIDERS[scope])
        if scope is Scope.DOMAIN or (scope is Scope.URL and url_depth != "url"):
            names.extend(name for name in DOMAIN_PROVIDERS if name not in names)
        if scope is Scope.DOMAIN or (scope is Scope.URL and url_depth == "full"):
            names.extend(name for name in IP_PROVIDERS if name not in names)
        providers[scope] = tuple(credential_status(name, env) for name in names)

    return RecordingPlan(
        counts=counts,
        already_recorded=already_recorded,
        to_record=max(len(rows) - already_recorded, 0),
        minimum_calls=minimum,
        per_address_calls=per_address,
        unbounded=unbounded,
        providers=providers,
        resolves_dns=resolves_dns,
        url_depth=url_depth,
        min_interval=min_interval,
        fixture_dir=fixture_dir,
        label_problems=tuple(label_problems),
    )


def render_plan(plan: RecordingPlan) -> str:
    """The disclosure the operator reads before confirming. Printed before anything is contacted."""
    lines: List[str] = []
    lines.append("=" * 78)
    lines.append("CALIBRATION RECORDING -- WHAT YOU ARE ABOUT TO DO")
    lines.append("=" * 78)
    lines.append("")
    lines.append(f"Labelled indicators read : {plan.total_indicators}")
    for scope in Scope:
        if plan.counts[scope]:
            lines.append(f"  {scope.value:<7}                : {plan.counts[scope]}")
    if plan.label_problems:
        lines.append(f"Rows rejected            : {len(plan.label_problems)} (listed below; none is silently dropped)")
    lines.append(f"Already recorded (skipped): {plan.already_recorded}")
    lines.append(f"Will be recorded now      : {plan.to_record}")
    lines.append("")
    lines.append(f"MINIMUM provider calls    : {plan.minimum_calls}")
    if plan.unbounded:
        lines.append(
            f"  ...and MORE. Each address a domain or URL resolves to is enriched by all "
            f"{plan.per_address_calls} IP providers, and the address count is not knowable before "
            f"the lookup. Treat {plan.minimum_calls} as a floor, not an estimate."
        )
    lines.append(
        f"Pacing                    : one indicator every {plan.min_interval:g}s "
        f"(~{plan.estimated_minutes:g} min of deliberate idling)"
    )
    lines.append("")
    lines.append("PROVIDERS THAT WILL BE CONTACTED")
    lines.append("  Every indicator below is sent to every provider listed for its scope. Each")
    lines.append("  provider logs the indicator, the time, and your egress address. Where a")
    lines.append("  credential is set, the entry is attributed to YOUR ACCOUNT and is not")
    lines.append("  retractable. Hosts are listed in docs/OPSEC.md section 2.")
    for scope in Scope:
        disclosures = plan.providers.get(scope)
        if not disclosures:
            continue
        lines.append(f"  [{scope.value}]")
        for disclosure in disclosures:
            lines.append(f"    {disclosure.line}")
    lines.append("")
    if plan.resolves_dns:
        lines.append("ACTIVE COLLECTION")
        lines.append("  Domain indicators, and URL indicators at --url-depth full, use the SYSTEM")
        lines.append("  RESOLVER. A recursive lookup terminates at the target's own nameservers, so")
        lines.append("  the target learns that its name was resolved (docs/OPSEC.md section 3).")
        lines.append("  Use --url-depth host to keep URL rows fully passive.")
        lines.append("")
    lines.append(f"FIXTURES WILL BE WRITTEN TO {plan.fixture_dir}")
    lines.append("  Credentials are redacted from everything written, and the write is aborted if a")
    lines.append("  credential value survives. The indicators themselves are NOT redacted -- they")
    lines.append("  are the evidence. Review before committing: this repository is public.")
    lines.append("")
    lines.append("THIS DOES NOT VALIDATE ANYTHING")
    lines.append("  Recording fixtures produces evidence to replay against, not an accuracy figure.")
    lines.append("  Until a held-out evaluation has been run, the correct public claim stays")
    lines.append('  "tuned against N fixtures, not yet validated". This harness never edits')
    lines.append("  scoring.yaml.")
    if plan.label_problems:
        lines.append("")
        lines.append("ROWS REJECTED FROM THE LABEL SET")
        for problem in plan.label_problems:
            lines.append(f"  line {problem.line_number}: {problem.raw!r}: {problem.reason}")
    lines.append("")
    lines.append("=" * 78)
    return "\n".join(lines)


def confirm(
    plan: RecordingPlan,
    *,
    stream: TextIO,
    reader: Callable[[], str],
    interactive: bool,
) -> None:
    """Print the plan and require the confirmation phrase. Raises :class:`ConfirmationError`.

    ``interactive`` is normally ``sys.stdin.isatty()``. A non-interactive stdin is refused rather
    than defaulted: something that cannot be asked must not be assumed to have agreed, and the
    refusal is a second, independent reason this harness cannot run from a scheduler or a job.
    """
    print(render_plan(plan), file=stream)
    if plan.to_record <= 0:
        raise ConfirmationError("nothing left to record: every indicator in the set already has a fixture")
    if not interactive:
        raise ConfirmationError(
            "stdin is not an interactive terminal, so the confirmation cannot be given. This "
            "harness is run by hand, deliberately, and never from a script or a scheduler"
        )
    print(f"\nType exactly: {CONFIRMATION_PHRASE}", file=stream)
    print("Anything else aborts. > ", end="", file=stream, flush=True)
    answer = reader()
    if answer.strip() != CONFIRMATION_PHRASE:
        raise ConfirmationError(f"confirmation phrase not given (read {answer.strip()!r}); nothing was contacted")


# --------------------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------------------


def redact_structure(value: Any) -> Any:
    """Apply ``utils.redact.redact_text`` to every string in a nested structure.

    The redactor is the package's, not a second one: ``redact_text`` already handles both
    embedded URLs with credential query parameters and bare credential values pulled from the
    environment. This function only walks the container.
    """
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {redact_text(str(key)): redact_structure(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_structure(item) for item in value]
    return value


def verify_redacted(text: str, env: Optional[Mapping[str, str]] = None) -> None:
    """Post-condition on the redactor: raise if any known credential value survives in ``text``.

    This is a check, not a second redactor. It reads the same variable names
    ``utils.redact`` reads and asserts their values are absent from what is about to be written.
    The reason it exists at all: a fixture is written once and read for months, and a key that
    leaks into one is a key that leaks into every ticket the fixture ever supports. Failing the
    write is recoverable; publishing the key is not.
    """
    env = os.environ if env is None else env
    for name in SECRET_ENV_VARS:
        value = (env.get(name) or "").strip()
        if len(value) >= 8 and value in text:
            raise RedactionError(
                f"the value of {name} survived redaction and would have been written to disk. "
                "Nothing was written. This is a defect in tripper_recon.utils.redact or in a "
                "provider payload shape it does not anticipate -- report it before re-running"
            )


# --------------------------------------------------------------------------------------
# The fixture envelope and the resume ledger
# --------------------------------------------------------------------------------------


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _rfc3339(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def build_fixture(
    row: LabelledIndicator,
    result: InvestigationResult,
    *,
    now: dt.datetime,
    ruleset_version: str,
    url_depth: Optional[str] = None,
) -> Dict[str, Any]:
    """The recorded envelope: the label, the evidence, and when the evidence was obtained.

    ``recorded_at`` is the load-bearing field. Everything downstream that replays this fixture
    reports it, so a three-week-old cached answer can never be presented as a fresh lookup.

    ``verdict_at_record`` keeps the verdict the engine reached at recording time. It is what turns
    a weight change into a diff instead of silent drift; it is never read as evidence.
    """
    data = copy.deepcopy(dict(result.data))
    recorded_verdict = data.get("verdict")
    payload: Dict[str, Any] = {
        "schema": FIXTURE_SCHEMA,
        "fixture_id": row.fixture_id,
        "harness_version": HARNESS_VERSION,
        "indicator": row.value,
        "indicator_raw": row.raw,
        "indicator_sha256": row.indicator_sha256,
        "indicator_type": row.indicator_type.value,
        "scope": row.scope.value,
        "label": row.label.value,
        "label_source": row.label_source,
        "label_first_seen": _rfc3339(row.first_seen) if row.first_seen else None,
        "label_note": row.note,
        "recorded_at": _rfc3339(now),
        "recorded_by": {
            "tool": "tripper-recon",
            "tool_version": TOOL_VERSION,
            "run_id": result.run.run_id if result.run else None,
        },
        "ruleset_version_at_record": ruleset_version,
        "url_depth": url_depth,
        "redaction": {
            "applied": True,
            "module": "tripper_recon.utils.redact",
            "marker": REDACTED,
            "scope": "every string in this document",
        },
        "ok": result.ok,
        "warnings": list(result.warnings),
        "errors": list(result.errors),
        "coverage": result.coverage_or_unknown.model_dump(mode="json"),
        "verdict_at_record": recorded_verdict,
        "data": data,
    }
    return dict(redact_structure(payload))


def write_fixture(fixture_dir: Path, payload: Mapping[str, Any], *, env: Optional[Mapping[str, str]] = None) -> Path:
    """Serialise, verify no credential survived, then write atomically.

    Atomic because the run is resumable: a half-written fixture that a resumed run treats as
    complete is worse than no fixture, since it silently narrows the corpus.
    """
    records = fixture_dir / RECORDS_DIRNAME
    records.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    verify_redacted(text, env)
    path = records / f"{payload['fixture_id']}.json"
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)
    return path


@dataclass(frozen=True)
class LedgerEntry:
    fixture_id: str
    indicator: str
    scope: str
    status: str
    at: str
    error: Optional[str] = None

    @property
    def is_recorded(self) -> bool:
        return self.status == "recorded"


def read_ledger(fixture_dir: Path) -> Dict[str, LedgerEntry]:
    """The resume state: the last outcome recorded for each fixture id.

    A malformed line is skipped rather than fatal. The ledger is an append-only journal written
    during a run that can be interrupted at any moment, so a truncated last line is an expected
    state and must not stop the resume it exists to enable.
    """
    path = fixture_dir / LEDGER_NAME
    entries: Dict[str, LedgerEntry] = {}
    if not path.is_file():
        return entries
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(raw, dict) or "fixture_id" not in raw:
            continue
        entries[str(raw["fixture_id"])] = LedgerEntry(
            fixture_id=str(raw["fixture_id"]),
            indicator=str(raw.get("indicator") or ""),
            scope=str(raw.get("scope") or ""),
            status=str(raw.get("status") or ""),
            at=str(raw.get("at") or ""),
            error=raw.get("error"),
        )
    return entries


def append_ledger(fixture_dir: Path, entry: LedgerEntry, *, env: Optional[Mapping[str, str]] = None) -> None:
    """Append one journal line and flush it. Flushed per line so an interrupt loses nothing."""
    fixture_dir.mkdir(parents=True, exist_ok=True)
    payload = redact_structure(
        {
            "fixture_id": entry.fixture_id,
            "indicator": entry.indicator,
            "scope": entry.scope,
            "status": entry.status,
            "at": entry.at,
            "error": entry.error,
            "harness_version": HARNESS_VERSION,
        }
    )
    line = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    verify_redacted(line, env)
    with (fixture_dir / LEDGER_NAME).open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def completed_fixture_ids(fixture_dir: Path) -> Set[str]:
    """Fixture ids that are both journalled as recorded and present on disk.

    Both conditions, deliberately. A ledger line without a file means the run died between the
    write and the flush; a file without a ledger line means the run died the other way round.
    Requiring both makes an interrupted run resume by re-recording exactly one indicator.
    """
    records = fixture_dir / RECORDS_DIRNAME
    return {
        fixture_id
        for fixture_id, entry in read_ledger(fixture_dir).items()
        if entry.is_recorded and (records / f"{fixture_id}.json").is_file()
    }


# --------------------------------------------------------------------------------------
# Recording
# --------------------------------------------------------------------------------------


class LiveRecorder:
    """The only object in this file that reaches the network.

    Every path into it is guarded: the constructor refuses to build one in a test runner or CI,
    and :meth:`investigate` re-checks before every call so that an object built in a legitimate
    process cannot be carried into an illegitimate one.
    """

    def __init__(self, *, deadline: float = DEFAULT_DEADLINE, url_depth: str = "full") -> None:
        assert_not_test_environment()
        if url_depth not in URL_DEPTHS:
            raise CalibrationError(f"url depth {url_depth!r} is not one of {', '.join(URL_DEPTHS)}")
        self._deadline = deadline
        self._url_depth = url_depth

    @property
    def url_depth(self) -> str:
        return self._url_depth

    async def investigate(self, row: LabelledIndicator) -> InvestigationResult:
        assert_not_test_environment()
        if row.scope is Scope.IP:
            return await investigate_ip(row.value, deadline=self._deadline)
        if row.scope is Scope.DOMAIN:
            return await investigate_domain(row.value, deadline=self._deadline)
        return await investigate_url(row.value, depth=self._url_depth, deadline=self._deadline)


@dataclass
class RecordingSummary:
    recorded: int = 0
    skipped: int = 0
    failed: int = 0
    written: List[Path] = field(default_factory=list)
    failures: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        """Non-zero when any indicator failed. A partially-recorded corpus is not a success."""
        return EXIT_ERROR if self.failed else EXIT_OK


async def record_all(
    rows: Sequence[LabelledIndicator],
    *,
    recorder: Any,
    fixture_dir: Path,
    ruleset_version: str,
    url_depth: str = "full",
    min_interval: float = DEFAULT_MIN_INTERVAL,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    now: Callable[[], dt.datetime] = _utc_now,
    stream: TextIO = sys.stdout,
    env: Optional[Mapping[str, str]] = None,
    overwrite: bool = False,
) -> RecordingSummary:
    """Record every row that has no fixture yet, one at a time, writing as it goes.

    Sequential and paced on purpose. Concurrency here would buy minutes on a job nobody is
    waiting for and would spend them against per-provider rate limits under the operator's own
    keys -- and a 429 recorded as a provider error becomes a permanent hole in the corpus.

    Resumable by construction: the fixture and its ledger line are written before the next
    indicator is touched, so an interrupted run loses at most the indicator in flight. A failed
    indicator is journalled as an error and retried on the next run, because a failure produced
    no evidence and skipping it would silently shrink the corpus.
    """
    summary = RecordingSummary()
    done = set() if overwrite else completed_fixture_ids(fixture_dir)
    pending = [row for row in rows if row.fixture_id not in done]
    summary.skipped = len(rows) - len(pending)

    for index, row in enumerate(pending):
        if index:
            await sleep(min_interval)
        print(f"[{index + 1}/{len(pending)}] {row.scope.value} {row.value}", file=stream, flush=True)
        try:
            result = await recorder.investigate(row)
        except Exception as exc:  # noqa: BLE001 - one bad indicator must not end a paced run
            reason = redact_text(f"{type(exc).__name__}: {exc}")
            summary.failed += 1
            summary.failures.append((row.value, reason))
            append_ledger(
                fixture_dir,
                LedgerEntry(row.fixture_id, row.value, row.scope.value, "error", _rfc3339(now()), reason),
                env=env,
            )
            print(f"    FAILED: {reason}", file=stream, flush=True)
            continue

        payload = build_fixture(row, result, now=now(), ruleset_version=ruleset_version, url_depth=url_depth)
        try:
            path = write_fixture(fixture_dir, payload, env=env)
        except RedactionError as exc:
            # Not caught with the rest: a leaked credential is not a per-indicator failure to
            # journal and move past. Stop the run so the operator sees it immediately.
            print(f"    ABORTED: {exc}", file=stream, flush=True)
            raise
        summary.recorded += 1
        summary.written.append(path)
        append_ledger(
            fixture_dir,
            LedgerEntry(row.fixture_id, row.value, row.scope.value, "recorded", _rfc3339(now())),
            env=env,
        )
        coverage = payload.get("coverage") or {}
        print(f"    recorded {path.name}  ({coverage.get('headline', 'coverage unknown')})", file=stream, flush=True)

    return summary


# --------------------------------------------------------------------------------------
# Replay: hold-one-feed-out and the temporal split
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Fixture:
    """One recorded envelope, read back off disk."""

    path: Path
    payload: Dict[str, Any]

    @property
    def indicator(self) -> str:
        return str(self.payload.get("indicator") or "")

    @property
    def scope(self) -> Scope:
        return Scope(str(self.payload.get("scope")))

    @property
    def label(self) -> Label:
        return Label(str(self.payload.get("label")))

    @property
    def label_source(self) -> str:
        return str(self.payload.get("label_source") or "")

    @property
    def recorded_at(self) -> Optional[dt.datetime]:
        raw = self.payload.get("recorded_at")
        return _parse_timestamp(str(raw)) if raw else None

    @property
    def first_seen(self) -> Optional[dt.datetime]:
        raw = self.payload.get("label_first_seen")
        return _parse_timestamp(str(raw)) if raw else None

    @property
    def data(self) -> Dict[str, Any]:
        raw = self.payload.get("data")
        return dict(raw) if isinstance(raw, Mapping) else {}

    @property
    def coverage(self) -> Coverage:
        raw = self.payload.get("coverage")
        if isinstance(raw, Mapping):
            try:
                return Coverage.model_validate(dict(raw))
            except Exception:  # noqa: BLE001 - an unreadable coverage record is zero coverage
                return Coverage()
        return Coverage()


def load_fixtures(fixture_dir: Path) -> Tuple[List[Fixture], List[str]]:
    """Read every recorded fixture. Returns ``(fixtures, problems)``; never raises on one bad file."""
    records = fixture_dir / RECORDS_DIRNAME
    fixtures: List[Fixture] = []
    problems: List[str] = []
    if not records.is_dir():
        return fixtures, [f"no records directory at {records}"]
    for path in sorted(records.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            problems.append(f"{path.name}: unreadable ({type(exc).__name__})")
            continue
        if not isinstance(payload, dict):
            problems.append(f"{path.name}: not a JSON object")
            continue
        if payload.get("schema") != FIXTURE_SCHEMA:
            problems.append(f"{path.name}: schema {payload.get('schema')!r}, expected {FIXTURE_SCHEMA!r}")
            continue
        try:
            fixture = Fixture(path=path, payload=payload)
            _ = fixture.scope, fixture.label
        except ValueError as exc:
            problems.append(f"{path.name}: {exc}")
            continue
        fixtures.append(fixture)
    return fixtures, problems


def resolve_held_out_providers(feeds: Sequence[str], providers: Sequence[str]) -> Tuple[str, ...]:
    """Map feed names onto the orchestrator provider keys their evidence arrives under."""
    resolved: List[str] = []
    for feed in feeds:
        key = feed.strip().lower()
        if key not in FEED_PROVIDERS:
            raise CalibrationError(f"unknown feed {feed!r}; known feeds are {sorted(FEED_PROVIDERS)}")
        resolved.extend(FEED_PROVIDERS[key])
    resolved.extend(name.strip().lower() for name in providers if name.strip())
    seen: Dict[str, None] = {}
    for name in resolved:
        seen.setdefault(name, None)
    return tuple(seen)


def _hold_out_coverage(coverage: Coverage, providers: Sequence[str]) -> Coverage:
    """Move held-out providers from answered to skipped, keeping the denominator intact.

    The denominator must not shrink. A held-out provider was applicable and deliberately not
    consulted, which is missing coverage in exactly the sense ``Coverage`` already models -- and
    the confidence floor that follows from it is a true statement about the held-out run, not an
    artefact to be corrected away.

    Names may be namespaced by the caller (``url:virustotal_url``, ``1.2.3.4:otx``), so the
    comparison is on the last colon-separated segment.
    """
    held = {name.strip().lower() for name in providers}

    def is_held(name: str) -> bool:
        return name.rsplit(":", 1)[-1].lower() in held

    answered = [name for name in coverage.answered if not is_held(name)]
    moved = [name for name in coverage.answered if is_held(name)]
    return Coverage(
        answered=answered,
        not_found=[name for name in coverage.not_found if not is_held(name)],
        errored=list(coverage.errored),
        unconfigured=list(coverage.unconfigured),
        skipped=[*coverage.skipped, *moved],
    )


def apply_hold_out(data: Mapping[str, Any], scope: Scope, providers: Sequence[str]) -> Tuple[Dict[str, Any], List[str]]:
    """Return a copy of ``data`` with each held-out provider's evidence removed.

    Removal is done the way a real un-consulted provider looks, not by zeroing a weight: the
    payload is emptied, the status entry becomes ``skipped`` with the reason, and coverage is
    recomputed from the mutated status map. A weight set to zero would leave the provider
    counted as having answered, which would inflate confidence on precisely the run whose point
    is to measure without it.

    Returns ``(data, actually_held)`` -- ``actually_held`` names the providers that had in fact
    answered for this fixture. A hold-out that removes nothing is vacuous and the caller must
    know, because "held out" over a corpus where the feed never answered is not a hold-out.
    """
    mutated = copy.deepcopy(dict(data))
    held = {name.strip().lower() for name in providers}
    payload_keys = _PAYLOAD_KEYS[scope]
    status_key = _STATUS_KEY[scope]
    intel_key = _INTEL_KEY[scope]

    status = mutated.get(status_key)
    status = dict(status) if isinstance(status, Mapping) else {}
    actually_held: List[str] = []

    for provider in payload_keys:
        if provider.lower() not in held:
            continue
        entry = status.get(provider)
        if isinstance(entry, Mapping) and str(entry.get("outcome")) in {"ok", "not_found"}:
            actually_held.append(provider)
        status[provider] = {
            "outcome": "skipped",
            "elapsed_seconds": 0.0,
            "error": {"reason": "held_out_for_calibration"},
        }
        key = payload_keys[provider]
        if intel_key is None:
            mutated[key] = {}
        else:
            intel = mutated.get(intel_key)
            if isinstance(intel, Mapping) and key in intel:
                intel = dict(intel)
                intel.pop(key, None)
                mutated[intel_key] = intel

    mutated[status_key] = status
    if scope is Scope.IP:
        # ``evaluate_ip_analysis`` prefers ``data['coverage']`` over the status map, so the
        # recomputed figure has to land there or the hold-out would be invisible to confidence.
        mutated["coverage"] = Coverage.from_status_map(status, expected=IP_PROVIDERS).model_dump(mode="json")
    return mutated, actually_held


@dataclass(frozen=True)
class Adjudicator:
    """Ruleset, allowlist and clock, loaded once for a whole replay."""

    cfg: ScoringConfig
    catalogue: KnownInfrastructure
    now: dt.datetime


def load_adjudicator(now: Optional[dt.datetime] = None) -> Adjudicator:
    return Adjudicator(cfg=default_config(), catalogue=load_catalogue(), now=now or _utc_now())


def replay(fixture: Fixture, *, tools: Adjudicator, held_out: Sequence[str] = ()) -> Tuple[Verdict, List[str]]:
    """Re-score one recorded fixture offline. No network, no provider, no clock dependence beyond ``tools.now``.

    Returns ``(verdict, actually_held)``. The verdict is a **replay** of recorded evidence: read
    it beside the fixture's ``recorded_at``, never as a fresh lookup.
    """
    data, actually_held = apply_hold_out(fixture.data, fixture.scope, held_out)
    coverage = _hold_out_coverage(fixture.coverage, held_out)

    if fixture.scope is Scope.IP:
        entry: Dict[str, Any] = {**data, "ip": fixture.indicator}
        decision = tools.catalogue.evaluate(
            indicator=fixture.indicator,
            indicator_type="ip",
            asn=_announcing_asn(entry),
            as_of=tools.now.date(),
        )
        verdict = verdict_engine.evaluate_ip_analysis(
            entry,
            cfg=tools.cfg,
            now=tools.now,
            coverage=coverage,
            infrastructure=decision,
        )
        return verdict, actually_held

    if fixture.scope is Scope.DOMAIN:
        verdict = verdict_engine.evaluate_domain_intel(data, cfg=tools.cfg, now=tools.now)
        return verdict, actually_held

    display = str(data.get("url_display") or fixture.indicator)
    collection = data.get("collection")
    collection = dict(collection) if isinstance(collection, Mapping) else {}
    verdict = verdict_engine.evaluate(
        indicator=display,
        scope=IndicatorScope.URL,
        signals=verdict_signals.extract_url_signals(data.get("url_intel"), tools.cfg, tools.now, url=display),
        coverage=coverage,
        cfg=tools.cfg,
        now=tools.now,
        passive_only=bool(collection.get("passive_only", True)),
        active_collection=tuple(collection.get("active_steps") or ()),
    )
    return verdict, actually_held


def _announcing_asn(entry: Mapping[str, Any]) -> Optional[int]:
    """The ASN behind an address, for the known-infrastructure lookup.

    Mirrors ``orchestrators._announcing_asn``. Duplicated rather than imported because that
    function is private to the orchestrator and this file is a tool, not a second consumer of its
    internals; the shape it reads is the published fixture shape.
    """
    for source in (entry.get("ipinfo"), entry.get("asn_meta")):
        if not isinstance(source, Mapping):
            continue
        raw = source.get("asn")
        if raw is None or isinstance(raw, bool):
            continue
        try:
            return int(raw)
        except (TypeError, ValueError):
            continue
    return None


# --------------------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------------------

DEFAULT_POSITIVE_LABELS: Tuple[str, ...] = ("MALICIOUS",)


@dataclass
class EvaluationReport:
    """What a replay found, and precisely what it is allowed to claim about it."""

    generated_at: str
    replayed_at: str
    fixture_dir: str
    ruleset_version: str
    ruleset_source: str
    positive_labels: Tuple[str, ...]
    held_out_feeds: Tuple[str, ...]
    held_out_providers: Tuple[str, ...]
    temporal_after: Optional[str]
    temporal_before: Optional[str]
    fixture_count_total: int
    evaluated: int
    excluded: Dict[str, int]
    confusion: Dict[str, int]
    by_label_verdict: Dict[str, Dict[str, int]]
    recorded_between: Dict[str, Optional[str]]
    fixture_age_days: Dict[str, Optional[float]]
    hold_out_answering_fixtures: int
    hold_out_valid: bool
    accuracy: Optional[Dict[str, float]]
    accuracy_withheld_reason: Optional[str]
    claim: str
    caveats: List[str]
    problems: List[str]
    rows: List[Dict[str, Any]]

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "schema": REPORT_SCHEMA,
            "harness_version": HARNESS_VERSION,
            "generated_at": self.generated_at,
            "replayed_at": self.replayed_at,
            "fixture_dir": self.fixture_dir,
            "ruleset_version": self.ruleset_version,
            "ruleset_source": self.ruleset_source,
            "positive_labels": list(self.positive_labels),
            "hold_out": {
                "feeds": list(self.held_out_feeds),
                "providers": list(self.held_out_providers),
                "answering_fixtures": self.hold_out_answering_fixtures,
                "valid": self.hold_out_valid,
            },
            "temporal_split": {
                "after": self.temporal_after,
                "before": self.temporal_before,
                "applied": bool(self.temporal_after or self.temporal_before),
            },
            "fixture_count_total": self.fixture_count_total,
            "evaluated": self.evaluated,
            "excluded": dict(self.excluded),
            "recorded_between": dict(self.recorded_between),
            "fixture_age_days": dict(self.fixture_age_days),
            "confusion": dict(self.confusion),
            "by_label_verdict": {label: dict(counts) for label, counts in self.by_label_verdict.items()},
            "accuracy": self.accuracy,
            "accuracy_withheld_reason": self.accuracy_withheld_reason,
            "claim": self.claim,
            "caveats": list(self.caveats),
            "problems": list(self.problems),
            "rows": list(self.rows),
        }


def evaluate_fixtures(
    fixtures: Sequence[Fixture],
    *,
    tools: Adjudicator,
    held_out_feeds: Sequence[str] = (),
    held_out_providers: Sequence[str] = (),
    evaluate_after: Optional[dt.datetime] = None,
    evaluate_before: Optional[dt.datetime] = None,
    positive_labels: Sequence[str] = DEFAULT_POSITIVE_LABELS,
    problems: Sequence[str] = (),
) -> EvaluationReport:
    """Replay every eligible fixture and report what the ruleset said, with the claim it earns.

    Three gates decide whether a precision figure is emitted at all:

    1. **A hold-out was requested.** No hold-out means the engine may have read the same feed
       that supplied the labels, which is the engine grading its own answer key.
    2. **Every evaluated row was labelled by a held-out feed.** One row labelled by a feed still
       in play contaminates the whole figure.
    3. **The held-out feed actually answered somewhere.** Holding out a provider that never
       responded over this corpus removes nothing, and calling that a hold-out is worse than not
       claiming one, because it looks rigorous.

    Fail any of the three and the report carries confusion counts labelled as in-sample
    agreement, plus the reason the figure is withheld. That decision is deliberately not the
    caller's to override.
    """
    resolved = resolve_held_out_providers(held_out_feeds, held_out_providers)
    positives = tuple(label.strip().upper() for label in positive_labels)
    now = tools.now

    excluded: Dict[str, int] = {
        "outside_temporal_window": 0,
        "no_first_seen": 0,
        "label_source_not_held_out": 0,
        "replay_error": 0,
    }
    rows: List[Dict[str, Any]] = []
    confusion = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    by_label_verdict: Dict[str, Dict[str, int]] = {Label.MALICIOUS.value: {}, Label.BENIGN.value: {}}
    recorded_times: List[dt.datetime] = []
    answering = 0
    contaminated_sources: List[str] = []
    all_problems = list(problems)

    held_out_feed_keys = {feed.strip().lower() for feed in held_out_feeds}

    for fixture in fixtures:
        if evaluate_after is not None or evaluate_before is not None:
            first_seen = fixture.first_seen
            if first_seen is None:
                excluded["no_first_seen"] += 1
                continue
            if evaluate_after is not None and first_seen < evaluate_after:
                excluded["outside_temporal_window"] += 1
                continue
            if evaluate_before is not None and first_seen >= evaluate_before:
                excluded["outside_temporal_window"] += 1
                continue

        try:
            verdict, actually_held = replay(fixture, tools=tools, held_out=resolved)
        except Exception as exc:  # noqa: BLE001 - one unreplayable fixture must not lose the corpus
            excluded["replay_error"] += 1
            all_problems.append(f"{fixture.path.name}: replay failed ({type(exc).__name__}: {exc})")
            continue

        if actually_held:
            answering += 1
        if held_out_feed_keys and fixture.label_source not in held_out_feed_keys:
            contaminated_sources.append(fixture.label_source)

        label = fixture.label
        verdict_label = verdict.verdict.value if hasattr(verdict.verdict, "value") else str(verdict.verdict)
        by_label_verdict[label.value][verdict_label] = by_label_verdict[label.value].get(verdict_label, 0) + 1
        predicted_positive = verdict_label.upper() in positives

        if label is Label.MALICIOUS:
            confusion["tp" if predicted_positive else "fn"] += 1
        else:
            confusion["fp" if predicted_positive else "tn"] += 1

        recorded = fixture.recorded_at
        if recorded is not None:
            recorded_times.append(recorded)
        confidence = verdict.confidence.value if hasattr(verdict.confidence, "value") else str(verdict.confidence)
        rows.append(
            {
                "indicator": fixture.indicator,
                "scope": fixture.scope.value,
                "label": label.value,
                "label_source": fixture.label_source,
                "verdict": verdict_label,
                "confidence": confidence,
                "score": verdict.score,
                "predicted_positive": predicted_positive,
                "recorded_at": _rfc3339(recorded) if recorded else None,
                "held_out_answered": sorted(actually_held),
            }
        )

    evaluated = len(rows)
    hold_out_valid = bool(resolved) and evaluated > 0 and not contaminated_sources and answering > 0

    withheld: Optional[str] = None
    accuracy: Optional[Dict[str, float]] = None
    if not resolved:
        withheld = (
            "no feed was held out. The engine reads the same feeds these labels came from, so any "
            "ratio computed here is the engine grading its own answer key. Re-run with "
            "--hold-out-feed."
        )
    elif evaluated == 0:
        withheld = "no fixture survived the filters, so there is nothing to measure."
    elif contaminated_sources:
        names = sorted(set(contaminated_sources))
        withheld = (
            f"{len(contaminated_sources)} evaluated row(s) were labelled by feed(s) that were not "
            f"held out ({', '.join(names)}). A single contaminated row makes the whole figure "
            "circular. Filter the corpus, or hold those feeds out too."
        )
    elif answering == 0:
        withheld = (
            "the held-out provider(s) never answered for any fixture in this corpus, so holding "
            "them out removed nothing. This is not a hold-out; it only looks like one."
        )
    else:
        tp, fp, fn = confusion["tp"], confusion["fp"], confusion["fn"]
        accuracy = {
            "precision": round(tp / (tp + fp), 4) if (tp + fp) else 0.0,
            "recall": round(tp / (tp + fn), 4) if (tp + fn) else 0.0,
        }

    ages = [round((now - stamp).total_seconds() / 86400.0, 2) for stamp in recorded_times]
    noun = "fixture" if evaluated == 1 else "fixtures"
    if hold_out_valid and accuracy is not None:
        span = ""
        if recorded_times:
            span = (
                f", replayed from fixtures recorded "
                f"{_rfc3339(min(recorded_times))[:10]}..{_rfc3339(max(recorded_times))[:10]}"
            )
        claim = (
            f"tuned against {evaluated} {noun}; held-out precision {accuracy['precision']:.2f}, "
            f"recall {accuracy['recall']:.2f} with {', '.join(resolved)} disabled{span}"
        )
    else:
        claim = f"tuned against {evaluated} {noun}, not yet validated"

    caveats = [
        RESIDUAL_CIRCULARITY_NOTE,
        "Every number here is a REPLAY of evidence recorded earlier. It is not a fresh lookup, and "
        "the providers were not contacted during this evaluation.",
    ]
    if not (evaluate_after or evaluate_before):
        caveats.append(
            "No temporal split was applied. A scorer tested on indicators it has already seen "
            "reported is measuring memory, not judgement. Re-run with --evaluate-after."
        )
    if ages and max(ages) > 30:
        caveats.append(
            f"The oldest fixture in this evaluation is {max(ages):.0f} days old. Provider records "
            "move; an old fixture measures the ruleset against the world as it was on the "
            "recording date."
        )
    caveats.append(
        "This harness does not and will not edit verdict/scoring.yaml. Moving calibration.status "
        "off 'unvalidated' is a deliberate operator edit made after reading a held-out report."
    )

    return EvaluationReport(
        generated_at=_rfc3339(now),
        replayed_at=_rfc3339(now),
        fixture_dir="",
        ruleset_version=tools.cfg.version,
        ruleset_source=tools.cfg.source_label,
        positive_labels=positives,
        held_out_feeds=tuple(feed.strip().lower() for feed in held_out_feeds),
        held_out_providers=resolved,
        temporal_after=_rfc3339(evaluate_after) if evaluate_after else None,
        temporal_before=_rfc3339(evaluate_before) if evaluate_before else None,
        fixture_count_total=len(fixtures),
        evaluated=evaluated,
        excluded=excluded,
        confusion=confusion,
        by_label_verdict=by_label_verdict,
        recorded_between={
            "earliest": _rfc3339(min(recorded_times)) if recorded_times else None,
            "latest": _rfc3339(max(recorded_times)) if recorded_times else None,
        },
        fixture_age_days={"min": min(ages) if ages else None, "max": max(ages) if ages else None},
        hold_out_answering_fixtures=answering,
        hold_out_valid=hold_out_valid,
        accuracy=accuracy,
        accuracy_withheld_reason=withheld,
        claim=claim,
        caveats=caveats,
        problems=all_problems,
        rows=rows,
    )


def render_report(report: EvaluationReport) -> str:
    """The human summary. Leads with the claim the run earns, not with the numbers."""
    lines: List[str] = []
    lines.append("=" * 78)
    lines.append("CALIBRATION REPLAY -- RECORDED EVIDENCE, RE-SCORED OFFLINE")
    lines.append("=" * 78)
    lines.append("")
    lines.append(f"THE CLAIM THIS RUN SUPPORTS: {report.claim}")
    lines.append("")
    lines.append(f"Ruleset            : {report.ruleset_version} ({report.ruleset_source or 'packaged'})")
    lines.append(f"Fixtures on disk   : {report.fixture_count_total}")
    lines.append(f"Evaluated          : {report.evaluated}")
    for reason, count in sorted(report.excluded.items()):
        if count:
            lines.append(f"  excluded ({reason}): {count}")
    lines.append(
        f"Evidence recorded  : {report.recorded_between['earliest'] or 'n/a'} .. "
        f"{report.recorded_between['latest'] or 'n/a'}"
    )
    lines.append(f"Replayed at        : {report.replayed_at}")
    age_max = report.fixture_age_days.get("max")
    lines.append(f"Evidence age       : up to {age_max:.1f} days old" if age_max is not None else "Evidence age: n/a")
    lines.append("")
    lines.append("HOLD-ONE-FEED-OUT")
    lines.append(f"  Feeds held out   : {', '.join(report.held_out_feeds) or 'NONE'}")
    lines.append(f"  Providers disabled: {', '.join(report.held_out_providers) or 'NONE'}")
    lines.append(f"  Fixtures where a held-out provider had answered: {report.hold_out_answering_fixtures}")
    lines.append(f"  Valid hold-out   : {'yes' if report.hold_out_valid else 'NO'}")
    lines.append("")
    lines.append("TEMPORAL SPLIT")
    lines.append(f"  first_seen >= {report.temporal_after or 'unset'}")
    lines.append(f"  first_seen <  {report.temporal_before or 'unset'}")
    lines.append("")
    lines.append("COUNTS")
    confusion = report.confusion
    lines.append(
        f"  malicious-labelled : {confusion['tp']} scored positive, {confusion['fn']} not "
        f"(positive = {', '.join(report.positive_labels)})"
    )
    lines.append(f"  benign-labelled    : {confusion['fp']} scored positive, {confusion['tn']} not")
    for label, counts in sorted(report.by_label_verdict.items()):
        if not counts:
            continue
        rendered = ", ".join(f"{verdict}={count}" for verdict, count in sorted(counts.items()))
        lines.append(f"  {label:<18} : {rendered}")
    lines.append("")
    if report.accuracy is not None:
        lines.append("HELD-OUT ACCURACY")
        lines.append(f"  precision : {report.accuracy['precision']:.4f}")
        lines.append(f"  recall    : {report.accuracy['recall']:.4f}")
    else:
        lines.append("ACCURACY WITHHELD -- THE COUNTS ABOVE ARE IN-SAMPLE AGREEMENT, NOT ACCURACY")
        lines.append(f"  {report.accuracy_withheld_reason}")
    lines.append("")
    lines.append("CAVEATS")
    for caveat in report.caveats:
        lines.append(f"  - {caveat}")
    if report.problems:
        lines.append("")
        lines.append("PROBLEMS")
        for problem in report.problems:
            lines.append(f"  - {problem}")
    lines.append("")
    lines.append("=" * 78)
    return "\n".join(lines)


# --------------------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="calibrate.py",
        description=(
            "Record real provider responses for labelled indicators, and replay them against the "
            "verdict engine offline. Spends the operator's API quota; run it by hand, never from "
            "a script."
        ),
        epilog="Full documentation, including what this discloses to providers: tools/README.md",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    plan = sub.add_parser("plan", help="print the cost and disclosure plan and exit. Contacts nothing")
    plan.add_argument("--labels", required=True, type=Path, help="labelled indicator CSV")
    plan.add_argument("--fixture-dir", type=Path, default=DEFAULT_FIXTURE_DIR)
    plan.add_argument("--url-depth", choices=list(URL_DEPTHS), default="full")
    plan.add_argument("--min-interval", type=float, default=DEFAULT_MIN_INTERVAL)

    record = sub.add_parser("record", help="record real provider responses. SPENDS QUOTA")
    record.add_argument("--labels", required=True, type=Path, help="labelled indicator CSV")
    record.add_argument("--fixture-dir", type=Path, default=DEFAULT_FIXTURE_DIR)
    record.add_argument("--url-depth", choices=list(URL_DEPTHS), default="full")
    record.add_argument(
        "--min-interval",
        type=float,
        default=DEFAULT_MIN_INTERVAL,
        help=f"seconds between indicators (default {DEFAULT_MIN_INTERVAL:g}; lower it deliberately or not at all)",
    )
    record.add_argument("--deadline", type=float, default=DEFAULT_DEADLINE, help="wall-clock ceiling per indicator")
    record.add_argument("--limit", type=int, default=0, help="record at most N indicators this run (0 = no limit)")
    record.add_argument(
        "--overwrite",
        action="store_true",
        help="re-record indicators that already have a fixture. Spends quota again; off by default",
    )
    record.add_argument(
        QUOTA_FLAG,
        dest="acknowledged",
        action="store_true",
        help="required. Without it this subcommand refuses to do anything",
    )

    evaluate = sub.add_parser("evaluate", help="replay recorded fixtures offline. Contacts nothing")
    evaluate.add_argument("--fixture-dir", type=Path, default=DEFAULT_FIXTURE_DIR)
    evaluate.add_argument(
        "--hold-out-feed",
        action="append",
        default=[],
        metavar="FEED",
        help=(
            "disable the provider that supplied this feed's labels before scoring, and evaluate "
            "only rows that feed labelled. Repeatable. Without it, no accuracy figure is emitted"
        ),
    )
    evaluate.add_argument(
        "--hold-out-provider",
        action="append",
        default=[],
        metavar="PROVIDER",
        help="disable an orchestrator provider key directly, for a hold-out a feed name cannot express",
    )
    evaluate.add_argument(
        "--evaluate-after", metavar="DATE", help="evaluate only rows whose first_seen is on/after this"
    )
    evaluate.add_argument(
        "--evaluate-before", metavar="DATE", help="evaluate only rows whose first_seen is before this"
    )
    evaluate.add_argument(
        "--positive-includes-suspicious",
        action="store_true",
        help="count SUSPICIOUS as a positive prediction as well as MALICIOUS",
    )
    evaluate.add_argument("--report-out", type=Path, help="also write the full report as JSON to this path")
    return parser


def _command_plan(args: argparse.Namespace, *, stream: TextIO) -> int:
    label_set = load_label_set(args.labels)
    plan = build_plan(
        label_set.rows,
        env=os.environ,
        fixture_dir=args.fixture_dir,
        already_recorded=len(completed_fixture_ids(args.fixture_dir) & {row.fixture_id for row in label_set.rows}),
        url_depth=args.url_depth,
        min_interval=args.min_interval,
        label_problems=label_set.problems,
    )
    print(render_plan(plan), file=stream)
    print("\nThis was a dry run. Nothing was contacted and nothing was written.", file=stream)
    return EXIT_OK


def _command_record(args: argparse.Namespace, *, stream: TextIO) -> int:
    if not args.acknowledged:
        print(
            f"REFUSED: {QUOTA_FLAG} was not given.\n"
            "This subcommand contacts real OSINT providers with your API keys, spends your quota, "
            "and writes every indicator into their logs against your account. Read tools/README.md, "
            "then pass the flag if that is what you intend.",
            file=stream,
        )
        return EXIT_REFUSED

    label_set = load_label_set(args.labels)
    rows = list(label_set.rows)
    already = completed_fixture_ids(args.fixture_dir) & {row.fixture_id for row in rows}
    if args.limit and args.limit > 0:
        pending = [row for row in rows if row.fixture_id not in already]
        rows = [*(row for row in rows if row.fixture_id in already), *pending[: args.limit]]

    plan = build_plan(
        rows,
        env=os.environ,
        fixture_dir=args.fixture_dir,
        already_recorded=len(already),
        url_depth=args.url_depth,
        min_interval=args.min_interval,
        label_problems=label_set.problems,
    )
    try:
        confirm(plan, stream=stream, reader=input, interactive=sys.stdin.isatty())
    except ConfirmationError as exc:
        print(f"\nREFUSED: {exc}", file=stream)
        return EXIT_REFUSED

    tools = load_adjudicator()
    recorder = LiveRecorder(deadline=args.deadline, url_depth=args.url_depth)
    summary = asyncio.run(
        record_all(
            rows,
            recorder=recorder,
            fixture_dir=args.fixture_dir,
            ruleset_version=tools.cfg.version,
            url_depth=args.url_depth,
            min_interval=args.min_interval,
            stream=stream,
            overwrite=args.overwrite,
        )
    )
    print(
        f"\nrecorded {summary.recorded}, skipped {summary.skipped} (already had fixtures), failed {summary.failed}",
        file=stream,
    )
    for indicator, reason in summary.failures:
        print(f"  failed: {indicator}: {reason}", file=stream)
    print(
        "\nRecording is not validation. Run `evaluate --hold-out-feed <feed>` before any accuracy "
        "claim, and leave scoring.yaml's calibration.status alone until you have read one.",
        file=stream,
    )
    return summary.exit_code


def _command_evaluate(args: argparse.Namespace, *, stream: TextIO) -> int:
    fixtures, problems = load_fixtures(args.fixture_dir)
    if not fixtures:
        print(f"No fixtures under {args.fixture_dir / RECORDS_DIRNAME}. Record some first.", file=stream)
        for problem in problems:
            print(f"  {problem}", file=stream)
        return EXIT_ERROR

    after = _parse_timestamp(args.evaluate_after) if args.evaluate_after else None
    before = _parse_timestamp(args.evaluate_before) if args.evaluate_before else None
    positives = ("MALICIOUS", "SUSPICIOUS") if args.positive_includes_suspicious else DEFAULT_POSITIVE_LABELS

    tools = load_adjudicator()
    report = evaluate_fixtures(
        fixtures,
        tools=tools,
        held_out_feeds=args.hold_out_feed,
        held_out_providers=args.hold_out_provider,
        evaluate_after=after,
        evaluate_before=before,
        positive_labels=positives,
        problems=problems,
    )
    report.fixture_dir = str(args.fixture_dir)
    print(render_report(report), file=stream)
    if args.report_out:
        args.report_out.parent.mkdir(parents=True, exist_ok=True)
        args.report_out.write_text(
            json.dumps(report.to_json_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"report written to {args.report_out}", file=stream)
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None, *, stream: Optional[TextIO] = None) -> int:
    """Entry point. Refuses to run in a test runner or CI before parsing anything.

    The guard is first and applies to every subcommand, including the two that contact nothing.
    A narrower guard would need a reader to verify that ``evaluate`` really is offline today and
    stays offline tomorrow; an unconditional one needs no such argument.
    """
    stream = sys.stdout if stream is None else stream
    try:
        assert_not_test_environment()
    except GuardError as exc:
        print(f"REFUSED: {exc}", file=stream)
        return EXIT_GUARD

    args = build_parser().parse_args(argv)
    # Credentials are needed to disclose which providers will be asked under a named account, and
    # to make the calls at all. Reading a local .env contacts nothing and spends nothing; it
    # happens after the guard so a test or CI process never reaches it.
    load_env()

    try:
        if args.command == "plan":
            return _command_plan(args, stream=stream)
        if args.command == "record":
            return _command_record(args, stream=stream)
        return _command_evaluate(args, stream=stream)
    except CalibrationError as exc:
        print(f"REFUSED: {exc}", file=stream)
        return EXIT_REFUSED
    except KeyboardInterrupt:
        print(
            "\nInterrupted. Everything recorded so far is on disk and journalled; re-run the same "
            "command to resume where it stopped.",
            file=stream,
        )
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
