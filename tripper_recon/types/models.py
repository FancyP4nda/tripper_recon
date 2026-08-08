"""The typed surface of an investigation: what was asked, what answered, and what was not.

Roadmap W4.1 / W4.4 / W4.5 live here. The problem these models exist to solve is a rendering
problem with a data cause: with two of six credentials configured, the console showed one
VirusTotal score and one Shodan error and said nothing at all about the four providers that
were never asked. Sparse output reads as a clean indicator. The truth was in the data --
``orchestrators._status_map`` has recorded a per-provider outcome since W3.6 -- and absent
from the screen.

Three additions close that gap, and all three serialise through ``-o json`` for free because
they are pydantic models on :class:`InvestigationResult`:

* :class:`Coverage` -- "N of M providers answered", with the names in each bucket. Its whole
  design rule is that a provider with no API key is MISSING COVERAGE, not an excuse.
* :class:`RunMetadata` -- tool version, a timezone-aware UTC timestamp, and one run id shared
  by every target in a run. None of the three reached output before.
* :class:`SkippedAddress` -- the addresses the private/reserved guard refused. On the domain
  path these currently vanish from the output entirely: an analyst is not told that three of
  four resolved addresses were internal and deliberately not investigated.

Design note for the verdict engine (W5). It consumes :class:`Coverage` to compute confidence
under one absolute rule: **absent data never scores as clean.** Every default here is chosen
so that the lazy path is the safe one. An empty ``Coverage`` has a ratio of ``0.0``, not
``1.0``. ``InvestigationResult.coverage`` may be ``None``, so
:attr:`InvestigationResult.coverage_or_unknown` is the accessor the engine should use -- it
returns zero coverage rather than ``None``, and there is no code path in which a division by
zero silently becomes full coverage.
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from pydantic import BaseModel, Field, computed_field, field_serializer, field_validator, model_validator

from tripper_recon import __version__


class ProviderStatus(str, Enum):
    """What happened when one provider was asked about one indicator.

    The distinction between ``NOT_CONFIGURED`` and ``OK`` is the point of this enum. A
    provider that was never asked because no credential exists produces no data, and so does a
    provider that was asked and found nothing -- but only one of those is evidence. Collapsing
    them is how "never asked" starts rendering as "came back clean".

    ``OK``, ``ERROR`` and ``NOT_CONFIGURED`` are the three values ``orchestrators._envelope``
    produces today; their wire strings are what ``data['provider_status'][name]['outcome']``
    already contains, so they are not renamed here. ``NOT_FOUND`` and ``SKIPPED`` complete the
    W4.1 set for callers that can distinguish them: a provider that answered "no record" and a
    provider that was deliberately not consulted. The roadmap spells ``OK`` as ``answered``;
    that spelling is accepted as an input alias so either name parses.

    Two properties carry the semantics the verdict engine needs, so no caller has to re-derive
    which outcomes count as evidence:

    * :attr:`is_observation` -- the provider was consulted and its answer means something.
    * :attr:`is_missing_coverage` -- the provider contributed nothing, for any reason. There is
      no third category, and the two are exact complements.
    """

    #: The provider answered and its payload is in :attr:`ProviderCall.data`.
    OK = "ok"
    #: The provider was asked and holds no record of this indicator. An observation, not a gap.
    NOT_FOUND = "not_found"
    #: The call was made and failed. Details are in :attr:`ProviderCall.error`.
    ERROR = "error"
    #: No credential, so no request was made. Absence of data here means nothing at all.
    NOT_CONFIGURED = "not_configured"
    #: Deliberately not consulted (guard refused the target, provider not applicable, budget).
    SKIPPED = "skipped"

    @classmethod
    def _missing_(cls, value: object) -> Optional[ProviderStatus]:
        """Accept the roadmap's spellings and casing variants; never guess at unknown values.

        ``answered`` is the roadmap's name for :attr:`OK`, and hyphen/underscore drift between
        ``not_found`` and ``not-found`` is the kind of thing a hand-written fixture gets wrong.
        Anything genuinely unrecognised still raises, because silently mapping an unknown
        outcome onto a known one is exactly the class of bug this module exists to prevent.
        """
        if not isinstance(value, str):
            return None
        key = value.strip().casefold().replace("-", "_")
        aliases: Dict[str, ProviderStatus] = {
            "answered": cls.OK,
            "ok": cls.OK,
            "not_found": cls.NOT_FOUND,
            "notfound": cls.NOT_FOUND,
            "error": cls.ERROR,
            "not_configured": cls.NOT_CONFIGURED,
            "notconfigured": cls.NOT_CONFIGURED,
            "skipped": cls.SKIPPED,
        }
        return aliases.get(key)

    @property
    def is_observation(self) -> bool:
        """True when the provider was consulted and its answer is evidence."""
        return self in {ProviderStatus.OK, ProviderStatus.NOT_FOUND}

    @property
    def is_missing_coverage(self) -> bool:
        """True when this provider contributed nothing, whatever the reason."""
        return not self.is_observation


#: Retained name for the enum. ``orchestrators`` imports ``ProviderOutcome`` and that import
#: is owned by another lane; this alias keeps it working while the W4 name is the documented
#: one. Both refer to the same class, so they cannot drift.
ProviderOutcome = ProviderStatus


class ProviderCall(BaseModel):
    """One provider call: what came back, whether it worked, and what it cost.

    Produced by ``orchestrators._call_provider`` for every outbound provider call in the
    package. It replaces the 23 copies of ``try / await / except`` that each flattened a
    failure into a bare ``{}`` at the data-assembly step.

    Fields deliberately kept apart:

    * :attr:`data` is populated only on :attr:`ProviderStatus.OK`. It is the provider's own
      ``data`` sub-dict, unchanged, which is what the renderer consumes.
    * :attr:`error` is the redacted ``_error_payload`` with ``ok`` and null fields stripped.
      Every string in it has been through ``utils.redact``.
    * :attr:`summary` is the one-line form that lands in ``InvestigationResult.errors``.
    * :attr:`suppressed` records the ``_should_suppress`` decision at call time, so the
      rendering layer can choose to hide an expected failure without the data being discarded.
      Suppression is a rendering decision and never a coverage decision: a suppressed call is
      still counted as missing coverage by :meth:`Coverage.from_status_map`.
    """

    #: Label used for suppression and in the error summary; not always the output key.
    provider: str
    outcome: ProviderStatus
    #: Wall-clock seconds spent awaiting this provider, including its internal retries.
    elapsed_seconds: float = Field(default=0.0, ge=0.0)
    data: Dict[str, Any] = Field(default_factory=dict)
    error: Dict[str, Any] = Field(default_factory=dict)
    summary: str = Field(default="")
    suppressed: bool = Field(default=False)

    @property
    def ok(self) -> bool:
        return self.outcome is ProviderStatus.OK


def _dedupe(names: Iterable[str]) -> List[str]:
    """Order-preserving dedupe. Provider order is stable output, so sorting is not an option."""
    seen: Dict[str, None] = {}
    for name in names:
        if name not in seen:
            seen[name] = None
    return list(seen)


class Coverage(BaseModel):
    """How much of the intended provider set actually answered, by name.

    **A provider with no API key is MISSING COVERAGE, not an excuse.** That is the single
    semantic this model exists to enforce. An unconfigured provider is counted in the
    denominator and never in the numerator, so a run with two of six credentials reports
    ``2 of 6``. There is no mode, flag or constructor argument that shrinks the denominator to
    the providers that happened to be configured -- that arrangement would make an
    unconfigured tool look fully covered, which is the failure this whole workstream exists to
    remove.

    Buckets:

    * :attr:`answered` -- consulted, answer is evidence. This is the numerator, and it
      includes the not-found responses.
    * :attr:`not_found` -- a documented **subset** of :attr:`answered`: asked, no record held.
      Kept separately because "no record" and "here is the record" are different evidence, and
      a verdict weighing corroboration needs to tell them apart.
    * :attr:`errored`, :attr:`unconfigured`, :attr:`skipped` -- the three ways to contribute
      nothing. All three sit in the denominator only.

    Conflicts resolve toward less coverage, never more. If the same provider name lands in
    :attr:`answered` and in any missing bucket -- which happens when a caller merges the
    per-IP coverages of a domain without namespacing the names -- the name is dropped from
    :attr:`answered`. The result under-states coverage rather than over-stating it, which is
    the direction that cannot mislead an analyst.

    The zero value is deliberate: ``Coverage()`` has :attr:`ratio` ``0.0``,
    :attr:`is_complete` ``False`` and :attr:`is_sufficient` ``False``. Nothing known is never
    treated as everything clean, including when the denominator is zero.
    """

    answered: List[str] = Field(default_factory=list)
    not_found: List[str] = Field(default_factory=list)
    errored: List[str] = Field(default_factory=list)
    unconfigured: List[str] = Field(default_factory=list)
    skipped: List[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _normalise(self) -> Coverage:
        """Dedupe every bucket and resolve cross-bucket conflicts toward missing coverage."""
        self.errored = _dedupe(self.errored)
        self.unconfigured = _dedupe(self.unconfigured)
        self.skipped = _dedupe(self.skipped)

        missing = set(self.errored) | set(self.unconfigured) | set(self.skipped)
        answered = [name for name in _dedupe(self.answered) if name not in missing]
        answered_set = set(answered)
        self.answered = answered
        # not_found is a subset of answered by contract, enforced rather than assumed.
        self.not_found = [name for name in _dedupe(self.not_found) if name in answered_set]
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def answered_count(self) -> int:
        """The N in "N of M providers answered"."""
        return len(self.answered)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def applicable_count(self) -> int:
        """The M: every provider that was intended for this indicator, configured or not."""
        return len(self.answered) + len(self.errored) + len(self.unconfigured) + len(self.skipped)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def missing(self) -> List[str]:
        """Every provider that contributed nothing, in bucket order. The gap, by name."""
        return [*self.errored, *self.unconfigured, *self.skipped]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ratio(self) -> float:
        """Answered over applicable, in ``[0.0, 1.0]``.

        Zero applicable providers yields ``0.0``. Not ``1.0``, and not a
        ``ZeroDivisionError`` that a caller might paper over with a default of ``1.0``: an
        investigation that consulted nobody has no coverage.
        """
        total = self.applicable_count
        if total <= 0:
            return 0.0
        return round(len(self.answered) / total, 4)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_complete(self) -> bool:
        """True only when at least one provider was applicable and none is missing."""
        return self.applicable_count > 0 and not self.missing

    @computed_field  # type: ignore[prop-decorator]
    @property
    def headline(self) -> str:
        """The line W4.4 requires on every render: ``2 of 6 providers answered``."""
        total = self.applicable_count
        noun = "provider" if total == 1 else "providers"
        return f"{len(self.answered)} of {total} {noun} answered"

    def is_sufficient(self, minimum: float = 0.5) -> bool:
        """Whether coverage clears a floor, for the W5.4 confidence rule.

        ``minimum`` is a ratio in ``[0.0, 1.0]``. Zero applicable providers is never
        sufficient, whatever the floor -- including a floor of ``0.0``, which would otherwise
        pass an investigation that asked nobody anything.
        """
        if self.applicable_count <= 0:
            return False
        return self.ratio >= minimum

    @classmethod
    def from_status_map(
        cls,
        status_map: Mapping[str, Mapping[str, Any]],
        *,
        expected: Optional[Sequence[str]] = None,
        prefix: str = "",
    ) -> Coverage:
        """Build coverage from ``data['provider_status']`` as ``orchestrators._status_map`` writes it.

        Each value is read for its ``outcome`` key. An outcome that is absent, or that is not
        one of :class:`ProviderStatus`, is filed as :attr:`errored` -- the conservative
        reading, because an outcome nobody can interpret is not an observation.

        ``expected`` names the providers that were meant to be consulted for this indicator.
        Any expected name with no entry in ``status_map`` is filed as :attr:`skipped`, which
        is what keeps a provider that was never even attempted from quietly shrinking the
        denominator. Pass it wherever the intended provider set is known.

        ``prefix`` namespaces the names, for callers merging several maps into one coverage --
        the domain path has one status map per resolved address plus one for the domain
        itself, and without a prefix the same provider name would collide across them.
        """
        buckets: Dict[ProviderStatus, List[str]] = {status: [] for status in ProviderStatus}
        unreadable: List[str] = []

        for name, entry in status_map.items():
            label = f"{prefix}{name}"
            raw = entry.get("outcome") if isinstance(entry, Mapping) else None
            try:
                status = ProviderStatus(raw)
            except ValueError:
                unreadable.append(label)
                continue
            buckets[status].append(label)

        seen = set(status_map)
        never_attempted = [f"{prefix}{name}" for name in (expected or ()) if name not in seen]

        answered = [*buckets[ProviderStatus.OK], *buckets[ProviderStatus.NOT_FOUND]]
        return cls(
            answered=answered,
            not_found=list(buckets[ProviderStatus.NOT_FOUND]),
            errored=[*buckets[ProviderStatus.ERROR], *unreadable],
            unconfigured=list(buckets[ProviderStatus.NOT_CONFIGURED]),
            skipped=[*buckets[ProviderStatus.SKIPPED], *never_attempted],
        )

    @classmethod
    def merge(cls, coverages: Iterable[Coverage]) -> Coverage:
        """Union of several coverages, bucket by bucket.

        Names are expected to be namespaced by the caller (see ``prefix`` on
        :meth:`from_status_map`). Where they are not, the model validator resolves the
        collision toward missing coverage, so a merge can under-state but never over-state.
        """
        answered: List[str] = []
        not_found: List[str] = []
        errored: List[str] = []
        unconfigured: List[str] = []
        skipped: List[str] = []
        for coverage in coverages:
            answered.extend(coverage.answered)
            not_found.extend(coverage.not_found)
            errored.extend(coverage.errored)
            unconfigured.extend(coverage.unconfigured)
            skipped.extend(coverage.skipped)
        return cls(
            answered=answered,
            not_found=not_found,
            errored=errored,
            unconfigured=unconfigured,
            skipped=skipped,
        )


class SkipReason(str, Enum):
    """Why an address was refused before any provider was asked.

    The values are the lowercased labels ``orchestrators._NON_PUBLIC_CATEGORIES`` already
    emits into ``data['skipped_ips'][*]['reason']``, so an existing payload parses unchanged.
    """

    PRIVATE = "private"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link-local"
    MULTICAST = "multicast"
    RESERVED = "reserved"
    UNSPECIFIED = "unspecified"
    #: Anything else. The raw text is preserved in :attr:`SkippedAddress.detail`.
    OTHER = "other"

    @classmethod
    def _missing_(cls, value: object) -> Optional[SkipReason]:
        """Normalise casing and ``link_local``/``link-local`` drift; fall back to ``OTHER``.

        Falling back rather than raising is right for this enum specifically: the field's job
        is to explain a refusal to an analyst, and an unrecognised reason must still be
        reported. :meth:`SkippedAddress.from_mapping` keeps the original wording in
        ``detail`` so nothing is lost by the fallback.
        """
        if not isinstance(value, str):
            return None
        key = value.strip().casefold().replace("_", "-")
        for member in cls:
            if member.value == key:
                return member
        return cls.OTHER


class SkippedAddress(BaseModel):
    """An address that was resolved and then deliberately not investigated.

    The verified gap this closes: on the domain path, addresses the private/reserved guard
    refuses disappear from the output entirely. An analyst is shown one enriched address and
    is never told that the other three resolved to internal space and were withheld from five
    third-party providers on purpose. Silence there reads as "the domain resolves to one
    address", which is false.

    A skipped address is missing coverage in the same sense as an unconfigured provider: no
    question was asked, so no answer may be inferred. It is never evidence of anything about
    the address.
    """

    #: The address as resolved, unmodified.
    address: str
    #: Why it was refused.
    reason: SkipReason
    #: Where the address came from: ``active``, ``passive`` or ``active+passive``.
    source: Optional[str] = None
    #: Original reason text when it did not map to a known :class:`SkipReason`.
    detail: Optional[str] = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def explanation(self) -> str:
        """One analyst-facing sentence, carried in the JSON so both renderers agree."""
        reason = self.detail if self.reason is SkipReason.OTHER and self.detail else self.reason.value
        origin = f" ({self.source})" if self.source else ""
        return f"{self.address}{origin} was not investigated: {reason} addressing is never sent to a provider"

    @classmethod
    def from_mapping(cls, entry: Mapping[str, Any]) -> SkippedAddress:
        """Parse one ``data['skipped_ips']`` entry: ``{'ip', 'source', 'reason'}``.

        ``address`` is also accepted for ``ip``, so a caller building these directly does not
        have to know which key the orchestrator happened to use. An explicit ``detail`` on the
        entry is preserved; failing that, an unrecognised ``reason`` becomes the detail, so no
        wording is lost on the way in.
        """
        raw_address = entry.get("ip") or entry.get("address") or ""
        raw_reason = entry.get("reason")
        reason = SkipReason(raw_reason) if isinstance(raw_reason, str) else SkipReason.OTHER
        raw_detail = entry.get("detail")
        detail = str(raw_detail) if raw_detail else None
        if detail is None and reason is SkipReason.OTHER and raw_reason is not None:
            detail = str(raw_reason)
        source = entry.get("source")
        return cls(
            address=str(raw_address),
            reason=reason,
            source=str(source) if source is not None else None,
            detail=detail,
        )


def _utc_now() -> datetime:
    """Timezone-aware UTC. ``datetime.utcnow()`` returns a naive value and is never used here."""
    return datetime.now(timezone.utc)


class RunMetadata(BaseModel):
    """Which tool produced this result, when, and under which run (roadmap W4.5).

    None of the three reached output before: the console header was ``--- IP lookup for {ip}
    ---`` and nothing else, ``__version__`` was defined and never read, and the package had no
    ``datetime`` import at all. A saved report that cannot say what produced it, or when,
    cannot be defended in a ticket three months later.

    :attr:`started_at` is always timezone-aware UTC. A naive datetime is rejected rather than
    assumed to be UTC, because assuming is how a report acquires a timestamp that is wrong by
    the operator's offset. It serialises as an RFC 3339 string in both ``model_dump()`` and
    ``model_dump_json()`` -- python-mode dumps are handed straight to ``rich.print_json``,
    which cannot serialise a ``datetime``.

    :attr:`run_id` is deterministic per run, not per target: :func:`current_run` caches one
    instance for the process so every target in a bulk run carries the same id and the lines
    can be correlated afterwards.
    """

    tool: str = Field(default="tripper-recon")
    tool_version: str = Field(default=__version__)
    run_id: str
    started_at: datetime

    @field_validator("started_at")
    @classmethod
    def _require_aware_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            raise ValueError("started_at must be timezone-aware; a naive datetime has no defensible meaning")
        return value.astimezone(timezone.utc)

    @field_serializer("started_at")
    def _serialise_started_at(self, value: datetime) -> str:
        return _rfc3339(value)

    @property
    def started_at_rfc3339(self) -> str:
        """The timestamp as RFC 3339 UTC, e.g. ``2026-08-08T14:03:11.482913Z``.

        Not a computed field: :attr:`started_at` already serialises to exactly this string, and
        a second key holding the same value invites the two to disagree.
        """
        return _rfc3339(self.started_at)

    @classmethod
    def new(cls, *, now: Optional[datetime] = None, run_id: Optional[str] = None) -> RunMetadata:
        """Mint metadata for one run. ``now`` and ``run_id`` are injectable for tests."""
        started = now or _utc_now()
        if started.tzinfo is None or started.tzinfo.utcoffset(started) is None:
            raise ValueError("now must be timezone-aware")
        started = started.astimezone(timezone.utc)
        return cls(run_id=run_id or _mint_run_id(started), started_at=started)


def _rfc3339(value: datetime) -> str:
    """RFC 3339 in UTC with a ``Z`` designator, which ``isoformat()`` renders as ``+00:00``."""
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _mint_run_id(started: datetime) -> str:
    """Sortable-by-time, unique per run. The timestamp prefix makes a run id greppable in logs."""
    return f"{started.astimezone(timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"


_RUN_LOCK = threading.Lock()
_CURRENT_RUN: Optional[RunMetadata] = None


def current_run() -> RunMetadata:
    """The one :class:`RunMetadata` for this process, minted on first use.

    "Deterministic per run" means every target investigated by a single invocation carries the
    same :attr:`RunMetadata.run_id` and the same :attr:`RunMetadata.started_at`. A bulk run
    over forty addresses produces forty results that can be correlated to one another and to
    the log lines that describe them.
    """
    global _CURRENT_RUN
    with _RUN_LOCK:
        if _CURRENT_RUN is None:
            _CURRENT_RUN = RunMetadata.new()
        return _CURRENT_RUN


def reset_run(run: Optional[RunMetadata] = None) -> RunMetadata:
    """Replace the cached run. For tests, and for a long-lived process starting a new run."""
    global _CURRENT_RUN
    with _RUN_LOCK:
        _CURRENT_RUN = run or RunMetadata.new()
        return _CURRENT_RUN


class ApiKeys(BaseModel):
    cloudflare_api_token: Optional[str] = Field(default=None)
    vt_api_key: Optional[str] = Field(default=None)
    shodan_api_key: Optional[str] = Field(default=None)
    abuseipdb_api_key: Optional[str] = Field(default=None)
    ipinfo_token: Optional[str] = Field(default=None)
    otx_api_key: Optional[str] = Field(default=None)


class Settings(BaseModel):
    timeout_seconds: float = Field(default=15.0)
    rate_limit: int = Field(default=5)
    api_keys: ApiKeys = Field(default_factory=ApiKeys)


class IPQuery(BaseModel):
    ip: str


class DomainQuery(BaseModel):
    domain: str


class ASNQuery(BaseModel):
    asn: int


class InvestigationResult(BaseModel):
    """One investigation of one indicator.

    ``ok``, ``data``, ``warnings`` and ``errors`` are unchanged. The three W4 fields are
    optional and default to nothing, so every existing construction site keeps working while
    the orchestrator and console lanes wire them up.

    Read :attr:`coverage` through :attr:`coverage_or_unknown` in any code that scores or
    renders confidence. ``coverage is None`` means coverage was not computed, which is not the
    same as full coverage and must never be rendered as though it were.
    """

    ok: bool
    data: Dict[str, Any] = Field(default_factory=dict)
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    #: Provenance for the run that produced this result (W4.5).
    run: Optional[RunMetadata] = Field(default=None)
    #: "N of M providers answered" (W4.4). ``None`` means not computed, never "all answered".
    coverage: Optional[Coverage] = Field(default=None)
    #: Addresses the non-public guard refused, which otherwise vanish from the output (W4.4).
    skipped_addresses: List[SkippedAddress] = Field(default_factory=list)

    @property
    def coverage_or_unknown(self) -> Coverage:
        """:attr:`coverage`, or zero coverage when it was never computed.

        The accessor exists so that "we did not measure coverage" and "coverage is zero" reach
        a scoring rule as the same conservative value. Neither can be mistaken for a clean
        result, and neither raises, so there is no tempting ``or Coverage(answered=all)``
        fallback for a caller to write.
        """
        return self.coverage if self.coverage is not None else Coverage()

    def with_run(self, run: Optional[RunMetadata] = None) -> InvestigationResult:
        """Return a copy stamped with run metadata, defaulting to :func:`current_run`."""
        return self.model_copy(update={"run": run or current_run()})


def skipped_addresses_from_data(entries: Optional[Sequence[Mapping[str, Any]]]) -> List[SkippedAddress]:
    """Parse ``data['skipped_ips']`` into typed records, tolerating a missing or empty key."""
    if not entries:
        return []
    return [SkippedAddress.from_mapping(entry) for entry in entries if isinstance(entry, Mapping)]


def coverage_from_result_data(
    data: Mapping[str, Any],
    *,
    expected: Optional[Sequence[str]] = None,
    domain_expected: Optional[Sequence[str]] = None,
) -> Coverage:
    """Coverage for a whole ``InvestigationResult.data``, whichever orchestrator produced it.

    Handles the three shapes the package emits:

    * IP and ASN -- one ``provider_status`` map at the top level.
    * Domain -- a ``domain_provider_status`` map for the domain-level providers, plus one
      ``provider_status`` map per entry in ``data['ips']``.

    Per-address maps are namespaced with the address so the same provider name consulted about
    four addresses produces four countable entries rather than one. ``expected`` applies to
    the per-address maps, ``domain_expected`` to the domain-level one.

    Addresses in ``data['skipped_ips']`` are not represented here. They are not a provider gap
    -- no provider was asked about them by design -- and they are reported separately through
    :func:`skipped_addresses_from_data`, so folding them in would double-count the omission.
    """
    parts: List[Coverage] = []

    top = data.get("provider_status")
    if isinstance(top, Mapping):
        parts.append(Coverage.from_status_map(top, expected=expected))

    domain_status = data.get("domain_provider_status")
    if isinstance(domain_status, Mapping):
        parts.append(Coverage.from_status_map(domain_status, expected=domain_expected, prefix="domain:"))

    for entry in data.get("ips") or []:
        if not isinstance(entry, Mapping):
            continue
        per_ip = entry.get("provider_status")
        if not isinstance(per_ip, Mapping):
            continue
        address = str(entry.get("ip") or "?")
        parts.append(Coverage.from_status_map(per_ip, expected=expected, prefix=f"{address}:"))

    return Coverage.merge(parts)
