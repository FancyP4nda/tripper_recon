"""Tier A/B/C infrastructure overrides -- roadmap 5.6.

This module answers one question: *is this address published infrastructure, and if so what does
that entitle the engine to do about it?* It is the only component permitted to produce a benign
conclusion, and it is deliberately the dullest one -- a dated snapshot of publisher-issued ranges,
an index over it, and a precedence rule.

**The three tiers, and why A and B are not the same thing.**

``A`` is absolute. Public DNS resolvers and the root nameservers force
``KNOWN_INFRASTRUCTURE`` and short-circuit scoring. These addresses carry permanent nonzero
VirusTotal and AbuseIPDB residue -- they are the far end of every DNS tunnel and every scanner's
first packet -- and an engine that reports ``MALICIOUS`` for ``1.1.1.1`` even once has spent its
credibility. Tier A is the price of not doing that, and it is kept small and sourced because it
is also the only way a genuinely bad address could be silenced.

``B`` is a cap, not an allowlist, and confusing the two is the failure this module exists to
prevent. Shared hosting is where malware actually lives. A Tier B match zeroes the signals that
describe the *edge* rather than the *tenant* (the ASN's reputation, its hijack history, the
Shodan surface), caps the **IP-level** verdict at ``SUSPICIOUS``, attaches an attribution
warning, and leaves **domain-level scoring completely untouched**. Too strong and every phishing
site behind a CDN reads clean; too weak and every CDN address reads suspicious. Both are real and
this is the only shape that avoids both.

``C`` is a note. Declared scanners and crawlers accumulate abuse reports as a property of what
they do, so those two signals are suppressed and nothing else is. A scanner range that starts
serving malware still scores on VirusTotal and OTX, and Tier C never says an address is safe.

**Everything numeric or nameable lives in the YAML.** No verdict label, signal id, cap, warning
string, range or ASN appears as a literal in this file. What is here is structure: how a match is
found, how precedence resolves, and how staleness is reported. :data:`_VERDICT_LABELS` is the one
near-exception and it is a taxonomy check rather than a tunable -- see its comment.

**Staleness is reported, not prevented.** A shipped snapshot cannot know that a publisher handed
a range back, and a range that moved keeps matching here and keeps suppressing signal on whatever
moved in. There is no runtime fix for that which does not put a third party on the analysis path,
so the design goal is detectability: every entry carries a retrieval date, every decision carries
the oldest retrieval date among the entries that actually matched, and
:attr:`InfraDecision.stale` turns that into a flag the renderer can show. A decision that matched
nothing still reports the catalogue-level date, so an old file is visible on a miss too.
"""

from __future__ import annotations

import bisect
import hashlib
import ipaddress
import os
import threading
from datetime import date
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

import yaml
from pydantic import BaseModel, Field, field_serializer, field_validator, model_validator

#: Path of the packaged catalogue. Overridable per call, or process-wide via the environment
#: variable below, so an operator can ship a site-specific allowlist without forking the package.
DEFAULT_CATALOGUE_PATH = Path(__file__).with_name("known_infrastructure.yaml")

#: Environment override for :func:`load_catalogue`, mirroring ``TRIPPER_RECON_SCORING_CONFIG``.
CATALOGUE_PATH_ENV = "TRIPPER_RECON_KNOWN_INFRASTRUCTURE"

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# The five verdict labels from the design taxonomy. This is a spelling check on the YAML, not a
# tunable: a typo in `forces_verdict` would otherwise reach the engine as an unknown label and be
# discovered at render time on a real investigation. The authoritative enum lives with the verdict
# models; keeping a frozenset here avoids a circular import between the catalogue and the engine.
_VERDICT_LABELS = frozenset(
    {
        "MALICIOUS",
        "SUSPICIOUS",
        "NO_ADVERSE_FINDINGS",
        "INSUFFICIENT_DATA",
        "KNOWN_INFRASTRUCTURE",
    }
)


class InfraTier(str, Enum):
    """Which override tier an entry belongs to.

    The letters are identifiers, not strengths -- the behaviour attached to each is entirely in
    the YAML ``tiers:`` block. Ordering matters only for precedence, which
    :data:`_TIER_PRECEDENCE` states once.
    """

    A = "A"
    B = "B"
    C = "C"


#: Precedence when several tiers match one address: A beats B beats C. Structural, not tunable --
#: an allowlisted resolver inside a CDN range must resolve to the allowlist every time, and the
#: design fixes that ordering deliberately for predictability.
_TIER_PRECEDENCE: Dict[InfraTier, int] = {InfraTier.A: 0, InfraTier.B: 1, InfraTier.C: 2}


class CatalogueError(ValueError):
    """The catalogue file is missing, unreadable, or internally inconsistent.

    Raised at load time and never swallowed. A silently-empty allowlist is indistinguishable from
    a correct one until it lets a false positive through, so refusing to start is the safe
    behaviour.
    """


class AsnRange(BaseModel):
    """One ASN or one inclusive ASN range, as the registry states it.

    Registries hand out blocks -- ARIN returns a single autnum object spanning 8068-8075 for
    Microsoft -- and recording the block as queried would either lose the siblings or invent
    membership for them. Both endpoints are kept as published.
    """

    start: int = Field(ge=0)
    end: int = Field(ge=0)

    @model_validator(mode="after")
    def _ordered(self) -> AsnRange:
        if self.end < self.start:
            raise ValueError(f"ASN range {self.start}-{self.end} ends before it starts")
        return self

    def contains(self, asn: int) -> bool:
        return self.start <= asn <= self.end

    def __str__(self) -> str:
        return f"AS{self.start}" if self.start == self.end else f"AS{self.start}-AS{self.end}"

    @classmethod
    def parse(cls, value: Any) -> AsnRange:
        """Accept ``13335``, ``"13335"``, ``"AS13335"`` or ``"8068-8075"``.

        Anything else raises. Guessing at an unparseable ASN would put an unintended network in a
        suppression list, which is precisely the error class this module is defending against.
        """
        if isinstance(value, bool):  # bool is an int subclass; it is never a valid ASN
            raise ValueError(f"invalid ASN entry: {value!r}")
        if isinstance(value, int):
            return cls(start=value, end=value)
        if isinstance(value, str):
            text = value.strip().upper().replace("AS", "")
            if "-" in text:
                low, _, high = text.partition("-")
                try:
                    return cls(start=int(low), end=int(high))
                except ValueError as exc:
                    raise ValueError(f"invalid ASN range: {value!r}") from exc
            try:
                number = int(text)
            except ValueError as exc:
                raise ValueError(f"invalid ASN entry: {value!r}") from exc
            return cls(start=number, end=number)
        raise ValueError(f"invalid ASN entry: {value!r}")


class TierPolicy(BaseModel):
    """What a match in one tier is entitled to do.

    Every field is read from the YAML. The engine asks the policy what happened; it does not know
    which tier implied what, which is what keeps a retune to a data edit.
    """

    tier: InfraTier
    label: str
    #: Set only on Tier A. The single path to a benign verdict in the whole engine.
    forces_verdict: Optional[str] = None
    #: Set only on Tier B. A ceiling, never a floor -- it can lower a verdict and never raise one.
    caps_verdict: Optional[str] = None
    #: Signal ids whose contribution is discarded because they describe the operator, not the target.
    zeroed_signals: List[str] = Field(default_factory=list)
    #: Signal ids suppressed with a note. Entries may narrow or widen this for themselves.
    suppressed_signals: List[str] = Field(default_factory=list)
    #: Indicator types this tier acts on. ``ip`` only, by design: domain scoring stays untouched.
    applies_to: List[str] = Field(default_factory=list)
    attribution_warning: Optional[str] = None
    note: str = ""

    @field_validator("forces_verdict", "caps_verdict")
    @classmethod
    def _known_label(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        if value not in _VERDICT_LABELS:
            raise ValueError(f"unknown verdict label {value!r}; expected one of {sorted(_VERDICT_LABELS)}")
        return value

    @field_validator("applies_to")
    @classmethod
    def _lowercase_types(cls, value: List[str]) -> List[str]:
        return [item.strip().lower() for item in value]

    def acts_on(self, indicator_type: str) -> bool:
        return indicator_type.strip().lower() in self.applies_to


class InfraEntry(BaseModel):
    """One catalogue entry: a named piece of infrastructure, its ranges, and its provenance.

    :attr:`source` and :attr:`retrieved` are mandatory. An entry that cannot say where it came
    from and when is not admissible, because the whole value of the list is that a reader can
    check it.
    """

    id: str
    tier: InfraTier
    name: str
    operator: str
    category: str
    #: URL (or URLs) the values were read from.
    source: str
    #: ``publisher_endpoint`` | ``publisher_doc`` | ``rir_rdap`` -- how much the source is worth.
    source_type: str
    retrieved: date
    cidrs: List[str] = Field(default_factory=list)
    asns: List[AsnRange] = Field(default_factory=list)
    #: Tier C only: overrides the tier's default suppression set for this entry.
    suppresses: Optional[List[str]] = None
    note: Optional[str] = None

    @field_validator("asns", mode="before")
    @classmethod
    def _parse_asns(cls, value: Any) -> Any:
        if value is None:
            return []
        if isinstance(value, (str, int)):
            return [AsnRange.parse(value)]
        if isinstance(value, Sequence):
            return [item if isinstance(item, AsnRange) else AsnRange.parse(item) for item in value]
        raise ValueError(f"invalid asns value: {value!r}")

    @field_validator("cidrs")
    @classmethod
    def _validate_cidrs(cls, value: List[str]) -> List[str]:
        """Reject anything ``ipaddress`` will not parse, and reject host bits outside the mask.

        ``strict=True`` matters: ``104.16.0.1/13`` is a typo for a network and silently
        normalising it would widen a suppression range by a factor of half a million addresses.
        Bare addresses are accepted and normalised to ``/32`` or ``/128`` by :func:`_parse_network`.
        """
        for item in value:
            _parse_network(item)
        return list(value)

    @field_serializer("retrieved")
    def _serialise_retrieved(self, value: date) -> str:
        """ISO date. ``model_dump()`` output is handed to ``rich.print_json`` elsewhere in the
        package, which cannot serialise a ``date``."""
        return value.isoformat()

    def suppression_set(self, policy: TierPolicy) -> List[str]:
        """Signal ids this entry suppresses: its own list when it has one, else the tier's."""
        return list(self.suppresses) if self.suppresses is not None else list(policy.suppressed_signals)


class InfraMatch(BaseModel):
    """One entry matched one indicator, and how.

    Matches are reported even when the tier does not act on this indicator type -- see
    :attr:`effects_applied`. Reporting a match the engine then ignores is deliberate: the analyst
    looking at a domain that resolves into a CDN should be able to see that, and hiding it would
    be the same suppression-by-silence the rest of this workstream is removing.
    """

    entry_id: str
    tier: InfraTier
    name: str
    operator: str
    category: str
    #: ``cidr`` or ``asn``.
    matched_on: str
    #: The range or ASN that matched, as published: ``104.16.0.0/13``, ``AS13335``.
    matched_value: str
    #: Prefix length for a CIDR match, so the most specific match sorts first. ``-1`` for an ASN
    #: match, which has no comparable specificity and sorts after every CIDR in the same tier.
    specificity: int
    source: str
    source_type: str
    source_retrieved: date
    #: False when this tier does not act on this indicator type. The match is context only.
    effects_applied: bool
    note: Optional[str] = None

    @field_serializer("source_retrieved")
    def _serialise_source_retrieved(self, value: date) -> str:
        return value.isoformat()


class InfraDecision(BaseModel):
    """What the catalogue concluded about one indicator.

    The engine reads the effect fields -- :attr:`forced_verdict`, :attr:`capped_verdict`,
    :attr:`zeroed_signals`, :attr:`suppressed_signals` -- and never re-derives them from
    :attr:`matches`, which may contain context-only entries for indicator types no tier acts on.

    A decision with no matches is an empty decision, not a benign one. Nothing here can produce a
    verdict except an explicit Tier A allowlist hit.
    """

    indicator: str
    indicator_type: str
    #: Address that was matched against the CIDR index, when there was one.
    ip: Optional[str] = None
    #: ASN that was matched against the ASN index, when there was one.
    asn: Optional[int] = None

    matches: List[InfraMatch] = Field(default_factory=list)

    #: Tier A only. When set, the engine short-circuits scoring and emits this label.
    forced_verdict: Optional[str] = None
    #: Tier B only. A ceiling on the IP-level verdict; it never raises a verdict.
    capped_verdict: Optional[str] = None
    #: Signals whose points are discarded (Tier B: they describe the operator, not the target).
    zeroed_signals: List[str] = Field(default_factory=list)
    #: Signals suppressed with a note (Tier C: expected consequence of declared scanning).
    suppressed_signals: List[str] = Field(default_factory=list)
    attribution_warning: Optional[str] = None

    #: Catalogue ``version:``, so a verdict in an old ticket names the list that produced it.
    list_version: str
    #: Oldest retrieval date among the matched entries, or the catalogue date when nothing matched.
    list_retrieved: date
    #: True when :attr:`list_retrieved` is older than the catalogue's ``max_age_days``.
    stale: bool
    #: One sentence naming the age and what it means. Always populated, stale or not.
    staleness_note: str
    #: Non-fatal observations: an unparseable address, an indicator type no tier acts on.
    notes: List[str] = Field(default_factory=list)

    @field_serializer("list_retrieved")
    def _serialise_list_retrieved(self, value: date) -> str:
        return value.isoformat()

    @property
    def is_empty(self) -> bool:
        """True when nothing matched. Distinct from "matched and had no effect"."""
        return not self.matches

    def override_records(self) -> List[Dict[str, Any]]:
        """The applied effects as ``OverrideApplied``-shaped dicts, one per effect.

        Keys match the verdict model's field names (``rule_id``, ``tier``, ``effect``,
        ``source_list``, ``source_retrieved_at``, ``note``) so the engine can construct the model
        without a translation layer here -- this module must not import the verdict models, or
        the catalogue and the engine become mutually dependent.

        Only matches whose tier acts on this indicator type produce records. A context-only match
        is visible in :attr:`matches` and is not an applied override.
        """
        records: List[Dict[str, Any]] = []
        for match in self.matches:
            if not match.effects_applied:
                continue
            for effect in self._effects_for(match):
                records.append(
                    {
                        "rule_id": match.entry_id,
                        "tier": match.tier.value,
                        "effect": effect,
                        "source_list": match.source,
                        "source_retrieved_at": match.source_retrieved.isoformat(),
                        "note": match.note,
                    }
                )
        return records

    def _effects_for(self, match: InfraMatch) -> List[str]:
        if match.tier is InfraTier.A:
            return ["verdict_forced"] if self.forced_verdict else []
        if match.tier is InfraTier.B:
            effects = []
            if self.capped_verdict:
                effects.append("verdict_capped")
            if self.zeroed_signals:
                effects.append("signal_zeroed")
            return effects
        effects = []
        if self.suppressed_signals:
            effects.append("signal_suppressed")
        return effects


def _parse_network(value: str) -> IPNetwork:
    """``"8.8.8.8"`` -> ``8.8.8.8/32``; ``"104.16.0.0/13"`` -> itself. Anything else raises.

    ``strict=True`` is the important half. A prefix with host bits set is a typo, and quietly
    masking it off turns a mistake in a suppression list into a much larger suppression list.
    """
    try:
        return ipaddress.ip_network(value.strip(), strict=True)
    except ValueError as exc:
        raise ValueError(f"invalid CIDR or address {value!r}: {exc}") from exc


class _NetworkIndex:
    """Prefix-length-bucketed exact-match index over one address family.

    A linear scan over every prefix is fine for one lookup and is not fine for a bulk run over a
    file of addresses, so networks are bucketed by prefix length: masking the query address to
    each length in use and probing a dict costs one dict lookup per *distinct prefix length*
    (about a dozen for this catalogue), independent of how many prefixes are in it. Longest
    prefix is probed first so the most specific match is found first.
    """

    __slots__ = ("_buckets",)

    def __init__(self, networks: Iterable[Tuple[IPNetwork, int]], bits: int) -> None:
        tables: Dict[int, Dict[int, List[Tuple[IPNetwork, int]]]] = {}
        for network, entry_index in networks:
            table = tables.setdefault(network.prefixlen, {})
            table.setdefault(int(network.network_address), []).append((network, entry_index))
        # (prefix length, mask, table), longest prefix first.
        self._buckets: List[Tuple[int, int, Dict[int, List[Tuple[IPNetwork, int]]]]] = [
            (prefixlen, ((1 << bits) - 1) ^ ((1 << (bits - prefixlen)) - 1), table)
            for prefixlen, table in sorted(tables.items(), reverse=True)
        ]

    def lookup(self, address: IPAddress) -> List[Tuple[IPNetwork, int]]:
        """Every network containing ``address``, most specific first."""
        value = int(address)
        found: List[Tuple[IPNetwork, int]] = []
        for _prefixlen, mask, table in self._buckets:
            hit = table.get(value & mask)
            if hit:
                found.extend(hit)
        return found


class _AsnIndex:
    """Sorted-interval index over ASN ranges, searched by bisect.

    Ranges are disjoint in practice but nothing requires them to be, so the search walks back
    from the insertion point rather than assuming. With a few dozen ranges this is not a
    performance question; it is a correctness one.
    """

    __slots__ = ("_starts", "_ranges")

    def __init__(self, ranges: Iterable[Tuple[AsnRange, int]]) -> None:
        ordered = sorted(ranges, key=lambda item: (item[0].start, item[0].end))
        self._starts: List[int] = [item[0].start for item in ordered]
        self._ranges: List[Tuple[AsnRange, int]] = ordered

    def lookup(self, asn: int) -> List[Tuple[AsnRange, int]]:
        found: List[Tuple[AsnRange, int]] = []
        position = bisect.bisect_right(self._starts, asn)
        for index in range(position - 1, -1, -1):
            asn_range, entry_index = self._ranges[index]
            if asn_range.contains(asn):
                found.append((asn_range, entry_index))
        return found


class KnownInfrastructure:
    """The loaded catalogue: entries, tier policy, and the indexes over them.

    Construct through :meth:`from_mapping` or :func:`load_catalogue`. Instances are immutable in
    practice and safe to share across a bulk run; :func:`load_catalogue` caches one per path.
    """

    def __init__(
        self,
        *,
        version: str,
        retrieved: date,
        max_age_days: int,
        tiers: Mapping[InfraTier, TierPolicy],
        entries: Sequence[InfraEntry],
        deliberately_omitted: Sequence[Mapping[str, Any]] = (),
        source_path: Optional[Path] = None,
    ) -> None:
        self.version = version
        self.retrieved = retrieved
        self.max_age_days = max_age_days
        self.tiers = dict(tiers)
        self.entries = list(entries)
        self.deliberately_omitted = [dict(item) for item in deliberately_omitted]
        self.source_path = source_path

        v4: List[Tuple[IPNetwork, int]] = []
        v6: List[Tuple[IPNetwork, int]] = []
        asns: List[Tuple[AsnRange, int]] = []
        for index, entry in enumerate(self.entries):
            for raw in entry.cidrs:
                network = _parse_network(raw)
                (v6 if network.version == 6 else v4).append((network, index))
            for asn_range in entry.asns:
                asns.append((asn_range, index))
        self._v4 = _NetworkIndex(v4, bits=32)
        self._v6 = _NetworkIndex(v6, bits=128)
        self._asn = _AsnIndex(asns)

    # -- construction ------------------------------------------------------------------------

    @classmethod
    def from_mapping(cls, document: Mapping[str, Any], *, source_path: Optional[Path] = None) -> KnownInfrastructure:
        """Validate a parsed YAML document into a catalogue.

        Every failure here is a :class:`CatalogueError`. A catalogue that half-loads is worse
        than one that refuses to: the missing half is a suppression rule that silently is not
        there, and nothing downstream can tell.
        """
        if not isinstance(document, Mapping):
            raise CatalogueError("catalogue root must be a mapping")

        try:
            version = str(document["version"])
            retrieved = _coerce_date(document["retrieved"], field="retrieved")
            max_age_days = int(document["max_age_days"])
        except KeyError as exc:
            raise CatalogueError(f"catalogue is missing required key {exc.args[0]!r}") from exc
        except (TypeError, ValueError) as exc:
            raise CatalogueError(f"catalogue header is malformed: {exc}") from exc

        if max_age_days <= 0:
            raise CatalogueError("max_age_days must be positive; staleness must always be computable")

        raw_tiers = document.get("tiers")
        if not isinstance(raw_tiers, Mapping) or not raw_tiers:
            raise CatalogueError("catalogue must define a non-empty `tiers` mapping")
        tiers: Dict[InfraTier, TierPolicy] = {}
        for key, body in raw_tiers.items():
            try:
                tier = InfraTier(str(key).strip().upper())
            except ValueError as exc:
                raise CatalogueError(f"unknown tier {key!r}") from exc
            if not isinstance(body, Mapping):
                raise CatalogueError(f"tier {tier.value} policy must be a mapping")
            try:
                tiers[tier] = TierPolicy(tier=tier, **dict(body))
            except Exception as exc:  # pydantic ValidationError and friends
                raise CatalogueError(f"tier {tier.value} policy is invalid: {exc}") from exc

        cls._check_tier_invariants(tiers)

        raw_entries = document.get("entries") or []
        if not isinstance(raw_entries, Sequence) or isinstance(raw_entries, (str, bytes)):
            raise CatalogueError("`entries` must be a list")
        entries: List[InfraEntry] = []
        seen: Dict[str, int] = {}
        for position, raw in enumerate(raw_entries):
            if not isinstance(raw, Mapping):
                raise CatalogueError(f"entry at position {position} is not a mapping")
            try:
                entry = InfraEntry(**dict(raw))
            except Exception as exc:
                raise CatalogueError(f"entry at position {position} is invalid: {exc}") from exc
            if entry.tier not in tiers:
                raise CatalogueError(f"entry {entry.id!r} names tier {entry.tier.value} which has no policy")
            if not entry.cidrs and not entry.asns:
                raise CatalogueError(f"entry {entry.id!r} matches nothing: it has no cidrs and no asns")
            if entry.id in seen:
                raise CatalogueError(f"duplicate entry id {entry.id!r} at positions {seen[entry.id]} and {position}")
            seen[entry.id] = position
            entries.append(entry)

        omitted = document.get("deliberately_omitted") or []
        if not isinstance(omitted, Sequence) or isinstance(omitted, (str, bytes)):
            raise CatalogueError("`deliberately_omitted` must be a list when present")

        return cls(
            version=version,
            retrieved=retrieved,
            max_age_days=max_age_days,
            tiers=tiers,
            entries=entries,
            deliberately_omitted=[item for item in omitted if isinstance(item, Mapping)],
            source_path=source_path,
        )

    @staticmethod
    def _check_tier_invariants(tiers: Mapping[InfraTier, TierPolicy]) -> None:
        """Refuse a catalogue whose tier policy could make absent data look clean.

        Two rules, both structural rather than stylistic:

        * only Tier A may force a verdict, and only to the one label that means "this is fine".
          A Tier B or C policy that could force a verdict would turn a CDN membership into a
          conclusion, which is the exact error the B/A distinction exists to prevent;
        * a cap may not be the benign label. A cap lowers a verdict, and a "cap" at
          ``NO_ADVERSE_FINDINGS`` would be a benign verdict wearing a ceiling's clothing.
        """
        for tier, policy in tiers.items():
            if policy.forces_verdict and tier is not InfraTier.A:
                raise CatalogueError(
                    f"tier {tier.value} sets forces_verdict; only tier A may force a verdict "
                    "(a CDN match is a cap, never a conclusion)"
                )
            if tier is InfraTier.A and policy.caps_verdict:
                raise CatalogueError("tier A short-circuits scoring and must not also set caps_verdict")
            if policy.caps_verdict in {"NO_ADVERSE_FINDINGS", "KNOWN_INFRASTRUCTURE"}:
                raise CatalogueError(
                    f"tier {tier.value} caps at {policy.caps_verdict}; a cap may not be a benign label"
                )

    # -- lookup ------------------------------------------------------------------------------

    def match_ip(self, ip: str) -> List[InfraMatch]:
        """Every entry whose published ranges contain ``ip``, best match first.

        Raises :class:`ValueError` on an unparseable address. :meth:`evaluate` catches that and
        records it as a note rather than failing an investigation.
        """
        address = ipaddress.ip_address(ip.strip())
        index = self._v6 if address.version == 6 else self._v4
        return [
            self._build_match(
                entry_index,
                matched_on="cidr",
                matched_value=str(network),
                specificity=network.prefixlen,
            )
            for network, entry_index in index.lookup(address)
        ]

    def match_asn(self, asn: int) -> List[InfraMatch]:
        """Every entry that claims ``asn``."""
        return [
            self._build_match(
                entry_index,
                matched_on="asn",
                matched_value=str(asn_range),
                specificity=-1,
            )
            for asn_range, entry_index in self._asn.lookup(asn)
        ]

    def _build_match(self, entry_index: int, *, matched_on: str, matched_value: str, specificity: int) -> InfraMatch:
        entry = self.entries[entry_index]
        return InfraMatch(
            entry_id=entry.id,
            tier=entry.tier,
            name=entry.name,
            operator=entry.operator,
            category=entry.category,
            matched_on=matched_on,
            matched_value=matched_value,
            specificity=specificity,
            source=entry.source,
            source_type=entry.source_type,
            source_retrieved=entry.retrieved,
            effects_applied=False,  # set by evaluate(), which knows the indicator type
            note=entry.note,
        )

    def evaluate(
        self,
        *,
        indicator: str,
        indicator_type: str,
        ip: Optional[str] = None,
        asn: Optional[int] = None,
        as_of: Optional[date] = None,
    ) -> InfraDecision:
        """Match ``indicator`` and resolve the tier effects it earns.

        ``ip`` defaults to ``indicator`` when ``indicator_type`` is ``ip``. ``asn`` is the
        address's announcing ASN, which the IP path already has from IPinfo -- pass it, because
        CIDR coverage is deliberately partial for the cloud providers and ASN matching is the
        only thing that catches them.

        Effects are applied only for tiers whose ``applies_to`` includes ``indicator_type``. For
        a domain that means no effects at all: domain-level scoring is untouched by this module,
        which is what stops a phishing site behind a CDN from reading clean. Matches are still
        reported so the analyst can see the hosting context.
        """
        kind = indicator_type.strip().lower()
        notes: List[str] = []

        target_ip = ip if ip is not None else (indicator if kind == "ip" else None)
        matches: List[InfraMatch] = []
        if target_ip:
            try:
                matches.extend(self.match_ip(target_ip))
            except ValueError as exc:
                # Address validation belongs upstream; a bulk run must not abort here.
                notes.append(f"address not matched against the catalogue: {exc}")
                target_ip = None
        if asn is not None:
            matches.extend(self.match_asn(asn))

        matches = _dedupe_matches(matches)
        for match in matches:
            match.effects_applied = self.tiers[match.tier].acts_on(kind)

        forced: Optional[str] = None
        capped: Optional[str] = None
        zeroed: List[str] = []
        suppressed: List[str] = []
        warning: Optional[str] = None

        for match in matches:
            if not match.effects_applied:
                continue
            policy = self.tiers[match.tier]
            entry = self._entry_by_id(match.entry_id)
            if policy.forces_verdict and forced is None:
                forced = policy.forces_verdict
            if policy.caps_verdict and capped is None:
                capped = policy.caps_verdict
            if policy.attribution_warning and warning is None:
                warning = policy.attribution_warning
            zeroed.extend(policy.zeroed_signals)
            if match.tier is InfraTier.C:
                suppressed.extend(entry.suppression_set(policy))
            else:
                suppressed.extend(policy.suppressed_signals)

        if forced is not None:
            # Tier A short-circuits scoring, so every lower-tier effect describes a score that is
            # never computed. Two reasons to clear them rather than report them alongside the
            # force: an engine that applied `capped_verdict` after `forced_verdict` would demote
            # an allowlisted resolver to SUSPICIOUS, and an effect that had no effect should not
            # appear in override_records() as though it did. The superseded matches stay visible
            # in `matches` with effects_applied False, which is what makes the conflict auditable.
            superseded = sorted(
                {match.entry_id for match in matches if match.effects_applied and match.tier is not InfraTier.A}
            )
            if superseded:
                notes.append(
                    "tier A allowlist outranks lower-tier matches on this indicator; "
                    f"{', '.join(superseded)} matched and had no effect"
                )
                for match in matches:
                    if match.tier is not InfraTier.A:
                        match.effects_applied = False
            capped = None
            zeroed = []
            suppressed = []
            warning = None

        if matches and not any(match.effects_applied for match in matches):
            notes.append(
                f"catalogue matched {len(matches)} entr{'y' if len(matches) == 1 else 'ies'} "
                f"but no tier acts on indicator type {kind!r}; reported as context only"
            )

        effective = [match for match in matches if match.effects_applied]
        oldest = min((match.source_retrieved for match in effective), default=None)
        if oldest is None:
            oldest = min((match.source_retrieved for match in matches), default=self.retrieved)
        stale, staleness_note = self._staleness(oldest, as_of=as_of, matched=bool(matches))

        return InfraDecision(
            indicator=indicator,
            indicator_type=kind,
            ip=target_ip,
            asn=asn,
            matches=matches,
            forced_verdict=forced,
            capped_verdict=capped,
            zeroed_signals=_dedupe_strings(zeroed),
            suppressed_signals=_dedupe_strings(suppressed),
            attribution_warning=warning,
            list_version=self.version,
            list_retrieved=oldest,
            stale=stale,
            staleness_note=staleness_note,
            notes=notes,
        )

    def _entry_by_id(self, entry_id: str) -> InfraEntry:
        for entry in self.entries:
            if entry.id == entry_id:
                return entry
        raise CatalogueError(f"no entry with id {entry_id!r}")  # unreachable via evaluate()

    def _staleness(self, retrieved: date, *, as_of: Optional[date], matched: bool) -> Tuple[bool, str]:
        """Age of the data behind this decision, and whether it has passed ``max_age_days``.

        The note is written even when the list is fresh. A reader who only ever sees the sentence
        on a stale list has no way to calibrate what its absence means.
        """
        today = as_of or date.today()
        age = (today - retrieved).days
        subject = "matched allowlist data" if matched else "catalogue"
        if age > self.max_age_days:
            return True, (
                f"{subject} retrieved {retrieved.isoformat()}, {age} days old, past the "
                f"{self.max_age_days}-day refresh age -- a reassigned range would still match here, "
                "so treat any suppression below as unverified"
            )
        return False, f"{subject} retrieved {retrieved.isoformat()}, {age} days old (refresh age {self.max_age_days})"


def _dedupe_matches(matches: Sequence[InfraMatch]) -> List[InfraMatch]:
    """Order by tier precedence, then most specific first; keep one match per entry.

    One entry can match twice -- Cloudflare by CIDR and by ASN. Keeping both would double every
    downstream count for no added information, so the more specific match wins and the entry
    appears once.
    """
    best: Dict[str, InfraMatch] = {}
    for match in matches:
        existing = best.get(match.entry_id)
        if existing is None or match.specificity > existing.specificity:
            best[match.entry_id] = match
    return sorted(
        best.values(),
        key=lambda match: (_TIER_PRECEDENCE[match.tier], -match.specificity, match.entry_id),
    )


def _dedupe_strings(values: Iterable[str]) -> List[str]:
    """Order-preserving dedupe. Signal ids are rendered, so their order should be stable."""
    seen: Dict[str, None] = {}
    for value in values:
        if value not in seen:
            seen[value] = None
    return list(seen)


def _coerce_date(value: Any, *, field: str) -> date:
    """Accept a YAML date or an ISO string. Reject anything else rather than guessing.

    PyYAML parses an unquoted ``2026-08-08`` into a ``date`` and a quoted one into a ``str``, and
    both spellings occur in hand-edited files.
    """
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip())
        except ValueError as exc:
            raise ValueError(f"{field} is not an ISO date: {value!r}") from exc
    raise ValueError(f"{field} must be a date, got {type(value).__name__}")


_CACHE_LOCK = threading.Lock()
_CACHE: Dict[Tuple[str, str], KnownInfrastructure] = {}


def catalogue_path(path: Optional[Union[str, Path]] = None) -> Path:
    """Resolve which catalogue to load: explicit path, then the environment, then the package."""
    if path is not None:
        return Path(path)
    from_env = os.environ.get(CATALOGUE_PATH_ENV)
    if from_env:
        return Path(from_env)
    return DEFAULT_CATALOGUE_PATH


def load_catalogue(path: Optional[Union[str, Path]] = None, *, use_cache: bool = True) -> KnownInfrastructure:
    """Load and validate a catalogue, caching by path and file mtime.

    The cache key includes the file's size and modification time, so editing the YAML during a
    long-lived process picks the change up without a stale-cache footgun. Pass
    ``use_cache=False`` to force a re-read.

    Raises :class:`CatalogueError` when the file is missing, unparseable, or fails validation.
    Failing loudly is the point: an empty allowlist looks exactly like a working one until it
    lets a false positive through.
    """
    resolved = catalogue_path(path)
    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        raise CatalogueError(f"cannot read known-infrastructure catalogue at {resolved}: {exc}") from exc

    # Keyed on content, not on mtime and size. Those are the conventional cache key and they are
    # wrong here: filesystems with coarse timestamp resolution (and same-length edits, which a
    # version bump usually is) produce an identical key for different content, and a stale
    # allowlist served from cache is exactly the failure this module is built to make visible.
    # Hashing costs one read of a small file per load; the parse and validation are what the
    # cache is actually saving.
    key = (str(resolved), hashlib.sha256(text.encode("utf-8")).hexdigest())
    if use_cache:
        with _CACHE_LOCK:
            cached = _CACHE.get(key)
        if cached is not None:
            return cached

    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise CatalogueError(f"known-infrastructure catalogue at {resolved} is not valid YAML: {exc}") from exc

    catalogue = KnownInfrastructure.from_mapping(raw, source_path=resolved)
    if use_cache:
        with _CACHE_LOCK:
            _CACHE[key] = catalogue
    return catalogue


def clear_cache() -> None:
    """Drop the load cache. For tests and for a process that rewrites the catalogue in place."""
    with _CACHE_LOCK:
        _CACHE.clear()


def evaluate_indicator(
    *,
    indicator: str,
    indicator_type: str,
    ip: Optional[str] = None,
    asn: Optional[int] = None,
    as_of: Optional[date] = None,
    path: Optional[Union[str, Path]] = None,
) -> InfraDecision:
    """Convenience wrapper: load the packaged catalogue and evaluate one indicator."""
    return load_catalogue(path).evaluate(
        indicator=indicator,
        indicator_type=indicator_type,
        ip=ip,
        asn=asn,
        as_of=as_of,
    )
