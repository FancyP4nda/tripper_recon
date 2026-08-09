"""Per-provider TTL cache and the case directory (roadmap 7.7).

**The rule this module exists to enforce: a cached fact must never claim to have been queried
now.** Everything below -- the entry envelope, the lookup states, the freshness summary, the
case record -- is machinery for keeping one distinction alive from the moment a payload is
replayed to the moment somebody reads the report three weeks later:

    "VirusTotal says 12/94"  and  "VirusTotal said 12/94, forty-one minutes ago"

are different claims. The second is defensible and the first is not, and the only thing standing
between them is whether the tool bothered to carry the timestamp. A report that presents a
three-week-old cached answer as a fresh lookup is worse than no report at all, because it
launders staleness into apparent currency.

So three properties are structural here rather than conventional:

* **Every stored payload carries ``queried_at``**, the instant the request actually left, and it
  is never rewritten on replay. :class:`CacheEntry` is frozen; there is no setter to get it
  wrong.
* **Every replay is announced.** :meth:`CacheSession.lookup` records what it did under the
  cache key, ``orchestrators._status_map`` copies that record onto the per-provider status entry,
  and :func:`summarise_freshness` folds the lot into the ``freshness`` block that reaches both
  ``-o json`` and the console warning list. There is no path that serves a cached value silently.
* **Offline refuses rather than degrades.** In ``--offline`` mode a miss or an expired entry
  produces a ``skipped`` provider outcome naming the gap -- never the stale value. That costs
  coverage, which is the honest price: an answer nobody can date is not an answer.

**What is cached, and what is not.** Only successful payloads (``payload['ok'] is True``). A
failure is not a fact worth replaying: an unset API key, a 429 and a network blip are all states
of the world at one instant, and re-serving them would turn a transient outage into a persistent
one. A provider that errored is asked again on the next run.

**The key.** ``sha256(schema | tool version | scope | provider | indicator)``. The tool version
is in there deliberately: a provider module's extraction shape can change between releases, and
replaying a payload shaped for the previous parser is a subtler version of the same lie. A
version bump therefore invalidates the cache wholesale, which is the safe direction.

**Where things land on disk.**

* The cache defaults to ``$XDG_CACHE_HOME/tripper_recon`` (``~/.cache/tripper_recon``), outside
  the repository entirely, so nothing here can be committed by accident.
* Case directories default to ``<cwd>/outputs/cases``. ``.gitignore`` ignores ``outputs/`` as a
  DIRECTORY, and git does not descend into an ignored directory, so every case written under the
  default is covered -- including its evidence envelopes, whose ``*.json`` names would otherwise
  rely on the blanket ``*.json`` rule. A case directory placed elsewhere with ``--case-dir`` is
  the operator's own call and is not covered; :func:`write_case` says so in the case record.

.. note::
   ``cache.yaml`` ships beside this module and is read through ``importlib.resources``. It is
   NOT yet declared in ``[tool.setuptools.package-data]`` (that file belongs to another lane), so
   an installed wheel may not carry it. The loader degrades to a conservative built-in default
   with a stated source label rather than raising -- a cache is an optimisation and must never
   take a run down -- but the per-provider table lives only in the YAML, so a wheel without it
   caches everything for the short default and says which state it is in.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import tempfile
from contextlib import contextmanager
from contextvars import ContextVar, Token
from enum import Enum
from importlib import resources
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, NamedTuple, Optional, Sequence, Tuple

from pydantic import BaseModel, ConfigDict, Field

from tripper_recon import __version__
from tripper_recon.utils.logging import logger
from tripper_recon.utils.redact import redact_url

try:  # pragma: no cover - exercised by the ImportError test via monkeypatching
    import yaml
except ImportError:  # pragma: no cover - see the module docstring note
    yaml = None

log = logger("cache")

__all__ = [
    "CACHE_CONFIG_ENV_VAR",
    "CACHE_CONFIG_SCHEMA",
    "CACHE_DIR_ENV_VAR",
    "CACHE_ENTRY_SCHEMA",
    "CASE_SCHEMA",
    "FRESHNESS_SCHEMA",
    "FUTURE_SKEW_TOLERANCE_SECONDS",
    "PACKAGED_CACHE_CONFIG_NAME",
    "CacheConfig",
    "CacheConfigError",
    "CacheEntry",
    "CacheError",
    "CacheLookup",
    "CacheSession",
    "CacheState",
    "CaseError",
    "CasePaths",
    "active_cache",
    "cache_key",
    "case_id_for",
    "clear_cache_config_cache",
    "default_cache_config",
    "default_cache_root",
    "default_case_root",
    "format_age",
    "freshness_warnings",
    "load_cache_config",
    "load_case",
    "parse_duration",
    "summarise_freshness",
    "use_cache",
    "write_case",
]

#: Schema tag on every stored entry. Read before the entry is constructed, so a file written by
#: a future version is discarded as a miss rather than raising out of ``extra="forbid"``.
CACHE_ENTRY_SCHEMA = "tripper-recon.cache-entry/1"

#: Schema tag on ``cache.yaml``.
CACHE_CONFIG_SCHEMA = "tripper-recon.cache-config/1"

#: Schema tag on the ``freshness`` block published onto ``result.data``.
FRESHNESS_SCHEMA = "tripper-recon.freshness/1"

#: Schema tag on ``case.json``.
CASE_SCHEMA = "tripper-recon.case/1"

#: An explicit TTL ruleset, beating both the user override and the packaged file.
CACHE_CONFIG_ENV_VAR = "TRIPPER_RECON_CACHE_CONFIG"

#: Where cached provider answers live. Beaten only by an explicit ``--cache-dir``.
CACHE_DIR_ENV_VAR = "TRIPPER_RECON_CACHE_DIR"

#: The filename in the user override directory and in this package.
PACKAGED_CACHE_CONFIG_NAME = "cache.yaml"

#: Directory under ``$XDG_CONFIG_HOME`` / ``~/.config`` searched for a TTL override.
USER_CONFIG_SUBDIR = "tripper_recon"

#: The conservative lifetime used when no configuration can be read at all. Short on purpose:
#: guessing long about an unknown provider is the failure this module exists to prevent.
FALLBACK_TTL_SECONDS = 3600

#: How far into the future a stored ``queried_at`` may sit before the entry is refused outright.
#:
#: An entry whose acquisition time is in the future cannot be aged: the arithmetic yields a
#: negative number, and a reader that clamps it at zero reports the entry as **maximally fresh**
#: -- "obtained 0s ago" -- while also slipping past any ``--max-age``, because nothing is older
#: than a limit when everything is zero seconds old. That is this module's own rule failing in
#: the one direction it may not fail, so a future stamp is treated like an unreadable one and the
#: entry is discarded rather than trusted.
#:
#: The tolerance exists because a few seconds of backwards clock correction (NTP stepping, a VM
#: resuming) is ordinary and harmless, and refusing on it would flush the cache for no gain.
#: Anything beyond it is skew, a cache directory copied from another host, or an edited file --
#: none of which is a basis for a freshness claim.
FUTURE_SKEW_TOLERANCE_SECONDS = 5.0


class CacheError(RuntimeError):
    """Base class for the two failures a caller might reasonably catch."""


class CacheConfigError(CacheError):
    """``cache.yaml`` exists and could not be read as a TTL ruleset."""


class CaseError(CacheError):
    """A case directory could not be written, or a case record could not be read."""


# --------------------------------------------------------------------------------------
# Durations and ages, in the two directions a human needs them
# --------------------------------------------------------------------------------------

_DURATION_RE = re.compile(r"^\s*(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>[smhdw]?)\s*$", re.IGNORECASE)

_DURATION_UNITS: Dict[str, float] = {
    "": 1.0,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
    "d": 86400.0,
    "w": 604800.0,
}


def parse_duration(text: str) -> float:
    """Parse ``30``, ``90s``, ``15m``, ``6h``, ``7d``, ``2w`` into seconds.

    Raises :class:`ValueError` on anything else. A ``--max-age`` the tool guessed at would be a
    freshness guarantee the operator never actually made, so an unparseable value is refused
    rather than defaulted.
    """
    match = _DURATION_RE.match(text or "")
    if match is None:
        raise ValueError(
            f"could not read {text!r} as a duration: expected a number of seconds, "
            "or a number with a unit (s, m, h, d, w) -- for example 90s, 15m, 6h, 7d"
        )
    value = float(match.group("value"))
    if value < 0:
        raise ValueError("a duration cannot be negative")
    return value * _DURATION_UNITS[match.group("unit").lower()]


def format_age(seconds: Optional[float]) -> str:
    """Render an age the way a reader under time pressure reads it: coarse and unambiguous.

    ``None`` is ``"unknown"`` rather than ``"0s"``. An age the tool could not compute is exactly
    the case where a zero would be read as "just now".
    """
    if seconds is None:
        return "unknown"
    total = max(0.0, float(seconds))
    if total < 60:
        return f"{int(total)}s"
    if total < 3600:
        return f"{int(total // 60)}m"
    if total < 86400:
        hours = int(total // 3600)
        minutes = int((total % 3600) // 60)
        return f"{hours}h" if minutes == 0 else f"{hours}h {minutes}m"
    days = int(total // 86400)
    hours = int((total % 86400) // 3600)
    return f"{days}d" if hours == 0 else f"{days}d {hours}h"


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _rfc3339(value: dt.datetime) -> str:
    """RFC 3339 UTC with a ``Z``. The one timestamp format this package writes."""
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_rfc3339(value: Any) -> Optional[dt.datetime]:
    """Read a stored timestamp back, or ``None``. Never raises: an unreadable stamp is a miss."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(dt.timezone.utc)


# --------------------------------------------------------------------------------------
# The TTL ruleset
# --------------------------------------------------------------------------------------


class CacheConfig(BaseModel):
    """How long each provider's answer may be replayed before it stops being current.

    ``extra="forbid"`` so a misspelled key is a load error rather than a provider silently
    falling back to the default lifetime -- the failure mode being that a fast-moving reputation
    feed quietly acquires a seven-day TTL because somebody typed ``abusech:`` as ``abuse_ch:``.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default=CACHE_CONFIG_SCHEMA)
    enabled: bool = Field(default=True)
    default_ttl_seconds: int = Field(default=FALLBACK_TTL_SECONDS, ge=0)
    providers: Dict[str, int] = Field(default_factory=dict)
    #: Where this ruleset came from, for the appendix of a report that has to be defended.
    source_label: str = Field(default="built-in defaults")

    def ttl_for(self, provider: str) -> int:
        """The lifetime for one provider label, falling back to :attr:`default_ttl_seconds`."""
        return int(self.providers.get(provider, self.default_ttl_seconds))


def _user_config_path() -> Path:
    base = os.getenv("XDG_CONFIG_HOME")
    root = Path(base).expanduser() if base else Path.home() / ".config"
    return root / USER_CONFIG_SUBDIR / PACKAGED_CACHE_CONFIG_NAME


def _read_yaml(path: Path) -> Dict[str, Any]:
    if yaml is None:  # pragma: no cover - guarded import, see module docstring
        raise CacheConfigError(
            "PyYAML is required to read a cache TTL ruleset. Install it, or unset "
            f"{CACHE_CONFIG_ENV_VAR} to fall back to the built-in default lifetime."
        )
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CacheConfigError(f"could not read {path}: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - yaml raises its own hierarchy
        raise CacheConfigError(f"{path} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise CacheConfigError(f"{path} must contain a mapping at the top level")
    return raw


def _build_config(raw: Mapping[str, Any], *, label: str) -> CacheConfig:
    payload = {key: value for key, value in raw.items()}
    payload["source_label"] = label
    try:
        config = CacheConfig(**payload)
    except Exception as exc:  # noqa: BLE001 - pydantic's ValidationError, re-raised as ours
        raise CacheConfigError(f"{label} is not a usable cache ruleset: {exc}") from exc
    if config.schema_version != CACHE_CONFIG_SCHEMA:
        raise CacheConfigError(
            f"{label} declares schema {config.schema_version!r}; this build reads {CACHE_CONFIG_SCHEMA!r}"
        )
    return config


def load_cache_config(path: Optional[Path] = None) -> CacheConfig:
    """Load the TTL ruleset. Precedence: argument, env var, user override, packaged file.

    An explicit path that does not exist is an error, never a silent fallback -- the operator
    asked for a specific policy and getting a different one without being told is how a
    thirty-minute lifetime becomes seven days. A MISSING packaged file is not an error: the
    result is a config with no per-provider entries and a source label that says so, so every
    provider gets the short default rather than an invented one.
    """
    explicit = path or (Path(os.environ[CACHE_CONFIG_ENV_VAR]) if os.getenv(CACHE_CONFIG_ENV_VAR) else None)
    if explicit is not None:
        resolved = Path(explicit).expanduser()
        if not resolved.is_file():
            raise CacheConfigError(f"cache ruleset {resolved} does not exist")
        return _build_config(_read_yaml(resolved), label=str(resolved))

    user = _user_config_path()
    if user.is_file():
        return _build_config(_read_yaml(user), label=str(user))

    try:
        packaged = resources.files("tripper_recon.utils").joinpath(PACKAGED_CACHE_CONFIG_NAME)
        with resources.as_file(packaged) as handle:
            if handle.is_file():
                return _build_config(_read_yaml(handle), label=f"packaged {PACKAGED_CACHE_CONFIG_NAME}")
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        pass

    log["warn"](
        "Packaged cache ruleset not found; every provider falls back to the default lifetime",
        default_ttl_seconds=FALLBACK_TTL_SECONDS,
    )
    return CacheConfig(source_label=f"built-in defaults ({PACKAGED_CACHE_CONFIG_NAME} not found)")


_CONFIG_CACHE: Optional[CacheConfig] = None


def default_cache_config() -> CacheConfig:
    """The process-wide ruleset, loaded once. :func:`clear_cache_config_cache` resets it."""
    global _CONFIG_CACHE
    if _CONFIG_CACHE is None:
        _CONFIG_CACHE = load_cache_config()
    return _CONFIG_CACHE


def clear_cache_config_cache() -> None:
    """Drop the memoised ruleset. For tests, and for a process that changed its environment."""
    global _CONFIG_CACHE
    _CONFIG_CACHE = None


# --------------------------------------------------------------------------------------
# Keys and paths
# --------------------------------------------------------------------------------------

_SLUG_RE = re.compile(r"[^a-z0-9._-]+")


def _slug(value: str) -> str:
    """A filesystem-safe directory name. Never derived from an indicator -- see :func:`_entry_path`."""
    cleaned = _SLUG_RE.sub("-", (value or "").strip().lower()).strip("-.")
    return cleaned or "other"


def cache_key(*, provider: str, scope: str, indicator: str, tool_version: str = __version__) -> str:
    """The key one provider answer is filed under.

    Four things are in it, and each earns its place by being able to change the answer:

    ``provider``
        The endpoint that was asked. ``shodan`` and ``internetdb`` share a coverage slot and are
        two different datasets, so they must not share an entry.
    ``scope``
        ``ip`` / ``domain`` / ``url`` / ``asn``. abuse.ch answers a different question about a
        host than about an exact URL.
    ``indicator``
        The thing asked about, verbatim -- so an API-key rotation does not miss, but a different
        target does.
    ``tool_version``
        Because the provider module's extraction shape can change between releases, and a payload
        shaped for the previous parser is a stale answer wearing a current schema. A version bump
        invalidates every entry, which is the safe direction.
    """
    material = "\n".join((CACHE_ENTRY_SCHEMA, tool_version, scope, provider, indicator))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class CacheState(str, Enum):
    """What the cache was able to do for one question.

    Five outcomes, and the distinctions between them are the point. ``STALE`` and ``TOO_OLD``
    both mean "an entry exists and may not be used", but only one of them is the operator's own
    ``--max-age`` talking, and an analyst debugging why a run went to the network deserves to
    know which.
    """

    #: An entry exists, is within its TTL and within any ``--max-age``. Replayed.
    HIT = "hit"
    #: Nothing is filed under this key.
    MISS = "miss"
    #: An entry exists and is past its provider TTL.
    STALE = "stale"
    #: An entry exists and is within its TTL, but older than the ``--max-age`` demanded.
    TOO_OLD = "too_old"
    #: The cache is switched off, or the entry on disk could not be read.
    DISABLED = "disabled"


class CacheEntry(BaseModel):
    """One provider answer, and the honest record of when it was actually obtained.

    Frozen. ``queried_at`` is the whole product: there is no setter, no ``touch()``, and nothing
    that rewrites it on replay, because every one of those would be a way for a cached fact to
    start claiming it was queried now.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(default=CACHE_ENTRY_SCHEMA)
    provider: str
    scope: str
    #: The indicator, through :func:`utils.redact.redact_url`. Matching is on the key, which is
    #: computed from the raw value, so redacting the stored copy costs nothing and keeps a URL's
    #: userinfo out of a file that gets attached to a ticket.
    indicator: str
    key: str
    tool_version: str = Field(default=__version__)
    #: **When the request actually left.** Not when it was stored, not when it was replayed.
    queried_at: str
    stored_at: str
    ttl_seconds: int = Field(ge=0)
    #: The provider payload exactly as ``_call_provider`` received it: ``{"ok": True, "data": …}``.
    payload: Dict[str, Any] = Field(default_factory=dict)

    def age_seconds(self, now: Optional[dt.datetime] = None) -> Optional[float]:
        """How long ago this answer was obtained, or ``None`` if the stamp is unreadable.

        Clamped at zero, because this value is what a reader is shown and a negative age is not
        a thing a human can act on. The clamp is safe **only because**
        :meth:`future_skew_seconds` is checked first: :meth:`CacheStore.get` refuses an entry
        whose stamp is meaningfully in the future rather than letting it arrive here and be
        flattened into "0s", which would read as "queried just now".
        """
        queried = _parse_rfc3339(self.queried_at)
        if queried is None:
            return None
        return max(0.0, ((now or _utc_now()) - queried).total_seconds())

    def future_skew_seconds(self, now: Optional[dt.datetime] = None) -> Optional[float]:
        """How far AHEAD of ``now`` this entry claims to have been obtained, never negative.

        ``0.0`` for every honest entry. Anything above
        :data:`FUTURE_SKEW_TOLERANCE_SECONDS` means the stamp cannot be believed, and an entry
        whose acquisition time cannot be believed cannot support a freshness claim -- which is
        the only thing a cache entry is for here.
        """
        queried = _parse_rfc3339(self.queried_at)
        if queried is None:
            return None
        return max(0.0, (queried - (now or _utc_now())).total_seconds())

    @property
    def expires_at(self) -> Optional[str]:
        queried = _parse_rfc3339(self.queried_at)
        if queried is None:
            return None
        return _rfc3339(queried + dt.timedelta(seconds=self.ttl_seconds))

    def describe(self, now: Optional[dt.datetime] = None) -> Dict[str, Any]:
        """The per-provider disclosure block copied onto ``provider_status[<name>]['cache']``."""
        age = self.age_seconds(now)
        return {
            "hit": True,
            "queried_at": self.queried_at,
            "age_seconds": None if age is None else round(age, 3),
            "age": format_age(age),
            "ttl_seconds": self.ttl_seconds,
            "expires_at": self.expires_at,
            "note": "served from cache; this value was NOT queried now",
        }


class CacheLookup(NamedTuple):
    """The result of asking the cache one question, and why it answered that way."""

    state: CacheState
    key: str
    entry: Optional[CacheEntry] = None
    age_seconds: Optional[float] = None
    reason: str = ""

    @property
    def is_hit(self) -> bool:
        return self.state is CacheState.HIT and self.entry is not None


class CacheStore:
    """A directory of cached provider answers, one JSON file per key.

    Every method here fails soft. A cache that raises has converted an optimisation into an
    outage, and the run it took down was one that could have gone to the network instead. Read
    errors become :attr:`CacheState.DISABLED` lookups; write errors are logged and dropped.
    """

    def __init__(self, root: Path, *, config: Optional[CacheConfig] = None) -> None:
        self.root = Path(root).expanduser()
        self.config = config or default_cache_config()

    def path_for(self, *, provider: str, scope: str, key: str) -> Path:
        """``<root>/<scope>/<provider>/<key>.json``.

        The indicator is never a path component. It is attacker-influenced text on the bulk path,
        and a filename derived from it is a traversal waiting to happen; the key is a hex digest
        and cannot be anything else.
        """
        return self.root / _slug(scope) / _slug(provider) / f"{key}.json"

    def get(
        self,
        *,
        provider: str,
        scope: str,
        indicator: str,
        now: Optional[dt.datetime] = None,
        max_age_seconds: Optional[float] = None,
    ) -> CacheLookup:
        """Look one answer up and classify it. Never raises, never returns a stale entry as a hit."""
        key = cache_key(provider=provider, scope=scope, indicator=indicator)
        if not self.config.enabled:
            return CacheLookup(CacheState.DISABLED, key, reason="the cache is disabled in configuration")

        path = self.path_for(provider=provider, scope=scope, key=key)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return CacheLookup(CacheState.MISS, key, reason="nothing is filed under this key")
        except (OSError, ValueError) as exc:
            log["warn"]("Discarding an unreadable cache entry", provider=provider, error=str(exc))
            return CacheLookup(CacheState.DISABLED, key, reason=f"the stored entry could not be read: {exc}")

        if not isinstance(raw, dict) or raw.get("schema_version") != CACHE_ENTRY_SCHEMA:
            return CacheLookup(
                CacheState.DISABLED,
                key,
                reason=f"the stored entry declares a schema this build does not read ({raw.get('schema_version')!r})"
                if isinstance(raw, dict)
                else "the stored entry is not an object",
            )
        try:
            entry = CacheEntry(**raw)
        except Exception as exc:  # noqa: BLE001 - a malformed entry is a miss, never a crash
            log["warn"]("Discarding a malformed cache entry", provider=provider, error=str(exc))
            return CacheLookup(CacheState.DISABLED, key, reason=f"the stored entry is malformed: {exc}")

        age = entry.age_seconds(now)
        if age is None:
            # An entry that cannot say when it was obtained is exactly the artefact this module
            # exists to prevent. It is discarded rather than trusted.
            return CacheLookup(CacheState.DISABLED, key, reason="the stored entry carries no readable queried_at")

        skew = entry.future_skew_seconds(now)
        if skew is not None and skew > FUTURE_SKEW_TOLERANCE_SECONDS:
            # A stamp in the future is worse than a missing one, because it does not merely fail
            # to support a freshness claim -- it manufactures the strongest one available. The
            # age arithmetic clamps to zero, so the entry would be served as "obtained 0s ago"
            # and would sail past any --max-age. Refused, and named, so the operator can see that
            # a clock is wrong rather than wondering why a lookup keeps going to the network.
            log["warn"](
                "Discarding a cache entry stamped in the future",
                provider=provider,
                queried_at=entry.queried_at,
                ahead_by=format_age(skew),
            )
            return CacheLookup(
                CacheState.DISABLED,
                key,
                entry=entry,
                reason=(
                    f"the stored entry claims it was obtained {format_age(skew)} in the FUTURE "
                    f"(at {entry.queried_at}); a clock is wrong or this cache came from another host, "
                    "and an entry that cannot be dated cannot be served as current"
                ),
            )

        if age > entry.ttl_seconds:
            return CacheLookup(
                CacheState.STALE,
                key,
                entry=entry,
                age_seconds=age,
                reason=f"cached {format_age(age)} ago, past its {format_age(entry.ttl_seconds)} lifetime",
            )
        if max_age_seconds is not None and age > max_age_seconds:
            return CacheLookup(
                CacheState.TOO_OLD,
                key,
                entry=entry,
                age_seconds=age,
                reason=f"cached {format_age(age)} ago, older than the {format_age(max_age_seconds)} --max-age demanded",
            )
        return CacheLookup(
            CacheState.HIT,
            key,
            entry=entry,
            age_seconds=age,
            reason=f"served from cache, obtained {format_age(age)} ago",
        )

    def put(
        self,
        *,
        provider: str,
        scope: str,
        indicator: str,
        payload: Mapping[str, Any],
        queried_at: dt.datetime,
        now: Optional[dt.datetime] = None,
    ) -> Optional[CacheEntry]:
        """File one successful answer. Returns the entry, or ``None`` when nothing was stored.

        Only successful payloads are stored. An error is a state of the world at one instant --
        a 429, a network blip, an unset key -- and replaying it would turn a transient outage
        into a persistent one that outlives its cause.
        """
        if not self.config.enabled or not payload.get("ok"):
            return None
        key = cache_key(provider=provider, scope=scope, indicator=indicator)
        entry = CacheEntry(
            provider=provider,
            scope=scope,
            indicator=redact_url(indicator),
            key=key,
            queried_at=_rfc3339(queried_at),
            stored_at=_rfc3339(now or _utc_now()),
            ttl_seconds=self.config.ttl_for(provider),
            payload=dict(payload),
        )
        path = self.path_for(provider=provider, scope=scope, key=key)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write(path, entry.model_dump_json(indent=2) + "\n")
        except OSError as exc:
            log["warn"]("Could not write a cache entry", provider=provider, error=str(exc))
            return None
        return entry


def _atomic_write(path: Path, text: str) -> None:
    """Write via a sibling temp file and ``os.replace``, so a reader never sees a half file."""
    descriptor, temp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def default_cache_root() -> Path:
    """``$TRIPPER_RECON_CACHE_DIR``, else ``$XDG_CACHE_HOME/tripper_recon``, else ``~/.cache/…``.

    Outside the repository on every branch of that chain, which is deliberate: a cache under the
    working tree would need a ``.gitignore`` rule to stay uncommitted, and a rule is a thing that
    can be edited away.
    """
    explicit = os.getenv(CACHE_DIR_ENV_VAR)
    if explicit:
        return Path(explicit).expanduser()
    base = os.getenv("XDG_CACHE_HOME")
    root = Path(base).expanduser() if base else Path.home() / ".cache"
    return root / "tripper_recon"


# --------------------------------------------------------------------------------------
# The session: one cache policy, in force for one run
# --------------------------------------------------------------------------------------


class CacheSession:
    """The cache policy for one invocation, and the record of everything it did.

    Carried in a :class:`~contextvars.ContextVar` for the same reason the evidence recorder is:
    threading a cache handle through fourteen provider signatures would put a caching decision in
    every provider module, and the whole design here is that providers know nothing about it.

    **The object is the carrier, not the ContextVar value.** ``asyncio`` copies the context when a
    task is created, so a task sees the same session instance and its mutations are visible to the
    caller after the loop finishes. Set the session BEFORE ``asyncio.run``.
    """

    def __init__(
        self,
        store: Optional[CacheStore],
        *,
        offline: bool = False,
        max_age_seconds: Optional[float] = None,
        now: Optional[dt.datetime] = None,
    ) -> None:
        self.store = store
        self.offline = offline
        self.max_age_seconds = max_age_seconds
        #: Pinned clock, when the caller supplied one. ``None`` reads the wall clock per lookup.
        self.now = now
        #: Keyed by cache key: the disclosure block for every question the cache was asked.
        self.records: Dict[str, Dict[str, Any]] = {}
        self.hits = 0
        self.misses = 0
        self.stores = 0
        self.refusals = 0

    @property
    def enabled(self) -> bool:
        return self.store is not None and self.store.config.enabled

    def clock(self) -> dt.datetime:
        """**The** clock for this run: the pinned one if the caller supplied it, else the wall.

        Public, and callers outside this module are expected to use it, because a session that
        reads ages from a pinned clock while something else stamps new entries from the wall
        clock is internally inconsistent -- entries land in the session's own future, which the
        skew check in :meth:`CacheStore.get` correctly refuses to date. One clock per run, read
        and write alike.
        """
        return self.now or _utc_now()

    def lookup(self, *, provider: str, scope: str, indicator: str) -> CacheLookup:
        """Ask the cache, and record what it said under the key. Never raises."""
        if self.store is None:
            key = cache_key(provider=provider, scope=scope, indicator=indicator)
            return CacheLookup(CacheState.DISABLED, key, reason="no cache is in use for this run")
        result = self.store.get(
            provider=provider,
            scope=scope,
            indicator=indicator,
            now=self.clock(),
            max_age_seconds=self.max_age_seconds,
        )
        if result.is_hit and result.entry is not None:
            self.hits += 1
            self.records[result.key] = result.entry.describe(self.clock())
        else:
            self.misses += 1
            self.records[result.key] = {
                "hit": False,
                "state": result.state.value,
                "reason": result.reason,
                "age_seconds": None if result.age_seconds is None else round(result.age_seconds, 3),
                "age": format_age(result.age_seconds) if result.age_seconds is not None else None,
            }
        return result

    def store_payload(
        self,
        *,
        provider: str,
        scope: str,
        indicator: str,
        payload: Mapping[str, Any],
        queried_at: dt.datetime,
    ) -> None:
        """File a fresh answer, and mark the per-provider record as a live lookup."""
        key = cache_key(provider=provider, scope=scope, indicator=indicator)
        self.records[key] = {"hit": False, "state": "fresh", "reason": "queried now", "age_seconds": 0.0, "age": "0s"}
        if self.store is None:
            return
        entry = self.store.put(
            provider=provider,
            scope=scope,
            indicator=indicator,
            payload=payload,
            queried_at=queried_at,
            now=self.clock(),
        )
        if entry is not None:
            self.stores += 1

    def note_refusal(self, *, provider: str, scope: str, indicator: str, reason: str) -> None:
        """Record that ``--offline`` refused to answer this question, and why."""
        key = cache_key(provider=provider, scope=scope, indicator=indicator)
        self.refusals += 1
        self.records[key] = {"hit": False, "state": "offline_refused", "reason": reason, "offline": True}

    def record_for(self, *, provider: str, scope: str, indicator: str) -> Optional[Dict[str, Any]]:
        """The disclosure block for one question, for ``_status_map`` to copy onto the status."""
        return self.records.get(cache_key(provider=provider, scope=scope, indicator=indicator))

    def summary(self) -> Dict[str, Any]:
        """Run-level counters, for the case record and for a debugging operator."""
        return {
            "enabled": self.enabled,
            "offline": self.offline,
            "max_age_seconds": self.max_age_seconds,
            "root": str(self.store.root) if self.store is not None else None,
            "ruleset": self.store.config.source_label if self.store is not None else None,
            "hits": self.hits,
            "misses": self.misses,
            "stores": self.stores,
            "offline_refusals": self.refusals,
        }


_ACTIVE: ContextVar[Optional[CacheSession]] = ContextVar("tripper_recon_cache_session", default=None)


def active_cache() -> Optional[CacheSession]:
    """The session in force, or ``None`` -- in which case nothing is cached and nothing changes."""
    return _ACTIVE.get()


@contextmanager
def use_cache(session: Optional[CacheSession]) -> Iterator[Optional[CacheSession]]:
    """Install ``session`` for the duration of the block.

    Must be entered BEFORE ``asyncio.run``: a task copies the context at creation, so a session
    installed inside the loop is invisible to tasks created before it.
    """
    token: Token[Optional[CacheSession]] = _ACTIVE.set(session)
    try:
        yield session
    finally:
        _ACTIVE.reset(token)


# --------------------------------------------------------------------------------------
# Freshness: the distinction the coverage ratio cannot express on its own
# --------------------------------------------------------------------------------------
#
# "8 of 8 providers answered" is true of a run that queried everything a second ago and of a run
# that replayed eight answers from last Tuesday. Both are answers; they are not the same
# evidentiary claim, and a coverage line that cannot tell them apart is the mechanism by which a
# cache launders staleness. This block is the second half of that sentence.

#: Where in ``result.data`` the per-provider status maps live, and the namespace each one uses.
#: Matches ``Coverage.from_status_map``'s prefixes exactly, so the two never state a ratio in
#: different vocabularies.
_STATUS_MAP_KEYS: Tuple[Tuple[str, str], ...] = (
    ("provider_status", ""),
    ("url_provider_status", "url:"),
    ("domain_provider_status", "domain:"),
)


def _iter_status_entries(data: Mapping[str, Any]) -> Iterator[Tuple[str, Mapping[str, Any]]]:
    for key, prefix in _STATUS_MAP_KEYS:
        status = data.get(key)
        if isinstance(status, Mapping):
            for name, entry in status.items():
                if isinstance(entry, Mapping):
                    yield f"{prefix}{name}", entry
    for item in data.get("ips") or []:
        if not isinstance(item, Mapping):
            continue
        status = item.get("provider_status")
        if not isinstance(status, Mapping):
            continue
        prefix = f"{item.get('ip') or '?'}:"
        for name, entry in status.items():
            if isinstance(entry, Mapping):
                yield f"{prefix}{name}", entry


def summarise_freshness(data: Mapping[str, Any], *, offline: bool = False) -> Dict[str, Any]:
    """Split the answers into "queried now" and "replayed from cache", by name and by age.

    Pure, and it reads the same ``provider_status`` maps ``Coverage`` reads, so the two cannot
    disagree about who answered. What it adds is the thing ``Coverage`` structurally cannot say:
    *when*.
    """
    fresh: List[str] = []
    cached: List[Dict[str, Any]] = []
    refused: List[Dict[str, str]] = []
    oldest_age: Optional[float] = None
    oldest_queried_at: Optional[str] = None

    for name, entry in _iter_status_entries(data):
        cache_block = entry.get("cache")
        outcome = str(entry.get("outcome") or "")
        if not isinstance(cache_block, Mapping):
            if outcome in {"ok", "not_found"}:
                fresh.append(name)
            continue
        if cache_block.get("hit"):
            age = cache_block.get("age_seconds")
            age_value = float(age) if isinstance(age, (int, float)) else None
            cached.append(
                {
                    "provider": name,
                    "queried_at": cache_block.get("queried_at"),
                    "age_seconds": age_value,
                    "age": cache_block.get("age") or format_age(age_value),
                }
            )
            if age_value is not None and (oldest_age is None or age_value > oldest_age):
                oldest_age = age_value
                oldest_queried_at = cache_block.get("queried_at")
            continue
        if cache_block.get("state") == "offline_refused":
            refused.append({"provider": name, "reason": str(cache_block.get("reason") or "")})
            continue
        if outcome in {"ok", "not_found"}:
            fresh.append(name)

    answered_now = len(fresh)
    answered_cached = len(cached)
    total = answered_now + answered_cached
    if total == 0:
        headline = "no provider answered, from the network or from cache"
    elif answered_cached == 0:
        headline = f"{answered_now} of {total} answers were queried now; none came from cache"
    elif answered_now == 0:
        headline = f"all {total} answers came from cache, none was queried now (oldest {format_age(oldest_age)})"
    else:
        headline = (
            f"{total} answers: {answered_now} queried now, "
            f"{answered_cached} from cache (oldest {format_age(oldest_age)})"
        )

    return {
        "schema_version": FRESHNESS_SCHEMA,
        "offline": offline,
        "answered_total": total,
        "answered_now": answered_now,
        "answered_from_cache": answered_cached,
        "queried_now": sorted(fresh),
        "from_cache": sorted(cached, key=lambda row: str(row.get("provider"))),
        "unanswerable_offline": sorted(refused, key=lambda row: row["provider"]),
        "oldest_age_seconds": None if oldest_age is None else round(oldest_age, 3),
        "oldest_age": format_age(oldest_age) if oldest_age is not None else None,
        "oldest_queried_at": oldest_queried_at,
        "headline": headline,
    }


def freshness_warnings(summary: Mapping[str, Any]) -> List[str]:
    """The sentences that have to reach the screen, not just the JSON.

    The console renderers print ``result.warnings``; nothing renders ``data['freshness']``. So the
    disclosure travels as a warning, and it leads with the count and the age because that is the
    part a reader who stops after one line has to have seen.
    """
    warnings: List[str] = []
    cached = int(summary.get("answered_from_cache") or 0)
    refused = list(summary.get("unanswerable_offline") or [])

    if cached:
        oldest = summary.get("oldest_age") or "unknown"
        stamp = summary.get("oldest_queried_at") or "an unrecorded time"
        warnings.append(
            f"{cached} of {summary.get('answered_total')} answers came from cache and were NOT queried now: "
            f"oldest is {oldest} old (obtained {stamp}). Re-run with --max-age 0 to force a fresh lookup"
        )
    if summary.get("offline") and refused:
        names = ", ".join(row["provider"] for row in refused)
        warnings.append(
            f"--offline: {len(refused)} question(s) could not be answered from cache and were NOT asked: {names}. "
            "This is missing coverage, not a clean result"
        )
    elif summary.get("offline"):
        warnings.append("--offline: nothing was contacted. Every answer above is a replay of an earlier lookup")
    return warnings


# --------------------------------------------------------------------------------------
# The case directory
# --------------------------------------------------------------------------------------
#
# What the case buys is regeneration without re-querying: the result, the verdict inside it, the
# freshness record and (when capture is on) the evidence envelopes are all on disk, so a report
# can be rebuilt weeks later with no provider contacted and no quota spent -- and, critically,
# with the original timestamps intact rather than the regeneration's.


def case_id_for(scope: str, indicator: str) -> str:
    """A stable id for one (scope, indicator) pair, for deduplication downstream.

    Deterministic on purpose: two runs against the same indicator produce the same case id, which
    is what lets a downstream system recognise them as the same case. The run id keeps the two
    runs' directories apart.
    """
    return hashlib.sha256(f"{scope}\n{indicator}".encode()).hexdigest()[:16]


def default_case_root() -> Path:
    """``<cwd>/outputs/cases``.

    Under ``outputs/`` deliberately. ``.gitignore`` ignores ``outputs/`` as a DIRECTORY and git
    does not descend into an ignored directory, so a case written here -- ``case.json``,
    ``report.md``, every evidence envelope -- cannot be committed by accident. A ``--case-dir``
    pointed somewhere else is the operator's call and carries no such guarantee; the case record
    records which of the two it was.
    """
    return Path.cwd() / "outputs" / "cases"


class CasePaths(NamedTuple):
    """Where one case landed."""

    directory: Path
    case_json: Path
    evidence_dir: Optional[Path]
    report: Optional[Path]
    evidence_written: int


def _is_under_ignored_output_dir(directory: Path) -> bool:
    """True when this path sits under a directory ``.gitignore`` ignores wholesale.

    Named parts only -- ``outputs``, ``results``, ``reports`` -- because that is exactly what the
    ignore rules say. This is a disclosure, not a control: it tells the operator whether the case
    they just wrote is protected from a stray ``git add``, and the honest answer for a custom
    ``--case-dir`` is usually "no".
    """
    ignored = {"outputs", "results", "reports"}
    return any(part in ignored for part in directory.resolve().parts)


def write_case(
    root: Path,
    *,
    result: Any,
    indicator: str,
    scope: str,
    run_id: Optional[str] = None,
    evidence: Sequence[Any] = (),
    evidence_complete: bool = True,
    evidence_dropped: int = 0,
    report: Optional[str] = None,
    cache_summary: Optional[Mapping[str, Any]] = None,
    now: Optional[dt.datetime] = None,
) -> CasePaths:
    """Write one investigation to ``<root>/<scope>-<case_id>/<run_id>/``.

    The directory name is built from the scope and a **hash** of the indicator, never from the
    indicator itself: on the bulk path the indicator is attacker-authored text, and a path
    component derived from it is a traversal waiting to happen.

    Raises :class:`CaseError` on any I/O failure. Unlike the cache, this one is loud -- the
    operator asked for a case to be written, and silently not writing it would leave them
    believing they have evidence they do not have.
    """
    stamp = now or _utc_now()
    case_id = case_id_for(scope, indicator)
    run = run_id or "run"
    directory = Path(root).expanduser() / f"{_slug(scope)}-{case_id}" / _slug(run)

    payload: Any = result
    if hasattr(result, "model_dump"):
        payload = result.model_dump(mode="json")

    record: Dict[str, Any] = {
        "schema_version": CASE_SCHEMA,
        "case_id": case_id,
        "run_id": run_id,
        "scope": scope,
        # Redacted, like the cache entry: a case directory is the thing an analyst attaches to a
        # ticket, and a URL's userinfo has no business travelling with it.
        "indicator": redact_url(indicator),
        "tool": "tripper-recon",
        "tool_version": __version__,
        "written_at": _rfc3339(stamp),
        "cache": dict(cache_summary) if cache_summary is not None else None,
        "git_ignored_location": _is_under_ignored_output_dir(directory),
        "result": payload,
    }

    evidence_written = 0
    evidence_dir: Optional[Path] = None
    try:
        directory.mkdir(parents=True, exist_ok=True)
        if evidence:
            evidence_dir = directory / "evidence"
            evidence_dir.mkdir(parents=True, exist_ok=True)
            for index, envelope in enumerate(evidence, start=1):
                text = envelope.to_json() if hasattr(envelope, "to_json") else json.dumps(envelope, indent=2)
                host = _slug(str(getattr(envelope, "host", "") or "unknown"))
                _atomic_write(evidence_dir / f"{index:04d}-{host}.json", text if text.endswith("\n") else text + "\n")
                evidence_written += 1
        record["evidence"] = {
            "captured": evidence_written,
            "complete": bool(evidence_complete),
            "dropped": int(evidence_dropped),
            "directory": "evidence" if evidence_dir is not None else None,
        }

        case_json = directory / "case.json"
        _atomic_write(case_json, json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + "\n")

        report_path: Optional[Path] = None
        if report is not None:
            report_path = directory / "report.md"
            _atomic_write(report_path, report if report.endswith("\n") else report + "\n")
    except OSError as exc:
        raise CaseError(f"could not write the case directory {directory}: {exc}") from exc

    return CasePaths(
        directory=directory,
        case_json=case_json,
        evidence_dir=evidence_dir,
        report=report_path,
        evidence_written=evidence_written,
    )


def load_case(path: Path) -> Dict[str, Any]:
    """Read a case record back, from its directory or from ``case.json`` itself.

    Version-gated before anything is read out of it. A record written by a future build is
    refused rather than partially understood, because the failure mode of "partially understood"
    here is a report that quotes fields whose meaning has changed.
    """
    target = Path(path).expanduser()
    if target.is_dir():
        target = target / "case.json"
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CaseError(f"no case record at {target}") from exc
    except (OSError, ValueError) as exc:
        raise CaseError(f"could not read the case record {target}: {exc}") from exc
    if not isinstance(raw, dict):
        raise CaseError(f"{target} does not contain a case record")
    declared = raw.get("schema_version")
    if declared != CASE_SCHEMA:
        raise CaseError(f"{target} declares schema {declared!r}; this build reads {CASE_SCHEMA!r}")
    return raw
