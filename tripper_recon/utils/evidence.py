"""The evidence envelope: what left, what came back, when, and a hash of it (roadmap 7.6).

**The rule this module exists to serve: a cached fact must never claim to have been queried
now.** Everything here is in service of a report that is still defensible three weeks later,
which means the timestamps are the product and the body is merely the payload.

An :class:`Evidence` record is captured ONCE, by a response event hook installed at
``utils.http.create_client`` -- the single place this package builds an ``httpx.AsyncClient``.
Capturing at the client rather than in each of the fourteen providers is what makes the record
uniform: every provider, every retry, and every redirect hop produces the same envelope with no
provider-side cooperation and no per-provider drift.

Three consumers sit on this one capture:

* **Integrity.** :attr:`Evidence.body_sha256` is the sha256 of the bytes that actually arrived,
  so a body attached to a ticket can be checked against the record months later.
* **Offline regeneration.** The body, status and headers are enough to replay a run without
  spending quota or writing a second entry into a provider's logs.
* **Caching (roadmap 7.7).** :attr:`Evidence.queried_at` is what a cache reader renders as an
  age. A cache that drops it produces exactly the failure this workstream exists to prevent.

---

**Capture is OPT-IN and off by default.** Recording every raw body for every run costs disk and
puts provider payloads on disk that the analyst may not want there; that is the analyst's call,
not a default. "Off" is the absence of an active recorder in the :mod:`contextvars` context, so
the no-capture path in the hook is a single ``is None`` test and the client behaves exactly as
it did before this module existed.

**Credentials never reach an envelope.** This is the reason 7.6 was sequenced after the W0.1
redaction work rather than before it. Shodan and IPinfo authenticate in the QUERY STRING
(``?key=``, ``?token=``); VirusTotal, AbuseIPDB, OTX, Cloudflare and abuse.ch authenticate in
REQUEST HEADERS; and a provider's own 401 body routinely echoes the key it rejected. An
evidence file is written precisely so it can be attached to a ticket, so a naive recorder is a
credential-distribution mechanism. Three controls, all fail-closed:

1. Every URL goes through :func:`utils.redact.redact_url` before it is stored.
2. Headers are captured by ALLOWLIST -- :data:`CAPTURED_REQUEST_HEADERS` and
   :data:`CAPTURED_RESPONSE_HEADERS`. A denylist fails open on the next provider that invents a
   header name nobody anticipated; an allowlist fails closed, and the cost of failing closed is
   a missing diagnostic field rather than a leaked key. Captured values additionally go through
   :func:`utils.redact.redact_text`.
3. Every body goes through :func:`utils.redact.redact_text`.

---

**Two timestamps, never one** (roadmap 7.4). :attr:`Evidence.queried_at` is when THIS TOOL sent
the request. :attr:`Evidence.observed_at` is when the PROVIDER says it observed the fact, which
at the HTTP layer is its ``Date`` header. They are usually seconds apart and occasionally weeks
apart, and collapsing them hides exactly the staleness the evidence exists to expose.
:attr:`Evidence.observed_at_source` names which of the two possible origins the value came from,
because an ``observed_at`` whose provenance is unstated is no better than no ``observed_at``.
A payload-level observation time (VirusTotal's ``last_analysis_date``, Shodan's ``last_update``)
is per-provider knowledge that this layer cannot have, so a provider that parses one attaches it
with :meth:`Evidence.with_observed_at`.

**Bounding the body.** A body is truncated at :data:`DEFAULT_MAX_BODY_BYTES` of the raw bytes,
and a truncated record says so in :attr:`Evidence.body_transforms`. The distinction that matters:
:attr:`Evidence.body_sha256` always hashes the FULL body as received, never the stored prefix,
so the hash keeps meaning something -- and :attr:`Evidence.body_transforms` is what tells a
reader that the stored text is not the thing that was hashed. Redaction and a lossy decode
change the stored text the same way and are recorded the same way. An empty
``body_transforms`` is the only state in which the stored body can be verified against the hash;
:attr:`Evidence.body_is_verbatim` is that predicate, and the cache lane should refuse to replay
a record where it is false.
"""

from __future__ import annotations

import contextvars
import datetime as dt
import hashlib
import json
import threading
from contextlib import contextmanager
from email.utils import parsedate_to_datetime
from enum import Enum
from typing import Dict, FrozenSet, Iterator, List, Mapping, Optional, Tuple

import httpx
from pydantic import BaseModel, ConfigDict, Field

from tripper_recon.utils.redact import redact_text, redact_url

# --------------------------------------------------------------------------------------
# Schema and bounds
# --------------------------------------------------------------------------------------

#: Version tag carried by every record. The cache lane persists these and will read records
#: written by older builds, so the shape is versioned from the first commit rather than from
#: the first time it breaks.
EVIDENCE_SCHEMA = "tripper-recon.evidence/1"

#: Raw response bytes retained per record. 256 KiB holds every provider payload this tool has
#: been observed to receive with room to spare -- the largest are VirusTotal IP reports and
#: Cloudflare Radar BGP pages, both well under 100 KiB -- so truncation should be the rare
#: pathological case rather than routine. Raising it costs memory and disk linearly in the
#: number of provider calls, and a bulk run makes hundreds.
DEFAULT_MAX_BODY_BYTES = 262_144

#: Records retained per recorder. A bulk run over forty indicators against fourteen providers
#: with retries is comfortably inside this; something pathological is not, and unbounded growth
#: in a long-running process is a defect. Overflow is COUNTED, never silent
#: (:attr:`EvidenceRecorder.dropped`), because an evidence set that is quietly incomplete is
#: the same class of lie as a cached fact presented as fresh.
DEFAULT_MAX_RECORDS = 2_000

#: The stored body was cut to :attr:`EvidenceRecorder.max_body_bytes`. It is a PREFIX of the
#: bytes that :attr:`Evidence.body_sha256` hashes, and hashing it again will not match.
TRANSFORM_TRUNCATED = "truncated"

#: A credential was found in the body and replaced. The stored text differs from the hashed
#: bytes -- which is the point, and it has to be visible so nobody reads the mismatch as
#: tampering.
TRANSFORM_REDACTED = "redacted"

#: The bytes were not valid UTF-8 and were decoded with replacement characters. Usually a
#: truncation that landed mid-codepoint; occasionally a genuinely binary body.
TRANSFORM_LOSSY_DECODE = "lossy_decode"


class ObservedAtSource(str, Enum):
    """Where an :attr:`Evidence.observed_at` value came from.

    Unstated provenance is why the field would otherwise be worthless: an ``observed_at`` read
    off a ``Date`` header says when the provider generated the RESPONSE, while one read out of
    a payload says when the provider observed the FACT. Those are wildly different claims -- the
    first is seconds old by construction, the second can be months old -- and a reader who
    cannot tell which one they are looking at cannot use either.
    """

    #: The response's own ``Date`` header. Bounds when the provider generated this response.
    HTTP_DATE = "http_date"
    #: A timestamp inside the payload, attached by a provider module that knows how to read it.
    PAYLOAD = "payload"


# --------------------------------------------------------------------------------------
# Header capture policy
# --------------------------------------------------------------------------------------

#: Header names that must never appear in an envelope under any policy. Redundant with the
#: allowlists below by design: this is the invariant a future widening of an allowlist has to
#: be checked against, and ``tests/test_evidence.py`` checks it mechanically so the redundancy
#: cannot rot into a comment.
NEVER_CAPTURED_HEADERS: FrozenSet[str] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-apikey",  # VirusTotal
        "key",  # AbuseIPDB
        "auth-key",  # abuse.ch
        "x-otx-api-key",  # AlienVault OTX
        "x-auth-key",
        "x-auth-email",
        "api-key",
        "apikey",
        "token",
        "x-api-key",
    }
)

#: Request headers worth recording. Deliberately tiny. The User-Agent is an OPSEC-relevant fact
#: about what the provider saw (docs/OPSEC.md section 4) and the rest is content negotiation,
#: which is what makes a response reproducible. Nothing here can carry a credential.
CAPTURED_REQUEST_HEADERS: FrozenSet[str] = frozenset(
    {
        "user-agent",
        "accept",
        "accept-encoding",
        "content-type",
    }
)

#: Response headers worth recording: what the body is, when the provider generated it, and the
#: cache validators that let a later run ask whether anything changed without re-downloading.
CAPTURED_RESPONSE_HEADERS: FrozenSet[str] = frozenset(
    {
        "content-type",
        "content-length",
        "date",
        "age",
        "cache-control",
        "etag",
        "last-modified",
        "retry-after",
        "server",
    }
)

#: Rate-limit headers are per-provider in name and load-bearing for the quota work, so they are
#: matched by prefix rather than enumerated. Every known spelling is a counter or a reset time;
#: none is a credential.
CAPTURED_RESPONSE_HEADER_PREFIXES: Tuple[str, ...] = (
    "ratelimit-",
    "x-ratelimit-",
    "x-rate-limit-",
)


def _filter_headers(
    headers: Mapping[str, str],
    allowed: FrozenSet[str],
    prefixes: Tuple[str, ...] = (),
) -> Dict[str, str]:
    """Keep the allowlisted headers, lowercased, redacted, in sorted order.

    Sorted because the envelope has to serialise deterministically and httpx preserves wire
    order, which is not stable across HTTP/1.1 and HTTP/2 for the same provider.
    """
    kept: Dict[str, str] = {}
    for raw_name, value in headers.items():
        name = raw_name.lower()
        if name in NEVER_CAPTURED_HEADERS:
            continue
        if name in allowed or name.startswith(prefixes):
            kept[name] = redact_text(value)
    return {name: kept[name] for name in sorted(kept)}


def _rfc3339(value: dt.datetime) -> str:
    """RFC 3339 in UTC with a ``Z`` designator, matching ``types.models._rfc3339``."""
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _http_date_to_rfc3339(value: Optional[str]) -> Optional[str]:
    """Parse an RFC 7231 ``Date`` header into RFC 3339 UTC, or ``None`` if it will not parse.

    Never raises. A provider that emits a malformed ``Date`` should cost the record one optional
    field, not the whole capture.
    """
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        # RFC 7231 fixes the timezone at GMT; a parser that returns naive has told us that.
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return _rfc3339(parsed)


# --------------------------------------------------------------------------------------
# The envelope
# --------------------------------------------------------------------------------------


class Evidence(BaseModel):
    """One request/response exchange, recorded so it can be defended later.

    Frozen: a record is a statement about something that already happened, and code that wants
    a different statement makes a new record (:meth:`with_observed_at`) rather than editing
    history.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    #: Schema tag, :data:`EVIDENCE_SCHEMA`. Named ``schema_version`` and not ``schema`` because
    #: ``schema`` shadows a ``BaseModel`` attribute in pydantic v2.
    schema_version: str = Field(default=EVIDENCE_SCHEMA)

    #: The host contacted. A third party that already holds the data, never the target
    #: (docs/OPSEC.md section 1) -- the egress allowlist hook guarantees that before this hook
    #: ever runs.
    host: str
    #: HTTP method, uppercase.
    method: str
    #: The full URL, REDACTED. Shodan and IPinfo put the API key here.
    url: str
    #: sha256 of the request body, when there was one. The body ITSELF is deliberately not
    #: stored: the two POST-as-query providers (Cloudflare Radar GraphQL, abuse.ch) are the only
    #: senders, nothing needs their bytes back, and a hash is enough to tell two queries to the
    #: same URL apart -- which is what the cache lane needs for a correct key.
    request_body_sha256: Optional[str] = None
    #: Allowlisted request headers, lowercased and sorted.
    request_headers: Dict[str, str] = Field(default_factory=dict)

    #: HTTP status code as received. A 401 or a 429 is evidence too, and often the useful kind.
    status_code: int
    #: ``HTTP/1.1`` or ``HTTP/2``.
    http_version: str
    #: Allowlisted response headers, lowercased and sorted.
    response_headers: Dict[str, str] = Field(default_factory=dict)

    #: When THIS TOOL sent the request, RFC 3339 UTC. The number a cache renders as an age.
    queried_at: str
    #: When the PROVIDER says it observed this, RFC 3339 UTC, or ``None`` when it did not say.
    observed_at: Optional[str] = None
    #: Provenance of :attr:`observed_at`. Always set when :attr:`observed_at` is.
    observed_at_source: Optional[ObservedAtSource] = None
    #: Round trip in milliseconds, or ``None`` when httpx could not report it. ``None`` also
    #: means :attr:`queried_at` is the COMPLETION instant rather than the send instant, so the
    #: absence is load-bearing and is not defaulted to zero.
    elapsed_ms: Optional[float] = None

    #: The response body: redacted, possibly truncated, decoded as UTF-8.
    body: str = ""
    #: Length in bytes of the FULL body as received, before any transform.
    body_bytes: int = 0
    #: sha256 of the FULL raw body as received. Never of the stored :attr:`body`.
    body_sha256: str
    #: What was done to :attr:`body` relative to the bytes :attr:`body_sha256` hashes. Sorted.
    #: Empty means the stored body is byte-exact for the hash.
    body_transforms: List[str] = Field(default_factory=list)

    #: Set when the capture itself failed -- a body that could not be read, a hook that raised.
    #: Redacted. A record with this set is a record of a capture failure, not of a response.
    capture_error: Optional[str] = None

    # -- derived views -------------------------------------------------------------------

    @property
    def body_is_verbatim(self) -> bool:
        """True when :attr:`body` hashes to :attr:`body_sha256`.

        The predicate a cache must gate replay on. False means the stored text is a prefix, a
        redaction, a lossy decode, or some combination -- readable evidence, but not the
        response, and re-hashing it will not match.
        """
        return not self.body_transforms and self.capture_error is None

    @property
    def cache_key(self) -> str:
        """Stable identity of the FACT this record answers, independent of the credential used.

        Built from the method, the redacted URL and the request-body hash. Redaction is what
        makes it correct rather than merely convenient: rotating an API key changes the URL but
        changes nothing about what was asked, so a key that included the credential would miss
        on every rotation and cache the same fact twice.
        """
        material = f"{self.method}\n{self.url}\n{self.request_body_sha256 or ''}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def with_observed_at(self, observed_at: str, *, source: ObservedAtSource) -> Evidence:
        """A copy carrying a provider-stated observation time.

        The route by which a provider module attaches what only it can know: VirusTotal's
        ``last_analysis_date``, Shodan's ``last_update``. Overwrites a ``Date``-header value on
        purpose -- a payload timestamp is a statement about the FACT, which is what a staleness
        claim needs, while the header is only a statement about the response.
        """
        return self.model_copy(update={"observed_at": observed_at, "observed_at_source": source})

    # -- serialisation -------------------------------------------------------------------

    def canonical_json(self) -> str:
        """Compact, key-sorted JSON. The form to hash.

        Sorted keys rather than declaration order, so adding or reordering a field in a later
        schema version does not silently change the hash of a record that has not changed.
        """
        return json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    def canonical_bytes(self) -> bytes:
        return self.canonical_json().encode("utf-8")

    def envelope_sha256(self) -> str:
        """sha256 of :meth:`canonical_bytes`. Integrity of the RECORD, not of the response."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def to_json(self, *, indent: int = 2) -> str:
        """Key-sorted, indented JSON. The form to write to a case directory.

        Separate from :meth:`canonical_json` because the two have incompatible jobs: a hash
        wants no whitespace, and a file that two runs will be diffed against wants one field
        per line.
        """
        return json.dumps(self.model_dump(mode="json"), sort_keys=True, indent=indent, ensure_ascii=False)


# --------------------------------------------------------------------------------------
# The recorder
# --------------------------------------------------------------------------------------


class EvidenceRecorder:
    """Collects :class:`Evidence` for one investigation.

    Holding the records in a plain object rather than in the :mod:`contextvars` value is what
    makes the capture survive ``asyncio.run``: a task copies the context at creation, so a
    ContextVar SET inside the loop is invisible outside it, while mutations of an object the
    context merely points at are visible everywhere.
    """

    __slots__ = ("_dropped", "_lock", "_records", "max_body_bytes", "max_records")

    def __init__(
        self,
        *,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        max_records: int = DEFAULT_MAX_RECORDS,
    ) -> None:
        if max_body_bytes < 0:
            raise ValueError("max_body_bytes must be >= 0")
        if max_records < 1:
            raise ValueError("max_records must be >= 1")
        # ``max_body_bytes=0`` records metadata, timings and the hash of the full body while
        # storing none of it -- a legitimate mode when the payloads themselves are what the
        # analyst does not want on disk.
        self.max_body_bytes = max_body_bytes
        self.max_records = max_records
        self._records: List[Evidence] = []
        self._dropped = 0
        self._lock = threading.Lock()

    @property
    def records(self) -> Tuple[Evidence, ...]:
        """Everything captured, in capture order."""
        with self._lock:
            return tuple(self._records)

    @property
    def dropped(self) -> int:
        """Records refused because :attr:`max_records` was reached. Report it; never hide it."""
        with self._lock:
            return self._dropped

    @property
    def is_complete(self) -> bool:
        """False when anything was dropped, i.e. when this evidence set is not the whole run."""
        return self.dropped == 0

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    def record(self, evidence: Evidence) -> None:
        with self._lock:
            if len(self._records) >= self.max_records:
                self._dropped += 1
                return
            self._records.append(evidence)


_active_recorder: contextvars.ContextVar[Optional[EvidenceRecorder]] = contextvars.ContextVar(
    "tripper_recon_evidence_recorder", default=None
)


def active_recorder() -> Optional[EvidenceRecorder]:
    """The recorder in force, or ``None`` -- which is the default and means capture is OFF."""
    return _active_recorder.get()


@contextmanager
def capture_evidence(recorder: Optional[EvidenceRecorder] = None) -> Iterator[EvidenceRecorder]:
    """Turn capture on for the duration of the block.

    Wrap the whole investigation, including the ``asyncio.run`` that drives it -- a task copies
    the context when it is created, so a recorder installed before the loop starts is visible
    inside it, and one installed inside a task is not visible to its siblings.
    """
    active = recorder if recorder is not None else EvidenceRecorder()
    token = _active_recorder.set(active)
    try:
        yield active
    finally:
        _active_recorder.reset(token)


# --------------------------------------------------------------------------------------
# The hook
# --------------------------------------------------------------------------------------


def _body_fields(raw: bytes, max_body_bytes: int) -> Tuple[str, int, str, List[str]]:
    """``(body, body_bytes, body_sha256, body_transforms)`` for one raw response body.

    Order matters and is fixed: hash the full bytes FIRST, then truncate, then decode, then
    redact. Hashing anything other than the full bytes would make the hash a statement about
    this tool's configuration rather than about the response.
    """
    digest = hashlib.sha256(raw).hexdigest()
    transforms: List[str] = []

    kept = raw
    if len(raw) > max_body_bytes:
        kept = raw[:max_body_bytes]
        transforms.append(TRANSFORM_TRUNCATED)

    try:
        text = kept.decode("utf-8")
    except UnicodeDecodeError:
        text = kept.decode("utf-8", errors="replace")
        transforms.append(TRANSFORM_LOSSY_DECODE)

    redacted = redact_text(text)
    if redacted != text:
        transforms.append(TRANSFORM_REDACTED)

    return redacted, len(raw), digest, sorted(transforms)


def _request_body_sha256(request: httpx.Request) -> Optional[str]:
    """sha256 of the request body, or ``None`` when there is none or it cannot be read."""
    try:
        content = request.content
    except Exception:  # noqa: BLE001 - a streaming request body is not worth raising over here
        return None
    if not content:
        return None
    return hashlib.sha256(content).hexdigest()


def _elapsed_ms(response: httpx.Response) -> Optional[float]:
    """Round trip in ms, or ``None``. httpx raises until the stream is closed."""
    try:
        return round(response.elapsed.total_seconds() * 1000.0, 3)
    except (RuntimeError, AttributeError):
        return None


async def record_response(response: httpx.Response) -> None:
    """httpx response event hook: capture the exchange, if and only if capture is on.

    Installed beside -- never in place of -- the request hook that enforces the egress
    allowlist. The two are independent: the request hook decides whether a request may leave,
    this one records what came back, and neither can disable the other.

    Three properties this function must keep:

    * **No-op when capture is off.** One ``is None`` test, no body read, no allocation.
    * **Never raises.** It runs inside every provider call in the tool. A recorder that can
      break a lookup is worse than no recorder, so a capture failure is recorded AS a capture
      failure and the response is handed back untouched.
    * **Reads the body deliberately.** httpx calls response hooks BEFORE the body is read, so
      ``await response.aread()`` here is what makes ``.content`` available. It is idempotent --
      httpx's own read afterwards returns the cached content -- and this package never streams
      a response, so nothing downstream is consumed. A streaming caller added later has to opt
      out here first.
    """
    recorder = active_recorder()
    if recorder is None:
        return

    request = response.request
    try:
        capture_error: Optional[str] = None
        try:
            raw = await response.aread()
        except Exception as exc:  # noqa: BLE001 - a body we cannot read is recorded, not raised
            raw = b""
            capture_error = redact_text(f"body could not be read: {type(exc).__name__}: {exc}")

        body, body_bytes, body_sha256, transforms = _body_fields(raw, recorder.max_body_bytes)

        received = dt.datetime.now(dt.timezone.utc)
        elapsed_ms = _elapsed_ms(response)
        # queried_at is the SEND instant, derived from the completion instant and the measured
        # round trip. When httpx cannot report the round trip, this falls back to the completion
        # instant and elapsed_ms stays None -- which is the reader's signal that the timestamp
        # is an upper bound rather than the send time.
        queried_at = received if elapsed_ms is None else received - dt.timedelta(milliseconds=elapsed_ms)

        observed_at = _http_date_to_rfc3339(response.headers.get("date"))

        recorder.record(
            Evidence(
                host=(request.url.host or "").lower(),
                method=request.method.upper(),
                url=redact_url(str(request.url)),
                request_body_sha256=_request_body_sha256(request),
                request_headers=_filter_headers(request.headers, CAPTURED_REQUEST_HEADERS),
                status_code=response.status_code,
                http_version=response.http_version,
                response_headers=_filter_headers(
                    response.headers,
                    CAPTURED_RESPONSE_HEADERS,
                    CAPTURED_RESPONSE_HEADER_PREFIXES,
                ),
                queried_at=_rfc3339(queried_at),
                observed_at=observed_at,
                observed_at_source=ObservedAtSource.HTTP_DATE if observed_at else None,
                elapsed_ms=elapsed_ms,
                body=body,
                body_bytes=body_bytes,
                body_sha256=body_sha256,
                body_transforms=transforms,
                capture_error=capture_error,
            )
        )
    except Exception as exc:  # noqa: BLE001 - the recorder must never break a lookup
        _record_capture_failure(recorder, response, exc)


def _record_capture_failure(recorder: EvidenceRecorder, response: httpx.Response, exc: BaseException) -> None:
    """Last resort: record THAT the capture failed, with nothing that could carry a credential.

    Silence here would be the worst outcome available -- an evidence set that is missing a call
    and does not say so is precisely the artefact this module exists to prevent.
    """
    try:
        recorder.record(
            Evidence(
                host=(response.request.url.host or "").lower(),
                method=response.request.method.upper(),
                url=redact_url(str(response.request.url)),
                status_code=response.status_code,
                http_version=response.http_version,
                queried_at=_rfc3339(dt.datetime.now(dt.timezone.utc)),
                body_sha256=hashlib.sha256(b"").hexdigest(),
                capture_error=redact_text(f"evidence capture failed: {type(exc).__name__}: {exc}"),
            )
        )
    except Exception:  # noqa: BLE001 - nothing left to do; a lookup must not die for a record
        return


__all__ = [
    "CAPTURED_REQUEST_HEADERS",
    "CAPTURED_RESPONSE_HEADERS",
    "CAPTURED_RESPONSE_HEADER_PREFIXES",
    "DEFAULT_MAX_BODY_BYTES",
    "DEFAULT_MAX_RECORDS",
    "EVIDENCE_SCHEMA",
    "NEVER_CAPTURED_HEADERS",
    "TRANSFORM_LOSSY_DECODE",
    "TRANSFORM_REDACTED",
    "TRANSFORM_TRUNCATED",
    "Evidence",
    "EvidenceRecorder",
    "ObservedAtSource",
    "active_recorder",
    "capture_evidence",
    "record_response",
]
