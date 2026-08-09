"""Tranco rank lookup -- roadmap item 8.3.

Tranco is a research-oriented top-sites ranking built by averaging several source rankings over
a 30-day window, published so that a single manipulated source cannot move a domain far. This
module reads one endpoint of its public API: the per-domain rank history.

**What this provider is for, and the one way it must never be read.**

Rank is a *false-positive suppressor*. A domain that has sat in the global top few thousand for
thirty consecutive days is overwhelmingly unlikely to be the thing an analyst is hunting, and
knowing that in one keyless call is the fastest way to close out "is ``microsoft.com``
malicious" without spending a VirusTotal quota slot or an analyst's afternoon.

The inverse inference is invalid and this module is written to make it hard to draw:

* **A low rank means nothing adverse. An absent rank means nothing adverse.** The list holds a
  million domains and the web holds hundreds of millions. Every legitimate small business,
  every internal-facing service, every regional supplier and every newly registered but
  perfectly ordinary domain is unranked. Treating "not in the top million" as suspicious would
  flag essentially the entire honest long tail, which is not a detection, it is a tautology.
* **A high rank is not a safety certificate either.** Popular domains are compromised, popular
  hosting serves malware, and popular file-sharing and pastebin services carry payloads every
  day of the week. Rank caps how much suspicion an indicator deserves on *reputation* grounds.
  It never clears the indicator, and it never outweighs an affirmative observation of malice
  from a provider that actually saw something.

The envelope is shaped to leave no room for the wrong reading. There is no numeric "risk", no
band, and no classification: this module extracts fields and the scoring layer decides what
they are worth (``docs/ARCHITECTURE.md`` section 7 -- every scoring constant lives in
``verdict/scoring.yaml``, never in Python). Absence is reported as the observation it is,
``tranco_in_list: False``, and is accompanied by ``tranco_absence_note`` spelling out in words
that the absence is not adverse, so the sentence travels with the data into any JSON export or
report that carries it. ``tranco_suppression_only`` is a hard-coded ``True`` that says the same
thing to a machine: nothing in this payload may raise suspicion.

**The 1 query/second ceiling.**

The Tranco API documentation states the rank endpoint's limit as ``Rate limit exceeded
(1 query/second)`` on its 429 response (Tranco API documentation, ``GET
/api/ranks/domain/{domain}``, retrieved 2026-08-09). That is a *rate* over time. The global
limiter in ``utils/http.py`` is a *concurrency* semaphore -- it bounds how many requests are in
flight, not how often they start -- so it cannot express this ceiling at any setting, and the
per-provider budget that would (roadmap item 3.4) is not built. The ceiling is therefore
enforced here, by :func:`_await_pacing_slot`, which serialises every Tranco request in the
process behind a lock and holds each one until at least
:data:`MIN_REQUEST_INTERVAL_SECONDS` has elapsed since the previous request started.

The pacer is per event loop and weakly keyed, matching ``utils/http.py``'s limiter, so a second
``asyncio.run`` in one process gets a pacer bound to *its* loop instead of raising.

The cost is real and is stated rather than hidden: **N domains take at least N seconds**, and a
retry spends a slot because a retry is another query. In a single-indicator investigation this
is one second and invisible. In bulk mode it is the dominant term in wall-clock time, and the
requests queue while holding a global concurrency permit, which can starve the other providers.
See the module notes in ``docs/PROVIDERS.md`` when this provider is wired; until then the
constraint is recorded here.

**Why the per-domain API and not a cached snapshot.** Tranco also publishes each daily list as a
downloadable file (``/api/lists/date/latest`` returns the metadata and a download URL), and for
bulk work one download plus a local set lookup beats one paced request per domain by a wide
margin -- a thousand domains is a thousand seconds against a single fetch. It is deliberately
not what this module does, for three reasons. The snapshot needs the TTL disk cache that
roadmap item 8.10 has not built yet, so building it here would build that subsystem sideways.
A snapshot answers one bit -- present or absent at rank R today -- while the API returns the
30-day history, which is the more useful signal, because a domain ranked steadily for a month
and a domain that appeared once yesterday are different findings. And a cached rank asserted as
a current fact is exactly the staleness defect roadmap item 7.7 exists to prevent. When bulk
mode needs this, the snapshot is the right answer and should be built on 8.10, not bolted on
here.

**Keyless.** No credential is required or accepted for this endpoint, so there is no
``api_key`` parameter and no ``missing_api_key`` path. Authentication on the Tranco API applies
only to ``PUT /api/lists/create``, which generates custom lists and which this tool must never
call: it queues server-side work on somebody else's infrastructure and answers no question an
investigation asks.

**Passivity.** Tranco is a third party that already holds the ranking; it is not the target,
and asking it about a domain does not cause anything to contact that domain. The lookup is a
plain ``GET`` against a fixed host, and the domain is percent-encoded into a single path
segment so that a hostile indicator cannot escape the path.
"""

from __future__ import annotations

import asyncio
import re
import time
import weakref
from typing import Any, Dict, List, MutableMapping, Optional
from urllib.parse import quote

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff

TRANCO_BASE = "https://tranco-list.eu/api"

#: Minimum wall-clock seconds between the *starts* of two Tranco requests in this process.
#:
#: The published ceiling is one query per second. This is deliberately not a fraction under it:
#: the server measures arrival, not departure, and a value that just meets the limit turns
#: ordinary network jitter into 429s. Read at acquisition time rather than captured, so a test
#: can lower it without reaching into the pacer.
MIN_REQUEST_INTERVAL_SECONDS: float = 1.0

#: The sentence that travels with an unranked answer. It is data, not a log line, because the
#: place the wrong inference gets drawn is downstream -- in a report, a ticket or a scoring
#: rule -- and a note left behind in this module protects nothing there.
ABSENCE_NOTE = (
    "Not in the Tranco list. This is NOT adverse and must not raise suspicion: the list holds "
    "roughly one million domains while the public web holds hundreds of millions, so the "
    "overwhelming majority of legitimate domains are unranked. Absence here means no "
    "popularity-based suppression is available, nothing more."
)

#: ISO-8601 calendar dates, the form the rank endpoint documents (``Date(YYYY-mm-dd)``).
#: Entries whose date does not parse are dropped: a rank that cannot be placed in time cannot
#: support "the most recent rank", which is the field an analyst reads first.
_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


# --------------------------------------------------------------------------------------
# The 1 qps pacer
# --------------------------------------------------------------------------------------


class _Pacer:
    """The serialisation point for one event loop: a lock, and when the next request may start."""

    __slots__ = ("lock", "next_start")

    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        # monotonic() is always >= 0 and the first request should never wait, so 0.0 is a
        # correct "no request has gone out yet" sentinel rather than a magic number.
        self.next_start = 0.0


# Weakly keyed by event loop for the same reason as ``utils/http.py``'s limiter: an
# asyncio.Lock binds to the loop that first awaits it, and sharing one across two
# ``asyncio.run`` calls in one process raises RuntimeError the moment it has to make a caller
# wait. Weak keys also stop a finished loop being kept alive by this table.
_loop_pacers: MutableMapping[asyncio.AbstractEventLoop, _Pacer] = weakref.WeakKeyDictionary()


def _pacer() -> _Pacer:
    """The pacer for the running loop, created there on that loop's first Tranco request."""
    loop = asyncio.get_running_loop()
    pacer = _loop_pacers.get(loop)
    if pacer is None:
        pacer = _Pacer()
        _loop_pacers[loop] = pacer
    return pacer


async def _await_pacing_slot() -> None:
    """Block until this coroutine may start a Tranco request, then reserve the next slot.

    The sleep happens **while holding the lock**. That is the whole mechanism: it makes the
    requests strictly sequential, one per interval, instead of letting a burst of callers all
    read the same deadline, all sleep to it, and all fire together.

    Called once per attempt from inside the retried closure, so a retry pays for its own slot.
    A retry is another query and the provider counts it as one.
    """
    interval = MIN_REQUEST_INTERVAL_SECONDS
    if interval <= 0:
        return
    pacer = _pacer()
    async with pacer.lock:
        now = time.monotonic()
        wait = pacer.next_start - now
        if wait > 0:
            await asyncio.sleep(wait)
            now = time.monotonic()
        pacer.next_start = now + interval


# --------------------------------------------------------------------------------------
# Response parsing
# --------------------------------------------------------------------------------------


def _as_rank(value: Any) -> Optional[int]:
    """Return a positive integer rank, otherwise ``None``.

    ``bool`` is rejected explicitly -- it is an ``int`` subclass in Python and ``True`` would
    otherwise become rank 1, the single most misleading value this module could emit. Zero and
    negatives are rejected because Tranco ranks start at 1; a non-positive value is a parse
    failure wearing a number.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value > 0 else None


def _as_date(value: Any) -> Optional[str]:
    """Return an ISO calendar date string, otherwise ``None``. Passed through unparsed."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped if _ISO_DATE.match(stripped) else None


def _history(payload: Any) -> Optional[List[Dict[str, Any]]]:
    """The usable ``(date, rank)`` pairs from a ``ranks`` array, newest first.

    Returns ``None`` -- not an empty list -- when the body does not carry a ``ranks`` array at
    all. The distinction is the point. ``{"ranks": []}`` is Tranco stating that the domain is
    not in its lists, which is an observation this provider is glad to report. A body with no
    ``ranks`` key is Tranco stating nothing, and reporting that as "not in list" would
    manufacture an observation out of a parse failure -- the same class of defect as rendering
    an unqueried provider as a green zero (``docs/ARCHITECTURE.md`` section 8.1).

    Sorted here rather than trusted from the wire so ``tranco_rank`` means "the most recent
    rank" regardless of the order the API happened to send. Entries missing either half are
    dropped rather than half-reported: a rank with no date and a date with no rank both fail to
    answer the question this provider exists to answer.
    """
    ranks = payload.get("ranks") if isinstance(payload, dict) else None
    if not isinstance(ranks, list):
        return None
    entries: List[Dict[str, Any]] = []
    for entry in ranks:
        if not isinstance(entry, dict):
            continue
        date = _as_date(entry.get("date"))
        rank = _as_rank(entry.get("rank"))
        if date is None or rank is None:
            continue
        entries.append({"date": date, "rank": rank})
    # ISO-8601 calendar dates sort correctly as strings, which is why they are kept as strings.
    entries.sort(key=lambda item: str(item["date"]), reverse=True)
    return entries


def _payload(history: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build the ``data`` half of the envelope from the cleaned history.

    Every field is derived from what Tranco actually returned. When the domain is not in the
    list, the rank fields are ``None`` rather than a sentinel number, ``tranco_in_list`` is the
    observation, and ``tranco_absence_note`` carries the "this is not adverse" sentence with the
    data instead of leaving it in a docstring nobody downstream reads.
    """
    ranks = [int(entry["rank"]) for entry in history]
    in_list = bool(ranks)
    return {
        # The most recent rank Tranco published for this domain in the returned window.
        "tranco_rank": ranks[0] if in_list else None,
        "tranco_rank_date": history[0]["date"] if in_list else None,
        # An observation, not a verdict: Tranco answered, and said the domain does or does not
        # appear in its daily lists for the window.
        "tranco_in_list": in_list,
        # Best rank in the window. A domain drifting between 900k and just outside the list is
        # a different fact from one that has never been near it.
        "tranco_best_rank": min(ranks) if in_list else None,
        # How many daily lists in the returned window carried a rank. Distinguishes a steady
        # presence from a single day's appearance. Not the window length: the API documents
        # "at least the past 30 days" and does not pin the number, so claiming one would be
        # inventing a fact.
        "tranco_days_ranked": len(ranks),
        "tranco_history": history,
        # Hard-coded contract marker. This provider can only ever lower suspicion. A consumer
        # that finds itself increasing a score from anything in this payload has a defect.
        "tranco_suppression_only": True,
        "tranco_absence_note": None if in_list else ABSENCE_NOTE,
    }


# --------------------------------------------------------------------------------------
# The provider
# --------------------------------------------------------------------------------------


async def tranco_rank(*, client: httpx.AsyncClient, domain: str) -> Dict[str, Any]:
    """Tranco's published rank history for ``domain``, as a false-positive suppressor.

    Keyless: the rank endpoint takes no credential, so there is no ``missing_api_key`` path.

    Success is ``{"ok": True, "data": {...}}`` whether or not the domain is ranked -- Tranco
    answering "this domain is not in my list" is a successful lookup and a real observation,
    and reporting it as a failure would erase the difference between a domain Tranco has never
    listed and a domain Tranco was never asked about.

    **Read the returned data in one direction only.** A rank lowers suspicion. An absent rank
    means nothing adverse -- most of the web is unranked -- and a present rank does not clear
    an indicator, because popular domains get compromised. The module docstring above states
    this at length; ``tranco_suppression_only`` and ``tranco_absence_note`` state it in the
    payload.

    Failure envelopes:

    * ``invalid_domain`` -- an empty or whitespace-only argument. Rejected before any request,
      because it would otherwise be sent as a request for the collection rather than a domain.
    * ``not_found`` -- HTTP 404. **Unknown, never clean.** It is not the same answer as
      ``tranco_in_list: False``: that one is Tranco telling you the domain is unranked, this
      one is Tranco not telling you anything. Nothing benign may be inferred from it.
    * ``service_unavailable`` -- HTTP 403, which this API documents as a temporary service
      condition rather than an authorisation failure. Not retried: ``utils/backoff.py`` treats
      403 as permanent, and a 403 that is a real block would be hammered by a retry loop that
      cannot tell the two apart. The caller sees an error and the run reports a gap.
    * ``malformed_response`` -- HTTP 200 whose body carries no ``ranks`` array. Also unknown,
      never clean, and deliberately not collapsed into ``tranco_in_list: False``.

    429 and the 5xx family raise and are retried by :func:`with_exponential_backoff`, which
    honours ``Retry-After``. Retries that exhaust propagate as an exception, matching every
    other provider in this package; ``orchestrators._call_provider`` files it as a provider
    error. Each attempt takes its own pacing slot.
    """
    target = domain.strip()
    if not target:
        return {"ok": False, "error": "invalid_domain"}

    # One path segment, percent-encoded with no safe characters, so a hostile indicator cannot
    # add a segment, traverse upward, or append a query. The host is a fixed literal and is
    # never built from the indicator; the runtime egress hook in utils/http.py is the backstop.
    url = f"{TRANCO_BASE}/ranks/domain/{quote(target, safe='')}"

    async def _call() -> Dict[str, Any]:
        await _await_pacing_slot()
        r = await client.get(url)
        if r.status_code == 404:
            return {"ok": False, "error": "not_found", "status": 404}
        if r.status_code == 403:
            return {"ok": False, "error": "service_unavailable", "status": 403}
        r.raise_for_status()
        history = _history(r.json())
        if history is None:
            return {"ok": False, "error": "malformed_response", "status": r.status_code}
        return {"ok": True, "data": _payload(history)}

    return await with_exponential_backoff(_call)
