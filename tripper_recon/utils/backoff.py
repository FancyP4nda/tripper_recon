"""Retry policy for provider HTTP calls.

Every provider in the package wraps its request in :func:`with_exponential_backoff`, so the
policy here is a direct multiplier on the tool's egress and on each provider's rate-limit
budget. Retrying is therefore decided by *what failed*, not by the fact that something did.

Classification -- :func:`is_retryable_exception`:

* ``httpx.RequestError`` (connect failure, timeout, read error). The request may never have
  reached the provider, so a retry is the correct response.
* ``httpx.HTTPStatusError`` whose status is in :data:`RETRYABLE_STATUS_CODES` -- the transient
  server-side and throttling responses.
* Everything else -- 401/403/404, any other 4xx, and any non-httpx exception such as a JSON
  decode failure -- is permanent for this key and this indicator. It is raised on the first
  attempt with no sleep, because retrying it burns three more rate-limit slots and still fails.

``Retry-After`` (RFC 9110 section 10.2.3 -- deliberately cited by number, not by URL: the
passivity test in ``tests/test_passivity.py`` allowlists every URL literal in the package) is
honoured when the response carries it, in both the delta-seconds and the HTTP-date form, and it
overrides the exponential schedule for that attempt. It is clamped to
:data:`RETRY_AFTER_CEILING_SECONDS` (60 seconds) so a hostile or broken header cannot park an
investigation for an hour. It is deliberately allowed to exceed ``max_delay``: a server that
names a wait has better information than the local schedule does, and ignoring it is how a
client earns a longer ban.

Nuance worth knowing: ``httpx.DecodingError`` and ``httpx.TooManyRedirects`` are subclasses of
``httpx.RequestError`` and so are retried under the rule above, even though both are likely to
be permanent. They are rare on the ten providers in use and the retry count is bounded; the rule
is kept as stated rather than special-cased.
"""

from __future__ import annotations

import asyncio
import datetime
import email.utils
import math
import random
import time
from typing import Awaitable, Callable, FrozenSet, Optional, TypeVar

import httpx

T = TypeVar("T")

#: Statuses worth a second attempt: request timeout, too-early, throttled, and the 5xx family
#: that indicates the server -- not the request -- is the problem.
RETRYABLE_STATUS_CODES: FrozenSet[int] = frozenset({408, 425, 429, 500, 502, 503, 504})

#: Upper bound applied to any server-supplied ``Retry-After``. A provider (or a hostile
#: middlebox) can send ``Retry-After: 86400``; honouring that literally would hang an
#: investigation for a day. Sixty seconds is longer than every published per-minute window
#: across the providers in use and short enough that the analyst does not think the tool died.
RETRY_AFTER_CEILING_SECONDS: float = 60.0

#: Jitter is additive and one-sided: a computed delay ``d`` is slept as a value in
#: ``[d, d * (1 + JITTER_FRACTION)]``. Ten providers firing concurrently would otherwise retry
#: in lockstep.
JITTER_FRACTION: float = 0.25


def is_retryable_exception(exc: BaseException) -> bool:
    """Return True when retrying ``exc`` could plausibly succeed.

    Exposed separately from the retry loop so the policy can be unit-tested and so a caller can
    compose it into its own ``should_retry``.
    """
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in RETRYABLE_STATUS_CODES
    # HTTPStatusError is checked first because it is a sibling of RequestError, not a subclass;
    # anything reaching here is a transport failure or an unrelated exception.
    return isinstance(exc, httpx.RequestError)


def parse_retry_after(value: str, *, now: Optional[float] = None) -> Optional[float]:
    """Parse a ``Retry-After`` header value into seconds-from-now.

    Accepts both RFC 9110 forms -- delta-seconds (``"120"``) and an HTTP-date
    (``"Wed, 21 Oct 2015 07:28:00 GMT"``). Returns ``None`` when the value is not parseable in
    either form, so the caller can fall back to its own schedule. A value in the past, or a
    negative delta, yields ``0.0`` rather than a negative sleep.

    ``now`` overrides the wall-clock reference used for the HTTP-date form; it exists so tests
    can assert exact values without patching :mod:`time`.
    """
    raw = value.strip()
    if not raw:
        return None

    try:
        seconds = float(raw)
    except ValueError:
        pass
    else:
        # Reject nan/inf, which float() accepts and which would poison the sleep.
        return max(0.0, seconds) if math.isfinite(seconds) else None

    try:
        parsed = email.utils.parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        # RFC 9110 HTTP-dates are GMT; a missing zone is treated as such rather than as local.
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)

    reference = time.time() if now is None else now
    return max(0.0, parsed.timestamp() - reference)


def retry_after_seconds(exc: BaseException, *, now: Optional[float] = None) -> Optional[float]:
    """Extract an unclamped ``Retry-After`` hint from ``exc``, or ``None`` if it carries none."""
    if not isinstance(exc, httpx.HTTPStatusError):
        return None
    raw = exc.response.headers.get("Retry-After")
    if raw is None:
        return None
    return parse_retry_after(raw, now=now)


def next_delay(
    exc: BaseException,
    *,
    attempt: int,
    base_delay: float = 0.5,
    max_delay: float = 5.0,
    retry_after_ceiling: float = RETRY_AFTER_CEILING_SECONDS,
    now: Optional[float] = None,
) -> float:
    """Seconds to wait before retrying ``exc``, where ``attempt`` is the 0-based failed attempt.

    A server-supplied ``Retry-After`` wins and is clamped to ``retry_after_ceiling``; it is not
    jittered, because the server named a specific wait. Otherwise the delay is the jittered
    exponential ``base_delay * 2**attempt``, capped at ``max_delay``.
    """
    hinted = retry_after_seconds(exc, now=now)
    if hinted is not None:
        return min(hinted, retry_after_ceiling)
    delay = min(max_delay, base_delay * (2**attempt))
    return delay + random.uniform(0, JITTER_FRACTION * delay)


async def with_exponential_backoff(
    fn: Callable[[], Awaitable[T]],
    *,
    retries: int = 3,
    base_delay: float = 0.5,
    max_delay: float = 5.0,
    retry_after_ceiling: float = RETRY_AFTER_CEILING_SECONDS,
    should_retry: Callable[[BaseException], bool] = is_retryable_exception,
) -> T:
    """Call ``fn``, retrying only failures that ``should_retry`` classifies as transient.

    ``retries=N`` permits N+1 attempts and at most N sleeps; there is never a sleep after the
    final attempt, and never a sleep before raising a non-retryable failure. The exception that
    escapes is the last one observed, re-raised with its original traceback.
    """
    for attempt in range(retries + 1):
        try:
            return await fn()
        except Exception as exc:  # noqa: BLE001 -- classified below, not swallowed
            if attempt >= retries or not should_retry(exc):
                raise
            await asyncio.sleep(
                next_delay(
                    exc,
                    attempt=attempt,
                    base_delay=base_delay,
                    max_delay=max_delay,
                    retry_after_ceiling=retry_after_ceiling,
                )
            )
    raise AssertionError("unreachable: the retry loop always returns or raises")
