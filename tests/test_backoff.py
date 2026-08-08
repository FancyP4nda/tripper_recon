"""Unit tests for tripper_recon.utils.backoff.

Every provider call in the package is wrapped in `with_exponential_backoff`, so its retry policy
is a direct multiplier on the tool's egress and on provider quota burn. These tests assert on the
delays *requested* -- `asyncio.sleep` is patched out, so the suite is instant. Nothing here opens
a socket: `httpx.Request` / `httpx.Response` objects are constructed locally.

Roadmap 3.5 ("Honour `Retry-After`; classify retryable vs non-retryable status codes") has
landed. The retry decision is now made by `is_retryable_exception` on the status code, not by
whichever error style a given provider happens to use, and a 401 fails on the first attempt.
"""

from __future__ import annotations

import email.utils
import itertools
import time
from typing import Any, Dict, Optional

import httpx
import pytest

from tripper_recon.utils import backoff as backoff_mod
from tripper_recon.utils.backoff import (
    JITTER_FRACTION,
    RETRY_AFTER_CEILING_SECONDS,
    RETRYABLE_STATUS_CODES,
    is_retryable_exception,
    next_delay,
    parse_retry_after,
    with_exponential_backoff,
)

NON_RETRYABLE_STATUSES = [400, 401, 403, 404, 405, 409, 410, 418, 422, 451, 501]


def _status_error(
    status: int,
    headers: Optional[Dict[str, str]] = None,
    *,
    message: Optional[str] = None,
) -> httpx.HTTPStatusError:
    """Build an `httpx.HTTPStatusError` the way `response.raise_for_status()` would.

    Constructed offline -- no transport is involved, so no request leaves the machine.
    """
    request = httpx.Request("GET", "https://provider.invalid/v3/probe")
    response = httpx.Response(status, headers=headers or {}, request=request)
    return httpx.HTTPStatusError(message or f"HTTP {status}", request=request, response=response)


def _network_error(exc_type: type[httpx.RequestError] = httpx.ConnectError) -> httpx.RequestError:
    return exc_type("transport failed", request=httpx.Request("GET", "https://provider.invalid/v3/probe"))


def _http_date(offset_seconds: float, *, now: Optional[float] = None) -> str:
    """Format an HTTP-date `offset_seconds` in the future, per RFC 9110."""
    reference = time.time() if now is None else now
    return email.utils.formatdate(reference + offset_seconds, usegmt=True)


@pytest.fixture()
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record every delay the helper asks for, without waiting.

    Jitter is pinned to zero so the arithmetic is deterministic; `test_jitter_is_bounded...`
    exercises the un-pinned path separately.
    """
    recorded: list[float] = []

    async def _fake_sleep(delay: float) -> None:
        recorded.append(delay)

    monkeypatch.setattr(backoff_mod.asyncio, "sleep", _fake_sleep)
    monkeypatch.setattr(backoff_mod.random, "uniform", lambda _a, _b: 0.0)
    return recorded


# --------------------------------------------------------------------------------------------
# Classification predicate
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("status", sorted(RETRYABLE_STATUS_CODES))
def test_is_retryable_accepts_the_transient_statuses(status: int) -> None:
    assert is_retryable_exception(_status_error(status)) is True


@pytest.mark.parametrize("status", NON_RETRYABLE_STATUSES)
def test_is_retryable_rejects_permanent_statuses(status: int) -> None:
    """401/403/404 are permanent for a given key and indicator -- retrying spends quota to earn
    the same answer."""
    assert is_retryable_exception(_status_error(status)) is False


@pytest.mark.parametrize(
    "exc_type",
    [httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.PoolTimeout, httpx.ReadError],
)
def test_is_retryable_accepts_transport_failures(exc_type: type[httpx.RequestError]) -> None:
    """A transport failure may mean the request never reached the provider at all."""
    assert is_retryable_exception(_network_error(exc_type)) is True


@pytest.mark.parametrize("exc", [ValueError("bad json"), KeyError("data"), RuntimeError("boom"), TypeError()])
def test_is_retryable_rejects_non_httpx_exceptions(exc: Exception) -> None:
    """A JSON decode failure or a KeyError on a parsed body is deterministic: the same request
    returns the same broken body."""
    assert is_retryable_exception(exc) is False


def test_retryable_status_set_is_exactly_the_documented_one() -> None:
    """Pinned deliberately: silently widening this set multiplies egress against every provider."""
    assert set(RETRYABLE_STATUS_CODES) == {408, 425, 429, 500, 502, 503, 504}


# --------------------------------------------------------------------------------------------
# Retry loop -- happy paths and counting
# --------------------------------------------------------------------------------------------


async def test_succeeds_first_try_and_never_sleeps(sleeps: list[float]) -> None:
    calls: list[int] = []

    async def fn() -> str:
        calls.append(1)
        return "ok"

    assert await with_exponential_backoff(fn, retries=3) == "ok"
    assert len(calls) == 1
    assert sleeps == []


async def test_succeeds_on_retry_after_one_transient_failure(sleeps: list[float]) -> None:
    calls: list[int] = []

    async def fn() -> str:
        calls.append(1)
        if len(calls) < 2:
            raise _status_error(503)
        return "ok"

    assert await with_exponential_backoff(fn, retries=3, base_delay=0.5) == "ok"
    assert len(calls) == 2
    assert sleeps == [0.5]  # one sleep only -- no trailing sleep after the successful attempt


async def test_exhausts_retries_and_reraises_the_last_exception(sleeps: list[float]) -> None:
    """The re-raised object must be the LAST failure, not the first. If a caller retries a
    request that fails 500, 500, 503, the last one is what the analyst sees."""
    raised: list[httpx.HTTPStatusError] = []

    async def fn() -> str:
        err = _status_error(503, message=f"attempt-{len(raised)}")
        raised.append(err)
        raise err

    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        await with_exponential_backoff(fn, retries=2, base_delay=0.5)

    assert len(raised) == 3
    assert exc_info.value is raised[-1]
    assert str(exc_info.value) == "attempt-2"


@pytest.mark.parametrize(("retries", "expected_calls"), [(0, 1), (1, 2), (2, 3), (3, 4), (5, 6)])
async def test_respects_the_retries_count_exactly(sleeps: list[float], retries: int, expected_calls: int) -> None:
    """`retries=N` means N+1 total attempts and N sleeps. Off-by-one here is a silent doubling
    of provider quota consumption."""
    calls: list[int] = []

    async def fn() -> str:
        calls.append(1)
        raise _status_error(503)

    with pytest.raises(httpx.HTTPStatusError):
        await with_exponential_backoff(fn, retries=retries, base_delay=0.5)

    assert len(calls) == expected_calls
    assert len(sleeps) == retries


async def test_retries_zero_makes_a_single_attempt_and_never_sleeps(sleeps: list[float]) -> None:
    calls: list[int] = []

    async def fn() -> str:
        calls.append(1)
        raise _status_error(503)

    with pytest.raises(httpx.HTTPStatusError):
        await with_exponential_backoff(fn, retries=0)

    assert len(calls) == 1
    assert sleeps == []


async def test_does_not_swallow_the_return_value_type(sleeps: list[float]) -> None:
    """The helper is generic; a falsy-but-valid provider result must come back untouched rather
    than being treated as a failure."""
    payloads: list[Any] = [{}, [], 0, "", None, False]
    for payload in payloads:

        async def fn(p: Any = payload) -> Any:
            return p

        assert await with_exponential_backoff(fn, retries=1) == payload
    assert sleeps == []


# --------------------------------------------------------------------------------------------
# Retry loop -- classification drives the loop
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("status", sorted(RETRYABLE_STATUS_CODES))
async def test_retryable_status_is_retried_the_full_count(sleeps: list[float], status: int) -> None:
    calls: list[int] = []

    async def fn() -> str:
        calls.append(1)
        raise _status_error(status)

    with pytest.raises(httpx.HTTPStatusError):
        await with_exponential_backoff(fn, retries=3, base_delay=0.5)

    assert len(calls) == 4
    assert sleeps == [0.5, 1.0, 2.0]


@pytest.mark.parametrize("status", NON_RETRYABLE_STATUSES)
async def test_non_retryable_status_is_attempted_exactly_once(sleeps: list[float], status: int) -> None:
    calls: list[int] = []

    async def fn() -> str:
        calls.append(1)
        raise _status_error(status)

    with pytest.raises(httpx.HTTPStatusError):
        await with_exponential_backoff(fn, retries=3, base_delay=0.5)

    assert len(calls) == 1
    assert sleeps == []


async def test_a_401_fails_fast(sleeps: list[float]) -> None:
    """Replaces `test_retries_every_exception_including_a_401`, which documented the pre-3.5
    behaviour: a bad API key was retried four times against an authenticated endpoint, burning
    four rate-limit slots on a request that can never succeed. It now costs exactly one."""
    calls: list[int] = []

    async def fn() -> str:
        calls.append(1)
        raise _status_error(401)

    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        await with_exponential_backoff(fn, retries=3, base_delay=0.5)

    assert len(calls) == 1
    assert sleeps == []
    assert exc_info.value.response.status_code == 401


async def test_a_401_fails_fast_even_when_it_carries_retry_after(sleeps: list[float]) -> None:
    """Classification is checked before the `Retry-After` hint is read, so a header on a
    permanent failure cannot resurrect it."""
    calls: list[int] = []

    async def fn() -> str:
        calls.append(1)
        raise _status_error(401, {"Retry-After": "30"})

    with pytest.raises(httpx.HTTPStatusError):
        await with_exponential_backoff(fn, retries=3)

    assert len(calls) == 1
    assert sleeps == []


async def test_network_error_is_retried(sleeps: list[float]) -> None:
    calls: list[int] = []

    async def fn() -> str:
        calls.append(1)
        raise _network_error(httpx.ConnectTimeout)

    with pytest.raises(httpx.ConnectTimeout):
        await with_exponential_backoff(fn, retries=2, base_delay=0.5)

    assert len(calls) == 3
    assert sleeps == [0.5, 1.0]


async def test_unclassified_exception_is_not_retried(sleeps: list[float]) -> None:
    """A malformed provider body raises `ValueError` from `r.json()`. Retrying re-fetches the
    same malformed body, so the helper surfaces it immediately."""
    calls: list[int] = []

    async def fn() -> str:
        calls.append(1)
        raise ValueError("Expecting value: line 1 column 1")

    with pytest.raises(ValueError):
        await with_exponential_backoff(fn, retries=3)

    assert len(calls) == 1
    assert sleeps == []


async def test_should_retry_is_overridable(sleeps: list[float]) -> None:
    """The predicate is a parameter, so a caller with provider-specific knowledge can widen or
    narrow the policy without editing the loop."""
    calls: list[int] = []

    async def fn() -> str:
        calls.append(1)
        raise ValueError("normally permanent")

    with pytest.raises(ValueError):
        await with_exponential_backoff(fn, retries=2, base_delay=0.5, should_retry=lambda _exc: True)

    assert len(calls) == 3
    assert sleeps == [0.5, 1.0]


# --------------------------------------------------------------------------------------------
# Exponential schedule and jitter
# --------------------------------------------------------------------------------------------


async def test_delay_grows_exponentially(sleeps: list[float]) -> None:
    async def fn() -> str:
        raise _status_error(500)

    with pytest.raises(httpx.HTTPStatusError):
        await with_exponential_backoff(fn, retries=4, base_delay=0.5, max_delay=100.0)

    assert sleeps == [0.5, 1.0, 2.0, 4.0]
    assert all(b > a for a, b in itertools.pairwise(sleeps))


async def test_delay_is_capped_at_max_delay(sleeps: list[float]) -> None:
    async def fn() -> str:
        raise _status_error(502)

    with pytest.raises(httpx.HTTPStatusError):
        await with_exponential_backoff(fn, retries=5, base_delay=1.0, max_delay=3.0)

    assert sleeps == [1.0, 2.0, 3.0, 3.0, 3.0]
    assert max(sleeps) <= 3.0


async def test_jitter_is_bounded_to_25_percent_above_the_base_delay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Jitter is additive and one-sided, so a recorded delay is always in [d, 1.25d]. Asserted
    without pinning `random` so a change from additive to symmetric jitter is caught."""
    recorded: list[float] = []

    async def _fake_sleep(delay: float) -> None:
        recorded.append(delay)

    monkeypatch.setattr(backoff_mod.asyncio, "sleep", _fake_sleep)

    async def fn() -> str:
        raise _status_error(503)

    with pytest.raises(httpx.HTTPStatusError):
        await with_exponential_backoff(fn, retries=3, base_delay=1.0, max_delay=100.0)

    assert len(recorded) == 3
    for i, actual in enumerate(recorded):
        undelayed = 1.0 * (2**i)
        assert undelayed <= actual <= undelayed * (1 + JITTER_FRACTION)


# --------------------------------------------------------------------------------------------
# Retry-After parsing
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("0", 0.0),
        ("1", 1.0),
        ("120", 120.0),
        (" 45 ", 45.0),
        ("-5", 0.0),  # a negative delta means "now", not "sleep backwards"
        ("2.5", 2.5),  # out of spec but unambiguous; accepted rather than discarded
    ],
)
def test_parse_retry_after_delta_seconds(value: str, expected: float) -> None:
    assert parse_retry_after(value) == pytest.approx(expected)


def test_parse_retry_after_http_date_is_relative_to_now() -> None:
    """RFC 9110 example date, evaluated against a fixed reference so the assertion is exact."""
    reference = email.utils.parsedate_to_datetime("Wed, 21 Oct 2015 07:28:00 GMT").timestamp()
    assert parse_retry_after("Wed, 21 Oct 2015 07:28:30 GMT", now=reference) == pytest.approx(30.0)


def test_parse_retry_after_http_date_in_the_past_clamps_to_zero() -> None:
    reference = email.utils.parsedate_to_datetime("Wed, 21 Oct 2015 07:28:00 GMT").timestamp()
    assert parse_retry_after("Wed, 21 Oct 2015 07:00:00 GMT", now=reference) == 0.0


@pytest.mark.parametrize("value", ["", "   ", "soon", "later please", "Wed, 99 Zzz 2015 07:28:00 GMT", "nan", "inf"])
def test_parse_retry_after_rejects_unparseable_values(value: str) -> None:
    """Returning None -- not 0.0 -- matters: 0.0 would mean "retry immediately", which is the
    opposite of what a broken throttling header should buy."""
    assert parse_retry_after(value) is None


# --------------------------------------------------------------------------------------------
# Retry-After in the loop
# --------------------------------------------------------------------------------------------


async def test_retry_after_delta_seconds_is_honoured(sleeps: list[float]) -> None:
    async def fn() -> str:
        raise _status_error(429, {"Retry-After": "7"})

    with pytest.raises(httpx.HTTPStatusError):
        await with_exponential_backoff(fn, retries=2, base_delay=0.5, max_delay=5.0)

    assert sleeps == [7.0, 7.0]


async def test_retry_after_http_date_is_honoured(sleeps: list[float]) -> None:
    """The date form is evaluated against the real clock here, so the assertion is a window
    rather than a point; `test_parse_retry_after_http_date_is_relative_to_now` pins the exact
    arithmetic."""

    async def fn() -> str:
        raise _status_error(503, {"Retry-After": _http_date(30)})

    with pytest.raises(httpx.HTTPStatusError):
        await with_exponential_backoff(fn, retries=1, base_delay=0.5, max_delay=5.0)

    assert len(sleeps) == 1
    assert 25.0 <= sleeps[0] <= 30.0  # formatdate truncates to whole seconds


async def test_retry_after_overrides_max_delay(sleeps: list[float]) -> None:
    """`max_delay` bounds the local schedule. A server that names a wait is better informed, and
    undercutting it is how a client earns a longer ban."""

    async def fn() -> str:
        raise _status_error(429, {"Retry-After": "20"})

    with pytest.raises(httpx.HTTPStatusError):
        await with_exponential_backoff(fn, retries=1, base_delay=0.5, max_delay=5.0)

    assert sleeps == [20.0]


@pytest.mark.parametrize("value", ["3600", "86400", "999999"])
async def test_retry_after_is_clamped_to_the_ceiling(sleeps: list[float], value: str) -> None:
    """A hostile or broken header must not park an investigation for an hour."""

    async def fn() -> str:
        raise _status_error(429, {"Retry-After": value})

    with pytest.raises(httpx.HTTPStatusError):
        await with_exponential_backoff(fn, retries=1)

    assert sleeps == [RETRY_AFTER_CEILING_SECONDS]
    assert RETRY_AFTER_CEILING_SECONDS == 60.0


async def test_retry_after_http_date_far_in_the_future_is_clamped(sleeps: list[float]) -> None:
    async def fn() -> str:
        raise _status_error(503, {"Retry-After": _http_date(6 * 3600)})

    with pytest.raises(httpx.HTTPStatusError):
        await with_exponential_backoff(fn, retries=1)

    assert sleeps == [RETRY_AFTER_CEILING_SECONDS]


async def test_retry_after_ceiling_is_overridable(sleeps: list[float]) -> None:
    async def fn() -> str:
        raise _status_error(429, {"Retry-After": "600"})

    with pytest.raises(httpx.HTTPStatusError):
        await with_exponential_backoff(fn, retries=1, retry_after_ceiling=90.0)

    assert sleeps == [90.0]


async def test_malformed_retry_after_falls_back_to_the_exponential_schedule(sleeps: list[float]) -> None:
    async def fn() -> str:
        raise _status_error(429, {"Retry-After": "whenever"})

    with pytest.raises(httpx.HTTPStatusError):
        await with_exponential_backoff(fn, retries=3, base_delay=0.5, max_delay=100.0)

    assert sleeps == [0.5, 1.0, 2.0]


async def test_retry_after_zero_sleeps_zero_not_the_exponential_delay(sleeps: list[float]) -> None:
    """`Retry-After: 0` is a real instruction ("try again now"), and must not be confused with
    an absent header."""

    async def fn() -> str:
        raise _status_error(503, {"Retry-After": "0"})

    with pytest.raises(httpx.HTTPStatusError):
        await with_exponential_backoff(fn, retries=2, base_delay=0.5)

    assert sleeps == [0.0, 0.0]


async def test_retry_after_is_never_slept_after_the_final_attempt(sleeps: list[float]) -> None:
    """The header is present on every response, but a sleep after the last attempt only delays
    the error the analyst is waiting for."""
    calls: list[int] = []

    async def fn() -> str:
        calls.append(1)
        raise _status_error(429, {"Retry-After": "10"})

    with pytest.raises(httpx.HTTPStatusError):
        await with_exponential_backoff(fn, retries=2)

    assert len(calls) == 3
    assert sleeps == [10.0, 10.0]


async def test_retry_after_is_read_per_attempt(sleeps: list[float]) -> None:
    """A server that lengthens its cool-off between attempts is followed, not averaged."""
    hints = ["2", "8", "30"]
    calls: list[int] = []

    async def fn() -> str:
        idx = len(calls)
        calls.append(1)
        raise _status_error(429, {"Retry-After": hints[idx]})

    with pytest.raises(httpx.HTTPStatusError):
        await with_exponential_backoff(fn, retries=2, base_delay=0.5)

    assert sleeps == [2.0, 8.0]


# --------------------------------------------------------------------------------------------
# next_delay in isolation
# --------------------------------------------------------------------------------------------


def test_next_delay_prefers_retry_after_over_the_schedule(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backoff_mod.random, "uniform", lambda _a, _b: 0.0)
    exc = _status_error(429, {"Retry-After": "12"})
    assert next_delay(exc, attempt=0, base_delay=0.5, max_delay=5.0) == 12.0


def test_next_delay_without_retry_after_uses_the_schedule(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backoff_mod.random, "uniform", lambda _a, _b: 0.0)
    exc = _status_error(500)
    assert [next_delay(exc, attempt=i, base_delay=0.5, max_delay=100.0) for i in range(4)] == [0.5, 1.0, 2.0, 4.0]


def test_next_delay_on_a_non_status_error_uses_the_schedule(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backoff_mod.random, "uniform", lambda _a, _b: 0.0)
    assert next_delay(_network_error(), attempt=2, base_delay=0.5, max_delay=100.0) == 2.0
