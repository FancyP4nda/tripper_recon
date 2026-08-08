"""Unit tests for tripper_recon.utils.backoff.with_exponential_backoff.

Every provider call in the package is wrapped in this helper, so its retry count is a direct
multiplier on the tool's egress and on provider quota burn. These tests assert on the delays
*requested* -- `asyncio.sleep` is patched out, so the suite is instant and makes no network calls.

Roadmap 3.5 ("Honour `Retry-After`; classify retryable vs non-retryable status codes") is the
scheduled fix for the behaviour documented in `test_retries_every_exception_including_a_401`:
today a 401 is retried four times while a transient 502 returned as a dict is never retried at all.
"""

from __future__ import annotations

import itertools
from typing import Any

import pytest

from tripper_recon.utils import backoff as backoff_mod
from tripper_recon.utils.backoff import with_exponential_backoff


@pytest.fixture()
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record every delay `with_exponential_backoff` asks for, without waiting.

    Jitter is pinned to zero so the arithmetic is deterministic; `test_jitter_is_bounded`
    exercises the un-pinned path separately.
    """
    recorded: list[float] = []

    async def _fake_sleep(delay: float) -> None:
        recorded.append(delay)

    monkeypatch.setattr(backoff_mod.asyncio, "sleep", _fake_sleep)
    monkeypatch.setattr(backoff_mod.random, "uniform", lambda _a, _b: 0.0)
    return recorded


class _Boom(Exception):
    """Distinguishable failure so tests can assert on identity, not just on type."""


async def test_succeeds_first_try_and_never_sleeps(sleeps: list[float]) -> None:
    calls: list[int] = []

    async def fn() -> str:
        calls.append(1)
        return "ok"

    assert await with_exponential_backoff(fn, retries=3) == "ok"
    assert len(calls) == 1
    assert sleeps == []


async def test_succeeds_on_retry_after_one_failure(sleeps: list[float]) -> None:
    calls: list[int] = []

    async def fn() -> str:
        calls.append(1)
        if len(calls) < 2:
            raise _Boom("transient")
        return "ok"

    assert await with_exponential_backoff(fn, retries=3, base_delay=0.5) == "ok"
    assert len(calls) == 2
    assert sleeps == [0.5]  # one sleep only -- no trailing sleep after the successful attempt


async def test_exhausts_retries_and_reraises_the_last_exception(sleeps: list[float]) -> None:
    """The re-raised object must be the LAST failure, not the first. If a caller retries a
    request that fails 500, 500, 403, the 403 is the actionable one."""
    raised: list[_Boom] = []

    async def fn() -> str:
        err = _Boom(f"attempt-{len(raised)}")
        raised.append(err)
        raise err

    with pytest.raises(_Boom) as exc_info:
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
        raise _Boom("always")

    with pytest.raises(_Boom):
        await with_exponential_backoff(fn, retries=retries, base_delay=0.5)

    assert len(calls) == expected_calls
    assert len(sleeps) == retries


async def test_retries_zero_makes_a_single_attempt_and_never_sleeps(sleeps: list[float]) -> None:
    calls: list[int] = []

    async def fn() -> str:
        calls.append(1)
        raise _Boom("no retries")

    with pytest.raises(_Boom):
        await with_exponential_backoff(fn, retries=0)

    assert len(calls) == 1
    assert sleeps == []


async def test_delay_grows_exponentially(sleeps: list[float]) -> None:
    async def fn() -> str:
        raise _Boom("always")

    with pytest.raises(_Boom):
        await with_exponential_backoff(fn, retries=4, base_delay=0.5, max_delay=100.0)

    assert sleeps == [0.5, 1.0, 2.0, 4.0]
    assert all(b > a for a, b in itertools.pairwise(sleeps))


async def test_delay_is_capped_at_max_delay(sleeps: list[float]) -> None:
    async def fn() -> str:
        raise _Boom("always")

    with pytest.raises(_Boom):
        await with_exponential_backoff(fn, retries=5, base_delay=1.0, max_delay=3.0)

    assert sleeps == [1.0, 2.0, 3.0, 3.0, 3.0]
    assert max(sleeps) <= 3.0


async def test_jitter_is_bounded_to_25_percent_above_the_base_delay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Jitter is additive and one-sided: `delay += random.uniform(0, 0.25 * delay)`, so a
    recorded delay is always in [d, 1.25d]. Asserted without pinning `random` so a change from
    additive to symmetric jitter is caught."""
    recorded: list[float] = []

    async def _fake_sleep(delay: float) -> None:
        recorded.append(delay)

    monkeypatch.setattr(backoff_mod.asyncio, "sleep", _fake_sleep)

    async def fn() -> str:
        raise _Boom("always")

    with pytest.raises(_Boom):
        await with_exponential_backoff(fn, retries=3, base_delay=1.0, max_delay=100.0)

    for i, actual in enumerate(recorded):
        undelayed = 1.0 * (2**i)
        assert undelayed <= actual <= undelayed * 1.25


async def test_retries_every_exception_including_a_401(sleeps: list[float]) -> None:
    """Documents CURRENT behaviour, not desired behaviour.

    There is no retryable/non-retryable classification: a 401 (bad API key -- never going to
    succeed) is retried the full `retries` times, wasting four requests against an authenticated
    endpoint and four rate-limit slots. Roadmap 3.5 adds status-code classification and
    `Retry-After` handling; when it lands this test should be replaced with one asserting that a
    401 fails fast.
    """

    class _Unauthorized(Exception):
        status_code = 401

    calls: list[int] = []

    async def fn() -> str:
        calls.append(1)
        raise _Unauthorized("401 Unauthorized")

    with pytest.raises(_Unauthorized):
        await with_exponential_backoff(fn, retries=3, base_delay=0.5)

    assert len(calls) == 4  # the 401 was retried three times
    assert sleeps == [0.5, 1.0, 2.0]


async def test_does_not_swallow_the_return_value_type(sleeps: list[float]) -> None:
    """The helper is generic; a falsy-but-valid provider result must come back untouched rather
    than being treated as a failure."""
    payloads: list[Any] = [{}, [], 0, "", None, False]
    for payload in payloads:

        async def fn(p: Any = payload) -> Any:
            return p

        assert await with_exponential_backoff(fn, retries=1) == payload
    assert sleeps == []
