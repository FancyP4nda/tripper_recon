from __future__ import annotations

import asyncio
import random
from typing import Awaitable, Callable, TypeVar

T = TypeVar("T")


async def with_exponential_backoff(
    fn: Callable[[], Awaitable[T]],
    *,
    retries: int = 3,
    base_delay: float = 0.5,
    max_delay: float = 5.0,
) -> T:
    err: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return await fn()
        except Exception as e:  # noqa: BLE001
            err = e
            if attempt >= retries:
                break
            delay = min(max_delay, base_delay * (2**attempt))
            delay += random.uniform(0, 0.25 * delay)
            await asyncio.sleep(delay)
    assert err is not None
    raise err


