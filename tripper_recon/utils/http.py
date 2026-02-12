from __future__ import annotations

import asyncio
import os
from typing import Any, Dict

import httpx


_DEFAULT_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0"
)


def _user_agent() -> str:
    value = os.getenv("TRIPPER_RECON_USER_AGENT")
    if value:
        ua = value.strip()
        if ua:
            return ua
    return _DEFAULT_BROWSER_UA


def default_headers() -> Dict[str, str]:
    return {
        "User-Agent": _user_agent(),
        "Accept": "application/json",
    }


def create_client(timeout: float = 15.0) -> httpx.AsyncClient:
    limits = httpx.Limits(max_keepalive_connections=20, max_connections=50)
    transport = httpx.AsyncHTTPTransport(retries=0)
    return httpx.AsyncClient(
        headers=default_headers(),
        http2=True,
        timeout=httpx.Timeout(timeout),
        limits=limits,
        transport=transport,
        verify=True,
    )


class RateLimiter:
    def __init__(self, rate: int = 5):
        self._sem = asyncio.Semaphore(rate)

    async def __aenter__(self) -> "RateLimiter":
        await self._sem.acquire()
        return self

    async def __aexit__(self, *_: Any) -> None:
        self._sem.release()


