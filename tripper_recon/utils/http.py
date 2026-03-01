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

_global_user_agent: str | None = None

def configure_user_agent(ua: str | None) -> None:
    global _global_user_agent
    if ua:
        _global_user_agent = ua

def _user_agent() -> str:
    if _global_user_agent:
        return _global_user_agent
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


_global_sem: asyncio.Semaphore | None = None
_init_rate: int = 10

def configure_rate_limit(rate: int) -> None:
    global _init_rate
    _init_rate = max(1, rate)

class RateLimiter:
    def __init__(self, rate: int | None = None):
        global _global_sem
        if _global_sem is None:
            _global_sem = asyncio.Semaphore(rate if rate is not None else _init_rate)
        self._sem = _global_sem

    async def __aenter__(self) -> "RateLimiter":
        await self._sem.acquire()
        return self

    async def __aexit__(self, *_: Any) -> None:
        self._sem.release()


