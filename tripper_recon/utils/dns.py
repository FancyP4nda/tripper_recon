from __future__ import annotations

import asyncio
import socket
from typing import List, Tuple


async def resolve_domain(domain: str) -> List[str]:
    # Uses system resolver via getaddrinfo in a thread to avoid blocking
    def _resolve() -> List[str]:
        addrs: set[str] = set()
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                infos = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
                for info in infos:
                    sockaddr = info[4]
                    ip = sockaddr[0]
                    addrs.add(ip)
            except socket.gaierror:
                continue
        return list(addrs)

    return await asyncio.to_thread(_resolve)


async def reverse_ptr(ip: str) -> str | None:
    def _rev() -> str | None:
        try:
            host, _aliases, _addrs = socket.gethostbyaddr(ip)
            return host
        except Exception:
            return None

    return await asyncio.to_thread(_rev)


