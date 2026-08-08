from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Iterable, List

# Wall-clock ceiling for one address-family lookup. The two families run concurrently, so
# this is also the ceiling for ``resolve_domain`` as a whole.
#
# ``getaddrinfo`` carries no timeout of its own: against a black-holed or slow authoritative
# nameserver the caller blocks for the system resolver's full retry schedule, commonly 20-40
# seconds. On the domain path that block sits in front of every downstream provider call.
RESOLVE_TIMEOUT_SECONDS = 5.0


def _sorted_addresses(addrs: Iterable[str]) -> List[str]:
    """Deduplicate and order addresses deterministically.

    Sorting on the packed form gives numeric order (``10.0.0.2`` before ``10.0.0.10``) rather
    than the lexicographic order a plain string sort produces. The literal is carried as a
    tiebreaker because ``packed`` discards an IPv6 scope id, so ``fe80::1%eth0`` and
    ``fe80::1%eth1`` are otherwise equal keys and would fall back to input order. Anything
    ``ipaddress`` refuses at all falls back to a plain string sort, which is still
    deterministic.

    Determinism is the point. This list flows into ``data['ips']`` and into the rendered
    panels, so two runs against the same domain have to diff cleanly (roadmap 4.9). The
    previous ``list(set(...))`` ordered by hash seed and did not.
    """
    unique = set(addrs)
    try:
        return sorted(unique, key=lambda addr: (ipaddress.ip_address(addr).packed, addr))
    except ValueError:
        return sorted(unique)


def _lookup_family(domain: str, family: int) -> List[str]:
    """Blocking ``getaddrinfo`` for one address family. Runs in a worker thread."""
    try:
        infos = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    # sockaddr[0] is typed str | int (AF_INET6 tuples carry ints); the host is always the
    # first element and always a string in practice.
    return [str(info[4][0]) for info in infos]


async def _resolve_family(domain: str, family: int) -> List[str]:
    """One family lookup, independently time-bounded and independently cancellable.

    Cancelling a ``to_thread`` call releases the awaiting coroutine but does not stop the
    worker thread -- ``getaddrinfo`` is not interruptible from Python. The thread finishes on
    its own and its result is discarded. What the timeout buys is a bounded critical path,
    not a reclaimed thread; say so rather than implying the lookup was stopped.
    """
    try:
        return await asyncio.wait_for(asyncio.to_thread(_lookup_family, domain, family), RESOLVE_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        return []


async def resolve_domain(domain: str) -> List[str]:
    """Resolve ``domain`` to its A and AAAA addresses through the system resolver.

    This is the tool's one active step (docs/OPSEC.md section 3) and it stays that way; the
    operator has accepted resolver egress as a known risk.

    Two properties the callers depend on:

    * **Bounded.** Each family is resolved in its own thread under its own
      ``RESOLVE_TIMEOUT_SECONDS`` deadline. A family that times out contributes nothing and
      the other family's answers are still returned -- a partial answer beats an exception on
      a path that has no handler for one.
    * **Deterministic.** IPv4 addresses first, then IPv6, each block deduplicated and sorted
      numerically. Resolvers rotate answer order between queries; the caller must not.

    A resolver failure for one family is ``socket.gaierror`` and yields an empty list for that
    family. Any other exception still propagates, as it did before, rather than being
    silently converted into "this domain has no addresses".
    """
    results = await asyncio.gather(
        _resolve_family(domain, socket.AF_INET),
        _resolve_family(domain, socket.AF_INET6),
        return_exceptions=True,
    )

    resolved: List[List[str]] = []
    for result in results:
        if isinstance(result, BaseException):
            raise result
        resolved.append(result)

    v4, v6 = resolved
    return _sorted_addresses(v4) + _sorted_addresses(v6)


async def reverse_ptr(ip: str) -> str | None:
    def _rev() -> str | None:
        try:
            host, _aliases, _addrs = socket.gethostbyaddr(ip)
            return host
        except Exception:
            return None

    return await asyncio.to_thread(_rev)
