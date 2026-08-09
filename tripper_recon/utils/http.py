"""HTTP client construction, the runtime egress allowlist, and the concurrency limiter.

Three concerns live in this one module on purpose: :func:`create_client` is the single place
an ``httpx.AsyncClient`` is built anywhere in the package, which makes it the only place a
check can be installed that sees *every* outbound request.

**The egress allowlist (roadmap 2.1).** ``tests/test_passivity.py`` scans the source for URL
literals, which catches a hard-coded destination but is blind to one assembled at runtime:
``client.get("https://" + target_host + "/")`` passes every static check and is a direct fetch
of the target. The request event hook installed here inspects the URL that is actually about
to leave and raises :class:`PassiveBoundaryViolation` when its host is not on
:data:`ALLOWED_EGRESS_HOSTS`. httpx runs request hooks before handing the request to the
transport, so a rejected request never opens a socket.

The two halves are complementary, not redundant: the static scan fails the build, the hook
fails the run.

**The limiter (roadmap 3.3).** The previous implementation built one module-global semaphore
lazily, at the rate the first caller happened to pass, and bound it to whichever event loop
created it. ``configure_rate_limit`` from the CLI therefore never took effect, and the
semaphore would have raised ``RuntimeError`` on a second ``asyncio.run()`` in the same process
the moment it actually contended. Both are fixed here: the rate is read at acquisition time,
and the semaphore is created inside the running loop and kept per loop.

**The User-Agent (roadmap 2.6).** The default identifies the tool. Impersonating a browser
bought nothing -- every authenticated provider already knows exactly who is calling from the
API key -- while creating a terms-of-service and evidence-chain problem.
"""

from __future__ import annotations

import asyncio
import os
import weakref
from contextlib import asynccontextmanager
from typing import AsyncIterator, Dict, FrozenSet, MutableMapping, Optional

import httpx

from tripper_recon import __version__
from tripper_recon.utils.redact import redact_url

# --------------------------------------------------------------------------------------
# Egress allowlist
# --------------------------------------------------------------------------------------

#: Where the OPSEC contract for this check is written down. Named as a constant so the
#: exception message and the docs cannot drift apart silently.
OPSEC_REFERENCE = "docs/OPSEC.md section 7"

#: Every host this tool is permitted to contact, and the provider each one serves.
#:
#: A host earns a place here only if it is a third party that ALREADY HOLDS the intelligence.
#: The target itself is never on this list and never can be -- that is the entire product
#: claim (docs/OPSEC.md section 1). Adding an entry is a deliberate act with an OPSEC
#: consequence: the new provider learns the operator's egress IP and indicator list. Add the
#: matching row to docs/OPSEC.md section 2 and to ``ALLOWED_HOSTS`` in
#: ``tests/test_passivity.py`` in the same commit.
#:
#: Deep-link hosts that are only ever RENDERED (radar.cloudflare.com, www.shodan.io,
#: www.abuseipdb.com) are deliberately absent: this tool must never fetch them, so a request
#: to one is a defect and should raise.
ALLOWED_EGRESS_HOSTS: FrozenSet[str] = frozenset(
    {
        "www.virustotal.com",  # VirusTotal API v3 - providers/virustotal.py
        "api.shodan.io",  # Shodan host lookup - providers/shodan_api.py
        "api.abuseipdb.com",  # AbuseIPDB /check - providers/abuseipdb.py
        "ipinfo.io",  # IPinfo geolocation and ASN - providers/ipinfo.py
        "otx.alienvault.com",  # AlienVault OTX API v1 - providers/otx.py
        "api.cloudflare.com",  # Cloudflare Radar GraphQL + BGP REST - providers/cloudflare_{radar,rest}.py
        "stat.ripe.net",  # RIPEstat data API - providers/ripestat.py
        "api.asrank.caida.org",  # CAIDA AS-Rank - providers/caida.py
        "www.peeringdb.com",  # PeeringDB net/IXP records - providers/peeringdb.py
        # urlscan.io Search API (GET /api/v1/search/) and Result API (GET /api/v1/result/{uuid}/)
        # - providers/urlscan.py. Reads of scans a DIFFERENT party already completed. The
        # submission route on this same API is forbidden permanently and without a flag,
        # because it loads the target in a real browser and publishes the scan; it is named
        # with its reason in docs/OPSEC.md section 7 and in tests/test_passivity.py, which
        # scans this package for the path on every run, so it is not spelled out here. The
        # screenshot base on this host is emitted as a link and never retrieved, so
        # allowlisting the host does not authorise fetching it.
        "urlscan.io",
    }
)


class PassiveBoundaryViolation(RuntimeError):
    """A request was about to leave for a host that is not on the egress allowlist.

    This is raised *before* the request reaches the transport, so nothing was sent. It is a
    programming error, not a runtime condition to be handled: reaching it means some code path
    in this package tried to contact a destination nobody reviewed, and the most likely such
    destination is the target under investigation.
    """

    def __init__(self, host: str, url: str) -> None:
        self.host = host
        self.url = url
        super().__init__(
            f"refusing to contact {host!r}: not on the egress allowlist. "
            f"Request was {url}. "
            "Tripper Recon investigates infrastructure without touching it; every outbound "
            "request must go to a third party that already holds the data, never to the "
            "target and never to anything the target operator can observe. "
            f"If this is a legitimate new passive provider, add it to "
            f"ALLOWED_EGRESS_HOSTS in tripper_recon/utils/http.py and record it in "
            f"{OPSEC_REFERENCE}. If the host came from a target-derived value interpolated "
            "into a URL, that is the violation itself."
        )


async def _enforce_egress_allowlist(request: httpx.Request) -> None:
    """httpx request event hook: reject any host that was not deliberately approved.

    The URL is redacted before it enters the exception message -- Shodan and IPinfo
    authenticate in the query string, and an exception message reaches logs and tracebacks.
    """
    host = (request.url.host or "").lower()
    if host not in ALLOWED_EGRESS_HOSTS:
        raise PassiveBoundaryViolation(host, redact_url(str(request.url)))


# --------------------------------------------------------------------------------------
# User-Agent
# --------------------------------------------------------------------------------------

#: Honest default. The tool says what it is; the API key already says who is calling.
DEFAULT_USER_AGENT = f"tripper-recon/{__version__}"

_global_user_agent: Optional[str] = None


def configure_user_agent(ua: Optional[str]) -> None:
    """Override the User-Agent for the rest of the process (the ``--user-agent`` flag)."""
    global _global_user_agent
    if ua:
        _global_user_agent = ua


def _user_agent() -> str:
    """Resolve the User-Agent: explicit override, then environment, then the honest default."""
    if _global_user_agent:
        return _global_user_agent
    value = os.getenv("TRIPPER_RECON_USER_AGENT")
    if value:
        ua = value.strip()
        if ua:
            return ua
    return DEFAULT_USER_AGENT


def default_headers() -> Dict[str, str]:
    return {
        "User-Agent": _user_agent(),
        "Accept": "application/json",
    }


def create_client(timeout: float = 15.0) -> httpx.AsyncClient:
    """Build the one client shape this package uses.

    No explicit ``transport=`` is passed. httpx applies ``http2`` and ``limits`` when it builds
    the transport itself; supplying a pre-built ``AsyncHTTPTransport`` makes it DISCARD both,
    which silently gave HTTP/1.1 and the 100-connection default instead of the 50 configured
    here. ``AsyncHTTPTransport`` defaults to ``retries=0`` anyway, so the line bought nothing
    (roadmap 3.1).
    """
    return httpx.AsyncClient(
        headers=default_headers(),
        http2=True,
        timeout=httpx.Timeout(timeout),
        limits=httpx.Limits(max_keepalive_connections=20, max_connections=50),
        event_hooks={"request": [_enforce_egress_allowlist]},
        verify=True,
    )


# --------------------------------------------------------------------------------------
# Concurrency limiter
# --------------------------------------------------------------------------------------

#: Concurrent in-flight provider requests permitted when the CLI does not say otherwise.
DEFAULT_RATE_LIMIT = 10

_configured_rate: int = DEFAULT_RATE_LIMIT


def configure_rate_limit(rate: int) -> None:
    """Set the process-wide concurrency ceiling (the ``--rate-limit`` flag).

    Read at acquisition time rather than captured at import time, which is what makes the flag
    reach every subcommand. Call it before ``asyncio.run``.
    """
    global _configured_rate
    _configured_rate = max(1, int(rate))


def configured_rate_limit() -> int:
    """The ceiling currently in force. Exposed for tests and for disclosure in output."""
    return _configured_rate


class _LoopLimiter:
    """The semaphore in force for one event loop, and the rate it was built for."""

    __slots__ = ("rate", "semaphore")

    def __init__(self, rate: int) -> None:
        self.rate = rate
        self.semaphore = asyncio.Semaphore(rate)


# Keyed by event loop, weakly, so a finished ``asyncio.run`` does not keep its loop alive and a
# second ``asyncio.run`` in the same process gets a semaphore bound to ITS loop. An
# asyncio.Semaphore attaches to the loop that first awaits on it; sharing one across loops
# raises RuntimeError as soon as it actually has to make a caller wait.
_loop_limiters: MutableMapping[asyncio.AbstractEventLoop, _LoopLimiter] = weakref.WeakKeyDictionary()


def _loop_semaphore() -> asyncio.Semaphore:
    """The semaphore for the running loop, created there if this is the loop's first request.

    Changing the rate mid-run replaces the semaphore, which can briefly allow the old and new
    ceilings to overlap in flight. That is accepted: ``configure_rate_limit`` is called once at
    startup, before any loop exists, and the alternative -- pinning the first rate a loop ever
    saw -- is the bug this function replaces.
    """
    loop = asyncio.get_running_loop()
    rate = _configured_rate
    limiter = _loop_limiters.get(loop)
    if limiter is None or limiter.rate != rate:
        limiter = _LoopLimiter(rate)
        _loop_limiters[loop] = limiter
    return limiter.semaphore


@asynccontextmanager
async def rate_limited() -> AsyncIterator[None]:
    """Hold one concurrency permit for the duration of the block.

    Wrap the AWAIT of a provider call, never ``asyncio.create_task``: creating a task schedules
    it without awaiting it, so a limiter around task creation acquires and releases in the same
    tick and constrains nothing (probe H6 -- requested 2, observed 10).

    The permit is held across a provider's internal retry sleeps as well as its request. That
    is deliberate: the ceiling is there to bound what this tool does to a provider's quota, and
    a retry spends that quota.
    """
    semaphore = _loop_semaphore()
    await semaphore.acquire()
    try:
        yield
    finally:
        semaphore.release()
