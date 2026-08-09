"""Tests for the HTTP core: the egress allowlist, the limiter, and the User-Agent.

Three roadmap items are pinned here, and each one replaced a control that was decorative:

* **2.1 — the egress allowlist.** ``tests/test_passivity.py`` scans the source for URL
  literals, which cannot see a host assembled at runtime. The request event hook installed by
  ``create_client`` inspects the URL actually about to leave. The two together are the gate;
  either alone is not.
* **3.1 / 3.3 — the client and the limiter.** Passing an explicit ``transport=`` made httpx
  discard the configured ``http2`` and ``limits``. The limiter acquired and released a
  semaphore around ``asyncio.create_task`` (which schedules without awaiting, so it bounded
  nothing), built that semaphore at whatever rate the first caller happened to pass (so
  ``--rate-limit`` never took effect), and pinned it to one event loop (so a second
  ``asyncio.run`` in the same process would have raised ``RuntimeError`` the moment it
  actually contended).
* **2.6 — the User-Agent.** The default impersonated Chrome. The API key already identifies
  the caller, so the impersonation bought nothing and created a terms-of-service exposure.

No test here makes a network call. The allowlist tests run inside ``respx`` with the route
registered but never reached: that a mocked request is NOT recorded is the assertion.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Iterator, List

import httpx
import pytest
import respx

from tests.test_passivity import ALLOWED_HOSTS as STATICALLY_ALLOWED_HOSTS
from tests.test_passivity import EXPECTED_PROVIDER_HOSTS
from tripper_recon import __version__
from tripper_recon.orchestrators import _call_provider
from tripper_recon.utils import http
from tripper_recon.utils.http import (
    ALLOWED_EGRESS_HOSTS,
    DEFAULT_RATE_LIMIT,
    DEFAULT_USER_AGENT,
    OPSEC_REFERENCE,
    PassiveBoundaryViolation,
    configure_rate_limit,
    configure_user_agent,
    configured_rate_limit,
    create_client,
    default_headers,
    rate_limited,
)
from tripper_recon.utils.redact import REDACTED


@pytest.fixture(autouse=True)
def restore_http_globals() -> Iterator[None]:
    """Undo the module-global mutations ``configure_*`` performs.

    ``configure_user_agent`` and ``configure_rate_limit`` deliberately outlive a single
    investigation -- the CLI sets them once for the process. In a test session that makes them
    cross-test contamination, and a limiter test that silently inherits another test's rate is
    a test that asserts nothing.
    """
    saved_ua = http._global_user_agent
    saved_rate = http._configured_rate
    try:
        yield
    finally:
        http._global_user_agent = saved_ua
        http._configured_rate = saved_rate


# --------------------------------------------------------------------------------------
# 2.1 -- the egress allowlist
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("host", sorted(ALLOWED_EGRESS_HOSTS))
async def test_allowlisted_host_is_permitted(host: str) -> None:
    """Every approved provider host still gets through. Guard against over-tightening."""
    async with respx.mock(assert_all_called=False) as router:
        route = router.get(f"https://{host}/probe").respond(200, json={})
        async with create_client() as client:
            response = await client.get(f"https://{host}/probe")

        assert response.status_code == 200
        assert route.called


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example.com/beacon",
        "http://evil.example.com/beacon",
        "https://EVIL.example.com/beacon",
        "https://evil.example.com:8443/beacon",
        # The single most important case: the target's own host, interpolated at runtime. The
        # static scanner in tests/test_passivity.py cannot see this one at all.
        "https://target-under-investigation.test/",
        # A deep-link host. These are rendered as clickable pivots and must never be FETCHED,
        # so they are deliberately absent from the runtime allowlist.
        "https://radar.cloudflare.com/ip/8.8.8.8",
        "https://www.shodan.io/host/8.8.8.8",
        # Non-public destinations. The orchestrator refuses non-public ADDRESSES as indicators
        # before it gets here, but that is a different control on a different value: this one is
        # about the URL a provider module builds. A provider that interpolated a target-supplied
        # host, or a redirect that was followed, could name any of these -- and on an analyst
        # workstation an RFC 1918 or link-local destination is the internal network, not the
        # internet. 169.254.169.254 in particular is the cloud instance-metadata service, which is
        # the classic SSRF payoff and returns credentials.
        "https://192.168.1.1/admin",
        "https://10.0.0.5:8443/",
        "https://172.16.4.9/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[fd00::1]/",
        "https://localhost:9200/_search",
        "http://127.0.0.1:8080/",
    ],
)
async def test_unlisted_host_raises_before_the_request_leaves(url: str) -> None:
    """The hook runs before the transport, so nothing is sent -- not even to a mock."""
    async with respx.mock(assert_all_called=False) as router:
        route = router.route(host=httpx.URL(url).host).respond(200, json={})
        async with create_client() as client:
            with pytest.raises(PassiveBoundaryViolation):
                await client.get(url)

        assert not route.called
        assert router.calls.call_count == 0, "the request reached the transport; the hook fired too late"


async def test_violation_message_names_the_host_and_cites_the_opsec_section() -> None:
    """The exception has to tell an operator at 3am what happened and where the rule lives."""
    async with respx.mock(assert_all_called=False):
        async with create_client() as client:
            with pytest.raises(PassiveBoundaryViolation) as excinfo:
                await client.get("https://phish-kit.example.test/login")

    message = str(excinfo.value)
    assert "phish-kit.example.test" in message
    assert OPSEC_REFERENCE in message
    assert excinfo.value.host == "phish-kit.example.test"


async def test_violation_message_redacts_a_credential_in_the_query_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Shodan and IPinfo authenticate in the query string, and this message reaches logs.

    A boundary violation that leaks the key while reporting itself would trade one incident
    for a worse one.
    """
    secret = "sk-tripperTESTSECRET-0123456789"
    monkeypatch.setenv("SHODAN_API_KEY", secret)

    async with respx.mock(assert_all_called=False):
        async with create_client() as client:
            with pytest.raises(PassiveBoundaryViolation) as excinfo:
                await client.get(f"https://evil.example.test/collect?key={secret}")

    message = str(excinfo.value)
    assert secret not in message
    assert REDACTED in message
    assert "evil.example.test" in message


def test_runtime_allowlist_covers_every_host_a_provider_contacts() -> None:
    """The runtime hook must not be able to break the tool it is protecting.

    ``EXPECTED_PROVIDER_HOSTS`` is the set of hosts with a module-level ``*_BASE`` constant.
    A host that a provider contacts but the hook does not permit turns every lookup through
    that provider into a ``PassiveBoundaryViolation``.
    """
    missing = EXPECTED_PROVIDER_HOSTS - ALLOWED_EGRESS_HOSTS

    assert not missing, (
        f"Provider hosts absent from ALLOWED_EGRESS_HOSTS: {sorted(missing)}.\n\n"
        "tripper_recon/utils/http.py installs the request hook that enforces this set. A "
        "provider whose host is missing cannot make a single request."
    )


def test_runtime_allowlist_is_a_subset_of_the_static_allowlist() -> None:
    """The two gates must not drift apart.

    ``tests/test_passivity.py`` allowlists URL literals in the source; this module allowlists
    hosts at request time. The static list is the wider of the two because it also covers
    rendered deep links. A host the hook permits but the static gate has never seen is a
    destination that was approved in only one of the two places it has to be.
    """
    undocumented = ALLOWED_EGRESS_HOSTS - STATICALLY_ALLOWED_HOSTS

    assert not undocumented, (
        f"Hosts permitted at runtime but absent from tests/test_passivity.py ALLOWED_HOSTS: "
        f"{sorted(undocumented)}.\n\n"
        "Add them there and to docs/OPSEC.md section 2 in the same commit, or remove them here."
    )


# --------------------------------------------------------------------------------------
# 3.1 -- the client keeps the settings it is configured with
# --------------------------------------------------------------------------------------


def test_create_client_keeps_http2_and_the_connection_limit() -> None:
    """Probe H1: with an explicit ``transport=``, httpx discarded both of these.

    Observed pre-fix: ``http2=False`` and ``max_connections=100`` -- the library default, not
    the 50 configured one line above. README.md's "Async & HTTP/2 First" claim was false as
    shipped.

    This reads httpx internals on purpose. There is no public accessor, and the alternative is
    trusting that a constructor argument was honoured, which is exactly the assumption that
    was wrong.
    """
    client = create_client()
    transport = client._transport
    assert isinstance(transport, httpx.AsyncHTTPTransport)

    pool = transport._pool
    assert pool._http2 is True, "HTTP/2 is off; an explicit transport= was reintroduced"
    assert pool._max_connections == 50, "the configured connection limit was discarded"
    assert pool._max_keepalive_connections == 20


def test_create_client_sets_the_configured_timeout() -> None:
    client = create_client(timeout=3.5)
    assert client.timeout.connect == 3.5
    assert client.timeout.read == 3.5


# --------------------------------------------------------------------------------------
# 3.3 -- the limiter bounds real concurrency, in whichever loop is running
# --------------------------------------------------------------------------------------


class _ConcurrencyProbe:
    """Records the highest number of workers ever inside the limiter at once."""

    def __init__(self) -> None:
        self.current = 0
        self.peak = 0

    async def work(self, hold: float = 0.01) -> None:
        async with rate_limited():
            self.current += 1
            self.peak = max(self.peak, self.current)
            await asyncio.sleep(hold)
            self.current -= 1


async def test_limiter_bounds_concurrency_at_the_configured_rate() -> None:
    """Probe H6 pre-fix: requested 2, observed 10.

    The old limiter wrapped ``asyncio.create_task``, which schedules a coroutine without
    awaiting it -- so the semaphore was acquired and released within one tick and every task
    ran at once.
    """
    configure_rate_limit(2)
    probe = _ConcurrencyProbe()

    await asyncio.gather(*(probe.work() for _ in range(10)))

    assert probe.peak == 2, f"limiter admitted {probe.peak} concurrent workers, ceiling was 2"
    assert probe.current == 0, "a permit was not released"


async def test_limiter_honours_a_rate_set_after_import() -> None:
    """``configure_rate_limit`` was unreachable: the semaphore was built at the FIRST caller's
    rate and cached at module level for the life of the process, so the CLI flag changed
    nothing."""
    configure_rate_limit(1)
    serial = _ConcurrencyProbe()
    await asyncio.gather(*(serial.work() for _ in range(5)))
    assert serial.peak == 1

    configure_rate_limit(4)
    assert configured_rate_limit() == 4
    parallel = _ConcurrencyProbe()
    await asyncio.gather(*(parallel.work() for _ in range(8)))
    assert parallel.peak == 4


async def test_limiter_releases_its_permit_when_the_body_raises() -> None:
    configure_rate_limit(1)

    with pytest.raises(RuntimeError):
        async with rate_limited():
            raise RuntimeError("boom")

    probe = _ConcurrencyProbe()
    await asyncio.wait_for(asyncio.gather(*(probe.work() for _ in range(3))), timeout=5.0)
    assert probe.peak == 1


def test_limiter_works_across_two_sequential_event_loops() -> None:
    """The coupling the critic flagged: fixing the limiter activates a dormant defect.

    An ``asyncio.Semaphore`` attaches to the loop that first makes a caller wait on it. The
    old module-global semaphore was therefore bound to the first loop that used it, and was
    harmless ONLY because the limiter never actually contended. Fix the contention and the
    second ``asyncio.run`` in the same process raises
    ``RuntimeError: ... is bound to a different event loop``.

    Two real ``asyncio.run`` calls, not one loop reused, because that is the shape of the bug.
    """
    configure_rate_limit(2)

    async def _run() -> int:
        probe = _ConcurrencyProbe()
        await asyncio.gather(*(probe.work() for _ in range(6)))
        return probe.peak

    first = asyncio.run(_run())
    second = asyncio.run(_run())

    assert first == 2
    assert second == 2


def test_default_rate_limit_is_the_documented_one() -> None:
    assert configured_rate_limit() == DEFAULT_RATE_LIMIT


async def test_call_provider_holds_a_permit_for_the_whole_await() -> None:
    """The limiter has to wrap the AWAIT of the provider call, not its scheduling.

    ``orchestrators._call_provider`` is the only place in the package that awaits a provider,
    so this is the assertion that the ceiling applies to real provider traffic rather than to
    a helper nothing uses.
    """
    configure_rate_limit(3)
    probe = _ConcurrencyProbe()

    async def _fake_provider() -> Dict[str, Any]:
        probe.current += 1
        probe.peak = max(probe.peak, probe.current)
        await asyncio.sleep(0.01)
        probe.current -= 1
        return {"ok": True, "data": {"seen": True}}

    calls = await asyncio.gather(*(_call_provider("fake", _fake_provider()) for _ in range(12)))

    assert probe.peak == 3, f"provider calls reached {probe.peak} concurrent, ceiling was 3"
    assert all(call.ok for call in calls)
    assert all(call.elapsed_seconds > 0 for call in calls)


# --------------------------------------------------------------------------------------
# 2.6 -- honest User-Agent
# --------------------------------------------------------------------------------------


def test_default_user_agent_identifies_the_tool() -> None:
    expected = f"tripper-recon/{__version__}"
    assert default_headers()["User-Agent"] == expected
    assert DEFAULT_USER_AGENT.startswith("tripper-recon/")
    assert DEFAULT_USER_AGENT.endswith(__version__)


@pytest.mark.parametrize("marker", ["Mozilla", "AppleWebKit", "Chrome", "Safari", "Edg/"])
def test_default_user_agent_does_not_impersonate_a_browser(marker: str) -> None:
    """The key already authenticates the caller, so impersonation bought nothing and put the
    operator on the wrong side of several providers' terms of service."""
    assert marker not in default_headers()["User-Agent"]


def test_environment_variable_overrides_the_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRIPPER_RECON_USER_AGENT", "  custom-agent/2.0  ")
    assert default_headers()["User-Agent"] == "custom-agent/2.0"


def test_blank_environment_variable_falls_back_to_the_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRIPPER_RECON_USER_AGENT", "   ")
    assert default_headers()["User-Agent"] == DEFAULT_USER_AGENT


def test_configure_user_agent_wins_over_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRIPPER_RECON_USER_AGENT", "from-env/1.0")
    configure_user_agent("from-flag/1.0")
    assert default_headers()["User-Agent"] == "from-flag/1.0"


def test_configure_user_agent_ignores_an_empty_value() -> None:
    configure_user_agent("")
    configure_user_agent(None)
    assert default_headers()["User-Agent"] == DEFAULT_USER_AGENT


def test_client_carries_the_user_agent_header() -> None:
    client = create_client()
    assert client.headers["user-agent"] == DEFAULT_USER_AGENT
    assert client.headers["accept"] == "application/json"


async def test_the_user_agent_actually_goes_out_on_the_wire() -> None:
    """Header construction is only useful if the client sends it."""
    seen: List[str] = []

    async with respx.mock(assert_all_called=False) as router:

        def _record(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers["user-agent"])
            return httpx.Response(200, json={})

        router.get("https://stat.ripe.net/data/ok").mock(side_effect=_record)
        async with create_client() as client:
            await client.get("https://stat.ripe.net/data/ok")

    assert seen == [DEFAULT_USER_AGENT]
