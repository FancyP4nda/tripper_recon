"""Unit tests for tripper_recon.utils.dns.

``resolve_domain`` is the tool's single active step and it sits at the head of the domain
path, in front of every provider call. Two properties are asserted here:

* **Bounded and partial-tolerant** (roadmap 3.10). ``getaddrinfo`` has no timeout of its own.
  Each address family now runs in its own thread under its own deadline, so a family that
  hangs costs the deadline instead of the resolver's full retry schedule, and the other
  family's answers still come back.
* **Deterministic** (roadmap 4.9). The result used to be ``list(set(...))``, whose order
  varies with the hash seed. That order reaches ``data['ips']`` and the rendered panels, so
  two runs on the same domain did not diff cleanly.

No test here touches the network: ``socket.getaddrinfo`` is replaced for the duration of each
test, so a machine with no resolver and a machine on a corporate one behave identically.
``reverse_ptr`` is covered only to the extent of pinning its current behaviour -- its fate is
an open operator decision (roadmap 2.5), so these tests must not be read as endorsing it.
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time
from typing import Any, Callable, Dict, Iterator, List, Tuple

import pytest

from tripper_recon.utils import dns as dns_mod
from tripper_recon.utils.dns import resolve_domain, reverse_ptr

# The 5-tuple getaddrinfo returns; only element 4 (sockaddr) is read by the code under test.
AddrInfo = Tuple[int, int, int, str, Tuple[Any, ...]]


def _v4(address: str) -> AddrInfo:
    return (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0))


def _v6(address: str) -> AddrInfo:
    return (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, 0, 0, 0))


@pytest.fixture()
def fake_resolver(monkeypatch: pytest.MonkeyPatch) -> Callable[..., List[Tuple[Any, ...]]]:
    """Install a per-family fake ``getaddrinfo`` and record the calls it receives.

    Returns a registrar: call it with ``{socket.AF_INET: <list or callable or exception>}``.
    A callable is invoked (so a test can block or raise mid-lookup); an exception instance is
    raised; a list is returned as-is.
    """
    behaviour: Dict[int, Any] = {}
    families: List[int] = []

    def _fake(host: str, port: Any, family: int, socktype: int) -> List[Tuple[Any, ...]]:
        families.append(family)
        action = behaviour.get(family, [])
        if isinstance(action, BaseException):
            raise action
        if callable(action):
            return list(action())
        return list(action)

    monkeypatch.setattr(dns_mod.socket, "getaddrinfo", _fake)

    def _register(**_unused: Any) -> List[Tuple[Any, ...]]:  # pragma: no cover - not used
        raise AssertionError("use fake_resolver.set(...)")

    _register.set = behaviour.update  # type: ignore[attr-defined]
    _register.families = families  # type: ignore[attr-defined]
    return _register  # type: ignore[return-value]


@pytest.fixture()
def released_threads() -> Iterator[threading.Event]:
    """An event every blocking fake waits on, set at teardown.

    A worker thread parked in a fake lookup outlives the test that abandoned it -- cancelling
    ``to_thread`` releases the awaiting coroutine, not the thread. Setting the event on the
    way out keeps the suite from accumulating parked threads.
    """
    event = threading.Event()
    try:
        yield event
    finally:
        event.set()


async def test_ipv4_addresses_come_before_ipv6(fake_resolver: Any) -> None:
    fake_resolver.set(
        {
            socket.AF_INET: [_v4("203.0.113.8")],
            socket.AF_INET6: [_v6("2001:db8::1")],
        }
    )

    assert await resolve_domain("example.test") == ["203.0.113.8", "2001:db8::1"]


async def test_addresses_sort_numerically_within_a_family(fake_resolver: Any) -> None:
    """``10.0.0.10`` sorts after ``10.0.0.2``; a plain string sort would invert them."""
    fake_resolver.set(
        {
            socket.AF_INET: [_v4("198.51.100.10"), _v4("198.51.100.2"), _v4("198.51.100.100")],
            socket.AF_INET6: [_v6("2001:db8::10"), _v6("2001:db8::2")],
        }
    )

    assert await resolve_domain("example.test") == [
        "198.51.100.2",
        "198.51.100.10",
        "198.51.100.100",
        "2001:db8::2",
        "2001:db8::10",
    ]


async def test_duplicate_answers_collapse(fake_resolver: Any) -> None:
    """getaddrinfo returns one tuple per socktype/protocol, so duplicates are the norm."""
    fake_resolver.set(
        {
            socket.AF_INET: [_v4("203.0.113.8"), _v4("203.0.113.8"), _v4("203.0.113.9")],
            socket.AF_INET6: [],
        }
    )

    assert await resolve_domain("example.test") == ["203.0.113.8", "203.0.113.9"]


async def test_order_is_stable_when_the_resolver_rotates_answers(fake_resolver: Any) -> None:
    """Roadmap 4.9. Resolvers round-robin their answers between queries; the caller must not.

    The fake returns a different permutation on every call, which is what a real resolver
    doing round-robin does. Two runs still produce the identical list.
    """
    rotations = [
        [_v4("203.0.113.1"), _v4("203.0.113.2"), _v4("203.0.113.3")],
        [_v4("203.0.113.3"), _v4("203.0.113.1"), _v4("203.0.113.2")],
        [_v4("203.0.113.2"), _v4("203.0.113.3"), _v4("203.0.113.1")],
    ]
    calls = {"n": 0}

    def _rotate() -> List[Tuple[Any, ...]]:
        answer = rotations[calls["n"] % len(rotations)]
        calls["n"] += 1
        return answer

    fake_resolver.set({socket.AF_INET: _rotate, socket.AF_INET6: []})

    first = await resolve_domain("example.test")
    second = await resolve_domain("example.test")

    assert first == second == ["203.0.113.1", "203.0.113.2", "203.0.113.3"]


async def test_both_families_are_queried(fake_resolver: Any) -> None:
    """A regression guard: dropping AAAA would silently halve coverage on a v6-only host."""
    fake_resolver.set({socket.AF_INET: [], socket.AF_INET6: []})

    await resolve_domain("example.test")

    assert sorted(fake_resolver.families) == sorted([socket.AF_INET, socket.AF_INET6])


async def test_failure_for_one_family_returns_the_other(fake_resolver: Any) -> None:
    """A v4-only host raises ``gaierror`` for AAAA on most resolvers. That is not an error."""
    fake_resolver.set(
        {
            socket.AF_INET: [_v4("203.0.113.8")],
            socket.AF_INET6: socket.gaierror(socket.EAI_NONAME, "Name or service not known"),
        }
    )

    assert await resolve_domain("example.test") == ["203.0.113.8"]


async def test_failure_for_both_families_returns_empty(fake_resolver: Any) -> None:
    """NXDOMAIN. The empty list is the caller's signal, not an exception."""
    fake_resolver.set(
        {
            socket.AF_INET: socket.gaierror(socket.EAI_NONAME, "Name or service not known"),
            socket.AF_INET6: socket.gaierror(socket.EAI_NONAME, "Name or service not known"),
        }
    )

    assert await resolve_domain("nx.example.test") == []


async def test_timeout_on_one_family_returns_the_other_familys_answers(
    fake_resolver: Any, released_threads: threading.Event, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The partial-answer requirement.

    A hung AAAA lookup -- routine against a resolver with a broken v6 path -- must not cost
    the A answers that already came back, and must not raise onto a caller
    (``orchestrators.investigate_domain``) that has no handler for it.
    """
    monkeypatch.setattr(dns_mod, "RESOLVE_TIMEOUT_SECONDS", 0.05)

    def _hang() -> List[Tuple[Any, ...]]:
        released_threads.wait(timeout=2.0)
        return [_v6("2001:db8::1")]

    fake_resolver.set({socket.AF_INET: [_v4("203.0.113.8")], socket.AF_INET6: _hang})

    started = time.monotonic()
    result = await resolve_domain("example.test")
    elapsed = time.monotonic() - started

    released_threads.set()

    assert result == ["203.0.113.8"]
    assert elapsed < 2.0, f"resolve_domain waited {elapsed:.2f}s on a hung family"


async def test_timeout_bounds_the_call_when_every_family_hangs(
    fake_resolver: Any, released_threads: threading.Event, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A black-holed nameserver costs the deadline, not the resolver's full retry schedule."""
    monkeypatch.setattr(dns_mod, "RESOLVE_TIMEOUT_SECONDS", 0.05)

    def _hang() -> List[Tuple[Any, ...]]:
        released_threads.wait(timeout=2.0)
        return []

    fake_resolver.set({socket.AF_INET: _hang, socket.AF_INET6: _hang})

    started = time.monotonic()
    result = await resolve_domain("example.test")
    elapsed = time.monotonic() - started

    released_threads.set()

    assert result == []
    assert elapsed < 2.0, f"resolve_domain waited {elapsed:.2f}s with both families hung"


async def test_families_do_not_serialise(
    fake_resolver: Any, released_threads: threading.Event, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both families run at once, so the deadline is per-call, not per-call times two.

    Each lookup blocks past the deadline. Serial execution would take two deadlines; the
    assertion allows generous slack so a loaded CI box does not flake it, while still failing
    a genuine re-serialisation.
    """
    monkeypatch.setattr(dns_mod, "RESOLVE_TIMEOUT_SECONDS", 0.3)

    def _hang() -> List[Tuple[Any, ...]]:
        released_threads.wait(timeout=2.0)
        return []

    fake_resolver.set({socket.AF_INET: _hang, socket.AF_INET6: _hang})

    started = time.monotonic()
    await resolve_domain("example.test")
    elapsed = time.monotonic() - started

    released_threads.set()

    assert elapsed < 0.55, f"families appear to run in sequence ({elapsed:.2f}s for a 0.30s deadline)"


async def test_an_unexpected_resolver_error_still_propagates(fake_resolver: Any) -> None:
    """Only ``gaierror`` means "no such record".

    ``getaddrinfo`` raises ``UnicodeError`` on an over-long label, among others. Swallowing
    that would report "this domain has no addresses", which is a different and false claim.
    Propagation is the pre-existing behaviour and is deliberately preserved.
    """
    fake_resolver.set({socket.AF_INET: UnicodeError("label too long"), socket.AF_INET6: []})

    with pytest.raises(UnicodeError):
        await resolve_domain("example.test")


async def test_resolve_domain_returns_a_list_of_str(fake_resolver: Any) -> None:
    """The signature contract the orchestrator concatenates against (``active_ips + passive_ips``)."""
    fake_resolver.set({socket.AF_INET: [_v4("203.0.113.8")], socket.AF_INET6: [_v6("2001:db8::1")]})

    result = await resolve_domain("example.test")

    assert isinstance(result, list)
    assert all(isinstance(item, str) for item in result)


def test_sorted_addresses_falls_back_when_a_value_is_unparseable() -> None:
    """Scoped and malformed values must still sort deterministically rather than raise."""
    messy = ["fe80::1%eth0", "fe80::1%eth1", "2001:db8::1"]

    first = dns_mod._sorted_addresses(messy)
    second = dns_mod._sorted_addresses(list(reversed(messy)))

    assert first == second == sorted(set(messy))


async def test_reverse_ptr_returns_the_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    """Behaviour pin only. ``reverse_ptr`` has no callers and its fate is undecided (2.5)."""
    monkeypatch.setattr(dns_mod.socket, "gethostbyaddr", lambda ip: ("host.example.test", [], [ip]))

    assert await reverse_ptr("203.0.113.8") == "host.example.test"


async def test_reverse_ptr_returns_none_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(_ip: str) -> Any:
        raise socket.herror(1, "Unknown host")

    monkeypatch.setattr(dns_mod.socket, "gethostbyaddr", _boom)

    assert await reverse_ptr("203.0.113.8") is None


async def test_resolve_domain_is_still_a_coroutine_function() -> None:
    """Guards the one property every caller depends on syntactically."""
    assert asyncio.iscoroutinefunction(resolve_domain)
