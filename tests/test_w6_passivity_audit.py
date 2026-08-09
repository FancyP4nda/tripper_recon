"""W6 adversarial passivity audit — the URL path, end to end, against hostile input.

W6 added URL handling, which is the point at which a passive tool most easily stops being one.
Everything in ``tests/test_passivity.py`` is static: it reads the source and asserts about what
is written down. This file is the runtime counterpart. It **runs** the URL path, the bulk-paste
path and the VirusTotal 404 path against attacker-authored input and asserts on the requests
that were actually attempted.

The distinction the whole file turns on:

* a ``GET`` on a report that ALREADY EXISTS at a third party is passive, and is allowed;
* a request that asks a third party to GO AND FETCH the target is active, and is forbidden
  with no flag and no exception;
* **a request to the target itself is the worst case of all**, and is what the runtime egress
  allowlist exists to make impossible.

Method. ``respx`` is registered for the allowlisted provider hosts ONLY. Nothing routes the
target's host, so a request there would fail the mock — but it never gets that far, because the
egress hook in ``utils/http.create_client`` raises :class:`PassiveBoundaryViolation` before the
transport is reached. Both properties are asserted: that the hook raises when provoked
(:func:`test_the_egress_hook_refuses_the_target_host_before_a_socket_opens`), and that a real
investigation never provokes it (the ``respx.calls`` assertions below).

Name resolution is stubbed throughout. ``--depth full`` is the one depth that resolves, and a
test suite must not put the operator's resolver on the wire for an invented domain; the stub
also lets the address stage run so the per-IP providers are exercised and counted.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlsplit

import httpx
import pytest
import respx

from tripper_recon import cli
from tripper_recon.orchestrators import investigate_url
from tripper_recon.providers.virustotal import VT_URL_NO_REPORT_ERROR
from tripper_recon.reporting.console import render_url_analysis
from tripper_recon.utils.http import ALLOWED_EGRESS_HOSTS, PassiveBoundaryViolation, create_client

# pytest-asyncio runs in "auto" mode for this repo (pyproject.toml), so async tests need no marker.

# --------------------------------------------------------------------------------------
# The hostile indicator
# --------------------------------------------------------------------------------------

#: RFC 2606 / RFC 6761 reserved. Never resolvable, never anybody's real infrastructure, and
#: unmistakable in a request URL if one ever escapes.
TARGET_HOST = "evil.example.test"

#: A URL carrying every construction this path has to survive at once: credentials before the
#: host (with the brand in the username), a non-default port, rich-markup metacharacters in the
#: query, and a fragment.
HOSTILE_URL = f"https://www.bank.example:hunter2@{TARGET_HOST}:8443/pay?id=[/]&next=%2E%2E#[green]ok[/]"

#: The password from ``HOSTILE_URL``. It belongs to the indicator, not to the operator — but it
#: must not be smuggled into a provider request either, and a userinfo-bearing URL sent verbatim
#: to a provider is exactly how that would happen.
HOSTILE_PASSWORD = "hunter2"

#: The address the stubbed resolver returns for the target's host.
#:
#: **Not** a documentation range. Python's ``ipaddress`` reports 192.0.2.0/24, 198.51.100.0/24 and
#: 203.0.113.0/24 as ``is_private``, so ``non_public_ip_reason`` refuses them and the address stage
#: never runs -- which would silently shrink this file's central test to the URL and host scopes
#: and hide any per-address request from the assertions. This address is globally routable, which
#: is the property the guard is checking; nothing is ever sent TO it, only asked ABOUT it, and
#: every provider that would be asked is mocked.
RESOLVED_ADDRESS = "93.184.216.34"

FAKE_KEYS: Dict[str, str] = {
    "VT_API_KEY": "test-key-not-a-credential",
    "SHODAN_API_KEY": "test-key-not-a-credential",
    "ABUSEIPDB_API_KEY": "test-key-not-a-credential",
    "IPINFO_TOKEN": "test-key-not-a-credential",
    "OTX_API_KEY": "test-key-not-a-credential",
    "CLOUDFLARE_API_TOKEN": "test-key-not-a-credential",
}


@pytest.fixture
def provider_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fake credentials for every provider, so no call is skipped for a missing key.

    A skipped provider is a request that was never attempted, and a request never attempted
    proves nothing about where requests go. These are obviously-fake literals; ``conftest``'s
    ``clear_provider_env`` has already removed the operator's real ones.
    """
    for name, value in FAKE_KEYS.items():
        monkeypatch.setenv(name, value)


@pytest.fixture
def no_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub the one active step so ``--depth full`` runs without touching a resolver.

    ``orchestrators._collect_domain`` imports ``resolve_domain`` from the module at call time,
    so patching the attribute on ``utils.dns`` is what reaches it.
    """
    import tripper_recon.utils.dns as dns_module

    async def _stub(domain: str) -> List[str]:
        return [RESOLVED_ADDRESS]

    monkeypatch.setattr(dns_module, "resolve_domain", _stub)


def _mock_every_allowlisted_host(router: respx.MockRouter, *, status: int = 404) -> None:
    """Answer any request to an allowlisted host, and only to an allowlisted host.

    Deliberately a catch-all per host rather than a route per endpoint: the question this file
    asks is *which hosts were contacted*, and a per-endpoint mock would turn an unexpected
    destination into a routing error instead of leaving it visible in the call log.
    """
    for host in sorted(ALLOWED_EGRESS_HOSTS):
        router.route(host=host).mock(return_value=httpx.Response(status, json={"error": "not mocked in detail"}))


class Attempted:
    """A snapshot of the requests respx saw, taken before the router is reset.

    ``respx.mock`` clears ``router.calls`` when its context exits, so an assertion written after
    the ``async with`` block reads an empty list and passes for the wrong reason. This class
    exists because that mistake is silent and this file's central claim -- "no request went to
    the target" -- is exactly the claim it would falsely confirm.
    """

    def __init__(self, router: respx.MockRouter) -> None:
        self.methods: List[str] = [call.request.method for call in router.calls]
        self.urls: List[str] = [str(call.request.url) for call in router.calls]
        self.hosts: Set[str] = {(call.request.url.host or "").lower() for call in router.calls}

    def __bool__(self) -> bool:
        return bool(self.urls)

    def __len__(self) -> int:
        return len(self.urls)


async def _run_under_mock(coro: Any, *, status: int = 404) -> Any:
    """Await ``coro`` with every allowlisted host mocked, returning ``(result, Attempted)``."""
    async with respx.mock(assert_all_called=False) as router:
        _mock_every_allowlisted_host(router, status=status)
        result = await coro
        return result, Attempted(router)


# --------------------------------------------------------------------------------------
# (c) the URL path end to end — no request is attempted to the target host
# --------------------------------------------------------------------------------------


async def test_the_egress_hook_refuses_the_target_host_before_a_socket_opens() -> None:
    """Guard the guard, and prove the mechanism the next test relies on.

    The assertions in the rest of this file are of the form "respx saw no request to the
    target". That is only meaningful if a request to the target would in fact have been
    stopped — otherwise the tests are asserting that the code happens not to do something, not
    that it cannot. This provokes the hook directly.

    No route is registered, so if the hook did NOT fire the request would reach the transport
    and respx would raise its own "not mocked" error instead. The exception type is the
    assertion.
    """
    async with respx.mock(assert_all_called=False):
        async with create_client() as client:
            with pytest.raises(PassiveBoundaryViolation) as raised:
                await client.get(f"https://{TARGET_HOST}/pay")

    assert raised.value.host == TARGET_HOST
    assert "egress allowlist" in str(raised.value)


@pytest.mark.usefixtures("provider_keys", "no_resolution")
async def test_url_investigation_never_attempts_a_request_to_the_target_host() -> None:
    """The whole point of W6, asserted on the calls that were actually made.

    ``--depth full`` is used deliberately: it is the deepest path, it runs the URL scope, the
    host scope and the per-address scope, and it is the only depth that resolves anything. If a
    request to the target were going to happen anywhere, it would happen here.
    """
    result, attempted = await _run_under_mock(investigate_url(HOSTILE_URL, depth="full"))

    # The investigation actually ran. Without this, every assertion below is a claim about the
    # empty set and passes for the wrong reason.
    assert attempted, "no provider request was made at all, so this test proves nothing"
    assert "www.virustotal.com" in attempted.hosts

    assert TARGET_HOST not in attempted.hosts, (
        f"PASSIVE BOUNDARY: a request was attempted to the target host {TARGET_HOST}.\nRequests seen: {attempted.urls}"
    )
    unexpected = attempted.hosts - ALLOWED_EGRESS_HOSTS
    assert not unexpected, f"requests went to hosts outside the egress allowlist: {sorted(unexpected)}"

    # The credentials in the indicator are not smuggled into a provider request. The URL is
    # base64'd into the VirusTotal identifier and never appears verbatim, and no other provider
    # is given the URL at all.
    for url in attempted.urls:
        assert HOSTILE_PASSWORD not in url, f"the indicator's password reached a provider: {url}"

    # The result still describes the URL rather than failing shut, and the password is masked
    # in the human-facing form while the evidence form keeps it byte-for-byte.
    assert result.data["host"] == TARGET_HOST
    assert HOSTILE_PASSWORD not in result.data["url_display"]
    assert HOSTILE_PASSWORD in result.data["url"]


@pytest.mark.usefixtures("provider_keys")
@pytest.mark.parametrize("depth", ["url", "host"])
async def test_the_shallow_depths_resolve_nothing(depth: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """``--depth url`` and ``--depth host`` must not reach the resolver.

    docs/OPSEC.md section 3 states this as the control for an operator who cannot accept
    resolver egress. A stub that fails the test if called is the only way to assert it — a stub
    that returns an empty list would let a regression pass silently.
    """
    import tripper_recon.utils.dns as dns_module

    async def _explode(domain: str) -> List[str]:
        raise AssertionError(f"depth={depth} resolved {domain!r}; only --depth full may resolve (docs/OPSEC.md §3)")

    monkeypatch.setattr(dns_module, "resolve_domain", _explode)

    result, attempted = await _run_under_mock(investigate_url(HOSTILE_URL, depth=depth))

    assert attempted, "no provider request was made at all, so this test proves nothing"
    assert TARGET_HOST not in attempted.hosts
    assert result.data["collection"]["passive_only"] is True
    assert result.data["collection"]["active_steps"] == []


#: A VirusTotal URL report that DOES carry a redirect chain, so the rendered output has hops in
#: it. Shape taken from providers/virustotal.vt_url_summary.
VT_URL_REPORT_WITH_CHAIN: Dict[str, Any] = {
    "data": {
        "id": "9f0c8e1d2b3a4c5d",
        "attributes": {
            "last_analysis_stats": {"harmless": 60, "malicious": 11, "suspicious": 3, "undetected": 20, "timeout": 0},
            "reputation": -34,
            "last_analysis_date": 1754600000,
            "last_final_url": f"https://cdn.{TARGET_HOST}/harvest/step2.html",
            "redirection_chain": [
                f"https://{TARGET_HOST}:8443/pay",
                f"https://cdn.{TARGET_HOST}/harvest/step2.html",
            ],
        },
    }
}


@pytest.mark.usefixtures("provider_keys")
async def test_a_passively_sourced_redirect_chain_is_defanged_in_the_human_facing_report(render: Any) -> None:
    """Every hop in the chain is defanged when the rest of the report is.

    **This test found a real defect.** ``render_url_analysis`` printed the chain straight out of
    ``RedirectChain.render()``, so while every other indicator field went through
    ``indicator_text`` and came out as ``hxxps[://]evil[.]example``, the redirect chain went out
    live. The two URLs in a chain are the landing page and the kit — the two most dangerous
    strings in the report — and a report pasted into a ticket or a chat client that linkifies
    URLs turns a passive investigation into a visit by somebody else's click.

    The resolution word, the source and the observation date must survive the defanging: they
    are what stop a reader inferring that this tool followed the link.
    """
    async with respx.mock(assert_all_called=False) as router:
        _vt_url_route(router, 200, VT_URL_REPORT_WITH_CHAIN)
        result = await investigate_url(HOSTILE_URL, depth="url")

    text = render(render_url_analysis(result.data, defang=True), width=100)

    assert "FROM PASSIVE RECORD" in text
    assert "virustotal:redirection_chain" in text
    assert f"https://{TARGET_HOST}" not in text, "a live target URL survived defanging in the chain"
    assert f"https://cdn.{TARGET_HOST}" not in text
    assert "hxxps[://]" in text

    # ...and --fanged still produces the literal chain, for the analyst who wants to copy it.
    fanged = render(render_url_analysis(result.data, defang=False), width=100)
    assert f"https://cdn.{TARGET_HOST}" in fanged


@pytest.mark.usefixtures("provider_keys")
async def test_the_json_export_is_never_defanged(render: Any) -> None:
    """``-o json`` carries the indicator byte-for-byte. A machine consumes it.

    ``evil[.]example`` is not a hostname, so a defanged export is one a downstream tool cannot
    parse. The two output modes therefore make opposite promises, and both are asserted here so
    a change to one cannot silently be applied to the other.
    """
    async with respx.mock(assert_all_called=False) as router:
        _vt_url_route(router, 200, VT_URL_REPORT_WITH_CHAIN)
        result = await investigate_url(HOSTILE_URL, depth="url")

    exported = json.dumps(result.model_dump(mode="json"))

    assert "hxxp" not in exported, "the JSON export was defanged"
    assert "[.]" not in exported, "the JSON export was defanged"
    assert TARGET_HOST in exported
    assert f"https://cdn.{TARGET_HOST}/harvest/step2.html" in exported
    # The evidence form keeps the credentials; only the human-facing form masks them.
    assert HOSTILE_PASSWORD in exported


@pytest.mark.usefixtures("provider_keys", "no_resolution")
async def test_the_redirect_chain_is_reported_as_not_resolved_and_nothing_followed_it() -> None:
    """A redirect is never resolved locally, including by ``HEAD``.

    The provider answers 404 here, so no passive source supplied a chain. The correct output is
    the honest one — NOT RESOLVED, with the reason — and not a blank field a reader would take
    for "this link does not redirect".
    """
    result, attempted = await _run_under_mock(investigate_url(HOSTILE_URL, depth="url"))

    chain = result.data["redirect_chain"]
    assert chain["resolution"] == "NOT RESOLVED"
    assert chain["hops"] == []
    assert chain["final_url"] is None
    assert "active fetch" in chain["rendered"]

    # Nothing issued a bodyless probe at the target on the way to that answer.
    assert attempted, "no provider request was made at all, so this test proves nothing"
    assert TARGET_HOST not in attempted.hosts
    assert set(attempted.methods) == {"GET"}, f"a non-GET verb was used: {attempted.methods}"


# --------------------------------------------------------------------------------------
# (d) bulk paste — attacker-authored text
# --------------------------------------------------------------------------------------

#: Everything the audit asks for, in one block, written the way it would actually arrive.
#: ``[/]`` is a rich close tag and raises ``MarkupError`` if it reaches the console unescaped;
#: ``[green]…[/]`` would render as a verdict the tool never computed.
HOSTILE_PASTE = f"""From: "Accounts [/]" <billing@{TARGET_HOST}>
Subject: [green]0/94 clean[/] action required

Click here: javascript:alert(document.cookie)
Or here:    data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
Long host:  http://{"a" * 4000}.example/
Homograph:  https://аpple.com/signin
Internal:   http://10.0.0.5/admin/console
Creds:      {HOSTILE_URL}
Defanged:   hxxps://evil[.]example[.]test/already-judged
"""

#: The RFC1918 address in the paste. It is the operator's internal addressing the moment it is
#: forwarded, which is the leak this test exists to disprove.
INTERNAL_ADDRESS = "10.0.0.5"


async def test_bulk_triage_survives_attacker_authored_text_and_makes_no_request() -> None:
    """Triage is pure. It classifies a hostile wall of text without contacting anything.

    Extraction and classification are string work by construction, so the default ``bulk`` run
    is safe to paste an entire phishing email into. That is asserted rather than assumed: the
    run happens under a mock with no routes, where any outbound request raises.

    **This test found a real crash.** ``_read_bulk_text`` probed its argument with
    ``Path(source).is_file()``, and on a paste longer than ``PATH_MAX`` that does not return
    ``False`` -- it raises ``OSError: [Errno 36] File name too long``. Any pasted email body
    over ~4 KB took the whole command down with an uncaught traceback, which is the single most
    ordinary input this command has. The probe is guarded now (``cli.py:_read_bulk_text``); the
    4000-character hostname in ``HOSTILE_PASTE`` is what pushes the paste over the limit and is
    deliberately left there so the regression cannot come back quietly.
    """
    assert len(HOSTILE_PASTE) > 4096, "the paste must exceed PATH_MAX or it does not exercise the guard"

    async with respx.mock(assert_all_called=False) as router:
        code = await cli._cmd_bulk(HOSTILE_PASTE, output="console")
        attempted = Attempted(router)

    assert code == 0
    assert not attempted, f"triage made a request: {attempted.urls}"


@pytest.mark.usefixtures("provider_keys", "no_resolution")
async def test_bulk_investigate_leaks_nothing_internal_to_a_provider() -> None:
    """The load-bearing one: with ``--investigate``, what actually goes out.

    Three separate claims, each asserted on the request log rather than on the triage table:

    1. no request reaches the target host, or any host off the allowlist;
    2. the RFC1918 address in the paste is never sent to a third party — forwarding it would
       disclose the operator's internal addressing to five vendors under the operator's own
       API keys, and the answer would be worthless anyway;
    3. the indicator's embedded password does not travel either.
    """
    code, attempted = await _run_under_mock(
        cli._cmd_bulk(HOSTILE_PASTE, investigate=True, max_targets=6, output="console")
    )

    assert code in (0, 1)  # every mocked provider answers 404, so a blackout exit is expected
    assert attempted, "nothing was investigated, so this test proves nothing"

    off_allowlist = attempted.hosts - ALLOWED_EGRESS_HOSTS
    assert TARGET_HOST not in attempted.hosts, f"a request reached the target: {attempted.urls}"
    assert not off_allowlist, f"off-allowlist hosts contacted: {sorted(off_allowlist)}"

    for url in attempted.urls:
        assert INTERNAL_ADDRESS not in url, f"internal addressing reached a provider: {url}"
        assert HOSTILE_PASSWORD not in url, f"the indicator's password reached a provider: {url}"

    # And no request path or query carries a non-public address in any position, which is the
    # general form of the claim above rather than the one literal from this paste.
    for url in attempted.urls:
        split = urlsplit(url)
        for token in split.path.split("/") + split.query.replace("&", "=").split("="):
            try:
                address = ipaddress.ip_address(token)
            except ValueError:
                continue
            assert address.is_global, f"non-public address {token} was sent to {split.netloc}"


def test_bulk_triage_withholds_a_url_whose_host_is_a_private_address() -> None:
    """The RFC1918 indicator is held back — and reported as held back, not deleted.

    **This test found a real defect.** ``_withhold_reason`` applied the non-public guard to a
    bare address only, so ``http://10.0.0.5/admin/console`` was listed as ``routable`` and did
    not appear in the withheld table at all. Nothing internal ever left the box —
    ``investigate_url`` refuses the same address a moment later, which
    :func:`test_bulk_investigate_leaks_nothing_internal_to_a_provider` proves on the request log
    — but the two layers disagreed, and the layer the analyst reads was the wrong one. A
    withheld table that omits what it withheld cannot be trusted for the case it exists for.

    An indicator that simply vanishes would be worse still: the internal address a filter binned
    is sometimes the pivot the incident turns on, so it is reported with its reason, not dropped.
    """
    kept, withheld = cli._triage(cli.extract_indicators(HOSTILE_PASTE))

    kept_hosts = {row["value"] for row in kept}
    withheld_hosts = {row["value"] for row in withheld}

    assert not any(INTERNAL_ADDRESS in value for value in kept_hosts)
    assert any(INTERNAL_ADDRESS in value for value in withheld_hosts), (
        f"the RFC1918 URL is neither kept nor withheld — it vanished. withheld={sorted(withheld_hosts)}"
    )
    assert all(row.get("reason") for row in withheld), "a withheld indicator carries no reason"


def test_bulk_triage_renders_hostile_markup_without_raising(render: Any) -> None:
    """``[/]`` and ``[green]…[/]`` are attacker-authored and reach a rich console.

    Unescaped, the first raises ``MarkupError`` and the second prints a green verdict this tool
    never computed. Rendering without raising is half the assertion; the other half is that the
    markup arrives as literal text rather than being consumed as a style, because a consumed
    ``[green]`` tag is a verdict the tool never computed appearing in the operator's report.
    """
    kept, _withheld = cli._triage(cli.extract_indicators(HOSTILE_PASTE))
    text = render(cli.render_triage_table(kept, defang=True), width=200)

    assert text
    # Survived as literal text: `esc()` did its job and rich did not eat the tag.
    assert "[green]" in text


def test_the_non_web_schemes_are_never_routed_to_a_provider() -> None:
    """``javascript:`` and ``data:`` must not reach an orchestrator.

    Both arrive in real phishing mail and neither has a report at any provider, so routing one
    spends quota on a string that cannot have an answer. Note what is NOT asserted here: see
    :func:`test_an_overlong_hostname_is_routed_and_that_is_a_known_finding`.
    """
    routable = {row["value"] for row in cli._triage(cli.extract_indicators(HOSTILE_PASTE))[0] if row["routable"]}

    assert not any(value.startswith(("javascript:", "data:")) for value in routable)


def test_an_overlong_hostname_is_routed_and_that_is_a_known_finding() -> None:
    """A 4000-character hostname IS routed to VirusTotal. Pinned as a finding, not as approval.

    RFC 1035 §2.3.4 caps a presentation-form name at 253 octets, so this string cannot be a
    hostname and cannot have a report anywhere. ``utils/validation.normalize_domain`` enforces
    the limit; ``utils/urls.parse_url`` deliberately does not, because its job is to observe a
    hostile string rather than to judge it, and ``orchestrators._url_target_error`` checks the
    scheme, the host's presence and its routability but not its length.

    **It is not a passivity breach** — the request goes to VirusTotal, not to the target, and
    :func:`test_bulk_investigate_leaks_nothing_internal_to_a_provider` covers that. It is a
    wasted-quota and readability defect: the name also renders across ~50 wrapped lines of the
    triage table, pushing the other five indicators off a terminal screen.

    This test asserts the CURRENT behaviour so the finding is visible in the suite rather than
    living only in a report. When a length check lands in ``_url_target_error``, this test
    should be inverted, not deleted.
    """
    routable = [row["value"] for row in cli._triage(cli.extract_indicators(HOSTILE_PASTE))[0] if row["routable"]]

    overlong = [value for value in routable if len(value) > 253]
    assert overlong, "the over-long name is no longer routed — invert this test, the defect is fixed"


# --------------------------------------------------------------------------------------
# (e) a VirusTotal 404 on a URL is UNKNOWN, never clean
# --------------------------------------------------------------------------------------


def _vt_url_route(router: respx.MockRouter, status: int, payload: Optional[Dict[str, Any]] = None) -> None:
    router.route(host="www.virustotal.com").mock(return_value=httpx.Response(status, json=payload or {}))


@pytest.mark.usefixtures("provider_keys")
async def test_a_virustotal_404_on_a_url_is_unknown_and_is_never_rendered_as_clean() -> None:
    """404 means nobody has ever submitted this URL. That is the ordinary state of a new
    phishing link and carries no exculpatory weight whatsoever.

    The failure this guards against is the quiet one: a suppressed provider error renders
    identically to "we asked and found nothing", and the reader takes the blank for a clean
    verdict. So the 404 is published as its own flag, promoted to the first warning, and the
    run exits non-zero because at ``--depth url`` the single URL-scope provider is the whole
    denominator.
    """
    async with respx.mock(assert_all_called=False) as router:
        _vt_url_route(router, 404, {"error": {"code": "NotFoundError"}})
        result = await investigate_url(HOSTILE_URL, depth="url")
        attempted = Attempted(router)

    assert attempted, "VirusTotal was never asked, so this test proves nothing"
    assert result.data["url_report_missing"] is True
    assert result.ok is False, "a URL nobody has ever scanned must not exit 0 at --depth url"

    vt_error = result.data["url_errors"]["virustotal_url"]
    assert vt_error["error"] == VT_URL_NO_REPORT_ERROR
    assert vt_error["renders_as"] == "unknown"
    # Not suppressible: the suppression rules must never be able to hide this one.
    assert vt_error["suppressible"] is False

    # The warning states the absence and denies the exculpatory reading in words. It is the
    # first warning, because a reader who stops after one line must still get this one.
    warning = result.warnings[0]
    assert "holds no report" in warning
    assert "no exculpatory weight" in warning
    assert not any("clean" in w.lower() and "not" not in w.lower() for w in result.warnings)

    # No detection block was invented out of the absence.
    assert "virustotal" not in (result.data.get("url_intel") or {})


@pytest.mark.usefixtures("provider_keys")
async def test_the_rendered_url_panel_says_unknown_rather_than_showing_a_clean_score(render: Any) -> None:
    """The same fact, on the screen, which is where the misreading would actually happen."""
    async with respx.mock(assert_all_called=False) as router:
        _vt_url_route(router, 404, {"error": {"code": "NotFoundError"}})
        result = await investigate_url(HOSTILE_URL, depth="url")

    text = render(render_url_analysis(result.data, defang=True), width=100)

    assert "0/" not in text, "a zero-detection score was rendered for a report that does not exist"
    lowered = text.lower()
    assert "no virustotal report" in lowered or "unknown" in lowered
