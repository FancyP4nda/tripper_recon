"""Unit tests for tripper_recon.cli.

Three things are locked in here, all of them regressions from the W0 fix pass (commit ae59d18):

* **Fix 0.6 — flag position.** Each subparser declares ``-o/--format`` with
  ``default=argparse.SUPPRESS`` (``cli.py:419``, ``:424``, ``:430``). Before the fix each
  subparser carried ``default="console"``, and argparse writes a subparser default over the
  namespace value the top-level parser already set. The consequence was silent and ugly:
  ``tripper-recon -o json ip 8.8.8.8`` produced console text, so anything piping the tool into
  ``jq`` got a panel of box-drawing characters instead of JSON, with no error to explain it.
* **Fix 0.7 — defanged input.** ``_cmd_domain`` guards ``urlparse`` and re-checks the normalised
  host (``cli.py:212-233``). Pre-fix, ``hxxps://evil[.]com`` reached an unguarded ``urlparse``,
  which reads ``[.]`` as an IPv6 literal and raises ``ValueError: Invalid IPv6 URL`` — an
  uncaught traceback for the single most common thing an analyst pastes into this tool.
* **The pure helpers.** ``_load_ip_targets``, ``_fmt_provider_error`` and ``_fmt_dn`` have no
  coverage elsewhere and every console and JSON path runs through them.

**Network:** nothing here touches it. The parser tests replace ``_cmd_ip``/``_cmd_domain``/
``_cmd_asn`` with recorders, and the defang tests run under ``respx.mock`` with no routes
registered, so any outbound httpx call fails the test rather than leaving the box.

**Credentials:** ``cli.main`` calls ``load_env()``, which reads the operator's real ``.env`` into
``os.environ`` and would defeat the ``clear_provider_env`` control in ``conftest.py``. Every test
that invokes ``main`` stubs it out. Do not remove that stub.

Note for a future refactor: ``main()`` builds its parser inline, so these tests drive the real
parser by calling ``main()`` with a patched ``sys.argv``. Extracting a ``build_parser()`` from
``main()`` would let the format tests call ``parse_args`` directly and drop the stubbing
machinery. That change belongs in the source, not here.
"""

from __future__ import annotations

import io
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest
import respx
from rich.console import Console, RenderableType

from tripper_recon import cli
from tripper_recon.cli import (
    _DEFANG_MARKERS,
    _cmd_domain,
    _fmt_dn,
    _fmt_provider_error,
    _load_ip_targets,
    _looks_defanged,
)
from tripper_recon.reporting.console import (
    defang_address,
    defang_host,
    defang_indicator,
    render_ip_analysis,
    render_triage_table,
)
from tripper_recon.types.models import Coverage, InvestigationResult

# --------------------------------------------------------------------------------------
# Harness for driving cli.main() without side effects
# --------------------------------------------------------------------------------------


@dataclass
class _Invocation:
    """One recorded call to a ``_cmd_*`` coroutine."""

    cmd: str
    args: tuple[Any, ...] = field(default_factory=tuple)
    kwargs: dict[str, Any] = field(default_factory=dict)


RunCli = Callable[[list[str]], tuple[int, _Invocation]]


@pytest.fixture
def run_cli(monkeypatch: pytest.MonkeyPatch) -> RunCli:
    """Run ``cli.main()`` against an argv, returning the exit code and the dispatched call.

    Everything with a side effect is neutralised:

    * ``load_env`` — would load the operator's real ``.env`` into the process environment.
    * ``configure_rate_limit`` / ``configure_user_agent`` — both mutate module globals in
      ``utils.http`` that would outlive the test and leak into unrelated tests in the session.
    * ``_cmd_ip`` / ``_cmd_domain`` / ``_cmd_asn`` — the only things in ``main`` that make
      network calls. Replaced with coroutines that record their arguments and return 0.

    What survives is exactly the part under test: argument parsing and dispatch.
    """

    def _run(argv: list[str]) -> tuple[int, _Invocation]:
        recorded: list[_Invocation] = []

        def _recorder(name: str) -> Callable[..., Any]:
            async def _fake(*args: Any, **kwargs: Any) -> int:
                recorded.append(_Invocation(name, args, kwargs))
                return 0

            return _fake

        monkeypatch.setattr(cli, "load_env", lambda: None)
        monkeypatch.setattr(cli, "configure_rate_limit", lambda *_a, **_k: None)
        monkeypatch.setattr(cli, "configure_user_agent", lambda *_a, **_k: None)
        for name in ("_cmd_ip", "_cmd_domain", "_cmd_asn"):
            monkeypatch.setattr(cli, name, _recorder(name))
        monkeypatch.setattr(sys, "argv", ["tripper-recon", *argv])

        with pytest.raises(SystemExit) as excinfo:
            cli.main()

        code = excinfo.value.code
        assert len(recorded) == 1, f"expected exactly one dispatch for {argv!r}, got {recorded!r}"
        return int(code or 0), recorded[0]

    return _run


# --------------------------------------------------------------------------------------
# Fix 0.6 -- -o/--format works before OR after the subcommand
# --------------------------------------------------------------------------------------

# (subcommand, target argv fragment, recorder name)
_SUBCOMMANDS = [
    pytest.param("ip", "8.8.8.8", "_cmd_ip", id="ip"),
    pytest.param("domain", "example.com", "_cmd_domain", id="domain"),
    pytest.param("asn", "15133", "_cmd_asn", id="asn"),
]


@pytest.mark.parametrize(("cmd", "target", "recorder"), _SUBCOMMANDS)
def test_format_flag_before_subcommand_is_honoured(run_cli: RunCli, cmd: str, target: str, recorder: str) -> None:
    """``-o json <cmd> <target>`` reaches the command as ``output="json"``.

    THIS IS THE REGRESSION. Pre-fix the subparser's ``default="console"`` overwrote the
    top-level value during ``parse_args`` and the tool emitted a console panel while the
    operator had explicitly asked for JSON.
    """
    code, call = run_cli(["-o", "json", cmd, target])

    assert code == 0
    assert call.cmd == recorder
    assert call.kwargs["output"] == "json"


@pytest.mark.parametrize(("cmd", "target", "recorder"), _SUBCOMMANDS)
def test_format_flag_after_subcommand_is_honoured(run_cli: RunCli, cmd: str, target: str, recorder: str) -> None:
    """``<cmd> <target> -o json`` still works -- the fix must not break the documented form."""
    code, call = run_cli([cmd, target, "-o", "json"])

    assert code == 0
    assert call.cmd == recorder
    assert call.kwargs["output"] == "json"


@pytest.mark.parametrize(("cmd", "target", "recorder"), _SUBCOMMANDS)
def test_format_defaults_to_console(run_cli: RunCli, cmd: str, target: str, recorder: str) -> None:
    """With no ``-o`` anywhere, the top-level default applies.

    ``argparse.SUPPRESS`` on the subparser means the attribute is never set there, so this
    asserts the top-level default still lands on the namespace.
    """
    code, call = run_cli([cmd, target])

    assert code == 0
    assert call.cmd == recorder
    assert call.kwargs["output"] == "console"


@pytest.mark.parametrize(("cmd", "target", "recorder"), _SUBCOMMANDS)
def test_long_format_flag_before_subcommand_is_honoured(run_cli: RunCli, cmd: str, target: str, recorder: str) -> None:
    """``--format json`` behaves the same as ``-o json`` in the leading position."""
    code, call = run_cli(["--format", "json", cmd, target])

    assert code == 0
    assert call.cmd == recorder
    assert call.kwargs["output"] == "json"


@pytest.mark.parametrize(("cmd", "target", "recorder"), _SUBCOMMANDS)
def test_subcommand_format_wins_over_leading_format(run_cli: RunCli, cmd: str, target: str, recorder: str) -> None:
    """When both positions are given, the later (subcommand) flag wins.

    This is the precedence ``SUPPRESS`` produces: the subparser sets the attribute only when
    the flag is actually present, and it parses after the top-level parser.
    """
    code, call = run_cli(["-o", "json", cmd, target, "-o", "console"])

    assert code == 0
    assert call.cmd == recorder
    assert call.kwargs["output"] == "console"


def test_asn_accepts_as_prefix_and_passes_int(run_cli: RunCli) -> None:
    """``asn AS15133`` normalises to the int 15133 before dispatch (``cli.py:454-458``)."""
    code, call = run_cli(["-o", "json", "asn", "AS15133"])

    assert code == 0
    assert call.args == (15133,)
    assert call.kwargs["output"] == "json"


# --------------------------------------------------------------------------------------
# Fix 0.7 -- defanged indicator detection
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "hxxp://evil.com",
        "hxxps://evil.com",
        "hxxps://evil[.]com",
        "evil[.]com",
        "evil(.)com",
        "evil[dot]com",
        "1.2.3.4[:]80",
        "hxxps[://]evil.com",
        "HXXPS://EVIL[.]COM",  # markers are matched case-insensitively
    ],
)
def test_looks_defanged_accepts_common_defang_styles(value: str) -> None:
    assert _looks_defanged(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "example.com",
        "sub.example.co.uk",
        "https://example.com/path?q=1",
        "http://example.com",
        "8.8.8.8",
        "2001:db8::1",
        "xn--bcher-kva.example",  # punycode, not a defang marker
        "",
    ],
)
def test_looks_defanged_rejects_ordinary_indicators(value: str) -> None:
    assert _looks_defanged(value) is False


def test_defang_markers_are_all_lowercase() -> None:
    """``_looks_defanged`` lowercases its input, so an uppercase marker could never match.

    Guards the table itself rather than the function -- a marker added as ``"[DOT]"`` would be
    dead code and the case-insensitivity test above would not catch it.
    """
    assert all(marker == marker.lower() for marker in _DEFANG_MARKERS)


@respx.mock
async def test_cmd_domain_refangs_a_defanged_url_and_proceeds(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``hxxps://evil[.]com`` is refanged and investigated, and the change is announced.

    Behaviour changed deliberately in W6: a defanged indicator is the normal thing an analyst
    pastes at 02:00, so refusing it and demanding a retype was friction at the worst moment.
    What must NOT regress is the crash this guard originally fixed -- ``urlparse`` reads ``[.]``
    as an IPv6 literal and raises ``ValueError: Invalid IPv6 URL`` -- and the requirement that
    the transform is visible rather than silent.
    """
    seen: list[str] = []

    async def _capture(target: str, *_a: Any, **_k: Any) -> Any:
        seen.append(target)
        return SimpleNamespace(ok=False, errors=["stub"], data={}, warnings=[])

    monkeypatch.setattr(cli, "investigate_domain", _capture)

    code = await _cmd_domain("hxxps://evil[.]com")

    out = capsys.readouterr().out
    assert seen == ["evil.com"], "the refanged host is what gets investigated"
    assert "refanged" in out.lower(), "the transform must be announced, never silent"
    assert code != 2, "a refangable target is no longer rejected"


@respx.mock
@pytest.mark.parametrize(
    "target",
    [
        # urlparse succeeds and returns hostname=None; norm_domain falls back to the raw value.
        pytest.param("evil[dot]com", id="bracket-dot-word"),
        pytest.param("evil(.)com", id="paren-dot"),
        pytest.param("1.2.3.4[:]80", id="defanged-port"),
        # urlparse succeeds AND yields a hostname -- 'hxxps' is just an unknown scheme to it.
        pytest.param("hxxps://evil(.)com", id="hxxps-paren-dot"),
    ],
)
async def test_cmd_domain_refangs_a_defanged_host_that_urlparse_accepts(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    target: str,
) -> None:
    """The SECOND guard catches defanged hosts ``urlparse`` is perfectly happy with.

    These never raise ``ValueError``, so a try/except around ``urlparse`` alone would let them
    through to ``investigate_domain`` -- a passive-source lookup for a hostname that cannot
    exist, i.e. wasted API quota and a confusing empty result. ``cli.py:226`` re-checks the
    normalised host for the same reason.
    """

    seen: list[str] = []

    async def _capture(target: str, *_a: Any, **_k: Any) -> Any:
        seen.append(target)
        return SimpleNamespace(ok=False, errors=["stub"], data={}, warnings=[])

    monkeypatch.setattr(cli, "investigate_domain", _capture)

    code = await _cmd_domain(target)

    # The target is refanged and investigated rather than refused (W6). What must hold is that
    # the value handed to the orchestrator carries no defang markers left in it.
    assert seen, "the refanged target must reach the orchestrator"
    assert not any(m in seen[0].lower() for m in ("hxxp", "[.]", "(.)", "[dot]", "[:]"))
    assert code != 2
    assert "refanged" in capsys.readouterr().out.lower()


@respx.mock
@pytest.mark.parametrize(
    "target",
    [
        pytest.param("evil(.)com", id="paren-dot"),
        pytest.param("1.2.3.4[:]80", id="defanged-port"),
        pytest.param(
            "evil[dot]com",
            id="bracket-dot-word",
        ),
    ],
)
async def test_cmd_domain_echoes_the_refanged_target(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    target: str,
) -> None:
    """The rejected target appears in the message unmangled, so it can be refanged and retried."""

    seen: list[str] = []

    async def _capture(target: str, *_a: Any, **_k: Any) -> Any:
        seen.append(target)
        return SimpleNamespace(ok=False, errors=["stub"], data={}, warnings=[])

    monkeypatch.setattr(cli, "investigate_domain", _capture)

    await _cmd_domain(target)

    # The RAW form the analyst pasted must still appear, so the note shows what was changed.
    # This is the markup-safety case too: a target containing "[/]" must not blow up rich.
    assert target in capsys.readouterr().out


@respx.mock
@pytest.mark.parametrize(
    "target",
    [
        pytest.param("hxxps://evil[.]com[/]", id="first-guard-urlparse-valueerror"),
        pytest.param("evil(.)com[/]", id="second-guard-normalised-host"),
        # '[dot]' opens a tag that '[/]' then closes, so this one happens to balance and
        # survives -- it is here to pin that the crash is markup-shape-dependent, not
        # input-length-dependent. It still displays the target wrong (see the test above).
        pytest.param("evil[dot]com[/]", id="second-guard-accidentally-balanced"),
    ],
)
async def test_cmd_domain_survives_rich_markup_in_a_defanged_target(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    target: str,
) -> None:
    """A defanged target carrying rich markup must not raise on the refang-and-announce path.

    Indicator strings are attacker-influenced and the announcement echoes the raw value back,
    so this path renders hostile text by construction. It is the last place that can afford to
    crash. Originally this guarded the rejection message; W6 replaced rejection with refanging,
    and the markup hazard moved with it rather than going away.
    """

    async def _stub(target: str, *_a: Any, **_k: Any) -> Any:
        return SimpleNamespace(ok=False, errors=["stub"], data={}, warnings=[])

    monkeypatch.setattr(cli, "investigate_domain", _stub)

    await _cmd_domain(target)
    out = capsys.readouterr().out
    assert target in out, "the raw value is echoed so the analyst sees what was changed"


@respx.mock
async def test_cmd_domain_json_output_refangs_too(monkeypatch: pytest.MonkeyPatch) -> None:
    """The JSON path suppresses the console message but must not change the exit code.

    Scripts branch on the exit status, so a defanged target has to be distinguishable from a
    successful investigation regardless of ``--format``.
    """

    seen: list[str] = []

    async def _capture(target: str, *_a: Any, **_k: Any) -> Any:
        seen.append(target)
        return SimpleNamespace(ok=False, errors=["stub"], data={}, warnings=[])

    monkeypatch.setattr(cli, "investigate_domain", _capture)

    await _cmd_domain("hxxps://evil[.]com", output="json")
    assert seen == ["evil.com"], "json mode refangs identically to console mode"


# --------------------------------------------------------------------------------------
# _load_ip_targets
# --------------------------------------------------------------------------------------


def test_load_ip_targets_reads_file_skipping_blanks_and_comments(tmp_path: Path) -> None:
    """Blank lines and ``#`` comments are dropped, duplicates collapse, order is preserved."""
    listfile = tmp_path / "targets.txt"
    # Written verbatim: the whitespace-only line and the trailing spaces on 9.9.9.9 are the
    # point, so keep them literal rather than assembling the text from a list.
    listfile.write_text(
        "# scan batch 2026-08-08\n8.8.8.8\n\n   \n1.1.1.1\n# trailing note\n8.8.8.8\n  9.9.9.9  \n",
        encoding="utf-8",
    )

    targets, source = _load_ip_targets(str(listfile))

    assert targets == ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    assert source == str(listfile)


def test_load_ip_targets_treats_missing_path_as_a_literal_target() -> None:
    """A plain indicator is not a path, so it comes back as a one-element list with no source.

    ``source_file is None`` is what ``_cmd_ip`` keys off to decide whether to print the
    "Processing N targets" banner and whether an empty result is an error.
    """
    targets, source = _load_ip_targets("8.8.8.8")

    assert targets == ["8.8.8.8"]
    assert source is None


def test_load_ip_targets_on_empty_file_returns_no_targets_but_names_the_file(tmp_path: Path) -> None:
    """An empty list file yields ``([], path)`` -- the shape ``_cmd_ip`` reports as exit 1.

    The distinction matters: ``([], path)`` is "you gave me an empty file", while
    ``([value], None)`` is "that was not a file". Collapsing them would make an empty file
    silently investigate a target named after the file.
    """
    listfile = tmp_path / "empty.txt"
    listfile.write_text("", encoding="utf-8")

    targets, source = _load_ip_targets(str(listfile))

    assert targets == []
    assert source == str(listfile)


def test_load_ip_targets_on_comments_only_file_returns_no_targets(tmp_path: Path) -> None:
    listfile = tmp_path / "comments.txt"
    listfile.write_text("# nothing here\n\n#   still nothing\n", encoding="utf-8")

    targets, source = _load_ip_targets(str(listfile))

    assert targets == []
    assert source == str(listfile)


def test_load_ip_targets_handles_crlf_line_endings(tmp_path: Path) -> None:
    """A file authored on Windows must not yield targets with a trailing carriage return.

    Written in binary so the CRLFs survive to disk; ``\\r`` leaking into a target string would
    be passed straight into a provider URL.
    """
    listfile = tmp_path / "crlf.txt"
    listfile.write_bytes(b"8.8.8.8\r\n\r\n# comment\r\n1.1.1.1\r\n")

    targets, source = _load_ip_targets(str(listfile))

    assert targets == ["8.8.8.8", "1.1.1.1"]
    assert not any("\r" in t for t in targets)
    assert source == str(listfile)


def test_load_ip_targets_expands_user_relative_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``~/targets.txt`` resolves against the home directory (``Path.expanduser`` at cli.py:125)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    (tmp_path / "targets.txt").write_text("8.8.8.8\n", encoding="utf-8")

    targets, source = _load_ip_targets("~/targets.txt")

    assert targets == ["8.8.8.8"]
    assert source == str(tmp_path / "targets.txt")


# --------------------------------------------------------------------------------------
# _fmt_provider_error
# --------------------------------------------------------------------------------------


def test_fmt_provider_error_renders_every_field_in_order() -> None:
    detail = {
        "status_code": 429,
        "reason": "Too Many Requests",
        "message": "quota exhausted",
        "url": "https://api.example.test/v1/ip/8.8.8.8",
        "body": '{"error":"rate limited"}',
    }

    assert _fmt_provider_error(detail) == (
        "status=429 | reason=Too Many Requests | message=quota exhausted "
        '| url=https://api.example.test/v1/ip/8.8.8.8 | body={"error":"rate limited"}'
    )


def test_fmt_provider_error_accepts_status_as_well_as_status_code() -> None:
    """Providers are inconsistent about the key name; both spellings must render."""
    assert _fmt_provider_error({"status": 503}) == "status=503"


def test_fmt_provider_error_url_only_reports_a_connection_failure() -> None:
    """A payload carrying only a URL means the request never got a response.

    Rendering it as ``url=...`` alone told the analyst nothing, so this branch translates it.
    """
    detail = {"url": "https://api.example.test/v1/ip/8.8.8.8"}

    assert _fmt_provider_error(detail) == "Connection Timeout / Network Error"


def test_fmt_provider_error_url_with_status_is_not_collapsed() -> None:
    """The collapse only applies when the URL is the *only* signal present."""
    out = _fmt_provider_error({"status_code": 404, "url": "https://api.example.test/x"})

    assert out == "status=404 | url=https://api.example.test/x"
    assert "Connection Timeout" not in out


def test_fmt_provider_error_on_empty_dict() -> None:
    assert _fmt_provider_error({}) == "Unknown error"


@pytest.mark.parametrize(
    ("detail", "expected"),
    [
        ("plain string failure", "plain string failure"),
        (None, "None"),
        (503, "503"),
        (["a", "b"], "['a', 'b']"),  # Cloudflare GraphQL returns an errors ARRAY
    ],
)
def test_fmt_provider_error_on_non_dict_falls_back_to_str(detail: Any, expected: str) -> None:
    assert _fmt_provider_error(detail) == expected


# --------------------------------------------------------------------------------------
# _fmt_dn
# --------------------------------------------------------------------------------------


def test_fmt_dn_joins_dict_flattening_list_values() -> None:
    """Certificate DNs arrive as dicts whose values may be scalars or lists (multi-valued RDNs)."""
    dn = {
        "C": "US",
        "O": "Example Inc.",
        "CN": "example.com",
        "OU": ["Infrastructure", "Edge"],
    }

    assert _fmt_dn(dn) == "C=US, O=Example Inc., CN=example.com, OU=Infrastructure, Edge"


def test_fmt_dn_on_empty_dict_is_empty_string() -> None:
    assert _fmt_dn({}) == ""


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("CN=example.com, O=Example Inc.", "CN=example.com, O=Example Inc."),
        (None, "None"),
        (42, "42"),
    ],
)
def test_fmt_dn_on_non_dict_falls_back_to_str(value: Any, expected: str) -> None:
    assert _fmt_dn(value) == expected


# ==========================================================================================
# W6 -- url, check, bulk, and defanging
#
# The properties pinned below are the ones that make this workstream safe rather than merely
# working. Two of them are load-bearing beyond this file:
#
# * **Detection-only costs nothing.** ``check --detect-only`` and plain ``bulk`` must not touch
#   the network, and the way that is proved here is by making any provider call an error --
#   `respx.mock` with no routes registered raises on any request, and the orchestrator
#   sentinels raise on any call. A future refactor that adds "just one quick lookup" to a
#   classification path fails these rather than quietly spending an analyst's quota.
# * **Defanging never touches the JSON.** ``evil[.]example`` is not a hostname, and a machine
#   consuming ``-o json`` would break on one.
# ==========================================================================================


def _no_orchestrators(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every provider-consulting entry point an error.

    Used by the zero-quota tests. A sentinel that raises is stronger than asserting a call
    count: it fails at the moment of the mistake, with a stack that names the caller.
    """

    async def _boom(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("a detection-only path must not consult any provider")

    for name in ("investigate_ip", "investigate_domain", "investigate_asn", "investigate_url"):
        monkeypatch.setattr(cli, name, _boom)


# ------------------------------------------------------------------------------------------
# 6.2 -- defanging is a per-field transform
# ------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("evil.example.test", "evil[.]example[.]test"),
        ("http://evil.example.test/a", "hxxp[://]evil[.]example[.]test/a"),
        ("HTTPS://EVIL.EXAMPLE/A", "hxxps[://]EVIL[.]EXAMPLE/A"),
        ("8.8.8.8", "8[.]8[.]8[.]8"),
        ("8.8.8.8:443", "8[.]8[.]8[.]8:443"),
        ("https://user:pw@evil.example:8443/p", "hxxps[://]user:pw@evil[.]example:8443/p"),
        # The embedded second URL is a live link riding inside the first; a terminal will
        # linkify it out of a report that claims to be defanged.
        (
            "http://a.example/x?next=http://evil.example/y",
            "hxxp[://]a[.]example/x?next=hxxp[://]evil.example/y",
        ),
        ("", ""),
    ],
)
def test_defang_indicator_neutralises_the_indicator_and_nothing_else(value: str, expected: str) -> None:
    assert defang_indicator(value) == expected


@pytest.mark.parametrize("value", ["10.0.0.5", "192.168.10.9", "127.0.0.1", "169.254.1.1"])
def test_non_public_addressing_is_never_defanged(value: str) -> None:
    """The operator's own internal addressing is not a hostile indicator.

    Bracketing it adds noise to the one table -- addresses resolved but not investigated --
    that exists to be read carefully, and nothing linkifies an RFC1918 address anyway.
    """
    assert defang_address(value) == value
    assert defang_indicator(value) == value


@pytest.mark.parametrize("value", ["2606:4700::1111", "http://[2606:4700::1111]:8080/x"])
def test_ipv6_literals_survive_defanging_intact(value: str) -> None:
    """Only the scheme is neutralised in an IPv6 URL; the address itself stays copyable.

    Bracketing every colon yields ``2606[:]4700[:][:]1111``, which is harder to read and to
    paste back and buys no safety, because nothing linkifies a bare IPv6 literal.
    """
    assert "2606:4700::1111" in defang_indicator(value)


def test_defanging_leaves_a_third_party_pivot_link_alone() -> None:
    """A regex sweep over the finished report would destroy exactly this.

    ``radar.cloudflare.com/ip/1.2.3.4`` points at Cloudflare, never at the target, and its
    entire value is being clickable. That is why defanging is a per-field transform applied at
    chosen call sites rather than a pass over the rendered document.
    """
    data = {"provider_status": {"virustotal": {"outcome": "not_configured"}}}
    out = _plain_render(render_ip_analysis("93.184.216.34", data, defang=True))

    assert "93[.]184[.]216[.]34" in out
    assert "radar.cloudflare.com/ip/93.184.216.34" in out
    assert "www.abuseipdb.com/check/93.184.216.34" in out


def _plain_render(renderable: RenderableType, *, width: int = 200) -> str:
    """Render to plain text at a width wide enough that no cell is truncated.

    Wider than the fixtures in ``conftest`` on purpose: several assertions below are about a
    whole URL surviving to the screen, and a truncated one would fail them for the wrong reason.
    """
    buffer = io.StringIO()
    Console(file=buffer, width=width, force_terminal=False, color_system=None, legacy_windows=False).print(renderable)
    return buffer.getvalue()


def test_defang_host_brackets_every_dot() -> None:
    assert defang_host("a.b.c.example") == "a[.]b[.]c[.]example"


# ------------------------------------------------------------------------------------------
# 6.9 -- check: detection-only costs zero provider quota
# ------------------------------------------------------------------------------------------


@respx.mock
@pytest.mark.parametrize(
    ("target", "expected_type"),
    [
        ("8.8.8.8", "ipv4"),
        ("2606:4700::1111", "ipv6"),
        ("evil.example.test", "domain"),
        ("https://evil.example.test/a", "url"),
        ("AS15169", "asn"),
        ("44d88612fea8a8f36de82e1278abb02f", "md5"),
        ("billing@evil.example.test", "email"),
    ],
)
async def test_check_detect_only_classifies_without_consulting_anyone(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    target: str,
    expected_type: str,
) -> None:
    """The zero-quota guarantee, proved by making any provider call raise."""
    _no_orchestrators(monkeypatch)

    code = await cli._cmd_check(target, detect_only=True)

    assert code == 0
    out = capsys.readouterr().out
    assert expected_type in out
    assert "no provider was consulted" in out


@respx.mock
async def test_check_detect_only_refangs_before_classifying(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``check`` is the paste-anything verb, so it accepts what ``domain`` rejects.

    The explicit subcommands stay strict on purpose -- ``domain hxxps://evil[.]com`` still
    exits 2 -- because an analyst who names the type should not have their input silently
    rewritten. ``check`` is where the rewriting is the point, and it says so on screen.
    """
    _no_orchestrators(monkeypatch)

    code = await cli._cmd_check("hxxps://Evil[.]Example[.]TEST/pay", detect_only=True)

    assert code == 0
    out = capsys.readouterr().out
    assert "url" in out
    assert "refanged_for_lookup" in out


@respx.mock
async def test_check_detect_only_on_garbage_exits_two_and_still_explains(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Unclassifiable is exit 2, but the attempt list still prints: "I could not tell, and here
    are seven reasons why" is actionable where a bare failure is not."""
    _no_orchestrators(monkeypatch)

    code = await cli._cmd_check("not an indicator at all !!", detect_only=True)

    assert code == 2
    assert "unknown" in capsys.readouterr().out


@respx.mock
async def test_check_detect_only_json_is_never_defanged(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A machine consumes this and ``evil[.]example`` is not a hostname."""
    _no_orchestrators(monkeypatch)

    assert await cli._cmd_check("https://evil.example.test/a", detect_only=True, output="json") == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["value"] == "https://evil.example.test/a"
    assert "[.]" not in payload["value"]


@respx.mock
@pytest.mark.parametrize(
    ("target", "recorder"),
    [
        ("8.8.8.8", "_cmd_ip"),
        ("evil.example.test", "_cmd_domain"),
        ("https://evil.example.test/a", "_cmd_url"),
    ],
)
async def test_check_routes_to_the_matching_subcommand(
    monkeypatch: pytest.MonkeyPatch, target: str, recorder: str
) -> None:
    seen: List[tuple[str, Any]] = []

    for name in ("_cmd_ip", "_cmd_domain", "_cmd_url", "_cmd_asn"):

        def _record(command: str) -> Any:
            async def _fake(first: Any, **_k: Any) -> int:
                seen.append((command, first))
                return 0

            return _fake

        monkeypatch.setattr(cli, name, _record(name))

    assert await cli._cmd_check(target) == 0
    assert [command for command, _ in seen] == [recorder]


@respx.mock
async def test_check_passes_the_asn_as_an_int_not_the_as_prefixed_string(monkeypatch: pytest.MonkeyPatch) -> None:
    """``_cmd_asn`` takes an int. The classifier reports the number in ``parts['asn']``, and
    reaching for ``indicator.value`` here would hand it the string ``"AS15169"``."""
    seen: List[Any] = []

    async def _fake_asn(asn: Any, **_k: Any) -> int:
        seen.append(asn)
        return 0

    monkeypatch.setattr(cli, "_cmd_asn", _fake_asn)

    assert await cli._cmd_check("AS15169") == 0
    assert seen == [15169]


@respx.mock
@pytest.mark.parametrize("target", ["44d88612fea8a8f36de82e1278abb02f", "billing@evil.example.test", "10.0.0.0/8"])
async def test_check_refuses_a_type_with_no_route_and_says_why(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], target: str
) -> None:
    """Classified fine, nowhere to go. That is a different failure from "I could not read
    that", and reporting it as one is what tells the analyst where to take the indicator."""
    _no_orchestrators(monkeypatch)

    code = await cli._cmd_check(target)

    assert code == 2
    assert "Not investigated" in " ".join(capsys.readouterr().out.split())


# ------------------------------------------------------------------------------------------
# 6.10 -- bulk paste: extraction, dedupe, filtering, triage order
# ------------------------------------------------------------------------------------------

PASTED_ALERT = """Subject: URGENT invoice 4471

Please review hxxps://pay-now[.]evil[.]test/inv?id=44 before close of business.
Received: from mx1.pphosted.com (10.0.0.5) by contoso.mail.protection.outlook.com;
Sender was 185.220.101.5, and we saw (185.220.101.5) again in the second hop.
Attachment hash 44d88612fea8a8f36de82e1278abb02f, reply-to billing@evil.test.
Netblock 185.220.101.0/24 is announced by AS15169. Internal relay 192.168.10.9 too.
Also referenced: evil.test and 2606:4700::1111.
"""


def test_extraction_pulls_indicators_out_of_prose() -> None:
    values = {indicator.value for indicator in cli.extract_indicators(PASTED_ALERT)}

    assert "185.220.101.5" in values
    assert "evil.test" in values
    assert "https://pay-now.evil.test/inv?id=44" in values  # hxxps -> https, brackets removed
    assert "44d88612fea8a8f36de82e1278abb02f" in values


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("(10.0.0.5)", "10.0.0.5"),
        ("evil.test.", "evil.test"),
        ("<https://evil.test/a>", "https://evil.test/a"),
        ("evil.test,", "evil.test"),
        ("[2001:db8::1]", "2001:db8::1"),
        # The one thing trimming must never do.
        ("evil[.]test", "evil[.]test"),
        ("hxxps://evil[.]test/a)", "hxxps://evil[.]test/a"),
    ],
)
def test_candidate_trimming_sheds_prose_wrapping_but_never_a_defang(token: str, expected: str) -> None:
    assert cli._clean_candidate(token) == expected


def test_bulk_dedupes_on_the_canonical_value_and_keeps_the_count() -> None:
    """ "Seen once in the body" and "seen in every Received: header" are different starting
    points, and deduplication without a count destroys the difference."""
    kept, _withheld = cli._triage(cli.extract_indicators(PASTED_ALERT))

    rows = {row["value"]: row for row in kept}
    assert rows["185.220.101.5"]["occurrences"] == 2
    assert len([row for row in kept if row["value"] == "185.220.101.5"]) == 1


def test_bulk_withholds_rfc1918_and_mail_infrastructure_without_deleting_either() -> None:
    """A filter that removes evidence silently is indistinguishable from evidence that was
    never there -- and the internal address a filter binned is sometimes the pivot."""
    kept, withheld = cli._triage(cli.extract_indicators(PASTED_ALERT))

    kept_values = {row["value"] for row in kept}
    withheld_values = {row["value"] for row in withheld}

    assert "10.0.0.5" not in kept_values
    assert "192.168.10.9" not in kept_values
    assert "mx1.pphosted.com" not in kept_values
    assert {"10.0.0.5", "192.168.10.9", "mx1.pphosted.com"} <= withheld_values
    assert all(row["reason"] for row in withheld)


def test_bulk_no_filter_keeps_mail_infrastructure_but_still_withholds_internal_addresses() -> None:
    """``--no-filter`` relaxes the heuristic, never the passive-boundary guard: forwarding the
    operator's internal addressing to five third parties is not a display preference."""
    kept, withheld = cli._triage(cli.extract_indicators(PASTED_ALERT), filter_infrastructure=False)

    assert "mx1.pphosted.com" in {row["value"] for row in kept}
    assert "10.0.0.5" in {row["value"] for row in withheld}


def test_triage_orders_urls_first_and_defanged_indicators_ahead_of_their_peers() -> None:
    kept, _withheld = cli._triage(cli.extract_indicators(PASTED_ALERT))

    assert kept[0]["type"] == "url"
    assert kept[0]["defanged_input"] is True
    assert kept[0]["note"].startswith("arrived defanged")
    types = [row["type"] for row in kept]
    assert types.index("domain") < types.index("md5")


@respx.mock
async def test_bulk_default_run_consults_nobody(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The highest-risk surface in the tool, in its default mode, makes no request at all.

    Extraction and classification are pure, so it is safe to paste an entire phishing email
    into this command. ``respx.mock`` with no routes raises on any outbound request and the
    sentinels raise on any orchestrator call.
    """
    _no_orchestrators(monkeypatch)

    code = await cli._cmd_bulk(PASTED_ALERT)

    assert code == 0
    out = " ".join(capsys.readouterr().out.split())
    assert "no provider was consulted" in out
    assert "withheld from triage" in out


@respx.mock
async def test_bulk_json_lists_indicators_undefanged(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _no_orchestrators(monkeypatch)

    assert await cli._cmd_bulk(PASTED_ALERT, output="json") == 0

    payload = json.loads(capsys.readouterr().out)
    values = {row["value"] for row in payload["indicators"]}
    assert "185.220.101.5" in values
    assert not any("[.]" in value for value in values)


@respx.mock
async def test_bulk_console_defangs_by_default(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _no_orchestrators(monkeypatch)

    await cli._cmd_bulk("185.220.101.5 evil.test", output="console")

    out = " ".join(capsys.readouterr().out.split())
    assert "185[.]220[.]101[.]5" in out
    assert "evil[.]test" in out


@respx.mock
async def test_bulk_with_nothing_extractable_exits_two(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _no_orchestrators(monkeypatch)

    assert await cli._cmd_bulk("nothing here but prose and commas, honestly") == 2
    assert "none found" in " ".join(capsys.readouterr().out.split())


@respx.mock
async def test_bulk_investigate_is_capped_by_max_targets(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An unbounded fan-out over a pasted mail thread is a quota incident at best.

    The cap is asserted on the number of routed lookups rather than on the message, because
    the message is cosmetic and the bound is the control.
    """
    routed: List[str] = []

    async def _fake_check(target: str, **_k: Any) -> int:
        routed.append(target)
        return 0

    monkeypatch.setattr(cli, "_cmd_check", _fake_check)

    code = await cli._cmd_bulk(PASTED_ALERT, investigate=True, max_targets=2)

    assert code == 0
    assert len(routed) == 2
    assert "above the --max-targets cap" in capsys.readouterr().out


def test_bulk_reads_a_file_when_the_argument_is_a_path(tmp_path: Path) -> None:
    paste = tmp_path / "alert.txt"
    paste.write_text(PASTED_ALERT, encoding="utf-8")

    assert cli._read_bulk_text(str(paste)) == PASTED_ALERT


def test_bulk_treats_a_non_path_argument_as_the_text_itself() -> None:
    assert cli._read_bulk_text("185.220.101.5 evil.test") == "185.220.101.5 evil.test"


def test_bulk_reads_stdin_for_a_dash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("evil.test\n"))

    assert cli._read_bulk_text("-") == "evil.test\n"


def test_triage_table_renders_an_empty_list_without_implying_a_clean_result() -> None:
    """Zero extracted indicators is "nothing was found in this text", never "this text is
    fine". The caveat line rides with the table so it cannot be read the second way."""
    out = _plain_render(render_triage_table([]))

    assert "none found" in out
    assert "no provider was consulted" in out


# ------------------------------------------------------------------------------------------
# 6.8 -- the url subcommand
# ------------------------------------------------------------------------------------------


def _url_result(
    *,
    ok: bool = True,
    depth: str = "url",
    verdict: Optional[Dict[str, Any]] = None,
    resolution: str = "NOT RESOLVED",
    errors: Optional[List[str]] = None,
) -> Any:
    status = {"virustotal_url": {"outcome": "ok"}}
    coverage = Coverage.from_status_map(status, expected=("virustotal_url",), prefix="url:")
    chain: Dict[str, Any] = {
        "resolution": resolution,
        "reason": "not followed: resolving a redirect is an active fetch of the target",
        "hops": [],
        "final_url": None,
        "source": None,
        "observed_at": None,
        "rendered": f"{resolution} -- not followed: resolving a redirect is an active fetch",
    }
    data: Dict[str, Any] = {
        "url": "http://evil.example.test/pay?id=9",
        "url_display": "http://evil.example.test/pay?id=9",
        "url_raw": "http://evil.example.test/pay?id=9",
        "depth": depth,
        "scheme": "http",
        "scheme_assumed": False,
        "host": "evil.example.test",
        "host_kind": "dns_name",
        "host_ascii": "evil.example.test",
        "pivot_host": "evil.example.test",
        "registrable_domain": None,
        "registrable_domain_status": "unavailable_no_public_suffix_list",
        "port": None,
        "path": "/pay",
        "query": "id=9",
        "fragment": "",
        "userinfo_present": False,
        "url_anomalies": [],
        "redirect_chain": chain,
        "url_provider_status": status,
        "ips": [],
        "addresses": {"resolved": 0, "investigated": 0, "skipped": 0},
        "skipped_ips": [],
        "collection": {"passive_only": True, "active_steps": []},
        "coverage": coverage.model_dump(),
        "warnings": [],
    }
    if verdict is not None:
        data["verdict"] = verdict
    return InvestigationResult(ok=ok, data=data, errors=errors or [], coverage=coverage)


@respx.mock
async def test_cmd_url_reports_the_redirect_chain_as_not_resolved(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The single most important line in a URL report.

    A blank here reads as "this link does not redirect", which is the opposite claim from
    "nobody followed it and this tool never will" -- and the blank is the dangerous one.
    """

    async def _fake(*_a: Any, **_k: Any) -> Any:
        return _url_result()

    monkeypatch.setattr(cli, "investigate_url", _fake)

    code = await cli._cmd_url("http://evil.example.test/pay?id=9")

    assert code == 0
    out = " ".join(capsys.readouterr().out.split())
    assert "redirect_chain" in out
    assert "NOT RESOLVED" in out
    assert "active fetch" in out


@respx.mock
async def test_cmd_url_defangs_the_url_by_default_and_not_with_fanged(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def _fake(*_a: Any, **_k: Any) -> Any:
        return _url_result()

    monkeypatch.setattr(cli, "investigate_url", _fake)

    await cli._cmd_url("http://evil.example.test/pay?id=9")
    defanged = " ".join(capsys.readouterr().out.split())
    assert "hxxp[://]evil[.]example[.]test/pay" in defanged
    assert "http://evil.example.test/pay" not in defanged

    await cli._cmd_url("http://evil.example.test/pay?id=9", defang=False)
    fanged = " ".join(capsys.readouterr().out.split())
    assert "http://evil.example.test/pay" in fanged


@respx.mock
async def test_cmd_url_json_is_never_defanged(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def _fake(*_a: Any, **_k: Any) -> Any:
        return _url_result()

    monkeypatch.setattr(cli, "investigate_url", _fake)

    assert await cli._cmd_url("http://evil.example.test/pay?id=9", output="json") == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["data"]["url"] == "http://evil.example.test/pay?id=9"
    assert "[.]" not in json.dumps(payload["data"]["url"])


@respx.mock
async def test_cmd_url_refangs_a_defanged_target_before_lookup(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 2, and a pointer at the verb that does accept it."""

    seen: list[str] = []

    async def _boom(target: str, *_a: Any, **_k: Any) -> Any:
        seen.append(target)
        return SimpleNamespace(ok=False, errors=["stub"], data={}, warnings=[])

    monkeypatch.setattr(cli, "investigate_url", _boom)

    await cli._cmd_url("hxxps://evil[.]test/a")
    out = capsys.readouterr().out
    assert seen == ["https://evil.test/a"], "the refanged URL is what gets investigated"
    assert "refanged" in out.lower(), "the transform must be announced, never silent"


@respx.mock
async def test_cmd_url_failure_still_names_the_providers(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A blackout on the URL path prints the coverage line for the same reason every other
    path does: "the lookup failed" with no attribution is the least actionable message the
    tool can produce."""

    async def _fake(*_a: Any, **_k: Any) -> Any:
        return _url_result(ok=False, errors=["no provider answered for the URL"])

    monkeypatch.setattr(cli, "investigate_url", _fake)

    assert await cli._cmd_url("http://evil.example.test/pay?id=9") == 1
    assert "provider" in capsys.readouterr().out


# ------------------------------------------------------------------------------------------
# Parser wiring for the new verbs
# ------------------------------------------------------------------------------------------

_NEW_SUBCOMMANDS = [
    pytest.param("url", "https://evil.example.test/a", "_cmd_url", id="url"),
    pytest.param("check", "8.8.8.8", "_cmd_check", id="check"),
    pytest.param("bulk", "8.8.8.8", "_cmd_bulk", id="bulk"),
]


@pytest.fixture
def run_cli_all(monkeypatch: pytest.MonkeyPatch) -> RunCli:
    """``run_cli``, extended to the W6 verbs. Same neutralisation, same guarantees."""

    def _run(argv: list[str]) -> tuple[int, _Invocation]:
        recorded: list[_Invocation] = []

        def _recorder(name: str) -> Callable[..., Any]:
            async def _fake(*args: Any, **kwargs: Any) -> int:
                recorded.append(_Invocation(name, args, kwargs))
                return 0

            return _fake

        monkeypatch.setattr(cli, "load_env", lambda: None)
        monkeypatch.setattr(cli, "configure_rate_limit", lambda *_a, **_k: None)
        monkeypatch.setattr(cli, "configure_user_agent", lambda *_a, **_k: None)
        for name in ("_cmd_ip", "_cmd_domain", "_cmd_asn", "_cmd_url", "_cmd_check", "_cmd_bulk"):
            monkeypatch.setattr(cli, name, _recorder(name))
        monkeypatch.setattr(sys, "argv", ["tripper-recon", *argv])

        with pytest.raises(SystemExit) as excinfo:
            cli.main()

        code = excinfo.value.code
        assert len(recorded) == 1, f"expected exactly one dispatch for {argv!r}, got {recorded!r}"
        return int(code or 0), recorded[0]

    return _run


@pytest.mark.parametrize(("cmd", "target", "recorder"), _NEW_SUBCOMMANDS)
def test_new_subcommands_dispatch(run_cli_all: RunCli, cmd: str, target: str, recorder: str) -> None:
    code, call = run_cli_all([cmd, target])

    assert code == 0
    assert call.cmd == recorder


@pytest.mark.parametrize(
    ("cmd", "target"),
    [("ip", "8.8.8.8"), ("domain", "evil.example.test"), ("url", "https://evil.example.test/a")],
)
def test_defang_is_on_by_default_and_off_with_fanged(run_cli_all: RunCli, cmd: str, target: str) -> None:
    """The flag is the operator's, and the default is the safe one."""
    _code, default_call = run_cli_all([cmd, target])
    assert default_call.kwargs["defang"] is True

    _code, fanged_call = run_cli_all(["--fanged", cmd, target])
    assert fanged_call.kwargs["defang"] is False


@pytest.mark.parametrize("depth", ["url", "host", "full"])
def test_url_depth_reaches_the_command(run_cli_all: RunCli, depth: str) -> None:
    _code, call = run_cli_all(["url", "https://evil.example.test/a", "--depth", depth])

    assert call.kwargs["depth"] == depth


def test_url_depth_defaults_to_full(run_cli_all: RunCli) -> None:
    _code, call = run_cli_all(["url", "https://evil.example.test/a"])

    assert call.kwargs["depth"] == "full"


def test_bulk_investigate_and_cap_reach_the_command(run_cli_all: RunCli) -> None:
    _code, call = run_cli_all(["bulk", "8.8.8.8", "--investigate", "--max-targets", "3", "--no-filter"])

    assert call.kwargs["investigate"] is True
    assert call.kwargs["max_targets"] == 3
    assert call.kwargs["filter_infrastructure"] is False


def test_bulk_defaults_to_triage_only(run_cli_all: RunCli) -> None:
    """Opt-in is the whole safety argument for the highest-risk input surface in the tool."""
    _code, call = run_cli_all(["bulk", "8.8.8.8"])

    assert call.kwargs["investigate"] is False
    assert call.kwargs["filter_infrastructure"] is True


def test_check_detect_only_reaches_the_command(run_cli_all: RunCli) -> None:
    _code, call = run_cli_all(["check", "8.8.8.8", "--detect-only"])

    assert call.kwargs["detect_only"] is True


@respx.mock
async def test_cmd_url_says_no_report_exists_rather_than_query_failed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The two are different facts and only one of them is about the link.

    A 404 from the VirusTotal URL report means nobody has ever submitted this link -- the
    ordinary state of one stood up an hour ago. Rendering that as "query failed" points the
    analyst at their own API key instead of at the finding.
    """

    async def _fake(*_a: Any, **_k: Any) -> Any:
        result = _url_result()
        result.data["url_report_missing"] = True
        result.data["url_provider_status"] = {"virustotal_url": {"outcome": "error"}}
        return result

    monkeypatch.setattr(cli, "investigate_url", _fake)

    assert await cli._cmd_url("http://evil.example.test/pay?id=9") == 0
    out = " ".join(capsys.readouterr().out.split())
    assert "no report exists" in out
    assert "UNKNOWN, not clean" in out
    assert "0/0" not in out


@respx.mock
@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("unavailable_no_public_suffix_list", "no public suffix list is vendored"),
        ("not_applicable_ip_literal", "the host is an IP literal"),
        ("not_applicable_single_label", "single label"),
    ],
)
async def test_cmd_url_words_the_registrable_domain_gap_per_status(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], status: str, expected: str
) -> None:
    """ "No list is vendored" is a gap in this tool; "the host is an IP literal" is not a gap at
    all, and one sentence for both would misreport whichever it is not."""

    async def _fake(*_a: Any, **_k: Any) -> Any:
        result = _url_result()
        result.data["registrable_domain_status"] = status
        return result

    monkeypatch.setattr(cli, "investigate_url", _fake)

    await cli._cmd_url("http://evil.example.test/pay?id=9")

    assert expected in " ".join(capsys.readouterr().out.split())


def _real_verdict_dict(indicator: str) -> Dict[str, Any]:
    """A verdict payload produced by the real engine rather than hand-written.

    ``render_verdict`` parses ``data['verdict']`` back through the ``Verdict`` model precisely
    so a truncated payload fails to parse instead of printing a clean word it did not earn. A
    hand-written fixture here would either drift from that model or be written to satisfy it,
    and neither proves the renderer works on what the orchestrator actually publishes.
    """
    import datetime as _dt

    from tripper_recon.verdict import engine as _engine
    from tripper_recon.verdict.config import IndicatorScope as _Scope
    from tripper_recon.verdict.config import default_config as _default_config

    verdict = _engine.evaluate(
        indicator=indicator,
        scope=_Scope.DOMAIN,
        signals=(),
        coverage=Coverage.from_status_map({"virustotal": {"outcome": "not_configured"}}, expected=("virustotal",)),
        cfg=_default_config(),
        now=_dt.datetime(2026, 8, 8, tzinfo=_dt.timezone.utc),
    )
    payload: Dict[str, Any] = verdict.to_json_dict()
    return payload


@respx.mock
async def test_cmd_url_prints_the_host_verdict_separately_from_the_url_verdict(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The composition claim behind 6.8, and the reason the two are never merged.

    A phishing page on a compromised WordPress site is a malicious URL on a host that is itself
    a victim. Merging the two either clears the page or indicts the victim, so both verdicts
    reach the screen and the host's intelligence rows are printed by the same code the
    ``domain`` subcommand uses.
    """

    async def _fake(*_a: Any, **_k: Any) -> Any:
        result = _url_result(depth="host", verdict=_real_verdict_dict("http://evil.example.test/pay?id=9"))
        result.data["domain"] = "evil.example.test"
        result.data["domain_provider_status"] = {"virustotal": {"outcome": "not_configured"}}
        result.data["host_verdict"] = _real_verdict_dict("evil.example.test")
        return result

    monkeypatch.setattr(cli, "investigate_url", _fake)

    assert await cli._cmd_url("http://evil.example.test/pay?id=9") == 0
    out = " ".join(capsys.readouterr().out.split())

    assert out.count("VERDICT:") == 2
    assert "domain_intelligence" in out
    # The host's own rows come from the shared helper, so the "never asked" wording that stops
    # an unset key looking like a clean result is inherited rather than reimplemented.
    assert "no data - not configured, no API key" in out
