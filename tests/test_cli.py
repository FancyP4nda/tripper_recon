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

import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
import respx

from tripper_recon import cli
from tripper_recon.cli import (
    _DEFANG_MARKERS,
    _cmd_domain,
    _fmt_dn,
    _fmt_provider_error,
    _load_ip_targets,
    _looks_defanged,
)

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
async def test_cmd_domain_rejects_defanged_url_that_urlparse_rejects(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``hxxps://evil[.]com`` exits 2 with an instruction, and never resolves anything.

    Pre-fix this hit the FIRST guard's absence: ``urlparse`` treats ``[.]`` as an IPv6 literal
    and raises ``ValueError: Invalid IPv6 URL``, which propagated as a traceback out of
    ``main``. ``respx.mock`` with no routes registered means any httpx request raises, and the
    ``investigate_domain`` sentinel below means any resolution attempt fails loudly.
    """

    async def _boom(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("investigate_domain must not run for a defanged target")

    monkeypatch.setattr(cli, "investigate_domain", _boom)

    code = await _cmd_domain("hxxps://evil[.]com")

    assert code == 2
    out = capsys.readouterr().out
    assert "defanged" in out.lower()


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
async def test_cmd_domain_rejects_defanged_host_that_urlparse_accepts(
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

    async def _boom(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("investigate_domain must not run for a defanged target")

    monkeypatch.setattr(cli, "investigate_domain", _boom)

    code = await _cmd_domain(target)

    assert code == 2
    assert "defanged" in capsys.readouterr().out.lower()


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
async def test_cmd_domain_echoes_the_rejected_target_verbatim(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    target: str,
) -> None:
    """The rejected target appears in the message unmangled, so it can be refanged and retried."""

    async def _boom(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("investigate_domain must not run for a defanged target")

    monkeypatch.setattr(cli, "investigate_domain", _boom)

    assert await _cmd_domain(target) == 2
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
    """A defanged target carrying rich markup must still exit 2, not raise.

    Indicator strings are attacker-influenced. The rejection path is the last place that can
    afford to crash.
    """

    async def _boom(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("investigate_domain must not run for a defanged target")

    monkeypatch.setattr(cli, "investigate_domain", _boom)

    assert await _cmd_domain(target) == 2
    capsys.readouterr()


@respx.mock
async def test_cmd_domain_json_output_still_exits_2_on_defanged(monkeypatch: pytest.MonkeyPatch) -> None:
    """The JSON path suppresses the console message but must not change the exit code.

    Scripts branch on the exit status, so a defanged target has to be distinguishable from a
    successful investigation regardless of ``--format``.
    """

    async def _boom(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("investigate_domain must not run for a defanged target")

    monkeypatch.setattr(cli, "investigate_domain", _boom)

    assert await _cmd_domain("hxxps://evil[.]com", output="json") == 2


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
