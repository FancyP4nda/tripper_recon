"""``--help`` is documentation, so it is tested like documentation (roadmap 9.11).

The README this project started with claimed URL support that did not exist, HTTP/2 that was
disabled, and a config value that crashed the tool. ``--help`` is the copy of that documentation
an analyst actually reads, at the moment they are least able to check it, and it rots the same
way -- silently, because nothing executes it. These tests execute it.

Four properties are pinned, each chosen because breaking it would mislead rather than merely
annoy:

* **The exit-code table is present and complete.** A playbook branches on ``$?``. The table is
  the public contract, and the caveat that code 0 is not a claim of cleanliness is the single
  most misreadable thing in the tool.
* **Every worked example parses.** Each example line in the epilog is extracted and fed back
  through the real parser, so an example cannot advertise a flag that was renamed or removed.
  This is the check that would have caught ``--monochrome`` surviving in a doc block after the
  flag went.
* **The ENVIRONMENT block names every variable the package reads.** The expected set is derived
  by walking the package's own AST for ``os.getenv``/``os.environ.get`` literals rather than
  from a list written here, so adding a variable and forgetting the help text fails the build.
* **Each subcommand's help names the providers that path consults**, and points at
  ``docs/PROVIDERS.md`` for the rest. "Why is my output empty" is the first question a sparse
  panel produces.

**Network:** nothing here touches it. Every ``_cmd_*`` coroutine is replaced with a recorder,
and the ``--help`` paths exit inside ``argparse`` before dispatch.

**Credentials:** ``cli.main`` calls ``load_env()``, which would read the operator's real ``.env``
into ``os.environ`` and defeat the ``clear_provider_env`` control in ``conftest.py``. Every test
here that reaches ``main`` stubs it out. Do not remove that stub.
"""

from __future__ import annotations

import ast
import pathlib
import re
import shlex
import sys
from collections.abc import Callable
from typing import Any, List

import pytest

from tripper_recon import cli
from tripper_recon.verdict.config import CONFIG_ENV_VAR
from tripper_recon.verdict.known_infrastructure import CATALOGUE_PATH_ENV

# The six subcommands the parser declares. Kept as a literal so a subcommand that is added
# without an example, or removed without its example being removed, fails here.
SUBCOMMANDS: tuple[str, ...] = ("ip", "domain", "asn", "url", "check", "bulk")

# Every ``_cmd_*`` coroutine ``main`` can dispatch to. All of them make network calls.
COMMAND_FUNCTIONS: tuple[str, ...] = (
    "_cmd_ip",
    "_cmd_domain",
    "_cmd_asn",
    "_cmd_url",
    "_cmd_check",
    "_cmd_bulk",
)

PACKAGE_ROOT = pathlib.Path(cli.__file__).resolve().parent


# --------------------------------------------------------------------------------------
# Harness
# --------------------------------------------------------------------------------------


HelpFor = Callable[[List[str]], str]


@pytest.fixture
def help_for(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> HelpFor:
    """Return the help text ``main`` prints for an argv, with every side effect neutralised.

    ``argparse`` writes help to stdout and raises ``SystemExit(0)``, so this asserts the exit
    code as well: a ``--help`` that exits non-zero is itself a defect.
    """

    def _help(argv: List[str]) -> str:
        monkeypatch.setattr(cli, "load_env", lambda: None)
        monkeypatch.setattr(sys, "argv", ["tripper-recon", *argv])
        with pytest.raises(SystemExit) as excinfo:
            cli.main()
        assert excinfo.value.code in (0, None), f"{argv!r} exited {excinfo.value.code}"
        return capsys.readouterr().out

    return _help


ParseArgv = Callable[[List[str]], int]


@pytest.fixture
def parse_argv(monkeypatch: pytest.MonkeyPatch) -> ParseArgv:
    """Run an argv through the real parser and dispatch, returning the exit code.

    Stubs everything with a side effect: ``load_env`` (the operator's ``.env``), the two
    ``utils.http`` configuration calls (they mutate module globals that outlive the test), and
    every ``_cmd_*`` coroutine (the only things in ``main`` that reach the network). What is
    left under test is argument parsing and dispatch, which is exactly what an example claims.
    """

    def _parse(argv: List[str]) -> int:
        async def _fake(*_args: Any, **_kwargs: Any) -> int:
            return 0

        monkeypatch.setattr(cli, "load_env", lambda: None)
        monkeypatch.setattr(cli, "configure_rate_limit", lambda *_a, **_k: None)
        monkeypatch.setattr(cli, "configure_user_agent", lambda *_a, **_k: None)
        for name in COMMAND_FUNCTIONS:
            monkeypatch.setattr(cli, name, _fake)
        monkeypatch.setattr(sys, "argv", ["tripper-recon", *argv])

        with pytest.raises(SystemExit) as excinfo:
            cli.main()
        return int(excinfo.value.code or 0)

    return _parse


def _example_commands() -> List[str]:
    """The ``tripper-recon ...`` invocation lines from the epilog's examples block."""
    return [line.strip() for line in cli._EXAMPLES.splitlines() if line.strip().startswith("tripper-recon ")]


# --------------------------------------------------------------------------------------
# Exit codes
# --------------------------------------------------------------------------------------


def test_help_carries_the_exit_code_table(help_for: HelpFor) -> None:
    """The exit-code contract is in ``--help``, not only in the module docstring.

    A playbook author branching on ``$?`` reads ``--help``. Every code the CLI can return is
    documented there, and the three returns are enumerated in the source: ``0`` and ``1`` from
    the command functions, ``2`` from the input guards and from ``main`` with no subcommand.
    """
    text = help_for(["--help"])
    assert "exit codes:" in text
    for code in ("0", "1", "2"):
        assert re.search(rf"^\s+{code}\s+\S", text, re.MULTILINE), f"exit code {code} is not documented"


def test_help_says_a_zero_exit_is_not_a_clean_verdict(help_for: HelpFor) -> None:
    """The caveat is load-bearing, so it is pinned separately from the table.

    ``0`` means a provider answered. Reading it as "clean" is the single most damaging
    misreading available, and the coverage line is the thing that corrects it.
    """
    text = help_for(["--help"])
    assert "NOT a claim that the indicator is clean" in text
    assert "provider_coverage" in text
    assert "The exit code is not the verdict." in text


# --------------------------------------------------------------------------------------
# Worked examples
# --------------------------------------------------------------------------------------


def test_help_shows_at_least_five_worked_examples(help_for: HelpFor) -> None:
    text = help_for(["--help"])
    assert "examples:" in text
    assert len(_example_commands()) >= 5


@pytest.mark.parametrize("subcommand", SUBCOMMANDS)
def test_every_subcommand_has_a_worked_example(help_for: HelpFor, subcommand: str) -> None:
    """Each subcommand appears in the examples block as an invocation, not just in the list."""
    help_for(["--help"])  # asserts the epilog renders at all
    prefix = f"tripper-recon {subcommand} "
    assert any(line.startswith(prefix) for line in _example_commands()), f"no worked example for `{subcommand}`"


@pytest.mark.parametrize("command", _example_commands(), ids=lambda c: shlex.split(c)[1])
def test_every_worked_example_parses(parse_argv: ParseArgv, command: str) -> None:
    """An example that the parser rejects is worse than no example.

    This is the anti-rot check: rename or remove a flag and the example naming it fails here,
    at the same moment, instead of misleading an analyst months later.
    """
    argv = shlex.split(command)[1:]
    assert parse_argv(argv) == 0, f"the documented example `{command}` does not parse"


# --------------------------------------------------------------------------------------
# ENVIRONMENT block
# --------------------------------------------------------------------------------------


def _env_vars_read_by_package() -> set[str]:
    """Every environment variable name the package reads, found by walking its own AST.

    Derived rather than listed so the expectation cannot drift from the code. Two forms are
    covered: a string literal passed to ``os.getenv`` / ``.get`` (which catches the six
    credentials, the two behaviour knobs, and ``XDG_CONFIG_HOME``), and the two names held in
    module constants, which are imported directly at the top of this file.

    The ALL-CAPS filter is what keeps ordinary ``dict.get("key")`` calls out. It currently
    yields exactly the nine literals and no false positives; a lower-case variable would be
    missed, which is a limit of this check and not a licence to add one.
    """
    literal_name = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")
    found: set[str] = set()
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in {"getenv", "get"} or not node.args:
                continue
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str) and literal_name.match(first.value):
                found.add(first.value)
    return found | {CONFIG_ENV_VAR, CATALOGUE_PATH_ENV}


def test_help_lists_every_environment_variable_the_package_reads(help_for: HelpFor) -> None:
    """Add a variable, document it. The expected set comes from the source, not from a list."""
    text = help_for(["--help"])
    assert "environment:" in text
    expected = _env_vars_read_by_package()
    # Sanity floor: if the scan finds nothing the assertion below would pass vacuously.
    assert len(expected) >= 9, f"the AST scan found only {sorted(expected)}; the check is broken"
    missing = sorted(name for name in expected if name not in text)
    assert not missing, f"--help does not document: {missing}"


def test_help_names_the_three_keyless_providers(help_for: HelpFor) -> None:
    """The empty-``.env`` case is the fastest way to prove the tool works, so it is stated."""
    text = help_for(["--help"])
    for provider in ("RIPEstat", "CAIDA", "PeeringDB"):
        assert provider in text


# --------------------------------------------------------------------------------------
# "Why is my output empty"
# --------------------------------------------------------------------------------------


def test_help_answers_why_output_is_empty_and_points_at_the_provider_doc(help_for: HelpFor) -> None:
    text = help_for(["--help"])
    assert "docs/PROVIDERS.md" in text
    assert "no data" in text
    assert "unvalidated" in text, "the help text must not imply the verdict weights are calibrated"


# --------------------------------------------------------------------------------------
# Per-subcommand provider notes
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("subcommand", "expected"),
    [
        pytest.param("ip", ("VirusTotal", "IPinfo", "Shodan", "AbuseIPDB", "OTX", "Cloudflare"), id="ip"),
        pytest.param("domain", ("VirusTotal", "OTX", "system resolver"), id="domain"),
        pytest.param("asn", ("RIPEstat", "CAIDA", "PeeringDB", "Cloudflare"), id="asn"),
        pytest.param("url", ("VirusTotal", "--depth"), id="url"),
        pytest.param("check", ("--detect-only",), id="check"),
        pytest.param("bulk", ("--investigate", "--max-targets"), id="bulk"),
    ],
)
def test_subcommand_help_names_what_it_consults(help_for: HelpFor, subcommand: str, expected: tuple[str, ...]) -> None:
    text = help_for([subcommand, "--help"])
    for token in expected:
        assert token in text, f"`{subcommand} --help` does not mention {token!r}"


def test_url_help_states_which_depths_resolve(help_for: HelpFor) -> None:
    """``--depth`` is the passivity control, so the help says which value leaves the box.

    ``url`` and ``host`` resolve nothing; ``full`` is the default and uses the system resolver,
    which is the one documented exception to passivity.
    """
    text = help_for(["url", "--help"])
    assert "Resolves nothing" in text
    assert "system resolver" in text


def test_url_help_does_not_claim_urlscan_is_wired_in(help_for: HelpFor) -> None:
    """urlscan.io is implemented and allowlisted but not yet consulted by any path.

    ``orchestrators.URL_PROVIDERS`` is the denominator of the URL coverage ratio and holds one
    entry. If urlscan is wired in, this test is the reminder to update the help text with it.
    """
    from tripper_recon.orchestrators import URL_PROVIDERS

    text = help_for(["url", "--help"])
    if "urlscan" in URL_PROVIDERS or "urlscan_url" in URL_PROVIDERS:
        pytest.fail("urlscan is now a URL provider -- update the `url` epilog and this test")
    assert "not yet wired into this" in text


# --------------------------------------------------------------------------------------
# Flags removed under roadmap 9.11
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("flag", ["--monochrome", "--enrich", "--enrich-limit"])
def test_removed_asn_flags_are_absent_from_help(help_for: HelpFor, flag: str) -> None:
    """All three advertised behaviour the code did not have. They are gone, not hidden.

    ``--enrich``'s help named a whois/pWhois path that exists nowhere in the package;
    ``--monochrome`` fed a ``use_color`` parameter that neither renderer body reads.
    """
    assert flag not in help_for(["asn", "--help"])


@pytest.mark.parametrize("flag", ["--monochrome", "--enrich"])
def test_removed_asn_flags_are_rejected_by_the_parser(parse_argv: ParseArgv, flag: str) -> None:
    """Removed means rejected. A silently-accepted no-op flag is the defect being removed."""
    assert parse_argv(["asn", "15169", flag]) == 2
