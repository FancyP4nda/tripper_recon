"""Regression net for W0 fix 0.8 -- the FastAPI server is gone and stays gone.

This was the one fix of the nine with no test behind it. The other eight are pinned by
``test_redact``, ``test_console_render``, ``test_orchestrators``, ``test_logging`` and
``test_cli``; 0.8 was locked in by nothing at all, so a future session could reintroduce
``tripper_recon/api/server.py`` and the suite would stay green.

Why the removal matters beyond tidiness: Tripper Recon is a passive OSINT CLI whose whole
claim is that it never touches the target and never listens. A bundled HTTP server inverts
both properties -- it opens a listening socket on the analyst's host, and it turns a
single-user local tool into a service that accepts requests carrying provider credentials
from ``.env``. The removed module had no authentication.

Pre-fix behaviour: ``tripper_recon/api/server.py`` existed (51 lines, deleted in ae59d18),
``fastapi``/``uvicorn`` were listed as dependencies, and ``[project.scripts]`` exposed a
``tripper-recon-api`` command pointing at ``tripper_recon.api.server:run``.

One wrinkle worth recording, because it explains why the dependency check below does NOT
fail against the pre-fix tree even though the frameworks are visible in that file: pre-fix
``pyproject.toml`` declared ``dependencies`` *after* the ``[project.urls]`` header, so TOML
parsed the array into ``project.urls`` rather than ``project``. The dependencies were
therefore never installed by the packaging metadata at all -- a separate packaging bug that
ae59d18 also corrected by moving the array back under ``[project]``. The entry-point and
import checks are what catch the removal on the pre-fix tree.

Deliberate scoping note -- this module does NOT assert that the ``tripper_recon.api``
package is unimportable. The directory survives in a working tree as untracked cruft (a
stale ``__pycache__`` left by the deleted sources), which makes it an implicit namespace
package locally while being absent from a fresh clone. An assertion on it would pass in CI
and fail on the maintainer's machine for reasons unrelated to the code. The checks below
are all deterministic in both places.
"""

from __future__ import annotations

import importlib
import re
import sys
from pathlib import Path

import pytest

# ``tomllib`` is stdlib from 3.11. This project declares requires-python = ">=3.10" and CI
# runs a 3.10 job, so importing it unconditionally would turn the 3.10 matrix leg into a
# collection error. The two pyproject-parsing tests below are skipped there rather than
# adding a ``tomli`` backport to the dev dependencies for two assertions; the import and
# entry-point checks still run on every interpreter.
if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on the 3.10 CI leg
    tomllib = None  # type: ignore[assignment]

needs_tomllib = pytest.mark.skipif(
    sys.version_info < (3, 11),
    reason="tomllib is stdlib only on 3.11+; pyproject assertions run on the 3.11/3.12 legs",
)

PACKAGE_ROOT = Path(__file__).resolve().parent.parent / "tripper_recon"
PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"

# Web-server machinery that has no place in a passive CLI. Matched as import statements
# rather than bare substrings so prose in a docstring or a comment cannot trip the gate.
WEB_FRAMEWORKS: tuple[str, ...] = ("fastapi", "uvicorn", "starlette")

_IMPORT_RE = re.compile(
    r"^\s*(?:from\s+(?P<from>[\w.]+)|import\s+(?P<import>[\w.]+))",
    re.MULTILINE,
)


def _source_files() -> list[Path]:
    return sorted(PACKAGE_ROOT.rglob("*.py"))


def test_source_tree_is_not_empty() -> None:
    """Guard the guards.

    Every other test in this module is a negative assertion over ``_source_files()``. If the
    glob silently returned nothing -- wrong path, renamed package -- they would all pass
    while checking nothing. This makes that failure mode loud.
    """
    files = _source_files()
    assert len(files) > 10, (
        f"expected the package source to be scannable, found {len(files)} .py files under {PACKAGE_ROOT}"
    )


def test_server_module_is_not_importable() -> None:
    """``tripper_recon.api.server`` is gone.

    A leftover ``__pycache__/server.*.pyc`` does not resurrect it: CPython will not import a
    module from a cache entry whose source file is absent, so this is stable even in a dirty
    working tree.

    Pre-fix behaviour: this import succeeded and pulled in FastAPI.
    """
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("tripper_recon.api.server")


@pytest.mark.parametrize("framework", WEB_FRAMEWORKS)
def test_no_web_framework_is_imported_anywhere_in_the_package(framework: str) -> None:
    """No module in the package imports a web framework.

    Catches reintroduction under a new filename, which an assertion pinned to the old
    ``api/server.py`` path would miss.
    """
    offenders: list[str] = []
    for path in _source_files():
        text = path.read_text(encoding="utf-8")
        for match in _IMPORT_RE.finditer(text):
            module = match.group("from") or match.group("import") or ""
            if module == framework or module.startswith(f"{framework}."):
                lineno = text.count("\n", 0, match.start()) + 1
                offenders.append(f"{path.relative_to(PACKAGE_ROOT.parent)}:{lineno}")

    assert not offenders, (
        f"'{framework}' is imported by the package at: {offenders}.\n\n"
        "Tripper Recon is a passive, single-user CLI. A bundled HTTP server opens a "
        "listening socket on the analyst's host and exposes provider credentials loaded "
        "from .env to anything that can reach it -- the removed server had no auth. "
        "If a service front-end is genuinely wanted it belongs in a separate package with "
        "its own threat model, not behind an import in the recon tool."
    )


@needs_tomllib
@pytest.mark.parametrize("framework", WEB_FRAMEWORKS)
def test_no_web_framework_is_a_declared_dependency(framework: str) -> None:
    """The frameworks are absent from runtime AND optional dependencies.

    Removing the code while leaving the dependency declared re-installs the attack surface
    for every user and invites the import back.

    Pre-fix behaviour: ``fastapi`` and ``uvicorn`` were listed in ``[project] dependencies``.
    """
    config = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    project = config.get("project", {})

    declared: list[str] = list(project.get("dependencies", []))
    for extra, deps in project.get("optional-dependencies", {}).items():
        declared.extend(f"{dep}  (extra: {extra})" for dep in deps)

    offenders = [dep for dep in declared if re.match(rf"^\s*{framework}\b", dep, re.IGNORECASE)]

    assert not offenders, f"'{framework}' is still a declared dependency in pyproject.toml: {offenders}"


@needs_tomllib
def test_no_server_entry_point_is_exposed() -> None:
    """No console script launches a server.

    ``[project.scripts]`` is the other way a server comes back: the module could live
    outside the package and still be wired to a ``tripper-recon-serve`` command.
    """
    config = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    scripts: dict[str, str] = config.get("project", {}).get("scripts", {})

    offenders = {
        name: target
        for name, target in scripts.items()
        if re.search(r"serve|server|api|uvicorn", f"{name} {target}", re.IGNORECASE)
    }

    assert not offenders, f"a console script appears to launch a server: {offenders}"
