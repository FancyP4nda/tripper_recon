"""Unit tests for tripper_recon.utils.logging (W0.5 regression net).

Two things are locked in here:

* `_min_level()` accepts BOTH a number and a level name. Pre-fix it was `int(raw)` with no
  fallback, so `TRIPPER_RECON_LOG_LEVEL=INFO` -- the form the README documented -- raised
  ValueError at logger construction and took the whole tool down over a logging preference.
* Records go to **stderr, never stdout**. Pre-fix they went to stdout, where they interleaved
  with `-o json` output and broke any downstream parser (the reason `-o json` exists at all).

`test_min_level_*` and `test_record_goes_to_stderr_not_stdout` are the two that fail against the
pre-fix code.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from tripper_recon.utils.logging import _min_level, _parse_context, logger

_ENV = "TRIPPER_RECON_LOG_LEVEL"


# --------------------------------------------------------------------------------------
# _min_level
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("10", 10),
        ("20", 20),
        ("30", 30),
        ("40", 40),
        ("DEBUG", 10),
        ("INFO", 20),
        ("info", 20),  # case-insensitive via .upper()
        ("Info", 20),
        ("WARN", 30),
        ("warn", 30),
        ("WARNING", 30),
        ("ERROR", 40),
        ("error", 40),
        ("  INFO  ", 20),  # stripped
        ("  30  ", 30),
    ],
)
def test_min_level_accepts_numeric_and_named_levels(monkeypatch: pytest.MonkeyPatch, raw: str, expected: int) -> None:
    """Pre-fix, every named value in this table raised `ValueError: invalid literal for int()`."""
    monkeypatch.setenv(_ENV, raw)
    assert _min_level() == expected


@pytest.mark.parametrize("raw", ["", "   ", "nonsense", "INFORMATIONAL", "20.5", "TRACE", "!!"])
def test_min_level_falls_back_to_info_on_garbage(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    """A malformed logging preference must never be fatal."""
    monkeypatch.setenv(_ENV, raw)
    assert _min_level() == 20


def test_min_level_defaults_to_info_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_ENV, raising=False)
    assert _min_level() == 20


def test_min_level_does_not_raise_for_any_input(monkeypatch: pytest.MonkeyPatch) -> None:
    for raw in ["INFO", "", "nope", "-5", "999999", "0x14", "\n\t"]:
        monkeypatch.setenv(_ENV, raw)
        assert isinstance(_min_level(), int)


# --------------------------------------------------------------------------------------
# record destination and shape
# --------------------------------------------------------------------------------------


def _emit(level: str, message: str, **ctx: Any) -> None:
    log = logger("test.module")
    log[level](message, **ctx)


def test_record_goes_to_stderr_not_stdout(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """The W0.5 fix. Pre-fix this wrote to stdout and corrupted `-o json` output."""
    monkeypatch.setenv(_ENV, "10")
    _emit("info", "hello")

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "hello" in captured.err


def test_record_is_one_json_object_per_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(_ENV, "10")
    log = logger("test.module")
    log["info"]("first")
    log["warn"]("second")

    lines = [ln for ln in capsys.readouterr().err.splitlines() if ln.strip()]
    assert len(lines) == 2
    for line in lines:
        json.loads(line)  # raises if the line is not standalone valid JSON


def test_record_has_ts_level_module_message(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(_ENV, "10")
    _emit("warn", "provider failed")

    record = json.loads(capsys.readouterr().err.strip())
    assert set(record) >= {"ts", "level", "module", "message"}
    assert isinstance(record["ts"], int)
    assert record["ts"] > 1_700_000_000_000  # epoch MILLIseconds, not seconds
    assert record["level"] == "WARN"
    assert record["module"] == "test.module"
    assert record["message"] == "provider failed"


@pytest.mark.parametrize(
    ("method", "expected_level"),
    [("debug", "DEBUG"), ("info", "INFO"), ("warn", "WARN"), ("error", "ERROR")],
)
def test_every_method_emits_its_own_level_name(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    method: str,
    expected_level: str,
) -> None:
    monkeypatch.setenv(_ENV, "10")
    log = logger("m")
    log[method]("x")
    assert json.loads(capsys.readouterr().err.strip())["level"] == expected_level


# --------------------------------------------------------------------------------------
# level filtering
# --------------------------------------------------------------------------------------


def test_level_filtering_suppresses_below_the_threshold(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(_ENV, "30")
    log = logger("m")
    log["debug"]("d")
    log["info"]("i")
    log["warn"]("w")
    log["error"]("e")

    captured = capsys.readouterr()
    assert captured.out == ""
    messages = [json.loads(ln)["message"] for ln in captured.err.splitlines() if ln.strip()]
    assert messages == ["w", "e"]


def test_level_filtering_works_with_a_named_threshold(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The named form must filter identically to the numeric form -- pre-fix it could not be
    used at all."""
    monkeypatch.setenv(_ENV, "ERROR")
    log = logger("m")
    log["warn"]("w")
    log["error"]("e")

    messages = [json.loads(ln)["message"] for ln in capsys.readouterr().err.splitlines() if ln.strip()]
    assert messages == ["e"]


def test_threshold_is_resolved_once_at_logger_construction(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Documents current behaviour: `_min_level()` is read in `logger()`, not per record, so a
    later env change does not affect an already-constructed logger."""
    monkeypatch.setenv(_ENV, "40")
    log = logger("m")
    monkeypatch.setenv(_ENV, "10")
    log["info"]("still suppressed")

    assert capsys.readouterr().err == ""


def test_context_keys_can_shadow_reserved_record_fields(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Documents a defect, not the desired behaviour.

    `record = {"ts": ..., "level": ..., "module": ..., "message": ..., **_parse_context(**ctx)}`
    puts context LAST, so a context key named `ts` or `module` silently overwrites the real value.
    (`message` and `level` happen to be shielded by `_log`'s positional signature and raise
    TypeError instead, which is its own inconsistency.) This matters once log correlation depends
    on these fields -- roadmap 7.5's `run_id`/`case_id` work is the first consumer that would be
    misled. Fix: namespace the context, or emit it under a single `ctx` key.
    """
    monkeypatch.setenv(_ENV, "10")
    logger("real.module")["error"]("boom", module="attacker.controlled", ts=0)

    record = json.loads(capsys.readouterr().err.strip())
    assert record["module"] == "attacker.controlled"  # should be "real.module"
    assert record["ts"] == 0  # should be the real timestamp


def test_reserved_positional_names_in_context_raise_typeerror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other half of the same inconsistency: `message=` and `level=` collide with `_log`'s
    positional parameters, so a logging call built from provider-supplied keys can crash the
    caller rather than mislabel a record."""
    monkeypatch.setenv(_ENV, "10")
    log = logger("m")
    with pytest.raises(TypeError):
        log["info"]("real", message="spoofed")
    with pytest.raises(TypeError):
        log["info"]("real", level="DEBUG")


# --------------------------------------------------------------------------------------
# _parse_context
# --------------------------------------------------------------------------------------


class _NotSerialisable:
    def __repr__(self) -> str:
        return "<NotSerialisable object>"


def test_parse_context_stringifies_non_json_serialisable_values() -> None:
    """A logging call must never be the thing that raises. `json.dumps(object())` raises
    TypeError, so the value is coerced with `str()` instead."""
    out = _parse_context(obj=_NotSerialisable(), err=ValueError("boom"), fine={"a": 1})

    assert out["obj"] == "<NotSerialisable object>"
    assert out["err"] == "boom"
    assert out["fine"] == {"a": 1}  # serialisable values pass through untouched
    json.dumps(out)  # the whole dict is now safe to serialise


def test_parse_context_preserves_json_native_types() -> None:
    out = _parse_context(s="x", i=1, f=1.5, b=True, n=None, lst=[1, 2], d={"k": "v"})
    assert out == {"s": "x", "i": 1, "f": 1.5, "b": True, "n": None, "lst": [1, 2], "d": {"k": "v"}}


def test_logging_a_non_serialisable_context_value_does_not_raise(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(_ENV, "10")
    log = logger("m")
    log["error"]("provider failed", exc=_NotSerialisable(), status=502)

    record = json.loads(capsys.readouterr().err.strip())
    assert record["exc"] == "<NotSerialisable object>"
    assert record["status"] == 502


def test_parse_context_handles_a_value_whose_str_is_itself_expensive_but_valid() -> None:
    """Circular structures are the realistic case: `json.dumps` raises ValueError (not TypeError)
    on them, and the bare `except Exception` has to catch that too."""
    circular: dict[str, Any] = {}
    circular["self"] = circular

    out = _parse_context(c=circular)
    assert isinstance(out["c"], str)
    json.dumps(out)
