from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, Dict


def _now_ms() -> int:
    return int(time.time() * 1000)


def _level_name(level: int) -> str:
    return {10: "DEBUG", 20: "INFO", 30: "WARN", 40: "ERROR"}.get(level, str(level))


def _parse_context(**ctx: Any) -> Dict[str, Any]:
    safe: Dict[str, Any] = {}
    for k, v in ctx.items():
        try:
            json.dumps(v)
            safe[k] = v
        except Exception:
            safe[k] = str(v)
    return safe


_LEVEL_ALIASES = {"DEBUG": 10, "INFO": 20, "WARN": 30, "WARNING": 30, "ERROR": 40}


def _min_level() -> int:
    """Resolve the configured level, accepting either a number or a name.

    The value used to be numeric only, so `TRIPPER_RECON_LOG_LEVEL=INFO` -- the form the README
    documented -- raised ValueError at import and took the whole tool down. Accept both forms
    and fall back to INFO rather than crashing over a logging preference.
    """
    raw = (os.getenv("TRIPPER_RECON_LOG_LEVEL") or "20").strip()
    try:
        return int(raw)
    except ValueError:
        return _LEVEL_ALIASES.get(raw.upper(), 20)


def logger(module: str) -> Any:
    min_level = _min_level()

    def _log(level: int, message: str, **ctx: Any) -> None:
        if level < min_level:
            return
        record = {
            "ts": _now_ms(),
            "level": _level_name(level),
            "module": module,
            "message": message,
            **_parse_context(**ctx),
        }
        # stderr, not stdout: structured logs on stdout interleave with `-o json` output and
        # break any downstream parser.
        sys.stderr.write(json.dumps(record) + "\n")
        sys.stderr.flush()

    return {
        "debug": lambda msg, **c: _log(10, msg, **c),
        "info": lambda msg, **c: _log(20, msg, **c),
        "warn": lambda msg, **c: _log(30, msg, **c),
        "error": lambda msg, **c: _log(40, msg, **c),
    }
