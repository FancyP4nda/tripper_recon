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


def logger(module: str) -> Any:
    min_level = int(os.getenv("TRIPPER_RECON_LOG_LEVEL", "20"))

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
        sys.stdout.write(json.dumps(record) + "\n")
        sys.stdout.flush()

    return {
        "debug": lambda msg, **c: _log(10, msg, **c),
        "info": lambda msg, **c: _log(20, msg, **c),
        "warn": lambda msg, **c: _log(30, msg, **c),
        "error": lambda msg, **c: _log(40, msg, **c),
    }


