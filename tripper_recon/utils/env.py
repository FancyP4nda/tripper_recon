from __future__ import annotations

import os
from pathlib import Path


def load_env() -> None:
    try:
        from dotenv import load_dotenv
    except Exception:
        # dotenv not installed; nothing to load
        return

    # Look for .env in CWD and project root
    candidates = [
        Path(os.getcwd()) / ".env",
        Path(__file__).resolve().parents[2] / ".env",
    ]
    for p in candidates:
        if p.is_file():
            load_dotenv(p, override=False)
            break
