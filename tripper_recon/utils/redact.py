"""Credential redaction for anything that can reach output.

Two providers authenticate in the query string (Shodan ``?key=``, IPInfo ``?token=``), so a
failing request URL contains the API key. httpx puts that URL into ``str(request.url)`` and
embeds it again in ``str(HTTPStatusError)``. Both strings are copied into the investigation
result, which reaches console output and ``-o json``.

Everything here is defence in depth: parameter-name redaction catches the known shapes, and
literal redaction catches a key that arrives by a route this module does not anticipate.
"""

from __future__ import annotations

import os
import re
from typing import Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "REDACTED"

# Query parameters whose value is a credential. Compared case-insensitively.
_SENSITIVE_PARAMS = frozenset(
    {
        "key",
        "apikey",
        "api_key",
        "token",
        "access_token",
        "auth",
        "auth_key",
        "secret",
        "password",
        "passwd",
        "pwd",
    }
)

# Environment variables holding a credential. Their values are redacted literally wherever
# they appear, regardless of how they got there.
_SECRET_ENV_VARS = (
    "CLOUDFLARE_API_TOKEN",
    "VT_API_KEY",
    "SHODAN_API_KEY",
    "ABUSEIPDB_API_KEY",
    "IPINFO_TOKEN",
    "OTX_API_KEY",
)

# Shortest value treated as a secret. Guards against a blank or placeholder env var causing
# runaway substitution across unrelated output.
_MIN_SECRET_LEN = 8

_URL_RE = re.compile(r"https?://[^\s'\"<>|]+", re.IGNORECASE)


def _known_secrets() -> list[str]:
    """Credential values present in the environment, longest first.

    Longest first matters: if one key is a substring of another, redacting the shorter one
    first would leave the remainder of the longer one exposed.
    """
    values = []
    for name in _SECRET_ENV_VARS:
        value = (os.getenv(name) or "").strip()
        if len(value) >= _MIN_SECRET_LEN:
            values.append(value)
    return sorted(set(values), key=len, reverse=True)


def redact_url(url: str) -> str:
    """Replace credential-bearing query parameter values in a URL.

    Returns the input unchanged if it cannot be parsed — never raises, because this runs on
    the error path where a second exception would mask the original failure.
    """
    if not url:
        return url
    try:
        parts = urlsplit(url)
        if not parts.query:
            return _redact_literals(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        cleaned = [
            (name, REDACTED if name.lower() in _SENSITIVE_PARAMS else value)
            for name, value in pairs
        ]
        rebuilt = urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urlencode(cleaned), parts.fragment)
        )
        return _redact_literals(rebuilt)
    except Exception:  # noqa: BLE001 - redaction must never raise on the error path
        return _redact_literals(url)


def _redact_literals(text: str, secrets: Iterable[str] | None = None) -> str:
    for secret in _known_secrets() if secrets is None else secrets:
        if secret and secret in text:
            text = text.replace(secret, REDACTED)
    return text


def redact_text(text: str) -> str:
    """Redact credentials from free text such as an exception message.

    Handles both URLs embedded in the text and bare credential values.
    """
    if not text:
        return text
    try:
        secrets = _known_secrets()
        cleaned = _URL_RE.sub(lambda m: redact_url(m.group(0)), text)
        return _redact_literals(cleaned, secrets)
    except Exception:  # noqa: BLE001 - redaction must never raise on the error path
        return text
