"""AbuseIPDB ``/check`` lookup.

Roadmap 4.6 -- what changed here. The ``/check`` response already carried six fields the tool
read and threw away. The most important by a distance is ``lastReportedAt``: a 100% confidence
score from 2019 and a 100% score from yesterday are the same number and completely different
findings, and the tool previously could not tell an analyst which one it was holding.

The rest qualify the score in ways that change the conclusion:

* ``isWhitelisted`` -- AbuseIPDB's own signal that the address is known-good infrastructure.
* ``usageType`` -- "Data Center/Web Hosting" versus "Fixed Line ISP" changes what a report means.
* ``isTor`` -- an exit node attracts reports as a property of being an exit node.
* ``countryCode`` -- corroborates or contradicts the geolocation the other providers report.
* ``numDistinctUsers`` -- 200 reports from 1 reporter is not 200 independent observations.

Absence discipline: every new field is ``None`` when the provider did not report it. The two
booleans in particular must never default to ``False`` -- "AbuseIPDB says this is not
whitelisted" and "AbuseIPDB did not say" are different claims, and collapsing them is the same
class of defect as rendering an unqueried provider as a green zero. The two pre-existing count
fields keep their pre-existing ``0`` defaults; changing those would change a published meaning.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff

ABUSE_BASE = "https://api.abuseipdb.com/api/v2"


def _as_bool(value: Any) -> Optional[bool]:
    """Return ``value`` when it is a real bool, otherwise ``None``.

    Not ``bool(value)``: that maps ``None`` and ``""`` to ``False``, which asserts a negative
    the provider never made.
    """
    return value if isinstance(value, bool) else None


def _as_str(value: Any) -> Optional[str]:
    """Return a non-empty string, otherwise ``None``.

    AbuseIPDB sends ``null`` for an unknown ``usageType`` and, on some records, an empty
    string. Both mean "not reported" and both become ``None`` so a consumer has one case to
    handle instead of three.
    """
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _as_int(value: Any) -> Optional[int]:
    """Return an int count, otherwise ``None``. ``bool`` is rejected -- ``True`` is not a count."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


async def abuseipdb_check(*, client: httpx.AsyncClient, api_key: Optional[str], ip: str) -> Dict[str, Any]:
    if not api_key:
        return {"ok": False, "error": "missing_api_key"}

    headers = {"Key": api_key, "Accept": "application/json"}

    async def _call() -> Dict[str, Any]:
        r = await client.get(
            f"{ABUSE_BASE}/check",
            headers=headers,
            params={"ipAddress": ip, "maxAgeInDays": 365},
        )
        r.raise_for_status()
        body = r.json()
        data = body.get("data", {}) if isinstance(body, dict) else {}
        if not isinstance(data, dict):
            data = {}
        return {
            "ok": True,
            "data": {
                "abuseipdb_reports": data.get("totalReports", 0),
                "abuseipdb_confidence_score": data.get("abuseConfidenceScore", 0),
                # Freshness. Reported as the provider's own ISO-8601 string, unparsed: the
                # timestamp is evidence and reformatting it would put this module in the
                # business of guessing timezones on behalf of a report.
                "abuseipdb_last_reported_at": _as_str(data.get("lastReportedAt")),
                "abuseipdb_is_whitelisted": _as_bool(data.get("isWhitelisted")),
                "abuseipdb_usage_type": _as_str(data.get("usageType")),
                "abuseipdb_is_tor": _as_bool(data.get("isTor")),
                "abuseipdb_country_code": _as_str(data.get("countryCode")),
                "abuseipdb_num_distinct_users": _as_int(data.get("numDistinctUsers")),
            },
        }

    return await with_exponential_backoff(_call)
