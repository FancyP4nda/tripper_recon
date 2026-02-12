from __future__ import annotations

from typing import Any, Dict, Optional

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff


ABUSE_BASE = "https://api.abuseipdb.com/api/v2"


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
        data = r.json().get("data", {})
        return {
            "ok": True,
            "data": {
                "abuseipdb_reports": data.get("totalReports", 0),
                "abuseipdb_confidence_score": data.get("abuseConfidenceScore", 0),
            },
        }

    return await with_exponential_backoff(_call)


