from __future__ import annotations

from typing import Any, Dict, Optional

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff


CF_BASE = "https://api.cloudflare.com/client/v4/radar"


async def bgp_incidents(*, client: httpx.AsyncClient, api_token: Optional[str], asn: int) -> Dict[str, Any]:
    if not api_token:
        return {"ok": False, "error": "missing_api_token"}
    headers = {"Authorization": f"Bearer {api_token}"}

    async def _call() -> Dict[str, Any]:
        r1 = await client.get(f"{CF_BASE}/bgp/hijacks/events", params={"dateRange": "52w", "involvedAsn": asn}, headers=headers)
        r2 = await client.get(f"{CF_BASE}/bgp/leaks/events", params={"dateRange": "52w", "involvedAsn": asn}, headers=headers)
        if r1.status_code >= 400 and r2.status_code >= 400:
            return {"ok": False, "error": "http_error"}
        out: Dict[str, Any] = {}
        if r1.status_code < 400:
            j1 = r1.json()
            total = j1.get("result_info", {}).get("total_count")
            events = j1.get("result", {}).get("events", [])
            as_hijacker = len([e for e in events if e.get("hijacker_asn") == asn])
            out["hijacks"] = {"total": total, "as_hijacker": as_hijacker, "as_victim": (total - as_hijacker) if isinstance(total, int) else None}
        if r2.status_code < 400:
            j2 = r2.json()
            total = j2.get("result_info", {}).get("total_count")
            out["leaks"] = {"total": total}
        return {"ok": True, "data": out}

    return await with_exponential_backoff(_call)


