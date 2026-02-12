from __future__ import annotations

from typing import Any, Dict, Optional

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff


SHODAN_BASE = "https://api.shodan.io"


async def shodan_host(*, client: httpx.AsyncClient, api_key: Optional[str], ip: str) -> Dict[str, Any]:
    if not api_key:
        return {"ok": False, "error": "missing_api_key"}

    async def _call() -> Dict[str, Any]:
        r = await client.get(f"{SHODAN_BASE}/shodan/host/{ip}", params={"key": api_key})
        if r.status_code == 404:
            return {"ok": False, "error": "not_found"}
        r.raise_for_status()
        j = r.json()
        ports = j.get("ports", [])
        org = j.get("org") or j.get("isp")
        tags = j.get("tags", [])
        cpe = []
        for item in j.get("data", []):
            cpe += item.get("cpe", []) or []
        return {"ok": True, "data": {"ports": ports, "org": org, "tags": tags, "cpe": sorted(set(cpe))}}

    return await with_exponential_backoff(_call)


