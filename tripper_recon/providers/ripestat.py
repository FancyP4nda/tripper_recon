from __future__ import annotations

from typing import Any, Dict, Optional

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff


RIPE_BASE = "https://stat.ripe.net/data"


async def _get(client: httpx.AsyncClient, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    async def _call() -> Dict[str, Any]:
        r = await client.get(f"{RIPE_BASE}{path}", params=params)
        if r.status_code == 404:
            return {"ok": False, "error": "not_found"}
        if r.status_code >= 400:
            return {"ok": False, "error": "http_error", "status": r.status_code}
        return {"ok": True, "data": r.json().get("data", {})}

    return await with_exponential_backoff(_call)


async def as_overview(*, client: httpx.AsyncClient, asn: int) -> Dict[str, Any]:
    return await _get(client, "/as-overview/data.json", {"resource": f"AS{asn}", "sourceapp": "tripper-recon"})


async def abuse_contact(*, client: httpx.AsyncClient, asn: int) -> Dict[str, Any]:
    return await _get(client, "/abuse-contact-finder/data.json", {"resource": f"AS{asn}", "sourceapp": "tripper-recon"})


async def routing_status(*, client: httpx.AsyncClient, asn: int) -> Dict[str, Any]:
    return await _get(client, "/routing-status/data.json", {"resource": f"AS{asn}", "sourceapp": "tripper-recon"})


async def asn_neighbours(*, client: httpx.AsyncClient, asn: int) -> Dict[str, Any]:
    return await _get(client, "/asn-neighbours/data.json", {"resource": f"AS{asn}", "sourceapp": "tripper-recon"})


async def announced_prefixes(*, client: httpx.AsyncClient, asn: int) -> Dict[str, Any]:
    return await _get(client, "/announced-prefixes/data.json", {"resource": f"AS{asn}", "sourceapp": "tripper-recon"})


