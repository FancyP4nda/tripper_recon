from __future__ import annotations

from typing import Any, Dict, List

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff


BGPVIEW_BASE = "https://api.bgpview.io"


async def _bgpview_get(client: httpx.AsyncClient, path: str) -> Dict[str, Any]:
    async def _call() -> Dict[str, Any]:
        r = await client.get(f"{BGPVIEW_BASE}{path}")
        if r.status_code == 404:
            return {"ok": False, "error": "not_found"}
        if r.status_code >= 400:
            return {"ok": False, "error": "http_error", "status": r.status_code}
        return {"ok": True, "data": r.json().get("data", {})}

    return await with_exponential_backoff(_call)


async def bgpview_asn(*, client: httpx.AsyncClient, asn: int) -> Dict[str, Any]:
    gen = await _bgpview_get(client, f"/asn/{asn}")
    if not gen.get("ok"):
        return gen

    d = gen.get("data", {})
    rir_alloc = d.get("rir_allocation") or {}

    # Try to fetch IXPs list from dedicated endpoint
    ixs: List[Dict[str, Any]] = []
    ixs_resp = await _bgpview_get(client, f"/asn/{asn}/ixs")
    if ixs_resp.get("ok"):
        data_obj = ixs_resp.get("data", {})
        if isinstance(data_obj, dict):
            raw_ixs = data_obj.get("ixs") or data_obj.get("ixps") or []
        elif isinstance(data_obj, list):
            raw_ixs = data_obj
        else:
            raw_ixs = []
        names: list[str] = []
        for x in raw_ixs:
            if isinstance(x, dict) and x.get("name"):
                names.append(str(x.get("name")))
            elif isinstance(x, str):
                names.append(x)
        ixs = [{"name": n} for n in sorted(set(names))]

    data = {
        "asn": asn,
        "name": d.get("name") or d.get("description_short"),
        "organization": d.get("description_short") or d.get("name") or d.get("description_full"),
        "rir": (rir_alloc.get("rir_name") or (rir_alloc.get("rir_code") if isinstance(rir_alloc, dict) else None)),
        "allocationDate": rir_alloc.get("date") or rir_alloc.get("allocation_date"),
        "ixps": ixs,
    }
    return {"ok": True, "data": data}

