from __future__ import annotations

from typing import Any, Dict

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff


CAIDA_BASE = "https://api.asrank.caida.org/dev/restful/asns"


async def caida_asrank(*, client: httpx.AsyncClient, asn: int) -> Dict[str, Any]:
    async def _call() -> Dict[str, Any]:
        r = await client.get(f"{CAIDA_BASE}/{asn}")
        if r.status_code == 404:
            return {"ok": False, "error": "not_found"}
        if r.status_code >= 400:
            return {"ok": False, "error": "http_error", "status": r.status_code}
        data = r.json().get("data", {}).get("asn", {})
        rank = data.get("rank")
        deg = data.get("asnDegree", {})
        cone = data.get("cone", {})
        out = {
            "caidaRank": rank,
            "degree_total": deg.get("total"),
            "degree_customer": deg.get("customer"),
            "degree_peer": deg.get("peer"),
            "degree_provider": deg.get("provider"),
            "customer_cone_asns": cone.get("numberAsns"),
            # Some CAIDA responses also include a RIR-like source under 'source'
            "rir": data.get("source"),
        }
        return {"ok": True, "data": out}

    return await with_exponential_backoff(_call)


