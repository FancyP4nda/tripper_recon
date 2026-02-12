from __future__ import annotations

from typing import Any, Dict, List

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff


PDB_BASE = "https://www.peeringdb.com/api"


async def peeringdb_ixps_for_asn(*, client: httpx.AsyncClient, asn: int) -> Dict[str, Any]:
    async def _call() -> Dict[str, Any]:
        # Get net entry id(s) for the ASN
        r = await client.get(f"{PDB_BASE}/net", params={"asn__in": asn})
        if r.status_code >= 400:
            return {"ok": False, "error": "http_error", "status": r.status_code}
        nets = r.json().get("data", [])
        if not nets:
            return {"ok": True, "data": {"ixps": []}}
        ix_names: List[str] = []
        for net in nets:
            net_id = net.get("id")
            if not net_id:
                continue
            r2 = await client.get(f"{PDB_BASE}/net/{net_id}")
            if r2.status_code >= 400:
                continue
            net_data = r2.json().get("data", [])
            if not net_data:
                continue
            netixlan = net_data[0].get("netixlan_set", [])
            for entry in netixlan:
                name = entry.get("name")
                if name:
                    ix_names.append(name)
        ixps = [{"name": n} for n in sorted(set(ix_names))]
        return {"ok": True, "data": {"ixps": ixps}}

    return await with_exponential_backoff(_call)


