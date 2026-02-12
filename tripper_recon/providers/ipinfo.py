from __future__ import annotations

from typing import Any, Dict, Optional

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff


IPINFO_BASE = "https://ipinfo.io"


async def ipinfo_ip(*, client: httpx.AsyncClient, token: Optional[str], ip: str) -> Dict[str, Any]:
    if not token:
        return {"ok": False, "error": "missing_token"}

    async def _call() -> Dict[str, Any]:
        r = await client.get(f"{IPINFO_BASE}/{ip}", params={"token": token})
        r.raise_for_status()
        j = r.json()
        loc = j.get("loc") or ","
        lat, lon = (None, None)
        if "," in loc:
            parts = loc.split(",")
            if len(parts) == 2:
                try:
                    lat = float(parts[0])
                    lon = float(parts[1])
                except Exception:
                    lat = lon = None
        org = j.get("org") or ""
        asn = None
        if org.startswith("AS"):
            try:
                asn = int(org.split()[0][2:])
            except Exception:
                asn = None
        return {
            "ok": True,
            "data": {
                "ip": j.get("ip"),
                "city": j.get("city"),
                "country": j.get("country"),
                "region": j.get("region"),
                "postal": j.get("postal"),
                "asn": asn,
                "org": j.get("org"),
                "coordinates": {"lat": lat, "lon": lon},
                "timezone": j.get("timezone"),
                "hostname": j.get("hostname"),
            },
        }

    return await with_exponential_backoff(_call)


async def ipinfo_asn(*, client: httpx.AsyncClient, token: Optional[str], asn: int) -> Dict[str, Any]:
    if not token:
        return {"ok": False, "error": "missing_token"}

    async def _call() -> Dict[str, Any]:
        r = await client.get(f"{IPINFO_BASE}/AS{asn}", params={"token": token})
        if r.status_code == 404:
            return {"ok": False, "error": "not_found"}
        if r.status_code in (401, 403):
            return {"ok": False, "error": "unauthorized", "status": r.status_code}
        if r.status_code >= 400:
            return {"ok": False, "error": "http_error", "status": r.status_code}
        j = r.json()
        # Common fields found in IPinfo ASN responses
        data = {
            "asn": asn,
            "name": j.get("name"),
            "country": j.get("country"),
            "rir": j.get("rir"),
            "allocationDate": j.get("allocated") or j.get("allocation"),
            "organization": (j.get("company") or {}).get("name") if isinstance(j.get("company"), dict) else j.get("org"),
        }
        return {"ok": True, "data": data}

    return await with_exponential_backoff(_call)

