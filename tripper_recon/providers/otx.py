from __future__ import annotations

from typing import Any, Dict, Optional

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff

OTX_BASE = "https://otx.alienvault.com/api/v1"


async def otx_ip_pulses(*, client: httpx.AsyncClient, api_key: Optional[str], ip: str) -> Dict[str, Any]:
    if not api_key:
        return {"ok": False, "error": "API key not configured"}

    headers = {"Accept": "application/json", "X-OTX-API-KEY": api_key}

    async def _call() -> Dict[str, Any]:
        r = await client.get(f"{OTX_BASE}/indicators/IPv4/{ip}/general", headers=headers, timeout=20.0)
        if r.status_code == 404:
            return {"ok": False, "error": "not_found"}
        r.raise_for_status()
        j = r.json()
        pulses = j.get("pulse_info", {}).get("pulses", [])
        return {
            "ok": True,
            "data": {
                "otx_pulse_count": len(pulses),
                "otx_pulse_titles": [p.get("name") for p in pulses[:5]],
            },
        }

    return await with_exponential_backoff(_call)


async def otx_domain_pulses(*, client: httpx.AsyncClient, api_key: Optional[str], domain: str) -> Dict[str, Any]:
    if not api_key:
        return {"ok": False, "error": "API key not configured"}

    headers = {"Accept": "application/json", "X-OTX-API-KEY": api_key}

    async def _call() -> Dict[str, Any]:
        r = await client.get(f"{OTX_BASE}/indicators/domain/{domain}/general", headers=headers, timeout=20.0)
        if r.status_code == 404:
            return {"ok": False, "error": "not_found"}
        r.raise_for_status()
        j = r.json()
        pulse_info = j.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        malware = j.get("malware", [])
        domains = j.get("passive_dns", [])
        return {
            "ok": True,
            "data": {
                "otx_pulse_count": len(pulses),
                "otx_pulse_titles": [p.get("name") for p in pulses[:5]],
                "otx_tags": pulse_info.get("tags"),
                "otx_malware_count": len(malware) if isinstance(malware, list) else None,
                "otx_passive_dns_count": len(domains) if isinstance(domains, list) else None,
            },
        }

    return await with_exponential_backoff(_call)
