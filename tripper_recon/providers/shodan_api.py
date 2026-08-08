"""Shodan host lookup.

``GET /shodan/host/{ip}`` returns what Shodan already observed. It does not scan on demand,
and the on-demand scan endpoint (``POST /shodan/scan``) must never appear in this codebase.

Roadmap 4.6 -- what changed here. Three fields already present in that response were being
discarded:

* ``vulns`` -- the CVEs Shodan associates with the banners it collected. This is the single
  most actionable field the endpoint returns and the tool was dropping it entirely.
* ``hostnames`` -- Shodan's own reverse names for the address, which is passive PTR the tool
  otherwise has no source for (``utils.dns.reverse_ptr`` is dead code, roadmap 2.5).
* ``last_update`` -- when Shodan last saw the host. An open-port list with no date attached
  invites an analyst to read a two-year-old observation as current state.

``vulns`` is gathered from both places Shodan puts it: the top-level field and the per-service
entries under ``data[]``. The per-service form has been seen as both a list of CVE ids and a
dict keyed by CVE id, so both are accepted and the union is sorted for a deterministic diff.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional, Set

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff

SHODAN_BASE = "https://api.shodan.io"


def _str_items(value: Any) -> Iterable[str]:
    """Yield the non-empty strings in ``value``, accepting a list, a dict's keys, or a bare string.

    Shodan's ``vulns`` is the reason for the dict branch: it appears as ``["CVE-2021-1234"]``
    in some responses and as ``{"CVE-2021-1234": {...}}`` in others. Anything else yields
    nothing rather than raising.
    """
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            yield stripped
        return
    if isinstance(value, dict):
        value = list(value.keys())
    if not isinstance(value, list):
        return
    for item in value:
        if isinstance(item, str):
            stripped = item.strip()
            if stripped:
                yield stripped


def _as_str(value: Any) -> Optional[str]:
    """Return a non-empty string, otherwise ``None``."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


async def shodan_host(*, client: httpx.AsyncClient, api_key: Optional[str], ip: str) -> Dict[str, Any]:
    if not api_key:
        return {"ok": False, "error": "missing_api_key"}

    async def _call() -> Dict[str, Any]:
        r = await client.get(f"{SHODAN_BASE}/shodan/host/{ip}", params={"key": api_key})
        if r.status_code == 404:
            return {"ok": False, "error": "not_found"}
        r.raise_for_status()
        j = r.json()
        if not isinstance(j, dict):
            j = {}
        ports = j.get("ports", [])
        org = j.get("org") or j.get("isp")
        tags = j.get("tags", [])
        cpe: Set[str] = set()
        vulns: Set[str] = set(_str_items(j.get("vulns")))
        services = j.get("data", [])
        for item in services if isinstance(services, list) else []:
            if not isinstance(item, dict):
                continue
            cpe.update(_str_items(item.get("cpe")))
            vulns.update(_str_items(item.get("vulns")))
        return {
            "ok": True,
            "data": {
                "ports": ports,
                "org": org,
                "tags": tags,
                "cpe": sorted(cpe),
                "vulns": sorted(vulns),
                "hostnames": sorted(set(_str_items(j.get("hostnames")))),
                # Passed through as Shodan's own timestamp string. It is naive (no offset) and
                # documented as UTC; parsing it here would only add a way to be wrong about it.
                "last_update": _as_str(j.get("last_update")),
            },
        }

    return await with_exponential_backoff(_call)
