"""AlienVault OTX indicator lookups.

Roadmap 4.6 -- what changed here. ``otx_pulse_count`` on its own is a weak signal that reads
as a strong one. Fifty pulses cloned from a single author on a single day is one observation
wearing a large number, and the tool rendered it identically to fifty pulses from fifty authors
spanning two years. The ``general`` response already carried the fields that tell those apart:
per-pulse author, ``created`` and ``modified``.

``otx_pulses`` now carries one compact record per pulse -- name, author, created, modified --
so W5 can quality-adjust the count by author diversity and recency. It is deliberately NOT
truncated at five: a diversity measure computed over the first five pulses is not a diversity
measure. The existing ``otx_pulse_count`` and the five-entry ``otx_pulse_titles`` cap are
unchanged; the console and its tests depend on both.

Author extraction is defensive about shape. OTX has emitted the author as a flat
``author_name`` string and as a nested ``author`` object across versions of this endpoint, and
a pulse with neither reports ``None`` rather than guessing.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff

OTX_BASE = "https://otx.alienvault.com/api/v1"


def _as_str(value: Any) -> Optional[str]:
    """Return a non-empty string, otherwise ``None``."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _pulse_author(pulse: Dict[str, Any]) -> Optional[str]:
    """Pull an author name out of a pulse, whichever shape this endpoint used.

    Order is most-specific first: the flat ``author_name`` string, then ``author.username``,
    then ``author.name``. A pulse whose author is a bare string is accepted as-is. Anything
    else is ``None`` -- an unattributed pulse must not silently count as its own author, which
    is exactly the error a diversity weighting would then make.
    """
    flat = _as_str(pulse.get("author_name"))
    if flat is not None:
        return flat
    author = pulse.get("author")
    if isinstance(author, str):
        return _as_str(author)
    if isinstance(author, dict):
        return _as_str(author.get("username")) or _as_str(author.get("name"))
    return None


def _pulse_records(pulses: Any) -> List[Dict[str, Any]]:
    """One compact record per pulse: name, author, created, modified.

    Timestamps are passed through as the provider's own ISO-8601 strings, unparsed, for the
    same reason as AbuseIPDB's ``lastReportedAt`` -- they are evidence, not display values.
    Entries that are not dicts are skipped; they cannot describe a pulse.
    """
    if not isinstance(pulses, list):
        return []
    records: List[Dict[str, Any]] = []
    for pulse in pulses:
        if not isinstance(pulse, dict):
            continue
        records.append(
            {
                "name": _as_str(pulse.get("name")),
                "author": _pulse_author(pulse),
                "created": _as_str(pulse.get("created")),
                "modified": _as_str(pulse.get("modified")),
            }
        )
    return records


def _pulses(payload: Any) -> List[Any]:
    """The ``pulse_info.pulses`` list, or an empty list when the response has no usable one."""
    pulses = payload.get("pulses") if isinstance(payload, dict) else None
    return pulses if isinstance(pulses, list) else []


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
        pulse_info = j.get("pulse_info", {}) if isinstance(j, dict) else {}
        pulses = _pulses(pulse_info)
        return {
            "ok": True,
            "data": {
                "otx_pulse_count": len(pulses),
                "otx_pulse_titles": [p.get("name") if isinstance(p, dict) else None for p in pulses[:5]],
                "otx_pulses": _pulse_records(pulses),
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
        if not isinstance(j, dict):
            j = {}
        pulse_info = j.get("pulse_info", {})
        pulses = _pulses(pulse_info)
        malware = j.get("malware", [])
        domains = j.get("passive_dns", [])
        return {
            "ok": True,
            "data": {
                "otx_pulse_count": len(pulses),
                "otx_pulse_titles": [p.get("name") if isinstance(p, dict) else None for p in pulses[:5]],
                "otx_pulses": _pulse_records(pulses),
                "otx_tags": pulse_info.get("tags") if isinstance(pulse_info, dict) else None,
                "otx_malware_count": len(malware) if isinstance(malware, list) else None,
                "otx_passive_dns_count": len(domains) if isinstance(domains, list) else None,
            },
        }

    return await with_exponential_backoff(_call)
