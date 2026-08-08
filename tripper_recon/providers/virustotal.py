"""VirusTotal v3 report lookups.

Both functions GET an *existing* report. Neither submits an indicator for analysis. The
submission endpoints on this same API -- and the analysis-object reads that are their
receipts -- are forbidden here and are named, with the reason for each, in
``tests/test_passivity.py``; that test scans this package for them on every run, so they are
deliberately not spelled out again in this docstring.

Roadmap 4.6 -- what changed here. Both endpoints already returned ``last_analysis_results``
and ``last_analysis_date`` in the response body and both were discarded on the IP path.
They are the two fields that turn a bare detection count into a finding:

* ``last_analysis_results`` names *which* engines flagged the indicator. Five no-name engines
  and five major vendors both render as ``5/94``, and they are not the same evidence.
* ``last_analysis_date`` says how old that verdict is. A 5/94 from last week and a 5/94 from
  2019 support very different claims, and the tool could not previously tell them apart.

Key naming is deliberately uniform across the two functions: the domain path already shipped
the full per-engine map as ``vt_security_results``, so the IP path adopts that name rather
than introducing a second name for the same thing. The compact ``vt_detecting_engines`` list
is derived for consumers that want the adverse engines only -- the full map runs to ~94
entries per indicator, which belongs in the JSON report and not on a console line.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, FrozenSet, List, Optional

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff

VT_BASE = "https://www.virustotal.com/api/v3"

#: The ``category`` values that count as an adverse engine verdict. VirusTotal also emits
#: ``harmless``, ``undetected``, ``timeout`` and ``type-unsupported``; none of those is a
#: detection and none belongs in the derived list.
ADVERSE_VT_CATEGORIES: FrozenSet[str] = frozenset({"malicious", "suspicious"})


def _as_dict(value: Any) -> Dict[str, Any]:
    """Return ``value`` when it is a dict, otherwise an empty dict.

    Every attribute read in this module goes through a guard like this one. These are
    third-party response bodies: a field can be absent, ``null``, or -- on an error shape --
    a list or a string where a dict was expected. None of those may raise.
    """
    return value if isinstance(value, dict) else {}


def _as_str(value: Any) -> Optional[str]:
    """Return ``value`` when it is a string, otherwise ``None``.

    Deliberately not ``str(value)``: coercing a dict or a list into text would manufacture a
    plausible-looking engine result out of a malformed response.
    """
    return value if isinstance(value, str) else None


def _epoch(value: Any) -> Optional[int]:
    """Coerce a VirusTotal Unix timestamp to an int, or ``None`` when it is not one.

    ``bool`` is rejected explicitly because ``True`` is an ``int`` to Python and 1970-01-01 is
    not a scan date. A missing timestamp stays ``None`` rather than becoming 0, which would
    render as an epoch-era scan and read as maximally stale.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return int(value)
    except (OverflowError, ValueError):  # float('nan') / float('inf')
        return None


def _epoch_to_iso(epoch: Optional[int]) -> Optional[str]:
    """Render an epoch as a UTC ISO-8601 string, or ``None`` if it cannot be rendered.

    VirusTotal is the only provider in the package that reports freshness as an epoch --
    AbuseIPDB and Shodan both send ISO-ish strings -- so the conversion happens here to give
    every consumer one comparable form. UTC is stated explicitly; a naive local-time rendering
    of a threat-intel timestamp is a defect in an evidence artefact.
    """
    if epoch is None:
        return None
    try:
        return datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        # An out-of-range timestamp (a provider bug, or a bad coercion upstream) is reported
        # as unknown rather than crashing the investigation.
        return None


def _detecting_engines(results: Any) -> List[Dict[str, Any]]:
    """Compact the per-engine map down to the engines that actually flagged the indicator.

    Ordering is deterministic -- malicious before suspicious, then engine name -- so two runs
    over the same report diff cleanly. Entries that are not dicts, or that carry no usable
    ``category``, are skipped rather than partially rendered.
    """
    engines: List[Dict[str, Any]] = []
    for name, verdict in _as_dict(results).items():
        if not isinstance(verdict, dict):
            continue
        category = _as_str(verdict.get("category"))
        if category is None or category.lower() not in ADVERSE_VT_CATEGORIES:
            continue
        engines.append(
            {
                "engine": str(name),
                "category": category.lower(),
                "result": _as_str(verdict.get("result")),
                "method": _as_str(verdict.get("method")),
            }
        )
    engines.sort(key=lambda entry: (entry["category"] != "malicious", str(entry["engine"]).lower()))
    return engines


async def vt_ip_summary(*, client: httpx.AsyncClient, api_key: Optional[str], ip: str) -> Dict[str, Any]:
    if not api_key:
        return {"ok": False, "error": "missing_api_key"}

    headers = {"x-apikey": api_key}

    async def _call() -> Dict[str, Any]:
        r = await client.get(f"{VT_BASE}/ip_addresses/{ip}", headers=headers)
        if r.status_code == 404:
            return {"ok": False, "error": "not_found"}
        r.raise_for_status()
        data = _as_dict(_as_dict(r.json()).get("data"))
        attr = _as_dict(data.get("attributes"))
        stats = attr.get("last_analysis_stats", {})
        reputation = attr.get("reputation")
        security = _as_dict(attr.get("last_analysis_results"))
        analysis_date = _epoch(attr.get("last_analysis_date"))
        return {
            "ok": True,
            "data": {
                "vt_last_analysis_stats": stats,
                "vt_reputation": reputation,
                "vt_security_results": security,
                "vt_detecting_engines": _detecting_engines(security),
                "vt_last_analysis_date": analysis_date,
                "vt_last_analysis_date_iso": _epoch_to_iso(analysis_date),
                "vt_link": f"https://www.virustotal.com/gui/ip-address/{ip}",
            },
        }

    return await with_exponential_backoff(_call)


async def vt_domain_summary(*, client: httpx.AsyncClient, api_key: Optional[str], domain: str) -> Dict[str, Any]:
    if not api_key:
        return {"ok": False, "error": "missing_api_key"}

    headers = {"x-apikey": api_key}

    async def _call() -> Dict[str, Any]:
        r = await client.get(f"{VT_BASE}/domains/{domain}", headers=headers)
        if r.status_code == 404:
            return {"ok": False, "error": "not_found"}
        r.raise_for_status()
        data = _as_dict(_as_dict(r.json()).get("data"))
        attr = _as_dict(data.get("attributes"))
        stats = attr.get("last_analysis_stats", {})
        reputation = attr.get("reputation")
        categories = attr.get("categories") or {}
        tags = attr.get("tags") or []
        dns_records = attr.get("last_dns_records") or []
        whois = attr.get("whois")
        whois_ts = attr.get("whois_timestamp")
        # Pre-existing key, pre-existing meaning: the full per-engine map. The IP path above
        # now emits the same field under the same name.
        security = attr.get("last_analysis_results") or {}
        analysis_date = _epoch(attr.get("last_analysis_date"))

        https_cert = attr.get("last_https_certificate") or {}
        https_validity = https_cert.get("validity") or {}
        https_subject = https_cert.get("subject") or {}
        https_issuer = https_cert.get("issuer") or {}
        https_thumbprint = (
            attr.get("last_https_certificate_fingerprint_sha256")
            or https_cert.get("thumbprint_sha256")
            or https_cert.get("fingerprint_sha256")
        )
        https_jarm = attr.get("last_https_certificate_jarm") or https_cert.get("jarm")

        return {
            "ok": True,
            "data": {
                "vt_last_analysis_stats": stats,
                "vt_reputation": reputation,
                "vt_categories": categories,
                "vt_tags": tags,
                "vt_dns_records": dns_records,
                "vt_security_results": security,
                "vt_detecting_engines": _detecting_engines(security),
                "vt_last_analysis_date": analysis_date,
                "vt_last_analysis_date_iso": _epoch_to_iso(analysis_date),
                "vt_whois": whois,
                "vt_whois_timestamp": whois_ts,
                "vt_last_https_certificate": {
                    "serial_number": https_cert.get("serial_number"),
                    "version": https_cert.get("version"),
                    "thumbprint_sha256": https_thumbprint,
                    "signature_algorithm": https_cert.get("signature_algorithm"),
                    "issuer": https_issuer,
                    "subject": https_subject,
                    "validity": {
                        "not_before": https_validity.get("not_before"),
                        "not_after": https_validity.get("not_after"),
                    },
                },
                "vt_last_https_certificate_jarm": https_jarm,
                "vt_link": f"https://www.virustotal.com/gui/domain/{domain}",
            },
        }

    return await with_exponential_backoff(_call)
