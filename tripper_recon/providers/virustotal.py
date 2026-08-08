from __future__ import annotations

from typing import Any, Dict, Optional

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff

VT_BASE = "https://www.virustotal.com/api/v3"


async def vt_ip_summary(*, client: httpx.AsyncClient, api_key: Optional[str], ip: str) -> Dict[str, Any]:
    if not api_key:
        return {"ok": False, "error": "missing_api_key"}

    headers = {"x-apikey": api_key}

    async def _call() -> Dict[str, Any]:
        r = await client.get(f"{VT_BASE}/ip_addresses/{ip}", headers=headers)
        if r.status_code == 404:
            return {"ok": False, "error": "not_found"}
        r.raise_for_status()
        data = r.json().get("data", {})
        attr = data.get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        reputation = attr.get("reputation")
        return {
            "ok": True,
            "data": {
                "vt_last_analysis_stats": stats,
                "vt_reputation": reputation,
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
        data = r.json().get("data", {})
        attr = data.get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        reputation = attr.get("reputation")
        categories = attr.get("categories") or {}
        tags = attr.get("tags") or []
        dns_records = attr.get("last_dns_records") or []
        whois = attr.get("whois")
        whois_ts = attr.get("whois_timestamp")
        security = attr.get("last_analysis_results") or {}

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
