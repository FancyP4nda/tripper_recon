from __future__ import annotations

import asyncio
import os
from typing import Any, Dict, List
from ipaddress import ip_address

import httpx

from tripper_recon.providers.abuseipdb import abuseipdb_check
from tripper_recon.providers.cloudflare_radar import fetch_asn_metadata
from tripper_recon.providers.ipapi_is import ipapi_is_ip, ipapi_is_asn
from tripper_recon.providers.otx import otx_domain_pulses, otx_ip_pulses
from tripper_recon.providers.shodan_api import shodan_host
from tripper_recon.providers.virustotal import vt_domain_summary, vt_ip_summary
from tripper_recon.types.models import ApiKeys, InvestigationResult
from tripper_recon.utils.http import RateLimiter, create_client
from tripper_recon.utils.logging import logger
from tripper_recon.utils.validation import dedupe_preserve_order, is_valid_asn, is_valid_domain, is_valid_ip
from tripper_recon.providers.ripestat import as_overview, abuse_contact, routing_status, asn_neighbours, announced_prefixes
from tripper_recon.providers.caida import caida_asrank
from tripper_recon.providers.peeringdb import peeringdb_ixps_for_asn
from tripper_recon.providers.cloudflare_rest import bgp_incidents


log = logger("orchestrators")


def _error_payload(err: Exception) -> Dict[str, Any]:
    if isinstance(err, httpx.HTTPStatusError):
        resp = err.response
        req = getattr(resp, "request", None)
        return {
            "ok": False,
            "error": "http_error",
            "status_code": resp.status_code if resp else None,
            "reason": resp.reason_phrase if resp else None,
            "url": str(req.url) if req else None,
            "message": str(err),
        }
    if isinstance(err, httpx.RequestError):
        req = getattr(err, "request", None)
        return {
            "ok": False,
            "error": "network_error",
            "url": str(req.url) if req else None,
            "message": str(err),
        }
    return {"ok": False, "error": type(err).__name__, "message": str(err)}


def _error_details(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in payload.items() if k != "ok" and v is not None}


def _error_summary(provider: str, payload: Dict[str, Any]) -> str:
    details = _error_details(payload)
    parts: List[str] = [provider]
    status = details.get("status_code")
    if status is None:
        status = details.get("status")
    if status is not None:
        parts.append(str(status))
    reason = details.get("reason")
    if reason:
        parts.append(str(reason))
    message = details.get("message")
    if message and str(message) not in parts:
        parts.append(str(message))
    return " | ".join(parts)


def _env_first(*names: str) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return None


def _should_suppress(provider: str, payload: Dict[str, Any]) -> bool:
    if not payload or payload.get("ok"):
        return False
    err = payload.get("error")
    status = payload.get("status") or payload.get("status_code")
    if err in {"missing_api_key", "missing_api_token", "missing_token", "API key not configured"}:
        return True
    if provider == "ipapi_asn" and err in {"unauthorized", "http_error"} and status in {401, 403}:
        return True
    if provider.startswith("cloudflare"):
        if err in {"missing_api_token"}:
            return True
        if err == "http_error" and status == 400:
            return True
    return False


def _env_keys() -> ApiKeys:
    return ApiKeys(
        cloudflare_api_token=os.getenv("CLOUDFLARE_API_TOKEN"),
        vt_api_key=os.getenv("VT_API_KEY"),
        shodan_api_key=os.getenv("SHODAN_API_KEY"),
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY"),
        ipapi_is_api_key=_env_first(
            "IPAPI.IS_API_KEY",
            "IPAPI_IS_API_KEY",
            "IPAPI_API_KEY",
            "IPAPI_IS_KEY",
            "IPAPI_KEY",
            "IPAPI_IS_TOKEN",
            "IPAPI_TOKEN",
        ),
        otx_api_key=os.getenv("OTX_API_KEY"),
    )


async def investigate_ip(ip: str) -> InvestigationResult:
    if not is_valid_ip(ip):
        return InvestigationResult(ok=False, errors=["Invalid IP address"], data={})

    try:
        ip_obj = ip_address(ip)
        if ip_obj.is_private:
            return InvestigationResult(ok=False, errors=[f"Private IP address {ip} cannot be investigated."], data={})
    except ValueError:
        # This should be caught by is_valid_ip, but as a fallback.
        return InvestigationResult(ok=False, errors=[f"Invalid IP address format: {ip}"], data={})

    keys = _env_keys()
    async with create_client() as client:
        limiter = RateLimiter(rate=5)
        vt_task = ipapi_task = sh_task = ab_task = otx_task = None

        async with limiter:
            vt_task = asyncio.create_task(vt_ip_summary(client=client, api_key=keys.vt_api_key, ip=ip))
        async with limiter:
            ipapi_task = asyncio.create_task(ipapi_is_ip(client=client, api_key=keys.ipapi_is_api_key, ip=ip))
        async with limiter:
            sh_task = asyncio.create_task(shodan_host(client=client, api_key=keys.shodan_api_key, ip=ip))
        async with limiter:
            ab_task = asyncio.create_task(abuseipdb_check(client=client, api_key=keys.abuseipdb_api_key, ip=ip))
        async with limiter:
            otx_task = asyncio.create_task(otx_ip_pulses(client=client, api_key=keys.otx_api_key, ip=ip))

        # Ensure provider failures don't crash the whole investigation
        try:
            vt = await vt_task  # type: ignore[assignment]
        except Exception as e:  # noqa: BLE001
            vt = _error_payload(e)
        try:
            ipapi = await ipapi_task  # type: ignore[assignment]
        except Exception as e:  # noqa: BLE001
            ipapi = _error_payload(e)
        try:
            sh = await sh_task  # type: ignore[assignment]
        except Exception as e:  # noqa: BLE001
            sh = _error_payload(e)
        try:
            ab = await ab_task  # type: ignore[assignment]
        except Exception as e:  # noqa: BLE001
            ab = _error_payload(e)
        try:
            otx = await otx_task  # type: ignore[assignment]
        except Exception as e:  # noqa: BLE001
            otx = _error_payload(e)

        asn_meta: Dict[str, Any] = {}
        if ipapi.get("ok") and ipapi["data"].get("asn"):
            asn = int(ipapi["data"]["asn"])  # type: ignore[arg-type]
            cf = await fetch_asn_metadata(client=client, api_token=keys.cloudflare_api_token, asn=asn)
            if cf.get("ok"):
                asn_meta = cf["data"]

        providers = {
            "virustotal": vt,
            "ipapi": ipapi,
            "shodan": sh,
            "abuseipdb": ab,
            "otx": otx,
        }
        provider_errors: Dict[str, Dict[str, Any]] = {}
        result_errors: List[str] = []
        for name, payload in providers.items():
            if not payload or payload.get("ok"):
                continue
            if _should_suppress(name, payload):
                continue
            details = _error_details(payload)
            if details:
                provider_errors[name] = details
            result_errors.append(_error_summary(name, payload))

        data: Dict[str, Any] = {
            "ipapi": ipapi.get("data", {}) if ipapi.get("ok") else {},
            "virustotal": vt.get("data", {}) if vt.get("ok") else {},
            "shodan": sh.get("data", {}) if sh.get("ok") else {},
            "abuseipdb": ab.get("data", {}) if ab.get("ok") else {},
            "otx": otx.get("data", {}) if otx.get("ok") else {},
            "asn_meta": asn_meta,
        }
        if provider_errors:
            data["errors"] = provider_errors

        return InvestigationResult(ok=True, data=data, errors=result_errors)


async def investigate_domain(domain: str) -> InvestigationResult:
    if not is_valid_domain(domain):
        return InvestigationResult(ok=False, errors=["Invalid domain"], data={})
    ips: List[str] = []
    keys = _env_keys()
    result_errors: List[str] = []
    domain_error_msgs: List[str] = []
    domain_intel: Dict[str, Any] = {}
    domain_errors: Dict[str, Dict[str, Any]] = {}
    out: List[Dict[str, Any]] = []
    async with create_client() as client:
        vt_domain_task = asyncio.create_task(vt_domain_summary(client=client, api_key=keys.vt_api_key, domain=domain)) if keys.vt_api_key else None
        otx_domain_task = asyncio.create_task(otx_domain_pulses(client=client, api_key=keys.otx_api_key, domain=domain)) if keys.otx_api_key else None

        vt_domain = None
        if vt_domain_task:
            try:
                vt_domain = await vt_domain_task
            except Exception as e:  # noqa: BLE001
                vt_domain = _error_payload(e)

        otx_domain = None
        if otx_domain_task:
            try:
                otx_domain = await otx_domain_task
            except Exception as e:  # noqa: BLE001
                otx_domain = _error_payload(e)

        passive_ips: List[str] = []

        if vt_domain:
            if vt_domain.get("ok"):
                vt_data = vt_domain.get("data", {}) or {}
                domain_intel["virustotal"] = vt_data
                dns_records = vt_data.get("vt_dns_records") or []
                for record in dns_records:
                    if not isinstance(record, dict):
                        continue
                    if record.get("type") not in {"A", "AAAA"}:
                        continue
                    value = record.get("value")
                    if value:
                        passive_ips.append(str(value))
            elif not _should_suppress("virustotal_domain", vt_domain):
                domain_errors["virustotal"] = _error_details(vt_domain)
                domain_error_msgs.append(_error_summary("virustotal_domain", vt_domain))

        if otx_domain:
            if otx_domain.get("ok"):
                domain_intel["otx"] = otx_domain.get("data", {}) or {}
            elif not _should_suppress("otx_domain", otx_domain):
                domain_errors["otx"] = _error_details(otx_domain)
                domain_error_msgs.append(_error_summary("otx_domain", otx_domain))

        if passive_ips:
            ips = dedupe_preserve_order(passive_ips)

        for ip in ips:
            ptr = None
            try:
                vt = await vt_ip_summary(client=client, api_key=keys.vt_api_key, ip=ip)
            except Exception as e:  # noqa: BLE001
                vt = _error_payload(e)
            try:
                sh = await shodan_host(client=client, api_key=keys.shodan_api_key, ip=ip)
            except Exception as e:  # noqa: BLE001
                sh = _error_payload(e)
            try:
                ipapi = await ipapi_is_ip(client=client, api_key=keys.ipapi_is_api_key, ip=ip)
            except Exception as e:  # noqa: BLE001
                ipapi = _error_payload(e)
            try:
                ab = await abuseipdb_check(client=client, api_key=keys.abuseipdb_api_key, ip=ip)
            except Exception as e:  # noqa: BLE001
                ab = _error_payload(e)
            try:
                otx_ip = await otx_ip_pulses(client=client, api_key=keys.otx_api_key, ip=ip)
            except Exception as e:  # noqa: BLE001
                otx_ip = _error_payload(e)

            providers = {
                "virustotal": vt,
                "shodan": sh,
                "ipapi": ipapi,
                "abuseipdb": ab,
                "otx": otx_ip,
            }
            provider_errors: Dict[str, Dict[str, Any]] = {}
            for name, payload in providers.items():
                if not payload or payload.get("ok"):
                    continue
                if _should_suppress(name, payload):
                    continue
                details = _error_details(payload)
                if details:
                    provider_errors[name] = details
                result_errors.append(f"{ip} :: {_error_summary(name, payload)}")

            asn_meta: Dict[str, Any] = {}
            if ipapi.get("ok") and ipapi["data"].get("asn"):
                asn = int(ipapi["data"]["asn"])  # type: ignore[arg-type]
                cf = await fetch_asn_metadata(client=client, api_token=keys.cloudflare_api_token, asn=asn)
                if cf.get("ok"):
                    asn_meta = cf["data"]

            entry = {
                "ip": ip,
                "ptr": ptr,
                "virustotal": vt.get("data", {}) if vt.get("ok") else {},
                "shodan": sh.get("data", {}) if sh.get("ok") else {},
                "ipapi": ipapi.get("data", {}) if ipapi.get("ok") else {},
                "abuseipdb": ab.get("data", {}) if ab.get("ok") else {},
                "otx": otx_ip.get("data", {}) if otx_ip.get("ok") else {},
                "asn_meta": asn_meta,
            }
            if provider_errors:
                entry["errors"] = provider_errors
            out.append(entry)

    result_errors.extend(domain_error_msgs)

    data: Dict[str, Any] = {"domain": domain, "ips": out}
    if domain_intel:
        data["domain_intel"] = domain_intel
    if domain_errors:
        data["domain_errors"] = domain_errors

    return InvestigationResult(ok=True, data=data, errors=result_errors)


async def investigate_asn(asn: int | str, *, resolve_neighbors: int = 0, enrich: bool = False, enrich_limit: int = 50) -> InvestigationResult:
    if not is_valid_asn(asn):
        return InvestigationResult(ok=False, errors=["Invalid ASN"], data={})
    asn_int = int(asn)
    keys = _env_keys()
    async with create_client() as client:
        # Kick off IPAPI.IS ASN in parallel with Cloudflare when possible
        ipapi_task = asyncio.create_task(ipapi_is_asn(client=client, api_key=keys.ipapi_is_api_key, asn=asn_int))
        ripe_overview_task = asyncio.create_task(as_overview(client=client, asn=asn_int))
        ripe_abuse_task = asyncio.create_task(abuse_contact(client=client, asn=asn_int))
        caida_task = asyncio.create_task(caida_asrank(client=client, asn=asn_int))
        pdb_task = asyncio.create_task(peeringdb_ixps_for_asn(client=client, asn=asn_int))

        cf_bgp_task = None
        if keys.cloudflare_api_token:
            cf_bgp_task = asyncio.create_task(bgp_incidents(client=client, api_token=keys.cloudflare_api_token, asn=asn_int))

        cf_task = None
        if keys.cloudflare_api_token:
            cf_task = asyncio.create_task(fetch_asn_metadata(client=client, api_token=keys.cloudflare_api_token, asn=asn_int))

        try:
            ipapi = await ipapi_task  # type: ignore[assignment]
        except Exception as e:  # noqa: BLE001
            ipapi = _error_payload(e)
        try:
            ripe = await ripe_overview_task  # type: ignore[assignment]
        except Exception as e:  # noqa: BLE001
            ripe = _error_payload(e)
        try:
            rp_abuse = await ripe_abuse_task  # type: ignore[assignment]
        except Exception as e:  # noqa: BLE001
            rp_abuse = _error_payload(e)
        try:
            caida = await caida_task  # type: ignore[assignment]
        except Exception as e:  # noqa: BLE001
            caida = _error_payload(e)
        try:
            pdb = await pdb_task  # type: ignore[assignment]
        except Exception as e:  # noqa: BLE001
            pdb = _error_payload(e)
        if cf_bgp_task:
            try:
                cf_bgp = await cf_bgp_task  # type: ignore[assignment]
            except Exception as e:  # noqa: BLE001
                cf_bgp = _error_payload(e)
        else:
            cf_bgp = {"ok": False, "error": "missing_api_token"}

        rs_task = asyncio.create_task(routing_status(client=client, asn=asn_int))
        nb_task = asyncio.create_task(asn_neighbours(client=client, asn=asn_int))
        ap_task = asyncio.create_task(announced_prefixes(client=client, asn=asn_int))
        try:
            rs = await rs_task  # type: ignore[assignment]
        except Exception as e:  # noqa: BLE001
            rs = _error_payload(e)
        try:
            nb = await nb_task  # type: ignore[assignment]
        except Exception as e:  # noqa: BLE001
            nb = _error_payload(e)
        try:
            ap = await ap_task  # type: ignore[assignment]
        except Exception as e:  # noqa: BLE001
            ap = _error_payload(e)
        if cf_task:
            try:
                cf = await cf_task  # type: ignore[assignment]
            except Exception as e:  # noqa: BLE001
                cf = _error_payload(e)
        else:
            cf = {"ok": False}

        providers = {
            "ipapi_asn": ipapi,
            "ripe_overview": ripe,
            "ripe_abuse": rp_abuse,
            "caida": caida,
            "peeringdb": pdb,
            "ripe_routing_status": rs,
            "ripe_neighbors": nb,
            "ripe_prefixes": ap,
        }
        if cf_bgp_task:
            providers["cloudflare_bgp"] = cf_bgp
        if cf_task:
            providers["cloudflare_asn"] = cf
        provider_errors: Dict[str, Dict[str, Any]] = {}
        result_errors: List[str] = []
        for name, payload in providers.items():
            if not payload or payload.get("ok"):
                continue
            if _should_suppress(name, payload):
                continue
            details = _error_details(payload)
            if details:
                provider_errors[name] = details
            result_errors.append(_error_summary(name, payload))

        meta: Dict[str, Any] = {}
        # Prefer Cloudflare values when present; fall back to IPAPI.IS
        if cf.get("ok"):
            meta.update(cf["data"])  # type: ignore[index]
        if ipapi.get("ok"):
            # Only set fields that are missing from CF
            for k, v in ipapi["data"].items():  # type: ignore[index]
                if k not in meta or meta.get(k) in (None, ""):
                    meta[k] = v
        if ripe.get("ok"):
            holder = ripe["data"].get("holder")
            name = holder
            if name and ("-" in name):
                name = name.split(" - ", 1)[-1]
            if name and (not meta.get("name")):
                meta["name"] = name
            # Country code could be combined into name like asn tool; keep separate
        if rp_abuse.get("ok"):
            contacts = rp_abuse["data"].get("abuse_contacts") or []
            if contacts:
                meta["abuseContacts"] = contacts
        if caida.get("ok"):
            for k, v in caida["data"].items():
                if k not in meta or meta.get(k) in (None, ""):
                    meta[k] = v
        if pdb.get("ok"):
            ixps = pdb["data"].get("ixps") or []
            existing = meta.get("ixps") or []
            existing_names = {i.get("name") for i in existing if isinstance(i, dict) and i.get("name")}
            new_names = {i.get("name") for i in ixps if isinstance(i, dict) and i.get("name")}
            names = sorted(existing_names | new_names)
            if names:
                meta["ixps"] = [{"name": n} for n in names]

        # Attach CF BGP incidents summary if available
        meta_bgp: Dict[str, Any] = {}
        if cf_bgp.get("ok"):
            meta_bgp = cf_bgp.get("data", {})
        # Add RIPE routing counts
        if rs.get("ok"):
            d = rs.get("data", {})
            v4p = (d.get("announced_space", {}).get("v4", {}) or {}).get("prefixes")
            v6p = (d.get("announced_space", {}).get("v6", {}) or {}).get("prefixes")
            neigh = d.get("observed_neighbours")
            meta_bgp.update({
                "ripe_announced_prefixes_v4": v4p,
                "ripe_announced_prefixes_v6": v6p,
                "ripe_observed_neighbours": neigh,
            })
        # Add RIPE neighbours lists
        if nb.get("ok"):
            neighs = nb.get("data", {}).get("neighbours", [])
            upstream = [n.get("asn") for n in neighs if n.get("type") == "left"]
            downstream = [n.get("asn") for n in neighs if n.get("type") == "right"]
            uncertain = [n.get("asn") for n in neighs if n.get("type") == "uncertain"]
            meta_bgp.update({
                "ripe_upstream_asns": upstream,
                "ripe_downstream_asns": downstream,
                "ripe_uncertain_asns": uncertain,
            })
            # Optionally resolve first N neighbor names via RIPE as-overview
            if resolve_neighbors and resolve_neighbors > 0:
                to_resolve = set()
                for seq in (upstream[:resolve_neighbors], downstream[:resolve_neighbors], uncertain[:resolve_neighbors]):
                    for a in seq:
                        if isinstance(a, int):
                            to_resolve.add(a)
                name_map: Dict[int, str] = {}
                tasks = [asyncio.create_task(as_overview(client=client, asn=int(a))) for a in to_resolve]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for a, reso in zip(to_resolve, results):
                    if isinstance(reso, dict) and reso.get("ok"):
                        holder = reso.get("data", {}).get("holder")
                        if holder:
                            # Trim "ASNAME - Company" style
                            name = holder.split(" - ", 1)[-1] if " - " in holder else holder
                            name_map[int(a)] = name
                def _name_list(lst: list[int]) -> list[str]:
                    out: list[str] = []
                    for a in lst[:resolve_neighbors]:
                        nm = name_map.get(int(a))
                        out.append(f"{nm} ({a})" if nm else str(a))
                    return out
                meta_bgp.update({
                    "ripe_upstream_named": _name_list(upstream),
                    "ripe_downstream_named": _name_list(downstream),
                    "ripe_uncertain_named": _name_list(uncertain),
                })
        # Add announced prefixes lists (limited)
        if ap.get("ok"):
            prefs = ap.get("data", {}).get("prefixes", [])
            v4_list = [p.get("prefix") for p in prefs if isinstance(p.get("prefix"), str) and ":" not in p.get("prefix")]
            v6_list = [p.get("prefix") for p in prefs if isinstance(p.get("prefix"), str) and ":" in p.get("prefix")]
            meta_bgp.update({
                "ripe_prefixes_v4": v4_list,
                "ripe_prefixes_v6": v6_list,
            })
            # Optional enrichment: placeholder aggregation (fast). Full whois/pWhois can be added later.
            if enrich:
                inetnums = {
                    "v4": v4_list[:enrich_limit],
                    "v6": v6_list[:enrich_limit],
                    "other_v4": [],
                    "other_v6": [],
                }
                meta_bgp.update({"inetnums": inetnums})

        warnings: list[str] = []
        ipapi_suppressed = _should_suppress("ipapi_asn", ipapi)
        if keys.cloudflare_api_token and not cf.get("ok"):
            warnings.append("cloudflare_query_failed_or_missing")
        if not ipapi.get("ok") and not ipapi_suppressed:
            warnings.append("ipapi_query_failed_or_missing")
        if not ripe.get("ok"):
            warnings.append("ripestat_overview_failed")
        if not rp_abuse.get("ok"):
            warnings.append("ripestat_abuse_failed")
        if not caida.get("ok"):
            warnings.append("caida_failed")
        if not pdb.get("ok"):
            warnings.append("peeringdb_failed")

        data: Dict[str, Any] = {"asn": asn_int, "meta": meta, "bgp": meta_bgp}
        if provider_errors:
            data["errors"] = provider_errors

        return InvestigationResult(ok=True, data=data, warnings=warnings, errors=result_errors)

