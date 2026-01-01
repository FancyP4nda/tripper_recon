from __future__ import annotations

import os
from typing import Any, Dict, Optional

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff


IPAPI_IS_BASE = os.getenv("IPAPI_IS_BASE_URL", "https://api.ipapi.is")


def _float_or_none(value: Any) -> Optional[float]:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _bool_or_none(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "y"}:
            return True
        if lowered in {"0", "false", "no", "n"}:
            return False
    return None


def _parse_asn(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        cleaned = value.strip().upper()
        if cleaned.startswith("AS"):
            cleaned = cleaned[2:]
        if cleaned.isdigit():
            return int(cleaned)
    return None


def _pick_any(keys: tuple[str, ...], *sources: Any) -> Any:
    for src in sources:
        if not isinstance(src, dict):
            continue
        for key in keys:
            if key in src and src[key] not in (None, ""):
                return src[key]
    return None


def _compact_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    cleaned: Dict[str, Any] = {}
    for key, value in data.items():
        if value is None or value == "":
            continue
        if isinstance(value, (list, dict)) and not value:
            continue
        cleaned[key] = value
    return cleaned


def _extract_flags(*sources: Any) -> Dict[str, bool]:
    flag_map = {
        "vpn": ("is_vpn", "vpn"),
        "proxy": ("is_proxy", "proxy"),
        "tor": ("is_tor", "tor"),
        "relay": ("is_relay", "relay"),
        "hosting": ("is_hosting", "hosting"),
        "datacenter": ("is_datacenter", "datacenter"),
        "satellite": ("is_satellite", "satellite"),
        "abuser": ("is_abuser", "abuser"),
        "bogon": ("is_bogon", "bogon"),
        "mobile": ("is_mobile", "mobile"),
        "crawler": ("is_crawler", "crawler"),
    }
    out: Dict[str, bool] = {}
    for label, keys in flag_map.items():
        val: Optional[bool] = None
        for src in sources:
            if not isinstance(src, dict):
                continue
            for key in keys:
                if key in src:
                    val = _bool_or_none(src.get(key))
                    if val is not None:
                        break
            if val is not None:
                break
        if val is not None:
            out[f"is_{label}"] = val
    return out


def _auth_headers(api_key: Optional[str]) -> Dict[str, str]:
    if not api_key:
        return {}
    return {
        "Authorization": f"Bearer {api_key}",
        "X-API-Key": api_key,
    }


def _auth_params(api_key: Optional[str]) -> Dict[str, str]:
    if not api_key:
        return {}
    return {
        "key": api_key,
        "api_key": api_key,
        "apikey": api_key,
    }


def _unwrap_payload(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    for key in ("data", "result", "response"):
        nested = payload.get(key)
        if isinstance(nested, dict):
            return nested
    return payload


def _normalize_ip_payload(payload: Dict[str, Any], fallback_ip: str) -> Dict[str, Any]:
    location = payload.get("location") if isinstance(payload.get("location"), dict) else {}
    city = _pick_any(("city",), location, payload)
    region = _pick_any(("region", "region_name", "state", "state_prov"), location, payload)
    country = _pick_any(("country", "country_name"), location, payload)
    country_code = _pick_any(("country_code", "countryCode", "country_code2", "country_code3"), location, payload)
    continent = _pick_any(("continent", "continent_name"), location, payload)
    timezone = _pick_any(("timezone", "time_zone", "timeZone"), location, payload)
    postal = _pick_any(("postal", "postal_code", "zip"), location, payload)
    lat = _float_or_none(_pick_any(("latitude", "lat"), location, payload))
    lon = _float_or_none(_pick_any(("longitude", "lon", "lng"), location, payload))
    accuracy = _pick_any(("accuracy_radius", "accuracyRadius"), location, payload)
    calling_code = _pick_any(("calling_code", "callingCode"), location, payload)
    currency = _pick_any(("currency", "currency_code", "currencyCode"), location, payload)
    currency_code = _pick_any(("currency_code", "currencyCode"), location, payload)
    languages = _pick_any(("languages", "language"), location, payload)
    flag = _pick_any(("flag", "country_flag", "emoji"), location, payload)
    local_time = _pick_any(("local_time",), location, payload)
    local_time_unix = _pick_any(("local_time_unix",), location, payload)
    is_dst = _pick_any(("is_dst",), location, payload)
    is_eu_member = _pick_any(("is_eu_member",), location, payload)
    state = _pick_any(("state",), location, payload)

    asn_block = payload.get("asn") if isinstance(payload.get("asn"), dict) else {}
    connection = payload.get("connection") if isinstance(payload.get("connection"), dict) else {}
    company = payload.get("company") if isinstance(payload.get("company"), dict) else {}
    abuse = payload.get("abuse") if isinstance(payload.get("abuse"), dict) else {}
    datacenter = payload.get("datacenter") if isinstance(payload.get("datacenter"), dict) else {}

    asn_value = payload.get("asn")
    if isinstance(asn_value, dict):
        asn_value = asn_value.get("asn") or asn_value.get("number") or asn_value.get("id")
    asn_value = asn_value or _pick_any(("asn", "as_number", "number", "id"), connection, payload)
    asn = _parse_asn(asn_value)
    asn_name = _pick_any(("name", "asn_name"), asn_block, connection, payload)
    asn_domain = _pick_any(("domain",), asn_block, connection, company)
    asn_type = _pick_any(("type",), asn_block, connection, company)

    org = _pick_any(("organization", "org"), payload, connection, asn_block, company)
    isp = _pick_any(("isp",), payload, connection)

    security = payload.get("security") if isinstance(payload.get("security"), dict) else {}
    privacy = payload.get("privacy") if isinstance(payload.get("privacy"), dict) else {}
    flags = _extract_flags(security, privacy, payload)
    risk = _pick_any(("risk", "risk_score", "threat", "fraud_score"), security, privacy, payload)

    coords = None
    if lat is not None and lon is not None:
        coords = {"lat": lat, "lon": lon}

    return _compact_dict(
        {
            "ip": payload.get("ip") or fallback_ip,
            "type": _pick_any(("type", "ip_type"), payload),
            "continent": continent,
            "country": country,
            "country_code": country_code,
            "region": region,
            "city": city,
            "postal": postal,
            "timezone": timezone,
            "coordinates": coords,
            "latitude": lat,
            "longitude": lon,
            "accuracy_radius": accuracy,
            "calling_code": calling_code,
            "currency": currency,
            "currency_code": currency_code,
            "languages": languages,
            "country_flag": flag,
            "hostname": _pick_any(("hostname", "reverse", "ptr"), payload),
            "asn": asn,
            "asn_name": asn_name,
            "asn_domain": asn_domain,
            "asn_type": asn_type,
            "asn_details": _compact_dict(asn_block) if isinstance(asn_block, dict) else None,
            "org": org,
            "isp": isp,
            "company": _compact_dict(company) if isinstance(company, dict) else None,
            "connection": _compact_dict(connection) if isinstance(connection, dict) else None,
            "security": _compact_dict(security) if isinstance(security, dict) else None,
            "privacy": _compact_dict(privacy) if isinstance(privacy, dict) else None,
            "abuse_contact": _compact_dict(abuse) if isinstance(abuse, dict) else None,
            "datacenter": _compact_dict(datacenter) if isinstance(datacenter, dict) else None,
            "rir": _pick_any(("rir",), payload, asn_block),
            "elapsed_ms": _pick_any(("elapsed_ms", "elapsedMs"), payload),
            "flags": flags,
            "security_flag_statuses": flags,
            "risk": risk,
            "location": _compact_dict(
                {
                    "continent": continent,
                    "country": country,
                    "country_code": country_code,
                    "region": region,
                    "state": state,
                    "city": city,
                    "postal": postal,
                    "timezone": timezone,
                    "latitude": lat,
                    "longitude": lon,
                    "accuracy_radius": accuracy,
                    "calling_code": calling_code,
                    "currency_code": currency_code or currency,
                    "local_time": local_time,
                    "local_time_unix": local_time_unix,
                    "is_dst": is_dst,
                    "is_eu_member": is_eu_member,
                }
            ),
        }
    )


def _normalize_asn_payload(payload: Dict[str, Any], asn: int) -> Dict[str, Any]:
    asn_block = payload.get("asn") if isinstance(payload.get("asn"), dict) else {}
    connection = payload.get("connection") if isinstance(payload.get("connection"), dict) else {}
    company = payload.get("company") if isinstance(payload.get("company"), dict) else {}

    name = _pick_any(("name", "asn_name", "description"), asn_block, connection, payload)
    org = _pick_any(("organization", "org", "name"), asn_block, payload, company)
    country = _pick_any(("country", "country_code", "country_name"), asn_block, payload)
    rir = _pick_any(("rir", "registry"), asn_block, payload)
    allocation = _pick_any(
        ("allocationDate", "allocation_date", "allocated", "allocation", "allocated_on"),
        asn_block,
        payload,
    )
    domain = _pick_any(("domain", "website"), asn_block, connection, company)
    route = _pick_any(("route", "prefix", "prefixes"), asn_block, connection, payload)
    asn_type = _pick_any(("type", "asn_type"), asn_block, connection, payload)

    return _compact_dict(
        {
            "asn": asn,
            "name": name,
            "country": country,
            "rir": rir,
            "allocationDate": allocation,
            "organization": org,
            "domain": domain,
            "route": route,
            "type": asn_type,
        }
    )


async def ipapi_is_ip(*, client: httpx.AsyncClient, api_key: Optional[str], ip: str) -> Dict[str, Any]:
    if not api_key:
        return {"ok": False, "error": "missing_api_key"}

    async def _call() -> Dict[str, Any]:
        params = {"q": ip}
        params.update(_auth_params(api_key))
        r = await client.get(IPAPI_IS_BASE, params=params, headers=_auth_headers(api_key))
        if r.status_code == 404:
            return {"ok": False, "error": "not_found"}
        if r.status_code in (401, 403):
            return {"ok": False, "error": "unauthorized", "status": r.status_code}
        if r.status_code >= 400:
            message = None
            body: Any = None
            try:
                parsed = r.json()
                if isinstance(parsed, dict):
                    message = parsed.get("error") or parsed.get("message")
                body = parsed
            except ValueError:
                body = r.text
            return _compact_dict({"ok": False, "error": "http_error", "status": r.status_code, "message": message, "body": body})
        try:
            payload = r.json()
        except ValueError:
            return {"ok": False, "error": "invalid_json", "status": r.status_code}
        if isinstance(payload, dict) and (payload.get("error") or payload.get("success") is False):
            return {
                "ok": False,
                "error": "api_error",
                "message": payload.get("error") or payload.get("message"),
            }
        if not isinstance(payload, dict):
            return {"ok": False, "error": "invalid_response"}
        payload_data = _unwrap_payload(payload)
        if payload_data and (payload_data.get("error") or payload_data.get("success") is False):
            return {
                "ok": False,
                "error": "api_error",
                "message": payload_data.get("error") or payload_data.get("message"),
            }
        data = _normalize_ip_payload(payload_data or payload, ip)
        return {"ok": True, "data": data}

    return await with_exponential_backoff(_call)


async def ipapi_is_asn(*, client: httpx.AsyncClient, api_key: Optional[str], asn: int) -> Dict[str, Any]:
    if not api_key:
        return {"ok": False, "error": "missing_api_key"}

    async def _call() -> Dict[str, Any]:
        params = {"q": f"AS{asn}"}
        params.update(_auth_params(api_key))
        r = await client.get(IPAPI_IS_BASE, params=params, headers=_auth_headers(api_key))
        if r.status_code == 404:
            return {"ok": False, "error": "not_found"}
        if r.status_code in (401, 403):
            return {"ok": False, "error": "unauthorized", "status": r.status_code}
        if r.status_code >= 400:
            message = None
            body: Any = None
            try:
                parsed = r.json()
                if isinstance(parsed, dict):
                    message = parsed.get("error") or parsed.get("message")
                body = parsed
            except ValueError:
                body = r.text
            return _compact_dict({"ok": False, "error": "http_error", "status": r.status_code, "message": message, "body": body})
        try:
            payload = r.json()
        except ValueError:
            return {"ok": False, "error": "invalid_json", "status": r.status_code}
        if isinstance(payload, dict) and (payload.get("error") or payload.get("success") is False):
            return {
                "ok": False,
                "error": "api_error",
                "message": payload.get("error") or payload.get("message"),
            }
        if not isinstance(payload, dict):
            return {"ok": False, "error": "invalid_response"}
        payload_data = _unwrap_payload(payload)
        if payload_data and (payload_data.get("error") or payload_data.get("success") is False):
            return {
                "ok": False,
                "error": "api_error",
                "message": payload_data.get("error") or payload_data.get("message"),
            }
        data = _normalize_asn_payload(payload_data or payload, asn)
        if not data:
            return {"ok": False, "error": "not_found"}
        return {"ok": True, "data": data}

    return await with_exponential_backoff(_call)
