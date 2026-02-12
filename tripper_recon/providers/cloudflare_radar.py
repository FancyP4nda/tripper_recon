from __future__ import annotations

from typing import Any, Dict, Optional

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff


RADAR_GRAPHQL_ENDPOINT = "https://api.cloudflare.com/client/v4/radar/graphql"


async def fetch_asn_metadata(*, client: httpx.AsyncClient, api_token: Optional[str], asn: int) -> Dict[str, Any]:
    if not api_token:
        return {"ok": False, "error": "missing_api_token"}

    # Primary query: Int-typed ASN variable
    query_int = {
        "query": (
            "query($asn: Int!) {\n"
            "  asn(asn: $asn) {\n"
            "    asn name countryCode caidaRank organization { name }\n"
            "    abuseContacts rir allocationDate\n"
            "    ixps { name }\n"
            "  }\n"
            "}"),
        "variables": {"asn": asn},
    }

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    async def _call_int() -> Dict[str, Any]:
        r = await client.post(RADAR_GRAPHQL_ENDPOINT, json=query_int, headers=headers)
        if r.status_code != 200:
            return {"ok": False, "error": "http_error", "status": r.status_code, "body": r.text[:500]}
        j = r.json()
        if "errors" in j:
            return {"ok": False, "error": j["errors"]}
        data = j.get("data", {}).get("asn")
        if not data:
            return {"ok": False, "error": "not_found"}
        return {"ok": True, "data": data}

    # Fallback query: String-typed ASN variable with "AS" prefix
    query_str = {
        "query": (
            "query($asn: String!) {\n"
            "  asn(asn: $asn) {\n"
            "    asn name countryCode caidaRank organization { name }\n"
            "    abuseContacts rir allocationDate\n"
            "    ixps { name }\n"
            "  }\n"
            "}"),
        "variables": {"asn": f"AS{asn}"},
    }

    async def _call_str() -> Dict[str, Any]:
        r = await client.post(RADAR_GRAPHQL_ENDPOINT, json=query_str, headers=headers)
        if r.status_code != 200:
            return {"ok": False, "error": "http_error", "status": r.status_code, "body": r.text[:500]}
        j = r.json()
        if "errors" in j:
            return {"ok": False, "error": j["errors"]}
        data = j.get("data", {}).get("asn")
        if not data:
            return {"ok": False, "error": "not_found"}
        return {"ok": True, "data": data}

    res = await with_exponential_backoff(_call_int)
    if res.get("ok"):
        return res
    # try string fallback
    res2 = await with_exponential_backoff(_call_str)
    return res2

