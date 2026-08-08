from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff

PDB_BASE = "https://www.peeringdb.com/api"

# PeeringDB is queried without an API key and enforces a real rate limit on anonymous
# callers, so the per-net fan-out below is bounded. An ASN can hold many net records and
# each one costs a request; five in flight hides latency on a multi-net ASN without turning
# one investigation into a burst the provider will throttle.
MAX_CONCURRENT_NET_LOOKUPS = 5


async def peeringdb_ixps_for_asn(*, client: httpx.AsyncClient, asn: int) -> Dict[str, Any]:
    """IXP names PeeringDB lists for ``asn``.

    Two request shapes are involved: one ``/net`` search for the ASN's net records, then one
    ``/net/{id}`` fetch per record for its ``netixlan_set``.

    Each request is retried on its own. Retrying the whole sequence as a single closure --
    which is what this did before -- meant a failure on the last per-net fetch replayed every
    earlier one, so N+1 requests became up to 2N+2 against a keyless, rate-limited provider.
    The per-net fetches also run concurrently rather than in sequence, bounded by
    ``MAX_CONCURRENT_NET_LOOKUPS``.

    Failure semantics are unchanged: an HTTP error on ``/net`` returns the error envelope
    without retrying, an HTTP error on a single ``/net/{id}`` drops that record and keeps the
    rest, and an exception that survives its own retries propagates to the caller.
    """

    async def _fetch_nets() -> Dict[str, Any]:
        """One request: the net records for the ASN. Retried independently of everything else."""
        r = await client.get(f"{PDB_BASE}/net", params={"asn__in": asn})
        if r.status_code >= 400:
            return {"ok": False, "status": r.status_code}
        return {"ok": True, "nets": r.json().get("data", [])}

    async def _fetch_ix_names(net_id: Any) -> List[str]:
        """One request: the IXP names on a single net record. Retried independently."""
        r = await client.get(f"{PDB_BASE}/net/{net_id}")
        if r.status_code >= 400:
            return []
        net_data = r.json().get("data", [])
        if not net_data:
            return []
        netixlan = net_data[0].get("netixlan_set", [])
        return [name for name in (entry.get("name") for entry in netixlan) if name]

    first = await with_exponential_backoff(_fetch_nets)
    if not first["ok"]:
        return {"ok": False, "error": "http_error", "status": first["status"]}

    nets = first["nets"]
    if not nets:
        return {"ok": True, "data": {"ixps": []}}

    net_ids = [net_id for net_id in (net.get("id") for net in nets) if net_id]
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_NET_LOOKUPS)

    async def _bounded_fetch(net_id: Any) -> List[str]:
        async with semaphore:
            return await with_exponential_backoff(lambda: _fetch_ix_names(net_id))

    # return_exceptions=True so one dead sub-request does not abandon the siblings mid-flight
    # with their results unretrieved. The first failure is re-raised once every task has
    # settled, which keeps the pre-existing contract that an exhausted retry escapes.
    results = await asyncio.gather(*(_bounded_fetch(net_id) for net_id in net_ids), return_exceptions=True)

    ix_names: List[str] = []
    failure: BaseException | None = None
    for result in results:
        if isinstance(result, BaseException):
            if failure is None:
                failure = result
            continue
        ix_names.extend(result)
    if failure is not None:
        raise failure

    ixps = [{"name": name} for name in sorted(set(ix_names))]
    return {"ok": True, "data": {"ixps": ixps}}
