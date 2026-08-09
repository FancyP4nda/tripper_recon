"""Shodan InternetDB -- the keyless, free exposed-services lookup (roadmap 8.1).

**This is not the paid Shodan provider and must never be merged into it.** Read this paragraph
before touching either module. ``providers/shodan_api.py`` calls the paid host-lookup endpoint on
``api.shodan.io`` with ``SHODAN_API_KEY``; this module calls the free InternetDB service on a
different host with no credential at all. They answer overlapping questions from different
datasets with different freshness and different depth:

===================  ==========================================  =====================================
                     ``shodan_api.shodan_host`` (paid)           ``internetdb_host`` (this module)
===================  ==========================================  =====================================
credential           ``SHODAN_API_KEY``, in the query string     none
dataset              the full host record Shodan holds           the InternetDB extract
per-service banners  yes (``data[]``)                            no
``org`` / ``isp``    yes                                         **not in the response**
observation date     yes (``last_update``)                       **not in the response**
identifies you by    your API key                                your egress IP, and only that
===================  ==========================================  =====================================

The consequence for anyone tempted to "unify" the two: InternetDB is a strict subset that drops
the banner detail, the network owner and the observation date. Preferring it for an operator who
holds a key is a silent downgrade of a paid capability, and the missing ``last_update`` is the
worst of the three -- it removes the tool's only means of saying how old an open-port list is.
**InternetDB is the fallback for an operator with no key, never the default.** How the
orchestrator is expected to choose is written in the report accompanying this change; this module
holds no opinion and reads no environment variable.

What it adds. The paid path surfaced CVEs only after roadmap 4.6; the no-key path surfaced nothing
whatsoever, because ``shodan_host`` returns ``missing_api_key`` without a key and the orchestrator
classifies that as "not configured" and suppresses it. For the many users who will never set
``SHODAN_API_KEY``, exposed services and their associated CVEs were simply absent from every
report. This restores both.

Fields kept, and the names they are kept under. InternetDB returns exactly six top-level fields --
``ip``, ``ports``, ``hostnames``, ``cpes``, ``tags`` and ``vulns`` (Shodan's "Introducing the
InternetDB API" announcement, and the InternetDB page of the Shodan Book, both retrieved
2026-08-09). Five of them are carried under the key names ``shodan_api.shodan_host`` already uses
for the same concept -- ``ports``, ``hostnames``, ``tags``, ``vulns``, and ``cpe`` for what
InternetDB spells ``cpes`` -- so a renderer or a signal extractor written against the paid
provider reads this one unchanged. ``org`` and ``last_update`` are **absent rather than
fabricated**: a consumer that asks for them gets nothing, which is the honest answer, instead of a
``None`` that renders as a value or an invented timestamp that renders as freshness. ``source``
carries the discriminator so a merged JSON payload still says which dataset answered.

**A 404 is UNKNOWN, never clean.** InternetDB answers 404 for an address it holds no record of,
which happens for the great majority of the address space and says nothing at all about exposure.
It is returned as ``{"ok": False, "error": "not_found"}`` -- an error envelope the orchestrator
files as a provider that did not answer -- specifically so it can never be rendered as an empty
port list, which reads as "we looked and found nothing exposed".

**Rate limiting is IP-scoped and a 429 is terminal here.** With no key, the operator's egress IP is
the only identifier the service has, so a limit breach is charged against the whole connection
rather than a credential. Shodan's announcement claims a "much higher rate limit" than the paid
API without naming a number; the only concrete figure available is a community report against this
same endpoint (blacklanternsecurity/bbot issue 2412, retrieved 2026-08-09) describing an
approximately one-hour IP ban after roughly 600 rapid requests, with the recommendation to
self-throttle to one request per second. Because that ban lands *before* the 429 is read and lasts
far longer than any investigation, a 429 is returned as a terminal ``rate_limited`` envelope
instead of being raised into ``with_exponential_backoff``: retrying it cannot succeed and only
deepens the offence. This follows the precedent ``providers/peeringdb.py`` set for the other
keyless, rate-limited provider in the package. Transport failures and the 5xx family are still
retried normally.

The passive boundary is unchanged: the only host contacted is Shodan's, which already holds the
data, and the target is never touched. The host is not yet on ``ALLOWED_EGRESS_HOSTS``
(``utils/http.py``) or on ``ALLOWED_HOSTS`` in ``tests/test_passivity.py``; both, plus section 2
of ``docs/OPSEC.md``, are wired in the same commit that adds this module to an orchestrator.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff
from tripper_recon.utils.validation import is_valid_ip

INTERNETDB_BASE = "https://internetdb.shodan.io"

#: Marks which Shodan dataset produced a payload, so a consumer merging this with
#: ``shodan_api.shodan_host`` output can still tell the paid record from the free extract.
INTERNETDB_SOURCE = "shodan_internetdb"


def _str_items(value: Any) -> Iterable[str]:
    """Yield the non-empty strings in ``value``, accepting a list or a bare string.

    Anything else -- a number, a nested object, ``None`` -- yields nothing rather than raising.
    A provider that changes a field's shape must degrade to an empty list, not to a traceback in
    the middle of an investigation.
    """
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            yield stripped
        return
    if not isinstance(value, list):
        return
    for item in value:
        if isinstance(item, str):
            stripped = item.strip()
            if stripped:
                yield stripped


def _sorted_strings(value: Any) -> List[str]:
    """Deduplicated, sorted string list. Sorted so two runs diff cleanly."""
    return sorted(set(_str_items(value)))


def _ports(value: Any) -> List[int]:
    """Deduplicated, ascending port list.

    ``bool`` is excluded explicitly because it is an ``int`` subclass, so a stray ``true`` in the
    array would otherwise become port 1. Non-integers are dropped rather than coerced: a port
    number this module could not read is not a port number it should assert.
    """
    if not isinstance(value, list):
        return []
    ports = {item for item in value if isinstance(item, int) and not isinstance(item, bool)}
    return sorted(ports)


def _as_str(value: Any) -> Optional[str]:
    """Return a non-empty string, otherwise ``None``."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


async def internetdb_host(*, client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    """Exposed ports, hostnames, CPEs, tags and CVEs InternetDB already holds for ``ip``.

    Keyless by construction, so there is no ``api_key`` parameter and no ``missing_api_key``
    path -- see the module docstring for why that makes this a fallback rather than a
    replacement, and for the OPSEC consequence of authenticating with an egress IP.

    Failure envelopes, all terminal:

    ``invalid_ip``
        ``ip`` is not an address. Checked before any request is issued: this module interpolates
        a caller-supplied value into a URL path, and a value that is not an address has no
        business reaching the wire.
    ``not_found``
        HTTP 404 -- InternetDB holds no record. **Unknown, not clean.**
    ``rate_limited``
        HTTP 429 -- the egress IP is throttled or banned. Not retried; see the module docstring.

    Everything else follows the house policy: 5xx, 408, 425 and transport errors are retried by
    ``with_exponential_backoff``, and any other permanent status raises to the caller.
    """
    if not is_valid_ip(ip):
        return {"ok": False, "error": "invalid_ip"}

    async def _call() -> Dict[str, Any]:
        r = await client.get(f"{INTERNETDB_BASE}/{ip}")
        if r.status_code == 404:
            # Absence of a record, not absence of exposure. The orchestrator files this as a
            # provider that did not answer, which is the only reading the data supports.
            return {"ok": False, "error": "not_found"}
        if r.status_code == 429:
            return {"ok": False, "error": "rate_limited", "status": r.status_code}
        r.raise_for_status()
        j = r.json()
        if not isinstance(j, dict):
            j = {}
        return {
            "ok": True,
            "data": {
                "ports": _ports(j.get("ports")),
                "hostnames": _sorted_strings(j.get("hostnames")),
                # InternetDB spells this 'cpes'; carried under the paid provider's 'cpe' so one
                # consumer reads both.
                "cpe": _sorted_strings(j.get("cpes")),
                "tags": _sorted_strings(j.get("tags")),
                "vulns": _sorted_strings(j.get("vulns")),
                # Echoed from the response, not from the request, so a record describing a
                # different address than the one asked for is visible rather than hidden.
                "ip": _as_str(j.get("ip")),
                "source": INTERNETDB_SOURCE,
            },
        }

    return await with_exponential_backoff(_call)
