"""abuse.ch URLhaus and ThreatFox -- observations, not opinions. Roadmap 8.7.

Every other reputation provider in this package answers with an aggregate: *n* of *m* engines
disliked this, *k* people reported it, *p* pulses mention it. Those are opinions about an
indicator, and they degrade in the two ways an aggregate always does -- a stale consensus keeps
reading as current, and a thin consensus reads identically to a thick one.

URLhaus and ThreatFox answer with something categorically different. A URLhaus hit says *this
exact URL served this exact file, whose SHA-256 is this, first seen on this date, reported by
this handle, and here is whether it is still serving right now*. A ThreatFox hit says *this
indicator is a command-and-control endpoint for this named malware family, at this confidence,
first seen then, last seen then*. Those are first-party observations with a payload or an actor
attached. They are the strongest evidence this tool can obtain, and the module is written to
carry the evidence rather than to compress it into another score.

**Two APIs, one credential.** Both platforms authenticate with the same abuse.ch Auth-Key,
issued from the abuse.ch authentication portal (auth.abuse.ch -- written scheme-less on purpose,
the way ``utils/backoff.py`` cites RFC 9110 by number: the passivity gate allowlists every
absolute URL literal in this package and that host is never contacted). The key travels in the
``Auth-Key`` request header. Both APIs now *require* it; an unauthenticated request is rejected,
so there is no keyless mode to fall back to and :data:`MISSING_API_KEY` is returned rather than
raised, exactly as every other provider here does.

**POST here is a QUERY, and the distinction is the whole passivity argument.**
Read this before touching the request code. URLhaus takes a form-encoded ``POST`` with
``url=<...>`` or ``host=<...>``; ThreatFox takes a JSON ``POST`` with
``{"query": "search_ioc", "search_term": ...}``. In both cases the verb is how the API accepts
its *arguments*, not what it does with them: the request reads rows abuse.ch already holds,
written by somebody else, before this tool existed. **Nothing is submitted, nothing is fetched
on the operator's behalf, and the target never learns anything.** That is the same reason
Cloudflare's Radar GraphQL POST is sanctioned in ``docs/OPSEC.md`` section 7, and it is exactly
NOT the reason a VirusTotal URL submission or a urlscan scan submission is forbidden -- those
instruct a third party to go and load the target.

Both of these hosts also carry routes that would break that promise, and both are one call away:

* URLhaus exposes a sample-download route on this same API. It is the abuse.ch analogue of the
  MalwareBazaar route already named in ``docs/OPSEC.md`` section 7, and it is forbidden here for
  the same reason -- a passive recon CLI must never hold a live sample. This module therefore
  drops the per-payload download link from every record it builds, keeping the hashes, which are
  the part an analyst can actually pivot on.
* ThreatFox's endpoint is a single URL that dispatches on the ``query`` selector, and one of the
  selectors it accepts writes an IOC into the public corpus. :data:`THREATFOX_SEARCH_QUERY` is
  the only selector this module will ever send, and it is a module-level constant so the gate
  can pin it.

**"No record" is UNKNOWN, never clean.** A miss on either platform returns the
``no_results`` failure envelope rather than a success envelope with an empty list. That is a
deliberate refusal to hand a consumer a zero it can render green. URLhaus indexes malware
distribution URLs somebody reported; ThreatFox indexes IOCs somebody submitted. Neither is a
census of the benign internet, and a freshly stood-up phishing host is *expected* to be absent
from both. The absence of a record is the absence of evidence and this module says so in the
error slug (the same call the urlscan provider makes with ``no_public_scan``).

**Freshness is carried, never collapsed.** ``url_status`` (``online``/``offline``/``unknown``)
and ThreatFox's ``last_seen`` are the fields that separate "this was bad in 2019" from "this is
serving right now". Timestamps are passed through as abuse.ch's own strings, unparsed, for the
same reason as AbuseIPDB's ``lastReportedAt``: they are evidence, and reformatting them would
put this module in the business of guessing timezones on behalf of an incident report.

**Wildcard search is filtered, not trusted.** ThreatFox stores C2 indicators as ``ip:port``, so
an exact-match search for a bare address misses every one of them. This module therefore issues
the wildcard search and then applies :func:`_ioc_matches_term` to the results, keeping only IOCs
that are the indicator itself or the indicator with a port appended. The number discarded is
reported in the payload rather than hidden, because "we asked broadly and narrowed" is a
different evidentiary claim from "the provider returned exactly this".

**TERMS OF USE -- an accepted, unmitigated exposure.** The abuse.ch Terms of Use prohibit any
attempt to "use any high volume automatic, electronic or manual process to access, search or
harvest information from the Platforms (including without limitation robots, spiders or
scripts)", and describe query volume limits as "volumes reasonably expected for non-commercial
or non-profit purposes". Per-indicator interactive lookups plausibly sit inside that. This
tool's ``bulk`` mode -- a script issuing one lookup per line of a pasted file -- is arguably the
named prohibited case. **The operator has been told this and has accepted the exposure
knowingly** (``docs/ROADMAP.md`` section 4b, decision Q5): this provider is built in full,
including bulk mode, with no gate, no exclusion, and no disabled-by-default flag. The exposure
is recorded rather than mitigated. Do not add a gate here on your own initiative; that decision
is settled. Do keep this paragraph accurate if the terms change.

**Documentation retrieved 2026-08-09** from the URLhaus API page (urlhaus-api.abuse.ch), the
ThreatFox API page (threatfox.abuse.ch/api/) and the abuse.ch Terms of Use. What could not be
confirmed from those pages is recorded at :data:`UNVERIFIED_QUERY_STATUSES`.
"""

from __future__ import annotations

import re
from typing import Any, Awaitable, Dict, FrozenSet, List, Optional

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff
from tripper_recon.utils.http import PassiveBoundaryViolation

# --------------------------------------------------------------------------------------
# Endpoints
#
# Every destination is a module-level constant so that the passivity gate's endpoint
# resolver can follow it, and so the POST call sites can be pinned by constant NAME rather
# than by a line of text (tests/test_passivity.py sections 3 and 5).
# --------------------------------------------------------------------------------------

#: URLhaus API v1 root. Documented at urlhaus-api.abuse.ch.
URLHAUS_BASE = "https://urlhaus-api.abuse.ch/v1"

#: URLhaus "URL information" query. Form-encoded POST, parameter ``url``. Reads the record for
#: one URL that somebody already reported; it does not create one.
URLHAUS_URL_ENDPOINT = f"{URLHAUS_BASE}/url/"

#: URLhaus "Host information" query. Form-encoded POST, parameter ``host``. Accepts an IPv4
#: address, a hostname or a domain, case-insensitively -- which is why the IP path and the
#: domain path share one function here.
URLHAUS_HOST_ENDPOINT = f"{URLHAUS_BASE}/host/"

#: ThreatFox API v1. One endpoint that dispatches on the ``query`` selector in the JSON body.
THREATFOX_ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"

#: The ONLY ThreatFox selector this module sends. Named as a constant so a reviewer can see at
#: a glance that no write selector is reachable from this file: the endpoint is shared between
#: read and write operations, so the selector -- not the URL -- is what makes this call passive.
THREATFOX_SEARCH_QUERY = "search_ioc"


# --------------------------------------------------------------------------------------
# Envelope slugs and response vocabulary
# --------------------------------------------------------------------------------------

#: The spelling ``orchestrators.NOT_CONFIGURED_ERRORS`` recognises as "never asked", so an
#: unset key is reported as a skipped provider rather than as a failed investigation.
MISSING_API_KEY = "missing_api_key"

#: ``query_status`` on a successful query, both platforms.
QUERY_STATUS_OK = "ok"

#: Miss spellings observed across the two platforms' documentation. URLhaus documents
#: ``no_results``; ThreatFox's error vocabulary is undocumented and the singular form is what
#: its API has emitted in practice, so both are accepted and both mean the same thing: abuse.ch
#: holds no record. That is UNKNOWN, not clean -- see the module docstring.
NO_RESULT_STATUSES: FrozenSet[str] = frozenset({"no_result", "no_results"})

#: **Not confirmed from the vendor documentation** (retrieved 2026-08-09). The URLhaus API page
#: enumerates ``ok``, ``no_results``, ``http_post_expected``, ``http_get_expected``,
#: ``invalid_url``, ``invalid_host``, ``invalid_md5`` and ``invalid_sha256``. The ThreatFox API
#: page documents ``ok`` and nothing else -- no error vocabulary, and no statement of what a
#: rejected Auth-Key returns. This module therefore never switches on an undocumented literal:
#: anything that is not ``ok`` and not in :data:`NO_RESULT_STATUSES` is passed through verbatim
#: as the error slug, so an unrecognised status reaches the analyst as itself instead of being
#: silently reclassified as "no data".
UNVERIFIED_QUERY_STATUSES = "ThreatFox error statuses are undocumented; unknown values pass through verbatim"

#: URLhaus ``url_status``. ``unknown`` is a real value the API returns and is NOT the same as
#: the field being absent -- absent means URLhaus did not say, ``unknown`` means URLhaus said it
#: does not know. Both are preserved distinctly (``None`` versus the string).
URL_STATUS_ONLINE = "online"

#: abuse.ch timestamps are ``YYYY-MM-DD HH:MM:SS UTC``. Matched rather than parsed: the strings
#: are carried through unparsed, and this pattern exists only so that a lexicographic min/max
#: over them is defensible. A value in any other shape is excluded from the min/max rather than
#: coerced, because lexicographic ordering is only valid within one fixed format.
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC$")


# --------------------------------------------------------------------------------------
# Self-imposed record caps
#
# None of these is a limit quoted from the API. They exist so that a single lookup against a
# heavily-abused host cannot put a thousand records into a JSON report, and every one of them
# reports the true count and a truncation flag alongside the capped list -- a cap that hides
# the number it dropped is the same defect class as a green zero.
# --------------------------------------------------------------------------------------

#: Payload records carried per URLhaus URL record.
MAX_PAYLOAD_RECORDS = 25

#: URL records carried per URLhaus host record. A host with 120 known malware URLs is already
#: adjudicated by the first few; the total is reported separately and is not truncated.
MAX_URL_RECORDS = 25

#: IOC records carried per ThreatFox search.
MAX_IOC_RECORDS = 50


# --------------------------------------------------------------------------------------
# Coercion helpers
#
# Every field read below goes through one of these. abuse.ch emits integers as JSON strings
# (``"url_count": "120"``, ``"response_size": "179664"``), booleans as the strings ``"true"``
# and ``"false"``, and ``null`` for fields it has no value for. A missing field must read as
# absent and never as a benign value.
# --------------------------------------------------------------------------------------


def _as_dict(value: Any) -> Dict[str, Any]:
    """Return ``value`` when it is a dict, otherwise an empty dict."""
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    """Return ``value`` when it is a list, otherwise an empty list.

    ThreatFox sets ``data`` to a plain string on a miss rather than to an empty array, so this
    is load-bearing and not defensive decoration.
    """
    return value if isinstance(value, list) else []


def _as_str(value: Any) -> Optional[str]:
    """Return a non-empty stripped string, otherwise ``None``."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _as_str_list(value: Any) -> Optional[List[str]]:
    """Return the non-empty strings in a list, or ``None`` when there is no usable list.

    ``None`` and ``[]`` are kept distinct: abuse.ch sends ``"tags": null`` for "no tags were
    recorded", and an empty list would assert that the record was checked and had none.
    """
    if not isinstance(value, list):
        return None
    items = [text for text in (_as_str(entry) for entry in value) if text is not None]
    return items or None


def _as_int(value: Any) -> Optional[int]:
    """Return an int, accepting the JSON-string integers abuse.ch emits. ``bool`` is rejected."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        candidate = value.strip()
        if candidate.lstrip("-").isdigit():
            return int(candidate)
    return None


def _as_bool(value: Any) -> Optional[bool]:
    """Return a bool for a real bool or for abuse.ch's ``"true"``/``"false"`` strings.

    Never ``bool(value)``: that maps ``None`` and ``""`` to ``False``, asserting a negative the
    provider never made. ``larted`` ("has this been reported to the hoster") is the field this
    exists for, and "abuse.ch did not say" must not render as "nobody reported it".
    """
    if isinstance(value, bool):
        return value
    text = _as_str(value)
    if text is None:
        return None
    lowered = text.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return None


def _first_str(record: Dict[str, Any], *keys: str) -> Optional[str]:
    """First key present as a usable string. Same field, two spellings across endpoints."""
    for key in keys:
        found = _as_str(record.get(key))
        if found is not None:
            return found
    return None


def _first_int(record: Dict[str, Any], *keys: str) -> Optional[int]:
    """First key present as a usable int. ``0`` is a value, so this cannot be written with ``or``."""
    for key in keys:
        found = _as_int(record.get(key))
        if found is not None:
            return found
    return None


def _distinct(values: List[Optional[str]]) -> Optional[List[str]]:
    """Sorted distinct non-``None`` values, or ``None`` when there were none."""
    items = sorted({value for value in values if value is not None})
    return items or None


def _timestamp_bounds(values: List[Optional[str]]) -> Dict[str, Optional[str]]:
    """Earliest and latest of a set of abuse.ch timestamps, or ``None`` when none parse.

    Compared lexicographically, which is only sound because :data:`_TIMESTAMP_RE` restricts the
    set to one zero-padded fixed-width UTC format. Anything else is excluded rather than
    coerced.
    """
    stamps = sorted(value for value in values if value is not None and _TIMESTAMP_RE.match(value))
    if not stamps:
        return {"first": None, "last": None}
    return {"first": stamps[0], "last": stamps[-1]}


# --------------------------------------------------------------------------------------
# Response-envelope helpers
# --------------------------------------------------------------------------------------


def _query_status(body: Any) -> Optional[str]:
    """The ``query_status`` of a response body, tolerating abuse.ch's own documented typo.

    The URLhaus host-information example in the vendor documentation (retrieved 2026-08-09)
    spells the key ``query_staus``. Whether that is a documentation error or a live response
    key could not be determined without issuing a request, which this repo does not do to
    "try it". Both spellings are accepted; reading the wrong one would turn every successful
    host lookup into an unrecognised status.
    """
    record = _as_dict(body)
    return _as_str(record.get("query_status")) or _as_str(record.get("query_staus"))


def _status_envelope(body: Any) -> Optional[Dict[str, Any]]:
    """Failure envelope for a non-``ok`` ``query_status``, or ``None`` when the query succeeded.

    A miss becomes ``no_results`` -- a failure envelope, deliberately, so that no consumer can
    render "abuse.ch has never heard of this" as a clean result. Any other status is passed
    through verbatim (see :data:`UNVERIFIED_QUERY_STATUSES`).
    """
    status = _query_status(body)
    if status is None:
        return {"ok": False, "error": "invalid_response", "message": "response carried no query_status"}
    lowered = status.lower()
    if lowered == QUERY_STATUS_OK:
        return None
    if lowered in NO_RESULT_STATUSES:
        return {"ok": False, "error": "no_results"}
    return {"ok": False, "error": lowered, "query_status": status}


def _http_envelope(response: httpx.Response) -> Optional[Dict[str, Any]]:
    """Failure envelope for the status codes worth a distinct slug, or ``None`` to continue.

    All three are permanent for this key and this indicator, and none is retried: the backoff
    policy raises non-retryable statuses on the first attempt, and returning here keeps them out
    of the exception path entirely so the orchestrator sees a slug rather than a stack.

    ``404`` is a distinct ``not_found``, and it means UNKNOWN. It is never "clean" -- a URL that
    abuse.ch has no page for is a URL nobody reported, which is the normal state of a phishing
    site during the hour it matters.
    """
    if response.status_code in (401, 403):
        return {
            "ok": False,
            "error": "unauthorized",
            "status": response.status_code,
            "message": "abuse.ch rejected the Auth-Key; both URLhaus and ThreatFox now require one",
        }
    if response.status_code == 404:
        return {"ok": False, "error": "not_found", "status": response.status_code}
    return None


def _json_body(response: httpx.Response) -> Any:
    """Decode a JSON body, or return the sentinel ``None`` for anything that is not JSON.

    abuse.ch answers an infrastructure failure with an HTML error page under a 200 in some
    conditions. Letting :meth:`httpx.Response.json` raise would surface that as an unclassified
    exception; a slug is more useful and cannot be mistaken for data.
    """
    try:
        return response.json()
    except ValueError:
        return None


def _headers(api_key: str) -> Dict[str, str]:
    """Auth-Key plus an explicit Accept. Both platforms authenticate with the same key."""
    return {"Auth-Key": api_key, "Accept": "application/json"}


# --------------------------------------------------------------------------------------
# URLhaus extraction
# --------------------------------------------------------------------------------------


def _payload_record(entry: Any) -> Optional[Dict[str, Any]]:
    """One payload observed being served from a URLhaus URL.

    This is the record that makes a URLhaus hit dominate a verdict: it is not an opinion about
    the URL, it is a file that was retrieved from it, with a hash an analyst can search
    elsewhere and a ``signature`` naming the malware family.

    Two field spellings are accepted for the hashes and the size because the URL-information
    response and the payload-information response name them differently
    (``response_md5``/``response_sha256``/``response_size`` versus
    ``md5_hash``/``sha256_hash``/``file_size``).

    The download URL abuse.ch attaches to each payload is deliberately **not** carried. It is a
    live-malware retrieval route, forbidden by ``docs/OPSEC.md`` section 7 for the same reason
    the MalwareBazaar equivalent is; emitting the link into a report invites exactly the fetch
    the whole document forbids. The hashes are carried instead, which is the pivot an analyst
    actually needs.
    """
    if not isinstance(entry, dict):
        return None
    virustotal = _as_dict(entry.get("virustotal"))
    vt_record: Optional[Dict[str, Any]] = None
    if virustotal:
        vt_record = {
            "result": _as_str(virustotal.get("result")),
            "percent": _as_str(virustotal.get("percent")),
            "link": _as_str(virustotal.get("link")),
        }
    return {
        "firstseen": _as_str(entry.get("firstseen")),
        "lastseen": _as_str(entry.get("lastseen")),
        "filename": _as_str(entry.get("filename")),
        "file_type": _as_str(entry.get("file_type")),
        "file_size": _first_int(entry, "response_size", "file_size"),
        "md5": _first_str(entry, "response_md5", "md5_hash"),
        "sha256": _first_str(entry, "response_sha256", "sha256_hash"),
        "signature": _as_str(entry.get("signature")),
        "imphash": _as_str(entry.get("imphash")),
        "ssdeep": _as_str(entry.get("ssdeep")),
        "tlsh": _as_str(entry.get("tlsh")),
        "magika": _as_str(entry.get("magika")),
        "virustotal": vt_record,
    }


def _payload_records(value: Any) -> List[Dict[str, Any]]:
    """Every usable payload record in a ``payloads`` array, uncapped."""
    records: List[Dict[str, Any]] = []
    for entry in _as_list(value):
        record = _payload_record(entry)
        if record is not None:
            records.append(record)
    return records


def _url_record(entry: Any) -> Optional[Dict[str, Any]]:
    """One malware URL from a URLhaus host response."""
    if not isinstance(entry, dict):
        return None
    return {
        "id": _as_str(entry.get("id")),
        "url": _as_str(entry.get("url")),
        "url_status": _as_str(entry.get("url_status")),
        "date_added": _as_str(entry.get("date_added")),
        "threat": _as_str(entry.get("threat")),
        "reporter": _as_str(entry.get("reporter")),
        "larted": _as_bool(entry.get("larted")),
        "takedown_time_seconds": _as_int(entry.get("takedown_time_seconds")),
        "tags": _as_str_list(entry.get("tags")),
        "reference": _as_str(entry.get("urlhaus_reference")),
    }


def _blacklists(value: Any) -> Optional[Dict[str, Optional[str]]]:
    """URLhaus's third-party blocklist status for the host, or ``None`` when absent.

    Carried as the provider's own strings (``"listed"``, ``"not listed"``,
    ``"abused_legit_malware"``, ...) rather than coerced to booleans. These are Spamhaus DBL and
    SURBL classifications with distinct meanings, and flattening ``abused_legit_malware`` --
    a compromised legitimate site -- into ``True`` destroys the one distinction that changes
    what an analyst does next.
    """
    record = _as_dict(value)
    if not record:
        return None
    return {
        "spamhaus_dbl": _as_str(record.get("spamhaus_dbl")),
        "surbl": _as_str(record.get("surbl")),
    }


def _urlhaus_url_payload(body: Any) -> Dict[str, Any]:
    """Shape a URLhaus URL-information response into the provider payload."""
    record = _as_dict(body)
    payloads = _payload_records(record.get("payloads"))
    bounds = _timestamp_bounds([payload.get("firstseen") for payload in payloads])
    url_status = _as_str(record.get("url_status"))
    return {
        "urlhaus_id": _as_str(record.get("id")),
        "urlhaus_reference": _as_str(record.get("urlhaus_reference")),
        "urlhaus_url": _as_str(record.get("url")),
        "urlhaus_host": _as_str(record.get("host")),
        # The freshness field. `online` means abuse.ch believes it is still serving; `offline`
        # means it was and is not; `unknown` means abuse.ch said it does not know; `None` means
        # abuse.ch did not report the field at all. Four states, none collapsed.
        "urlhaus_url_status": url_status,
        "urlhaus_online": True if url_status == URL_STATUS_ONLINE else (None if url_status is None else False),
        "urlhaus_threat": _as_str(record.get("threat")),
        "urlhaus_tags": _as_str_list(record.get("tags")),
        "urlhaus_date_added": _as_str(record.get("date_added")),
        "urlhaus_last_online": _as_str(record.get("last_online")),
        "urlhaus_reporter": _as_str(record.get("reporter")),
        "urlhaus_larted": _as_bool(record.get("larted")),
        "urlhaus_takedown_time_seconds": _as_int(record.get("takedown_time_seconds")),
        "urlhaus_blacklists": _blacklists(record.get("blacklists")),
        "urlhaus_payload_count": len(payloads),
        "urlhaus_payloads": payloads[:MAX_PAYLOAD_RECORDS],
        "urlhaus_payloads_truncated": len(payloads) > MAX_PAYLOAD_RECORDS,
        # The attribution. Distinct malware families named across the payloads served from this
        # URL -- the field a scoring lane should read before any count.
        "urlhaus_signatures": _distinct([payload.get("signature") for payload in payloads]),
        "urlhaus_payload_first_seen": bounds["first"],
        "urlhaus_payload_last_seen": bounds["last"],
    }


def _urlhaus_host_payload(body: Any) -> Dict[str, Any]:
    """Shape a URLhaus host-information response into the provider payload."""
    record = _as_dict(body)
    urls = [entry for entry in (_url_record(item) for item in _as_list(record.get("urls"))) if entry is not None]
    online = sum(1 for entry in urls if entry.get("url_status") == URL_STATUS_ONLINE)
    return {
        "urlhaus_reference": _as_str(record.get("urlhaus_reference")),
        "urlhaus_host": _as_str(record.get("host")),
        "urlhaus_firstseen": _as_str(record.get("firstseen")),
        # The provider's own total for the host. Authoritative, and independent of how many
        # records the response actually carried.
        "urlhaus_url_count": _as_int(record.get("url_count")),
        "urlhaus_blacklists": _blacklists(record.get("blacklists")),
        "urlhaus_urls_returned": len(urls),
        "urlhaus_urls": urls[:MAX_URL_RECORDS],
        "urlhaus_urls_truncated": len(urls) > MAX_URL_RECORDS,
        # Counted over every record the response carried, before the display cap. It is a FLOOR
        # on the number of URLs still serving from this host, not the total: abuse.ch does not
        # document whether the response returns every URL it holds, so a consumer must read this
        # as "at least this many", which is what the name says.
        "urlhaus_online_urls_in_response": online,
        "urlhaus_online": True if online else (None if not urls else False),
        "urlhaus_threats": _distinct([entry.get("threat") for entry in urls]),
        "urlhaus_tags": _distinct([tag for entry in urls for tag in (entry.get("tags") or [])]),
        "urlhaus_reporters": _distinct([entry.get("reporter") for entry in urls]),
    }


# --------------------------------------------------------------------------------------
# ThreatFox extraction
# --------------------------------------------------------------------------------------


def _strip_brackets(value: str) -> str:
    """``[2001:db8::1]`` -> ``2001:db8::1``. Left alone when it is not bracketed."""
    if len(value) > 2 and value.startswith("[") and value.endswith("]"):
        return value[1:-1]
    return value


def _ioc_matches_term(ioc: str, term: str) -> bool:
    """Does a wildcard-search result actually describe the indicator that was searched for?

    ThreatFox stores command-and-control indicators as ``ip:port``, so an exact-match search for
    a bare address returns nothing while the wildcard search returns the rows that matter. The
    wildcard is a substring match, though, which means a search for ``8.8.8.8`` can also return
    ``18.8.8.80``. Issuing the broad query and narrowing here keeps the recall without
    inheriting the false positives.

    Accepted: the IOC equal to the term, or the term with a numeric port appended (bracketed
    IPv6 included). Everything else is discarded and counted.
    """
    left = ioc.strip().lower()
    right = term.strip().lower()
    if not left or not right:
        return False
    if left == right:
        return True
    head, separator, tail = left.rpartition(":")
    if not separator or not tail.isdigit() or not head:
        return False
    return head == right or _strip_brackets(head) == _strip_brackets(right)


def _ioc_record(entry: Any) -> Optional[Dict[str, Any]]:
    """One ThreatFox IOC.

    ``malware_printable`` and ``confidence_level`` are the two fields that make this a finding
    rather than a data point: a named family plus abuse.ch's own confidence in the attribution.
    Sample references are reduced to their hashes -- the sample pages they link to are on a
    host this tool neither contacts nor allowlists, and a report should not carry a link whose
    only use is to go and get malware.
    """
    if not isinstance(entry, dict):
        return None
    samples = [
        {"md5": _as_str(sample.get("md5_hash")), "sha256": _as_str(sample.get("sha256_hash"))}
        for sample in _as_list(entry.get("malware_samples"))
        if isinstance(sample, dict)
    ]
    return {
        "id": _as_str(entry.get("id")),
        "ioc": _as_str(entry.get("ioc")),
        "ioc_type": _as_str(entry.get("ioc_type")),
        "threat_type": _as_str(entry.get("threat_type")),
        "threat_type_desc": _as_str(entry.get("threat_type_desc")),
        "malware": _as_str(entry.get("malware")),
        "malware_printable": _as_str(entry.get("malware_printable")),
        "malware_alias": _as_str(entry.get("malware_alias")),
        "malware_malpedia": _as_str(entry.get("malware_malpedia")),
        "confidence_level": _as_int(entry.get("confidence_level")),
        "first_seen": _as_str(entry.get("first_seen")),
        "last_seen": _as_str(entry.get("last_seen")),
        "reporter": _as_str(entry.get("reporter")),
        "reference": _as_str(entry.get("reference")),
        "tags": _as_str_list(entry.get("tags")),
        "malware_sample_count": len(samples),
        "malware_sample_hashes": samples or None,
    }


def _threatfox_payload(body: Any, *, search_term: str, exact_match: bool) -> Dict[str, Any]:
    """Shape a ThreatFox ``search_ioc`` response, discarding wildcard collisions."""
    returned = [entry for entry in (_ioc_record(item) for item in _as_list(_as_dict(body).get("data"))) if entry]
    matched = [entry for entry in returned if _ioc_matches_term(entry.get("ioc") or "", search_term)]
    confidences = [entry["confidence_level"] for entry in matched if entry.get("confidence_level") is not None]
    first_bounds = _timestamp_bounds([entry.get("first_seen") for entry in matched])
    last_bounds = _timestamp_bounds([entry.get("last_seen") for entry in matched])
    return {
        "threatfox_search_term": search_term,
        "threatfox_exact_match": exact_match,
        "threatfox_ioc_count": len(matched),
        "threatfox_iocs": matched[:MAX_IOC_RECORDS],
        "threatfox_iocs_truncated": len(matched) > MAX_IOC_RECORDS,
        # The honesty field for the wildcard search. Non-zero means ThreatFox returned rows that
        # merely contain the indicator as a substring and this module dropped them.
        "threatfox_returned_count": len(returned),
        "threatfox_discarded_partial_matches": len(returned) - len(matched),
        # The attribution, and the reason a ThreatFox hit outranks a reputation score.
        "threatfox_malware_families": _distinct([entry.get("malware_printable") for entry in matched]),
        "threatfox_malware_ids": _distinct([entry.get("malware") for entry in matched]),
        "threatfox_threat_types": _distinct([entry.get("threat_type") for entry in matched]),
        "threatfox_reporters": _distinct([entry.get("reporter") for entry in matched]),
        "threatfox_tags": _distinct([tag for entry in matched for tag in (entry.get("tags") or [])]),
        "threatfox_confidence_max": max(confidences) if confidences else None,
        "threatfox_confidence_min": min(confidences) if confidences else None,
        "threatfox_first_seen": first_bounds["first"],
        # ThreatFox sends `last_seen: null` on IOCs it has not re-observed, so this is often
        # absent even when `first_seen` is present. Absent means "not re-observed", NOT "gone".
        "threatfox_last_seen": last_bounds["last"],
    }


# --------------------------------------------------------------------------------------
# Provider entry points
#
# Each is a QUERY. The POST verb carries the arguments; it does not ask abuse.ch to go and
# look at anything. See the module docstring.
# --------------------------------------------------------------------------------------


async def urlhaus_url(*, client: httpx.AsyncClient, api_key: Optional[str], url: str) -> Dict[str, Any]:
    """URLhaus URL information: has this exact URL been reported serving malware?

    Form-encoded POST with the ``url`` parameter. A hit carries the payloads served from it,
    which is the strongest single piece of evidence this tool can produce about a URL.
    """
    if not api_key:
        return {"ok": False, "error": MISSING_API_KEY}

    headers = _headers(api_key)

    async def _call() -> Dict[str, Any]:
        response = await client.post(URLHAUS_URL_ENDPOINT, headers=headers, data={"url": url})
        early = _http_envelope(response)
        if early is not None:
            return early
        response.raise_for_status()
        body = _json_body(response)
        if body is None:
            return {"ok": False, "error": "invalid_response", "message": "URLhaus did not return JSON"}
        failure = _status_envelope(body)
        if failure is not None:
            return failure
        return {"ok": True, "data": _urlhaus_url_payload(body)}

    return await with_exponential_backoff(_call)


async def urlhaus_host(*, client: httpx.AsyncClient, api_key: Optional[str], host: str) -> Dict[str, Any]:
    """URLhaus host information: what malware URLs has this IP, hostname or domain served?

    Form-encoded POST with the ``host`` parameter, which the API accepts case-insensitively for
    an IPv4 address, a hostname or a domain -- so the ``ip`` path and the ``domain`` path share
    this one function rather than duplicating it.
    """
    if not api_key:
        return {"ok": False, "error": MISSING_API_KEY}

    headers = _headers(api_key)

    async def _call() -> Dict[str, Any]:
        response = await client.post(URLHAUS_HOST_ENDPOINT, headers=headers, data={"host": host})
        early = _http_envelope(response)
        if early is not None:
            return early
        response.raise_for_status()
        body = _json_body(response)
        if body is None:
            return {"ok": False, "error": "invalid_response", "message": "URLhaus did not return JSON"}
        failure = _status_envelope(body)
        if failure is not None:
            return failure
        return {"ok": True, "data": _urlhaus_host_payload(body)}

    return await with_exponential_backoff(_call)


async def threatfox_search(
    *,
    client: httpx.AsyncClient,
    api_key: Optional[str],
    ioc: str,
    exact_match: bool = False,
) -> Dict[str, Any]:
    """ThreatFox IOC search: is this indicator a known C2, botnet or payload-delivery endpoint?

    JSON POST carrying :data:`THREATFOX_SEARCH_QUERY` as the selector. ``exact_match`` defaults
    to ``False`` -- the wildcard search -- because ThreatFox stores C2 indicators as ``ip:port``
    and an exact search for a bare address returns nothing. The substring collisions the
    wildcard introduces are removed by :func:`_ioc_matches_term` and counted in the payload;
    pass ``exact_match=True`` when the caller already holds the full ``ip:port`` form.
    """
    if not api_key:
        return {"ok": False, "error": MISSING_API_KEY}

    headers = _headers(api_key)
    request_body: Dict[str, Any] = {
        "query": THREATFOX_SEARCH_QUERY,
        "search_term": ioc,
        "exact_match": exact_match,
    }

    async def _call() -> Dict[str, Any]:
        response = await client.post(THREATFOX_ENDPOINT, headers=headers, json=request_body)
        early = _http_envelope(response)
        if early is not None:
            return early
        response.raise_for_status()
        body = _json_body(response)
        if body is None:
            return {"ok": False, "error": "invalid_response", "message": "ThreatFox did not return JSON"}
        failure = _status_envelope(body)
        if failure is not None:
            return failure
        payload = _threatfox_payload(body, search_term=ioc, exact_match=exact_match)
        # `query_status: ok` with every row discarded as a substring collision is a miss, and
        # reporting it as a success would hand the consumer an empty list to render green.
        if payload["threatfox_ioc_count"] == 0:
            return {
                "ok": False,
                "error": "no_results",
                "threatfox_returned_count": payload["threatfox_returned_count"],
                "threatfox_discarded_partial_matches": payload["threatfox_discarded_partial_matches"],
            }
        return {"ok": True, "data": payload}

    return await with_exponential_backoff(_call)


# --------------------------------------------------------------------------------------
# Composed lookups
#
# One abuse.ch call per indicator from the orchestrator's point of view, two requests
# underneath. Composed here rather than in the orchestrator so that the merge rule -- which
# is where a partial failure gets misreported as a clean result -- is unit-testable without
# an orchestrator.
# --------------------------------------------------------------------------------------


async def _settle(awaitable: Awaitable[Dict[str, Any]]) -> Dict[str, Any]:
    """Await one platform's lookup and turn any exception it raises into a failure envelope.

    Both platforms are asked independently, so a 500 from one must not destroy a hit from the
    other. Without this, a ThreatFox outage silently discards a URLhaus record naming the malware
    family being served right now -- which is the highest-value observation this tool can obtain.

    Two deliberate exclusions:

    * :class:`~tripper_recon.utils.http.PassiveBoundaryViolation` is re-raised. It is a
      programming error meaning some code path tried to contact an unreviewed destination, and
      absorbing it into a provider envelope would hide the one failure that must never be
      handled (``docs/ARCHITECTURE.md`` section 4).
    * ``BaseException`` is not caught, so a deadline cancellation still reaches the orchestrator
      rather than being filed as a provider failure.

    Only the exception's TYPE is carried into the envelope, never ``str(exc)``: httpx embeds the
    request URL in its messages and this package has already been bitten once by a credential
    reaching four output sinks that way (roadmap 0.1).
    """
    try:
        return await awaitable
    except PassiveBoundaryViolation:
        raise
    except httpx.HTTPStatusError as exc:
        return {"ok": False, "error": "http_error", "status": exc.response.status_code}
    except httpx.RequestError as exc:
        return {"ok": False, "error": "request_error", "message": type(exc).__name__}
    except Exception as exc:  # noqa: BLE001 -- classified above, recorded rather than swallowed
        return {"ok": False, "error": "provider_error", "message": type(exc).__name__}


def _merge(
    *,
    urlhaus: Dict[str, Any],
    threatfox: Dict[str, Any],
) -> Dict[str, Any]:
    """Combine the two envelopes into one, without letting either failure read as clean.

    Rules, in order:

    * Either side ``ok`` -> success. The failing side's slug is carried in the payload as
      ``abusech_<platform>_error`` so a consumer can see that half the question went unanswered
      rather than inferring it from missing keys.
    * Both failed with the same slug -> that slug. Two ``no_results`` is one honest
      ``no_results``; two ``unauthorized`` is one honest ``unauthorized``.
    * Both failed differently -> ``lookup_failed``, with both slugs carried. Collapsing an
      ``unauthorized`` and a ``no_results`` into either one of them would be a lie in one
      direction or the other.
    """
    urlhaus_ok = bool(urlhaus.get("ok"))
    threatfox_ok = bool(threatfox.get("ok"))
    urlhaus_error = None if urlhaus_ok else _as_str(urlhaus.get("error"))
    threatfox_error = None if threatfox_ok else _as_str(threatfox.get("error"))

    if not urlhaus_ok and not threatfox_ok:
        if urlhaus_error is not None and urlhaus_error == threatfox_error:
            return {"ok": False, "error": urlhaus_error}
        return {
            "ok": False,
            "error": "lookup_failed",
            "urlhaus_error": urlhaus_error,
            "threatfox_error": threatfox_error,
        }

    data: Dict[str, Any] = {}
    sources: List[str] = []
    if urlhaus_ok:
        data.update(_as_dict(urlhaus.get("data")))
        sources.append("urlhaus")
    if threatfox_ok:
        data.update(_as_dict(threatfox.get("data")))
        sources.append("threatfox")

    data["abusech_sources"] = sources
    data["abusech_urlhaus_error"] = urlhaus_error
    data["abusech_threatfox_error"] = threatfox_error
    # The two fields a scoring lane should read first. `abusech_actor_attribution` is the union
    # of the malware families URLhaus saw served and the families ThreatFox attributes the
    # indicator to; `abusech_online` is True only when a platform positively says the indicator
    # is live now, and stays None when neither platform spoke to liveness at all.
    data["abusech_actor_attribution"] = _distinct(
        list(data.get("urlhaus_signatures") or []) + list(data.get("threatfox_malware_families") or [])
    )
    data["abusech_online"] = data.get("urlhaus_online")
    return {"ok": True, "data": data}


async def abusech_url_summary(*, client: httpx.AsyncClient, api_key: Optional[str], url: str) -> Dict[str, Any]:
    """URLhaus URL record plus a ThreatFox search on the same URL. Two queries, no submission.

    Both platforms index URLs, and they index different ones: URLhaus is malware-distribution
    URLs somebody reported, ThreatFox is IOCs somebody submitted with an actor attached. Asking
    only one of them answers half the question.
    """
    if not api_key:
        return {"ok": False, "error": MISSING_API_KEY}
    urlhaus = await _settle(urlhaus_url(client=client, api_key=api_key, url=url))
    threatfox = await _settle(threatfox_search(client=client, api_key=api_key, ioc=url, exact_match=True))
    return _merge(urlhaus=urlhaus, threatfox=threatfox)


async def abusech_host_summary(*, client: httpx.AsyncClient, api_key: Optional[str], host: str) -> Dict[str, Any]:
    """URLhaus host record plus a ThreatFox search, for an IP address, hostname or domain.

    The ThreatFox side runs as a wildcard search so that ``ip:port`` C2 records are found; see
    :func:`threatfox_search` and :func:`_ioc_matches_term` for what that does and does not
    admit.
    """
    if not api_key:
        return {"ok": False, "error": MISSING_API_KEY}
    urlhaus = await _settle(urlhaus_host(client=client, api_key=api_key, host=host))
    threatfox = await _settle(threatfox_search(client=client, api_key=api_key, ioc=host, exact_match=False))
    return _merge(urlhaus=urlhaus, threatfox=threatfox)
