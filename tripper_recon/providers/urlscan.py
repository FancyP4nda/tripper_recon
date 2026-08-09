"""urlscan.io -- reading scans somebody else already ran. Roadmap 6.7.

This module is the passive answer to the redirect-chain problem. A redirect chain can only be
observed by loading the page, and loading the page is an active fetch of the target -- ``HEAD``
included, because the target's web server logs the request and its source either way. So this
tool never loads it. It reads the chain out of a scan that a *different* party already completed,
which costs the target nothing and tells them nothing.

**Two endpoints, both ``GET``, both reads of data urlscan already holds.**

* Search -- ``GET https://urlscan.io/api/v1/search/?q=<ElasticSearch query string>``.
  "You can use the same ElasticSearch syntax to search for scans as on the Search page."
  (https://urlscan.io/docs/api/)
* Result -- ``GET https://urlscan.io/api/v1/result/$uuid/``, the JSON for one finished scan
  (https://urlscan.io/docs/api/).

The submission endpoint on this same API is forbidden here, permanently and without a flag. It
instructs urlscan to load the target in a real browser from urlscan infrastructure and, unless
explicitly made private, publishes the resulting scan -- so the target learns they are being
looked at, and so does everyone reading the public feed. It is named, with the reason, in
``docs/OPSEC.md`` section 7 and in ``tests/test_passivity.py``, which scans this package for it on
every run; that is why this docstring does not spell the path out a third time. The same applies
to the screenshot and DOM download routes: this module emits the screenshot **link** and never
retrieves it.

**Every scan read here is somebody else's, and its DATE is the load-bearing field.** A two-year-old
scan describes infrastructure that may have been re-pointed, re-hosted, or taken down since. That
is the specific failure mode this module is written against, so ``urlscan_scan_date`` is the first
key of every result payload, an age in days is computed beside it, and
:data:`STALE_AFTER_DAYS` marks the point past which the payload says so in a boolean rather than
leaving the analyst to do the subtraction.

**Public scans only.** ``task.visibility`` "can be one of ``public``, ``unlisted``, or ``private``"
(docs.urlscan.io/pages/search-api-reference). Search is filtered to ``public`` in the query
*and* again on the parsed response, and :func:`urlscan_result` refuses a scan whose visibility is
anything else. An unlisted scan is frequently somebody's live investigation; copying it into a
report is a disclosure this tool has no right to make.

**API key.** urlscan's guidance is "Use your API key for all API requests (submit, search,
retrieve), otherwise you're subject to quotas for unauthenticated users"
(docs.urlscan.io/pages/api-best-practices). Unauthenticated search is therefore possible,
and this module still requires a key: an anonymous query is quota-starved, un-attributable, and
indistinguishable from the scraping that the same document prohibits ("Do not attempt to mirror or
scrape our data wholesale"). Missing key returns the ``missing_api_key`` envelope rather than
raising, as every other provider here does.

**Rate limits.** urlscan applies "separate limits per minute, per hour and per day for each
action" and answers ``HTTP 429`` past them, advertising the state in ``X-Rate-Limit-*`` response
headers (docs.urlscan.io/pages/api-rate-limits). Its best-practice page asks for
"exponential backoffs and limit concurrency for all types of requests. Respect HTTP 429 response
codes!" -- which is exactly what :func:`~tripper_recon.utils.backoff.with_exponential_backoff`
already provides, including ``Retry-After`` handling, so every call below is wrapped in it. The
same page asks callers to "Limit your searches by date if possible", which is what the
``max_age_days`` argument on the search functions is for.

A note on the citations below: references to ``docs.urlscan.io`` are written without a scheme,
the same way ``utils/backoff.py`` cites RFC 9110 by number rather than by URL. The passivity gate
allowlists every absolute URL literal in this package, and ``docs.urlscan.io`` is a host this tool
never contacts. Keeping it out of the URL-literal scanner leaves exactly one new allowlist entry
-- ``urlscan.io``, the host actually called -- rather than two, one of which would be a standing
permission for a destination no provider uses.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff

URLSCAN_BASE = "https://urlscan.io/api/v1"

#: Where a screenshot for a finished scan lives. Documented at https://urlscan.io/docs/api/ as
#: ``curl https://urlscan.io/screenshots/$uuid.png``. Used to BUILD A LINK only -- nothing in this
#: package retrieves it. It is included because an analyst wants to see the page without visiting
#: it, and a link into urlscan's own copy is how that happens without touching the target.
URLSCAN_SCREENSHOT_BASE = "https://urlscan.io/screenshots"

#: Self-imposed ceiling on ``size``, not a limit quoted from the API. urlscan asks callers not to
#: "mirror or scrape our data wholesale" (docs.urlscan.io/pages/api-best-practices); a
#: hundred scans is more than enough to pick a recent one and far short of bulk collection.
MAX_SEARCH_SIZE = 100

#: Enough candidates to skip a few unlisted or failed scans and still find a usable public one.
DEFAULT_SEARCH_SIZE = 10

#: The only ``task.visibility`` value this module will read.
PUBLIC_VISIBILITY = "public"

#: Age past which a scan is flagged stale. This is a JUDGEMENT, not a provider fact: ninety days
#: is roughly the point at which hosting, TLS certificates and redirect targets have turned over
#: often enough that the scan describes history rather than current state. It is exposed in the
#: payload as ``urlscan_scan_staleness_threshold_days`` so a consumer can disagree with it
#: explicitly instead of inheriting it silently.
STALE_AFTER_DAYS = 90.0

#: ElasticSearch query-string reserved characters, per
#: docs.urlscan.io/pages/search-general: ``+ - = && || > < ! ( ) { } [ ] ^ " ~ * ? : \ /``.
#: Only the two that survive inside a quoted phrase need escaping, and both are escaped in
#: :func:`_quoted_term`; the rest are neutralised by the quoting itself.
_PHRASE_ESCAPES = ("\\", '"')


# --------------------------------------------------------------------------------------
# Coercion helpers
#
# Every field read below goes through one of these. These are third-party response bodies:
# urlscan's own documentation warns "Make sure your response parser can handle missing fields"
# and that detailed fields may change without notice (https://urlscan.io/docs/result/). A
# missing field must read as absent, never as a benign value -- rendering "we did not learn
# this" identically to "we learned it and it was fine" is the defect this whole package is
# written against.
# --------------------------------------------------------------------------------------


def _as_dict(value: Any) -> Dict[str, Any]:
    """Return ``value`` when it is a dict, otherwise an empty dict."""
    return value if isinstance(value, dict) else {}


def _as_str(value: Any) -> Optional[str]:
    """Return a non-empty string, otherwise ``None``.

    Deliberately not ``str(value)``: coercing a dict or a list into text would manufacture a
    plausible-looking URL or timestamp out of a malformed response.
    """
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _as_int(value: Any) -> Optional[int]:
    """Return an int, or ``None``. ``bool`` is rejected -- ``True`` is an ``int`` to Python."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _as_bool(value: Any) -> Optional[bool]:
    """Return a bool, or ``None``. A missing verdict flag is unknown, not ``False``."""
    return value if isinstance(value, bool) else None


def _as_number(value: Any) -> Optional[float]:
    """Return a finite number as a float, or ``None``."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    numeric = float(value)
    # NaN and the infinities are not scores. `!=` self is the NaN test that needs no import.
    if numeric != numeric or numeric in (float("inf"), float("-inf")):
        return None
    return numeric


def _str_list(value: Any) -> List[str]:
    """The non-empty strings in ``value``, deduplicated and sorted for a deterministic diff.

    Sorting rather than preserving order is deliberate for the ``lists.*`` fields: they are
    membership sets, two runs over the same scan must diff cleanly, and urlscan does not
    document an ordering guarantee for them. The redirect chain is the exception and is built
    elsewhere, because for a chain the order *is* the evidence.
    """
    if not isinstance(value, list):
        return []
    items = {stripped for item in value if isinstance(item, str) and (stripped := item.strip())}
    return sorted(items)


def _quoted_term(value: str) -> str:
    """Quote a value for use as an ElasticSearch query-string phrase.

    urlscan's search takes an "ElasticSearch Query String" in which
    ``+ - = && || > < ! ( ) { } [ ] ^ " ~ * ? : \\ /`` are reserved
    (docs.urlscan.io/pages/search-general). A URL under investigation contains several of
    them by construction -- ``:``, ``/``, and frequently ``?`` and ``-``. Wrapping the value in a
    quoted phrase neutralises all of them except the quote and the backslash, which are escaped
    here. An unescaped indicator would otherwise turn into a syntactically valid *different*
    query, and a query returning somebody else's scans is worse than one returning none.
    """
    escaped = value
    for character in _PHRASE_ESCAPES:
        escaped = escaped.replace(character, "\\" + character)
    return f'"{escaped}"'


def _public_only(clause: str, *, max_age_days: Optional[int]) -> str:
    """Wrap a field clause with the public-visibility filter and an optional date bound.

    The date bound implements urlscan's own request to "Limit your searches by date if possible,
    e.g. query just the last 24 hours or seven days"
    (docs.urlscan.io/pages/api-best-practices), using the relative form their search
    documentation gives (``date:>now-7d``).
    """
    parts = [f"({clause})", f"task.visibility:{PUBLIC_VISIBILITY}"]
    if max_age_days is not None and max_age_days > 0:
        parts.append(f"date:>now-{int(max_age_days)}d")
    return " AND ".join(parts)


# --------------------------------------------------------------------------------------
# Scan freshness
# --------------------------------------------------------------------------------------


def _parse_iso8601(value: Any) -> Optional[datetime.datetime]:
    """Parse urlscan's ``task.time`` ("ISO-8601 timestamp") into an aware datetime, or ``None``.

    Two accommodations, both for real responses rather than for the specification:
    ``Z`` is rewritten to ``+00:00`` because ``fromisoformat`` on Python 3.10 rejects it, and a
    timestamp with an odd number of fractional-second digits is retried with the fraction removed
    for the same reason. A value that survives neither is reported as unparseable rather than
    guessed at -- a wrong scan date is worse than no scan date.
    """
    text = _as_str(value)
    if text is None:
        return None
    normalized = text[:-1] + "+00:00" if text[-1] in "Zz" else text
    for candidate in (normalized, _without_fractional_seconds(normalized)):
        if candidate is None:
            continue
        try:
            parsed = datetime.datetime.fromisoformat(candidate)
        except ValueError:
            continue
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=datetime.timezone.utc)
    return None


def _without_fractional_seconds(text: str) -> Optional[str]:
    """``2020-01-01T00:00:00.12345+00:00`` -> ``2020-01-01T00:00:00+00:00``, else ``None``."""
    dot = text.find(".")
    if dot == -1:
        return None
    end = dot + 1
    while end < len(text) and text[end].isdigit():
        end += 1
    return text[:dot] + text[end:]


def _age_days(scan_time: Any, *, now: Optional[datetime.datetime] = None) -> Optional[float]:
    """Age of a scan in days, or ``None`` when its timestamp could not be parsed.

    A negative value is returned as-is rather than clamped to zero. It means the scan is stamped
    in the future, which is a clock-skew or parsing problem worth seeing in the payload, and
    hiding it behind a floor would present a broken timestamp as a fresh scan.
    """
    parsed = _parse_iso8601(scan_time)
    if parsed is None:
        return None
    reference = now if now is not None else datetime.datetime.now(tz=datetime.timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=datetime.timezone.utc)
    return round((reference - parsed).total_seconds() / 86400.0, 2)


def _is_stale(age_days: Optional[float]) -> Optional[bool]:
    """``True`` past :data:`STALE_AFTER_DAYS`, ``False`` inside it, ``None`` when age is unknown.

    Unknown stays ``None``. An unparseable scan date is not a fresh scan, and returning ``False``
    here would say it was.
    """
    if age_days is None:
        return None
    return age_days > STALE_AFTER_DAYS


# --------------------------------------------------------------------------------------
# Response shaping
# --------------------------------------------------------------------------------------


def _result_api_url(uuid: str) -> str:
    return f"{URLSCAN_BASE}/result/{uuid}/"


def _screenshot_url(uuid: str, supplied: Any) -> str:
    """The screenshot LINK for a scan. Never fetched -- see the module docstring.

    urlscan supplies a ``screenshot`` link on search hits; when it is absent the documented
    ``/screenshots/$uuid.png`` form is built instead, so the analyst always gets a working pivot.
    """
    return _as_str(supplied) or f"{URLSCAN_SCREENSHOT_BASE}/{uuid}.png"


def _scan_record(entry: Any, *, now: Optional[datetime.datetime]) -> Optional[Dict[str, Any]]:
    """One search hit, compacted. ``None`` when the hit has no usable UUID or is not public.

    Non-public hits are dropped here as well as filtered in the query. The query filter is the
    efficient control and this one is the correct control: an API key that can see unlisted scans
    changes what the server returns, and only a check on the parsed response can be relied on.
    """
    hit = _as_dict(entry)
    task = _as_dict(hit.get("task"))
    page = _as_dict(hit.get("page"))

    uuid = _as_str(task.get("uuid")) or _as_str(hit.get("_id"))
    if uuid is None:
        return None

    visibility = _as_str(task.get("visibility"))
    if visibility is not None and visibility.lower() != PUBLIC_VISIBILITY:
        return None

    scan_date = _as_str(task.get("time"))
    age = _age_days(scan_date, now=now)
    return {
        "scan_date": scan_date,
        "scan_age_days": age,
        "scan_is_stale": _is_stale(age),
        "uuid": uuid,
        "visibility": visibility,
        "submitted_url": _as_str(task.get("url")),
        "final_url": _as_str(page.get("url")),
        "page_domain": _as_str(page.get("domain")),
        "page_ip": _as_str(page.get("ip")),
        "page_country": _as_str(page.get("country")),
        "result_api_url": _as_str(hit.get("result")) or _result_api_url(uuid),
        "screenshot_url": _screenshot_url(uuid, hit.get("screenshot")),
    }


def _newest_first(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Newest scan first; records with no parseable date sort last.

    Sorting on the parsed age rather than trusting the server's order keeps "the newest public
    scan" a property of the data this module can defend, and undated records must never win that
    position -- an undated scan is the one whose currency cannot be argued for at all.
    """
    return sorted(
        records,
        key=lambda record: (
            record.get("scan_age_days") is None,
            record.get("scan_age_days") if record.get("scan_age_days") is not None else 0.0,
        ),
    )


def _redirect_chain(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The redirect chain urlscan recorded, in order.

    ``data.redirects`` is documented only as the "Redirect chain from submitted URL to final page"
    (https://urlscan.io/docs/result/); the per-entry shape is not pinned, and urlscan warns that
    detailed fields change without notice. So three shapes are accepted -- a bare URL string, a
    dict carrying ``url``, and a dict nesting it under ``response`` -- and anything else is
    skipped rather than partially rendered. Order is preserved: for a chain, the order is the
    evidence.

    Nothing here resolves anything. Every hop in this list was observed by urlscan's browser at
    scan time; this tool did not follow a redirect and will not.
    """
    hops: List[Dict[str, Any]] = []
    redirects = data.get("redirects")
    if not isinstance(redirects, list):
        return hops
    for entry in redirects:
        if isinstance(entry, str):
            url = _as_str(entry)
            if url is not None:
                hops.append({"url": url, "status": None})
            continue
        if not isinstance(entry, dict):
            continue
        response = _as_dict(entry.get("response"))
        url = _as_str(entry.get("url")) or _as_str(response.get("url"))
        if url is None:
            continue
        status = _as_int(entry.get("status")) or _as_int(response.get("status"))
        hops.append({"url": url, "status": status})
    return hops


def _verdicts(verdicts: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """urlscan's own page verdict, or ``None`` when the scan carries none.

    ``None`` and "scored zero" are different states and are kept different. urlscan documents
    ``verdicts.urlscan.score`` as a maliciousness score from -100 to 100 alongside ``categories``
    and ``brands`` (docs.urlscan.io/pages/result-api-reference); ``verdicts.overall`` is
    read the same way when present. A scan with no verdict block returns ``None``, which reads as
    "urlscan did not adjudicate this" rather than "urlscan found nothing".
    """
    overall = _as_dict(verdicts.get("overall"))
    own = _as_dict(verdicts.get("urlscan"))
    if not overall and not own:
        return None
    shaped: Dict[str, Any] = {
        "overall_malicious": _as_bool(overall.get("malicious")),
        "overall_score": _as_number(overall.get("score")),
        "overall_has_verdicts": _as_bool(overall.get("hasVerdicts")),
        "urlscan_malicious": _as_bool(own.get("malicious")),
        "urlscan_score": _as_number(own.get("score")),
        "categories": _str_list(own.get("categories")) or _str_list(overall.get("categories")),
        "brands": _brand_names(own.get("brands")) or _brand_names(overall.get("brands")),
    }
    return shaped


def _brand_names(value: Any) -> List[str]:
    """Brand detections as names. Accepts a list of strings or a list of ``{"name": ...}`` dicts."""
    if not isinstance(value, list):
        return []
    names: List[str] = []
    for entry in value:
        if isinstance(entry, str):
            name = _as_str(entry)
        elif isinstance(entry, dict):
            name = _as_str(entry.get("name")) or _as_str(entry.get("key"))
        else:
            name = None
        if name is not None and name not in names:
            names.append(name)
    return sorted(names)


def _search_payload(body: Any, *, query: str, now: Optional[datetime.datetime]) -> Dict[str, Any]:
    """Shape a search response into the provider ``data`` mapping."""
    envelope = _as_dict(body)
    raw_results = envelope.get("results")
    entries = raw_results if isinstance(raw_results, list) else []
    records = _newest_first([record for record in (_scan_record(e, now=now) for e in entries) if record is not None])
    newest = records[0] if records else None
    return {
        # Date first, deliberately: every consumer of this payload is reading somebody else's
        # observation, and how old it is decides how much weight it can carry.
        "urlscan_newest_scan_date": newest["scan_date"] if newest else None,
        "urlscan_newest_scan_age_days": newest["scan_age_days"] if newest else None,
        "urlscan_newest_scan_is_stale": newest["scan_is_stale"] if newest else None,
        "urlscan_scan_staleness_threshold_days": STALE_AFTER_DAYS,
        "urlscan_query": query,
        "urlscan_total_matches": _as_int(envelope.get("total")),
        "urlscan_has_more": _as_bool(envelope.get("has_more")),
        "urlscan_public_scan_count": len(records),
        # The gap between what the server returned and what survived the public-only filter.
        # Reported rather than silently absorbed: a URL with scans that are all unlisted is a
        # meaningfully different situation from a URL with no scans at all.
        "urlscan_non_public_scans_excluded": max(len(entries) - len(records), 0),
        "urlscan_scans": records,
    }


def _result_payload(body: Any, *, now: Optional[datetime.datetime]) -> Dict[str, Any]:
    """Shape one finished scan into the provider ``data`` mapping."""
    envelope = _as_dict(body)
    task = _as_dict(envelope.get("task"))
    page = _as_dict(envelope.get("page"))
    lists = _as_dict(envelope.get("lists"))
    data = _as_dict(envelope.get("data"))

    uuid = _as_str(task.get("uuid")) or ""
    scan_date = _as_str(task.get("time"))
    age = _age_days(scan_date, now=now)
    submitted = _as_str(task.get("url"))
    final = _as_str(page.get("url"))
    chain = _redirect_chain(data)

    return {
        # Date first. See the module docstring: presenting a stale scan as current state is the
        # failure mode this provider is written against.
        "urlscan_scan_date": scan_date,
        "urlscan_scan_age_days": age,
        "urlscan_scan_is_stale": _is_stale(age),
        "urlscan_scan_staleness_threshold_days": STALE_AFTER_DAYS,
        "urlscan_scan_uuid": uuid or None,
        "urlscan_visibility": _as_str(task.get("visibility")),
        "urlscan_submitted_url": submitted,
        "urlscan_final_url": final,
        # Tri-state on purpose. ``None`` means one of the two URLs is missing, which is not the
        # same as "did not redirect".
        "urlscan_redirected": None if (submitted is None or final is None) else submitted != final,
        "urlscan_redirect_chain": chain,
        "urlscan_redirect_chain_hops": len(chain),
        # The provenance of the chain, carried with it so no consumer has to assume. This tool
        # resolves nothing: the hops above are what urlscan's browser saw at scan time, and are
        # exactly as old as the scan date above.
        "urlscan_redirect_chain_resolved_locally": False,
        "urlscan_redirect_chain_observed_by": "urlscan.io",
        "urlscan_redirect_chain_observed_at": scan_date,
        "urlscan_contacted_domains": _str_list(lists.get("domains")),
        "urlscan_contacted_ips": _str_list(lists.get("ips")),
        "urlscan_contacted_countries": _str_list(lists.get("countries")),
        "urlscan_contacted_url_count": len(_str_list(lists.get("urls"))),
        "urlscan_page_domain": _as_str(page.get("domain")),
        "urlscan_page_ip": _as_str(page.get("ip")),
        "urlscan_page_country": _as_str(page.get("country")),
        "urlscan_page_status": _as_str(page.get("status")) or _as_int(page.get("status")),
        "urlscan_verdict": _verdicts(_as_dict(envelope.get("verdicts"))),
        # A link, never a retrieval. See the module docstring.
        "urlscan_screenshot_url": _screenshot_url(uuid, task.get("screenshotURL")) if uuid else None,
        "urlscan_screenshot_fetched": False,
        "urlscan_report_url": _as_str(task.get("reportURL")),
        "urlscan_result_api_url": _result_api_url(uuid) if uuid else None,
    }


def _headers(api_key: str) -> Dict[str, str]:
    """urlscan authenticates with the ``API-Key`` header and no other name.

    "Use the API-Key HTTP header and not any other header name (e.g. x-api-key)"
    (docs.urlscan.io/guides/quickstart).
    """
    return {"Accept": "application/json", "API-Key": api_key}


def _clamp_size(size: int) -> int:
    return max(1, min(int(size), MAX_SEARCH_SIZE))


# --------------------------------------------------------------------------------------
# Public surface
# --------------------------------------------------------------------------------------


async def urlscan_search(
    *,
    client: httpx.AsyncClient,
    api_key: Optional[str],
    query: str,
    size: int = DEFAULT_SEARCH_SIZE,
    now: Optional[datetime.datetime] = None,
) -> Dict[str, Any]:
    """``GET /search/`` with a caller-supplied ElasticSearch query string.

    The two convenience wrappers below build their own query and are what callers normally want;
    this one exists for the cases they do not cover. It does **not** add the public-visibility
    filter -- a caller composing a raw query owns its clauses -- but the parsed response is still
    filtered to public scans in :func:`_scan_record`, so no unlisted scan reaches the payload by
    either route.

    ``now`` is a test seam. Leaving it ``None`` reads the wall clock, which is what production
    does; passing it makes the computed ages deterministic.
    """
    if not api_key:
        return {"ok": False, "error": "missing_api_key"}

    headers = _headers(api_key)
    params: Dict[str, Any] = {"q": query, "size": _clamp_size(size)}

    async def _call() -> Dict[str, Any]:
        r = await client.get(f"{URLSCAN_BASE}/search/", headers=headers, params=params)
        # A malformed ElasticSearch query is a permanent, actionable outcome, not an exception:
        # retrying it three times burns rate-limit budget against a query that will never parse.
        if r.status_code == 400:
            return {"ok": False, "error": "invalid_query"}
        r.raise_for_status()
        return {"ok": True, "data": _search_payload(r.json(), query=query, now=now)}

    return await with_exponential_backoff(_call)


async def urlscan_search_url(
    *,
    client: httpx.AsyncClient,
    api_key: Optional[str],
    url: str,
    size: int = DEFAULT_SEARCH_SIZE,
    max_age_days: Optional[int] = None,
    now: Optional[datetime.datetime] = None,
) -> Dict[str, Any]:
    """Find public scans of one URL.

    Both ``page.url`` ("URL of the primary page (after redirection)") and ``task.url`` ("The
    original URL that was tasked") are matched, per
    docs.urlscan.io/pages/search-api-reference. Matching only one of them misses half the
    useful hits in each direction: a shortener is found under ``task.url`` and its destination
    under ``page.url``, and which one the analyst holds is not knowable here.
    """
    clause = f"page.url:{_quoted_term(url)} OR task.url:{_quoted_term(url)}"
    return await urlscan_search(
        client=client,
        api_key=api_key,
        query=_public_only(clause, max_age_days=max_age_days),
        size=size,
        now=now,
    )


async def urlscan_search_domain(
    *,
    client: httpx.AsyncClient,
    api_key: Optional[str],
    domain: str,
    size: int = DEFAULT_SEARCH_SIZE,
    max_age_days: Optional[int] = None,
    now: Optional[datetime.datetime] = None,
) -> Dict[str, Any]:
    """Find public scans whose primary page was on one domain.

    ``page.domain`` is "Primary Domain (Analysed as all levels of parent domains)"
    (docs.urlscan.io/pages/search-api-reference). The broader ``domain`` field -- "Any
    domain and subdomain that was contacted" -- is deliberately not used: it matches every scan
    that merely loaded a resource from the domain, which for anything behind a CDN returns the
    CDN's traffic rather than the target's.
    """
    clause = f"page.domain:{_quoted_term(domain)}"
    return await urlscan_search(
        client=client,
        api_key=api_key,
        query=_public_only(clause, max_age_days=max_age_days),
        size=size,
        now=now,
    )


async def urlscan_result(
    *,
    client: httpx.AsyncClient,
    api_key: Optional[str],
    uuid: str,
    now: Optional[datetime.datetime] = None,
) -> Dict[str, Any]:
    """``GET /result/{uuid}/`` -- read one finished scan somebody else ran.

    Refuses any scan whose ``task.visibility`` is present and not ``public``. That is a stricter
    rule than "do not submit": an unlisted scan is often another analyst's live investigation, and
    lifting its contents into a report published elsewhere discloses their work. When visibility
    is absent entirely the scan is read, because urlscan documents that fields can be missing and
    refusing on absence would make the provider useless against older records -- the visibility
    actually observed is carried through in the payload either way.
    """
    if not api_key:
        return {"ok": False, "error": "missing_api_key"}

    headers = _headers(api_key)

    async def _call() -> Dict[str, Any]:
        r = await client.get(f"{URLSCAN_BASE}/result/{uuid}/", headers=headers)
        if r.status_code == 404:
            return {"ok": False, "error": "not_found"}
        r.raise_for_status()
        body = r.json()
        visibility = _as_str(_as_dict(_as_dict(body).get("task")).get("visibility"))
        if visibility is not None and visibility.lower() != PUBLIC_VISIBILITY:
            return {"ok": False, "error": "scan_not_public"}
        return {"ok": True, "data": _result_payload(body, now=now)}

    return await with_exponential_backoff(_call)


async def urlscan_url_summary(
    *,
    client: httpx.AsyncClient,
    api_key: Optional[str],
    url: str,
    size: int = DEFAULT_SEARCH_SIZE,
    max_age_days: Optional[int] = None,
    now: Optional[datetime.datetime] = None,
) -> Dict[str, Any]:
    """Search for public scans of ``url``, then read the newest one. Two ``GET``s, no submission.

    This is the composed call a URL investigation wants: it answers "has anyone already loaded
    this, and what did they see" without loading anything. When no public scan exists the answer
    is ``no_public_scan`` -- **not** an invitation to create one. The absence of a scan is itself
    a finding (a freshly stood-up phishing page frequently has none), and the passive tool's
    correct response to it is to say so.

    On success the payload is the newest scan's extraction merged with the search context, so a
    consumer can see both what was found and how many other scans exist behind it.
    """
    search = await urlscan_search_url(
        client=client,
        api_key=api_key,
        url=url,
        size=size,
        max_age_days=max_age_days,
        now=now,
    )
    if not search.get("ok"):
        return search

    search_data = _as_dict(search.get("data"))
    scans = search_data.get("urlscan_scans")
    records = scans if isinstance(scans, list) else []
    if not records:
        return {"ok": False, "error": "no_public_scan"}

    uuid = _as_str(_as_dict(records[0]).get("uuid"))
    if uuid is None:
        return {"ok": False, "error": "no_public_scan"}

    result = await urlscan_result(client=client, api_key=api_key, uuid=uuid, now=now)
    if not result.get("ok"):
        return result

    merged: Dict[str, Any] = dict(_as_dict(result.get("data")))
    merged.update(
        {
            "urlscan_query": search_data.get("urlscan_query"),
            "urlscan_total_matches": search_data.get("urlscan_total_matches"),
            "urlscan_public_scan_count": search_data.get("urlscan_public_scan_count"),
            "urlscan_non_public_scans_excluded": search_data.get("urlscan_non_public_scans_excluded"),
            "urlscan_other_scans": records[1:],
        }
    )
    return {"ok": True, "data": merged}
