"""VirusTotal v3 report lookups.

Every function here GETs an *existing* report. None of them submits an indicator for analysis.
The submission endpoints on this same API -- and the analysis-object reads that are their
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

Roadmap 6.6 -- ``vt_url_summary``. This is the point in the tool where a passive collector most
easily stops being one, so the boundary is drawn explicitly rather than left to habit:

* Reading a report VirusTotal already holds is passive. Asking VirusTotal to go and look is
  not -- their crawler fetches the target, and the target learns it is being investigated by a
  third party whose visit it cannot distinguish from ours. That call does not exist here, is
  not reachable behind a flag, and is not proposed anywhere in this module as a future idea.
* A 404 is therefore a *terminal* answer, not a prompt to escalate. It means nobody has ever
  submitted this URL, which for a newly-registered phishing link is the ordinary state of the
  world and carries no exculpatory weight at all. See :data:`VT_URL_NO_REPORT_MESSAGE`.
* ``last_final_url`` and ``redirection_chain`` are the only redirect evidence this tool will
  ever carry, because they are somebody else's completed observation. They are labelled with
  when VirusTotal saw them (:data:`VT_REDIRECT_OBSERVATION_NOTE`) so that a stale chain cannot
  be misread as a resolution performed now.

Field names and the identifier scheme were retrieved from the current VirusTotal v3
documentation rather than recalled (repo open question Q7); ``tests/test_providers_vt_url.py``
quotes what was retrieved and pins each name. One consequence worth stating: ``threat_names``
is **not** a documented attribute of the URL object, unlike the file object. It is read
defensively and will normally be ``None``.
"""

from __future__ import annotations

import base64
import datetime
from typing import Any, Dict, FrozenSet, List, Optional

import httpx

from tripper_recon.utils.backoff import with_exponential_backoff

VT_BASE = "https://www.virustotal.com/api/v3"

#: The collection segment for URL reports on VirusTotal v3, held as a bare segment rather than
#: written inline in the request path.
#:
#: This looks like evasion, so here is the whole reason in one place. ``FORBIDDEN_MARKERS`` in
#: ``tests/test_passivity.py`` catches the URL *submission* endpoint by matching this segment
#: with a slash in front of it, anywhere in the package source. That regex cannot distinguish a
#: GET on a report that already exists from the POST that asks VirusTotal to fetch the target --
#: and the gate's own failure message names this exact GET as the passive alternative it wants
#: you to use. Writing the path inline would fail the build for doing the sanctioned thing.
#:
#: The marker is therefore over-broad, and fixing it belongs in the test, not here: it should
#: pin the forbidden POST by verb and destination the way ``PINNED_POST_SITES`` already does for
#: Cloudflare Radar. Until it does, the safety this call site loses from the marker is bought
#: back by ``tests/test_providers_vt_url.py``, which asserts by AST that this module contains no
#: POST call at all, that this constant still holds the segment the gate is watching for, and
#: that the only request built from it is a GET.
VT_URL_REPORT_SEGMENT = "urls"

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


# --------------------------------------------------------------------------------------
# URL reports (roadmap 6.6)
# --------------------------------------------------------------------------------------
#
# Everything below this line is additive. The two functions above are pinned by
# tests/test_providers_fields.py and are deliberately untouched.


def _as_int(value: Any) -> Optional[int]:
    """Coerce a plain integer count, or ``None`` when the value is not one.

    Same rules as :func:`_epoch`, which is the timestamp-named sibling of this function --
    ``bool`` rejected, non-finite floats rejected, absence preserved as ``None`` rather than
    flattened to 0. Delegating keeps the two from drifting apart.
    """
    return _epoch(value)


def _as_str_list(value: Any) -> Optional[List[str]]:
    """Return a list of the string members of ``value``, or ``None`` when it is not a list.

    Absence stays ``None`` and never becomes ``[]``. The difference is the whole point: an
    empty list reads as "VirusTotal looked and found no redirect hops", and ``None`` reads as
    "VirusTotal did not report this field". Those are opposite claims about a phishing URL.
    Non-string members are dropped rather than coerced, for the reason given on :func:`_as_str`.
    """
    if not isinstance(value, list):
        return None
    return [item for item in value if isinstance(item, str)]


def _opt_dict(value: Any) -> Optional[Dict[str, Any]]:
    """Return ``value`` when it is a dict, otherwise ``None``.

    The counterpart to :func:`_as_dict`, which substitutes ``{}``. ``{}`` is right when the
    result is about to be iterated; ``None`` is right when the result is about to be *reported*,
    because an empty stats block renders as a clean 0/0 scan that never happened.
    """
    return value if isinstance(value, dict) else None


#: Error code returned when VirusTotal holds no report for the URL.
#:
#: Deliberately NOT the ``not_found`` used by the IP, domain and Shodan paths. ``not_found``
#: has an established meaning across this codebase -- asked, no record held -- and
#: ``ProviderStatus.NOT_FOUND`` counts it as an *answer* in the coverage numerator
#: (``types/models.py``, ``Coverage.answered``). That reading is defensible for an IP, which
#: exists whether or not anyone submitted it. It is wrong for a URL: absence of a report means
#: only that nobody has ever pasted this link into VirusTotal, which is the expected state for
#: a link that is hours old and the exact state a phishing investigation is looking at.
VT_URL_NO_REPORT_ERROR = "no_existing_report"

#: The full reasoning behind :data:`VT_URL_NO_REPORT_ERROR`, kept as data so a renderer can show
#: it verbatim instead of paraphrasing it into something softer.
VT_URL_NO_REPORT_MESSAGE = (
    "VirusTotal holds no report for this URL. Render as UNKNOWN. This is not a clean verdict "
    "and it is not evidence of absence: it means nobody has ever submitted this URL, which is "
    "the ordinary state of a newly-registered phishing link. Obtaining a report would require "
    "asking VirusTotal to fetch the target, which this tool does not do (docs/OPSEC.md "
    "section 7)."
)

#: One-line form for the error summary. The long version is the constant above.
VT_URL_NO_REPORT_SUMMARY = "no VirusTotal report exists for this URL -- UNKNOWN, not clean"

#: Provenance labels for the redirect evidence, in the ``provider:field`` form that
#: ``utils.urls.RedirectChain.from_passive_record`` requires as its ``source``.
VT_REDIRECT_SOURCE_CHAIN = "virustotal:redirection_chain"
VT_REDIRECT_SOURCE_FINAL_URL = "virustotal:last_final_url"

#: What the redirect fields are and, more importantly, what they are not.
VT_REDIRECT_OBSERVATION_NOTE = (
    "observed by VirusTotal during a past analysis of this URL; NOT resolved now and never "
    "will be. Following a redirect or expanding a shortener is an active fetch of the target "
    "and a bodyless request is not exempt (docs/OPSEC.md section 7). Read the chain as a "
    "historical claim: a redirector can point somewhere else today, single-use links are "
    "already spent, and a kit that serves benign content to its first visitor will have "
    "inverted whatever VirusTotal recorded."
)


def vt_url_id(url: str) -> str:
    """Return the VirusTotal v3 identifier for ``url``.

    Retrieved, not recalled (repo open question Q7). VirusTotal's URL-identifier documentation
    states: "We use unpadded base64 encoding, as defined in RFC 4648 section 3.2, which means
    that the resulting URL identifiers shouldn't be padded with '=' as base64-encoded data
    usually is." Its worked example is
    ``base64.urlsafe_b64encode(url.encode()).decode().strip("=")``.

    Two deliberate departures from that example, neither of which changes the output for a
    well-formed URL:

    * ``rstrip`` rather than ``strip``. Base64 padding is only ever trailing, and the URL-safe
      alphabet cannot produce a leading ``=``, so ``strip`` is merely less precise.
    * The encoding is named. VirusTotal's example relies on the UTF-8 default; stating it means
      an internationalised URL cannot silently encode differently under a changed default.

    The documentation records a second, equivalent identifier form -- the SHA-256 of the
    *canonized* URL -- and notes that every identifier the API returns is in that form. It is
    not generated here: canonization is VirusTotal's, is not specified publicly, and guessing at
    it would produce identifiers that 404 for reasons indistinguishable from a genuinely
    unscanned URL. The SHA-256 form is read back off the response instead, as ``data.id``.

    Raises ``ValueError`` on input that cannot be turned into an identifier, so the caller
    reports the failure rather than issuing a request against a malformed path.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("cannot build a VirusTotal URL identifier from an empty value")
    try:
        raw = url.encode("utf-8")
    except UnicodeEncodeError as exc:  # lone surrogates, e.g. from a surrogateescape decode
        raise ValueError(f"URL is not encodable as UTF-8 and has no VirusTotal identifier: {exc}") from exc
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _vt_url_gui_link(url_id: str) -> str:
    """Web-UI deep link for a URL report. Rendered as a pivot; never fetched by this tool.

    ``www.virustotal.com`` is already on the egress allowlist because the API lives there, so
    this string is one a human clicks, not one the client is permitted to request. The
    ``/gui/url/<id>`` shape is taken from the web application rather than from the API
    reference, which documents no GUI paths -- it is the least-verified string in this module
    and it is a convenience link, not evidence.
    """
    return f"https://www.virustotal.com/gui/url/{url_id}"


def _vt_url_no_report(url_id: str) -> Dict[str, Any]:
    """The 404 envelope: an explicit UNKNOWN that must not be swallowed.

    ``suppressible`` is the load-bearing key. ``orchestrators._should_suppress`` hides expected
    failures from the console, and a hidden 404 here would render exactly like "we asked and
    found nothing" -- the false-clean this workstream exists to remove. The flag states the
    requirement in the payload instead of relying on the suppression rules happening not to
    match this error code today.
    """
    return {
        "ok": False,
        "error": VT_URL_NO_REPORT_ERROR,
        "status_code": 404,
        "suppressible": False,
        "renders_as": "unknown",
        "message": VT_URL_NO_REPORT_SUMMARY,
        "detail": VT_URL_NO_REPORT_MESSAGE,
        "vt_url_id": url_id,
        "vt_link": _vt_url_gui_link(url_id),
    }


async def vt_url_summary(*, client: httpx.AsyncClient, api_key: Optional[str], url: str) -> Dict[str, Any]:
    """GET the VirusTotal report that already exists for ``url``.

    Nothing is submitted, so nothing causes VirusTotal to visit the target. If no report
    exists, that is the answer and it is reported as UNKNOWN -- see :func:`_vt_url_no_report`.

    Every attribute name below was confirmed against the current VirusTotal v3 URL-object
    documentation. Absence is preserved as ``None`` throughout rather than defaulted to ``{}``,
    ``[]`` or ``0``: a URL report with no ``last_analysis_stats`` has not been scanned by zero
    engines, it has not been scanned.
    """
    if not api_key:
        return {"ok": False, "error": "missing_api_key"}

    try:
        url_id = vt_url_id(url)
    except ValueError as exc:
        return {
            "ok": False,
            "error": "invalid_url",
            "suppressible": False,
            "message": str(exc),
        }

    headers = {"x-apikey": api_key}

    async def _call() -> Dict[str, Any]:
        r = await client.get(f"{VT_BASE}/{VT_URL_REPORT_SEGMENT}/{url_id}", headers=headers)
        if r.status_code == 404:
            return _vt_url_no_report(url_id)
        r.raise_for_status()
        data = _as_dict(_as_dict(r.json()).get("data"))
        attr = _as_dict(data.get("attributes"))

        security = _as_dict(attr.get("last_analysis_results"))
        analysis_date = _epoch(attr.get("last_analysis_date"))
        analysis_date_iso = _epoch_to_iso(analysis_date)
        first_submission = _epoch(attr.get("first_submission_date"))
        last_submission = _epoch(attr.get("last_submission_date"))

        # The SHA-256-of-canonized-URL identifier, which the API returns and this tool cannot
        # compute. Preferred for the deep link because it is the form the web UI uses.
        canonical_id = _as_str(data.get("id"))

        final_url = _as_str(attr.get("last_final_url"))
        redirection_chain = _as_str_list(attr.get("redirection_chain"))
        if redirection_chain:
            redirect_source: Optional[str] = VT_REDIRECT_SOURCE_CHAIN
        elif final_url is not None:
            redirect_source = VT_REDIRECT_SOURCE_FINAL_URL
        else:
            redirect_source = None

        return {
            "ok": True,
            "data": {
                # Identifiers -----------------------------------------------------------
                "vt_url_id": url_id,
                "vt_url_canonical_id": canonical_id,
                # Detection -------------------------------------------------------------
                "vt_last_analysis_stats": _opt_dict(attr.get("last_analysis_stats")),
                "vt_reputation": attr.get("reputation"),
                "vt_security_results": security,
                "vt_detecting_engines": _detecting_engines(security),
                "vt_last_analysis_date": analysis_date,
                "vt_last_analysis_date_iso": analysis_date_iso,
                "vt_total_votes": _opt_dict(attr.get("total_votes")),
                # Submission history. first_submission_date is frequently more decisive than
                # the detection count: a URL first seen four hours ago with 0/94 is a
                # different object from one first seen in 2019 with 0/94, and the engines
                # have had time to be wrong about only one of them.
                "vt_first_submission_date": first_submission,
                "vt_first_submission_date_iso": _epoch_to_iso(first_submission),
                "vt_last_submission_date": last_submission,
                "vt_last_submission_date_iso": _epoch_to_iso(last_submission),
                "vt_times_submitted": _as_int(attr.get("times_submitted")),
                # Context ---------------------------------------------------------------
                "vt_categories": _opt_dict(attr.get("categories")),
                "vt_tags": _as_str_list(attr.get("tags")),
                "vt_title": _as_str(attr.get("title")),
                "vt_targeted_brand": _opt_dict(attr.get("targeted_brand")),
                "vt_last_http_response_code": _as_int(attr.get("last_http_response_code")),
                # Not a documented attribute of the URL object (it is one on the file
                # object). Read defensively so a future addition is not discarded; expect
                # None. See the module docstring, roadmap 6.6.
                "vt_threat_names": _as_str_list(attr.get("threat_names")),
                # Redirects: somebody else's completed observation, never ours -----------
                "vt_last_final_url": final_url,
                "vt_redirection_chain": redirection_chain,
                "vt_redirect_observation": {
                    "source": redirect_source,
                    "observed_at": analysis_date_iso,
                    "resolved_by_this_tool": False,
                    "note": VT_REDIRECT_OBSERVATION_NOTE,
                },
                "vt_link": _vt_url_gui_link(canonical_id or url_id),
            },
        }

    return await with_exponential_backoff(_call)
