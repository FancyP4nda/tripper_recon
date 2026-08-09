"""Passivity build gate — roadmap item 1.6.

Tripper Recon promises that investigating a target never touches the target. Every other
test in this repo checks that the code does what it says; this file checks that the code
cannot quietly stop being passive.

These are STATIC tests. They parse the package source, they never import a provider and
never open a socket. They exist because the passive boundary is otherwise an authorial
intention with nothing enforcing it (docs/OPSEC.md section 6, gap 1): ``create_client()``
returns a general-purpose ``httpx.AsyncClient`` and nothing stops a future provider module
from pointing it at the thing under investigation.

If one of these fails in CI, the fix is almost never "edit the test". It is either
(a) you added an outbound destination and it needs a deliberate, reviewed entry in
``ALLOWED_HOSTS`` below, or (b) you added something that reaches the target and it must
be removed. Read the failure message; each one names the passive alternative.

KNOWN LIMIT — read this before trusting a green run. A static scan sees URL *literals*. It
cannot see a host assembled at runtime: a request built from a target-derived hostname is a
direct fetch of the target and passes every test in this file. Verified by mutation.

That gap is now covered by its runtime counterpart (roadmap item 2.1, shipped): an httpx
request event hook installed at the single ``create_client()`` construction point, which
checks ``ALLOWED_EGRESS_HOSTS`` against the URL actually about to go out and raises
``PassiveBoundaryViolation`` otherwise. See ``tripper_recon/utils/http.py`` and
``tests/test_http.py``. The two halves are complementary: the static scan fails the build, the
hook fails the run. Neither is a substitute for the other, and
``test_http.test_runtime_allowlist_is_a_subset_of_the_static_allowlist`` fails if the two
allowlists drift apart.

Authority for the constraint: docs/OPSEC.md sections 1, 2 and 7.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Optional

import pytest

# --------------------------------------------------------------------------------------
# Where the source lives
# --------------------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = REPO_ROOT / "tripper_recon"
PROVIDERS_ROOT = PACKAGE_ROOT / "providers"
DNS_MODULE = PACKAGE_ROOT / "utils" / "dns.py"


# --------------------------------------------------------------------------------------
# 1. The egress allowlist
# --------------------------------------------------------------------------------------
#
# Every hostname that may appear in a URL literal anywhere in the package. A host earns a
# place here only if it is a third party that already holds the intelligence — never the
# target, and never anything the target operator can observe.
#
# Adding a host here is a deliberate act with an OPSEC consequence: docs/OPSEC.md section 4
# is the standing warning that every provider learns your egress IP and your indicator list.
# Update docs/OPSEC.md section 2 in the same commit.

ALLOWED_HOSTS: set[str] = {
    # ---- Contacted over HTTP by a provider module --------------------------------------
    # VirusTotal API v3 — VT_BASE, providers/virustotal.py
    "www.virustotal.com",
    # Shodan host lookup — SHODAN_BASE, providers/shodan_api.py
    "api.shodan.io",
    # AbuseIPDB /check — ABUSE_BASE, providers/abuseipdb.py
    "api.abuseipdb.com",
    # IPinfo geo/ASN — IPINFO_BASE, providers/ipinfo.py
    "ipinfo.io",
    # AlienVault OTX API v1 — OTX_BASE, providers/otx.py
    "otx.alienvault.com",
    # Cloudflare Radar GraphQL (RADAR_GRAPHQL_ENDPOINT, providers/cloudflare_radar.py)
    # and Cloudflare Radar BGP REST (CF_BASE, providers/cloudflare_rest.py)
    "api.cloudflare.com",
    # RIPEstat data API — RIPE_BASE, providers/ripestat.py
    "stat.ripe.net",
    # CAIDA AS-Rank — CAIDA_BASE, providers/caida.py
    "api.asrank.caida.org",
    # PeeringDB net/IXP records — PDB_BASE, providers/peeringdb.py
    "www.peeringdb.com",
    # urlscan.io Search + Result APIs — URLSCAN_BASE, providers/urlscan.py. Both GET, both
    # reads of a scan somebody ELSE ran. The submission route on the same API is forbidden
    # (FORBIDDEN_MARKERS below, docs/OPSEC.md section 7), and the screenshot base
    # (URLSCAN_SCREENSHOT_BASE, same host) is emitted as a link and never retrieved.
    "urlscan.io",
    # ---- Rendered as a clickable pivot only; never fetched by this tool -----------------
    # Cloudflare Radar UI deep link — reporting/console.py, cli.py
    "radar.cloudflare.com",
    # AbuseIPDB UI deep link — reporting/console.py, cli.py
    "www.abuseipdb.com",
    # Shodan UI deep link — reporting/console.py
    "www.shodan.io",
}

# Hosts that MUST still be found by the scanner. Without this, a regex that silently stops
# matching would turn the allowlist test into an assertion about the empty set — green, and
# worthless. These are the hosts with a module-level *_BASE / *_ENDPOINT constant.
EXPECTED_PROVIDER_HOSTS: set[str] = {
    "www.virustotal.com",
    "api.shodan.io",
    "api.abuseipdb.com",
    "ipinfo.io",
    "otx.alienvault.com",
    "api.cloudflare.com",
    "stat.ripe.net",
    "api.asrank.caida.org",
    "www.peeringdb.com",
    "urlscan.io",
}

# Matches an absolute URL literal in source text. Stops at whitespace, quote, bracket or
# f-string placeholder so that f"{BASE}/{ip}" and f"https://host/path/{ip}" both behave.
_URL_LITERAL_RE = re.compile(r"https?://[^\s\"'`<>()\[\]\\]+")


# --------------------------------------------------------------------------------------
# 2. Endpoints that must never be added (docs/OPSEC.md section 7)
# --------------------------------------------------------------------------------------
#
# Each of these sits on an API this tool already talks to, or on one it plausibly would,
# and each has a passive sibling one call away. That is exactly why they get reached for
# by mistake. Marker regex, what it does to the target, what to use instead.
#
# W6 NARROWED TWO OF THESE, and both narrowings are paid for in section 5 below rather than
# given away. A line-level substring marker cannot tell a verb from a verb, so:
#
#   * ``/urls\b`` forbade the VirusTotal URL-report GET as loudly as the submission POST --
#     the very call its own failure message named as the passive alternative. It is now
#     ``/urls`` NOT followed by a path segment, i.e. a request that stops at the collection,
#     which is the shape a submission has and the report read does not.
#   * ``urlscan\.io`` forbade the whole HOST, which was right while no provider used it and
#     wrong the moment providers/urlscan.py started reading other people's completed scans
#     over GET. It is now the submission PATH.
#
# Both markers were also blind to a destination assembled from a module constant, which is
# exactly how a narrowed marker gets walked around. Section 5 resolves every request
# destination through the constants that build it and re-checks the result, so the
# narrowing costs nothing and the constant dodge closes at the same time.

ForbiddenMarker = tuple[str, str, str, str]  # (label, regex, why, passive alternative)

FORBIDDEN_MARKERS: list[ForbiddenMarker] = [
    (
        "VirusTotal POST /urls",
        # /urls at the end of a path -- the collection. /urls/<id> is the report GET and is
        # the sanctioned passive call; //urlscan.io is a different host and neither.
        r"/urls(?![/\w])",
        (
            "submitting a URL to VirusTotal instructs VT's own crawler to FETCH the target, "
            "and publishes the indicator to the VT community feed"
        ),
        (
            "GET https://www.virustotal.com/api/v3/urls/<url_id> for the report that already "
            "exists, as providers/virustotal.py already does for IPs and domains"
        ),
    ),
    (
        "VirusTotal /analyses",
        r"/analyses\b",
        (
            "an analysis object is the receipt for a submission — reading one means something "
            "in this codebase submitted the target for live analysis"
        ),
        "GET the existing ip_addresses/ or domains/ report and read last_analysis_stats",
    ),
    (
        "urlscan.io scan submission",
        # The submission PATH, not the host. urlscan.io is an allowlisted provider whose
        # search and result endpoints are GET reads of scans a DIFFERENT party already ran;
        # `scan` is the one route on that API that makes urlscan go and load the target.
        # `(?!\w)` matches /api/v1/scan and /api/v1/scan/ while sparing /api/v1/scanners.
        r"/api/v1/scan(?!\w)",
        (
            "urlscan loads the target in a real browser from urlscan infrastructure and, "
            "unless explicitly made private, publishes the resulting scan"
        ),
        "urlscan SEARCH (GET /api/v1/search/?q=...) for scans somebody else already ran",
    ),
    (
        "Pulsedive active probe",
        r"probe[\"']?\s*[:=]\s*[\"']?1\b",
        "probe=1 tells Pulsedive to scan the target live on your behalf",
        "the default Pulsedive query, which returns cached passive data only",
    ),
    (
        "MalwareBazaar get_file",
        r"get_file\b",
        (
            "get_file downloads live malware to this host — a passive recon CLI must never "
            "hold a sample, and the download itself is an active retrieval"
        ),
        "the MalwareBazaar metadata query (query=get_info) for hash, tags and first-seen",
    ),
    (
        "Spamhaus live zen DNSBL",
        r"zen\.spamhaus\.org|[sxpc]bl\.spamhaus\.org|\.dnsbl\.",
        (
            "a per-IP DNSBL lookup leaks the indicator you are investigating to the blocklist "
            "operator, one query at a time, with your resolver's timestamp attached"
        ),
        "the downloadable Spamhaus DROP list, matched locally against the indicator",
    ),
    (
        "Tor DNSEL per-IP lookup",
        r"dnsel\.torproject\.org|exitlist\.torproject\.org",
        (
            "the Tor DNS exit list is queried one indicator at a time, so it leaks the "
            "indicator the same way a DNSBL does"
        ),
        (
            "the bulk exit list (check.torproject.org/torbulkexitlist), fetched once and "
            "matched locally — add it to ALLOWED_HOSTS deliberately if you do this"
        ),
    ),
    (
        "Redirect / shortener expansion",
        r"follow_redirects\s*=\s*True|\.head\s*\(",
        (
            "resolving a redirect is an active fetch of the target, and HEAD is not exempt — "
            "the target's web server logs the request and its source"
        ),
        "the cached final URL VirusTotal or urlscan already recorded for that indicator",
    ),
]


# --------------------------------------------------------------------------------------
# 3. The only POST calls allowed in providers/
# --------------------------------------------------------------------------------------
#
# POST is not forbidden outright: GraphQL and form-encoded query APIs are read-only despite
# the verb. What is forbidden is POST to a SUBMISSION endpoint. Each entry pins one call
# site by module, by the constant naming its destination, and by how many times it appears.

PINNED_POST_SITES: dict[tuple[str, str], int] = {
    # providers/cloudflare_radar.py issues the same read-only Radar GraphQL query twice:
    # once with an Int-typed $asn variable and once with a String-typed fallback.
    ("cloudflare_radar.py", "RADAR_GRAPHQL_ENDPOINT"): 2,
}

# The value RADAR_GRAPHQL_ENDPOINT is pinned to. Repointing the constant would otherwise
# let a POST through the check above while sending it somewhere else entirely.
EXPECTED_RADAR_GRAPHQL_ENDPOINT = "https://api.cloudflare.com/client/v4/radar/graphql"

# Verbs that mutate remote state. None of them belong in a read-only OSINT client.
MUTATING_METHODS = ("put", "patch", "delete")


# --------------------------------------------------------------------------------------
# 4. Name resolution
# --------------------------------------------------------------------------------------
#
# Active DNS on the domain path is the tool's ONE documented exception (docs/OPSEC.md
# section 3): the target's own nameserver sees the query. The operator has ACCEPTED that
# resolver egress as a known risk, so this is a disclosed exception rather than a defect
# awaiting a fix. An accepted risk is only auditable while it lives in exactly one place --
# that is what these markers enforce. A second resolution site would make the OPSEC document
# wrong and would widen the accepted risk without anyone accepting the wider version.

ResolutionMarker = tuple[str, str, str]  # (label, regex, why it reaches the target)

RESOLUTION_MARKERS: list[ResolutionMarker] = [
    (
        "socket.getaddrinfo",
        r"\bgetaddrinfo\b",
        (
            "forward name resolution — the target's authoritative nameserver sees a query "
            "for their domain the moment you start investigating"
        ),
    ),
    (
        "socket.gethostbyaddr",
        r"\bgethostbyaddr\b",
        (
            "reverse PTR resolution — the same leak, and in-addr.arpa delegation can put "
            "the answering nameserver under the target operator's control"
        ),
    ),
    (
        "socket.gethostbyname",
        r"\bgethostbyname\b",
        "forward name resolution by another name",
    ),
    (
        "socket.create_connection",
        r"\bcreate_connection\b",
        (
            "opens a TCP socket to the resolved host, which is a direct connection to the "
            "target and not passive by any reading"
        ),
    ),
    (
        "aiodns",
        r"\bimport\s+aiodns\b|\bfrom\s+aiodns\b",
        "aiodns talks to a resolver directly, outside the sanctioned module",
    ),
    (
        "dnspython",
        r"\bimport\s+dns\b|\bfrom\s+dns(\.|\s+import)",
        (
            "dnspython can query the target's nameservers directly, bypassing even the "
            "recursive-resolver indirection that keeps your workstation IP out of it"
        ),
    ),
]


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


def _python_sources(root: Path) -> list[Path]:
    """Every committed .py file under ``root``, excluding bytecode caches."""
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def _rel(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT))


def _iter_source_lines(root: Path) -> Iterator[tuple[Path, int, str]]:
    for path in _python_sources(root):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            yield path, lineno, line


def _host_of(url: str) -> str:
    """Hostname portion of an absolute URL literal, lowercased, port stripped."""
    remainder = url.split("://", 1)[1]
    host = re.split(r"[/?#{]", remainder, maxsplit=1)[0]
    if "@" in host:  # userinfo@host — the userinfo half is a credential, not a host
        host = host.rsplit("@", 1)[1]
    return host.rsplit(":", 1)[0].lower() if host.count(":") == 1 else host.lower()


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _package_exists() -> bool:
    return PACKAGE_ROOT.is_dir()


pytestmark = pytest.mark.skipif(not _package_exists(), reason=f"package source not found at {PACKAGE_ROOT}")


# --------------------------------------------------------------------------------------
# Test 1 — egress allowlist
# --------------------------------------------------------------------------------------


def test_scanner_actually_finds_the_known_provider_hosts() -> None:
    """Guard the guard.

    Every other assertion in this file is a claim about a set the scanner produced. If the
    scanner stops matching — a regex edit, a source file moved out of the package — those
    assertions pass over an empty set and this file becomes decoration. Fail loudly instead.
    """
    found = {_host_of(m) for _p, _n, line in _iter_source_lines(PACKAGE_ROOT) for m in _URL_LITERAL_RE.findall(line)}
    missing = EXPECTED_PROVIDER_HOSTS - found

    assert not missing, (
        "The URL-literal scanner in tests/test_passivity.py did not find provider hosts it "
        f"is known to contain: {sorted(missing)}.\n\n"
        "This means the passivity gate is NOT actually inspecting the source, so every "
        "other test in this file is currently vacuous. Do not silence it.\n"
        "Likely causes: the provider module was deleted or moved out of tripper_recon/; the "
        "*_BASE constant was replaced by a runtime-built URL (which defeats static "
        "checking — see roadmap 2.1, the httpx event-hook allowlist, for the runtime "
        "counterpart); or _URL_LITERAL_RE was edited.\n"
        f"Scanner found: {sorted(found)}"
    )


def test_every_url_literal_targets_an_allowlisted_host() -> None:
    """No outbound destination exists that a human did not deliberately approve.

    Pre-fix behaviour: nothing checked this at all. A provider module could point
    ``create_client()`` at the target under investigation and no test, linter or review
    step would notice (docs/OPSEC.md section 6, gap 1).
    """
    offenders: dict[str, list[str]] = {}
    for path, lineno, line in _iter_source_lines(PACKAGE_ROOT):
        for url in _URL_LITERAL_RE.findall(line):
            host = _host_of(url)
            if host not in ALLOWED_HOSTS:
                offenders.setdefault(host, []).append(f"{_rel(path)}:{lineno}  {url}")

    if offenders:
        detail = "\n".join(
            f"  {host}\n" + "\n".join(f"      {site}" for site in sorted(sites))
            for host, sites in sorted(offenders.items())
        )
        pytest.fail(
            "PASSIVE BOUNDARY: a URL literal names a host that is not on the egress "
            "allowlist.\n\n"
            f"{detail}\n\n"
            "Tripper Recon investigates infrastructure WITHOUT TOUCHING IT (docs/OPSEC.md "
            "section 1). Every outbound request must go to a third party that already holds "
            "the data — never to the target, and never to anything the target operator can "
            "observe. That is the whole product claim; a single request to a "
            "target-controlled host tells a live actor they are being looked at.\n\n"
            "If this host is a legitimate new passive provider:\n"
            "  1. Confirm it cannot be attacker-controlled and cannot be made to fetch the "
            "target on your behalf (that is what makes VirusTotal's POST /urls forbidden "
            "while its GET report is fine).\n"
            "  2. Add it to ALLOWED_HOSTS in this file WITH a comment naming the provider "
            "and the module that contacts it.\n"
            "  3. Add a row to docs/OPSEC.md section 2 in the SAME commit.\n\n"
            "If the host came from a target-derived value interpolated into a URL, that is "
            "the violation itself — remove it. Static allowlisting cannot see a host that "
            "is only assembled at runtime; roadmap item 2.1 adds the httpx request event "
            "hook that catches those."
        )


def test_allowlist_has_no_dead_entries() -> None:
    """An allowlist that outlives its provider is a standing permission nobody re-approved."""
    found = {_host_of(m) for _p, _n, line in _iter_source_lines(PACKAGE_ROOT) for m in _URL_LITERAL_RE.findall(line)}
    stale = ALLOWED_HOSTS - found

    assert not stale, (
        f"ALLOWED_HOSTS permits hosts that no longer appear anywhere in the source: "
        f"{sorted(stale)}.\n\n"
        "This is not an error in the code — it is drift in the gate. A leftover entry is a "
        "pre-approved egress destination sitting there for the next provider module to "
        "reach for without review. Delete the entry (and its row in docs/OPSEC.md section 2) "
        "if the provider is gone."
    )


# --------------------------------------------------------------------------------------
# Test 2 — forbidden endpoints
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label,pattern,why,alternative",
    FORBIDDEN_MARKERS,
    ids=[m[0] for m in FORBIDDEN_MARKERS],
)
def test_forbidden_active_endpoint_absent(label: str, pattern: str, why: str, alternative: str) -> None:
    """No active endpoint from docs/OPSEC.md section 7 appears in the source.

    Each forbidden endpoint sits on an API this tool already uses, one call away from the
    passive sibling. That adjacency is the whole hazard: reaching for the wrong one is a
    plausible mistake, not a perverse one.
    """
    rx = re.compile(pattern, re.IGNORECASE)
    hits = [
        f"{_rel(path)}:{lineno}  {line.strip()}"
        for path, lineno, line in _iter_source_lines(PACKAGE_ROOT)
        if rx.search(line)
    ]

    if hits:
        formatted = "\n".join(f"      {h}" for h in hits)
        pytest.fail(
            f"PASSIVE BOUNDARY: forbidden active endpoint — {label}\n\n"
            f"{formatted}\n\n"
            f"WHY THIS IS FORBIDDEN: {why}.\n\n"
            f"USE INSTEAD: {alternative}.\n\n"
            "Tripper Recon's entire value is that running it does not tell the target you "
            "are looking (docs/OPSEC.md sections 1 and 7). An active endpoint breaks that "
            "for every user of the tool, silently, on the next release — and for a "
            "single-use phishing domain the resulting fetch can be the tell that burns the "
            "investigation.\n"
            "There is no --i-know-what-im-doing flag for this. If the passive alternative "
            "genuinely cannot answer the question, that belongs in a different tool."
        )


# --------------------------------------------------------------------------------------
# Test 3 — no POST to a submission endpoint
# --------------------------------------------------------------------------------------


def _post_call_sites(method: str) -> list[tuple[Path, int, ast.Call]]:
    sites: list[tuple[Path, int, ast.Call]] = []
    for path in _python_sources(PACKAGE_ROOT):
        for node in ast.walk(_parse(path)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == method:
                sites.append((path, node.lineno, node))
    return sites


def _first_arg_label(call: ast.Call) -> str:
    """A stable label for a call's destination argument."""
    if not call.args:
        kw = {k.arg: k.value for k in call.keywords if k.arg}
        target = kw.get("url")
        if target is None:
            return "<no destination argument>"
    else:
        target = call.args[0]
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Constant):
        return repr(target.value)
    return f"<{type(target).__name__} expression>"


def _receiver_name(call: ast.Call) -> str:
    """The object the method was called on — ``client`` in ``client.post(...)``."""
    func = call.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id
    return "<expr>"


def test_every_post_in_providers_is_a_pinned_query_endpoint() -> None:
    """POST is allowed only to a documented read-only query endpoint.

    POST is not inherently active — GraphQL and form-encoded query APIs are read-only
    despite the verb. POST to a *submission* endpoint is what turns a lookup into an
    instruction to fetch the target.

    Pre-fix behaviour: nothing distinguished the two. The Cloudflare Radar GraphQL POST and
    a hypothetical VirusTotal ``POST /urls`` were equally invisible to the build.
    """
    observed: dict[tuple[str, str], int] = {}
    unexpected: list[str] = []

    for path, lineno, call in _post_call_sites("post"):
        module = path.name
        label = _first_arg_label(call)
        receiver_name = _receiver_name(call)

        if path.parent != PROVIDERS_ROOT:
            unexpected.append(
                f"{_rel(path)}:{lineno}  {receiver_name}.post({label}) — POST outside "
                "providers/; all outbound traffic must originate in a provider module so "
                "that this gate and the roadmap 2.1 egress hook can both see it"
            )
            continue

        key = (module, label)
        if key not in PINNED_POST_SITES:
            unexpected.append(f"{_rel(path)}:{lineno}  {receiver_name}.post({label})")
        else:
            observed[key] = observed.get(key, 0) + 1

    drifted = {
        k: (PINNED_POST_SITES[k], observed.get(k, 0))
        for k in PINNED_POST_SITES
        if observed.get(k, 0) != PINNED_POST_SITES[k]
    }

    if unexpected or drifted:
        parts = []
        if unexpected:
            parts.append("Unpinned POST call sites:\n" + "\n".join(f"      {u}" for u in unexpected))
        if drifted:
            parts.append(
                "Pinned POST counts drifted (module, destination): expected -> observed\n"
                + "\n".join(f"      {k}: {exp} -> {got}" for k, (exp, got) in sorted(drifted.items()))
            )
        pytest.fail(
            "PASSIVE BOUNDARY: an unreviewed POST exists in the package.\n\n" + "\n\n".join(parts) + "\n\n"
            "Every POST this tool makes must be to a documented GraphQL or form-encoded "
            "QUERY endpoint — one that reads data the provider already holds. The only "
            "currently sanctioned example is the Cloudflare Radar GraphQL endpoint, posted "
            "twice by providers/cloudflare_radar.py (Int-typed $asn, then a String-typed "
            "fallback).\n\n"
            "A POST to a SUBMISSION endpoint is the classic way a passive tool stops being "
            "passive: VirusTotal POST /urls, urlscan POST /api/v1/scan, any 'analyze this "
            "for me' route. The provider fetches the target on your behalf and often "
            "publishes the indicator, so the target learns they are under investigation and "
            "so does everyone reading the public feed (docs/OPSEC.md section 7).\n\n"
            "If your new POST is genuinely a read-only query: name its destination with a "
            "module-level constant, then add (module_filename, CONSTANT_NAME) -> count to "
            "PINNED_POST_SITES in this file, with a comment saying which API it is and why "
            "it reads rather than submits."
        )


def test_radar_graphql_endpoint_constant_is_unchanged() -> None:
    """Pinning the POST by constant NAME is only as good as the constant's value."""
    source = (PROVIDERS_ROOT / "cloudflare_radar.py").read_text(encoding="utf-8")
    match = re.search(r'^RADAR_GRAPHQL_ENDPOINT\s*=\s*"([^"]+)"', source, re.MULTILINE)

    assert match is not None, (
        "RADAR_GRAPHQL_ENDPOINT is no longer a module-level string literal in "
        "providers/cloudflare_radar.py. The POST allowance in "
        "test_every_post_in_providers_is_a_pinned_query_endpoint pins that call site by "
        "CONSTANT NAME; if the value is now computed at runtime, the pin no longer "
        "constrains where the POST goes and the allowance must be removed."
    )
    assert match.group(1) == EXPECTED_RADAR_GRAPHQL_ENDPOINT, (
        f"RADAR_GRAPHQL_ENDPOINT was repointed to {match.group(1)!r}, but the passivity "
        f"gate sanctions POST to {EXPECTED_RADAR_GRAPHQL_ENDPOINT!r} only.\n\n"
        "The two POST calls in providers/cloudflare_radar.py are allowed because that exact "
        "endpoint is Cloudflare's read-only Radar GraphQL API. Point the constant elsewhere "
        "and the allowance silently carries over to a destination nobody reviewed."
    )


@pytest.mark.parametrize("method", MUTATING_METHODS)
def test_no_state_mutating_http_verb_anywhere(method: str) -> None:
    """PUT, PATCH and DELETE have no read-only reading."""
    sites = [
        f"{_rel(path)}:{lineno}  .{method}({_first_arg_label(call)})"
        for path, lineno, call in _post_call_sites(method)
        # ast cannot tell client.delete() from dict.delete(); require an httpx-shaped
        # receiver named `client` to keep the check specific.
        if isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "client"
    ]

    assert not sites, (
        f"PASSIVE BOUNDARY: an HTTP {method.upper()} call exists.\n\n" + "\n".join(f"      {s}" for s in sites) + "\n\n"
        f"{method.upper()} changes state on the remote side. Tripper Recon is a read-only "
        "collector: it looks up intelligence third parties already hold and writes nothing "
        "back anywhere (docs/OPSEC.md section 1). There is no passive use for this verb — "
        "if a provider API requires it for a plain lookup, that is worth a comment in "
        "docs/OPSEC.md and an explicit exception here, not a silent addition."
    )


# --------------------------------------------------------------------------------------
# Test 5 — resolved request endpoints (W6)
# --------------------------------------------------------------------------------------
#
# Everything above works on one line of text at a time. That is why two of the markers had
# to be over-broad to be safe, and it is also why an over-broad marker gets walked around:
# no provider writes its path inline, so every destination in this package is a constant and
# an f-string, and a line-level regex sees neither half of the result.
#
# This section resolves the destination of every request the package makes — through the
# module-level constants that build it — and asks the question the markers cannot: does the
# path this request will ACTUALLY go to end at a submission collection, and is anything but
# GET going anywhere but the one pinned read-only query endpoint.
#
# Concretely, it is what makes these three distinguishable, which no substring can do:
#     GET  https://www.virustotal.com/api/v3/urls/{url_id}   report read      — allowed
#     POST https://www.virustotal.com/api/v3/urls            submission       — FORBIDDEN
#     POST https://urlscan.io/api/v1/scan/                   submission       — FORBIDDEN
# and it stays true when the path is spelled f"{VT_BASE}/{SOME_SEGMENT}".

#: Every httpx method that opens a connection. ``request`` and ``stream`` take the verb as
#: their first argument and the destination as their second; the rest take the destination
#: first. Both shapes are handled in :func:`_request_call_sites`.
_HTTP_METHODS: frozenset[str] = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "request", "stream"}
)

#: Receivers that are an httpx client. ``ast`` cannot type-check, so the check is pinned to the
#: name every provider in this package uses; ``test_only_utils_http_constructs_a_client`` is what
#: keeps that name the only way a request can be made.
_CLIENT_RECEIVERS: frozenset[str] = frozenset({"client"})

#: Path segments that make the provider go and fetch the target, forbidden when a request PATH
#: ENDS there. Ending at the collection is what a submission looks like; the same segment
#: followed by an identifier is the report read, which is the passive sibling this tool uses.
FORBIDDEN_TERMINAL_SEGMENTS: dict[str, str] = {
    "urls": (
        "VirusTotal's URL collection. A request that stops here is a submission: VT's own "
        "crawler fetches the target and the indicator lands in the community feed. The report "
        "read is the same collection plus an identifier — /api/v3/urls/<url_id> — and is "
        "already implemented in providers/virustotal.vt_url_summary"
    ),
    "scan": (
        "urlscan's submission route. It loads the target in a real browser from urlscan "
        "infrastructure and, unless made private, publishes the scan. Use "
        "providers/urlscan.urlscan_search_url to find a scan somebody else already ran"
    ),
}

#: Path segments forbidden ANYWHERE in a resolved path, identifier or not. An analysis object is
#: the receipt for a submission: possessing one to read means something here submitted the target.
FORBIDDEN_ANY_SEGMENT: dict[str, str] = {
    "analyses": (
        "an analysis object is the receipt for a submission. Reading one — with or without an "
        "id — means something in this codebase asked a provider to go and look at the target. "
        "Read last_analysis_stats off the existing ip_addresses/, domains/ or urls/ report"
    ),
}

#: The one destination a verb other than GET may go to. Same endpoint the POST pin above names,
#: reached here by resolving the constant rather than by trusting its name.
NON_GET_DESTINATIONS: frozenset[str] = frozenset({EXPECTED_RADAR_GRAPHQL_ENDPOINT})

#: Resolved destinations expected to be found, so a resolver that quietly stops resolving cannot
#: turn every assertion below into a claim about the empty set. Keyed by module filename.
EXPECTED_RESOLVED_ENDPOINTS: dict[str, set[str]] = {
    "virustotal.py": {
        "GET https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        "GET https://www.virustotal.com/api/v3/domains/{domain}",
        # The one this section exists for: the segment constant is resolved through, so the
        # gate sees the real path and can tell this GET from the submission POST.
        "GET https://www.virustotal.com/api/v3/urls/{url_id}",
    },
    "urlscan.py": {
        "GET https://urlscan.io/api/v1/search/",
        "GET https://urlscan.io/api/v1/result/{uuid}/",
    },
    "cloudflare_radar.py": {
        "POST https://api.cloudflare.com/client/v4/radar/graphql",
    },
    "cloudflare_rest.py": {
        # Built from a nested constant (HIJACKS_URL = f"{CF_BASE}/..."), which proves the
        # resolver follows a constant that is itself an f-string over another constant.
        "GET https://api.cloudflare.com/client/v4/radar/bgp/hijacks/events",
        "GET https://api.cloudflare.com/client/v4/radar/bgp/leaks/events",
    },
}


def _module_string_constants(tree: ast.Module) -> dict[str, str]:
    """Module-level ``NAME = <string expression>`` bindings, resolved in source order.

    Source order matters: ``HIJACKS_URL = f"{CF_BASE}/bgp/hijacks/events"`` can only resolve
    once ``CF_BASE`` is known, and that is the shape a real dodge would take.
    """
    constants: dict[str, str] = {}
    for node in tree.body:
        targets: list[ast.expr]
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
            value = node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
            value = node.value
        else:
            continue
        resolved = _resolve_string(value, constants)
        if resolved is None or "{" in resolved:
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                constants[target.id] = resolved
    return constants


def _resolve_string(node: ast.expr, constants: dict[str, str], depth: int = 0) -> Optional[str]:
    """Best-effort static value of a string expression, with ``{name}`` for the unknown parts.

    An unresolvable interpolation becomes a placeholder rather than aborting the resolution.
    That is the point: ``f"{VT_BASE}/{SEGMENT}/{url_id}"`` has to come out as
    ``https://www.virustotal.com/api/v3/urls/{url_id}`` so that the trailing identifier is
    visible as a segment and the path is not mistaken for the bare collection.
    """
    if depth > 8:
        return "{...}"
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.Name):
        return constants.get(node.id, "{" + node.id + "}")
    if isinstance(node, ast.Attribute):
        return "{" + node.attr + "}"
    if isinstance(node, ast.FormattedValue):
        return _resolve_string(node.value, constants, depth + 1)
    if isinstance(node, ast.JoinedStr):
        parts = [_resolve_string(value, constants, depth + 1) for value in node.values]
        return "".join(part if part is not None else "{?}" for part in parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _resolve_string(node.left, constants, depth + 1)
        right = _resolve_string(node.right, constants, depth + 1)
        if left is None and right is None:
            return None
        return (left or "{?}") + (right or "{?}")
    if isinstance(node, ast.Call):
        return "{" + _first_arg_label(node) + "()}"
    return None


ResolvedRequest = tuple[Path, int, str, Optional[str]]  # (module, line, verb, resolved URL)


def _request_call_sites() -> list[ResolvedRequest]:
    """Every ``client.<verb>(...)`` in the package, with its destination resolved."""
    sites: list[ResolvedRequest] = []
    for path in _python_sources(PACKAGE_ROOT):
        tree = _parse(path)
        constants = _module_string_constants(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            method = node.func.attr
            if method not in _HTTP_METHODS:
                continue
            receiver = node.func.value
            if not isinstance(receiver, ast.Name) or receiver.id not in _CLIENT_RECEIVERS:
                continue

            keywords = {kw.arg: kw.value for kw in node.keywords if kw.arg}
            if method in {"request", "stream"}:
                verb_node = node.args[0] if node.args else keywords.get("method")
                verb = _resolve_string(verb_node, constants) if verb_node is not None else None
                destination = node.args[1] if len(node.args) > 1 else keywords.get("url")
            else:
                verb = method
                destination = node.args[0] if node.args else keywords.get("url")

            resolved = _resolve_string(destination, constants) if destination is not None else None
            sites.append((path, node.lineno, (verb or "<dynamic>").upper(), resolved))
    return sites


def _path_segments(url: str) -> list[str]:
    """Path segments of a resolved URL, query and fragment discarded, empties dropped."""
    remainder = url.split("://", 1)[1] if "://" in url else url
    remainder = remainder.split("?", 1)[0].split("#", 1)[0]
    _, _, path = remainder.partition("/")
    return [segment for segment in path.split("/") if segment]


def test_the_endpoint_resolver_actually_resolves() -> None:
    """Guard the guard.

    Every assertion in this section is a claim about the set of destinations the resolver
    produced. If the resolver stops following constants — a provider switches to a helper
    function, ``_resolve_string`` is edited, a module moves — the assertions pass over an empty
    or placeholder-riddled set and this section becomes decoration.

    The expected set is deliberately written out in full, including the VirusTotal URL-report
    GET, because that call site is the reason the section exists: it is the one destination the
    line-level markers above are narrowed around.
    """
    observed: dict[str, set[str]] = {}
    for path, _lineno, verb, resolved in _request_call_sites():
        if resolved is not None:
            observed.setdefault(path.name, set()).add(f"{verb} {resolved}")

    missing = {
        module: sorted(expected - observed.get(module, set()))
        for module, expected in EXPECTED_RESOLVED_ENDPOINTS.items()
        if expected - observed.get(module, set())
    }

    assert not missing, (
        "The endpoint resolver in tests/test_passivity.py no longer produces destinations it "
        f"is known to produce: {missing}.\n\n"
        "Section 5 is therefore NOT inspecting the real request paths, and the two narrowed "
        "markers in FORBIDDEN_MARKERS are running without the check that pays for them. Do "
        "not silence this.\n"
        "Likely causes: a provider stopped building its URL from module constants; a request "
        "moved off a receiver named `client`; _resolve_string or _module_string_constants was "
        "edited.\n"
        f"Resolver produced: { {k: sorted(v) for k, v in sorted(observed.items())} }"
    )


def test_no_resolved_request_path_reaches_a_submission_endpoint() -> None:
    """The destination a request will actually go to, checked after the constants are resolved.

    This is the check that lets ``/urls`` and ``urlscan.io`` be narrowed in FORBIDDEN_MARKERS
    without giving anything away. A substring marker sees ``f"{VT_BASE}/{SEGMENT}/{url_id}"``
    and learns nothing; this sees ``https://www.virustotal.com/api/v3/urls/{url_id}``, notes
    that the path does not stop at ``urls``, and passes it — while the same code fails
    ``f"{VT_BASE}/{SEGMENT}"``, which is the submission.
    """
    offenders: list[str] = []
    for path, lineno, verb, resolved in _request_call_sites():
        site = f"{_rel(path)}:{lineno}  {verb} {resolved if resolved is not None else '<unresolvable>'}"
        if resolved is None:
            offenders.append(
                f"{site} — the destination could not be resolved statically at all, so no gate "
                "in this file can see where this request goes. Build it from a module-level "
                "constant the way every provider here does"
            )
            continue
        segments = _path_segments(resolved)
        if not segments:
            continue
        terminal = segments[-1].lower()
        if terminal in FORBIDDEN_TERMINAL_SEGMENTS:
            offenders.append(f"{site} — path ends at '{terminal}': {FORBIDDEN_TERMINAL_SEGMENTS[terminal]}")
        for segment in segments:
            if segment.lower() in FORBIDDEN_ANY_SEGMENT:
                offenders.append(f"{site} — path contains '{segment}': {FORBIDDEN_ANY_SEGMENT[segment.lower()]}")

    assert not offenders, (
        "PASSIVE BOUNDARY: a request resolves to a submission endpoint.\n\n"
        + "\n".join(f"      {o}" for o in offenders)
        + "\n\n"
        "A submission does not read data a third party already holds — it instructs that third "
        "party to go and FETCH the target on your behalf. The target's server logs the visit, "
        "and on both VirusTotal and urlscan the indicator is published where anyone can read "
        "it, so a live actor learns they are under investigation twice over (docs/OPSEC.md "
        "sections 1 and 7).\n\n"
        "There is no flag for this and no exception. If the passive sibling genuinely cannot "
        "answer the question, the answer is that the question belongs in a different tool."
    )


def test_every_non_get_request_goes_to_the_one_pinned_query_endpoint() -> None:
    """Verb and destination checked together, against the resolved path.

    ``test_every_post_in_providers_is_a_pinned_query_endpoint`` pins the Radar POST by the NAME
    of the constant naming its destination, and ``test_radar_graphql_endpoint_constant_is_
    unchanged`` pins that constant's value — two tests that have to agree. This one asks the
    question directly of the resolved value, and covers every non-GET verb rather than POST
    alone.
    """
    offenders = [
        f"{_rel(path)}:{lineno}  {verb} {resolved if resolved is not None else '<unresolvable>'}"
        for path, lineno, verb, resolved in _request_call_sites()
        if verb != "GET" and resolved not in NON_GET_DESTINATIONS
    ]

    assert not offenders, (
        "PASSIVE BOUNDARY: a non-GET request goes somewhere other than the one sanctioned "
        "read-only query endpoint.\n\n" + "\n".join(f"      {o}" for o in offenders) + "\n\n"
        f"The only destination a verb other than GET may have is {EXPECTED_RADAR_GRAPHQL_ENDPOINT} "
        "— Cloudflare's Radar GraphQL API, which reads data Cloudflare already holds despite "
        "using POST.\n\n"
        "Every other non-GET on an OSINT API means one of two things, and both are out of "
        "scope here: a submission (the provider fetches the target for you) or a write (this "
        "tool contributes nothing anywhere). See docs/OPSEC.md sections 1 and 7."
    )


# --------------------------------------------------------------------------------------
# Test 4 — name resolution lives in exactly one module
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label,pattern,why",
    RESOLUTION_MARKERS,
    ids=[m[0] for m in RESOLUTION_MARKERS],
)
def test_name_resolution_only_in_utils_dns(label: str, pattern: str, why: str) -> None:
    """Only tripper_recon/utils/dns.py may resolve a name.

    Active DNS is the tool's single documented exception to passivity (docs/OPSEC.md
    section 3): a cache miss walks the delegation chain to the nameserver the TARGET
    operator runs, and that nameserver logs a query for their own domain at the moment the
    investigation started. For a single-use phishing domain that is the tell.

    The operator has accepted that resolver egress as a known risk, which makes it a disclosed
    exception rather than an open defect. Confining it to one module is what keeps the
    disclosure honest: the risk that was accepted is the one this module performs, and a
    second resolution site would silently widen it.
    """
    rx = re.compile(pattern)
    offenders = [
        f"{_rel(path)}:{lineno}  {line.strip()}"
        for path, lineno, line in _iter_source_lines(PACKAGE_ROOT)
        if rx.search(line) and path != DNS_MODULE
    ]

    assert not offenders, (
        f"PASSIVE BOUNDARY: name resolution ({label}) outside tripper_recon/utils/dns.py.\n\n"
        + "\n".join(f"      {o}" for o in offenders)
        + "\n\n"
        f"WHY THIS MATTERS: {why}.\n\n"
        "Resolving the target's name is the ONE active thing this tool does, and it is "
        "documented as an exception precisely because it is confined to one auditable "
        "module (docs/OPSEC.md section 3). The operator accepted THAT exception, in THAT "
        "module. A second resolution site makes the OPSEC document wrong and widens an "
        "accepted risk past what was accepted.\n\n"
        "USE INSTEAD: the passive A/AAAA records VirusTotal already returns "
        "(vt_dns_records, parsed in orchestrators.py), or call "
        "tripper_recon.utils.dns.resolve_domain so the one exception stays in one place."
    )


def test_utils_dns_is_the_module_that_resolves() -> None:
    """Counterpart to the test above: confirm the sanctioned site still exists.

    If utils/dns.py stops calling getaddrinfo, the parametrized test above passes trivially
    for every pattern and stops constraining anything.
    """
    assert DNS_MODULE.is_file(), (
        f"{_rel(DNS_MODULE)} is missing. The tests above assert that name resolution "
        "happens NOWHERE ELSE; with the sanctioned module gone they no longer constrain "
        "anything. Re-point DNS_MODULE at wherever resolution now lives, and update "
        "docs/OPSEC.md section 3, which cites utils/dns.py:14 by line."
    )
    # Deliberately an AST check, not a substring check: utils/dns.py:9 carries the word
    # "getaddrinfo" in a comment, so `"getaddrinfo" in source` stays true even after the
    # call itself is gone, and this guard would pass vacuously.
    calls = [
        node
        for node in ast.walk(_parse(DNS_MODULE))
        if isinstance(node, ast.Call)
        and (
            (isinstance(node.func, ast.Attribute) and node.func.attr in {"getaddrinfo", "gethostbyaddr"})
            or (isinstance(node.func, ast.Name) and node.func.id in {"getaddrinfo", "gethostbyaddr"})
        )
    ]
    assert calls, (
        f"{_rel(DNS_MODULE)} no longer CALLS getaddrinfo or gethostbyaddr. Either resolution "
        "moved (in which case update DNS_MODULE here and docs/OPSEC.md section 3, which "
        "cites utils/dns.py:14 by line), or the domain path went fully passive — which is "
        "roadmap item 2.2 and excellent news, but this gate must then be tightened to forbid "
        "resolution EVERYWHERE, including here, rather than left passing vacuously."
    )


# ------------------------------------------------------------------------------------------
# The runtime hook is only as good as its coverage of client construction
# ------------------------------------------------------------------------------------------

#: The one module allowed to build an ``httpx.AsyncClient``. Everything else receives a client
#: as a parameter, which is what keeps the egress hook on every request.
CLIENT_FACTORY_MODULE = "tripper_recon/utils/http.py"

#: Module-level httpx calls that open a connection without any client the package configured.
_BARE_HTTPX_CALL_RE = re.compile(r"\bhttpx\.(get|post|put|patch|delete|head|options|request|stream)\s*\(")

#: Client construction. ``httpx.Client`` is included even though the package is async: a
#: synchronous client is just as capable of reaching the target and just as unhooked.
_CLIENT_CONSTRUCTION_RE = re.compile(r"\bhttpx\.(Async)?Client\s*\(")


def test_only_utils_http_constructs_a_client() -> None:
    """The egress allowlist is a request event hook, and hooks belong to a client instance.

    ``create_client()`` installs ``_enforce_egress_allowlist``; a bare ``httpx.AsyncClient()``
    has an empty ``event_hooks["request"]`` list and enforces nothing. So the runtime half of
    the passive boundary holds only while ``create_client`` is the sole constructor.

    That property was true but unguarded: every provider takes ``client`` as a parameter today
    purely by convention. A future provider that builds its own client would keep passing the
    static URL-literal scan above, keep passing every other test in this file, and silently
    lose the one check that can see a host assembled at runtime -- which is precisely the
    case the hook exists for. This test makes the convention a build gate.
    """
    offenders: list[str] = []
    for path, lineno, line in _iter_source_lines(PACKAGE_ROOT):
        rel = _rel(path)
        stripped = line.strip()
        # Type annotations (`client: httpx.AsyncClient`) are not construction; require the
        # opening parenthesis, which the regex does.
        if _CLIENT_CONSTRUCTION_RE.search(line) and rel != CLIENT_FACTORY_MODULE:
            offenders.append(f"{rel}:{lineno}  {stripped}")
        if _BARE_HTTPX_CALL_RE.search(line):
            offenders.append(f"{rel}:{lineno}  {stripped}")

    assert not offenders, (
        "PASSIVE BOUNDARY: an HTTP client is being created outside "
        f"{CLIENT_FACTORY_MODULE}, or a module-level httpx call is opening a connection "
        "with no client at all.\n\n" + "\n".join(f"  {o}" for o in offenders) + "\n\n"
        "Only tripper_recon/utils/http.create_client() installs the egress allowlist hook "
        "(_enforce_egress_allowlist). A client built anywhere else has an empty "
        "event_hooks['request'] and can contact any host, including the target under "
        "investigation, with nothing raising PassiveBoundaryViolation.\n\n"
        "Fix: accept `client: httpx.AsyncClient` as a parameter the way every existing "
        "provider does, and let the orchestrator supply create_client(). If a genuinely "
        "different client shape is needed, add it to utils/http.py so it inherits the hook, "
        "and record why in docs/OPSEC.md."
    )


def test_the_factory_actually_installs_the_hook() -> None:
    """Guard against the gate above passing vacuously.

    ``test_only_utils_http_constructs_a_client`` is worth nothing if ``create_client`` stops
    installing the hook -- the whole package would funnel through one unguarded constructor
    and every test would stay green.
    """
    from tripper_recon.utils.http import _enforce_egress_allowlist, create_client

    client = create_client()
    try:
        assert _enforce_egress_allowlist in client.event_hooks.get("request", []), (
            "create_client() no longer installs the egress allowlist hook. The runtime half "
            "of the passive boundary is disabled: nothing inspects the host a request is "
            "actually about to leave for."
        )
    finally:
        pass
