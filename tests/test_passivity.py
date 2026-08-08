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
cannot see a host assembled at runtime: ``client.get("https://" + target_host + "/")`` is a
direct fetch of the target and passes every test in this file. Verified by mutation, and it
is the reason roadmap item 2.1 exists — an httpx request event hook at the single
``create_client()`` construction point, checking the same allowlist against the URL actually
about to go out. These tests are the compile-time half of that pair, not a substitute for it.

Authority for the constraint: docs/OPSEC.md sections 1, 2 and 7.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import Path

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

ForbiddenMarker = tuple[str, str, str, str]  # (label, regex, why, passive alternative)

FORBIDDEN_MARKERS: list[ForbiddenMarker] = [
    (
        "VirusTotal POST /urls",
        r"/urls\b",
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
        r"urlscan\.io|/api/v1/scan",
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
# section 3): the target's own nameserver sees the query. That exception is tolerable only
# while it lives in exactly one auditable place, so that roadmap item 2.2 can put it behind
# an --active-dns flag by editing a single module.

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

    Confining it to one module is what keeps the exception honest — and what makes roadmap
    item 2.2 (passive DNS by default, live resolution behind --active-dns) a single-file
    change rather than an archaeology project.
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
        "module (docs/OPSEC.md section 3). A second resolution site makes the OPSEC "
        "document wrong, and makes the planned --active-dns opt-out incomplete the day it "
        "ships — users would disable resolution and still be resolving.\n\n"
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
