# OPSEC & Passivity

What this tool does and does not send to the network, and who can see that you ran it.

This document describes the code as it stands on branch `feat/work-20260808-recon-hardening`.
Every claim carries a `file:line` anchor so you can check it yourself. If you change a provider,
change this file in the same commit.

---

## 1. The contract

**Tripper Recon investigates infrastructure without touching it.** All intelligence comes from
third-party APIs that already hold the data. The tool does not:

- scan the target, or connect to any port on it
- fetch a URL, follow a redirect, expand a shortener, or download a sample
- submit anything for live analysis (see the register in section 7)
- send an ICMP echo, a traceroute, or a TLS handshake to the target

There is **one documented exception**, in section 3.

**Redirects specifically.** Resolving a redirect or expanding a shortener is an active fetch of
the target, and a bodyless `HEAD` is not exempt — the target's web server logs the request and its
source either way. This tool therefore reports `redirect_chain` as **NOT RESOLVED** with the reason
attached (`tripper_recon/utils/urls.py:191-208`), unless a third party's already-completed scan
supplied the chain, in which case it is carried with the provider, the field and the observation
date (`RedirectChain.from_passive_record`, `utils/urls.py:291`). There is no `resolve()` method on
that class and there must never be one.

## 2. Every outbound destination

Sixteen outbound destinations appear below, plus the system resolver. Every one of the sixteen is
a third party that is not the target, and every one is enforced at runtime by the egress allowlist
(`utils/http.py:63`), which raises `PassiveBoundaryViolation` before a socket opens for any host
not on this table.

| Provider | Host contacted | Reaches target infrastructure? |
|---|---|---|
| VirusTotal | `www.virustotal.com` | No |
| Shodan | `api.shodan.io` | No |
| Shodan InternetDB | `internetdb.shodan.io` | No |
| AbuseIPDB | `api.abuseipdb.com` | No |
| IPInfo | `ipinfo.io` | No |
| AlienVault OTX | `otx.alienvault.com` | No |
| Cloudflare Radar | `api.cloudflare.com` | No |
| Cloudflare BGP | `api.cloudflare.com` | No |
| RIPEstat | `stat.ripe.net` | No |
| CAIDA AS-Rank | `api.asrank.caida.org` | No |
| PeeringDB | `www.peeringdb.com` | No |
| Tranco | `tranco-list.eu` | No |
| **abuse.ch URLhaus** | `urlhaus-api.abuse.ch` | No — `POST`, and a query. See section 7 |
| **abuse.ch ThreatFox** | `threatfox-api.abuse.ch` | No — `POST`, and a query. See section 7 |
| **RDAP bootstrap** | `data.iana.org` | No — a static file. The indicator is never sent |
| **RDAP registry** | chosen at runtime from the bootstrap file. **None is allowlisted today** | No — see below |
| **urlscan.io** | `urlscan.io` | No — see below |
| **System resolver** | your configured DNS resolver | **Yes, indirectly** — see section 3 |

**RDAP has a dynamic destination, and that is handled by refusing rather than by widening.** RDAP
deliberately has no single endpoint: each TLD and each RIR runs its own server, and a client finds
the right one through a bootstrap step (STD 95, RFC 9224). `providers/rdap.py` does that step
client-side — it fetches IANA's static JSON files (`IANA_BOOTSTRAP_BASE`, `rdap.py:137`), caches
them for the process, and resolves the authoritative base URL locally. The alternative, the
`rdap.org` aggregator, answers `302` and would mean following a redirect to a host chosen at
runtime; that is the exact hole this allowlist exists to close, and it is forbidden outright by
section 7.

Three properties follow, and each is checkable:

- **The indicator never goes to an intermediary.** IANA serves a file and learns nothing about
  what is being investigated. Only the registry that holds the record sees the query.
- **No redirect is ever followed.** Both requests in the module set `follow_redirects=False`
  explicitly (`rdap.py:480`, `:723`), and a `3xx` from a registry is reported as
  `unexpected_redirect` with the host it named (`rdap.py:199`) so that host can be reviewed
  deliberately instead of a client silently visiting it.
- **The resolved host is checked before a request is built.** `providers/rdap.py` reads the same
  `ALLOWED_EGRESS_HOSTS` the runtime hook reads and returns `registry_not_allowlisted`
  (`rdap.py:196`) — naming the host, with no request made — when it is not on the list. That check
  is a courtesy, not the enforcement: the hook in `utils/http.py` raises regardless, which was
  verified by disabling the provider-side check and watching `PassiveBoundaryViolation` fire.

**Which registries are approved, and which are deliberately not.** The high-volume registries were
read from the IANA bootstrap files on 2026-08-09 (`dns.json` carries 292 service entries;
`ipv4.json` and `asn.json` carry the five RIRs) and allowlisted host by host: the five RIRs for
`ip` and `asn` lookups, and the gTLD/ccTLD registries behind the highest query volume and the
heaviest phishing use. The long tail is **not** allowlisted and fails closed with
`registry_not_allowlisted`, which names the exact host to add — an unlisted TLD therefore degrades
to a stated UNKNOWN rather than to a silent miss.

Two registries are **deliberately absent**: `rdap.nic.ru` (`.ru`) and `rdap.cnnic.cn` (`.cn`). Both
are the genuine authoritative registries and both would work. But an RDAP query tells the registry
which domain is being investigated, and when. Handing that to a Russian or Chinese registry is a
disclosure decision that belongs to the operator, not to a default shipped in a tool. Both fail
closed with the host named, so enabling either is one reviewed line in `utils/http.py`.

The safety property that makes any of this acceptable: **the resolved host is a function of the
TLD, never of the indicator.** A target that registers `evil.com` cannot influence which server
answers `.com` RDAP, so this lookup cannot be steered at infrastructure the target controls.

VirusTotal is used correctly for a passive tool: the provider module issues `GET` requests against
reports that already exist, for IPs, domains and URLs alike
(`providers/virustotal.py:167`, `:200`, `:440`). It never submits an indicator for analysis.

**urlscan.io needs its own paragraph, because it is the host on this table with a live submission
route one call away from the two this tool uses.** `providers/urlscan.py` issues exactly two
requests, both `GET`: the Search API (`/api/v1/search/`, `urlscan.py:541`) and the Result API
(`/api/v1/result/{uuid}/`, `urlscan.py:628`). Both read a scan that a **different party already
completed** — the target is not loaded, and urlscan's browser is not dispatched. The submission
route on the same API is in the section 7 register and is unreachable from this codebase; the
static gate greps the whole package for it on every run. Two further consequences of using it
honestly:

- **Public scans only.** `task.visibility` is filtered to `public` in the query and re-checked on
  the parsed response (`urlscan.py:304`, `:634`). An unlisted scan is frequently another analyst's
  live investigation, and lifting it into a report is a disclosure this tool has no right to make.
- **The screenshot is a link, never a retrieval.** `urlscan_screenshot_url` is built for a human to
  click and `urlscan_screenshot_fetched` is hard-coded `False` (`urlscan.py:490-491`). Allowlisting
  the host does not authorise fetching artefacts from it.

Two hosts are named in `providers/urlscan.py` prose but never contacted: `docs.urlscan.io`
(documentation citations, written scheme-less so the URL-literal scanner does not read them as
egress destinations) and the deep-link hosts in the next paragraph.

Deep-link hosts that are only ever **rendered** for a human to click — `radar.cloudflare.com`,
`www.shodan.io`, `www.abuseipdb.com` — are deliberately **absent from the runtime allowlist**. A
request to one is a defect, and it raises.

## 3. The exception: active DNS on the `domain` command

`tripper-recon domain <target>` calls `socket.getaddrinfo()` on the target
(`tripper_recon/utils/dns.py:41`, invoked at `tripper_recon/orchestrators.py:1126`).

`tripper-recon url <target> --depth full` reaches the same call through the same path. **The two
shallower depths do not:** `--depth url` asks only about the link itself and `--depth host` adds
the host's own reputation, and neither resolves anything (`orchestrators.py:200-210`). If resolver
egress is the risk you are managing, that flag is the control.

**What that means.** Your organization's recursive resolver looks the name up. If the answer is not
already cached, the resolver walks the delegation chain and queries **the nameserver the target
operator controls**. That nameserver sees a query for their domain, sourced from your organization's
resolver, at the moment you started investigating.

**Why it matters.** For a live actor watching their own DNS logs, that is a tell. For a
single-use phishing domain, it can be the tell.

**What it does not leak.** Your workstation IP is not exposed to the target — the query arrives
from your recursive resolver. Nothing identifies you personally, and no query reaches the target's
web infrastructure.

**Working around it today.** Investigate the hostname's IPs directly with `tripper-recon ip`, or
read the passive DNS records VirusTotal already returns. The tool parses those passive A/AAAA
records at `orchestrators.py:992` and merges them with the active results at `:1130` — so the
passive substitute is already present, just not selectable.

**Settled: this is an accepted risk, not a pending fix.** Live resolution stays the default and is
disclosed here rather than removed. **There is no `--active-dns` flag and none is planned**
(`docs/ROADMAP.md` §4b, decision Q2, which resolves item 2.2 to documentation rather than code).
The controls that do exist are the ones above: `--depth url`, `--depth host`, or investigating the
addresses directly with `tripper-recon ip`.

## 4. What the third-party providers learn

Passive does not mean invisible. It means the *target* does not see you. The providers do.

- **Every query is attributable to your API key.** A VirusTotal lookup is logged against your
  account. Assume your employer, the provider, and anyone with access to provider logs can see
  which indicators you investigated and when.
- **Your egress IP is visible** to every provider the tool actually queries — the wired provider
  modules in the section 2 table. `providers/urlscan.py` is written but no orchestrator calls it,
  so urlscan.io sees nothing today (section 6, gap 3).
- **A keyless provider identifies you by egress IP and nothing else, which cuts both ways.** Shodan
  InternetDB, Tranco and RDAP take no credential, so the lookup is not attributable to an account
  — but the address is still the identifier the provider rate-limits and logs on, and it is the
  address your whole organisation shares. Keyless is cheaper, not quieter.
- **The indicator list itself is sensitive.** The set of things you are looking at can reveal an
  ongoing incident before you are ready to disclose it.
- **Look-ups are not submissions.** Nothing in this tool contributes your indicators to a public
  corpus. A VirusTotal *lookup* does not appear in the community feed the way a *submission* does.

If an investigation is sensitive enough that provider visibility is itself a risk, this tool is
the wrong instrument. Use an offline data set.

## 4a. Accepted risk: the abuse.ch terms of use

**Decision date: 2026-08-09. This is an accepted risk, recorded rather than mitigated.** It is not
a warning to be actioned and it is not an open item; `docs/ROADMAP.md` §4b decision Q5 settles it
and it is not to be re-litigated.

**What was accepted.** abuse.ch's Terms and Conditions prohibit automated access in broad terms.
Clause 6.2: "You shall not conduct, facilitate, authorize or permit any text or data mining or web
scraping in relation to our site or any services provided via, or in relation to, our site."
Clause 6.2.1 names the mechanism: "Any 'robot', 'bot', 'spider', 'scraper' or other automated
device, program, tool, algorithm, code, process or methodology to access, obtain, copy, monitor or
republish any portion of the site or any data, content, information or services accessed via the
same." (abuse.ch Terms and Conditions, retrieved 2026-08-09.)

Tripper Recon is a script that queries the URLhaus and ThreatFox APIs. `bulk --investigate` issues
one lookup per indicator in a file with no ceiling other than the global concurrency limiter, which
is the shape clause 6.2.1 describes. **The operator has decided to build it in full, including
bulk mode, with no gate**, and to carry the exposure rather than engineer around it.

**The counter-reading, stated so the decision is legible rather than flattering.** abuse.ch's own
API documentation supplies `curl` and `wget` invocations, requires an `Auth-Key` obtained from
their authentication portal, and states that the API "is available free of charge under the fair
use principles" (URLhaus API and ThreatFox API documentation, retrieved 2026-08-09). A published
API with issued credentials and worked command-line examples is an invitation to automate; the
site-wide terms read as though it is not. The two documents are in tension, and per-indicator
interactive lookups plausibly sit inside "fair use". Bulk mode is the part that does not.

**What this means operationally, in one sentence each:**

- The exposure is contractual, not technical. Nothing here touches the passive boundary — abuse.ch
  never contacts the target, and neither endpoint submits anything (section 7).
- The remedy if abuse.ch objects is to stop, not to obfuscate. Do not rotate keys, spread requests
  across addresses, or change the User-Agent to look like a browser; the honest User-Agent is a
  control (section 5), and evading a terms enforcement would convert an accepted contractual risk
  into a deliberate one.
- Commercial use has a different answer. abuse.ch directs commercial users to the Spamhaus
  offering. If this tool ever becomes part of paid work, that is the route, and it is a decision
  for the operator before the fact rather than after.

## 5. Controls already in the code

| Control | Anchor |
|---|---|
| Non-public addresses refused on the `ip` path | `orchestrators.py:919-921` |
| Non-public addresses refused on the `domain` and `url` paths, and **reported as skipped** rather than silently dropped | `orchestrators.py:1126-1131`, `_skipped_address` at `:1024` |
| **Runtime egress allowlist** — a host not on the section 2 table raises `PassiveBoundaryViolation` before a socket opens | `utils/http.py:63` (list), `:112` (hook), `:173` (installed on the one client factory) |
| **Static passivity gate** — URL literals, forbidden endpoints, resolved request paths, non-GET verbs, and resolution sites, all checked at build time | `tests/test_passivity.py` |
| Only `utils/http.create_client()` may construct an HTTP client, so nothing can obtain an unhooked one | `tests/test_passivity.py::test_only_utils_http_constructs_a_client` |
| TLS verification on, never disabled | `utils/http.py:174` |
| Honest User-Agent — the tool names itself rather than impersonating a browser | `utils/http.py:128` |
| API keys redacted from every error payload, including the failing request URL | `utils/redact.py`, `orchestrators.py:251` |
| The abuse.ch Auth-Key travels in a request **header**, which query-parameter redaction cannot see, so it is redacted by literal value from the environment | `ABUSECH_AUTH_KEY` in `utils/redact._SECRET_ENV_VARS` |
| **No RDAP redirect is followed**, and the registry host resolved from IANA's bootstrap file is checked against the egress allowlist before a request is built | `providers/rdap.py:480`, `:723` (`follow_redirects=False`), `:196` (`registry_not_allowlisted`) |
| **The test suite cannot reach a live provider.** An unmocked request raises instead of going out, so a forgotten mock fails the build rather than spending quota under the operator's egress IP | `tests/conftest.py::no_real_network` |
| Redirect chains reported as NOT RESOLVED unless a third party's scan supplied one | `utils/urls.py:236-322` |
| Every hop of a passively-sourced redirect chain is **defanged** in human-facing output, so a report pasted into a ticket or a chat client carries no clickable target URL | `reporting/console.py:1857` |
| A URL whose **host** is a non-public address is withheld at triage as well as refused at the orchestrator | `cli.py:1116-1117` (triage), `orchestrators.py:1334` (orchestrator) |
| A pasted email body cannot crash the `bulk` path through its filesystem probe | `cli.py:1214-1217` (`_read_bulk_text`, the `except (OSError, ValueError, RuntimeError)` guard) |
| Investigation output is gitignored in bulk | `.gitignore:80-92` |
| No `POST` to any submission endpoint anywhere in the package | `tests/test_passivity.py` sections 3 and 5 |

## 6. Gaps this document does not paper over

These are real and open. They are tracked in `docs/ROADMAP.md`.

1. **The static gate cannot see a host assembled at runtime.** A URL-literal scan is blind to
   `client.get("https://" + target_host + "/")`. That specific hole is closed by the runtime
   allowlist hook, which inspects the URL actually about to leave — but the two halves protect
   each other only while both are maintained. If the hook is removed, the build stays green.
2. **The allowlist is host-level, not path-level.** `urlscan.io` and `www.virustotal.com` are
   permitted hosts, and each carries a submission route the allowlist alone would not stop. What
   stops those is the static gate (section 7 register, plus the resolved-path check that can tell
   `GET /api/v3/urls/<id>` from a `POST` at the collection) and the per-provider tests. Belt and
   braces, not one control.
3. **`urlscan.io` is allowlisted ahead of its orchestrator wiring.** `providers/urlscan.py` is
   complete and tested, but no orchestrator calls it yet (`orchestrators.py:192-198`). Until it
   does, the entry is a standing permission for a code path nothing exercises. It is the smallest
   honest state — the alternative was wiring the provider and the allowlist in different commits,
   which would have shipped a `PassiveBoundaryViolation` on every URL lookup in between.
4. **`reverse_ptr` exists and is unused** (`utils/dns.py:98`). It has no callers. Whether PTR
   lookups belong in a passive tool has not been decided; see roadmap item 2.5. It is inside the
   one sanctioned resolution module, so it cannot be called from anywhere else without failing
   the gate.
5. **A provider could still be wrong about its own API.** Every claim in section 2 about what an
   endpoint does is read from that provider's documentation. If VirusTotal or urlscan changed a
   `GET` route to trigger a fetch, nothing here would detect it.
6. **An over-long hostname is routed to VirusTotal.** `orchestrators._url_target_error` checks a
   URL's scheme, the presence of a host and its routability, but not the RFC 1035 253-octet limit,
   so a 4000-character name from a pasted mail spends a quota unit on a string that cannot have a
   report. Not a passivity breach — the request goes to VirusTotal, not the target — but it is
   pinned as a current-behaviour finding in
   `tests/test_w6_passivity_audit.py::test_an_overlong_hostname_is_routed_and_that_is_a_known_finding`.
7. **An IDN homograph is displayed in its Unicode form.** `bulk` triage shows `аpple.com`
   (Cyrillic U+0430) as written, which renders identically to `apple.com`. `utils/urls.parse_url`
   computes the A-label and records `HOST_MIXED_SCRIPT`, but `types/indicators.detect` does not
   carry either into the triage row. The row is marked `probable` rather than `certain`, which is
   a hint and not a warning.
8. **~~A future provider will ask for `follow_redirects=True`.~~ CLOSED, and closed the other
   way.** This gap anticipated RDAP arriving via the `rdap.org` aggregator, which answers `302`,
   and warned that the flag would have to be bounded to allowlisted hosts. RDAP landed
   (`providers/rdap.py`) and **does not use the aggregator and does not follow redirects at all**:
   it bootstraps from IANA's static files client-side and calls the registry directly, with
   `follow_redirects=False` set explicitly on both requests and a `3xx` reported as
   `unexpected_redirect` rather than followed. No exception was written into section 7, because
   none was needed. A grep of the package for `follow_redirects` returns exactly those two `False`
   settings and nothing else. The gap is retained rather than deleted so the next provider that
   wants the flag finds the reasoning that refused it.
9. **RESOLVED 2026-08-09: the registry allowlist was reviewed and populated.** This gap read "no
   registry RDAP host is allowlisted, so RDAP answers UNKNOWN for everything", which was true as
   shipped and made the highest-value source in W8 inert. The five RIRs plus the high-volume
   gTLD/ccTLD registries were read from the IANA bootstrap files and added host by host; `.ru` and
   `.cn` were reviewed and deliberately excluded. See section 2. What remains is the long tail of
   ~270 further service entries, which stay unlisted on purpose: each is a party that would learn
   the operator's indicator list, and an unlisted TLD fails closed with the host named rather than
   failing silently.

   Note the structural constraint before attempting it: `tests/test_passivity.py`'s
   `test_allowlist_has_no_dead_entries` requires every allowlisted host to appear as a URL literal
   somewhere in the package, and `providers/rdap.py` is pinned by its own test to exactly one
   literal (`data.iana.org`). A reviewed registry table therefore needs somewhere to live that is
   neither of those two places.

## 7. Endpoints that must never be added

Each of these has a passive sibling on the same API, which is exactly why they get reached for by
mistake. **There is no flag for any of them.** If the passive sibling cannot answer the question,
the answer is that the question belongs in a different tool.

Every row is enforced by `tests/test_passivity.py`, which greps the whole package on every run.
The first three sit on hosts this tool already contacts, so they are one line away at all times.

| Forbidden | Why | Passive alternative |
|---|---|---|
| VirusTotal **`POST /urls`** (submission to the URL collection) | Instructs VirusTotal's own crawler to **fetch the target**, and publishes the indicator to the VT community feed | `GET /api/v3/urls/<url_id>` for the report that already exists — `providers/virustotal.vt_url_summary`. A 404 there is a terminal **UNKNOWN**, never an invitation to submit |
| VirusTotal **`POST /analyses`**, and reading any `/analyses/<id>` object | An analysis object is the **receipt for a submission**. Holding one to read means something in this codebase submitted the target | `last_analysis_stats` on the existing `ip_addresses/`, `domains/` or `urls/` report |
| urlscan.io **`POST /api/v1/scan/`** | Loads the target in a **real browser** from urlscan infrastructure and, unless explicitly made private, **publishes the scan** — so the target learns it is being investigated, and so does everyone reading the public feed | urlscan **Search** (`GET /api/v1/search/`) for a scan somebody else already ran, then **Result** (`GET /api/v1/result/<uuid>/`) to read it. `providers/urlscan.urlscan_url_summary` composes the two |
| urlscan.io screenshot / DOM **retrieval** | Does not touch the target, but is bulk retrieval of urlscan's data that their best-practice page asks integrators not to do, and the payload has no use for the bytes | Emit the screenshot **URL** as a clickable pivot; `urlscan_screenshot_fetched` stays `False` |
| Pulsedive `probe=1` | Triggers live scanning | Default passive query |
| MalwareBazaar `get_file` | Downloads live malware | Metadata query |
| Spamhaus live `zen` DNSBL | Per-IP query leaks the indicator | Downloadable DROP list |
| Tor DNSEL per-IP | Per-IP query leaks the indicator | Bulk exit list |
| **Any redirect or shortener expansion**, `follow_redirects=True` and `HEAD` included | A redirect resolution is an active fetch. The target's server logs the request and its source; a single-use link is burned by the lookup; and a kit that serves benign content to its first visitor inverts the verdict | The cached chain VirusTotal (`redirection_chain`, `last_final_url`) or urlscan (`data.redirects`) already recorded — carried with its source and observation date, and reported as **NOT RESOLVED** when nobody has one |

### How each row is enforced

Two mechanisms, because a substring marker alone is either too broad to live with or too narrow
to trust:

1. **Line-level markers** (`FORBIDDEN_MARKERS`) grep the package source for the forbidden path,
   the `probe=1` form, the DNSBL hostnames, `follow_redirects=True` and `.head(`.
2. **Resolved-path checks** (section 5 of `tests/test_passivity.py`) rebuild the destination of
   every `client.<verb>(...)` call through the module constants that assemble it, then assert
   that no resolved path ends at a submission collection, that `analyses` appears nowhere, and
   that **every non-GET request goes to one of the pinned read-only query endpoints**
   (`NON_GET_DESTINATIONS`). This is what distinguishes `GET .../api/v3/urls/{url_id}` from
   `POST .../api/v3/urls`, which no substring can do, and it is what closes the "hide the path in
   a constant" walkaround.

### POST-as-QUERY: why four POSTs are not four submissions

**Do not "fix" these into `GET`s. They cannot be, and the verb is not what makes a request
active.** A submission is a request that makes the provider go and *look at the target*. A query
is a request that makes the provider *read its own database*. HTTP verbs do not distinguish the
two, and three of the APIs this tool uses take their queries in a request body:

| Call | Body | Why it is a query |
|---|---|---|
| Cloudflare Radar GraphQL (`providers/cloudflare_radar.py`, ×2) | GraphQL document | GraphQL is POST-only by design. It reads Radar's aggregates; there is no write route on it |
| abuse.ch URLhaus `POST /v1/url/` (`abusech.py:108`) | form field `url=` | Looks up whether URLhaus already holds a record for that URL. abuse.ch does not fetch it |
| abuse.ch URLhaus `POST /v1/host/` (`abusech.py:113`) | form field `host=` | Same, keyed by host. Accepts an IPv4 address, a hostname or a domain |
| abuse.ch ThreatFox `POST /api/v1/` (`abusech.py:116`) | JSON `{"query": "search_ioc", ...}` | One endpoint dispatching on a selector. This tool sends exactly one selector, `search_ioc` (`THREATFOX_SEARCH_QUERY`, `abusech.py:121`), named as a constant so a reviewer can see no write selector is reachable |

**The ThreatFox endpoint is the one to watch**, because its URL is shared between read and write
operations — the selector, not the path, is what makes the call passive. That is why
`THREATFOX_SEARCH_QUERY` is a module constant rather than an inline string.

**What stops any of these drifting into a submission**, since the allowlist is host-level and
would not:

- `PINNED_POST_SITES` in `tests/test_passivity.py` pins each call site by *module and constant
  name* and by *how many times it appears*, so a fourth abuse.ch POST fails the build.
- `test_abusech_query_endpoint_constants_are_unchanged` and
  `test_radar_graphql_endpoint_constant_is_unchanged` pin each constant's resolved *value*,
  because pinning by name is worthless if the name can be repointed. The abuse.ch check resolves
  through `URLHAUS_BASE`, so moving the base is caught too.
- `test_every_non_get_request_goes_to_the_one_pinned_query_endpoint` asks the same question of the
  statically resolved destination rather than of the constant's name.

Neither abuse.ch endpoint submits anything. Both platforms have separate, credentialled submission
routes; this package does not name them anywhere, and adding one would be the change this section
exists to prevent. The terms-of-service exposure that *does* attach to abuse.ch is contractual and
is recorded in section 4a, not here.
