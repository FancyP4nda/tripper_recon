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

Twelve outbound paths appear below. Eleven go to a third party that is not the target. Every one
of them is enforced at runtime by the egress allowlist (`utils/http.py:63`), which raises
`PassiveBoundaryViolation` before a socket opens for any host not on this table.

| Provider | Host contacted | Reaches target infrastructure? |
|---|---|---|
| VirusTotal | `www.virustotal.com` | No |
| Shodan | `api.shodan.io` | No |
| AbuseIPDB | `api.abuseipdb.com` | No |
| IPInfo | `ipinfo.io` | No |
| AlienVault OTX | `otx.alienvault.com` | No |
| Cloudflare Radar | `api.cloudflare.com` | No |
| Cloudflare BGP | `api.cloudflare.com` | No |
| RIPEstat | `stat.ripe.net` | No |
| CAIDA AS-Rank | `api.asrank.caida.org` | No |
| PeeringDB | `www.peeringdb.com` | No |
| **urlscan.io** | `urlscan.io` | No — see below |
| **System resolver** | your configured DNS resolver | **Yes, indirectly** — see section 3 |

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

**Planned.** Passive DNS becomes the default and live resolution moves behind an explicit
`--active-dns` flag, with the collection mode recorded in the output. `docs/ROADMAP.md` item 2.2.

## 4. What the third-party providers learn

Passive does not mean invisible. It means the *target* does not see you. The providers do.

- **Every query is attributable to your API key.** A VirusTotal lookup is logged against your
  account. Assume your employer, the provider, and anyone with access to provider logs can see
  which indicators you investigated and when.
- **Your egress IP is visible** to all eleven providers.
- **The indicator list itself is sensitive.** The set of things you are looking at can reveal an
  ongoing incident before you are ready to disclose it.
- **Look-ups are not submissions.** Nothing in this tool contributes your indicators to a public
  corpus. A VirusTotal *lookup* does not appear in the community feed the way a *submission* does.

If an investigation is sensitive enough that provider visibility is itself a risk, this tool is
the wrong instrument. Use an offline data set.

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
| Redirect chains reported as NOT RESOLVED unless a third party's scan supplied one | `utils/urls.py:236-322` |
| Every hop of a passively-sourced redirect chain is **defanged** in human-facing output, so a report pasted into a ticket or a chat client carries no clickable target URL | `reporting/console.py:1857` |
| A URL whose **host** is a non-public address is withheld at triage as well as refused at the orchestrator | `cli.py:904` (triage), `orchestrators.py:1334` (orchestrator) |
| A pasted email body cannot crash the `bulk` path through its filesystem probe | `cli.py:996` |
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
8. **A future provider will ask for `follow_redirects=True`.** `docs/ROADMAP.md` item 8.2 proposes
   RDAP via `rdap.org`, which answers with a 30x to the authoritative registry server. That is a
   redirect **within provider infrastructure**, not a fetch of the target, so it is not the thing
   section 7 forbids — but the distinction is one sentence wide and the flag is set per-request on
   a shared client. If that provider lands, the redirect must be bounded to allowlisted hosts and
   the exception written into section 7 explicitly, not inherited by every other call.

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
   that **every non-GET request goes to the one pinned read-only query endpoint** (Cloudflare's
   Radar GraphQL API, which is POST but reads). This is what distinguishes
   `GET .../api/v3/urls/{url_id}` from `POST .../api/v3/urls`, which no substring can do, and it
   is what closes the "hide the path in a constant" walkaround.
