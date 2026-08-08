# tripper_recon — Passivity and OPSEC Audit

**Repo:** `/home/echo/dev/tripper_recon` @ `feat/work-20260808-recon-hardening` (base commit `de277f4`)
**Lens:** passivity and OPSEC — does the tool ever touch adversary infrastructure, and what leaks where?
**Method:** static read of all 22 Python files. No execution, no network calls, no `.env` access.
**Date:** 2026-08-08

---

## Bottom line

The provider layer is genuinely passive and well-built for it. Of roughly fourteen distinct outbound
network paths, **thirteen terminate at a third-party intelligence API and cannot reach infrastructure the
target controls.** There is no urlscan submission, no VT `POST /urls`, no Shodan `POST /shodan/scan`, no
AbuseIPDB `/report`, no HTTP fetch of the target URL, no TLS handshake against the target, and no port-43
whois socket. The only two `POST` calls in the codebase are the Cloudflare Radar GraphQL transport
(`providers/cloudflare_radar.py:37`, `:62`), which is a query to Cloudflare, not a submission about the
target. That restraint is deliberate and it is the hard part; credit where due.

**One path breaks the constraint, and it is on the default code path for the most common invocation.**
`investigate_domain` calls the system resolver against the target domain unconditionally
(`orchestrators.py:248` → `utils/dns.py:14`). For a freshly registered phishing domain — the exact case an
analyst triages — that recursive lookup has a high probability of reaching the adversary's own
authoritative nameserver and telling them, in near real time, that someone is looking. There is no flag to
disable it and no indication in the output that it happened.

Two further findings are, in my judgment, as operationally serious as the DNS leak even though they are not
passivity violations:

- **The Shodan and IPinfo API keys are passed in the query string and are rendered verbatim into console
  output and JSON reports on any HTTP error** (`shodan_api.py:18` → `orchestrators.py:38` →
  `console.py:153`). A `401` from an expired Shodan key — the single most likely error an analyst hits —
  prints the key into the terminal and into the JSON blob they paste into a ticket.
- **The domain path applies no private-IP filter**, so an RFC1918 address in a target's DNS records is
  forwarded to VirusTotal, Shodan, AbuseIPDB, IPinfo and OTX (`orchestrators.py:253`). The IP path guards
  against this (`orchestrators.py:109`); the domain path does not.

The browser User-Agent spoof is a real defect but a different kind: it does not touch the target, so it is
not a passivity break. It is a professionalism and defensibility problem, and it directly contradicts the
tool's own good-citizen `sourceapp=tripper-recon` parameter sent to RIPEstat.

---

## 1. Complete outbound network inventory

Every outbound call, its destination, and whether it can reach target-controlled infrastructure. All HTTP
traffic flows through the single client in `utils/http.py:41-51` (`verify=True`, HTTP/2, 15 s timeout).

### 1.1 Cannot reach the target (13 paths)

| # | Call site | Destination | Method | Auth carried | Reaches target? |
|---|---|---|---|---|---|
| 1 | `providers/virustotal.py:20` | `www.virustotal.com/api/v3/ip_addresses/{ip}` | GET | `x-apikey` header | No |
| 2 | `providers/virustotal.py:47` | `www.virustotal.com/api/v3/domains/{domain}` | GET | `x-apikey` header | No |
| 3 | `providers/shodan_api.py:18` | `api.shodan.io/shodan/host/{ip}` | GET | **key in query string** | No |
| 4 | `providers/abuseipdb.py:20` | `api.abuseipdb.com/api/v2/check` | GET | `Key` header | No |
| 5 | `providers/ipinfo.py:18` | `ipinfo.io/{ip}` | GET | **token in query string** | No |
| 6 | `providers/ipinfo.py:62` | `ipinfo.io/AS{asn}` | GET | **token in query string** | No |
| 7 | `providers/otx.py:20` | `otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general` | GET | `X-OTX-API-KEY` header | No |
| 8 | `providers/otx.py:44` | `otx.alienvault.com/api/v1/indicators/domain/{domain}/general` | GET | `X-OTX-API-KEY` header | No |
| 9 | `providers/cloudflare_radar.py:37`, `:62` | `api.cloudflare.com/client/v4/radar/graphql` | **POST** | `Bearer` header | No — GraphQL transport |
| 10 | `providers/cloudflare_rest.py:19`, `:20` | `api.cloudflare.com/client/v4/radar/bgp/{hijacks,leaks}/events` | GET | `Bearer` header | No |
| 11 | `providers/ripestat.py:15` (5 endpoints, `:26`–`:42`) | `stat.ripe.net/data/...` | GET | none | No |
| 12 | `providers/caida.py:15` | `api.asrank.caida.org/dev/restful/asns/{asn}` | GET | none | No |
| 13 | `providers/peeringdb.py:16`, `:27` | `www.peeringdb.com/api/net` | GET | none | No |

Two points worth stating explicitly because a reviewer skimming for `POST` will misread them:

- **Path 9 is a POST but is not active collection.** Cloudflare Radar's GraphQL endpoint requires POST as
  its transport. The request body (`cloudflare_radar.py:18-28`) is a query for ASN metadata. Nothing is
  submitted about the target and nothing reaches the target.
- **Path 1/2 (VirusTotal) is a read, not a submission.** `GET /api/v3/domains/{domain}` retrieves an
  existing report. The code never calls `POST /urls`, `POST /files`, or `POST /analyses`, so it never
  triggers a fresh scan and never puts a URL into VT's live-scanning pipeline. The whois shown to the
  analyst comes from VT's cached `attributes.whois` field (`virustotal.py:58`), not from a live port-43
  query — correct and passive.

Similarly, `abuseipdb.py:20` uses `/check` and never `/report`, and `shodan_api.py:18` uses
`/shodan/host/{ip}` (cached scan data) and never `/shodan/scan` (which enqueues a live scan). These are the
right endpoint choices and they are the whole reason the tool is nearly passive.

### 1.2 Can reach the target (1 path)

| # | Call site | Destination | Reaches target? |
|---|---|---|---|
| 14 | `utils/dns.py:14` via `orchestrators.py:248` | System resolver → recursive → root → TLD → **target's authoritative NS** | **Yes** |

Detailed below.

### 1.3 Defined but not called

`utils/dns.py:26-34` `reverse_ptr()` is defined and never invoked anywhere
(`orchestrators.py:254` hardcodes `ptr = None` and `:311` emits that null). It would cross the passive
boundary if wired up. Treated as a latent defect below.

---

## 2. Findings

### F1 — `resolve_domain` performs live recursive DNS against the target on the default path
**Severity: critical. Confidence: certain (behaviour), likely (magnitude of exposure).**
**Anchor:** `tripper_recon/utils/dns.py:14`, called from `tripper_recon/orchestrators.py:248`

```python
# orchestrators.py:247-249
from tripper_recon.utils.dns import resolve_domain
active_ips = await resolve_domain(domain)
ips = active_ips + passive_ips
```

`socket.getaddrinfo(domain, ...)` (`dns.py:14`) hands the target's name to the host's configured recursive
resolver for both A and AAAA. If the recursive does not already hold the record, it walks the delegation
chain and **queries the nameserver the target operates**. The adversary's authoritative server observes:
the QNAME, a timestamp, the query type, and the source address of the recursive resolver.

Why this matters more than it might sound:

- **This is instrumented tradecraft, not a theoretical channel.** Operators of phishing and C2 domains
  routinely watch authoritative DNS logs. A common pattern is a per-victim unique hostname
  (`<token>.cdn.example.com`) embedded in a phishing lure; a lookup for that exact label is directly
  attributable to the organisation that received the lure, and it tells the adversary their campaign has
  been detected. The usual response is to burn the infrastructure and rotate, which destroys the analyst's
  remaining collection opportunity.
- **The cache-hit argument does not rescue it.** A busy recursive may answer from cache without touching
  the authoritative, and for a high-volume domain it usually will. But the analyst has no way to know which
  case they got, and the population of domains an analyst types into this tool is skewed hard toward
  *newly registered, low-traffic* names — precisely the cache-miss case. Negative caching does not help
  either: an NXDOMAIN for a not-yet-live domain is also frequently forwarded.
- **EDNS Client Subnet may widen the leak from "some resolver" to "this network."** Several large public
  resolvers forward a truncated client prefix to the authoritative. Whether that happens depends entirely
  on the resolver the analyst's host is configured against, which the code neither knows nor records. I am
  not asserting it happens in the operator's environment — I am flagging that the code cannot rule it out.

**Aggravating factor — the provenance is then destroyed.** Line 249 concatenates live-resolved IPs with
VT passive-DNS IPs, and line 251 dedupes them. After that merge nothing in the data structure or the
rendered output distinguishes an IP the analyst's own host resolved from an IP VirusTotal observed
passively weeks ago. The variable names at `orchestrators.py:248` and `:221` (`active_ips` /
`passive_ips`) show the author understood the distinction; it simply never reaches the analyst. The
console renderer prints the merged list with no label (`cli.py:283`, `cli.py:289-293`).

**What would settle the exposure magnitude:** run `tcpdump -n port 53` on the analyst host while resolving
a controlled lab domain whose authoritative NS you own, and inspect that NS's query log for the source
address and any ECS option. That is the only way to characterise the real leak in a given deployment.

---

### F2 — Shodan and IPinfo API keys are printed to console and written into JSON reports on HTTP error
**Severity: critical. Confidence: certain.**
**Anchor:** `tripper_recon/orchestrators.py:38`

Both providers pass credentials as URL query parameters:

```python
# shodan_api.py:18
r = await client.get(f"{SHODAN_BASE}/shodan/host/{ip}", params={"key": api_key})
# ipinfo.py:18, :62
r = await client.get(f"{IPINFO_BASE}/{ip}", params={"token": token})
```

The full request URL — key included — then propagates into user-visible output. The chain is unbroken:

1. `r.raise_for_status()` raises `httpx.HTTPStatusError` (`shodan_api.py:21`).
2. `with_exponential_backoff` exhausts retries and re-raises (`utils/backoff.py:29`).
3. `orchestrators.py:143` catches it and calls `_error_payload`, which stores
   `"url": str(req.url)` (`orchestrators.py:38`) **and** `"message": str(err)` (`:39`) — httpx's own
   exception text embeds the same URL, so redacting one field is not sufficient.
4. `_error_details` strips only the `ok` key (`orchestrators.py:53`); the payload lands in
   `data["errors"]` (`:188`) and in the `result_errors` string list (`:177`, via `_error_summary` at `:67`).
5. Console rendering prints it: `console.py:153-155` (`parts.append(f"url={url}")`) and
   `cli.py:41-42`.
6. JSON rendering prints it: `cli.py:181` → `cli.py:196` (`console.print_json`), and the FastAPI
   response body at `api/server.py:28`.

The triggering condition is the most common operational error there is: an expired key, an exhausted
Shodan credit balance, or a 429. The output is exactly the artifact an analyst attaches to a ticket or
pastes into a chat channel. This is credential disclosure into a shared system with no attacker
involvement required.

Note `cloudflare_radar.py:39` additionally echoes `r.text[:500]` of the error body into the payload. The
Cloudflare token travels in an `Authorization` header rather than the URL, so it is not directly exposed,
but echoing raw provider response bodies into analyst-facing output is the same class of mistake.

---

### F3 — Domain path forwards private and internal IPs to five third-party providers
**Severity: high. Confidence: certain.**
**Anchor:** `tripper_recon/orchestrators.py:253`

`investigate_ip` correctly refuses private addresses:

```python
# orchestrators.py:109-110
if ip_obj.is_private:
    return InvestigationResult(ok=False, errors=[f"Private IP address {ip} cannot be investigated."], ...)
```

`investigate_domain` applies no equivalent check. Every IP in the merged list — whether from the analyst's
own resolver (`:248`) or from VT's `last_dns_records` (`:227-235`) — enters the enrichment loop at `:253`
and is sent to VirusTotal (`:256`), Shodan (`:260`), IPinfo (`:264`), AbuseIPDB (`:268`) and OTX (`:272`).

Concrete ways an RFC1918 or loopback address arrives there:

- Split-horizon DNS, where the analyst's corporate resolver returns the internal address for a name that
  also exists externally. The tool then submits the organisation's internal addressing to five commercial
  APIs, keyed to the operator's identity.
- Sinkholed or blocked domains, which commonly resolve to `127.0.0.1` or an internal sinkhole address.
- Deliberate adversary fingerprinting: an attacker who points an A record at `10.x.x.x` learns which
  analysts have split-horizon resolution and can watch for the resulting third-party lookups.

Secondary gap on the IP path: `is_private` does not cover multicast or reserved space
(`224.0.0.0/4`, `240.0.0.0/4` return `is_private == False`), so those pass the `:109` guard. Lower impact
than the domain gap, but the guard should be `is_private or is_reserved or is_multicast or is_unspecified`.

---

### F4 — `reverse_ptr` is an uncalled passive-boundary violation left in the tree
**Severity: medium. Confidence: certain (dead), unsure (glibc double-lookup behaviour).**
**Anchor:** `tripper_recon/utils/dns.py:26`

```python
async def reverse_ptr(ip: str) -> str | None:
    def _rev() -> str | None:
        try:
            host, _aliases, _addrs = socket.gethostbyaddr(ip)
```

Grep confirms no caller: `orchestrators.py:254` sets `ptr = None` and `:311` emits that constant, so the
`ptr` field in every domain result is permanently null — a second, smaller defect (a field that always
lies by omission).

If wired up, `gethostbyaddr` issues a PTR query in `in-addr.arpa`. Reverse delegation follows the IP
block, so for cloud-hosted targets the query reaches the cloud provider, not the adversary — genuinely
lower risk than F1. But for self-hosted, bulletproof-hosted, or leased-range infrastructure where the
adversary holds the reverse delegation, it is a direct tip-off with the same consequences as F1.

I am **not certain** whether CPython's `gethostbyaddr` triggers glibc's forward-confirmation lookup (which
would add a second, forward query to the attacker's zone) — that depends on the platform resolver and
`nsswitch.conf`. It would be settled by `strace -f -e trace=network` or a packet capture against a lab
zone. Either way the recommendation is the same: delete it, or gate it identically to F1. Leaving an
uncalled boundary-crossing helper in a tool whose headline property is "passive" is a trap for whoever
touches this file next.

Minor: the bare `except Exception` at `dns.py:31` would swallow the distinction between NXDOMAIN, timeout,
and resolver misconfiguration.

---

### F5 — Browser User-Agent spoofing is the default, and `--help` calls it "spoof"
**Severity: high. Confidence: certain.**
**Anchor:** `tripper_recon/utils/http.py:10`

```python
_DEFAULT_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0"
)
```

Applied to every outbound request via `default_headers()` (`http.py:35`) → `create_client()` (`:45`),
restated in `.env.example:24-25`, and exposed as `--user-agent` whose help text reads *"Custom User-Agent
string to spoof in HTTP requests"* (`cli.py:384`).

**To be precise about the category:** this is not a passivity violation. The UA only ever reaches the
thirteen third-party APIs, never the target. But it is wrong for this tool for four reasons:

1. **It buys nothing.** Every destination is an authenticated JSON API that authorises on the API key.
   There is no WAF, no bot filter, and no browser check to get past. The spoof is pure cost.
2. **It contradicts the tool's own good behaviour.** `providers/ripestat.py:26`, `:30`, `:34`, `:38`, `:42`
   correctly send `sourceapp=tripper-recon` — RIPE explicitly asks callers to identify themselves so they
   can be contacted about load rather than blocked. Sending that parameter while simultaneously
   impersonating Edge on Windows is self-defeating. The same identification concern applies to the other
   unauthenticated free datasets, CAIDA (`caida.py:15`) and PeeringDB (`peeringdb.py:16`), which have no
   API key to identify the caller at all — the UA is the *only* identity they get.
3. **It is indefensible in a report.** The operator's stated goal is defensibility of the answer. "The tool
   misrepresented its identity to the intelligence providers" is a question you do not want asked about
   your evidence chain, and in a federal or regulated setting it reads as deliberate evasion regardless of
   intent.
4. **The `--help` string is the wrong signal.** A SOC tool whose own documentation advertises spoofing
   invites exactly the wrong assumption about what else it does. This is the first thing a reviewer sees.

**Fix:** default to `tripper-recon/{__version__} (+https://github.com/FancyP4nda/tripper_recon)`, with an
optional `TRIPPER_RECON_CONTACT` appended when set. Keep the `--user-agent` override — there are legitimate
reasons to change it — but reword the help to "Override the outbound User-Agent (default identifies this
tool)."

---

### F6 — API server binds `0.0.0.0` unauthenticated, exposing a remote DNS-leak and quota-burn oracle
**Severity: high. Confidence: certain.**
**Anchor:** `tripper_recon/api/server.py:50`

```python
uvicorn.run(app, host="0.0.0.0", port=8000)
```

No authentication, no allowlist, no rate limiting. Anyone who can reach port 8000 can call
`GET /domain/{domain}` (`server.py:31`), which reaches `orchestrators.py:248` and **causes the analyst's
host to perform a live recursive DNS lookup of an attacker-chosen name.** That turns F1 from a
self-inflicted leak into a remotely triggerable one, and gives an adversary a way to confirm the analyst
host's resolver path and network position at will.

Secondary consequences of the same exposure: unmetered spend of the operator's paid VT/Shodan/IPinfo
quota, and attribution of arbitrary third-party lookups to the operator's API keys and identity.

`0.0.0.0` is defensible only if the process is known to sit behind an authenticating proxy, and nothing in
the repo says it does. Default to `127.0.0.1`, make the bind address a flag, and require a bearer token
before accepting any indicator.

---

### F7 — No provenance or freshness label on any fact in the output
**Severity: high. Confidence: certain.**
**Anchor:** `tripper_recon/types/models.py:35`

`InvestigationResult` carries `ok`, `data`, `warnings`, `errors` and nothing else. There is no per-fact
source, no collection method, and no observation timestamp. The renderer emits bare values —
`open_ports` (`console.py:130`), `virustotal_detections` (`:79`), `abuseipdb_confidence_score` (`:96`) —
with no indication of when the underlying observation was made or how it was obtained.

Two distinct problems for an incident report:

- **Method is invisible.** Per F1, the IP list mixes live-resolved and passive-observed addresses with no
  way to tell them apart. An analyst cannot state in a report which addresses were confirmed live and which
  are historical, and cannot answer "did we touch it?" — which is the question that matters after a
  detected investigation.
- **Staleness is invisible.** Shodan host data can be weeks or months old; VT `last_analysis_date` and
  Shodan `last_update` are both present in the API responses and both discarded by the parsers
  (`shodan_api.py:22-29`, `virustotal.py:24-35`). Presenting a months-old cached port list as a current
  fact is a defensibility defect, and it is the kind of error that survives into a report unchallenged
  because the output looks authoritative.

---

### F8 — `--enrich` help text promises a whois lookup that does not exist, and pre-authorises an active one
**Severity: medium. Confidence: certain.**
**Anchor:** `tripper_recon/cli.py:403`

The flag is documented as *"Enrich prefix info via whois/pWhois (slower)"*. The implementation
(`orchestrators.py:529-537`) makes **no network call at all** — the comment says "placeholder aggregation
(fast). Full whois/pWhois can be added later" and it simply slices the already-fetched RIPE prefix lists.

Two problems. The immediate one is that `--help` describes behaviour the tool does not have. The larger one
is that it is a landmine: the flag, its name, and its documentation all pre-authorise a future contributor
to add a real whois path. A naive implementation opens a TCP socket to port 43 on a whois server —
generally a registry, so usually not the target, but referral-following whois clients chase
`refer:`/`ReferralServer:` fields, and for a target that runs its own whois or is served by a bulletproof
registrar's infrastructure that referral can land on the adversary. Decide the policy now, while the code
is a no-op, rather than after someone fills it in.

---

### F9 — Nothing discloses that every indicator is reported to up to six commercial providers
**Severity: medium. Confidence: certain.**
**Anchor:** `README.md:78`

The README lists the providers as data sources but never states the corollary: **every indicator the
analyst types is disclosed to those providers, timestamped and bound to the operator's API key, and
therefore to the operator's account and organisation.** For an analyst under time pressure this is the
blast radius they are implicitly accepting, and for the operator's environment specifically, "which of our
investigations are visible to VirusTotal and Shodan" is a legitimate counterintelligence question that the
tool should answer up front rather than leave to be discovered.

On VirusTotal specifically: because the code only ever performs `GET` on existing reports and never
submits (see §1.1), **the tool does not push indicators into VT's community-visible submission stream.**
That is the important distinction and the code gets it right. What I cannot verify from the code is how
much *lookup* telemetry VT retains and what portion of it VT surfaces to its Enterprise customers. That
should be settled from VirusTotal's own API documentation and privacy terms before the tool is used
against sensitive indicators — it is not knowable from this repo, and I am not going to assert it either
way.

Add a short "What this tool discloses, and to whom" section to the README, and print a one-line notice on
first run listing which providers are enabled by the configured keys.

---

### F10 — `--rate-limit` is silently ignored on the IP path
**Severity: low. Confidence: certain.**
**Anchor:** `tripper_recon/utils/http.py:62`

`RateLimiter.__init__` creates the process-global semaphore on first construction using its `rate`
argument, ignoring `_init_rate` set by `configure_rate_limit` (`http.py:57-59`, called from `cli.py:415`).
`orchestrators.py:117` constructs it with a hardcoded `rate=5`, so on the IP path the operator's
`--rate-limit` value never takes effect.

Separately, the acquire/release pattern at `orchestrators.py:120-129` releases the semaphore immediately
after `create_task` returns, before any HTTP request is issued — so it does not bound concurrency at all.
Bulk mode (`cli.py:150-151`) gathers every target simultaneously on top of that.

Listed under this lens because throttling against the unauthenticated free datasets (RIPEstat, CAIDA,
PeeringDB) is an etiquette obligation, and an ungoverned burst from a browser-UA client (F5) is what gets a
source IP blocked.

---

## 3. Proposed design

### 3.1 `--passive` strict by default, with narrow explicit opt-in

Add a three-state collection mode resolved once in `main()` and threaded through the orchestrators as an
explicit parameter — not a module global, so the API server and any future library consumer must state
their choice.

| Mode | Flag | Behaviour |
|---|---|---|
| **strict** (default) | *(none)* | Third-party APIs only. `resolve_domain` is **not called**. Domain IPs come solely from VT `last_dns_records` and OTX passive DNS. |
| **grey, opt-in** | `--allow-active-dns` | Permits live forward resolution. Emits a prominent pre-flight warning naming the domain and the risk. Every resulting IP is labelled `method: active_dns`. |
| **grey, opt-in** | `--allow-active-ptr` | Permits reverse PTR, only if F4's helper is retained. Separate flag — the risk profiles differ and they should not be bundled. |

Design constraints that make this hold:

1. **Strict must be a hard refusal, not a warning.** If `resolve_domain` is reached without the flag, raise.
   A mode that degrades to "warn and proceed" is a mode that gets ignored at 2 a.m.
2. **Strict must still work.** VT's `last_dns_records` (already parsed at `orchestrators.py:227-235`) plus
   OTX passive DNS (currently only counted at `otx.py:60`, not extracted) give a usable IP list without
   touching anything. Extract the OTX records so strict mode is not visibly worse than active mode.
3. **The flag must appear in the output**, not just in the invocation — see §3.2.
4. **The API server never gets these flags.** `api/server.py` should be strict-only, unconditionally.
   Remote callers must not be able to induce a DNS leak from the analyst's host (F6).
5. **A passive-mode assertion belongs in CI.** A test that monkeypatches `socket.getaddrinfo` and
   `socket.gethostbyaddr` to raise, then runs a full domain investigation in strict mode against recorded
   fixtures, turns the hard constraint into something the test suite enforces rather than something the
   README claims.

### 3.2 Per-result provenance labelling

Attach provenance to each fact rather than to the result as a whole. Minimal shape:

```python
class Provenance(BaseModel):
    source: str           # "virustotal" | "shodan" | "system_resolver" | ...
    method: Literal["passive_cache", "passive_dataset", "active_dns", "active_ptr"]
    observed_at: datetime | None   # provider's own timestamp, not fetch time
    retrieved_at: datetime
```

Applied at three levels:

- **Each IP in the domain result** carries its own `Provenance`, so `active_dns` and `passive_cache`
  addresses stay distinguishable through the merge at `orchestrators.py:249-251`. Where the same IP appears
  from both, keep both records rather than deduping one away — that agreement is itself evidence.
- **Each provider block** records `observed_at` from the data the API already returns and the parsers
  currently discard: VT `last_analysis_date`, Shodan `last_update`. This is what fixes the staleness half
  of F7 and it costs two lines per parser.
- **The result envelope** records the collection mode actually used, so a JSON report carries proof of
  whether the run was passive.

Console rendering, minimally intrusive — the analyst is in a hurry, so the label should be one glyph plus a
suffix on the rows that need it:

```
--- Domain lookup for example.com ---
  collection_mode               strict-passive  (no traffic to target infrastructure)

  resolved_ips
    93.184.216.34               passive · VirusTotal DNS record · observed 2026-08-01
    93.184.216.35               ACTIVE  · system resolver · observed 2026-08-08   <-- only ever with --allow-active-dns
  open_ports                    80, 443  (Shodan cache, last scan 2026-06-12)
```

The `ACTIVE` marker doing double duty — provenance for the report and a visible consequence of the flag —
is what keeps the opt-in honest over time.

### 3.3 Immediate fixes, ordered

1. **F2** — move the Shodan and IPinfo credentials out of the query string where the provider supports a
   header, and unconditionally redact query parameters from `str(req.url)` and from `str(err)` in
   `_error_payload` (`orchestrators.py:38`, `:39`, `:46`). Redact at the point of capture, not at each
   render site; there are already three render sites (`console.py:153`, `cli.py:41`, `server.py:28`) and
   there will be more.
2. **F1 / F6** — make strict passive the default and bind the API server to `127.0.0.1` behind a token.
3. **F3** — apply `is_private or is_reserved or is_multicast` filtering to every IP entering the
   enrichment loop at `orchestrators.py:253`, and report filtered addresses to the analyst rather than
   dropping them silently.
4. **F5** — replace the browser UA default and reword `cli.py:384`.
5. **F4** — delete `reverse_ptr` or gate it; either way, remove the always-null `ptr` field or populate it.
6. **F7** — capture provider timestamps in the parsers; the model change can follow.
7. **F8 / F9** — correct the `--enrich` help text; add the disclosure section to the README.

---

## 4. What I did not verify

- No code was executed and no network call was made. All findings are from static reading; behavioural
  claims about the resolver (F1 cache behaviour, ECS, F4 glibc forward-confirmation) are reasoned from the
  API being called and are marked where uncertain.
- `.env` was not opened, per instruction. Findings about credential handling are derived from how the code
  *transports* whatever values it loads, not from the values.
- Provider-side behaviour — what VirusTotal retains about a lookup, whether IPinfo logs the token in the
  query string, how PeeringDB treats an unidentified UA — is asserted only where the code makes it
  determinable. Where it is not, it is flagged as needing the provider's own documentation.
- I did not assess correctness of the intelligence parsing, error handling beyond its leak surface, or the
  console layout except where provenance is concerned. Those belong to other lenses.
