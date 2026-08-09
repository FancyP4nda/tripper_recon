# Rate Limits and Quota

Two things live in this file, and they are not the same kind of claim.

**Section 2 is what each provider publishes.** Every figure carries the URL it came from and the
date it was retrieved. Nothing here was written from memory, and a provider whose limit could not
be retrieved is recorded as **not verified** with the date it was looked for. A wrong quota figure
in a runbook is worse than an absent one, because the absent one sends you to the source.

**Sections 3 to 6 are what this tool does**, verified against the code on branch
`feat/work-20260808-recon-hardening`, with a `file:line` anchor on every statement so you can
check it yourself.

The two halves do not currently meet. The tool has a global concurrency ceiling and no
per-provider budget, so nothing in the code enforces anything in section 2. Section 5 says
plainly where a normal run goes over a published limit.

---

## 1. How to read section 2

- **Every figure is quoted from the provider's own page** and dated. Free-tier limits move; a
  figure six months old is a lead, not a fact.
- **"Not verified" means exactly that.** It is not "no limit". It means the retrieval on the
  stated date did not find a published number, and you should not assume one either way.
- **Re-retrieve before you rely on a number.** When you do, change the date in the same edit. A
  number whose date was not moved was not re-checked.
- Only the endpoints this tool actually calls are considered. Where a provider publishes a limit
  per endpoint, the row names the endpoint from the provider module.

---

## 2. Published provider limits

All rows retrieved **2026-08-09**.

| Provider | Endpoint this tool calls | Published limit | Source |
|---|---|---|---|
| VirusTotal | `www.virustotal.com/api/v3/{ip_addresses,domains,urls}` (`providers/virustotal.py:56`) | "500 requests per day and a rate of 4 requests per minute" (Public API) | [docs.virustotal.com/reference/public-vs-premium-api](https://docs.virustotal.com/reference/public-vs-premium-api) |
| Shodan | `api.shodan.io/shodan/host/{ip}` (`providers/shodan_api.py:68`) | "All API plans are subject to a rate limit of 1 request per second" | [account.shodan.io/billing](https://account.shodan.io/billing) |
| AbuseIPDB | `api.abuseipdb.com/api/v2/check` (`providers/abuseipdb.py:71`) | Daily limit on `/check`: **1,000** on Standard (free), **3,000** on Webmaster | [docs.abuseipdb.com](https://docs.abuseipdb.com/) |
| IPinfo | `ipinfo.io/{ip}` and `ipinfo.io/AS{n}` (`providers/ipinfo.py:9`) | **Partly not verified** -- see the note below | [ipinfo.io/developers](https://ipinfo.io/developers) |
| AlienVault OTX | `otx.alienvault.com/api/v1/indicators/...` (`providers/otx.py:28`) | **Not verified in the API documentation** -- see the note below | [otx.alienvault.com/assets/static/external_api.html](https://otx.alienvault.com/assets/static/external_api.html) |
| Cloudflare Radar | `api.cloudflare.com/client/v4/radar/graphql` (`providers/cloudflare_radar.py:10`) and `.../client/v4/radar/bgp/*` (`providers/cloudflare_rest.py:35-38`) | Account-wide: "1,200 requests per five minute period per user". GraphQL: see the note below | [developers.cloudflare.com/fundamentals/api/reference/limits](https://developers.cloudflare.com/fundamentals/api/reference/limits/) |
| RIPEstat | `stat.ripe.net/data/...` (`providers/ripestat.py:9`) | "No limit on the amount of requests but please register if you plan to regularly do more than 1000 requests/day"; "The system limits the usage to 8 concurrent (at the same time) requests coming from one IP address." | [stat.ripe.net/docs/02.data-api](https://stat.ripe.net/docs/02.data-api/) |
| CAIDA AS-Rank | `api.asrank.caida.org/dev/restful/asns/{asn}` (`providers/caida.py:9`) | **Not verified** -- no rate limit published on the API documentation page as of this date | [asrank.caida.org/doc](https://asrank.caida.org/doc) |
| PeeringDB | `www.peeringdb.com/api/net` and `/api/net/{id}` (`providers/peeringdb.py:10`) | Anonymous: **20/minute per IP address**. Authenticated: **40/minute per user or organization**. Repeated anonymous identical requests above 100kb: **1/hour**; of any size: **2/minute** | [docs.peeringdb.com/howto/work_within_peeringdbs_query_limits](https://docs.peeringdb.com/howto/work_within_peeringdbs_query_limits/) |
| urlscan.io | Search and Result APIs (`providers/urlscan.py`) -- **not wired into any investigation path today**, see 4.5 | No fixed number published; per-account quotas | [urlscan.io/docs/api](https://urlscan.io/docs/api/) |

### Notes on the rows that are not a single number

**VirusTotal -- monthly quota not verified.** The Public-vs-Premium page states the daily and
per-minute figures above and no monthly figure. The separate quota page
([docs.virustotal.com/docs/quota-consumption](https://docs.virustotal.com/docs/quota-consumption))
says "Minute, daily and monthly limitations" exist but carries the numbers in an image that this
retrieval could not read. **Do not write a monthly VirusTotal figure into anything without
reading it off a VirusTotal page yourself.**

**Shodan -- where the figure lives.** The rate-limit sentence is on the plans page reached from
`developer.shodan.io/pricing`, which 302-redirects to `account.shodan.io/billing`; that redirect
target is the URL in the table. The 1 request/second ceiling is the one that binds this tool.
Query credits do not: "1 query credit is deducted per 100 pages of search results or per
page of domain information. IP lookups don't consume query credits."
([book.shodan.io/developer-apis/shodan-api](https://book.shodan.io/developer-apis/shodan-api/),
retrieved 2026-08-09). This tool only ever calls `/shodan/host/{ip}`
(`providers/shodan_api.py:68`), which is an IP lookup.

**AbuseIPDB -- what a 429 carries.** On exceeding the daily limit the API returns "HTTP 429 Too
Many Requests status" with `Retry-After` ("Seconds a client should wait until a retry"),
`X-RateLimit-Limit`, `X-RateLimit-Remaining` and `X-RateLimit-Reset` ("The epoch timestamp for the
daily limit reset"). The documented example carries `Retry-After: 29241` -- over eight hours.
Read 3.4 before assuming the tool handles that gracefully; it does not.

**IPinfo -- free-tier quota not verified.** The developer page states: "IPinfo Lite offers
unlimited access to our API. Paid plans include a monthly request limit with configurable alerts
to help you stay in control", and "If you exceed your plan's limit, you'll receive a `429` HTTP
status code." That covers Lite. **This tool does not call Lite.** It calls `ipinfo.io/{ip}` and
`ipinfo.io/AS{n}` (`providers/ipinfo.py:9`), the core API, and the free-plan monthly allowance for
those endpoints could not be verified on 2026-08-09: `support.ipinfo.io` returned HTTP 403 to the
retrieval and the pricing page's figure did not render reliably enough to quote. **No number is
recorded here on purpose.** Check your own account's usage page before a large run.

**OTX -- no figure in the API documentation.** The DirectConnect API documentation page carries no
rate-limit, request-limit or throttling statement (checked 2026-08-09). A vendor blog post from
LevelBlue, which owns OTX, states 1,000 requests per hour without an API key and 10,000 per hour
with one
([levelblue.com/blogs/levelblue-blog/the-upgraded-alienvault-otx-api-ways-to-score-swag](https://www.levelblue.com/blogs/levelblue-blog/the-upgraded-alienvault-otx-api-ways-to-score-swag),
retrieved 2026-08-09). That is a blog post, not API documentation, and it is not dated relative to
the current service. Treat it as an order of magnitude, not as a contract.

**Cloudflare -- three numbers, none Radar-specific.** The fundamentals page gives the account-wide
figure quoted in the table and, for GraphQL, "Varies by query cost. Max 320/5 min". The GraphQL
Analytics limits page states "The default quota is **300 GraphQL queries over 5-minute window**"
([developers.cloudflare.com/analytics/graphql-api/limits](https://developers.cloudflare.com/analytics/graphql-api/limits/),
retrieved 2026-08-09). The two Cloudflare pages disagree (320 versus 300) and **neither names the
Radar GraphQL endpoint this tool posts to**. All three figures are recorded because reconciling
them from outside Cloudflare would be a guess.

**PeeringDB -- the anonymous row is the one that applies.** This tool sends no PeeringDB
credential (`providers/peeringdb.py` constructs no auth header), so 20/minute per IP and the
duplicate-request limits bind, not the authenticated 40/minute.

**urlscan.io -- quotas are per account, not published as fixed numbers.** The documentation says
"Unauthenticated users only received minor quotas for API calls" and directs you to
`https://urlscan.io/user/quotas/` for "separate limits per minute, per hour and per day for each
action". Every response carries `X-Rate-Limit-Scope`, `X-Rate-Limit-Action`, `X-Rate-Limit-Window`,
`X-Rate-Limit-Limit`, `X-Rate-Limit-Remaining`, `X-Rate-Limit-Reset` and
`X-Rate-Limit-Reset-After`. Nothing in this tool reads those headers today.

---

## 3. What the tool does today

### 3.1 One global concurrency semaphore, and what it counts

There is a single process-wide semaphore. `DEFAULT_RATE_LIMIT = 10` (`utils/http.py:183`) is the
default ceiling; the semaphore is created inside the running event loop and kept per loop
(`utils/http.py:203-234`), and the rate is read at acquisition time rather than captured at import,
which is what makes `--rate-limit` reach every subcommand.

`_call_provider` is the only place in the package that awaits a provider
(`orchestrators.py:360-394`), and it takes one permit around that await
(`orchestrators.py:380-381`). Two consequences that matter for quota:

- **The permit counts provider calls, not HTTP requests.** Several providers issue more than one
  request inside a single permit: PeeringDB does one `/net` search plus one `/net/{id}` per record,
  five in flight (`providers/peeringdb.py:16,63`); Cloudflare BGP does a hijacks request plus a
  leaks request plus up to nine more hijack pages, `MAX_EVENT_PAGES = 10`
  (`providers/cloudflare_rest.py:43,148,231-232`). `--rate-limit 10` therefore does not mean ten
  HTTP requests in flight.
- **The permit is held across retry sleeps**, deliberately (`utils/http.py:244-246`): a retry
  spends provider quota, so it belongs inside the ceiling.

Two local gates bound fan-out below the global ceiling: `MAX_CONCURRENT_IPS = 8` addresses of one
domain enriched at once (`orchestrators.py:164`) and `MAX_CONCURRENT_NEIGHBOUR_LOOKUPS = 8`
neighbour-ASN name lookups (`orchestrators.py:168`). Both sit inside the global semaphore, so the
effective concurrency is the smaller of the two.

### 3.2 `--rate-limit`, and where it has to appear

`--rate-limit` is an `int`, default `10`, defined on the **top-level parser only**
(`cli.py:1418-1420`). The subparsers are built without `parents=` (`cli.py:1403,1437`), so the flag
must come **before** the subcommand:

```
tripper-recon --rate-limit 4 domain example.com     # takes effect
tripper-recon domain example.com --rate-limit 4     # argparse error
```

`main()` calls `configure_rate_limit(args.rate_limit)` once, before any `asyncio.run`
(`cli.py:1571`), and the value is clamped to a minimum of 1 (`utils/http.py:195`).

> **Trap:** `Settings.rate_limit` in `types/models.py:545` defaults to `5` and is wired to nothing
> -- `Settings` is never constructed anywhere in the package or the tests. The `10` above is the
> only default in force.

**What `--rate-limit` is not.** It is a concurrency ceiling, not a rate. It cannot express "4 per
minute", so setting `--rate-limit 4` does not keep you inside VirusTotal's 4/minute -- it only
means at most four provider calls are in flight at any instant, which on a fast link is four calls
every few hundred milliseconds.

### 3.3 What retries, and what does not

Every provider wraps its request in `with_exponential_backoff` (`utils/backoff.py:142`), so the
retry policy is a direct multiplier on quota consumption. No call site overrides the defaults:
`retries=3`, meaning **up to four attempts and at most three sleeps** per provider call, with
`base_delay=0.5` and `max_delay=5.0` (`utils/backoff.py:145-147`).

Retried (`utils/backoff.py:48,62-72`):

- `httpx.RequestError` -- connect failure, timeout, read error. The request may never have reached
  the provider.
- `httpx.HTTPStatusError` whose status is in `RETRYABLE_STATUS_CODES`:
  **408, 425, 429, 500, 502, 503, 504**.

Not retried: 401, 403, 404, every other 4xx, and any non-httpx exception such as a JSON decode
failure. These raise on the first attempt with no sleep, because retrying burns three more
rate-limit slots and still fails.

Delay when no `Retry-After` is present: `min(5.0, 0.5 * 2**attempt)` plus one-sided jitter of up to
25% (`utils/backoff.py:59,138-139`). So the unhinted schedule is roughly 0.5s, 1s, 2s.

`httpx.DecodingError` and `httpx.TooManyRedirects` are subclasses of `httpx.RequestError` and are
therefore retried, even though both are usually permanent (`utils/backoff.py:26-29`).

### 3.4 `Retry-After`, and the 60-second clamp

When a response carries `Retry-After`, it is honoured in both RFC 9110 forms -- delta-seconds and
HTTP-date -- and it **overrides** the exponential schedule for that attempt
(`utils/backoff.py:75-117,135-137`). It is not jittered: the server named a specific wait.

It is then clamped to `RETRY_AFTER_CEILING_SECONDS = 60.0` (`utils/backoff.py:54,137`). The clamp
exists so a hostile or broken header cannot park an investigation for a day.

**Read that against the AbuseIPDB row in section 2.** A daily-quota 429 from AbuseIPDB carries a
documented example `Retry-After` of 29,241 seconds. The tool clamps that to 60 seconds and retries
anyway -- three times, sleeping 60 seconds between attempts. That is **three extra requests against
an already-exhausted daily quota and about three minutes of wall clock**, on a call that cannot
succeed until the quota resets. Three minutes is also the whole per-target deadline
(`DEFAULT_TARGET_DEADLINE_SECONDS = 180.0`, `orchestrators.py:159`), so one exhausted-quota
provider can consume the budget the other providers needed. The clamp is the right default for a
transient throttle and the wrong one for an exhausted daily budget, and nothing in the code
currently tells them apart. Until per-provider budgets land (3.5), the mitigation is operational:
stop the run.

### 3.5 There is no per-provider budget

Roadmap item 3.4, not built. A semaphore bounds concurrency and cannot express "4 per minute" or
"1,000 per day". There is no counter per provider, no token bucket, no reading of the
`X-RateLimit-*` or `X-Rate-Limit-*` headers that AbuseIPDB and urlscan.io return, and no state that
survives the process. Every run starts with no memory of what the previous run spent.

### 3.6 There is no response cache

Roadmap item 7.7, not built. Nothing caches a provider response. Re-running the same investigation
one minute later spends the same quota again. The only cache in the package is the local
known-infrastructure YAML catalogue (`verdict/known_infrastructure.py:847`), which is a file on
disk and costs no provider quota.

---

## 4. What a run actually costs

Counted as **provider calls**, each of which is one permit and may be more than one HTTP request
(3.1), and each of which may retry up to four times (3.3). Every path is additionally bounded by a
180-second per-target wall-clock deadline (`DEFAULT_TARGET_DEADLINE_SECONDS`,
`orchestrators.py:159`).

### 4.1 `ip <address>`

Six provider calls (`orchestrators.py:185`): VirusTotal, IPinfo, Shodan, AbuseIPDB and OTX in one
wave (`orchestrators.py:846-861`), then Cloudflare Radar for the ASN **only if IPinfo returned
one** (`orchestrators.py:864-884`). Providers with no key configured cost nothing -- they return
`missing_api_key` without a request.

**VirusTotal cost: 1.**

### 4.2 `domain <name>`

One VirusTotal domain lookup and one OTX domain lookup (`orchestrators.py:188,1095-1097`), then the
full per-address wave from 4.1 for **every public address the name resolves to**
(`_enrich_domain_ip`, `orchestrators.py:1006`; fan-out at `orchestrators.py:1137-1143`).

**VirusTotal cost: N + 1**, where **N is the number of addresses actually investigated** -- the
value reported as `addresses.investigated` in the output (`orchestrators.py:1164-1169`). N is not
simply the A-record count: the address set is the union of the system resolver's answers and
VirusTotal's passive A **and AAAA** records (`_passive_ips_from_vt`, `orchestrators.py:992-1003`;
`_tag_ip_sources`, `orchestrators.py:969-990`), minus the non-public addresses the guard refuses
(`orchestrators.py:1130-1135`). A domain with eight A records, two AAAA records and no overlap
costs **eleven** VirusTotal calls, not nine.

The same multiplication applies to IPinfo, Shodan, AbuseIPDB and OTX, each of which is also called
once per address, and to Cloudflare Radar once per address whose IPinfo lookup returned an ASN.

At most eight addresses are enriched concurrently (`MAX_CONCURRENT_IPS`, `orchestrators.py:164`).

### 4.3 `url <link>`

`--depth` decides (`URL_DEPTHS`, `orchestrators.py:210`; default `full` at `orchestrators.py:213`):

| Depth | Provider calls | VirusTotal cost |
|---|---|---|
| `url` | 1 -- the VirusTotal URL report only (`orchestrators.py:1409-1412`) | 1 |
| `host` | The above plus the domain-level pair, no address resolution (`orchestrators.py:1420-1432`) | 2 |
| `full` | The above plus the 4.2 per-address fan-out | **N + 2** |

The table assumes a named host. When the URL's host is an IP literal there is no name to look up,
so `host` and `full` run the 4.1 address wave directly and nothing resolves
(`orchestrators.py:1422-1426`): total VirusTotal cost 2, not N + 2.

`--depth full` is the only depth that uses the system resolver, which is the one documented
passivity exception (`docs/OPSEC.md` section 3).

### 4.4 `asn <number>`

Ten provider calls in a single wave (`ASN_PROVIDERS`, `orchestrators.py:216-227`;
`orchestrators.py:1638-1655`), of which **five are RIPEstat** (overview, abuse contact, routing
status, neighbours, prefixes) and one is Cloudflare BGP, which is itself up to eleven HTTP requests
(3.1).

Then `--neighbors N` (default 8, `cli.py:1480`) resolves up to **3N** neighbour ASNs to names --
up to 24 additional RIPEstat `as-overview` calls at the default -- gathered at most eight at a time
(`orchestrators.py:1567-1587,1736-1748`).

There is no whois or registrar enrichment on this path and no flag that offers it. The `--enrich`
placeholder was removed (roadmap 9.11) rather than left advertising a capability the tool lacks.

**No VirusTotal, Shodan, AbuseIPDB or OTX call is made on this path.** `asn` runs on RIPEstat,
CAIDA and PeeringDB, none of which needs a key -- `tripper-recon asn 15169` works with an empty
`.env`.

### 4.5 What costs nothing

- `check --detect-only` -- classification only, zero provider calls (`cli.py:919-920`).
- `bulk` without `--investigate` -- triage only, zero provider calls (`cli.py:1265-1266`).
- Any provider whose key is unset: it returns `missing_api_key` / `missing_token` without issuing a
  request, and the run records it as `not_configured` rather than as a clean result.
- **urlscan.io.** `providers/urlscan.py` is written and tested and its host is allowlisted, but no
  orchestrator imports it -- `URL_PROVIDERS` is `("virustotal_url",)` (`orchestrators.py:201`) and a
  package-wide search finds no call site outside the module itself. It consumes no quota today. Its
  row in section 2 is there for when it is wired in.

### 4.6 `bulk --investigate`

`--max-targets` (default 10, `cli.py:1552-1556`) caps how many extracted indicators are looked up;
anything beyond the cap is reported as held back, not silently dropped (`cli.py:1268-1275`).

The lookups run **sequentially, one target at a time**, deliberately (`cli.py:1277-1290`). So the
peak concurrency of a bulk run is one target's fan-out, not the whole list -- but the **total**
quota is the sum of every target's cost from 4.1 to 4.4. Ten domains averaging four addresses each
is 50 VirusTotal calls, which is ten times the published per-minute allowance and a tenth of the
published daily one.

---

## 5. Where a normal run exceeds a published limit

Stated plainly, because nothing in the code prevents any of it.

| Published limit | What the tool can do | Where |
|---|---|---|
| VirusTotal: 4 requests/minute | A domain with 8 public addresses issues 9 VirusTotal calls, 8 of them across at most 8 concurrent address waves -- seconds, not minutes | 4.2 |
| VirusTotal: 500 requests/day | No counter exists across runs. A morning of `bulk --investigate` on multi-address domains reaches it without warning | 3.5 |
| Shodan: 1 request/second | Up to 8 concurrent Shodan calls on a multi-address domain, bounded only by `MAX_CONCURRENT_IPS` and the global semaphore | 4.2 |
| AbuseIPDB: 1,000/day (free) | Reachable the same way; and on the 429, the clamp turns a documented 8-hour `Retry-After` into three more doomed requests | 3.4 |
| RIPEstat: 8 concurrent per IP | The neighbour-resolution gate is exactly 8, so `asn` sits **at** the ceiling rather than under it. `--rate-limit` below 8 lowers it; above 8 does not raise it | 4.4 |
| PeeringDB: 2/minute for repeated identical anonymous requests | No cache, so re-running `asn 15169` twice inside a minute sends a byte-identical `/net?asn__in=15169` twice | 3.6 |
| Cloudflare: the GraphQL figure (300 or 320 per 5 min, section 2) | The nearer of the two Cloudflare ceilings. Every address on the `ip`, `domain` and `url` paths costs one Radar GraphQL post when IPinfo returned an ASN, so a `bulk --investigate` over ten multi-address domains is in the high tens of GraphQL posts per run. The account-wide 1,200/5 min is further away | 4.1, 4.2 |

The honest summary: **the passivity boundary is enforced in code, the quota boundary is not.** One
is a hard runtime check that raises before a socket opens; the other is currently the operator's
job.

---

## 6. Practical guidance for bulk runs

1. **Triage before you spend.** Run `bulk` with no `--investigate` first. It costs nothing and
   tells you how many routable indicators you actually have. Decide the budget from that number,
   not from the size of the paste.
2. **Do the arithmetic before the run, using section 4.** Domains are the expensive shape: cost is
   per address, not per name. Ten domains is not ten VirusTotal calls.
3. **Keep `--max-targets` small and raise it deliberately.** The default of 10 is a guardrail
   against a pasted mail thread fanning out, not a recommendation.
4. **Lower `--rate-limit` to reduce the burst, but do not mistake it for a budget.**
   `tripper-recon --rate-limit 4 bulk --investigate ...` reduces how many calls land at the same
   instant. It does not stop you from exceeding 4 requests per minute, and it does not stop you
   from exhausting a daily quota. Remember it must precede the subcommand (3.2).
5. **Prefer several small runs with a pause to one large run.** With no cross-run counter and no
   cache, a pause is the only rate control the tool actually gives you. Pausing is also the only
   way to stay near VirusTotal's per-minute figure.
6. **Stop the run on the first quota 429; do not let it grind.** Every retried 429 is another
   request against a limit you have already hit, and the 60-second clamp means the tool will keep
   trying long after the provider told it not to (3.4). Watch for the provider's error line in the
   report -- errors are surfaced per provider and per address, never swallowed
   (`orchestrators.py:397-414`).
7. **Read the coverage line, not the absence of findings.** A provider that was rate-limited out of
   a run is reported as not answering, and absent data never scores as clean. A verdict built on
   two of six providers is a verdict about your quota, not about the indicator.
8. **`asn` is free of the keyed providers.** When the question is about an ASN, that path costs no
   VirusTotal, Shodan, AbuseIPDB or OTX quota at all (4.4).

---

## 7. Keeping this file honest

- Re-retrieve every figure before a release, and move the date in the same edit. A date that did
  not move was not checked.
- Never edit a number without opening the source page. If the page is unreachable, write **not
  verified** with today's date and delete the old number -- a stale number that reads as current is
  the failure this file exists to prevent.
- When roadmap item 3.4 (per-provider budgets) or 7.7 (cache) lands, sections 3.5, 3.6 and 5 stop
  being true. Update them in the same commit as the code.
- When a provider is added to `ALLOWED_EGRESS_HOSTS` (`utils/http.py:63`), add its row to section 2
  in the same commit, with a retrieval date -- or with **not verified** and the date you looked.
