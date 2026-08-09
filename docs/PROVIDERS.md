# Providers

Ten providers are wired into investigations, in `tripper_recon/providers/`. An eleventh module —
urlscan.io — is implemented and tested but not yet consulted by any command; it has its own
section below and is marked accordingly.

**This file is the answer to "why is my output empty".** Each row lists the environment variable,
which commands use the provider, and exactly which fields the provider module keeps.

The provider sets below are transcriptions of the declared tuples in `orchestrators.py`
(`IP_PROVIDERS:185`, `DOMAIN_PROVIDERS:188`, `URL_PROVIDERS:201`, `ASN_PROVIDERS:216`). Those
tuples are the denominator of the `provider_coverage` ratio — "N of M providers answered" — so
what is written here and what the ratio counts are the same list by construction.

---

## At a glance

| Provider | Env var | Key needed | `ip` | `domain` | `url` | `asn` |
|---|---|---|:--:|:--:|:--:|:--:|
| RIPEstat | — | **no** | | | | yes |
| CAIDA AS-Rank | — | **no** | | | | yes |
| PeeringDB | — | **no** | | | | yes |
| VirusTotal | `VT_API_KEY` | yes | yes | yes | yes | |
| Shodan | `SHODAN_API_KEY` | yes | yes | yes | yes | |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | yes | yes | yes | yes | |
| IPInfo | `IPINFO_TOKEN` | yes | yes | yes | yes | yes |
| AlienVault OTX | `OTX_API_KEY` | yes | yes | yes | yes | |
| Cloudflare Radar | `CLOUDFLARE_API_TOKEN` | yes | yes | yes | yes | yes |
| Cloudflare BGP | `CLOUDFLARE_API_TOKEN` | yes | | | | yes |
| urlscan.io | — *(not wired)* | n/a | | | | |

`check` and `bulk` consult nothing of their own: `check` classifies the string and routes it to
`ip`, `domain`, `url` or `asn`, and `bulk --investigate` routes each surviving indicator through
`check`. `check --detect-only` and `bulk` without `--investigate` consult nobody at all.

The `url` column is indirect for everything except VirusTotal. The URL scope itself has exactly
one provider — VirusTotal's URL report. `--depth host` adds the domain-level providers about the
host, and `--depth full` (the default) adds the full per-address set for each address the host
resolves to.

**`tripper-recon asn 15169` works with a completely empty `.env`.** RIPEstat, CAIDA, and PeeringDB
carry that command on their own.

> **A provider with no key is never asked, and never renders as a zero.** Absence and a clean
> result are kept visibly different: a provider that was not asked renders as "no data", never as
> a green `0/0` (`reporting/console.py:342`, `no_data_text`). The `provider_coverage` line on
> every console block, and `coverage.headline` in `-o json`, say how many of the expected
> providers answered. A missing credential is classified as `not_configured` rather than as a
> failure (`orchestrators.py:173`, `:296`), so a sparse run is legible as a configuration state
> instead of looking like an incident.

---

## No key required

### RIPEstat — `providers/ripestat.py`

`https://stat.ripe.net/data`. Five endpoints, all on the `asn` command. Self-identifies with
`sourceapp=tripper-recon` on every call (`ripestat.py:25`), which is the correct behaviour and the
model the other providers should follow.

| Call | Gives you |
|---|---|
| `as-overview` | AS holder name, announced status |
| `abuse-contact-finder` | **Abuse contact address** — the incident-report fact |
| `routing-status` | Announced v4/v6 prefix counts, observed neighbour count |
| `asn-neighbours` | Upstream / downstream / uncertain ASNs |
| `announced-prefixes` | Full v4 and v6 prefix list |

Returns the raw `data` object (`ripestat.py:19`), so nothing is discarded. `--prefixes-out` on the
`asn` command writes the full announced-prefix list to a file; the console panel never prints it
in full.

### CAIDA AS-Rank — `providers/caida.py`

`https://api.asrank.caida.org/dev/restful/asns/{asn}` — the REST endpoint, not the GraphQL one.
Keeps: `caidaRank`, `degree_total`, `degree_customer`, `degree_peer`, `degree_provider`,
`customer_cone_asns`, `rir` (read from the response's `source` field).

`customer_cone_asns` is the field that tells you whether "same ASN" is a meaningful pivot or a
netblock the size of a country.

### PeeringDB — `providers/peeringdb.py`

`https://www.peeringdb.com/api`. Keeps IXP names only.

Two request shapes are involved: one `/net` search, then one `/net/{id}` fetch per record. Each
request is retried **independently**, and the per-net fetches run concurrently bounded by
`MAX_CONCURRENT_NET_LOOKUPS = 5` (`peeringdb.py:16`). The earlier defect — the whole 1+N sequence
inside a single retried closure, so one failure on the last sub-request replayed every earlier one
against a keyless rate-limited provider — is fixed.

---

## Key required

### VirusTotal v3 — `providers/virustotal.py`

`https://www.virustotal.com/api/v3`. `GET` only — reports that already exist. It never submits an
indicator for analysis, and there is no flag that would make it. Key travels in the `x-apikey`
**header**.

**IP** (`vt_ip_summary`): `vt_last_analysis_stats`, `vt_reputation`, `vt_security_results`,
`vt_detecting_engines`, `vt_last_analysis_date`, `vt_last_analysis_date_iso`, `vt_link`.

**Domain** (`vt_domain_summary`): the above plus `vt_categories`, `vt_tags`, `vt_dns_records`
(the passive A/AAAA records), `vt_whois`, `vt_whois_timestamp`, `vt_last_https_certificate`,
`vt_last_https_certificate_jarm`.

**No longer discarded.** `last_analysis_results` (the per-engine breakdown — *which* five of
ninety-odd flagged it) and `last_analysis_date` (how stale the verdict is) are both retained on
the IP path now, under the names the domain path already used: the full map is
`vt_security_results`, and `vt_detecting_engines` is the derived list of the adverse engines only,
because the full map runs to roughly ninety-four entries per indicator and belongs in the JSON
rather than on a console line. `vt_last_analysis_date_iso` is the same timestamp rendered from the
Unix epoch value; a missing timestamp stays `None` rather than becoming `0`, which would render as
a 1970 scan and read as maximally stale.

**URL** (`vt_url_summary`) — the one provider on the URL scope:

`vt_url_id`, `vt_url_canonical_id`, `vt_last_analysis_stats`, `vt_reputation`,
`vt_security_results`, `vt_detecting_engines`, `vt_last_analysis_date` (+ `_iso`),
`vt_total_votes`, `vt_first_submission_date` (+ `_iso`), `vt_last_submission_date` (+ `_iso`),
`vt_times_submitted`, `vt_categories`, `vt_tags`, `vt_title`, `vt_targeted_brand`,
`vt_last_http_response_code`, `vt_threat_names`, `vt_last_final_url`, `vt_redirection_chain`,
`vt_redirect_observation`, `vt_link`.

Two things about this call decide how its output should be read:

- **A 404 is a terminal answer, not a prompt to escalate.** It means nobody has ever submitted this
  URL. For a freshly registered phishing link that is the ordinary state of the world and carries
  no exculpatory weight: the payload says `no_existing_report`, and the correct reading is
  UNKNOWN, not clean.
- **`last_final_url` and `redirection_chain` are the only redirect evidence this tool will ever
  carry**, because they are somebody else's completed observation. They are labelled with when
  VirusTotal saw them (`vt_redirect_observation`) so a stale chain cannot be misread as a
  resolution performed now. Nothing in this tool resolves a redirect itself.

`threat_names` is **not** a documented attribute of the URL object, unlike the file object. It is
read defensively and will normally be `None`.

### Shodan — `providers/shodan_api.py`

`https://api.shodan.io/shodan/host/{ip}`. Keeps `ports`, `org`, `tags`, `cpe`, `vulns`,
`hostnames`, `last_update`. A `404` is correctly reported as `not_found` rather than an error.

**No longer discarded.** All three of `vulns`, `hostnames` and `last_update` are retained:

- `vulns` — the CVEs Shodan associates with the banners it collected, gathered from both places
  Shodan puts them (the top-level field and the per-service entries under `data[]`, which have
  been seen as both a list and a dict keyed by CVE id). The union is sorted so two runs diff
  cleanly.
- `hostnames` — Shodan's own reverse names for the address. This is passive PTR the tool otherwise
  has no source for: `utils/dns.py:98` `reverse_ptr` exists but has no callers, and the per-IP
  `ptr` field is still emitted as `null` (`orchestrators.py:892`).
- `last_update` — when Shodan last saw the host, passed through as Shodan's own timestamp string.
  An open-port list with no date attached invites an analyst to read a two-year-old observation as
  current state.

**Key travels in the query string** (`shodan_api.py:68`) — see the credential-handling section.

### AbuseIPDB — `providers/abuseipdb.py`

`https://api.abuseipdb.com/api/v2/check`, 365-day window. Keeps `abuseipdb_reports` and
`abuseipdb_confidence_score`, plus six fields that qualify them.

**No longer discarded:** `lastReportedAt`, `isWhitelisted`, `usageType`, `isTor`, `countryCode`
and `numDistinctUsers`, exposed as `abuseipdb_last_reported_at`, `abuseipdb_is_whitelisted`,
`abuseipdb_usage_type`, `abuseipdb_is_tor`, `abuseipdb_country_code` and
`abuseipdb_num_distinct_users`.

Why each one changes the reading: a 100% confidence score from 2019 and a 100% score from
yesterday are the same number and different findings; "Data Center/Web Hosting" versus "Fixed Line
ISP" changes what a report means; a Tor exit node attracts reports as a property of being an exit
node; and 200 reports from 1 reporter is not 200 independent observations.

Every new field is `None` when the provider did not report it. The two booleans in particular
never default to `False` — "AbuseIPDB says this is not whitelisted" and "AbuseIPDB did not say"
are different claims. The two pre-existing count fields keep their pre-existing `0` defaults.

### IPInfo — `providers/ipinfo.py`

`https://ipinfo.io`. Keeps `ip`, `city`, `country`, `region`, `postal`, `asn`, `org`,
`coordinates`, `timezone`, `hostname`. Also serves the `asn` command via `/AS{asn}` (keeping
`name`, `country`, `rir`, `allocationDate`, `organization`), which needs a paid plan — a `401`/`403`
there is suppressed by design (`orchestrators.py:296`) so an unpaid account does not render as a
provider incident on every ASN lookup.

**Token travels in the query string** (`ipinfo.py:17`, `:61`) — see below.

### AlienVault OTX — `providers/otx.py`

`https://otx.alienvault.com/api/v1`. Keeps `otx_pulse_count`, the **first five** pulse titles in
`otx_pulse_titles`, and `otx_pulses`. Domain lookups add `otx_tags`, `otx_malware_count`,
`otx_passive_dns_count`.

**No longer discarded.** A raw pulse count is a weak signal that reads as a strong one: fifty
pulses cloned from one author on one day is one observation wearing a large number.
`otx_pulses` now carries one compact record per pulse — `name`, `author`, `created`, `modified` —
so the count can be quality-adjusted by author diversity and recency. It is deliberately **not**
truncated at five: a diversity measure computed over the first five pulses is not a diversity
measure. The five-entry `otx_pulse_titles` cap and `otx_pulse_count` are unchanged.

Author extraction is defensive about shape — OTX has emitted the author as a flat `author_name`
string and as a nested `author` object across versions of this endpoint — and a pulse with neither
reports `None` rather than guessing, because an unattributed pulse must not silently count as its
own author.

### Cloudflare Radar — `providers/cloudflare_radar.py`

`https://api.cloudflare.com/client/v4/radar/graphql`. ASN metadata: `name`, `countryCode`,
`caidaRank`, `organization`, `abuseContacts`, `rir`, `allocationDate`, `ixps`. Tries an integer
ASN query, then falls back to the `AS{n}` string form.

On the `ip`, `domain` and `url` paths this runs as a **second wave**, and only when IPinfo
answered with an ASN — the ASN is not known until IPinfo replies. It stays in the coverage
denominator either way (`orchestrators.py:185`), so a failed IPinfo lookup does not quietly
shrink the denominator and report better coverage for the worse run.

### Cloudflare BGP — `providers/cloudflare_rest.py`

BGP hijack and route-leak incident counts for an ASN.

The victim/hijacker arithmetic is fixed. The split is now reported **only over a complete
enumeration** of the events: `as_hijacker` is counted from `hijacker_asn`, `as_victim` is counted
from the event's own victim-ASN keys, and neither is derived by subtracting one from the total.
When the enumeration is incomplete (the page walk is bounded at `MAX_EVENT_PAGES = 10`) or the
events do not name victims, both counts are absent and `split_unavailable_reason` says which.
Consumers must render that as unavailable rather than printing `None` as a zero.

---

## Implemented but not wired in

### urlscan.io — `providers/urlscan.py`

Written, tested (`tests/test_providers_urlscan.py`), and its host is allowlisted in both the
runtime egress allowlist (`utils/http.py:63`) and the static passivity gate
(`tests/test_passivity.py:66`). **It is not consulted by any command.** `URL_PROVIDERS`
(`orchestrators.py:201`) holds one entry, `virustotal_url`. There is no environment variable for
it, because nothing supplies it a key yet.

Wiring it in changes the URL-scope coverage denominator, which is why it was not done in the same
change that moved the passive boundary: a passivity change and a coverage change in one diff are
indistinguishable afterwards.

What the module does today, for whoever wires it up:

`https://urlscan.io/api/v1` (`urlscan.py:73`). Two endpoints, both `GET`, both reads of scans a
**different party** already completed:

- **Search** — `GET /search/?q=<ElasticSearch query string>`. Wrappers for one URL
  (`urlscan_search_url`, matching both `page.url` and `task.url`) and one domain
  (`urlscan_search_domain`, matching `page.domain` only — the broader `domain` field matches every
  scan that merely loaded a resource from the domain, which behind a CDN returns the CDN's traffic
  rather than the target's).
- **Result** — `GET /result/{uuid}/`, the JSON for one finished scan.
- **Composed** — `urlscan_url_summary` searches, then reads the newest hit. Two `GET`s, no
  submission. When no public scan exists the answer is `no_public_scan`, which is a finding rather
  than an invitation to create one.

The **submission** route on this same API (`POST /api/v1/scan/`) is forbidden permanently and
without a flag: it makes urlscan load the target in a real browser from urlscan infrastructure and,
unless marked otherwise, publishes the scan. `tests/test_passivity.py` scans the package for it on
every run.

Retained per scan: the scan date first and always — `urlscan_scan_date`, `urlscan_scan_age_days`,
`urlscan_scan_is_stale`, `urlscan_scan_staleness_threshold_days` — then `urlscan_scan_uuid`,
`urlscan_visibility`, `urlscan_submitted_url`, `urlscan_final_url`, `urlscan_redirected`,
`urlscan_redirect_chain` (+ `_hops`, `_resolved_locally`, `_observed_by`, `_observed_at`),
`urlscan_contacted_domains` / `_ips` / `_countries` / `_url_count`, `urlscan_page_domain` / `_ip` /
`_country` / `_status`, `urlscan_verdict`, `urlscan_screenshot_url`, `urlscan_screenshot_fetched`,
`urlscan_report_url`, `urlscan_result_api_url`. Search adds `urlscan_total_matches`,
`urlscan_public_scan_count` and `urlscan_non_public_scans_excluded`.

Three details worth carrying into whatever consumes it:

- **Staleness is a judgement, not a provider fact.** `STALE_AFTER_DAYS = 90` is this module's
  opinion and is exposed in the payload so a consumer can disagree with it explicitly.
- **Public-only is enforced twice** — in the query and again on the parsed response — because an
  API key that can see unlisted scans changes what the server returns.
- **The screenshot is a link, never a retrieval.** `urlscan_screenshot_fetched` is `False` and
  allowlisting the host does not authorise fetching it.

**A key is required as the code stands.** `urlscan_search` returns `missing_api_key` without one
(`urlscan.py:535`), authenticating with the `API-Key` header. urlscan's own guidance is to use the
key for all API requests, so unauthenticated search would be a deliberate departure, not a default.

### Planned

- **abuse.ch (URLhaus + ThreatFox)**, roadmap 8.7 — one Auth-Key, actor-attributed and
  payload-backed observations. **Not built.** Decision Q5 in `docs/ROADMAP.md`: build it in full
  including bulk mode, with the terms-of-service exposure accepted and recorded in
  `docs/OPSEC.md` rather than mitigated.
- **GreyNoise** (roadmap 8.8) is **struck** (decision Q10 — no eligible non-consumer email
  address, so it can never be started) and will not be built.

---

## Credential handling

**Header:** VirusTotal (`x-apikey`), AbuseIPDB (`Key`), OTX (`X-OTX-API-KEY`), Cloudflare
(`Authorization: Bearer`), urlscan (`API-Key`, unwired).
**Query string:** Shodan (`?key=`, `shodan_api.py:68`), IPInfo (`?token=`, `ipinfo.py:17`, `:61`).

For the two query-string providers the API key is part of the request URL, so a failing request
carries it in both `str(request.url)` and the exception text.

**That leak is fixed.** `_error_payload` (`orchestrators.py:251`) redacts every string it emits:
the `url` field goes through `redact_url` and the `message` field through `redact_text`
(`utils/redact.py`), which substitute credential-bearing query parameter values and any credential
value present in the environment. The error path never raises — a failure to parse a URL returns
it unchanged rather than throwing a second exception over the first.

Two limits worth knowing rather than assuming:

- Redaction of *values* works from the environment. A key that is set is redacted wherever it
  appears; a key shorter than eight characters is deliberately not treated as a secret, because a
  blank or placeholder value would cause runaway substitution across unrelated output.
- Cloudflare Radar redacts its own error bodies at the provider (`cloudflare_radar.py`), because a
  GraphQL error body is not an httpx exception and would not otherwise pass through
  `_error_payload`.

Structured logs go to **stderr**, never stdout, so they cannot interleave with `-o json` and break
a downstream parser.

---

## Rate limits and quota

Per-provider published limits are **not documented here on purpose** — they live in
`docs/RATE-LIMITS.md`, with the source URL and retrieval date on every figure. Published limits
change, and a number written from memory into a runbook is worse than no number.

What the code does today:

- **One process-global concurrency ceiling, default 10, and `--rate-limit` reaches it.** The
  limiter is created inside the running event loop and kept per loop, and the rate is read at
  acquisition time rather than captured at import (`utils/http.py:188`, `:238`). It wraps the
  *await* of a provider call, not `asyncio.create_task` — a limiter around task creation acquires
  and releases in the same tick and constrains nothing. The permit is held across a provider's
  retry sleeps as well as its request, because a retry spends the provider's quota too.
- **No per-provider budget exists.** A semaphore bounds concurrency and cannot express "4 per
  minute". Roadmap item 3.4, and it is blocked on retrieving each provider's published limits
  rather than recalling them.
- **`429` and `Retry-After` are handled.** `408`, `425`, `429`, `500`, `502`, `503` and `504` are
  retried; everything else — `401`, `403`, `404`, any other 4xx, and non-httpx failures such as a
  JSON decode error — is permanent for this key and this indicator and is raised on the first
  attempt with no sleep. `Retry-After` is honoured in both the delta-seconds and HTTP-date forms
  and overrides the exponential schedule, clamped to 60 seconds so a hostile or broken header
  cannot park an investigation for an hour (`utils/backoff.py`).
- **Per-indicator wall-clock deadline: 180 seconds** (`orchestrators.py:159`). A run that breaches
  it terminates and says so rather than hanging.
- **A domain with eight addresses costs eight times the per-address provider set**, plus the two
  domain-level calls — so nine VirusTotal calls for eight A records. Concurrency is bounded by
  `MAX_CONCURRENT_IPS = 8` for addresses and `MAX_CONCURRENT_NEIGHBOUR_LOOKUPS = 8` for ASN
  neighbour name resolution, so a domain with forty A records does not create two hundred pending
  provider calls before the first one returns.

---

## Adding a provider

1. New module in `providers/`, one async function per endpoint.
2. Return the envelope: `{"ok": True, "data": {...}}` or `{"ok": False, "error": "...", ...}`.
3. Return `{"ok": False, "error": "missing_api_key"}` when the key is unset — never raise. Use one
   of the strings in `NOT_CONFIGURED_ERRORS` (`orchestrators.py:173`) so "not asked" stays
   distinguishable from "asked and failed".
4. Wrap the call in `with_exponential_backoff`.
5. Coerce every field defensively. A missing field must read as absent, never as a benign value —
   rendering "we did not learn this" identically to "we learned it and it was fine" is the defect
   this whole package is written against.
6. **Passive only.** The endpoint must return data the provider already holds. If it makes the
   provider contact the target, it does not belong here — check the forbidden list in
   `docs/OPSEC.md` section 7.
7. Add the host to `ALLOWED_EGRESS_HOSTS` (`utils/http.py:63`) **and** to `ALLOWED_HOSTS` in
   `tests/test_passivity.py`, and record it in `docs/OPSEC.md` section 2, in the same commit. The
   runtime hook rejects an unlisted host before a socket opens; the static scan fails the build.
8. Add it to the relevant provider tuple in `orchestrators.py` — that tuple is the coverage
   denominator, and a provider consulted but not declared is invisible to the ratio.
9. Update this file and the README provider list in the same commit.
