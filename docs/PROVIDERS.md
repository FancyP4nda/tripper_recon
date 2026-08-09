# Providers

Fourteen provider modules are wired into investigations, in `tripper_recon/providers/`. One more —
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
| Shodan InternetDB | — | **no** | yes | yes | yes | |
| RDAP | — | **no** | yes | yes | | yes |
| Tranco | — | **no** | | yes | | |
| VirusTotal | `VT_API_KEY` | yes | yes | yes | yes | |
| Shodan | `SHODAN_API_KEY` | yes | yes | yes | yes | |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | yes | yes | yes | yes | |
| IPInfo | `IPINFO_TOKEN` | yes | yes | yes | yes | yes |
| AlienVault OTX | `OTX_API_KEY` | yes | yes | yes | yes | |
| Cloudflare Radar | `CLOUDFLARE_API_TOKEN` | yes | yes | yes | yes | yes |
| Cloudflare BGP | `CLOUDFLARE_API_TOKEN` | yes | | | | yes |
| abuse.ch (URLhaus + ThreatFox) | `ABUSECH_AUTH_KEY` | yes | yes | yes | yes | |
| urlscan.io | — *(not wired)* | n/a | | | | |

**Shodan and Shodan InternetDB share ONE coverage slot, named `shodan`.** The paid host lookup runs
when `SHODAN_API_KEY` is set and the keyless InternetDB extract runs when it is not, so exactly one
of them can answer for an address. Listing both in `IP_PROVIDERS` would permanently understate
coverage by one for every operator; the payload's `source` field says which dataset replied.

`check` and `bulk` consult nothing of their own: `check` classifies the string and routes it to
`ip`, `domain`, `url` or `asn`, and `bulk --investigate` routes each surviving indicator through
`check`. `check --detect-only` and `bulk` without `--investigate` consult nobody at all.

The `url` column is indirect for everything except VirusTotal and abuse.ch. The URL scope itself
has exactly two providers — VirusTotal's URL report and the abuse.ch summary. `--depth host` adds
the domain-level providers about the host, and `--depth full` (the default) adds the full
per-address set for each address the host resolves to.

**`tripper-recon asn 15169` works with a completely empty `.env`.** RIPEstat, CAIDA, and PeeringDB
carry that command on their own; RDAP is asked too and currently reports unknown (see its section).

**A keyless run is no longer a silent run.** Until 2026-08-09 an `ip` lookup with no credentials
made zero HTTP requests, because every provider short-circuited on its missing key. InternetDB,
RDAP and Tranco take no credential, so a keyless run now contacts `internetdb.shodan.io` and
`data.iana.org`. Keyless means unattributable to an account, not invisible: the egress IP is still
the identifier those providers log and rate-limit on (`docs/OPSEC.md` section 4).

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

### Shodan InternetDB — `providers/internetdb.py`

`https://internetdb.shodan.io/{ip}` (`internetdb.py:79`). The keyless fallback for the `shodan`
slot: same underlying dataset, no credential, `GET` only. Keeps `ports`, `hostnames`, `cpe`,
`tags`, `vulns`, `ip` (echoed from the *response*, so a record describing a different address than
the one asked for is visible rather than hidden) and `source`, which is the literal
`shodan_internetdb` so a consumer can tell which dataset answered.

**It adds CVEs the paid provider never surfaced here** and restores exposure data on a run with no
`SHODAN_API_KEY`, which previously returned `missing_api_key` and was silently suppressed.

Two things it is not:

- **Not a replacement for the paid lookup.** The dataset is coarser and, per Shodan's own book,
  updated weekly rather than continuously. When `SHODAN_API_KEY` is set the paid lookup runs.
- **Not a clean answer on 404.** `not_found` means InternetDB holds no record, which is absence of
  a record and not absence of exposure. `429` is `rate_limited` and is deliberately not retried:
  the identifier being throttled is the egress IP, and retrying into a throttle is how it becomes
  a ban.

### RDAP — `providers/rdap.py`

Registration data straight from the registry that holds it, for domains (`rdap_domain`), IP
networks (`rdap_ip`) and AS numbers (`rdap_asn`). No key, no quota, no submission. It answers two
questions nothing else in this tool can: **when was this registered**, which is the strongest cheap
phishing signal available, and **who do I send the abuse report to**.

**The bootstrap is done client-side, and that is the whole design.** RDAP has no single endpoint
(STD 95, RFC 9224). This module fetches IANA's static bootstrap files
(`IANA_BOOTSTRAP_BASE`, `rdap.py:137`), caches them for an hour per process, resolves the
authoritative base URL locally, and issues exactly one `GET` to it. It does **not** use the
`rdap.org` aggregator, which would mean following a `302` to a host chosen at runtime, and it sets
`follow_redirects=False` on both requests. See `docs/OPSEC.md` section 2 for why that matters more
here than anywhere else in the package.

> **As shipped, every RDAP lookup answers `registry_not_allowlisted`.** The bootstrap host is on
> the egress allowlist; the registries it names are not. That is unknown, never clean, and it
> shows as missing coverage. Adding registry hosts is a deliberate review — `docs/OPSEC.md`
> section 6, gap 9.

Domain payload, dates first because the date is the reason this provider exists:
`rdap_registration_date`, `rdap_age_days`, `rdap_is_newly_registered`,
`rdap_newly_registered_threshold_days` (30, published so a consumer can disagree with the
judgement explicitly), `rdap_expiration_date`, `rdap_last_changed_date`, `rdap_events`, then
`rdap_registrar_name` / `_iana_id` / `_handle`, `rdap_registrant_name` / `_organization`,
`rdap_abuse_email` / `_phone` / `_handle` / `_contact_source`, `rdap_status` (+ `_raw`),
`rdap_adverse_status`, `rdap_has_adverse_status`, `rdap_is_inactive`, `rdap_nameservers` (+
`_names`, `_count`, `_glue_addresses`), `rdap_dnssec_*`, and the routing provenance
`rdap_server` / `_server_host` / `_bootstrap_entry` / `_bootstrap_publication`.

Four readings worth carrying:

- **A `404` is unknown, not clean.** A registry returns it for a name never registered, for one
  that just dropped, and for names it holds but will not answer for.
- **The caller passes the name to look up, and RDAP holds the *registrable* name.** So
  `login.secure.example.com` returns `404` while `example.com` returns the record. Deriving the
  boundary would be right for `com` and wrong for `co.uk`, so the module reports the miss instead
  of silently rewriting the indicator. Every envelope, success or failure, carries the resource
  actually queried.
- **`rdap_abuse_contact_source` distinguishes a designated abuse address from a registrar
  fallback.** They are different queues with different obligations.
- **A missing `delegationSigned` stays `None`.** An unsigned delegation and an unreported one are
  different claims, and only one of them is the registry's.

### Tranco — `providers/tranco.py`

`https://tranco-list.eu/api/ranks/domain/{domain}` (`tranco.py:96`). Keyless. A **false-positive
suppressor**, and the payload says so in a field: `tranco_suppression_only` is hard-coded `True`,
and a consumer that finds itself raising a score from anything in this payload has a defect.

Keeps `tranco_rank`, `tranco_rank_date`, `tranco_in_list`, `tranco_best_rank`,
`tranco_days_ranked`, `tranco_history`, `tranco_suppression_only`, and — when the domain is
unranked — `tranco_absence_note`, which carries the "this is not adverse" sentence *with the data*
rather than leaving it in a docstring nobody downstream reads. The Tranco list holds roughly a
million domains against a public web of hundreds of millions, so **absence is the ordinary state
of a legitimate small site** and scoring it would flag the honest long tail.

`tranco_in_list: False` and a `404` are deliberately not collapsed: the first is Tranco telling you
the domain is unranked, the second is Tranco telling you nothing.

**It paces itself.** The published limit is one query per second and a global concurrency semaphore
cannot express that, so this module holds its own inter-request spacing
(`MIN_REQUEST_INTERVAL_SECONDS`, `tranco.py:104`) measured between request *starts*, because the
server measures arrival rather than departure.

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

### abuse.ch — URLhaus and ThreatFox — `providers/abusech.py`

Two platforms, **one Auth-Key** (`ABUSECH_AUTH_KEY`, free from the abuse.ch authentication portal),
travelling in an `Auth-Key` request **header**. Both APIs now require it; an unauthenticated
request is rejected.

> **Read `docs/OPSEC.md` section 4a before enabling this.** abuse.ch's terms prohibit automated
> access by "robot, bot, spider, scraper" while their API documentation issues keys and publishes
> `curl` examples. The operator accepted that exposure on 2026-08-09, bulk mode included, and it
> is recorded rather than mitigated.

**Both calls are `POST`, and both are queries.** URLhaus takes the indicator as a form field,
ThreatFox as a JSON body with a `query` selector; neither makes abuse.ch retrieve the target and
neither publishes anything. The selector this module sends is pinned to one constant,
`THREATFOX_SEARCH_QUERY = "search_ioc"` (`abusech.py:121`), because the ThreatFox endpoint is
shared between read and write operations and the *selector*, not the URL, is what makes the call
passive. `docs/OPSEC.md` section 7 has the register and the tests that hold it there.

Three endpoints, composed into two public functions:

| Function | Calls | Used by |
|---|---|---|
| `abusech_url_summary` | URLhaus `POST /v1/url/` + ThreatFox exact-match search on the same URL | `url` scope |
| `abusech_host_summary` | URLhaus `POST /v1/host/` + ThreatFox search | `ip` and `domain` scopes — the host endpoint takes an IPv4 address, a hostname or a domain, which is why one function serves both |

**Why both platforms, always.** They index different things: URLhaus is malware-*distribution*
URLs somebody reported, with the retrieved file behind them; ThreatFox is IOCs somebody submitted
with an actor attached. Asking one answers half the question.

Keeps, from URLhaus: `urlhaus_url`, `urlhaus_host`, `urlhaus_id`, `urlhaus_url_status`,
`urlhaus_online`, `urlhaus_date_added`, `urlhaus_firstseen`, `urlhaus_last_online`,
`urlhaus_threat` / `_threats`, `urlhaus_tags`, `urlhaus_reporter` / `_reporters`,
`urlhaus_blacklists`, `urlhaus_larted`, `urlhaus_takedown_time_seconds`, `urlhaus_reference`,
`urlhaus_payloads` (capped at 25, with `urlhaus_payloads_truncated` and an uncapped
`urlhaus_payload_count`), `urlhaus_signatures`, `urlhaus_payload_first_seen` / `_last_seen`, and
on the host route `urlhaus_urls` (capped at 25) with `urlhaus_url_count` and
`urlhaus_online_urls_in_response`.

From ThreatFox: `threatfox_iocs` (capped at 50), `threatfox_ioc_count`,
`threatfox_returned_count`, `threatfox_iocs_truncated`, `threatfox_malware_families` / `_ids`,
`threatfox_threat_types`, `threatfox_tags`, `threatfox_reporters`,
`threatfox_confidence_min` / `_max`, `threatfox_first_seen` / `_last_seen`,
`threatfox_search_term`, `threatfox_exact_match`, `threatfox_discarded_partial_matches`.

And three merged fields a consumer should read first: `abusech_sources` (which platforms actually
answered), `abusech_actor_attribution` (the union of URLhaus payload signatures and ThreatFox
malware families — the attribution sentence an incident report wants), and `abusech_online`, which
is `True` only when a platform positively says the indicator is live now and stays `None` when
neither spoke to liveness.

**Half an answer is reported as half an answer.** When one platform succeeds and the other fails,
the result is a success carrying `abusech_urlhaus_error` / `abusech_threatfox_error` so a consumer
can see which half went unanswered rather than inferring it from missing keys. Two identical
failures collapse to that one slug; two different failures become `lookup_failed` carrying both,
because folding an `unauthorized` and a `no_results` into either one would be a lie in one
direction or the other.

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

- **abuse.ch (URLhaus + ThreatFox)**, roadmap 8.7 — **built and wired**; see its section above.
  Decision Q5 in `docs/ROADMAP.md` stands: full build including bulk mode, terms-of-service
  exposure accepted and recorded in `docs/OPSEC.md` section 4a rather than mitigated.
- **GreyNoise** (roadmap 8.8) is **struck** (decision Q10 — no eligible non-consumer email
  address, so it can never be started) and will not be built.

---

## Credential handling

**Header:** VirusTotal (`x-apikey`), AbuseIPDB (`Key`), OTX (`X-OTX-API-KEY`), Cloudflare
(`Authorization: Bearer`), abuse.ch (`Auth-Key`, `abusech.py:371`), urlscan (`API-Key`, unwired).
**Query string:** Shodan (`?key=`, `shodan_api.py:68`), IPInfo (`?token=`, `ipinfo.py:17`, `:61`).
**None:** Shodan InternetDB, RDAP and Tranco.

The abuse.ch key is the one that query-parameter redaction cannot help with, because it never
appears in a URL. It is covered instead by literal redaction: `ABUSECH_AUTH_KEY` is listed in
`utils.redact._SECRET_ENV_VARS`, so its *value* is substituted wherever it appears in any string
the tool emits.

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
- **No per-provider budget exists — with one exception.** A semaphore bounds concurrency and
  cannot express "4 per minute". Roadmap item 3.4, blocked on retrieving each provider's published
  limits rather than recalling them. The exception is `providers/tranco.py`, whose published
  ceiling is one query per second and which therefore paces its own requests
  (`MIN_REQUEST_INTERVAL_SECONDS`, `tranco.py:104`), measured between request starts.
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
