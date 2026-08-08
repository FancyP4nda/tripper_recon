# Providers

Ten providers, in `tripper_recon/providers/`. This table is the answer to "why is my output empty".

Each row lists the environment variable, which commands use it, and exactly which fields the
provider module keeps. Fields the API returns but the module discards are noted, because they are
the cheapest capability upgrade available — no new request, no new quota.

---

## At a glance

| Provider | Env var | Key needed | `ip` | `domain` | `asn` |
|---|---|---|:--:|:--:|:--:|
| RIPEstat | — | **no** | | | yes |
| CAIDA AS-Rank | — | **no** | | | yes |
| PeeringDB | — | **no** | | | yes |
| VirusTotal | `VT_API_KEY` | yes | yes | yes | |
| Shodan | `SHODAN_API_KEY` | yes | yes | yes | |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | yes | yes | yes | |
| IPInfo | `IPINFO_TOKEN` | yes | yes | yes | yes |
| AlienVault OTX | `OTX_API_KEY` | yes | yes | yes | |
| Cloudflare Radar | `CLOUDFLARE_API_TOKEN` | yes | yes | yes | yes |
| Cloudflare BGP | `CLOUDFLARE_API_TOKEN` | yes | | | yes |

**`tripper-recon asn 15169` works with a completely empty `.env`.** RIPEstat, CAIDA, and PeeringDB
carry that command on their own.

> **A provider with no key is skipped silently.** It is not reported as missing, and on the console
> an absent VirusTotal renders as a green `0/0` — indistinguishable from a clean result
> (`reporting/console.py:70-79`). Until roadmap item 4.1 lands, confirm which keys are set before
> reading an empty result as a clean one.

---

## No key required

### RIPEstat — `providers/ripestat.py`

`https://stat.ripe.net/data`. Five endpoints, all on the `asn` command. Self-identifies with
`sourceapp=tripper-recon` (`ripestat.py:26`), which is the correct behaviour and the model the
other providers should follow.

| Call | Gives you |
|---|---|
| `as-overview` | AS holder name, announced status |
| `abuse-contact-finder` | **Abuse contact address** — the incident-report fact |
| `routing-status` | Announced v4/v6 prefix counts, observed neighbour count |
| `asn-neighbours` | Upstream / downstream / uncertain ASNs |
| `announced-prefixes` | Full v4 and v6 prefix list |

Returns the raw `data` object (`ripestat.py:20`), so nothing is discarded.

### CAIDA AS-Rank — `providers/caida.py`

`https://api.asrank.caida.org/v2/graphql`. Keeps: `rank`, `degree_total`, `degree_customer`,
`degree_peer`, `degree_provider`, `customer_cone_asns`, `rir`.

`customer_cone_asns` is the field that tells you whether "same ASN" is a meaningful pivot or a
netblock the size of a country.

### PeeringDB — `providers/peeringdb.py`

`https://www.peeringdb.com/api`. Keeps IXP names only (`peeringdb.py:38`).

Known defect: the netixlan lookup runs 1+N requests inside a retried closure, so one failure on the
last sub-request replays all the earlier ones (roadmap item 3.10).

---

## Key required

### VirusTotal v3 — `providers/virustotal.py`

`https://www.virustotal.com/api/v3`. `GET` only — reports that already exist. It never submits an
indicator for analysis. Key travels in the `x-apikey` **header**.

**IP** (`vt_ip_summary`): `vt_last_analysis_stats`, `vt_reputation`, `vt_link`.

**Domain** (`vt_domain_summary`): the above plus `vt_categories`, `vt_tags`, `vt_dns_records`
(the passive A/AAAA records), `vt_security_results`, `vt_whois`, `vt_whois_timestamp`,
`vt_last_https_certificate`, `vt_last_https_certificate_jarm`.

**Discarded but returned by the API:** `last_analysis_results` (the per-engine breakdown — which
five of ninety-one flagged it, and whether they are engines anyone trusts) and `last_analysis_date`
(how stale the verdict is). Both are needed by any real scoring layer. Roadmap item 4.6.

### Shodan — `providers/shodan_api.py`

`https://api.shodan.io/shodan/host/{ip}`. Keeps `ports`, `org`, `tags`, `cpe`. A `404` is
correctly reported as `not_found` rather than an error.

**Key travels in the query string** (`shodan_api.py:18`) — see the credential-leak warning below.

**Discarded:** `vulns`, `hostnames`, `last_update`. Roadmap item 4.6.

### AbuseIPDB — `providers/abuseipdb.py`

`https://api.abuseipdb.com/api/v2/check`, 365-day window. Keeps `totalReports` and
`abuseConfidenceScore`.

**Discarded:** `lastReportedAt` (a 100% score from 2019 is not a 100% score from yesterday),
`isWhitelisted`, `usageType`, `isTor`. Roadmap item 4.6.

### IPInfo — `providers/ipinfo.py`

`https://ipinfo.io`. Keeps `ip`, `city`, `country`, `region`, `postal`, `asn`, `org`,
`coordinates`, `timezone`, `hostname`. Also serves the `asn` command via `/AS{asn}`, which needs a
paid plan — a `401`/`403` there is suppressed by design (`orchestrators.py:80`).

**Key travels in the query string** (`ipinfo.py:18`) — see below.

### AlienVault OTX — `providers/otx.py`

`https://otx.alienvault.com/api/v1`. Keeps `otx_pulse_count` and the **first five** pulse titles.
Domain lookups add `otx_tags`, `otx_malware_count`, `otx_passive_dns_count`.

A raw pulse count is a weak signal: fifty pulses cloned from one author is not fifty independent
observations. **Discarded:** per-pulse author, created, and modified dates — the fields that would
let the count be quality-adjusted. Roadmap items 4.6 and 5.11.

### Cloudflare Radar — `providers/cloudflare_radar.py`

`https://api.cloudflare.com/client/v4/radar/graphql`. ASN metadata and prefixes. Tries an integer
ASN query, then falls back to the `AS{n}` string form.

### Cloudflare BGP — `providers/cloudflare_rest.py`

BGP hijack and route-leak incident counts for an ASN.

> **Do not trust the victim/hijacker split.** `total` comes from the all-pages `result_info.total_count`
> while `as_hijacker` is counted over a single unpaginated response, and `as_victim` is the
> difference (`cloudflare_rest.py:29`). The console turns that arithmetic into the prose "always as
> a victim" (`reporting/console.py:247`). Roadmap item 4.7.

---

## Credential handling

**Header (safer):** VirusTotal, AbuseIPDB, OTX, Cloudflare (both).
**Query string:** Shodan (`?key=`), IPInfo (`?token=`).

For the two query-string providers, the API key is part of the request URL. When a request fails,
`_error_payload` (`orchestrators.py:35-40`) copies both `str(request.url)` and the exception text
into the result. Both contain the key. That result reaches console output, `-o json` output, and
the REST API response.

Reproduced:

```
url field : https://api.shodan.io/shodan/host/1.1.1.1?key=SUPERSECRET
str(exc)  : Client error '401 Unauthorized' for url 'https://api.shodan.io/...?key=SUPERSECRET'
```

**Until roadmap item 0.1 lands, do not paste raw error output into a ticket, an issue, or a chat.**

---

## Rate limits and quota

Free-tier limits are **not documented here on purpose.** Published limits change, and a number
written from memory into a runbook is worse than no number. Retrieve them from each provider's
current documentation and record the retrieval date. `docs/RATE-LIMITS.md` is roadmap item 9.4.

What the code does today:

- One process-global semaphore, default 10, meant to cap concurrency (`utils/http.py:54-74`).
- `--rate-limit` does not reach it. The limiter wraps `asyncio.create_task()` rather than the
  request itself, so it constrains task creation and nothing else (`orchestrators.py:117-129`).
  Roadmap item 3.3.
- No per-provider budget exists. A semaphore bounds concurrency and cannot express "4 per minute".
  Roadmap item 3.4.
- `429` is not handled specially and `Retry-After` is never read. A `401` gets retried four times,
  while a transient RIPEstat `502` is never retried. Roadmap item 3.5.
- A domain with eight A records costs nine VirusTotal calls per run, because the per-IP loop
  re-queries every provider for every address (`orchestrators.py:253-274`).

## Adding a provider

1. New module in `providers/`, one async function per endpoint.
2. Return the envelope: `{"ok": True, "data": {...}}` or `{"ok": False, "error": "...", ...}`.
3. Return `{"ok": False, "error": "missing_api_key"}` when the key is unset — never raise.
4. Wrap the call in `with_exponential_backoff`.
5. **Passive only.** The endpoint must return data the provider already holds. If it makes the
   provider contact the target, it does not belong here — check the forbidden list in
   `docs/OPSEC.md` section 7.
6. Update this file and the README provider list in the same commit.
