# tripper_recon — additional passive intelligence sources

Review date: 2026-08-08. Repo: `/home/echo/dev/tripper_recon`, branch `feat/work-20260808-recon-hardening`. Read-only review; no files changed, `.env` not opened, no queries run against any indicator.

Every source below was verified by fetching its own documentation today. Where a page 404'd, 403'd, or omitted the number, that is stated as unverified rather than filled in.

---

## 1. What the codebase currently answers, and the gaps

The provider contract is small and consistent, which is good news for integration cost:

```python
async def shodan_host(*, client: httpx.AsyncClient, api_key: Optional[str], ip: str) -> Dict[str, Any]
```
— `tripper_recon/providers/shodan_api.py:13`

Every provider returns `{"ok": True, "data": {...}}` or `{"ok": False, "error": "..."}` (`shodan_api.py:15`, `shodan_api.py:29`), wraps its call in `with_exponential_backoff` (`tripper_recon/utils/backoff.py:10`), and receives the shared `httpx.AsyncClient` rather than making its own. Keyless providers are even simpler — `tripper_recon/providers/ripestat.py:13-22` is the template to copy for anything that needs no credential.

Current coverage, by question:

| Question an analyst asks | Answered today by | Anchor |
|---|---|---|
| Who owns this IP / what ASN | IPinfo, RIPEstat, Cloudflare Radar | `orchestrators.py:123`, `orchestrators.py:342` |
| Do AV engines flag it | VirusTotal | `orchestrators.py:121` |
| Has it been reported for abuse | AbuseIPDB | `orchestrators.py:127` |
| What ports/services are exposed | Shodan (key required) | `orchestrators.py:125` |
| Is it in threat-intel pulses | OTX (key required) | `orchestrators.py:129` |
| ASN routing / peering / rank | RIPEstat, CAIDA, PeeringDB | `orchestrators.py:342-345` |

Gaps that matter for the stated mission — "is this IP/domain/URL malicious, and capture the facts for a report":

1. **No domain age or registration data.** The domain path (`orchestrators.py:193-331`) has VT and OTX and nothing else. Registration date is the single cheapest high-signal feature in phishing triage and the tool does not have it.
2. **No "is this just internet background noise" signal.** AbuseIPDB conflates opportunistic mass-scanners with targeted attackers. Nothing distinguishes them.
3. **No popularity/prevalence signal.** No way to say "this domain is in the global top 1k, deprioritize" vs "nobody has ever heard of this domain".
4. **Shodan-shaped data is entirely gated on a key.** With `SHODAN_API_KEY` unset the provider returns `missing_api_key` (`shodan_api.py:15`) and the error is silently suppressed (`orchestrators.py:78`), so the analyst gets a blank ports field with no explanation.
5. **No exploitation context on CVEs.** Nothing turns a CPE/CVE list into "this one is on CISA KEV".
6. **No anonymiser signal.** Tor/VPN/proxy status is absent; IPinfo's privacy fields are a paid tier the tool does not use.
7. **No netblock/ASN reputation.** The ASN path is rich in routing data and empty on reputation.

Two integration costs beyond writing the provider module, worth pricing into every estimate below:

- **The console renderer is hand-rolled per provider.** `reporting/console.py:24` `render_ip_analysis` adds rows literally, one field at a time (`console.py:29-132`). Each new source is a second edit there.
- **Rate limiting is one process-global semaphore, not per-provider.** `utils/http.py:54-74` creates a single `asyncio.Semaphore` shared by everything. Sources with a hard per-second ceiling (Tranco at 1 qps, Team Cymru's null-routing policy) cannot be honoured by this design; they need a per-host limiter. Treat that as a prerequisite, not a per-source cost.

**A cross-cutting ToS problem you should fix before adding any of these.** `utils/http.py:10-14` sets a default User-Agent impersonating Chrome on Windows, applied to every outbound request via `default_headers()` (`http.py:34-38`). Several of the sources below explicitly want an identifying UA or a contact string, and RIPEstat's own `sourceapp=tripper-recon` parameter (`providers/ripestat.py:26`) shows the project already knows the right pattern. Spoofing a browser against an intelligence API is both a ToS risk and the opposite of "defensible". Recommend a default UA of the form `tripper-recon/0.1 (+contact)`.

---

## 2. The passivity ruling, up front

Excluded outright as **not passive** — these contact the target or make the investigation visible to it:

| Candidate | Why excluded |
|---|---|
| **urlscan.io `POST /api/v1/scan/`** | Loads the target URL in a real browser from urlscan infrastructure. Worse, a public scan is indexed and visible to anyone — including the operator of the site — so it signals the investigation. Hard exclude. The **search** endpoint is a different thing and is recommended below. https://urlscan.io/docs/api/ |
| **Pulsedive `/analyze.php?probe=1`** | Pulsedive's own quickstart describes `probe=1` as an "active scan" that contacts the target. Only `/indicator.php` is passive. If Pulsedive is ever added, `probe` must be pinned to `0` and the analyze endpoint should be absent from the codebase entirely. https://docs.pulsedive.com/api/quickstart |
| **MalwareBazaar `get_file`** | Downloads a live malware sample to the analyst workstation. Not a target-contact problem, an operational-hazard problem. The metadata queries are fine; the download endpoint must not be wired in. https://bazaar.abuse.ch/api/ |
| **Tor DNSEL live lookup** (`<reversed-ip>.ip-port.exitlist.torproject.org`) | Passive with respect to the target, but it leaks the indicator to a third-party DNS path on every query. The bulk list download achieves the same answer with zero per-indicator leakage. https://blog.torproject.org/changes-tor-exit-list-service/ |
| **Spamhaus live DNSBL** (`zen.spamhaus.org`) | Not target-contacting, but the Fair Use Policy requires querying from your own recursive resolver or an ECS-supporting public resolver, and use by "companies, organizations" at volume requires a paid Datafeed. The DROP JSON files below deliver the netblock signal with none of that. https://www.spamhaus.org/blocklists/dnsbl-fair-use-policy/ |

**Grey area already present in the codebase, which the prompt flags correctly.** `utils/dns.py:8-23` calls `socket.getaddrinfo` on the target domain and `utils/dns.py:26-34` does a reverse PTR; `orchestrators.py:248` runs `resolve_domain(domain)` on every domain investigation. On a cache miss this walks the delegation chain to the target's **own authoritative nameservers**, from the analyst's egress IP. For an attacker-controlled domain with a self-hosted NS, that is a direct tip-off carrying the analyst's source address and query timing. Three ways out, cheapest first:

1. **Prefer passive resolution.** VT's DNS records are already parsed into `passive_ips` (`orchestrators.py:228-235`) — invert the precedence at `orchestrators.py:249` so passive answers are used and live resolution becomes an opt-in `--active-dns` flag.
2. **Route live resolution through DoH** at `https://cloudflare-dns.com/dns-query` with `Accept: application/dns-json` — keyless, no documented rate limit, and it moves the recursion off the analyst's IP. It does **not** eliminate the leak (a cache miss still reaches the target's NS), it only anonymises the requester. Say that plainly in the docs rather than claiming it is passive. https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/
3. **Add a real passive DNS source** so the live path can be off by default. Options assessed in §4.

---

## 3. Ranked shortlist

Ranking is (analyst value) × (keyless or free) / (effort). Effort is S = one provider module on the existing pattern plus a renderer edit; M = adds a transport, cache, or new orchestrator wiring; L = new subsystem.

### Tier 1 — keyless or free, high value, do these first

**1. Shodan InternetDB — S, keyless, passive**
`GET https://internetdb.shodan.io/<ip>`. Shodan's own docs: "you don't need to have a Shodan account or a Shodan API key in order to use the InternetDB API." Returns open ports, CPEs, hostnames, tags, and **CVE IDs**. https://internetdb.shodan.io/

*Unique question:* what is exposed on this host, and does it carry known CVEs — currently unanswerable without a paid key, and the CVE list is something the full Shodan provider does not even extract today (`shodan_api.py:23-29` pulls ports/org/tags/cpe but no vulns).
*Passive:* yes. Shodan scanned the host on its own schedule; you read its database.
*Limits:* no rate limit published. Data refreshes weekly, not real-time — so it is a fallback and a CVE source, not a Shodan replacement. Docs say free for non-commercial use.
*Integration:* copy `shodan_api.py` verbatim, drop the key check, add `vulns` to the extracted fields. Wire beside `sh_task` at `orchestrators.py:125`. Best single ROI on this list.

**2. RDAP via IANA/rdap.org bootstrap — M, keyless, passive**
`https://rdap.org/domain/<domain>`, `/ip/<addr>`, `/autnum/<asn>`; 302-redirects to the authoritative registry RDAP server using the IANA bootstrap files (RFC 9224, `https://data.iana.org/rdap/dns.json`). ARIN's own RDAP at `https://rdap.arin.net/registry/ip/` requires no authentication and returns JSON. https://about.rdap.org/ · https://www.iana.org/assignments/rdap-dns/rdap-dns.xhtml · https://www.arin.net/resources/registry/whois/rdap/

*Unique question:* **how old is this domain**, who registered it, and what is the registrar abuse contact. Nothing in the tool answers this. A domain registered 48 hours ago is the strongest cheap phishing signal there is, and the registrar abuse address is exactly the "capture the facts for the report" output the mission calls for. On the IP side it gives the first-party network abuse contact, complementing RIPEstat's ASN-level `abuse-contact-finder` (`providers/ripestat.py:29`) with the specific netblock's contact.
*Passive:* yes. Registry data, no contact with the target.
*Limits:* no key, no published quota. rdap.org handles ~10M redirects/day. Registry ToS apply per-registry; some registries redact registrant fields under GDPR — creation date and registrar survive redaction, which is the part that matters.
*Integration:* M rather than S because of the redirect hop (httpx needs `follow_redirects=True` for this provider — the shared client at `utils/http.py:41-51` does not set it, so pass it per-request), and because RDAP responses are a nested jCard structure that needs a small parser. Also needs a new `domain_intel` slot at `orchestrators.py:200`.

**3. Tranco domain rank — S, keyless, passive**
`GET https://tranco-list.eu/api/ranks/domain/<domain>`. Verified today: **no authentication required**, rate limit **1 query/second**, returns rank history for the past 30+ days. https://tranco-list.eu/api_documentation

*Unique question:* is this a globally popular domain or one nobody visits. This is a false-positive suppressor — the fastest way to close out "is `microsoft.com` malicious" — and paired with domain age it separates "new and obscure" from "old and mainstream" in two cheap calls.
*Passive:* yes, static ranking dataset.
*Limits:* 1 qps is a hard constraint the current global semaphore (`utils/http.py:54-74`) cannot express. Needs a per-host limiter, or accept 429s and lean on the existing backoff (`utils/backoff.py:10`). Contributing sources carry mixed licences including CC BY-NC 4.0 (Cloudflare Radar), so check before redistributing rank values in a commercial product.
*Integration:* trivial provider; the qps ceiling is the only real work, and it matters mostly in bulk mode.

**4. GreyNoise Community API — S, free (key optional), passive**
`GET https://api.greynoise.io/v3/community/<ip>`. Returns `noise` (has this IP been mass-scanning the internet in the last 90 days), `riot` (is it known-benign infrastructure — Google, Microsoft, CDNs), `classification`, `name`, `last_seen`. https://docs.greynoise.io/docs/using-the-greynoise-community-api · https://github.com/GreyNoise-Intelligence/api.greynoise.io

*Unique question:* the two questions that most often decide whether an alert gets escalated — "is this opportunistic background noise" and "is this actually benign known infrastructure". AbuseIPDB's confidence score cannot distinguish a mass-scanner from a targeted attacker; `riot` is the closest thing to an authoritative allowlist available for free.
*Passive:* yes, GreyNoise's own sensor network.
*Limits — this is the catch:* **10 IP lookups/day unauthenticated, 50 searches/week for free authenticated accounts**, and that 50 is shared with Visualizer usage. Free accounts registered with consumer email domains (Gmail, ProtonMail, iCloud) do **not** get API-key access at all. ToS scope free use to non-commercial purposes. https://www.greynoise.io/terms
*Integration:* S — trivial provider. But at 50/week it cannot be a default-on provider in bulk mode. Wire it behind an explicit flag, or as a single-target-only enrichment, and surface the quota-exhausted case as a visible warning rather than routing it into the silent-suppression list at `orchestrators.py:78`.

**5. CISA KEV catalog — S, keyless, passive, cache locally**
`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`. Verified live today: catalogVersion `2026.08.07`, 1,662 entries, fields `cveID`, `vendorProject`, `product`, `dateAdded`, `knownRansomwareCampaignUse`, `cwes`. No key, no quota. https://www.cisa.gov/known-exploited-vulnerabilities-catalog

*Unique question:* of the CVEs on this host, which are **actually being exploited in the wild** — and which are tied to ransomware campaigns. It is a multiplier on #1 rather than a standalone source: InternetDB gives you a CVE list, KEV turns it into a prioritised one, and `knownRansomwareCampaignUse: "Known"` is a line that belongs verbatim in an incident report.
*Passive:* yes, a static government feed.
*Integration:* fetch once, cache to disk with a TTL, join in memory. Not a per-indicator HTTP call, so it does not fit the existing provider signature — it is a small enrichment module instead. Still S.

**6. Tor exit list (bulk) — S, keyless, passive**
`https://check.torproject.org/torbulkexitlist` — plain text, every current IPv4 exit address, refreshed roughly hourly. https://blog.torproject.org/changes-tor-exit-list-service/

*Unique question:* is this IP a Tor exit. Today this requires IPinfo Plus or Enterprise (§4), i.e. money. Attribution context an analyst needs before writing "the attacker is in Country X".
*Passive:* yes, when using the bulk file. The DNSEL per-IP lookup is excluded above.
*Integration:* download-and-cache like KEV; membership test is a set lookup. Note the file is IPv4-only, so the answer for an IPv6 target is "unknown", not "no" — say so in the output.

**7. Spamhaus DROP / ASN-DROP (JSON) — S, keyless, passive**
`https://www.spamhaus.org/drop/drop_v4.json`, `drop_v6.json`, `asndrop.json`. Netblocks and ASNs Spamhaus assesses as leased or hijacked by professional cybercrime operations. Free for any organisation; **attribution to The Spamhaus Project is required**, and the date/copyright text must stay with the data. Re-download no more often than hourly; daily is the expected cadence. https://www.spamhaus.org/blocklists/do-not-route-or-peer/

*Unique question:* is the containing netblock or the whole ASN known-criminal infrastructure. The ASN path (`orchestrators.py:334-558`) is dense with routing facts and carries no reputation signal at all; ASN-DROP fills that directly and is a strong finding for a report ("hosted in an ASN on the Spamhaus DROP list").
*Passive:* yes, static file, no per-indicator query.
*Integration:* cache + prefix-tree membership test. The attribution requirement needs to surface in both console and JSON output — that is a real obligation, not a footnote.

### Tier 2 — free but key-gated, or with a ToS caveat you must accept knowingly

**8. abuse.ch URLhaus — M, free Auth-Key, passive, ToS caveat**
`POST https://urlhaus-api.abuse.ch/v1/host/` (by IP or hostname) and `/v1/url/`. Requires `Auth-Key` header from https://auth.abuse.ch/ (free). https://urlhaus-api.abuse.ch/

*Unique question:* has this host actually **served a malware payload**, which payloads, and are the URLs still live. That is a materially stronger claim than a VT detection ratio, and the payload hash/signature is directly reportable.
*Passive:* yes for the lookup endpoints. The sample-download endpoint is excluded above.
*ToS caveat — read this before implementing:* the abuse.ch Terms of Use state you may not "use any high volume automatic, electronic or manual process to access, search or harvest information", explicitly naming "robots, spiders or scripts", and bind free access to "Query Volume Limits... reasonably expected for non-commercial or non-profit purposes". They also prohibit derivative works without written consent. https://abuse.ch/terms-of-use/ · The auth portal separately warns that accounts with unusually high query volumes may be limited for up to 72 hours. My read: interactive one-indicator-at-a-time lookups from an analyst's tool sit inside fair use — the API exists to be called programmatically and issues keys for exactly that — but **bulk-file mode in this tool (`cli.py:190-200`) is precisely the high-volume automated harvesting the ToS names.** I am not certain where they draw the line and cannot be. What would settle it: email abuse.ch/Spamhaus describing the use case and volume, and keep the written answer. Until then, gate URLhaus off in bulk mode and leave it on for single-target investigations.
*Integration:* M — POST with form-encoded body, unlike every existing provider, and no published rate limit to design against.

**9. abuse.ch ThreatFox — M, free Auth-Key, passive, same ToS caveat**
`POST https://threatfox-api.abuse.ch/api/v1/` with `query: search_ioc`. https://threatfox.abuse.ch/api/

*Unique question:* **malware-family attribution** for an IOC — "this IP is a Cobalt Strike C2", "this is a QakBot distribution host". OTX pulse titles (`providers/otx.py:30`) gesture at this; ThreatFox states it as structured data with a confidence level. Highest-value single string you can put at the top of an incident report.
*Same ToS analysis as URLhaus.* One Auth-Key covers the abuse.ch platforms, so #8 and #9 share the credential and should be built as one provider module with two functions.

**10. urlscan.io **search only** — M, free key recommended, passive**
`GET https://urlscan.io/api/v1/search/?q=domain:<d>` — ElasticSearch-syntax query over **existing** scans by domain, IP, ASN, or hash. https://urlscan.io/docs/api/

*Unique question:* has anyone already scanned this URL/domain, what did the page look like, what did it load, and what did it redirect to — page-level intelligence the tool has none of today, and screenshots/DOM from a prior scan are exactly what an analyst wants for a phishing writeup without ever loading the page themselves.
*Passive:* the search endpoint reads an existing corpus and does not contact the target. **The `/scan/` endpoint on the same API is the excluded active one.** If this is implemented, put a comment at the provider's top saying so, and do not import the scan path.
*Limits:* unauthenticated users get "minor quotas"; per-minute/hour/day limits vary by action and urlscan declines to publish fixed numbers, directing users to `https://urlscan.io/api/v1/quotas`. A doc example shows 30/minute for search but is explicitly illustrative. **Unverified — I could not confirm the free-tier search quota.** https://docs.urlscan.io/pages/api-rate-limits
*Integration:* M — result parsing is heavier than the other providers, and the tool should read the `X-Rate-Limit` response headers rather than guessing.

**11. Certificate Transparency — M, split recommendation**
Two routes, and the free one is unreliable:
- **crt.sh** — keyless, `?q=<domain>&output=json`. Operated by Sectigo. I confirmed it serving results today, but an earlier fetch in this same session returned **502**, and a **404** on the JSON variant. Community reports document sustained 502/504 periods, attributed by the maintainer to failing front-end SSDs and CT log backlogs. https://crt.sh/ · https://groups.google.com/g/crtsh
- **SSLMate Cert Spotter** — key required, free "Small" tier verified today at **100 single-hostname queries/hour, 10 full-domain queries/hour, 75/minute, 5/second**; paid tiers $50/mo and $500/mo. https://sslmate.com/ct_search_api/

*Unique question:* every hostname the target has ever certified, plus certificate issuance history — which surfaces sibling infrastructure and dates the domain's first appearance independent of RDAP.
*Passive:* yes for both. CT logs are a public append-only record.
*Recommendation:* if CT goes in, use Cert Spotter as primary and crt.sh as an unreliable keyless fallback — not the reverse. A SOC tool whose "is it malicious" answer intermittently 502s is worse than one that does not offer the field.

**12. Team Cymru IP-to-ASN — M, keyless, passive**
WHOIS on TCP/43 (`whois -h whois.cymru.com " -v <ip>"`), DNS TXT (`<reversed-octets>.origin.asn.cymru.com`), or HTTPS. No key. Free "forever", refreshed every 4 hours from 50+ BGP peers. https://team-cymru.com/community-services/ip-asn-mapping

*Unique question:* authoritative BGP-derived prefix and origin ASN with **no key at all** — a genuine fallback for the case where `IPINFO_TOKEN` is unset and the ASN chain at `orchestrators.py:154-158` silently produces nothing.
*Passive:* yes.
*Caveat that lowers its rank:* Team Cymru explicitly warn that "IPs that are seen abusing the whois server with large numbers of individual queries instead of using the bulk netcat interface will be null routed", and ask that queries be aggregated to /24 and /64. Their bulk interface is a netcat session, not HTTP — it does not fit the `httpx.AsyncClient` provider contract at all. Value is also largely duplicative of IPinfo/RIPEstat, so this is worth doing only as an explicit no-keys-configured fallback path.

---

## 4. Assessed and not recommended (with reasons)

| Candidate | Verified status | Verdict |
|---|---|---|
| **Feodo Tracker** | Site currently displays: "Our Feodo Tracker datasets are currently empty." https://feodotracker.abuse.ch/ | **Exclude on value, not passivity.** An empty feed produces a confident "no result" that reads identically to "not malicious". Re-check later. |
| **MalwareBazaar** | Free Auth-Key, `https://mb-api.abuse.ch/api/v1/`, hash-keyed lookups. https://bazaar.abuse.ch/api/ | Skip for this tool. It is hash-indexed; tripper_recon's inputs are IP/domain/URL/ASN. Only becomes relevant if URLhaus payload hashes are already being pivoted on. |
| **IPinfo privacy detection** | VPN/proxy/Tor/relay/hosting fields are on **Plus and Enterprise** plans; the free Lite tier is country-level geo plus basic ASN only. https://ipinfo.io/lite | Paid. The free Tor bulk list (#6) covers the highest-value slice of it at zero cost. |
| **Censys Platform** | Free tier verified at **250 API queries/month**, 100 results/query. https://censys.com/blog/new-free-user-features/ | 250/month is a rounding error for a SOC tool, and the data largely duplicates InternetDB/Shodan. Skip unless the operator has a paid seat. |
| **Netlas** | Community plan **50 requests/day**. https://netlas.io/pricing/ | Same shape as Censys — thin quota, duplicative data. |
| **Validin** | Community plan verified: **10 queries/day, 50/month**, 250 results/query; Professional $399/mo. https://docs.validin.com/docs/subscription-levels | Data (passive DNS + host response history) is genuinely good and non-duplicative. 10/day makes it unusable as an integrated provider. Revisit only at the paid tier. |
| **Pulsedive** | `https://pulsedive.com/api/indicator.php`, key optional. Free-plan limits reported in third-party sources as 50/day and 500/month; **I could not verify these against Pulsedive's own current documentation** — their docs index did not carry the numbers. https://docs.pulsedive.com/api/quickstart | Defer. Also carries the active-probe hazard noted in §2 — if added, `probe=1` must be unreachable from this codebase. |
| **SecurityTrails** | Now under Recorded Future; the API page presents paid pricing and I found **no verifiable current free tier**. https://securitytrails.com/corp/api | Skip. Do not assume the historically-free tier still exists. |
| **Onyphe** | Free tier exists; **I could not verify its current request limits** from Onyphe's own pricing or API docs. https://www.onyphe.io/pricing | Unverified — do not plan against it without checking. |
| **CIRCL Passive DNS** | Access "restricted to trusted partners"; no self-service registration, granted case-by-case after describing affiliation and intended use. https://www.circl.lu/services/passive-dns/ | Excellent data, but not something a distributed tool can assume. Worth the operator applying for personally; not worth a default-on provider. |
| **Silent Push Community Edition** | Free tier including API access and passive DNS is advertised; **request limits not verifiable** from their published material. https://www.silentpush.com/community-edition/ | Promising as the passive-DNS answer to the §2 live-resolution problem. Settle the limits question first — sign up and read the quota page. |
| **MISP / OpenCTI** | Platforms, not sources. | Not integrable as a provider — they are systems the operator would have to run, and they would consume tripper_recon's output rather than feed it. Out of scope unless the operator stands one up. |
| **Cloudflare Radar domain ranking** | `GET /radar/ranking/top` plus dataset endpoints; Bearer token required. Cloudflare's docs **do not state** whether free accounts can call it. https://developers.cloudflare.com/radar/investigate/domain-ranking-datasets/ | The tool already holds `CLOUDFLARE_API_TOKEN` (`.env.example:4`, `orchestrators.py:94`), so if free-account access works this is nearly free to add. But Tranco (#3) answers the same question keylessly and with a documented rate limit — prefer Tranco, and treat Radar ranking as redundant. |

---

## 5. Recommended sequencing

**Phase 0 — prerequisites (do before any source lands):**
- Replace the browser-impersonating default UA (`utils/http.py:10-14`) with an identifying `tripper-recon/<version>` string. ToS hygiene for everything below.
- Add a per-host rate limiter alongside the global semaphore (`utils/http.py:54-74`). Tranco's 1 qps and Cert Spotter's 5/sec cannot be honoured otherwise.
- Add a small disk cache with TTL for the bulk-file sources (KEV, Tor, DROP).
- Decide the live-DNS question (§2). Recommend: passive-first, `--active-dns` opt-in.

**Phase 1 — keyless, one PR each:** InternetDB, Tranco, CISA KEV, Tor exit list, Spamhaus DROP. All Tier-1 value, all S effort, no credentials, no ToS negotiation. This is the highest-yield batch on the list.

**Phase 2 — RDAP.** Highest single-source value (domain age + registrar abuse contact) and the biggest gap in the domain path, but M effort because of redirects and jCard parsing. Worth its own PR.

**Phase 3 — key-gated, after decisions:** GreyNoise (accept 50/week, single-target only), abuse.ch URLhaus + ThreatFox (after the fair-use question is settled in writing), urlscan search (after reading actual quota headers), CT via Cert Spotter.

**Never:** urlscan `/scan/`, Pulsedive `probe=1`, MalwareBazaar `get_file`.

---

## 6. Things I could not verify

Stated explicitly rather than filled in:

- urlscan.io free-tier **search** quota — urlscan declines to publish per-tier numbers; the 30/minute figure in their docs is labelled illustrative.
- Pulsedive free-plan limits (50/day, 500/month) — third-party sources only, not Pulsedive's current documentation.
- Onyphe free-tier request limits.
- Silent Push Community Edition API limits.
- Whether Cloudflare Radar's ranking endpoints are callable with a free-account API token.
- Shodan InternetDB rate limits — none published anywhere I could find; the absence of a stated limit is not a guarantee of none.
- crt.sh rate limits — undocumented; its availability record is the larger concern.
- Whether abuse.ch considers a per-indicator analyst tool "automated harvesting" under their ToS. This is a judgement call I am not able to resolve from published text, and it affects two Tier-2 sources. Settle it by asking them.
