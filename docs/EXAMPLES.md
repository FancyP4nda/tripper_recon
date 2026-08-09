# Examples

Real output from every subcommand, so you can see what the tool actually prints before you spend
any quota on it.

This document describes the code as it stands on branch `feat/work-20260808-recon-hardening`.

---

## About these samples

**The provider responses behind every sample are synthetic.** They were produced by driving the
CLI's command functions with `respx` mocking the HTTP layer, so no request left the machine, no
API key was spent, and no real host was looked up. What is real is everything the tool did with
those responses: the verdict arithmetic, the coverage accounting, the defanging, the wrapping and
the exit codes are the code's own output, captured verbatim.

Two consequences worth stating plainly:

- **No verdict here is a claim about a real address, domain or URL.** `192.88.99.23` and
  `secure-billing-update.example` are placeholders carrying invented provider data. The one
  exception is `8.8.8.8`, which is on the tool's Tier A allowlist and is used precisely because
  that is what the allowlist does.
- **The usual documentation ranges do not appear**, because the tool refuses them. `192.0.2.0/24`,
  `198.51.100.0/24` and `203.0.113.0/24` all return `Private` from
  `orchestrators.non_public_ip_reason` and are never forwarded to a provider — the same guard that
  withholds RFC1918 addresses in the domain and bulk samples below.

Everything was rendered to a **non-TTY at 100 columns**, which is what you get when the output is
redirected into a file or pasted into a ticket. `rich` drops every colour on that path, so anything
the tool says only in colour is not said at all here — and it does not rely on colour for anything
load-bearing. The wrapping you see is the tool's, not this document's.

Run ids and timestamps differ on every invocation; the ones below are from a single capture run.

---

## Reading the output

Three lines appear on almost every block and carry most of the meaning.

**`VERDICT:`** — the label, then **score** and **confidence as separate axes**. A high score at low
confidence is a real and common state, and the tool refuses to average the two into one number. The
labels are `MALICIOUS`, `SUSPICIOUS`, `NO_ADVERSE_FINDINGS`, `INSUFFICIENT_DATA` and
`KNOWN_INFRASTRUCTURE`.

**`provider_coverage:`** — "N of M providers answered", where M is the set the path *intended* to
consult, not the set it happened to reach. A provider with no API key stays in the denominator.
Read this line before drawing any conclusion from sparse output.

**`calibration:`** — the ruleset's own statement that its weights are informed priors and not
measurements. The tool makes no accuracy claim, and this line is why.

Indicators are **defanged by default** in human-facing output (`8[.]8[.]8[.]8`,
`hxxps[://]…`), because a recon report gets pasted into tickets and chat. Pivot links to
VirusTotal, Shodan, AbuseIPDB and Cloudflare Radar are never defanged — they point at a third
party, and being clickable is the point of them. `--fanged` turns defanging off and is a
**top-level flag**, so it goes before the subcommand: `tripper-recon --fanged ip 8.8.8.8`. `-o json`
is never defanged either way.

---

## 1. A clean well-known address — `KNOWN_INFRASTRUCTURE`

`KNOWN_INFRASTRUCTURE` is not something the score can reach. It comes only from the Tier A
allowlist in `verdict/known_infrastructure.yaml`, which is a human decision with a citation
attached — the `allowlist 2026-08-08.1 retrieved 2026-08-08` line below is that file's version and
retrieval date, carried into the verdict so a stale entry is detectable. The catalogue's own stated
reason for Tier A is that these addresses "carry permanent nonzero VirusTotal and AbuseIPDB residue
from DNS tunnelling and scanning reports" — and note what happens anyway: those reports still
score, and the disagreement is surfaced as a contradiction with `ANALYST REVIEW REQUIRED` rather
than being quietly dropped.

```
$ tripper-recon ip 8.8.8.8
--- IP lookup for 8[.]8[.]8[.]8 ---
tripper-recon 0.1.0 • 2026-08-09T11:53:10.977838Z • run 20260809T115310Z-a3869d0b
VERDICT: KNOWN_INFRASTRUCTURE   score 13 (raw 13.0)   confidence MEDIUM   6 of 6 providers answered
  why:
    - +10.0 of 10.0  abuseipdb.volume_recency: AbuseIPDB: 61 reports within the provider's 365-day
    reporting window from 27 distinct reporters; observed 6 days ago (recency x1.00). Fifty reports
    from one reporter is one observation
    - +3.0 of 15.0  otx.pulse_quality: OTX: 1 pulses reported, 0.60 effective after
    author-diversity, recency and duplicate-title adjustment
  ANALYST REVIEW REQUIRED
  contradictions (1), reported and not reconciled:
    - allowlist_vs_detection: abuseipdb.volume_recency reports adverse evidence on an address the
    Tier A allowlist declares to be known infrastructure. The allowlist was applied
      what to do: A feed reporting badness on allowlisted infrastructure is wrong far more often
      than the infrastructure is compromised, so the allowlist wins by design -- but verify this one
      manually before dismissing it
  collection: passive only - no traffic was sent to the target or its infrastructure
  allowlist 2026-08-08.1 retrieved 2026-08-08 - matched allowlist data retrieved 2026-08-08, 1 days
  old (refresh age 180)
  ruleset 0.1.0-draft (package:tripper_recon.verdict/scoring.yaml) • engine 1.0.0 • evaluated
  2026-08-09T11:53:11.011482Z
  calibration: Heuristic. The weights, thresholds and decay constants in this ruleset are informed
  priors, not measurements. No labelled corpus has been built and no held-out evaluation has been
  run, so this ruleset carries no precision, recall or accuracy claim of any kind. Verdicts are
  decision support for an analyst, never a decision.
provider_coverage: 6 of 6 providers answered
  ip                              8[.]8[.]8[.]8
  virustotal_detections           0/94
  virustotal_last_analysis        2026-08-06T11:53:10+00:00
  virustotal_community_score      612
  virustotal_analysis_link        https://www.virustotal.com/gui/ip-address/8.8.8.8
  abuseipdb_reports               61
  abuseipdb_distinct_reporters    27
  abuseipdb_confidence_score      0%
  abuseipdb_last_reported         2026-08-03T11:53:10+00:00
  abuseipdb_whitelisted           yes - AbuseIPDB lists this address as whitelisted
  abuseipdb_analysis_link         https://www.abuseipdb.com/check/8.8.8.8
  otx_pulse_count                 1
  otx_pulse_link                  https://otx.alienvault.com/indicator/ip/8.8.8.8
  otx_pulse_titles                Public DNS resolvers observed in tunnelling
  open_ports                      53, 443
  shodan_last_update              2026-08-01T04:12:55.412001
  shodan_hostnames                dns[.]google
  shodan_link                     https://www.shodan.io/host/8.8.8.8
  isp                             AS15169 GOOGLE
  organization                    {'name': 'Google LLC'}
  cloudflare_radar_link           https://radar.cloudflare.com/ip/8.8.8.8
  geolocation                     IPinfo registry data - context, not evidence
  city                            Mountain View
  country                         US
  coordinates                     37.4056, -122.0775
  postal_code                     94043


Summary: total=1 succeeded=1 failed=0
```

Exit code `0`.

---

## 2. A malicious address — `MALICIOUS`

Reaching `MALICIOUS` takes corroboration by construction. The largest single signal
(`vt.weighted_detections`) tops out at 35 points and the band starts at 70, so no one provider
family can carry the verdict alone. Here three independent families agree — multiscanner, abuse
reports and community threat intel — which is what triggers the
`escalation.multi_family_corroboration` rule visible under `--explain` in §9.

```
$ tripper-recon ip 192.88.99.23
--- IP lookup for 192[.]88[.]99[.]23 ---
tripper-recon 0.1.0 • 2026-08-09T11:53:10.977838Z • run 20260809T115310Z-a3869d0b
VERDICT: MALICIOUS   score 95 (raw 95.0)   confidence HIGH   6 of 6 providers answered
  why:
    - +35.0 of 35.0  vt.weighted_detections: VirusTotal: 11 of 94 engines adverse (9 malicious, 2
    suspicious); weighted 10.00 of 8.00; observed 4 days ago (recency x1.00); no high-confidence
    engine set is configured, so no single engine hit is decisive
    - +25.0 of 25.0  abuseipdb.confidence: AbuseIPDB: 100% abuse confidence, scaled from a floor of
    25% to saturation at 75%; observed 2 days ago (recency x1.00)
    - +15.0 of 15.0  otx.pulse_quality: OTX: 3 pulses reported, 3.00 effective after
    author-diversity, recency and duplicate-title adjustment
    and 3 more scoring signal(s); run with --explain for the full breakdown
  collection: passive only - no traffic was sent to the target or its infrastructure
  allowlist 2026-08-08.1 retrieved 2026-08-08 - catalogue retrieved 2026-08-08, 1 days old (refresh
  age 180)
  ruleset 0.1.0-draft (package:tripper_recon.verdict/scoring.yaml) • engine 1.0.0 • evaluated
  2026-08-09T11:53:11.035458Z
  calibration: Heuristic. The weights, thresholds and decay constants in this ruleset are informed
  priors, not measurements. No labelled corpus has been built and no held-out evaluation has been
  run, so this ruleset carries no precision, recall or accuracy claim of any kind. Verdicts are
  decision support for an analyst, never a decision.
provider_coverage: 6 of 6 providers answered
  ip                              192[.]88[.]99[.]23
  virustotal_detections           9/94
  virustotal_last_analysis        2026-08-05T11:53:10+00:00
  virustotal_detecting_engines    BitDefender: malicious (phishing); Emsisoft: malicious
                                  (phishing); ESET: malicious (phishing); Fortinet: malicious
                                  (phishing); G-Data: malicious (phishing); Kaspersky: malicious
                                  (phishing); Netcraft: malicious (phishing); Sophos: malicious
                                  (phishing) ... and 3 more
  virustotal_community_score      -64
  virustotal_analysis_link        https://www.virustotal.com/gui/ip-address/192.88.99.23
  abuseipdb_reports               412
  abuseipdb_distinct_reporters    96
  abuseipdb_confidence_score      100%
  abuseipdb_last_reported         2026-08-07T11:53:10+00:00
  abuseipdb_analysis_link         https://www.abuseipdb.com/check/192.88.99.23
  otx_pulse_count                 3
  otx_pulse_link                  https://otx.alienvault.com/indicator/ip/192.88.99.23
  otx_pulse_titles                Cobalt Strike C2 infrastructure August 2026; SocGholish staging
                                  hosts; Credential phishing infrastructure Q3
  open_ports                      22, 80, 443, 3389, 6379
  shodan_last_update              2026-08-05T09:31:02.118441
  shodan_vulns                    CVE-2021-23017, CVE-2023-38831
  shodan_link                     https://www.shodan.io/host/192.88.99.23
  isp                             AS64500 EXAMPLE-BULLETPROOF
  organization                    {'name': 'Example Bulletproof BV'}
  cloudflare_radar_link           https://radar.cloudflare.com/ip/192.88.99.23
  geolocation                     IPinfo registry data - context, not evidence
  city                            Amsterdam
  country                         NL
  coordinates                     52.374, 4.8897
  postal_code                     1012


Summary: total=1 succeeded=1 failed=0
```

Exit code `0`. **The exit code is not the verdict** — it reports whether the lookup worked, not
what it found. A `MALICIOUS` indicator with every provider answering exits `0`. Branch on
`data.verdict` in the JSON export, not on `$?`.

---

## 3. Degraded mode: no API keys at all

This is the first run on a fresh clone with an empty `.env`, and it is the sample most worth
reading. Every provider on the `ip` path needs a credential, so nothing is asked and nothing is
learned. The tool does not print an empty report and exit `0`; it says the words "intelligence
blackout", names every provider that was never asked, and exits `1`.

```
$ tripper-recon ip 192.88.99.23
IP: 192[.]88[.]99[.]23
  error: no provider answered for 192.88.99.23 (0 of 6 providers answered): this is an intelligence
blackout, not a clean result

provider_coverage: 0 of 6 providers answered
  never asked - no API key configured: virustotal, ipinfo, shodan, abuseipdb, otx
  never asked - skipped: cloudflare_asn

Summary: total=1 succeeded=0 failed=1
```

Exit code `1`.

`cloudflare_asn` is reported as `skipped` rather than unconfigured because it is a second wave that
only runs once IPinfo has returned an ASN — IPinfo never answered, so Cloudflare was never
attempted. It stays in the denominator regardless: a denominator derived from the calls that
happened would shrink from six to five and report *better* coverage for the worse run.

The same empty `.env` still produces a full report from `asn` — see §5.

---

## 4. A domain, including the addresses it will not investigate

Two things to watch here. First, the domain and each of its addresses are scored **separately and
never merged**: the domain is `MALICIOUS` while the address it resolves to is `SUSPICIOUS`. A
phishing kit on shared hosting is exactly that shape, and merging the two would either indict the
host's other tenants or clear the kit.

Second, three of the four resolved addresses are non-public and are reported in their own table
with the reason rather than disappearing. Before this, a domain resolving to three internal
addresses and one public one rendered as a domain with one address.

Note also `collection: ACTIVE COLLECTION contributed: system_dns_resolution` on the address panel.
The `domain` path uses the system resolver, which is the tool's one documented active step
(`docs/OPSEC.md` §3), and the verdict says so instead of claiming to be fully passive.

```
$ tripper-recon domain secure-billing-update.example

--- Domain lookup for secure-billing-update[.]example ---
tripper-recon 0.1.0 • 2026-08-09T11:53:10.977838Z • run 20260809T115310Z-a3869d0b
VERDICT: MALICIOUS   score 76 (raw 76.0)   confidence HIGH   2 of 2 providers answered
  why:
    - +35.0 of 35.0  vt.weighted_detections: VirusTotal: 13 of 94 engines adverse (11 malicious, 2
    suspicious); weighted 12.00 of 8.00; observed 2 days ago (recency x1.00); no high-confidence
    engine set is configured, so no single engine hit is decisive
    - +15.0 of 15.0  domain.age: Domain registered 5 days ago (2026-08-04); age band worth 15 points
    - +10.0 of 15.0  otx.pulse_quality: OTX: 2 pulses reported, 2.00 effective after
    author-diversity, recency and duplicate-title adjustment
    and 4 more scoring signal(s); run with --explain for the full breakdown
  collection: passive only - no traffic was sent to the target or its infrastructure
  ruleset 0.1.0-draft (package:tripper_recon.verdict/scoring.yaml) • engine 1.0.0 • evaluated
  2026-08-09T11:53:11.074047Z
  calibration: Heuristic. The weights, thresholds and decay constants in this ruleset are informed
  priors, not measurements. No labelled corpus has been built and no held-out evaluation has been
  run, so this ruleset carries no precision, recall or accuracy claim of any kind. Verdicts are
  decision support for an analyst, never a decision.
provider_coverage: 8 of 8 providers answered
addresses resolved but not investigated (3):
  address         source            reason
  10.10.4.7       active+passive    private addressing - never sent to a provider
  192.168.7.31    active            private addressing - never sent to a provider
  127.0.0.1       active            private addressing - never sent to a provider
  no provider was asked about these addresses; nothing here is evidence that they are clean

domain_intelligence:
  domain: secure-billing-update[.]example
  cloudflare_radar_link: https://radar.cloudflare.com/domain/secure-billing-update.example
  virustotal_detections: 11/94
  virustotal_last_analysis: 2026-08-07T11:53:10+00:00
  virustotal_community_score: -41
  virustotal_categories: phishing, phishing and other frauds
  virustotal_passive_ips: 192[.]88[.]99[.]77, 10.10.4.7
  virustotal_analysis_link: https://www.virustotal.com/gui/domain/secure-billing-update.example
  abuseipdb_analysis_link: https://www.abuseipdb.com/check/secure-billing-update.example
  otx_pulse_count: 2
  otx_pulse_link: https://otx.alienvault.com/indicator/domain/secure-billing-update.example
  otx_pulse_titles: Invoice-themed credential phishing 2026-08; Fake billing portals targeting SMBs


Whois Lookup
  Domain Name: SECURE-BILLING-UPDATE.EXAMPLE
  Registry Domain ID: 2899213371_DOMAIN_EXAMPLE-VRSN
  Registrar: Example Registrar LLC
  Registrar IANA ID: 1234
  Registrar Abuse Contact Email: abuse@example-registrar.test
  Registrar Abuse Contact Phone: +1.5555550100
  Updated Date: 2026-08-04T11:53:10+00:00
  Creation Date: 2026-08-04T11:53:10+00:00
  Registry Expiry Date: 2027-08-04T11:53:10+00:00
  Domain Status: clientTransferProhibited
  Name Server: NS1.EXAMPLE-DNS.TEST
  Name Server: NS2.EXAMPLE-DNS.TEST
  DNSSEC: unsigned

Last HTTPS Certificate
  JARM fingerprint: 29d3fd00029d29d00042d43d00041d598ac0c1012db967bb1ad0ff2491b3ae
  Version: V3
  Serial Number: 04f1a2b3c4d5e6f70819a2b3c4d5e6f7
  Thumbprint: 9f2c1d4e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f
  Signature Algorithm: sha256RSA
  Issuer: C=US, O=Let's Encrypt, CN=R11
  Not Before: 2026-08-04T11:53:10+00:00
  Not After: 2026-11-02T11:53:10+00:00
  Subject: CN=secure-billing-update.example


- Resolving "secure-billing-update[.]example"... 4 addresses resolved, 1 investigated, 3 skipped as
non-public and never sent to a provider:

--- IP lookup for 192[.]88[.]99[.]77 ---
VERDICT: SUSPICIOUS   score 69 (raw 68.6)   confidence HIGH   6 of 6 providers answered
  why:
    - +24.5 of 25.0  abuseipdb.confidence: AbuseIPDB: 74% abuse confidence, scaled from a floor of
    25% to saturation at 75%; observed 3 days ago (recency x1.00)
    - +24.1 of 35.0  vt.weighted_detections: VirusTotal: 6 of 94 engines adverse (5 malicious, 1
    suspicious); weighted 5.50 of 8.00; observed 3 days ago (recency x1.00); no high-confidence
    engine set is configured, so no single engine hit is decisive
    - +10.0 of 10.0  abuseipdb.volume_recency: AbuseIPDB: 38 reports within the provider's 365-day
    reporting window from 14 distinct reporters; observed 3 days ago (recency x1.00). Fifty reports
    from one reporter is one observation
    and 2 more scoring signal(s); run with --explain for the full breakdown
  collection: ACTIVE COLLECTION contributed: system_dns_resolution
  allowlist 2026-08-08.1 retrieved 2026-08-08 - catalogue retrieved 2026-08-08, 1 days old (refresh
  age 180)
  ruleset 0.1.0-draft (package:tripper_recon.verdict/scoring.yaml) • engine 1.0.0 • evaluated
  2026-08-09T11:53:11.074047Z
provider_coverage: 6 of 6 providers answered
  ip                              192[.]88[.]99[.]77
  address_source                  active+passive - resolved now, and corroborated by VirusTotal
                                  DNS history
  virustotal_detections           5/94
  virustotal_last_analysis        2026-08-06T11:53:10+00:00
  virustotal_detecting_engines    ESET: malicious (phishing); Fortinet: malicious (phishing);
                                  Kaspersky: malicious (phishing); Netcraft: malicious (phishing);
                                  Sophos: malicious (phishing); CRDF: suspicious (suspicious)
  virustotal_community_score      -22
  virustotal_analysis_link        https://www.virustotal.com/gui/ip-address/192.88.99.77
  abuseipdb_reports               38
  abuseipdb_distinct_reporters    14
  abuseipdb_confidence_score      74%
  abuseipdb_last_reported         2026-08-06T11:53:10+00:00
  abuseipdb_analysis_link         https://www.abuseipdb.com/check/192.88.99.77
  otx_pulse_count                 1
  otx_pulse_link                  https://otx.alienvault.com/indicator/ip/192.88.99.77
  otx_pulse_titles                Invoice-themed credential phishing 2026-08
  open_ports                      80, 443
  shodan_last_update              2026-08-06T11:02:44.900112
  shodan_hostnames                secure-billing-update[.]example
  shodan_link                     https://www.shodan.io/host/192.88.99.77
  isp                             AS64501 EXAMPLE-HOSTING
  organization                    {'name': 'Example Hosting GmbH'}
  cloudflare_radar_link           https://radar.cloudflare.com/ip/192.88.99.77
  geolocation                     IPinfo registry data - context, not evidence
  city                            Frankfurt am Main
  country                         DE
  coordinates                     50.1155, 8.6842
  postal_code                     60311
```

Exit code `0`.

The `provider_coverage: 8 of 8` on the header is the whole-run figure: two domain-level providers
plus the six that were asked about the one address investigated. It is namespaced in the JSON
export (`domain:virustotal`, `192.88.99.77:shodan`), so the header ratio and the export can never
state different numbers.

---

## 5. An ASN — no credentials required

RIPEstat, CAIDA and PeeringDB need no key, so this command produces a usable report against a
completely empty `.env`. Seven of ten providers answer; the three that need the IPinfo token or the
Cloudflare token are named on the coverage line rather than silently omitted.

```
$ tripper-recon asn 15169
--- ASN lookup for AS15169 (Google LLC, US) ---
tripper-recon 0.1.0 • 2026-08-09T11:53:10.977838Z • run 20260809T115310Z-a3869d0b
provider_coverage: 7 of 10 providers answered
  never asked - no API key configured: ipinfo_asn, cloudflare_bgp, cloudflare_asn
  AS Number        ──>    15169
  AS Name          ──>    Google LLC, US
  CAIDA AS Rank    ──>    #21
  Abuse contact    ──>    network-abuse@google.com
  RIR (Region)     ──>    ARIN (USA, Canada, many Caribbean and North Atlantic islands)
  Peering @IXPs    ──>    DE-CIX Frankfurt • Equinix Ashburn • LINX LON1


--- BGP informations for AS15169 ---
  BGP Neighbors        412 (2 Transits • 371 Peers • 39 Customers)
  Customer cone        61 (# of ASNs observed in the customer cone)
  In-depth BGP info    https://radar.cloudflare.com/routing/as15169?dateRange=52w

--- Prefix informations for AS15169 ---
  IPv4 Prefixes announced    1032
  IPv6 Prefixes announced    92

--- Peering informations for AS15169 ---
  Upstream      Cogent Communications, US (174)  Level 3 Parent, LLC, US (3356)  NTT America,
                Inc., US (2914)
  Downstream    Google LLC, US (396982)  Google LLC, SG (139070)
  Uncertain     Example Networks Ltd, GB (45566)

--- Aggregated IP resources for AS15169 ---
  IPv4    8.8.4.0/24
          8.8.8.0/24
          8.34.208.0/20
  IPv6    2001:4860::/32
          2404:6800::/32
```

Exit code `0`.

There is no verdict line here: the scoring engine has no `asn` scope. `--neighbors N` resolves the
first N of each neighbour class to holder names. `--prefixes-out FILE` writes the full announced
prefix list; the console panel above caps each address family at 50 entries and appends
`… and N more`, so for a large ASN the file is the complete record and the panel is not.

---

## 6. A URL — and `redirect_chain: NOT RESOLVED`

The line to read is `redirect_chain`. Following a redirect or expanding a shortener is an active
fetch of the target, and a bodyless `HEAD` is not exempt, so this tool never resolves one. There is
no code path that could. A chain is only ever reported when a third party's already-completed scan
supplied it, stamped with that party's name and the date they saw it.

The verdict is `INSUFFICIENT_DATA` and that is the honest answer, not a degradation: the ruleset
declares no signal whose scope includes `url`, so the engine is handed an empty signal list. The
VirusTotal detections below are shown as evidence for the reader; they are not scored at URL scope
yet.

```
$ tripper-recon url "https://secure-billing-update.example/portal/verify?id=8831" --depth url

--- URL lookup for hxxps[://]secure-billing-update[.]example/portal/verify?id=8831 ---
tripper-recon 0.1.0 • 2026-08-09T11:53:10.977838Z • run 20260809T115310Z-a3869d0b
VERDICT: INSUFFICIENT_DATA   score 0 (raw 0.0)   confidence LOW   1 of 1 provider answered
  ! INSUFFICIENT_DATA rather than NO_ADVERSE_FINDINGS: no provider returned an affirmative negative.
  A clean verdict needs a provider that was asked and answered, not merely a provider that reported
  nothing
  collection: passive only - no traffic was sent to the target or its infrastructure
  ruleset 0.1.0-draft (package:tripper_recon.verdict/scoring.yaml) • engine 1.0.0 • evaluated
  2026-08-09T11:53:11.123524Z
  calibration: Heuristic. The weights, thresholds and decay constants in this ruleset are informed
  priors, not measurements. No labelled corpus has been built and no held-out evaluation has been
  run, so this ruleset carries no precision, recall or accuracy claim of any kind. Verdicts are
  decision support for an analyst, never a decision.
provider_coverage: 1 of 1 provider answered
  url                             hxxps[://]secure-billing-update[.]example/portal/verify?id=8831
  scheme                          https
  host                            secure-billing-update[.]example
  host_kind                       dns_name
  registrable_domain              not derived - no public suffix list is vendored, so pivot on the
                                  full host
  pivot_host                      secure-billing-update[.]example
  path                            /portal/verify
  query                           id=8831
  redirect_chain                  NOT RESOLVED -- VirusTotal holds a report for this URL and it
                                  records no redirect. That is one passive source saying so at one
                                  moment, not a statement about where the link leads now.
  virustotal_detections           9/94
  virustotal_last_analysis        2026-08-07T11:53:10+00:00
  virustotal_detecting_engines    BitDefender: malicious (phishing); CRDF: malicious (phishing);
                                  ESET: malicious (phishing); Fortinet: malicious (phishing);
                                  G-Data: malicious (phishing); Kaspersky: malicious (phishing);
                                  Netcraft: malicious (phishing); Sophos: malicious (phishing) ...
                                  and 3 more
  virustotal_analysis_link        https://www.virustotal.com/gui/url/b1f0c7d2e39a4c5b6d7e8f90a1b2…
  depth                           url
  collection                      passive only - no traffic was sent to the target or its
                                  infrastructure
```

Exit code `0`.

`--depth url` was used above to keep the sample short. The three depths are:

| `--depth` | What it adds | Resolves anything? |
|---|---|---|
| `url` | the link's own VirusTotal report, and nothing else | no |
| `host` | plus the host's own reputation (VirusTotal and OTX about the name) | no |
| `full` *(default)* | plus every public address the host resolves to, each through the full `ip` provider set | yes — the system resolver |

At `full` the output is §6 followed by the host and address blocks from §4. A `--depth url` run
against a link nobody has ever submitted to VirusTotal exits `1`: the single URL-scope provider held
no report, so nothing was learned. For a link that went live an hour ago, that is the expected
result and it is not a clean verdict.

---

## 7. `check` and `bulk` on a wall of defanged indicators

### 7a. `check --detect-only` — classify and stop, zero quota

Detection is a pure function over the string. This branch returns before any orchestrator, and
therefore before any HTTP client, exists.

```
$ tripper-recon check "hxxps[://]secure-billing-update[.]example/portal/verify?id=8831" --detect-only
--- detection only, no provider was consulted ---
  input                  hxxps[://]secure-billing-update[.]example/portal/verify?id=8831
  type                   url
  confidence             certain
  value                  hxxps[://]secure-billing-update[.]example/portal/verify?id=8831
  refanged_for_lookup    bracketed_dot, bracketed_scheme_separator, hxxp_scheme

notes (2):
  - input was defanged and has been refanged for lookup (bracketed_dot, bracketed_scheme_separator,
hxxp_scheme); the raw form is preserved and is what a report should display
  - redirect chain NOT RESOLVED: expanding a shortener or following a redirect is an active fetch of
the target and HEAD is no exemption (docs/OPSEC.md section 7). A chain can only come from a scan
somebody else already completed
```

Exit code `0` (`2` when nothing could be classified).

### 7b. `check` — classify, then route

Drop `--detect-only` and `check` hands the indicator to the subcommand that investigates it. The
detection block still prints first, so an ambiguous reading is cheap to catch here rather than three
screens further down. A defanged paste is refanged and the transform is announced, never silent.

```
$ tripper-recon check "192[.]88[.]99[.]23"
--- detection only, no provider was consulted ---
  input                  192[.]88[.]99[.]23
  type                   ipv4
  confidence             certain
  value                  192[.]88[.]99[.]23
  refanged_for_lookup    bracketed_dot

notes (1):
  - input was defanged and has been refanged for lookup (bracketed_dot); the raw form is preserved
and is what a report should display

routing to: ip

--- IP lookup for 192[.]88[.]99[.]23 ---
tripper-recon 0.1.0 • 2026-08-09T11:53:10.977838Z • run 20260809T115310Z-a3869d0b
VERDICT: MALICIOUS   score 95 (raw 95.0)   confidence HIGH   6 of 6 providers answered
[... the same panel as §2 ...]
```

Exit code `0`.

### 7c. `bulk` — triage a pasted email, zero quota

Extraction and classification are pure, so the default run makes no request at all: it is safe to
paste an entire phishing email into this command. `--investigate` is the opt-in that spends quota,
hard-capped by `--max-targets` so a pasted mail thread carrying two hundred hosts cannot fan out.

Nothing is deleted. Indicators withheld by the non-public guard or the mail-infrastructure
heuristic get their own table with the reason, because a filter that removes evidence silently is
indistinguishable from evidence that was never there. `--no-filter` turns the mail heuristic off;
the non-public guard stays on.

Input was a pasted mail body containing headers, two defanged URLs, defanged and undefanged
addresses, a SHA-256, two mailboxes, a CIDR and an ASN.

```
$ tripper-recon bulk phish-email.txt

indicators (10) - extracted from pasted text and classified locally; no provider was consulted for
this list
   #    type      indicator                      seen    confidence    note
   1    url       hxxp[://]192[.]88[.]99[.]23       1    certain       arrived defanged - somebody
                  :8080/x                                              already judged this hostile
   2    url       hxxps[://]secure-billing-up       1    certain       arrived defanged - somebody
                  date[.]example/portal/verif                          already judged this hostile
                  y?id=8831
   3    domain    mx1[.]corp[.]example              1    certain
   4    ipv4      192[.]88[.]99[.]23                1    certain       arrived defanged - somebody
                                                                       already judged this hostile
   5    ipv4      192[.]88[.]99[.]77                1    certain
   6    sha256    3f786850e387550fdab836ed7e6       1    certain
                  dc881de23001b4b3c48fea86c1e
                  0a3e6b8f4d
   7    email     billing@secure-billing-upda       1    certain       arrived defanged - somebody
                  te[.]example                                         already judged this hostile
   8    email     help-desk@secure-billing-up       1    certain       arrived defanged - somebody
                  date[.]example                                       already judged this hostile
   9    cidr      192[.]88[.]99[.]0/24              1    certain       ambiguous: also parses as
                                                                       url
  10    asn       AS64500                           1    certain

withheld from triage (4), extracted but not investigated:
  type      indicator                      seen    reason
  domain    mail-out.pphosted.com             1    looks like mail transport infrastructure, not a
                                                   subject of investigation
  domain    mail.protection.outlook.com       1    looks like mail transport infrastructure, not a
                                                   subject of investigation
  ipv4      10.0.0.5                          1    non-public addressing; this tool never forwards
                                                   internal addresses to a third party
  ipv4      192.168.7.31                      1    non-public addressing; this tool never forwards
                                                   internal addresses to a third party
```

Exit code `0` (`2` when no indicator could be extracted).

Ordering is deliberate: URLs first because they are the click that starts the incident, then hosts
and addresses, then hashes, mailboxes, ranges and ASNs as context. Within a type, an indicator that
**arrived already defanged** sorts first — somebody bothered to neuter that one, which is a human
judgement worth surfacing for free.

---

## 8. `-o json`

`-o json` is never defanged: a machine consumes it and `evil[.]example` is not a hostname. The
document is a single JSON object. `-o` may be given before or after the subcommand.

```
$ tripper-recon -o json ip 192.88.99.23
```

The skeleton, with each `data` value replaced by `"..."` here for length:

```json
{
  "ok": true,
  "source_file": null,
  "total": 1,
  "succeeded": 1,
  "failed": 0,
  "results": [
    {
      "target": "192.88.99.23",
      "ok": true,
      "data": {
        "ipinfo": "...",
        "virustotal": "...",
        "shodan": "...",
        "abuseipdb": "...",
        "otx": "...",
        "asn_meta": "...",
        "provider_status": "...",
        "coverage": "...",
        "run": "...",
        "warnings": "...",
        "verdict": "..."
      },
      "warnings": [],
      "errors": [],
      "run": {
        "tool": "tripper-recon",
        "tool_version": "0.1.0",
        "run_id": "20260809T115310Z-a3869d0b",
        "started_at": "2026-08-09T11:53:10.977838Z"
      },
      "coverage": "...",
      "skipped_addresses": []
    }
  ]
}
```

`results[0].data.coverage`, verbatim. This is the counted form of the same accounting the console
prints as `provider_coverage`, and every bucket is a list of names rather than a total, so you can
tell *which* provider is missing and *why*:

```json
{
  "answered": [
    "virustotal",
    "ipinfo",
    "shodan",
    "abuseipdb",
    "otx",
    "cloudflare_asn"
  ],
  "not_found": [],
  "errored": [],
  "unconfigured": [],
  "skipped": [],
  "answered_count": 6,
  "applicable_count": 6,
  "missing": [],
  "ratio": 1.0,
  "is_complete": true,
  "headline": "6 of 6 providers answered"
}
```

`results[0].data.verdict`, verbatim except that eight of the nine `signals` entries and the
`rationale` and `confidence_criteria` arrays are elided for length. This is the object to branch
on — `verdict`, `confidence` and `coverage.ratio` are separate fields precisely so a pipeline
cannot collapse them:

```json
{
  "schema_version": "1.0",
  "indicator": "192.88.99.23",
  "indicator_type": "ip",
  "verdict": "MALICIOUS",
  "score": 95,
  "raw_score": 95.0,
  "score_band": "MALICIOUS",
  "adjusted_from": null,
  "adjustment_reasons": [],
  "confidence": "HIGH",
  "confidence_score": 1.0,
  "coverage": { "...": "as above" },
  "coverage_floor": 0.5,
  "corroborating_families": [
    "multiscanner",
    "abuse_reports",
    "community_ti"
  ],
  "signals": [
    {
      "id": "vt.weighted_detections",
      "provider": "virustotal",
      "family": "multiscanner",
      "direction": "adverse",
      "magnitude": 1.0,
      "points": 35.0,
      "max_points": 35.0,
      "observation": "VirusTotal: 11 of 94 engines adverse (9 malicious, 2 suspicious); weighted 10.00 of 8.00; observed 4 days ago (recency x1.00); no high-confidence engine set is configured, so no single engine hit is decisive",
      "evidence": {
        "malicious_engines": ["BitDefender", "ESET", "Emsisoft", "Fortinet", "G-Data", "Kaspersky", "Netcraft", "Sophos", "Webroot"],
        "suspicious_engines": ["CRDF", "Seclookup"],
        "adverse_engine_count": 11,
        "total_engines": 94,
        "weighted_detections": 10.0,
        "saturation": 8.0,
        "recency_factor": 1.0,
        "analysis_age_days": 4.0000136091666665,
        "high_confidence_hits": [],
        "consensus_threshold": 3,
        "per_engine_results_available": true
      },
      "raw_value": {
        "harmless": 52,
        "malicious": 9,
        "suspicious": 2,
        "undetected": 31,
        "timeout": 0
      },
      "weight_source": "package:tripper_recon.verdict/scoring.yaml#signals.vt.weighted_detections",
      "observed_at": "2026-08-05T11:53:10+00:00",
      "source_url": "https://www.virustotal.com/gui/ip-address/192.88.99.23",
      "ceiling_only": false
    }
  ],
  "contradictions": [],
  "overrides_applied": [
    {
      "rule_id": "escalation.multi_family_corroboration",
      "tier": "escalation",
      "effect": "verdict_forced",
      "source_list": "package:tripper_recon.verdict/scoring.yaml",
      "source_retrieved_at": null,
      "note": "Adverse signals from at least `min_families` independent provider families, each above its own decisiveness threshold. Corroboration across independent families is the one thing a six-provider panel buys that no single provider can."
    }
  ],
  "allowlist": {
    "list_version": "2026-08-08.1",
    "list_retrieved": "2026-08-08",
    "stale": false,
    "staleness_note": "catalogue retrieved 2026-08-08, 1 days old (refresh age 180)"
  },
  "requires_analyst_review": false,
  "attribution_warning": null,
  "summary": "192.88.99.23: MALICIOUS -- score 95/100, confidence HIGH, 6 of 6 providers answered",
  "passive_only": true,
  "active_collection": [],
  "ruleset_version": "0.1.0-draft",
  "ruleset_source": "package:tripper_recon.verdict/scoring.yaml",
  "calibration_statement": "Heuristic. The weights, thresholds and decay constants in this ruleset are informed priors, not measurements. No labelled corpus has been built and no held-out evaluation has been run, so this ruleset carries no precision, recall or accuracy claim of any kind. Verdicts are decision support for an analyst, never a decision.",
  "engine_version": "1.0.0",
  "evaluated_at": "2026-08-09T11:53:11.175832Z"
}
```

`ruleset_version` is stamped into every verdict for a reason: two verdicts produced under different
tunings are different claims, and a verdict pasted into a ticket six months ago has to stay
interpretable.

---

## 9. `--explain`

A verdict an analyst cannot audit is a verdict a SOC learns to ignore. `--explain` prints every
signal, the points it was worth out of its own ceiling, the ruleset key that set that ceiling, the
provider values behind it, and every confidence criterion the engine asked. Console only — `-o json`
already carries all of it.

The excerpt below is the top of the explanation block from `tripper-recon ip 192.88.99.23
--explain`, cut after the second of nine signals:

```
$ tripper-recon ip 192.88.99.23 --explain
[... the verdict summary and coverage lines from §2 ...]

verdict explanation (--explain)
  indicator: 192.88.99.23 (ip)
  score 95 (raw 95.0), band from score alone: MALICIOUS
  signals (9), highest contribution first:
    vt.weighted_detections  [adverse]  virustotal / multiscanner
      points 35.0 of 35.0 (magnitude 1.0000)
      observation: VirusTotal: 11 of 94 engines adverse (9 malicious, 2 suspicious); weighted 10.00
of 8.00; observed 4 days ago (recency x1.00); no high-confidence engine set is configured, so no
single engine hit is decisive
      weight from: package:tripper_recon.verdict/scoring.yaml#signals.vt.weighted_detections
      observed at: 2026-08-05T11:53:10+00:00
        evidence: malicious_engines = ['BitDefender', 'ESET', 'Emsisoft', 'Fortinet', 'G-Data',
'Kaspersky', 'Netcraft', 'Sophos', 'Webroot']
        evidence: suspicious_engines = ['CRDF', 'Seclookup']
        evidence: adverse_engine_count = 11
        evidence: total_engines = 94
        evidence: weighted_detections = 10.0
        evidence: saturation = 8.0
        evidence: recency_factor = 1.0
        evidence: analysis_age_days = 4.000014058078704
        evidence: high_confidence_hits = []
        evidence: consensus_threshold = 3
        evidence: per_engine_results_available = True
      source: https://www.virustotal.com/gui/ip-address/192.88.99.23
    abuseipdb.confidence  [adverse]  abuseipdb / abuse_reports
      points 25.0 of 25.0 (magnitude 1.0000)
      observation: AbuseIPDB: 100% abuse confidence, scaled from a floor of 25% to saturation at
75%; observed 2 days ago (recency x1.00)
      weight from: package:tripper_recon.verdict/scoring.yaml#signals.abuseipdb.confidence
      observed at: 2026-08-07T11:53:10+00:00
        evidence: confidence_score = 100
        evidence: confidence_floor = 25.0
        evidence: confidence_saturation = 75.0
        evidence: recency_factor = 1.0
        evidence: last_reported_age_days = 2.000014058078704
        evidence: reports = 412
      source: https://www.abuseipdb.com/check/192.88.99.23
[... seven more signals: otx.pulse_quality, abuseipdb.volume_recency, vt.community_reputation,
     shodan.exposure, and three zero-point context signals ...]
```

The block ends with the confidence audit and the overrides that were applied:

```
  confidence criteria (score 1.0000 -- a transparency aid, not a probability):
    [x] coverage_floor: 6 of 6 providers answered; ratio 1.0 against floor 0.5
    [x] coverage_high: ratio 1.0 against 0.8 required for HIGH
    [x] corroboration_medium: 3 corroborating famil(ies) against 2 required for MEDIUM
    [x] corroboration_high: 3 corroborating famil(ies) against 2 required for HIGH
    [x] decisive_signal: 5 signal(s) at or above 0.8 of their own ceiling
    [x] no_unresolved_contradiction: 0 unresolved contradiction(s)
    [x] fresh_adverse_evidence: 4 of 5 adverse signal(s) carry a timestamp; freshness window 30 days
  overrides applied (1):
    escalation.multi_family_corroboration: tier escalation, effect verdict_forced, list
package:tripper_recon.verdict/scoring.yaml
      Adverse signals from at least `min_families` independent provider families, each above its own
decisiveness threshold. Corroboration across independent families is the one thing a six-provider
panel buys that no single provider can.
  rationale, in order:
[... every scoring step in order, ending with the override and the calibration statement ...]
```

Two things worth noticing. `shodan.exposure` is marked `[ceiling-only]`: exposed services describe
what a host *is*, not whether it is hostile, so that signal can raise a verdict to `SUSPICIOUS` and
can never contribute to `MALICIOUS`. And the two `asn.*` entries and `abuseipdb.usage_type` carry
`points 0.0 of 0.0` — they are context printed for the reader, deliberately worth nothing.

---

## Exit codes

Automation may rely on these; they are a public interface.

| Code | Meaning |
|:---:|---|
| `0` | The investigation ran and **at least one provider answered**. Not a claim that the indicator is clean, and not a claim that the lookup was complete. Read `coverage` first. |
| `1` | Nothing was learned: an intelligence blackout (§3), a wall-clock deadline breach, a non-public target the tool refuses to forward, or a target the orchestrator rejected. |
| `2` | The input was rejected before any provider was consulted: an unparseable target, a non-numeric ASN, an indicator type no subcommand investigates, or no subcommand at all. |

`check --detect-only` and `bulk` without `--investigate` exit `0` on a successful classification and
`2` when nothing could be classified. Neither constructs an HTTP client.

---

## See also

- [`docs/OPSEC.md`](OPSEC.md) — every outbound destination, the egress allowlist, and the one
  documented active step.
- [`docs/PROVIDERS.md`](PROVIDERS.md) — which provider needs which credential, and which fields each
  one keeps. The answer to "why is my output empty".
- `tripper-recon <subcommand> --help` — the flags, and the provider set each path consults.
