<div align="center">

# Tripper Recon

**A passive OSINT CLI for IP, domain, URL and ASN investigations — that says what it does not know.**

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

</div>

---

## What this is

An async command-line tool that asks third-party intelligence providers what they already know
about an indicator, adjudicates their answers into one verdict, and shows you how much of the
panel actually answered.

**It never touches the target.** Every request goes to a provider that already holds the data.
There is no port scan, no banner grab, no HTTP request to the target, no redirect following, no
shortener expansion, and no submission of a URL to a scanner that would load it. That constraint
is enforced at runtime, not just intended — see [OPSEC and passivity](#opsec-and-passivity).

Two design rules run through the whole tool:

- **Absent data never scores as clean.** A provider with no API key is missing coverage, not an
  excuse. It is counted in the denominator and never in the numerator, and it renders as
  `no data - not configured, no API key`, never as a green zero.
- **The verdict and the confidence are separate axes.** "Score 71, confidence LOW, 2 of 6
  providers answered" is a real state, and the tool prints all three parts of it.

> **Status: alpha, and under active hardening.** The verdict engine's weights are **unvalidated
> priors** — no labelled corpus exists and the tool makes **no accuracy claim of any kind**. The
> sequenced hardening plan, with a defect list and `file:line` evidence, is in
> [`docs/ROADMAP.md`](docs/ROADMAP.md); the audits behind it are in [`docs/review/`](docs/review/).
> Read [Known limitations](#known-limitations) before you rely on output for a decision.

---

## Install

Requires **Python 3.10+**.

```bash
git clone https://github.com/FancyP4nda/tripper_recon.git
cd tripper_recon

# conda (the environment this is developed against)
conda create -n tripper python=3.12 && conda activate tripper

pip install .            # or: pip install -e ".[dev]" for the test/lint toolchain
```

Runtime dependencies: `httpx[http2]`, `pydantic`, `python-dotenv`, `pyyaml`, `rich`
([`pyproject.toml`](pyproject.toml)).

**No configuration is required to try it.** Six providers need no key at all, so
`tripper-recon asn 15169` works against a completely empty `.env` — and the `ip` and `domain`
paths still consult Shodan InternetDB, RDAP and Tranco without one.

---

## The seven subcommands

| Command | What it does | Provider quota |
|---|---|---|
| `ip <addr\|file>` | One address, or a file of addresses processed concurrently | 8 providers per address |
| `domain <name>` | The name itself, then each public address it resolves to | 5 at the domain level, then 8 per address |
| `url <link>` | The link, then optionally its host and that host's addresses | 2 at the URL level, plus the depths you ask for |
| `asn <number>` | Routing, peering, prefixes, registry and rank | 11 declared providers, 8 of which need no key |
| `check <anything>` | Classify a pasted string and route it to the right lookup | routes; `--detect-only` costs **zero** |
| `bulk [file\|-\|text]` | Extract and triage every indicator in a wall of pasted text | **zero** unless you pass `--investigate` |
| `report --from-case <dir>` | Rebuild a report from a saved case directory | **zero** — it contacts nobody |

### Worked examples

```bash
# An address. Eight providers in one wave.
tripper-recon ip 8.8.8.8

# A file of addresses: one per line, '#' comments skipped, duplicates collapsed.
tripper-recon ip ./suspicious_ips.txt

# A domain. Resolves it, then enriches each PUBLIC address it got back.
tripper-recon domain example.com

# An ASN. No API key needed for this one.
tripper-recon asn 15169
tripper-recon asn AS15169 --neighbors 4
tripper-recon asn 15169 --prefixes-out as15169.txt --prefixes v4

# A URL. --depth controls how far it pivots, and it is a passivity control:
#   url  = the link's own report        (resolves nothing)
#   host = plus the host's reputation   (resolves nothing)
#   full = plus the host's addresses    (this is the depth that resolves) - the default
tripper-recon url 'https://example.com/login' --depth host

# One verb for a string of unknown shape, pasted under pressure. Defanged input is fine.
tripper-recon check 'hxxps://secure-login-update[.]example/verify?id=8842'

# Classify and stop. Zero quota: detection is a pure function over the string.
tripper-recon check 45.33.32.156 --detect-only

# Triage a whole phishing email. Zero quota by default; nothing is deleted, only withheld.
tripper-recon bulk ./message.eml
cat message.eml | tripper-recon bulk -
tripper-recon bulk ./message.eml --investigate --max-targets 5

# Show every weight, its ruleset key and its evidence behind the verdict.
tripper-recon ip 8.8.8.8 --explain

# Machine output. Never defanged, and structured logs go to stderr so this pipes cleanly.
tripper-recon ip targets.txt -o json | jq '.results[].data.verdict.verdict'

# The form you paste into a ticket: ATX headings and pipe tables, no ANSI, no box drawing.
tripper-recon ip 8.8.8.8 -o markdown

# Answer from cache only. Contacts nobody at all -- not a provider, not the resolver.
tripper-recon --offline domain evil.example

# Demand freshness, save everything, and keep the raw provider exchanges.
tripper-recon --max-age 15m ip 8.8.8.8 -o markdown --case-dir ./cases --evidence

# Rebuild that report weeks later. No quota, no network, and the ORIGINAL timestamps.
tripper-recon report --from-case ./cases/ip-<case id>/<run id>
```

`-o` / `--format` works in either position — `tripper-recon -o json ip 8.8.8.8` and
`tripper-recon ip 8.8.8.8 -o json` are equivalent. `--rate-limit`, `--user-agent`, `--fanged`,
`--offline`, `--max-age`, `--no-cache`, `--cache-dir` and `-V` are top-level only and must come
**before** the subcommand. `--out`, `--case-dir` and `--evidence` are per-subcommand and come
after it.

### Output formats

| `-o` | For | Notes |
|---|---|---|
| `console` (default) | Reading now | `rich` tables and colour. **Colour is stripped the moment you redirect it**, which takes the malice signal with it — so do not redirect this into a file |
| `json` | A machine | Never defanged. Carries everything, including `freshness` and per-provider `cache` blocks |
| `markdown` | A ticket | ATX headings and GFM pipe tables only; no HTML, no box drawing. Defanged by default. Every provider-controlled value is escaped, so a pasted string containing `\|` or `#` cannot break the table or inject a heading |

### Defanging

Human-facing output brackets indicators by default (`8[.]8[.]8[.]8`, `hxxps[://]…`) because a
recon report gets pasted into tickets and chat, where a live link is one click from a compromise
and — for a single-use link — one click from burning the investigation. `--fanged` turns it off.
Third-party pivot links are never defanged: they point at VirusTotal, Shodan, AbuseIPDB and
Cloudflare Radar, and being clickable is the point of them. **`-o json` is never defanged**, in
either mode, because a machine consumes it and `evil[.]example` is not a hostname.

---

## What the output looks like

> Every block below is real rendered output, captured with the provider responses mocked
> (`respx`) rather than by querying anyone. The provider payloads are synthetic; the rendering,
> the scoring and the coverage arithmetic are the code's own.
>
> **Captured before the provider panel widened, and not yet re-captured.** Shodan InternetDB,
> RDAP, Tranco and abuse.ch were wired in on 2026-08-09, taking the `ip` scope from six providers
> to eight and the `domain` scope from two to five. The denominators in the blocks below —
> "5 of 6", "0 of 6" — are therefore the old panel. The shapes, the wording and the arithmetic
> rules are current; the numbers are one release behind. Re-rendering them is outstanding work,
> and inventing corrected output by hand would be worse than saying so.

### An address the allowlist recognises, with one provider unconfigured

```text
--- IP lookup for 8[.]8[.]8[.]8 ---
tripper-recon 0.1.0 • 2026-08-09T11:52:07.529912Z • run 20260809T115207Z-304027f3
VERDICT: KNOWN_INFRASTRUCTURE   score 0 (raw 0.0)   confidence MEDIUM   5 of 6 providers answered
  not answered: cloudflare_asn
  why:
    - VirusTotal: 0 of 94 engines flagged this indicator; observed 2 days ago (recency x1.00). An
    answer, not an absence
    - AbuseIPDB was asked and holds no abuse reports for this address within the provider's 365-day
    reporting window
    - OTX was asked and holds no pulses referencing this indicator
  collection: passive only - no traffic was sent to the target or its infrastructure
  allowlist 2026-08-08.1 retrieved 2026-08-08 - matched allowlist data retrieved 2026-08-08, 1 days
  old (refresh age 180)
  ruleset 0.1.0-draft (package:tripper_recon.verdict/scoring.yaml) • engine 1.0.0 • evaluated
  2026-08-09T11:52:07.615702Z
  calibration: Heuristic. The weights, thresholds and decay constants in this ruleset are informed
  priors, not measurements. No labelled corpus has been built and no held-out evaluation has been
  run, so this ruleset carries no precision, recall or accuracy claim of any kind. Verdicts are
  decision support for an analyst, never a decision.
provider_coverage: 5 of 6 providers answered
  never asked - no API key configured: cloudflare_asn
  ip                              8[.]8[.]8[.]8
  virustotal_detections           0/94
  virustotal_last_analysis        2026-08-07T06:12:00+00:00
  virustotal_community_score      512
  virustotal_analysis_link        https://www.virustotal.com/gui/ip-address/8.8.8.8
  abuseipdb_reports               0
  abuseipdb_distinct_reporters    0
  abuseipdb_confidence_score      0%
  abuseipdb_last_reported         unknown - provider supplied no date
  abuseipdb_whitelisted           yes - AbuseIPDB lists this address as whitelisted
  abuseipdb_analysis_link         https://www.abuseipdb.com/check/8.8.8.8
  otx_pulse_count                 0
  otx_pulse_link                  https://otx.alienvault.com/indicator/ip/8.8.8.8
  open_ports                      53, 443
  shodan_last_update              2026-07-30T11:04:22.000000
  shodan_hostnames                dns[.]google
  shodan_link                     https://www.shodan.io/host/8.8.8.8
  isp                             AS15169 Google LLC
  organization                    AS15169 Google LLC
  cloudflare_radar_link           https://radar.cloudflare.com/ip/8.8.8.8
  geolocation                     IPinfo registry data - context, not evidence
  city                            Mountain View
  country                         US
  coordinates                     37.4056, -122.0775
  postal_code                     94043
```

`KNOWN_INFRASTRUCTURE` is the one label that means "this is fine", and it is only reachable from a
curated Tier A allowlist entry with a citation and a retrieval date — never from a low score. The
allowlist line records which list answered and how old it was.

### Adverse evidence on a domain

Name reserved for documentation (RFC 2606 `.example`), provider payloads mocked:

```text
--- Domain lookup for secure-login-update[.]example ---
tripper-recon 0.1.0 • 2026-08-09T11:51:53.917222Z • run 20260809T115153Z-34be2bdd
VERDICT: SUSPICIOUS   score 64 (raw 64.0)   confidence HIGH   2 of 2 providers answered
  why:
    - +35.0 of 35.0  vt.weighted_detections: VirusTotal: 14 of 94 engines adverse (11 malicious, 3
    suspicious); weighted 12.50 of 8.00; observed 2 days ago (recency x1.00); no high-confidence
    engine set is configured, so no single engine hit is decisive
    - +15.0 of 15.0  otx.pulse_quality: OTX: 3 pulses reported, 3.00 effective after
    author-diversity, recency and duplicate-title adjustment
    - +5.0 of 5.0  vt.community_reputation: VirusTotal community score -34. Crowd-sourced, gameable
    and unversioned, so this is directional colour and scores as a flag, not a curve
    and 2 more scoring signal(s); run with --explain for the full breakdown
  collection: passive only - no traffic was sent to the target or its infrastructure
  ruleset 0.1.0-draft (package:tripper_recon.verdict/scoring.yaml) • engine 1.0.0 • evaluated
  2026-08-09T11:51:53.948138Z
  calibration: Heuristic. The weights, thresholds and decay constants in this ruleset are informed
  priors, not measurements. No labelled corpus has been built and no held-out evaluation has been
  run, so this ruleset carries no precision, recall or accuracy claim of any kind. Verdicts are
  decision support for an analyst, never a decision.
provider_coverage: 2 of 2 providers answered
```

The domain and each of its addresses are scored **separately and never merged**: a phishing kit on
a CDN is a malicious domain on a shared address, and both statements have to survive to the screen.

`--explain` prints the full audit trail — every signal, its points against its own ceiling, the
ruleset key that set the weight, the provider values behind it, and every confidence criterion the
engine asked:

```text
verdict explanation (--explain)
  indicator: secure-login-update.example (domain)
  score 64 (raw 64.0), band from score alone: SUSPICIOUS
  signals (5), highest contribution first:
    vt.weighted_detections  [adverse]  virustotal / multiscanner
      points 35.0 of 35.0 (magnitude 1.0000)
      observation: VirusTotal: 14 of 94 engines adverse (11 malicious, 3 suspicious); weighted 12.50
of 8.00; observed 2 days ago (recency x1.00); no high-confidence engine set is configured, so no
single engine hit is decisive
      weight from: package:tripper_recon.verdict/scoring.yaml#signals.vt.weighted_detections
      observed at: 2026-08-07T11:54:41+00:00
        evidence: adverse_engine_count = 14
        evidence: total_engines = 94
        evidence: weighted_detections = 12.5
        evidence: saturation = 8.0
        evidence: recency_factor = 1.0
        evidence: consensus_threshold = 3
```

### No keys configured — the most common first run

**This claim has changed and the block below is the old behaviour.** It used to be true that a
keyless `ip` run made **zero** HTTP requests, because every IP-scope provider returned its
missing-key envelope before issuing one. That stopped being true on 2026-08-09: Shodan InternetDB
and RDAP take no credential, so a keyless run now contacts `internetdb.shodan.io` and
`data.iana.org` — a keyless run is cheaper, not silent. See [`docs/OPSEC.md`](docs/OPSEC.md)
section 4. The verdict logic the block illustrates is unchanged: absent data is
`INSUFFICIENT_DATA`, never `NO_ADVERSE_FINDINGS`.

```text
--- IP lookup for 45[.]33[.]32[.]156 ---
VERDICT: INSUFFICIENT_DATA   score 0 (raw 0.0)   confidence LOW   0 of 6 providers answered
  ! INSUFFICIENT_DATA rather than NO_ADVERSE_FINDINGS: 0 of 6 providers answered, below the 0.5
  coverage floor. Absent data is not a clean result
  not answered: virustotal, ipinfo, shodan, abuseipdb, otx, cloudflare_asn
  collection: passive only - no traffic was sent to the target or its infrastructure
provider_coverage: 0 of 6 providers answered
  never asked - no API key configured: virustotal, ipinfo, shodan, abuseipdb, otx
  never asked - skipped: cloudflare_asn
  ip                            45[.]33[.]32[.]156
  virustotal_detections         no data - not configured, no API key
  abuseipdb_confidence_score    no data - not configured, no API key
  abuseipdb_analysis_link       https://www.abuseipdb.com/check/45.33.32.156
  otx_pulse_count               no data - not configured, no API key
  otx_pulse_link                https://otx.alienvault.com/indicator/ip/45.33.32.156
  open_ports                    no data - not configured, no API key
```

The run exits `1` with `no provider answered … this is an intelligence blackout, not a clean
result`.

### `asn 15169` on an empty `.env`

```text
--- ASN lookup for AS15169 (GOOGLE, US) ---
tripper-recon 0.1.0 • 2026-08-09T11:50:36.321878Z • run 20260809T115036Z-3e2b8955
provider_coverage: 7 of 10 providers answered
  never asked - no API key configured: ipinfo_asn, cloudflare_bgp, cloudflare_asn
  AS Number        ──>    15169
  AS Name          ──>    GOOGLE, US
  CAIDA AS Rank    ──>    #5
  Abuse contact    ──>    network-abuse@google.com
  RIR (Region)     ──>    ARIN (USA, Canada, many Caribbean and North Atlantic islands)
  Peering @IXPs    ──>    AMS-IX • DE-CIX Frankfurt • Equinix Ashburn • LINX LON1

--- BGP informations for AS15169 ---
  BGP Neighbors        1104 (4 Transits • 1070 Peers • 30 Customers)
  Customer cone        51 (# of ASNs observed in the customer cone)
  In-depth BGP info    https://radar.cloudflare.com/routing/as15169?dateRange=52w

--- Prefix informations for AS15169 ---
  IPv4 Prefixes announced    1052
  IPv6 Prefixes announced    116

--- Peering informations for AS15169 ---
  Upstream      COGENT-174, US (174)  LEVEL3, US (3356)  NTT-LTD-2914, US (2914)
  Downstream    HURRICANE, US (6939)
  Uncertain     NONE
```

### Zero-quota triage of a pasted email

`bulk` extraction and classification are pure functions over the string — no I/O, no client, no
request. It is safe to paste an entire hostile email into it:

```text
indicators (7) - extracted from pasted text and classified locally; no provider was consulted for
this list
  #    type      indicator                       seen    confidence    note
  1    url       hxxps[://]secure-login-updat       1    certain       arrived defanged - somebody
                 e[.]example/verify?id=8842                            already judged this hostile
  2    domain    mx[.]corp[.]example                1    certain
  3    ipv4      45[.]33[.]32[.]156                 1    certain       arrived defanged - somebody
                                                                       already judged this hostile
  4    ipv4      67[.]231[.]153[.]30                1    certain
  5    sha256    9f2b4c1d7e6a3b8c5d0e9f1a2b3c       1    certain
                 4d5e6f7a8b9c0d1e2f3a4b5c6d7e
                 8f9a0b1c
  6    email     it-helpdesk@corp[.]example         1    certain       no provider here
                                                                       investigates mailboxes;
                                                                       investigate the domain to
                                                                       the right of the @
  7    asn       AS15169                            1    certain

withheld from triage (2), extracted but not investigated:
  type      indicator                seen    reason
  domain    mail-out.pphosted.com       1    looks like mail transport infrastructure, not a
                                             subject of investigation
  ipv4      10.14.7.22                  1    non-public addressing; this tool never forwards
                                             internal addresses to a third party
```

Nothing is deleted. Anything the RFC1918 guard or the mail-infrastructure heuristic holds back is
printed in its own table with the reason, because a filter that removes evidence silently is
indistinguishable from evidence that was never there. `--no-filter` disables the mail-infrastructure
heuristic; the non-public guard is not optional.

### JSON

`-o json` carries the whole verdict record, so a verdict pasted into a ticket six months ago stays
interpretable:

```json
{
  "schema_version": "1.0",
  "indicator": "8.8.8.8",
  "indicator_type": "ip",
  "verdict": "KNOWN_INFRASTRUCTURE",
  "score": 0,
  "raw_score": 0.0,
  "score_band": "NO_ADVERSE_FINDINGS",
  "confidence": "MEDIUM",
  "confidence_score": 0.7143,
  "confidence_criteria": [
    { "name": "coverage_floor", "met": true,
      "detail": "5 of 6 providers answered; ratio 0.8333 against floor 0.5" },
    { "name": "corroboration_high", "met": true,
      "detail": "3 corroborating famil(ies) against 2 required for HIGH" },
    { "name": "decisive_signal", "met": false,
      "detail": "0 signal(s) at or above 0.8 of their own ceiling" }
  ],
  "coverage": {
    "answered": ["virustotal", "ipinfo", "shodan", "abuseipdb", "otx"],
    "errored": [], "unconfigured": ["cloudflare_asn"], "skipped": [],
    "answered_count": 5, "applicable_count": 6,
    "missing": ["cloudflare_asn"], "ratio": 0.8333,
    "is_complete": false, "headline": "5 of 6 providers answered"
  },
  "coverage_floor": 0.5,
  "corroborating_families": ["multiscanner", "abuse_reports", "community_ti"],
  "passive_only": true,
  "active_collection": [],
  "ruleset_version": "0.1.0-draft",
  "calibration_statement": "Heuristic. …no precision, recall or accuracy claim of any kind…"
}
```

---

## The verdict engine

Five states, and the clean one is deliberately not called `BENIGN`:

| Verdict | Meaning |
|---|---|
| `MALICIOUS` | Adverse evidence reaching the top band |
| `SUSPICIOUS` | Adverse evidence below that band, or a top-band call the panel cannot stand behind |
| `NO_ADVERSE_FINDINGS` | Coverage cleared the floor, a provider was asked and answered, and nothing adverse was reported. **Not** "benign" — six feeds agreeing they have never seen an indicator is exactly what a purpose-built C2 domain looks like on its first day |
| `INSUFFICIENT_DATA` | Coverage below the floor. Nothing was learned |
| `KNOWN_INFRASTRUCTURE` | A Tier A allowlist entry matched. The only label that means "this is fine", and it is unreachable without a curated entry behind it |

Structural rules enforced on the record itself, not left to the scoring code:

- `NO_ADVERSE_FINDINGS` is rejected without coverage above the floor **and** an affirmative
  negative among the signals **and** no adverse points. A failed call, a missing key and a 404 are
  not evidence of cleanliness.
- `KNOWN_INFRASTRUCTURE` is rejected without a Tier A override record with a citation.
- `MALICIOUS` at `LOW` confidence is rejected unless flagged for analyst review.
- **Contradictions are surfaced, never averaged.** Averaging VirusTotal's five detections with
  AbuseIPDB's 0% produces a number describing neither provider and destroys the one fact that
  directs the next step: that the panel is split, and which way each half points.
- **Corroboration counts provider families, not providers.** Two feeds re-ingesting one upstream
  is one observation wearing two hats.
- **No single provider family can reach `MALICIOUS` alone.** The band sits at 70 points and the
  largest single signal at full saturation is worth 35, so corroboration is structural rather than
  advisory — and a validator enforces it against a retuned ruleset.

Every tunable — weights, thresholds, bands, decay constants, the allowlist — lives in
[`tripper_recon/verdict/scoring.yaml`](tripper_recon/verdict/scoring.yaml) and
[`known_infrastructure.yaml`](tripper_recon/verdict/known_infrastructure.yaml), versioned and
stamped into every verdict. Point `TRIPPER_RECON_SCORING_CONFIG` at your own file, or drop one at
`$XDG_CONFIG_HOME/tripper_recon/scoring.yaml`, to retune without touching code.

**The weights are unvalidated priors.** `calibration.status` is `unvalidated`, no labelled corpus
exists, no held-out evaluation has been run, and the ruleset therefore carries no precision, recall
or accuracy figure. That statement travels inside every verdict rather than living only here.

---

## Providers

Detail per provider — endpoints, fields kept, fields discarded — is in
[`docs/PROVIDERS.md`](docs/PROVIDERS.md).

### No API key required

| Provider | Used by | What it gives |
|---|---|---|
| [RIPEstat](https://stat.ripe.net/) | `asn` | AS overview, abuse contact, routing status, neighbours, announced prefixes |
| [CAIDA AS-Rank](https://asrank.caida.org/) | `asn` | AS rank, customer cone, transit/peer/customer degree |
| [PeeringDB](https://www.peeringdb.com/) | `asn` | IXP presence |
| [Shodan InternetDB](https://internetdb.shodan.io/) | `ip` | Open ports, hostnames, tags, CPEs **and CVEs** — the keyless fallback for the Shodan slot, used when `SHODAN_API_KEY` is unset |
| [RDAP](https://www.rfc-editor.org/rfc/rfc9224) | `ip`, `domain`, `asn` | Registration date, registrar, abuse contact, EPP status, nameservers, DNSSEC — read from the registry that holds the record. **See the caveat below** |
| [Tranco](https://tranco-list.eu/) | `domain` | Popularity rank and its steadiness. A false-positive **suppressor**: it can lower suspicion and can never raise it |

**`tripper-recon asn 15169` runs on RIPEstat, CAIDA and PeeringDB alone, against an empty `.env`.**
They cover seven of the eleven declared ASN providers — RIPEstat contributes five endpoints — so
the run reports `7 of 11 providers answered` and names the ones it could not ask.

> **RDAP answers UNKNOWN today, by design, and it is worth understanding why before you rely on
> it.** RDAP has no single endpoint: a client finds the authoritative registry through IANA's
> bootstrap files (RFC 9224), so the final host is chosen at runtime. This tool refuses to contact
> a host nobody reviewed, and no registry host is on the egress allowlist yet — so every RDAP
> lookup reports `registry_not_allowlisted`, which is **unknown, never clean**, and shows up as
> missing coverage. Adding registry hosts is a deliberate review step, not a code change:
> [`docs/OPSEC.md`](docs/OPSEC.md) section 2 and section 6 gap 9.

### API key required

| Provider | Env var | Used by | What it gives |
|---|---|---|---|
| [VirusTotal v3](https://www.virustotal.com/) | `VT_API_KEY` | `ip`, `domain`, `url` | Per-engine detections, reputation, categories, tags, passive DNS records, whois (domain age is parsed out of it), HTTPS certificate and JARM |
| [Shodan](https://www.shodan.io/) | `SHODAN_API_KEY` | `ip` | Open ports, hostnames, tags, CPEs, CVEs, last-update timestamp |
| [AbuseIPDB](https://www.abuseipdb.com/) | `ABUSEIPDB_API_KEY` | `ip` | Abuse confidence, report counts, last-reported date, usage type, Tor flag (365-day window) |
| [IPinfo](https://ipinfo.io/) | `IPINFO_TOKEN` | `ip`, `asn` | Geolocation and network ownership |
| [AlienVault OTX](https://otx.alienvault.com/) | `OTX_API_KEY` | `ip`, `domain` | Pulse counts, titles, authors, dates |
| [Cloudflare Radar](https://radar.cloudflare.com/) | `CLOUDFLARE_API_TOKEN` | `ip`, `asn` | ASN metadata, registry, IXPs |
| Cloudflare BGP | same token | `asn` | BGP hijack and leak incident counts |
| [abuse.ch](https://abuse.ch/) URLhaus + ThreatFox | `ABUSECH_AUTH_KEY` | `ip`, `domain`, `url` | Malware-distribution URLs with the retrieved payload's hash, and actor/malware-family attributed IOCs. One free Auth-Key covers both platforms |

> **abuse.ch carries an accepted terms-of-service exposure**, decided 2026-08-09 and recorded
> rather than mitigated: their terms prohibit automated access by "robot, bot, spider, scraper",
> and `bulk --investigate` is arguably that. The decision, the exact clauses and the counter-reading
> are in [`docs/OPSEC.md`](docs/OPSEC.md) section 4a. Nothing about it touches the passive boundary
> — abuse.ch never contacts the target.

Providers used per scope: `ip` intends eight, `domain` intends five at the name level and then
eight per resolved address, `url` intends two at the link level plus the depths you request, `asn`
intends eleven. Those declared sets are the denominator of every "N of M answered" line — the tool
never shrinks the denominator to the providers that happened to be configured.

A [urlscan.io](https://urlscan.io/) provider (search and result reads only — never submission)
is implemented and tested, but **no orchestrator calls it yet**. It is not a source of output today.

---

## Configuration

Create a `.env` in the project root (it is gitignored; `.env.example` is a starting point):

```ini
# Provider credentials. Every one is optional; an unset key means that provider is
# counted as missing coverage, never as a clean answer.
VT_API_KEY=
SHODAN_API_KEY=
ABUSEIPDB_API_KEY=
IPINFO_TOKEN=
OTX_API_KEY=
CLOUDFLARE_API_TOKEN=
# One free key from https://auth.abuse.ch/ covers both URLhaus and ThreatFox.
# Read docs/OPSEC.md section 4a before turning this on: the terms-of-service exposure
# is an accepted risk, not an absent one.
ABUSECH_AUTH_KEY=

# Behaviour
# Log level: a number (10=DEBUG, 20=INFO, 30=WARN, 40=ERROR) or a name (DEBUG/INFO/WARN/ERROR).
TRIPPER_RECON_LOG_LEVEL=20
# User-Agent sent to providers. Defaults to `tripper-recon/<version>`.
TRIPPER_RECON_USER_AGENT=

# Verdict tuning (optional). Point these at your own YAML to override the packaged defaults.
TRIPPER_RECON_SCORING_CONFIG=
TRIPPER_RECON_KNOWN_INFRASTRUCTURE=

# Cache (optional).
# Where cached provider answers live. Defaults to $XDG_CACHE_HOME/tripper_recon.
TRIPPER_RECON_CACHE_DIR=
# A per-provider TTL ruleset to load instead of the packaged cache.yaml. A path that
# does not exist is an error, never a silent fallback to a different policy.
TRIPPER_RECON_CACHE_CONFIG=
```

`.env` is read from the current directory first, then the project root, and never overrides a
variable already exported in your shell.

Runtime flags: `--rate-limit N` sets the process-wide ceiling on concurrent in-flight provider
requests (default 10). `--user-agent` overrides the User-Agent for the run. Each target gets a
180-second wall-clock deadline, and a domain enriches at most 8 addresses concurrently.

---

## Caching, freshness, and saving a report

A domain with eight A records costs nine VirusTotal calls per run, and re-running the same
investigation an hour later pays for it again. So provider answers are cached on disk with a
per-provider lifetime — days for registration data, minutes for reputation feeds and DNS. The
lifetimes are policy rather than code and live in `tripper_recon/utils/cache.yaml`.

**The rule that makes the cache safe to ship: a cached fact never claims to have been queried
now.** A report that presents a three-week-old answer as a fresh lookup is worse than no report,
because it launders staleness into apparent currency. So:

* every cached value carries the instant it was **actually** obtained, and that instant is never
  rewritten on replay;
* every replay is disclosed in three places — the **first console warning**,
  `provider_status[<name>].cache` in `-o json`, and the `freshness` block, which states how many
  answers were queried now, how many were replayed, and how old the oldest one is;
* only successful answers are cached. A 429 or an unset key is a state of the world at one
  instant, and replaying it would outlive its cause;
* an entry that cannot be dated — unreadable timestamp, unknown schema, or a stamp **in the
  future** because a clock is wrong — is discarded rather than served.

| Flag | Effect |
|---|---|
| `--offline` | Contact nobody at all, including the system resolver. A question the cache cannot answer is reported as **missing coverage with the reason**, never served from an expired entry |
| `--max-age D` | Refuse anything cached older than `D` (`30`, `90s`, `15m`, `6h`, `7d`, `2w`). Online this forces a fresh lookup; offline it turns a stale entry into a stated gap. `--max-age 0` means "query everything now" |
| `--no-cache` | Read nothing and write nothing. Every answer is queried now |
| `--cache-dir DIR` | Where cached answers live. Outside the repository by default |
| `--out PATH` | Write the report to `PATH`. `-o json` writes JSON; `console` and `markdown` both write Markdown, because console output is ANSI-decorated and is not a document. A bare filename lands in `./outputs/` |
| `--case-dir DIR` | Save the whole run — `case.json`, `report.md`, and the evidence envelopes — so the report can be regenerated later without re-querying. Defaults to `./outputs/cases` |
| `--evidence` | Also capture the raw provider exchanges: status, timings, hashes and redacted bodies. **Requires `--case-dir`** |

`--offline` with `--no-cache` is refused at parse time rather than obeyed: it would consult nobody
and serve nothing, producing a run that cannot answer anything and looks, from the exit code, like
a total intelligence blackout.

**Evidence files hold provider responses and live on your disk.** Credentials cannot reach them —
request headers are captured by allowlist so an auth header is never recorded at all, and URLs and
bodies are redacted — but the contents are still intelligence about a live case. The default
locations keep them out of git: the cache sits outside the repository entirely, and case
directories default under `outputs/`, which `.gitignore` ignores as a directory. A custom
`--case-dir` carries no such guarantee, and the case record says which of the two it was. See
`docs/OPSEC.md` §5a.

### Exit codes

These are a public interface; a playbook may branch on them.

| Code | Meaning |
|---|---|
| `0` | The investigation ran and at least one provider answered. **Not** a claim that the indicator is clean, and **not** a claim that the lookup was complete — read the coverage line |
| `1` | Nothing was learned: an intelligence blackout, a deadline breach, a non-public target the tool refuses to forward, or a target the orchestrator rejected. **Also**: the run completed but an artefact you asked for (`--out`, `--case-dir`) could not be written — exiting `0` there would leave a pipeline believing it holds a report it does not hold |
| `2` | The CLI rejected the input before any provider was consulted: unparseable target, non-numeric ASN, an indicator type no subcommand investigates, or no subcommand |

**The exit code is not the verdict.** A `MALICIOUS` indicator with every provider answering exits
`0`. Branch on `data.verdict.verdict` in `-o json` instead. `check --detect-only` and `bulk`
without `--investigate` exit `0` on a successful classification and `2` when nothing could be
classified — and neither constructs an HTTP client at all.

---

## OPSEC and passivity

Full detail, per provider and per subcommand, with `file:line` evidence, is in
[`docs/OPSEC.md`](docs/OPSEC.md). The short version:

- **All intelligence comes from third parties that already hold it.** No scan, no connect, no fetch
  of the target, no redirect resolution, no shortener expansion, no scanner submission.
- **The boundary is enforced twice.** A runtime egress allowlist
  ([`utils/http.py`](tripper_recon/utils/http.py)) inspects the URL of every request as an httpx
  event hook and raises `PassiveBoundaryViolation` for any host not on the ten-entry list —
  **before a socket opens**. A static gate (`tests/test_passivity.py`) scans the package for URL
  literals and forbidden endpoints and fails the build. The static scan is blind to a host
  assembled at runtime; the hook catches exactly that. Neither replaces the other.
- **One documented exception: system DNS.** `domain <name>` and `url … --depth full` call
  `socket.getaddrinfo()` on the target. Your recursive resolver walks the delegation chain and
  queries **the nameserver the target operator controls**, which for a live actor watching their
  own DNS logs is a tell. This is an **accepted, documented risk, not a bug** — there is no
  opt-out flag. If resolver egress is the risk you are managing, use `--depth url` or
  `--depth host` (neither resolves anything), or investigate the addresses directly with `ip`.
- **Passive does not mean invisible.** Every query is attributable to your API key. A VirusTotal
  lookup under your key is logged against your account, and the provider learns your egress IP and
  your indicator list.
- **Internal addressing is never forwarded.** Private, reserved, loopback, link-local, multicast
  and unspecified addresses are refused on every path that would otherwise send them to a vendor
  under your keys — including a URL whose host is one, and a domain that resolves to one. Refused
  addresses are counted and named in the report, not silently dropped.
- **Every verdict states its collection mode** (`passive_only`, `active_collection[]`), so an
  analyst can see which kind of artifact they are holding before it goes into a report.

---

## Known limitations

Read these before you trust an answer. Each is tracked in [`docs/ROADMAP.md`](docs/ROADMAP.md).

| Limitation | Effect |
|---|---|
| **The verdict weights are unvalidated priors.** | No labelled corpus, no held-out evaluation, no accuracy claim. Treat a verdict as ordered decision support, never as a decision. The recording harness that would produce a corpus is designed but not built (roadmap W5.9) |
| **`--depth full` and `domain` resolve the target through your system resolver.** | An accepted, documented risk with no opt-out flag. See OPSEC above and `docs/OPSEC.md` §3 |
| **No verdict on the `asn` path.** | Only `ip`, `domain` and `url` are adjudicated. The ASN report carries no reputation signal at all — Spamhaus DROP/ASN-DROP would be the fix (roadmap 8.6) |
| **The domain level has only two providers.** | VirusTotal and OTX. There is no RDAP/registrar source, so registrar abuse contact is unavailable and domain age is parsed out of whatever whois text VirusTotal happens to return — when it cannot be read, the signal scores an explicit "age unknown is not age fine" weight rather than nothing (roadmap 8.2) |
| **No result caching and no `--offline`.** | Every run re-queries every provider. A domain with eight A records costs nine VirusTotal calls per run (roadmap 7.7) |
| **No per-provider rate budget.** | One process-wide concurrency ceiling. A semaphore cannot express "4 requests per minute", so a bulk run can still breach a published quota (roadmap 3.4) |
| **Retry policy is uneven across providers.** | VirusTotal, Shodan, AbuseIPDB, IPinfo and OTX raise on a bad status, so a `429` or `5xx` is retried with backoff and a server-supplied `Retry-After` is honoured (clamped to 60s). RIPEstat, CAIDA, PeeringDB and both Cloudflare providers return an error payload on any non-2xx instead, so a transient `502` from them is never retried — it just becomes a missing provider in the coverage line |
| **No markdown output.** | `-o` accepts `console` and `json` only. The four-line block an analyst pastes into a ticket does not exist yet (roadmap 7.2) |
| **No `--fail-on`.** | The verdict cannot be folded into the exit code. Automation that wants to branch on maliciousness must parse `-o json` |
| **`--prefixes-out` with a bare filename writes package-relative.** | It resolves against the installed package directory, so after `pip install .` it lands in `site-packages/outputs/`. Pass a path with a directory component. There is no `--out` for `ip`, `domain` or `url` at all (roadmap 7.3) |
| **No registrar/whois enrichment on the `asn` path.** | The `--enrich` placeholder flag that advertised it was removed rather than left promising a capability the tool lacks (roadmap 9.11). No whois or pWhois call exists anywhere in the codebase |
| **No colour flag.** | Colour is controlled by `rich`, which honours `NO_COLOR` and disables styling when output is not a TTY. The dead `--monochrome` flag was removed (roadmap 9.11) |
| **urlscan.io is implemented but not wired in.** | The provider module and its allowlist entry exist; no orchestrator calls it, so URL-scope coverage is `1 of 1` from VirusTotal alone (`docs/OPSEC.md` §6 gap 3) |
| **abuse.ch (URLhaus + ThreatFox) is planned, not built.** | It is the largest accuracy gain still on the list, and the terms-of-service exposure in bulk mode is a recorded accepted risk rather than a mitigated one (roadmap 8.7) |
| **IDN homographs render as written in `bulk` triage.** | `аpple.com` (Cyrillic U+0430) looks identical to `apple.com`. The A-label and mixed-script flag are computed but not carried into the triage row; the row is only marked `probable` (`docs/OPSEC.md` §6 gap 7) |
| **An over-long hostname is still sent to VirusTotal.** | The URL guard checks scheme, host presence and routability but not the RFC 1035 253-octet limit, so a pasted 4000-character name spends a quota unit. Not a passivity breach — pinned as current behaviour in `tests/test_w6_passivity_audit.py` |
| **A provider could be wrong about its own API.** | Every passivity claim about a third-party endpoint is read from that provider's documentation. If a `GET` route silently started triggering a fetch, nothing here would detect it (`docs/OPSEC.md` §6 gap 5) |

---

## Development

```bash
pip install -e ".[dev]"

python -m pytest -q          # the suite makes zero network calls, by design
python -m ruff check .       # pyproject sets extend-exclude = ["docs/"] — ruff >=0.16 reformats
python -m ruff format --check .   # Python inside Markdown, which would rewrite quoted evidence
python -m mypy tripper_recon/
```

CI runs all four on Python 3.10, 3.11 and 3.12, plus a `gitleaks` secret scan over the full
history. Every provider credential is explicitly unset in the job, so a test that forgot its
`respx` mock fails loudly instead of billing a real key. Lint, format and type checks are
**blocking on `tests/` and advisory on the package source** — the source predates any linter, and
the workflow documents the condition for flipping them to blocking
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)). `pytest` is blocking everywhere.

Adding a provider means adding its host to `ALLOWED_EGRESS_HOSTS` in
[`utils/http.py`](tripper_recon/utils/http.py) **and** to `ALLOWED_HOSTS` in
`tests/test_passivity.py` **and** to [`docs/OPSEC.md`](docs/OPSEC.md) §2, in the same commit.
Anything else fails one of the two gates.

## Documentation

| Document | Contents |
|---|---|
| [`docs/OPSEC.md`](docs/OPSEC.md) | The passivity contract with `file:line` evidence, every outbound destination, the DNS exception, what providers learn, and the gaps it does not paper over |
| [`docs/PROVIDERS.md`](docs/PROVIDERS.md) | Per-provider endpoints, fields kept and discarded, credential handling |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | The sequenced hardening plan, the deliberately-not-doing list, and the settled operator decisions |
| [`docs/review/`](docs/review/) | The six audit lenses, four design proposals, and the adversarial verification pass behind the roadmap |

## License

MIT — see [LICENSE](LICENSE).
