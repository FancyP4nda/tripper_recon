<div align="center">

# Tripper Recon

**A passive, asynchronous OSINT toolkit for IP, Domain, and ASN investigations.**

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

</div>

---

## Overview

Tripper Recon is an async Open Source Intelligence (OSINT) tool for infrastructure investigations. Whether you are hunting for threat actors, reviewing SIEM logs, or profiling external IP addresses, Tripper gives you one interface over ten third-party intelligence providers.

It offers a CLI for analysts, with JSON output for scripted use.

## Key Features

- **Ten providers, one command**: VirusTotal, Shodan, AbuseIPDB, IPInfo, AlienVault OTX, Cloudflare Radar, Cloudflare BGP, RIPEstat, CAIDA AS-Rank, and PeeringDB.
- **Works without keys**: the `asn` command runs fully on RIPEstat, CAIDA, and PeeringDB, which need no API key at all.
- **Passive collection**: every query goes to a third-party API. The tool does not scan, connect to, or fetch the target. See [OPSEC & Passivity](#opsec--passivity).
- **Concurrent IP lookups**: the `ip` command queries its five providers in one wave and processes bulk target files concurrently.
- **Retry with backoff**: jittered exponential backoff on provider requests.
- **Scriptable**: `-o json` emits the full result set; structured logs go to stderr so stdout stays parseable.

> **Status.** This is an active project under review. A sequenced hardening plan, with a
> known-defect list and file-line evidence, is in [`docs/ROADMAP.md`](docs/ROADMAP.md); the
> supporting audit reports are in [`docs/review/`](docs/review/). Read it before relying on
> the output for a decision.

---

## OPSEC & Passivity

The tool is built to investigate infrastructure without touching it. Full detail, per provider, is in [`docs/OPSEC.md`](docs/OPSEC.md). The short version:

- **All intelligence comes from third-party APIs.** No port scan, no banner grab, no HTTP request to the target, no submission of a URL for live scanning.
- **One documented exception:** the `domain` command resolves the target with your system resolver. That recursive lookup can reach the target's own authoritative nameserver. Treat it as a disclosure risk on a live investigation — see `docs/OPSEC.md`.
- **Every query is visible to the provider.** A VirusTotal lookup under your API key is attributable to you.

---

## Installation

Tripper Recon requires **Python 3.10+**.

```bash
# Clone the repository
git clone https://github.com/FancyP4nda/tripper_recon.git
cd tripper_recon

# Install using pip (recommended to use a virtual environment)
pip install .
```

---

## Quick Start

### CLI

The `tripper-recon` CLI provides immediate, readable intelligence straight to your terminal.

```bash
# Investigate a single IP address
tripper-recon ip 8.8.8.8

# Investigate a domain (resolves IPs, then enriches each one)
tripper-recon domain www.cloudflare.com

# Deep-dive into an Autonomous System Number (ASN) — no API key needed
tripper-recon asn 15169
```

**Bulk Processing**: Feed the tool a text file of targets for concurrent processing.
```bash
tripper-recon ip ./path/to/suspicious_ips.txt --format json
```

`--format` works in either position — `tripper-recon -o json ip 8.8.8.8` and
`tripper-recon ip 8.8.8.8 -o json` are equivalent. Structured logs go to stderr, so
`tripper-recon ip targets.txt -o json | jq` is safe.

### Known limitations

Read these before you trust an answer. Each is tracked in [`docs/ROADMAP.md`](docs/ROADMAP.md).

| Limitation | Effect |
|---|---|
| **The tool states no verdict.** | It renders provider data. Deciding "malicious or not" is still your job. This is the headline gap — see roadmap W5. |
| **Exit code is 0 even when every provider failed.** | Do not gate automation on exit status yet. Roadmap item 4.2. |
| **No coverage line.** | Nothing tells you how many providers actually answered. A sparse result and a clean result look alike. Roadmap item 4.4. |
| **Colour carries most of the signal.** | `rich` strips colour when you redirect to a file, which is exactly the "paste into a ticket" workflow. Roadmap item 5.8. |
| **No URL support.** | Pass the hostname to `domain` instead. Roadmap W6. |
| **`--rate-limit` has no effect.** | The limiter constrains task creation rather than requests. Roadmap item 3.3. |
| **The `domain` path queries providers serially per IP.** | Slow on a domain with many A records. Roadmap item 3.8. |

## Data Providers

Tripper Recon correlates data from the following sources. Per-provider detail — which fields are extracted, which commands use it, and what you get without a key — is in [`docs/PROVIDERS.md`](docs/PROVIDERS.md).

**No API key required:**

- **[RIPEstat](https://stat.ripe.net/)**: AS overview, abuse contact, routing status, neighbours, announced prefixes.
- **[CAIDA AS-Rank](https://asrank.caida.org/)**: AS rank, customer cone, transit relationships.
- **[PeeringDB](https://www.peeringdb.com/)**: IXP presence.

**API key required:**

- **[VirusTotal v3](https://www.virustotal.com/)**: Detections, reputation, passive DNS, Whois, HTTPS certificate.
- **[Shodan](https://www.shodan.io/)**: Open ports, service banners, SSL certificate fingerprints.
- **[AbuseIPDB](https://www.abuseipdb.com/)**: Abuse confidence scoring and report counts.
- **[IPInfo](https://ipinfo.io/)**: Geolocation and network ownership.
- **[AlienVault OTX](https://otx.alienvault.com/)**: Pulse counts and titles.
- **[Cloudflare Radar](https://radar.cloudflare.com/)**: ASN metadata and BGP prefixes.
- **Cloudflare BGP** (same token): BGP hijack incident counts.

> Providers whose key is unset are skipped silently. If your output looks sparse, check your
> `.env` before concluding the indicator is clean. This is a known defect — see
> [`docs/ROADMAP.md`](docs/ROADMAP.md) item 4.1.

---

## Configuration

API access requires configuring your provider keys. Create a `.env` file in the project root:

```ini
# Core
# Log level: a number (10=DEBUG, 20=INFO, 30=WARN, 40=ERROR) or a name (DEBUG/INFO/WARN/ERROR).
TRIPPER_RECON_LOG_LEVEL=20
TRIPPER_RECON_USER_AGENT="Your Custom User Agent"

# Provider Keys
CLOUDFLARE_API_TOKEN=your_token_here
VT_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
IPINFO_TOKEN=your_token_here
OTX_API_KEY=your_key_here
```
*(An example template is provided in `.env.example`)*


