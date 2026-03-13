# Tripper Recon

<div align="center">
  <p><strong>A unified, async OSINT toolkit for IP, domain, URL, and ASN investigations.</strong></p>
</div>

## Overview

Tripper Recon utilizes a functional design with RORO (Receive an Object, Return an Object) interfaces, typed models (Pydantic v2), structured JSON logs, and provider clients for Cloudflare Radar, VirusTotal, Shodan, AbuseIPDB, IPInfo, and AlienVault OTX. It exposes both a powerful CLI and a REST API server, featuring secure defaults, rate limiting, and jittered backoff.

- **CLI entrypoint**: [`tripper_recon/cli.py`](./tripper_recon/cli.py)
- **API server**: [`tripper_recon/api/server.py`](./tripper_recon/api/server.py)
- **Orchestrators**: [`tripper_recon/orchestrators.py`](./tripper_recon/orchestrators.py)

---

## Usage

### General Commands

Help and version information:
```bash
tripper-recon --help
tripper-recon --version
```

### IP Investigation

Investigate a single IP address:
```bash
tripper-recon ip 8.8.8.8
tripper-recon ip 8.8.8.8 --format json
```

Batch IP investigation from a text file (one IP per line, `#` comments allowed):
```bash
tripper-recon ip ./path/to/ips.txt
tripper-recon ip ./path/to/ips.txt --format json
```

### Domain Investigation

Investigate a domain or URL:
```bash
tripper-recon domain www.google.com
tripper-recon domain www.google.com --format json
```

### ASN Lookup

Investigate an Autonomous System Number:
```bash
tripper-recon asn 15169
tripper-recon asn 15169 --format json
```

---

## Global Flags

- `-o, --format console|json`: Output format (default: `console`).
- `--rate-limit <N>`: Max concurrent outgoing API requests across global providers (default: `10`).
- `--user-agent <str>`: Custom User-Agent string to spoof in HTTP requests.
- `-V, --version`: Print version and exit.
- `-h, --help`: Show command help.

---

## CLI Commands

- `tripper-recon --help` — Top-level usage and global flags.
- `tripper-recon ip <ip>` — Investigate an IP address (supports reading targets from a text file for concurrent batch processing).
  - `--format console|json`
  - `--ports-limit <N|all>`
- `tripper-recon domain <domain>` — Investigate a domain or URL.
  - `--format console|json`
  - `--ports-limit <N|all>`
- `tripper-recon asn <asn>` — Investigate an Autonomous System Number.
  - `--format console|json`
  - `--neighbors <N>`
  - `--enrich`
  - `--enrich-limit <N>`
  - `--monochrome`
  - `--prefixes-out <path>`
  - `--prefixes v4|v6|both`
- `tripper-recon-api` — Launch the FastAPI server (see `tripper_recon/api/server.py`).

*Python module alternative:* `python -m tripper_recon.cli ...`

---

## Techniques & Architecture

- **HTTP/2 with connection pooling**: Utilizing `httpx.AsyncClient` for lower latency and better multiplexing.
- **Explicit HTTP Headers**: Explicit `User-Agent` and `Accept` headers to improve API compatibility.
- **Jittered Exponential Backoff**: Handing transient errors and rate limits; aligns with `429 Too Many Requests` and `Retry-After` guidance.
- **Structured JSON Logging**: Flat key/value events for SIEM ingestion and correlation, implemented in [`tripper_recon/utils/logging.py`](./tripper_recon/utils/logging.py).
- **Async DNS Resolution**: Reverse PTR lookups offloaded to threads to avoid blocking the event loop; see [`tripper_recon/utils/dns.py`](./tripper_recon/utils/dns.py).
- **Dependency Injection**: Shared `httpx` client and environment-driven API keys to keep functions pure and testable (RORO throughout the toolchain).
- **Guard Clauses**: Early returns to handle invalid inputs fast (e.g., malformed IPs/domains/ASNs).
- **Provider Composition**: Results are normalized and merged by orchestrators to render consolidated reports. Console formatting utilizes Python's Rich library to render fast, borderless text tables that are perfectly aligned for copying and pasting directly into markdown reports (see [`tripper_recon/reporting/console.py`](./tripper_recon/reporting/console.py)).

---

## Configuration

The CLI and API auto-load a `.env` file when present; see [`tripper_recon/utils/env.py`](./tripper_recon/utils/env.py).
- Example configuration: [`.env.example`](./.env.example)

**Supported keys:**
- `CLOUDFLARE_API_TOKEN`
- `VT_API_KEY`
- `SHODAN_API_KEY`
- `ABUSEIPDB_API_KEY`
- `IPINFO_TOKEN`
- `OTX_API_KEY`
- `TRIPPER_RECON_LOG_LEVEL`
- `TRIPPER_RECON_USER_AGENT`

*Note: Outbound HTTP requests default to a modern Chromium User-Agent and can be overridden via `TRIPPER_RECON_USER_AGENT`; all provider calls use HTTPS endpoints (port 443).*

---

## Project Structure

```text
.
├── README.md
├── pyproject.toml
├── .gitignore
├── .env.example
├── .env
└── tripper_recon/
    ├── api/
    ├── providers/
    ├── reporting/
    ├── types/
    └── utils/
```

### File Highlights

- **CLI**: [`tripper_recon/cli.py`](./tripper_recon/cli.py) - Commands for IP, domain, and ASN. Auto-loads `.env`.
- **API Server**: [`tripper_recon/api/server.py`](./tripper_recon/api/server.py) - Endpoints: `/ip/{ip}`, `/domain/{domain}`, `/asn/{asn}`.
- **Orchestrators**: [`tripper_recon/orchestrators.py`](./tripper_recon/orchestrators.py) - Async flows that combine providers per target type.
- **Providers**:
  - Cloudflare Radar GraphQL: [`tripper_recon/providers/cloudflare_radar.py`](./tripper_recon/providers/cloudflare_radar.py)
  - VirusTotal: [`tripper_recon/providers/virustotal.py`](./tripper_recon/providers/virustotal.py)
  - Shodan: [`tripper_recon/providers/shodan_api.py`](./tripper_recon/providers/shodan_api.py)
  - AbuseIPDB: [`tripper_recon/providers/abuseipdb.py`](./tripper_recon/providers/abuseipdb.py)
  - IPInfo: [`tripper_recon/providers/ipinfo.py`](./tripper_recon/providers/ipinfo.py)
  - AlienVault OTX: [`tripper_recon/providers/otx.py`](./tripper_recon/providers/otx.py)
- **Reporting**: [`tripper_recon/reporting/console.py`](./tripper_recon/reporting/console.py) - Renders summaries aligned to your example outputs.
- **Utilities**:
  - JSON logging: [`tripper_recon/utils/logging.py`](./tripper_recon/utils/logging.py)
  - HTTP client + rate limiting: [`tripper_recon/utils/http.py`](./tripper_recon/utils/http.py)
  - Backoff: [`tripper_recon/utils/backoff.py`](./tripper_recon/utils/backoff.py)
  - DNS helpers: [`tripper_recon/utils/dns.py`](./tripper_recon/utils/dns.py)
  - Validation: [`tripper_recon/utils/validation.py`](./tripper_recon/utils/validation.py)
  - Env loader: [`tripper_recon/utils/env.py`](./tripper_recon/utils/env.py)

---

## Notable Libraries

- [httpx](https://www.python-httpx.org): Async HTTP client with HTTP/2.
- [FastAPI](https://fastapi.tiangolo.com): Typed, async web framework.
- [Pydantic v2](https://docs.pydantic.dev): Data validation.
- [Uvicorn](https://www.uvicorn.org): ASGI server.
- [python-dotenv](https://saurabh-kumar.com/python-dotenv): Load `.env` files.

## Provider APIs

- [Cloudflare Radar](https://developers.cloudflare.com/api) (GraphQL used for ASN metadata)
- [VirusTotal v3](https://docs.virustotal.com/reference/overview)
- [Shodan](https://developer.shodan.io/api)
- [AbuseIPDB](https://www.abuseipdb.com/api.html)
- [IPInfo](https://ipinfo.io/developers)
