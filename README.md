# tripper-recon

Unified, OSINT toolkit for IP, domain, URL, and ASN investigations. It uses a functional design with RORO interfaces, typed models (Pydantic v2), structured JSON logs, and provider clients for Cloudflare Radar, VirusTotal, Shodan, AbuseIPDB, IPAPI.IS, and OTX. It exposes both a CLI (see `tripper-recon` in [`pyproject.toml`](./pyproject.toml)) and a REST API server (see `tripper-recon-api`), with secure defaults, rate limiting, and jittered backoff.

- CLI entrypoint: [`tripper_recon/cli.py`](./tripper_recon/cli.py)
- API server: [`tripper_recon/api/server.py`](./tripper_recon/api/server.py)
- Orchestrators: [`tripper_recon/orchestrators.py`](./tripper_recon/orchestrators.py)

## Usage

```
# Help and version
tripper-recon --help
tripper-recon --version

# IP investigation
tripper-recon ip 8.8.8.8
tripper-recon ip 8.8.8.8 --format json

# Domain investigation
tripper-recon domain www.google.com
tripper-recon domain www.google.com --format json

# ASN lookup
tripper-recon asn 15169
tripper-recon asn 15169 --format json
```

Flags
- `-o, --format console|json` - Output format (default: `console`).
- `-V, --version` - Print version and exit.
- `-h, --help` - Show command help.

### CLI Commands

- `tripper-recon --help` — top-level usage and global flags.
- `tripper-recon ip <ip>` — investigate an IP address.
  - `--format console|json`
  - `--ports-limit <N|all>`
- `tripper-recon domain <domain>` — investigate a domain or URL.
  - `--format console|json`
  - `--ports-limit <N|all>`
- `tripper-recon asn <asn>` — investigate an Autonomous System Number.
  - `--format console|json`
  - `--neighbors <N>`
  - `--enrich`
  - `--enrich-limit <N>`
  - `--monochrome`
  - `--prefixes-out <path>`
  - `--prefixes v4|v6|both`
- `tripper-recon-api` — launch the FastAPI server (see `tripper_recon/api/server.py`).
- Python module alternative: `python -m tripper_recon.cli ...`

Provider APIs
- Cloudflare Radar (GraphQL used for ASN metadata): https://developers.cloudflare.com/api
- VirusTotal v3: https://docs.virustotal.com/reference/overview
- Shodan: https://developer.shodan.io/api
- AbuseIPDB: https://www.abuseipdb.com/api.html
- IPAPI.IS: https://ipapi.is/app/request-builder
- AlienVault OTX: https://otx.alienvault.com/api

Fonts
- No custom fonts are used.

## Project Structure

`
.
- README.md
- pyproject.toml
- .gitignore
- .env.example
- tripper_recon/
  - api/
  - providers/
  - reporting/
  - types/
  - utils/
`
## File Highlights

- CLI: [`tripper_recon/cli.py`](./tripper_recon/cli.py) - Commands for IP, domain, and ASN. Auto-loads `.env`.
- API Server: [`tripper_recon/api/server.py`](./tripper_recon/api/server.py) - Endpoints: `/ip/{ip}`, `/domain/{domain}`, `/asn/{asn}`.
- Orchestrators: [`tripper_recon/orchestrators.py`](./tripper_recon/orchestrators.py) - Async flows that combine providers per target type.
- Providers:
  - Cloudflare Radar GraphQL: [`tripper_recon/providers/cloudflare_radar.py`](./tripper_recon/providers/cloudflare_radar.py)
  - VirusTotal: [`tripper_recon/providers/virustotal.py`](./tripper_recon/providers/virustotal.py)
  - Shodan: [`tripper_recon/providers/shodan_api.py`](./tripper_recon/providers/shodan_api.py)
  - AbuseIPDB: [`tripper_recon/providers/abuseipdb.py`](./tripper_recon/providers/abuseipdb.py)
  - IPAPI.IS: [`tripper_recon/providers/ipapi_is.py`](./tripper_recon/providers/ipapi_is.py)
  - AlienVault OTX: [`tripper_recon/providers/otx.py`](./tripper_recon/providers/otx.py)
- Reporting: [`tripper_recon/reporting/console.py`](./tripper_recon/reporting/console.py) - Renders summaries aligned to your example outputs.
- Utilities:
  - JSON logging: [`tripper_recon/utils/logging.py`](./tripper_recon/utils/logging.py)
  - HTTP client + rate limiting: [`tripper_recon/utils/http.py`](./tripper_recon/utils/http.py)
  - Backoff: [`tripper_recon/utils/backoff.py`](./tripper_recon/utils/backoff.py)
  - DNS helpers: [`tripper_recon/utils/dns.py`](./tripper_recon/utils/dns.py)
  - Validation: [`tripper_recon/utils/validation.py`](./tripper_recon/utils/validation.py)
  - Env loader: [`tripper_recon/utils/env.py`](./tripper_recon/utils/env.py)

## Configuration

- The CLI and API auto-load a `.env` file when present; see [`tripper_recon/utils/env.py`](./tripper_recon/utils/env.py).
- Example configuration: [`.env.example`](./.env.example)
- Supported keys: `CLOUDFLARE_API_TOKEN`, `VT_API_KEY`, `SHODAN_API_KEY`, `ABUSEIPDB_API_KEY`, `IPAPI_IS_API_KEY`, `OTX_API_KEY`, `TRIPPER_RECON_LOG_LEVEL`, `TRIPPER_RECON_USER_AGENT`.
- Outbound HTTP requests default to a modern Chromium User-Agent and can be overridden via `TRIPPER_RECON_USER_AGENT`; all provider calls use HTTPS endpoints (port 443).





