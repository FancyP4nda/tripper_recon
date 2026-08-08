# OPSEC & Passivity

What this tool does and does not send to the network, and who can see that you ran it.

This document describes the code as it stands on branch `feat/work-20260808-recon-hardening`.
Every claim carries a `file:line` anchor so you can check it yourself. If you change a provider,
change this file in the same commit.

---

## 1. The contract

**Tripper Recon investigates infrastructure without touching it.** All intelligence comes from
third-party APIs that already hold the data. The tool does not:

- scan the target, or connect to any port on it
- fetch a URL, follow a redirect, or download a sample
- submit anything for live analysis (no VirusTotal `POST /urls`, no urlscan `POST /scan`)
- send an ICMP echo, a traceroute, or a TLS handshake to the target

There is **one documented exception**, in section 3.

## 2. Every outbound destination

Fourteen outbound paths exist. Thirteen go to a third party that is not the target.

| Provider | Host contacted | Reaches target infrastructure? |
|---|---|---|
| VirusTotal | `www.virustotal.com` | No |
| Shodan | `api.shodan.io` | No |
| AbuseIPDB | `api.abuseipdb.com` | No |
| IPInfo | `ipinfo.io` | No |
| AlienVault OTX | `otx.alienvault.com` | No |
| Cloudflare Radar | `api.cloudflare.com` | No |
| Cloudflare BGP | `api.cloudflare.com` | No |
| RIPEstat | `stat.ripe.net` | No |
| CAIDA AS-Rank | `api.asrank.caida.org` | No |
| PeeringDB | `www.peeringdb.com` | No |
| **System resolver** | your configured DNS resolver | **Yes, indirectly** — see section 3 |

VirusTotal is used correctly for a passive tool: the provider module issues `GET` requests against
reports that already exist. It never submits an indicator for analysis.

## 3. The exception: active DNS on the `domain` command

`tripper-recon domain <target>` calls `socket.getaddrinfo()` on the target
(`tripper_recon/utils/dns.py:14`, invoked at `tripper_recon/orchestrators.py:247-248`).

**What that means.** Your organization's recursive resolver looks the name up. If the answer is not
already cached, the resolver walks the delegation chain and queries **the nameserver the target
operator controls**. That nameserver sees a query for their domain, sourced from your organization's
resolver, at the moment you started investigating.

**Why it matters.** For a live actor watching their own DNS logs, that is a tell. For a
single-use phishing domain, it can be the tell.

**What it does not leak.** Your workstation IP is not exposed to the target — the query arrives
from your recursive resolver. Nothing identifies you personally, and no query reaches the target's
web infrastructure.

**Working around it today.** Investigate the hostname's IPs directly with `tripper-recon ip`, or
read the passive DNS records VirusTotal already returns. The tool parses those passive A/AAAA
records at `orchestrators.py:227-235` and merges them with the active results at `:249` — so the
passive substitute is already present, just not selectable.

**Planned.** Passive DNS becomes the default and live resolution moves behind an explicit
`--active-dns` flag, with the collection mode recorded in the output. `docs/ROADMAP.md` item 2.2.

## 4. What the third-party providers learn

Passive does not mean invisible. It means the *target* does not see you. The providers do.

- **Every query is attributable to your API key.** A VirusTotal lookup is logged against your
  account. Assume your employer, the provider, and anyone with access to provider logs can see
  which indicators you investigated and when.
- **Your egress IP is visible** to all ten providers.
- **The indicator list itself is sensitive.** The set of things you are looking at can reveal an
  ongoing incident before you are ready to disclose it.
- **Look-ups are not submissions.** Nothing in this tool contributes your indicators to a public
  corpus. A VirusTotal *lookup* does not appear in the community feed the way a *submission* does.

If an investigation is sensitive enough that provider visibility is itself a risk, this tool is
the wrong instrument. Use an offline data set.

## 5. Controls already in the code

| Control | Anchor |
|---|---|
| RFC1918 addresses are refused on the `ip` path | `orchestrators.py:109-110` |
| TLS verification on, never disabled | `utils/http.py:50` |
| Investigation output is gitignored in bulk | `.gitignore:85-92` |
| No `POST` to any analysis endpoint anywhere in `providers/` | `providers/*.py` |

## 6. Gaps this document does not paper over

These are real and open. They are tracked in `docs/ROADMAP.md`.

1. **The passive boundary is a convention, not a control.** `create_client()`
   (`utils/http.py:41`) returns a general-purpose HTTP client. Nothing stops a future provider
   module from pointing it at a target. An egress allowlist is roadmap item 2.1.
2. **Private IPs are forwarded to third parties on the `domain` path.** The RFC1918 guard exists
   on the `ip` path only. A split-horizon or sinkholed domain that resolves to `10.x` sends your
   internal addressing to five external providers (`orchestrators.py:253`). Roadmap item 2.4.
3. **The default User-Agent impersonates a browser** (`utils/http.py:10-14`). Every request claims
   to be Chrome on Windows. Against authenticated APIs this buys nothing — the key already
   identifies you — and it is a terms-of-service exposure. Roadmap item 2.6.
4. **API keys can leak into output.** Shodan and IPInfo carry the key in the query string
   (`shodan_api.py:18`, `ipinfo.py:18`), and `_error_payload` copies the failing URL and the
   exception text into the result (`orchestrators.py:35-40`). Both strings contain the key.
   Verified reproducible. Roadmap item 0.1 — **fix this before pasting error output anywhere.**
5. **`reverse_ptr` exists and is unused** (`utils/dns.py:26`). It has no callers today. Whether
   PTR lookups belong in a passive tool has not been decided; see roadmap item 2.5.

## 7. Endpoints that must never be added

Each of these has a passive sibling on the same API, which makes them easy to reach for by mistake.

| Forbidden | Why | Passive alternative |
|---|---|---|
| VirusTotal `POST /urls`, `POST /analyses` | Instructs VT to fetch the target | `GET` the existing report |
| urlscan.io `POST /api/v1/scan/` | Loads the target in a real browser, publishes the scan | urlscan **search** for existing scans |
| Pulsedive `probe=1` | Triggers live scanning | Default passive query |
| MalwareBazaar `get_file` | Downloads live malware | Metadata query |
| Spamhaus live `zen` DNSBL | Per-IP query leaks the indicator | Downloadable DROP list |
| Tor DNSEL per-IP | Per-IP query leaks the indicator | Bulk exit list |
| Any redirect or shortener expansion | A redirect resolution is an active fetch, `HEAD` included | Cached final URL from VT or urlscan |
