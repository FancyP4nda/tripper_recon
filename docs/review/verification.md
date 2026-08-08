# Adversarial verification — tripper_recon audit findings

Target: `/home/echo/dev/tripper_recon` @ `de277f4` (branch `feat/work-20260808-recon-hardening`)
Method: read-only source inspection plus **local, offline** probes (argparse, httpx object construction, rich rendering, asyncio semaphore semantics). No network calls. No target investigated. `.env` never opened.
Probe environment: `/home/echo/miniconda3/envs/tripper/bin/python` — Python 3.12.12, httpx 0.28.1, rich 14.3.3, h2 4.3.0.
Probe scripts: `probe1.py` (stdlib), `probe2.py` (httpx/asyncio), `probe3.py` (rich) in this directory.

Six audit agents produced **98 findings**. After de-duplication there are **~58 distinct claims**. Verdicts below.

---

## 0. Headline

The audit is unusually accurate. I set out to refute and could not refute much. Of the distinct claims:

- **CONFIRMED** — I personally reproduced or read the exact behaviour: the large majority, including every critical-rated code defect.
- **PARTIAL** — real underlying behaviour, but severity inflated, mechanism misdescribed, or the named trigger unverified: 14 claims.
- **REFUTED** — 1 claim (PKG-INFO "License: Proprietary" as a live defect).

The strongest findings, all independently reproduced by me:

1. **API keys leak into console, JSON and API responses** (`orchestrators.py:38-39`). Probe H2: `str(request.url)` **and** `str(HTTPStatusError)` both contain `?key=SECRETKEY123` verbatim on httpx 0.28.1.
2. **Green `0/0` for an absent provider** (`console.py:70-79`). Probe R1/R2: with `virustotal={}` the row renders `0/0` in ANSI green (`\x1b[32m`).
3. **The RateLimiter bounds nothing** (`orchestrators.py:120-129`). Probe H6: requested limit 2, observed peak concurrency **10**.
4. **`transport=` silently disables HTTP/2 and the connection cap** (`http.py:43-49`). Probe H1: with `transport=` → `http2=False, max_connections=100`; without → `http2=True, max_connections=50`.
5. **Global `-o json` is discarded** (`cli.py:382` vs `:390/:395/:401`). Probe P1: `-o json ip 8.8.8.8` → `format='console'`.
6. **Provider strings are parsed as rich markup** (`console.py:39+`). Probe R3: `MarkupError` raised; probe R4: an OTX pulse title `[green]0/94 - no detections[/]` renders green with the tags consumed.

The three things I was told to be most skeptical about:

- **RateLimiter claims — all correct.** Probe H6 settles it: `async with limiter:` around `asyncio.create_task()` acquires and releases a semaphore around a body that performs no I/O. `create_task` schedules; it does not await. The request runs entirely outside the guarded block. Separately `RateLimiter.__init__` (`http.py:62-66`) only sizes `_global_sem` on first construction and the sole call site passes `rate=5` explicitly (`orchestrators.py:117`), so `configure_rate_limit()` (`cli.py:415`) can never take effect. `--rate-limit` is dead in all three subcommands. Confirmed twice over.
- **Passivity / DNS leakage — the concern is real, not theatre, but one agent's `critical` is a notch high.** `dns.py:8-23` calls `socket.getaddrinfo` on the target name, invoked unconditionally at `orchestrators.py:248` with no flag and no opt-out. I verified that this is the **only** outbound path that can reach target-controlled infrastructure: all ten provider modules target third-party hosts, no socket connect to the target, no URL fetch, no urlscan submission, and `reverse_ptr` has no callers. Against the operator's stated hard constraint the finding stands squarely. The severity correction: the query reaches the adversary's authoritative NS *via the org's recursive resolver*, so attribution is org-granular, not analyst-granular, and for a domain already delivered in a lure the marginal signal is often nil. It becomes genuinely high-impact in the per-victim-unique-hostname case the OPSEC agent names. **Correct severity: high, not critical.**
- **"Security vulnerability" claims on a locally-run tool — three are inflated.** `--prefixes-out` path handling, `/etc/passwd` as a target file, and the normalised-vs-raw domain divergence all involve input the analyst supplies to a tool running as the analyst. No trust boundary is crossed. They are real robustness/UX defects; they are not vulnerabilities. The API server is the genuine exception — but it is an opt-in second entry point (`tripper-recon-api`), not the CLI path, which is why I rate it high rather than critical.

---

## 1. Verdicts — critical and high

### 1.1 CONFIRMED — Absent/failed provider renders as green `0/0`
Anchors: `reporting/console.py:70-79`, `orchestrators.py:78-79`, `:181`
Probe R1 output, `virustotal={}`:
```
  virustotal_detections      0/0
```
Probe R2 with colour forced: `\x1b[32m0/0\x1b[0m`. `vt_stats = vt.get("vt_last_analysis_stats", {})` on an empty dict yields `malicious=0, total_engines=0`, and `vt_color = "red" if malicious > 0 else "green"` has no third branch. `_should_suppress` (`orchestrators.py:78`) strips `missing_api_key` from both `provider_errors` and `result_errors`, so an unset `VT_API_KEY` produces no error row anywhere on screen. Verified that `virustotal.py:15`, `shodan_api.py:15`, `abuseipdb.py:15`, `ipinfo.py:15`, `otx.py:15` all return exactly those suppressed markers.
**Correction to the finding's wording:** AbuseIPDB (`console.py:86 if abuse:`) and OTX (`:100 if otx:`) fail *differently* — their value rows vanish entirely while their `_analysis_link` rows still print. That is a missing-row failure, not a false-zero. Only VirusTotal manufactures the affirmative green zero. The UX agent's version of this finding states it correctly; the correctness agent's "same shape" is loose.
Duplicates: analyst-lens "Missing API key renders as a green 0/0"; the second half of the async-lens "No per-provider rate budget".

### 1.2 CONFIRMED — Provider-controlled strings parsed as rich markup
Anchor: `reporting/console.py:39` and every `table.add_row` taking provider data
Probe R3, OTX title `"evil [/] campaign"`:
```
RAISED MarkupError: closing tag '[/]' at position 5 has nothing to close
```
Probe R4, OTX title `"[green]0/94 - no detections[/]"` renders as `\x1b[32m0/94 - no detections\x1b[0m` — tags consumed, style applied, inside the analyst's report.
**Corrections:** (a) the render at `cli.py:183` builds the table; the `MarkupError` fires at `console.print(panel)` on `cli.py:184`. (b) "discards every already-paid-for result in a 500-target run" is overstated — targets rendered before the poisoned one are already on the terminal; those *after* it are lost. (c) the JSON path is immune: `render_ip_analysis` is only called under `if output == "console"` (`cli.py:182`), and `print_json` does not parse markup. The crash and the spoofing both stand.

### 1.3 CONFIRMED — API keys copied into every output sink
Anchors: `orchestrators.py:38`, `:39`, `:46`; `providers/shodan_api.py:18`; `providers/ipinfo.py:18`
Probe H2 (httpx 0.28.1, offline `Request`/`Response` construction):
```
str(req.url) contains key: True -> https://api.shodan.io/shodan/host/1.2.3.4?key=SECRETKEY123
str(err) contains key: True
str(err) = Client error '401 Unauthorized' for url 'https://api.shodan.io/...?key=SECRETKEY123' | ...
```
Redacting one field is insufficient — both carry it. Sinks verified: `console.py:153-155`, `cli.py:41-42`, `cli.py:196` (JSON), `api/server.py:28`. `_should_suppress` only special-cases the provider name `ipinfo_asn` (`orchestrators.py:80`); the IP path registers the provider as `ipinfo` (`:163`), so a 401 there is *not* suppressed and the token is rendered.
**One correction:** probe H3 shows the `httpx.RequestError` branch differs — `str(err)` for a `ConnectTimeout` is just `"timed out"`; only the `url` field (`orchestrators.py:46`) leaks there. The security agent's "both strings contain `?key=`" is true for `HTTPStatusError`, not for transport errors.
Also confirmed: `ipinfo_asn` returns a dict on `>=400` (`ipinfo.py:65-68`) rather than raising, so the ASN path does **not** leak the token — only the IP path does.
Duplicate: security-lens "Provider API keys echoed verbatim…".

### 1.4 CONFIRMED — RateLimiter bounds nothing; `--rate-limit` is dead
Anchors: `orchestrators.py:117`, `:120-129`; `utils/http.py:57-66`; `cli.py:415`
Probe H6, exact pattern reproduced:
```
requested limit 2, observed peak concurrency: 10
```
Three independent defects, all read directly from source: (1) the semaphore wraps `create_task`, which performs no I/O; (2) `RateLimiter(rate=5)` at `:117` wins the first-construction race in `__init__`, so `_init_rate` written by `configure_rate_limit` is never read; (3) `investigate_domain` and `investigate_asn` construct no limiter at all, so `--rate-limit` is inert for two of three subcommands even in principle. `cli.py:150-151` gathers over an unbounded target list on top.
Duplicates: async-lens "RateLimiter constrains nothing"; opsec-lens "--rate-limit is silently ignored"; security-lens "Rate limiter is a no-op and file input fans out".

### 1.5 CONFIRMED — Global `-o/--format` silently discarded
Anchor: `cli.py:382` vs `:390`, `:395`, `:401`
Probe P1, faithful argparse replica on Python 3.12.13:
```
'-o json ip 8.8.8.8' -> console
'ip 8.8.8.8 -o json' -> json
```
`_SubParsersAction` parses into a fresh namespace and copies every attribute — including subparser defaults — back over the parent's parsed values.

### 1.6 CONFIRMED — `_should_suppress` raises `TypeError` on a list-valued error
Anchor: `orchestrators.py:78`; sources `providers/cloudflare_radar.py:42`, `:67`
Probe P5: `TypeError: unhashable type: 'list'`. Both `_call_int` and `_call_str` return `{"ok": False, "error": j["errors"]}` where `errors` is a GraphQL error **array**. Reachable at `orchestrators.py:425` (ASN path) and `:303` (domain path) — both unguarded. Not reachable on the IP path, which only checks `cf.get("ok")` (`:157`).
**Caveat on the stated trigger:** the list-valued branch requires **HTTP 200 with a GraphQL `errors` array**. An expired token more commonly yields 400/403, which takes the `http_error` string branch instead. Whether Cloudflare Radar returns 200-with-errors for a scope failure is unverified and would need a live call. The code defect is certain; the named failing input is not.

### 1.7 CONFIRMED — Active DNS resolution against the target, no opt-out
Anchors: `utils/dns.py:14`; `orchestrators.py:247-248`
`socket.getaddrinfo(domain, ...)` for both families via the system resolver, called unconditionally on every `domain` invocation. No flag, no warning in output. The passive alternative is already wired: VT `last_dns_records` are parsed at `:227-235` and merged at `:249`, and the author's own variable names (`active_ips` / `passive_ips`) show the distinction was understood before being discarded by `dedupe_preserve_order` at `:251`.
I verified this is the **only** target-reaching path in the codebase. All ten providers hit third-party hosts. `reverse_ptr` has no callers (`rg reverse_ptr` → definition only).
**Corrected severity: high.** The OPSEC agent's `critical` overstates: the query is resolver-mediated, so it identifies the organisation, not the analyst, and for a domain already delivered to users the marginal disclosure is often nil. The correctness agent's `medium` understates: it is the sole violation of the tool's headline constraint and it fires on the most common invocation.
Duplicates: opsec-lens "resolve_domain performs live recursive DNS"; security-lens "Passive-only violation"; docs-lens "Active system-resolver DNS documented only as a convenience".

### 1.8 CONFIRMED — `transport=` disables HTTP/2 and discards the connection limits
Anchor: `utils/http.py:43-49`
Probe H1:
```
with transport=:    http2=False max_conn=100 keepalive=20
without transport=: http2=True  max_conn=50  keepalive=20
AsyncHTTPTransport retries default: 0
```
`retries=0` is already the default, so the `transport=` line buys nothing and costs both HTTP/2 and the intended 50-connection cap. The `if http2:` guard in httpx still requires `h2` (installed, 4.3.0) — paid for in the install, never used. `README.md:23` ("Async & HTTP/2 First") is false as shipped. Note `max_keepalive_connections` happens to survive at 20 only because that is also httpx's default.

### 1.9 CONFIRMED — BGP hijack victim/hijacker attribution is arithmetic on mismatched denominators
Anchor: `providers/cloudflare_rest.py:26-29`
`total` comes from `result_info.total_count` (all pages); `as_hijacker` is counted over `result.events` from a single unpaginated response (no `per_page` sent); `as_victim = total - as_hijacker`. `console.py:247-250` converts the result into the prose "always as a victim" whenever the returned page contains no events where this ASN is the hijacker.
Two adjacent claims also confirmed: `total_h = hj.get("total") or 0` turns a missing `total_count` into the affirmative rendering `"None"` (`console.py:252`); and with no `CLOUDFLARE_API_TOKEN`, `cf_bgp = {"ok": False, "error": "missing_api_token"}` (`orchestrators.py:381`) so `if hj:` is falsy and the hijack/leak rows vanish, while the token-missing note at `cli.py:330` does not fire because `meta` is populated by RIPE/CAIDA/IPinfo.

### 1.10 CONFIRMED — RIPE/PeeringDB failures suppressed, rendered `NONE`, warnings computed then thrown away
Anchors: `orchestrators.py:87-88`, `:539-552`, `:558`; `console.py:207`, `:213-215`; `cli.py:322-341`
`_should_suppress` returns True for any `ripe_*` provider with `error == "network_error"`. `_join_asns` returns the literal `"NONE"` for an empty list, and `render_asn_header` prints `Peering @IXPs ──> NONE` at `:207`. `investigate_asn` computes `ripestat_overview_failed`, `peeringdb_failed` etc. and returns them in `warnings`, and the console branch of `_cmd_asn` never reads `res.warnings`. The JSON branch does carry them (`res.model_dump()` includes `warnings`), so this is console-only — worth stating precisely.

### 1.11 CONFIRMED — API server binds `0.0.0.0` with no authentication
Anchor: `api/server.py:50`
`uvicorn.run(app, host="0.0.0.0", port=8000)`, no middleware, no auth, no rate limit, four routes returning `res.model_dump()` — which includes `data["errors"][provider]["url"]`, i.e. the leaked Shodan/IPinfo key from §1.3. FastAPI serves `/docs` and `/openapi.json` unauthenticated; `README.md:74` advertises this.
**Corrected severity: high, not critical.** This is an opt-in second entry point (`pyproject.toml:24`, `tripper-recon-api`); the CLI never starts it. The key-oracle chain is real but requires the operator to have voluntarily started a server. One precision: driving *VirusTotal* to 429 does not leak the VT key — VT uses an `x-apikey` header. Only Shodan and IPinfo put secrets in the query string.
Duplicates: security-lens "API binds 0.0.0.0 …"; docs-lens "README's REST API section omits …".

### 1.12 CONFIRMED — Domain path forwards private/internal IPs to five third parties
Anchor: `orchestrators.py:253`
`investigate_ip` rejects `is_private` at `:109-110`; `investigate_domain` has no equivalent guard. Every merged IP — from the analyst's resolver or from VT passive DNS — is sent to VirusTotal, Shodan, IPinfo, AbuseIPDB and OTX under the operator's keys. Split-horizon DNS and sinkholed domains resolving to RFC1918 or loopback are the realistic triggers. The secondary claim is also correct: `is_private` does not cover multicast or `240.0.0.0/4`, so even the IP-path guard is narrow.

### 1.13 CONFIRMED — `investigate_domain` is fully sequential per IP
Anchors: `orchestrators.py:253-274`, `:298`
The domain-level VT/OTX pair does overlap (`:204-205` create, `:210/:217` await). Everything after is serial: `for ip in ips:` one at a time, and inside it five bare `await`s with no task creation, plus a conditional Cloudflare call. `investigate_ip` does the same five providers in one wave. `README.md:22` "Concurrent Orchestration" is therefore false for the path an analyst uses to triage a phishing domain. RTT count `1 + K*5` (`1 + K*7` with the Cloudflare string fallback) is correct.
Duplicate: docs-lens "Concurrent Orchestration is false on the domain path".

### 1.14 CONFIRMED — One `AsyncClient` per investigation
Anchors: `orchestrators.py:116`, `:203`, `:339`; `cli.py:150-151`; `api/server.py:25/33/41`
N targets → N independent pools, no shared keepalive, compounded by §1.8 turning HTTP/2 off.

### 1.15 CONFIRMED — No wall-clock deadline anywhere
Anchors: `utils/http.py:47`; `utils/backoff.py:18-27`
`httpx.Timeout(15.0)` sets connect/read/write/pool identically; `with_exponential_backoff` counts attempts, not elapsed time. `cli.py:208` awaits the whole investigation before printing anything.
**Correction to the arithmetic, in the finding's own direction:** OTX passes `timeout=20.0` per request (`otx.py:20`, `:44`), so its worst case is `4*20 + ~4.4 ≈ 84s`, not 64s. The 43-minute figure is a compounded hypothetical requiring all providers to hang for the full timeout across K=8 IPs; it is a valid upper bound, not an expected value.

### 1.16 CONFIRMED — Exit code 0 and "succeeded" when every provider failed
Anchors: `orchestrators.py:190`, `:331`; `cli.py:171-181`, `:201`, `:295`, `:376`
`investigate_ip` returns `ok=True` unconditionally once the IP parses. `_cmd_ip` branches only on `res.ok` and never on `res.errors`. `_cmd_domain` and `_cmd_asn` return 0 on every success path. Any automation keyed on exit status reads a total intelligence blackout as a clean lookup.
Duplicate: analyst-lens "No exit-code contract".

### 1.17 CONFIRMED — Malice is encoded only in ANSI colour, and colour is stripped on redirect
Anchors: `console.py:78-79`, `:95-96`; `cli.py:22`
Probe R5: `Console(file=StringIO).is_terminal = False`, and `[red]MALICIOUS[/]` writes `'MALICIOUS\n'` with no escape sequences. The operator's own captured artefacts confirm the workflow and the loss — `ip_example.md:10` reads `virustotal_detections  5/91` in plain text, carrying no more weight than `postal_code  100000` two lines above. Upgrade the finding's confidence from "likely" to verified.

### 1.18 CONFIRMED — Defanged indicators crash with an unhandled `ValueError`
Anchor: `cli.py:205`
Probe P2:
```
'hxxp://evil[.]com'   -> ValueError: Invalid IPv6 URL
'evil[.]com'          -> hostname=None
'www.evil[.]com/path' -> hostname=None
'123[.]123[.]123[.]123' -> hostname=None
```
`urlparse` is unguarded inside `asyncio.run` with no try/except up the stack, so the scheme-bearing defanged form produces a raw traceback; the bracket-only forms fall through to a bare `"Invalid domain"` (`cli.py:212`) with no hint that brackets are the problem. No `refang` exists anywhere in the tree.

### 1.19 CONFIRMED — No verdict, and decision-relevant signal sits below eight rows of geolocation
Anchors: `console.py:24`, `:41-67`, `:79`
`render_ip_analysis` returns a flat key/value table with no assessment, score or label; `ip_example.md:2-10` shows eight rows of preamble (city, country, isp, organization, coordinates, postal_code, radar link) before the first number that bears on the question, then five signals pointing different directions (VT 5/91, community −37, AbuseIPDB 0% but 5 reports, 50 OTX pulses) with adjudication left to the reader. This is a scope claim rather than a defect, but it is accurate and it is the operator's stated purpose.

### 1.20 CONFIRMED — No defanging of output
Anchors: `console.py:39`, `:163`; `cli.py:224`
Indicator printed raw in rows and titles; six live provider URLs emitted per IP. No `--defang` flag in the parser, no defang helper in the tree. Ticket systems that auto-linkify make the pasted report a one-click path to hostile infrastructure.

### 1.21 CONFIRMED — Four of ten providers undocumented; provider capability claims overstated
Anchors: `README.md:78-87`, `:82`, `:83`, `:84`
README lists six; `orchestrators.py:20-23` imports four more (RIPEstat, CAIDA, PeeringDB, Cloudflare REST BGP), all on the ASN path, three needing no API key. Verified against source: Cloudflare Radar's GraphQL selection set (`cloudflare_radar.py:19-27`) requests `asn name countryCode caidaRank organization abuseContacts rir allocationDate ixps` — no routing, no prefixes; those come from `ripestat.py:33` and `:41`. Shodan extracts `ports, org, tags, cpe` only (`shodan_api.py:23-29`) — no banners, no certificate fingerprints. VT passive DNS and whois exist only on the domain path (`virustotal.py:57-58`), not the IP path (`:24-35`).

### 1.22 CONFIRMED — `"Your Name"` placeholder in `pyproject.toml:10` and `LICENSE:3`
Verified verbatim: `authors = [{ name = "Your Name" }]` and `Copyright (c) 2026 Your Name`, on a public repo whose README was rewritten for portfolio purposes (`db11113`).

---

## 2. Verdicts — corrections (PARTIAL)

### 2.1 PARTIAL — "`TRIPPER_RECON_LOG_LEVEL=INFO` crashes at import"
Anchor: `utils/logging.py:30`; `README.md:97`; `.env.example:22`
The parse is unguarded (`int(os.getenv("TRIPPER_RECON_LOG_LEVEL","20"))`) and `int("INFO")` does raise `ValueError`. But **the README documents the value inside a `.env` file** (`README.md:93-107`), and `load_env()` runs at `cli.py:380` — *after* `logger()` has already executed at module scope (`cli.py:21`, `orchestrators.py:26`). So an operator who follows the README exactly gets **silence, not a crash**: the knob is read too late to have any effect. The crash requires the value to be exported in the shell, which the README does not instruct. Both halves appear inside the findings' bodies; the headline ("the value the README documents crashes at import") is the overstatement. `.env.example:22` uses the numeric form and contradicts the README either way.
Correct framing: *the documented mechanism is non-functional, and the undocumented shell form is fatal.*
Duplicates: security-lens, analyst-lens, and docs-lens versions of the same finding. The docs-lens version states it correctly.

### 2.2 PARTIAL — "No per-provider rate budget … one bulk run exhausts a 500/day quota"
Anchor: `utils/backoff.py:18`
Everything structural is confirmed: `rg "429|Retry-After"` over `tripper_recon/` returns **nothing**; `with_exponential_backoff` retries on bare `Exception` for 4 attempts; VT/Shodan/AbuseIPDB/IPinfo(ip)/OTX call `raise_for_status()` so a 429 becomes a retried `HTTPStatusError`. The green-`0/0` consequence is §1.1.
The overstatement is the worked example. The finding self-labels "VT free tier 4/min" and "500/day" as `[unverified]` — they are quoted from memory, not retrieved, and the "~788 VT requests in ~5s" figure is built on them. Under this repo's own §1.5 that arithmetic cannot be carried into a remediation plan without retrieving VT's published limits. The finding is also substantially a re-statement of §1.1 + §1.4 + §2.3 under a new name.

### 2.3 CONFIRMED (mechanism) — Backoff retries auth failures, ignores `Retry-After`, five providers never retry
Anchor: `utils/backoff.py:21`
Verified provider-by-provider. Raise-and-retry: `virustotal.py:23`, `shodan_api.py:21`, `abuseipdb.py:25`, `ipinfo.py:19`, `otx.py:23`/`:47`. Return-a-dict-and-never-retry on `>=400`: `ripestat.py:18-19`, `caida.py:18-19`, `peeringdb.py:17-18`, `cloudflare_radar.py:38-39`/`:63-64`, `ipinfo.py:67-68` (ASN only). So retry policy is decided by each provider's error *style*, not by status code — a 401 is retried while a genuinely transient 502 from RIPEstat is not. `README.md:24`'s "handling rate limits (429) elegantly" is unsupported by any 429-specific code.
Duplicates: async-lens "Non-retryable 4xx are retried 4x"; docs-lens "Backoff claim about handling 429".

### 2.4 PARTIAL — Cloudflare Radar Int-then-String fallback
Anchor: `providers/cloudflare_radar.py:73-78`
Confirmed: `_call_int` returns a dict on non-200 so the backoff never retries it, and `res.get("ok")` false unconditionally triggers a second serial `with_exponential_backoff(_call_str)` — up to 8 requests and ~8s serialised for one metadata block when the failure is a network error.
The inference is what I am marking down: "*that `orchestrators.py:82-86` already suppresses Cloudflare 400s as expected noise suggests the Int query is routinely wrong*". The suppression rule covers HTTP 400 from *either* variant and from `bgp_incidents` too (`provider.startswith("cloudflare")`); it is not evidence about the Int schema specifically. Settling it needs one live request, which is out of scope here.

### 2.5 PARTIAL (severity) — Browser User-Agent spoofing
Anchors: `utils/http.py:10-31`; `cli.py:384`; `.env.example:24-25`
Behaviour confirmed exactly: a Chrome 141 / Edge Windows UA on every outbound request including authenticated API calls, `--help` text reading "Custom User-Agent string to spoof", and the same string baked into `.env.example`. The reasoning is sound — the key already authenticates the caller, `ripestat.py:26` correctly self-identifies with `sourceapp=tripper-recon`, and CAIDA/PeeringDB get no key at all so the UA is their only identity.
But the OPSEC agent rates this **high** and the security agent rates the identical finding **low**. It is a professionalism, terms-of-service and evidence-chain issue, not a security or passivity defect — the finding itself concedes the UA never reaches the target. **Correct severity: low.** The fix is a one-line default change plus re-wording `cli.py:384`.
Duplicates: security-lens and docs-lens versions.

### 2.6 PARTIAL (severity) — `--prefixes-out` writes to any caller-supplied path
Anchors: `cli.py:360-369`, `:298-301`
Mechanism confirmed. Probe P4 confirms the dead clause: `Path("asn15169.txt").parent` is `PosixPath('.')` and `bool()` of it is `True`, so `if not out_path.parent` is unreachable and only the `== "."` comparison does work. `mkdir(parents=True)` on a supplied parent and unconditional `write_text` with no `exists()` check are as described. `expanduser()` is applied at `cli.py:125` but not here, so `~/out.txt` is taken literally — verified in P4.
The severity is inflated. The path comes from the analyst's own argv on their own workstation; there is no trust boundary and "no containment check" implies one exists to breach. The SOAR-playbook scenario is speculative. The two defects worth fixing are the silent overwrite and the bare-filename fallback writing into the installed package directory (`_default_output_dir` = `Path(__file__).parent.parent/"outputs"`, i.e. `site-packages/outputs/` after the README's own `pip install .`). **Correct severity: low.**
Duplicate: docs-lens "--prefixes-out writes analyst output into the installed package directory" — same code, and that framing is the more useful one.

### 2.7 PARTIAL (severity) — Domain validated in normalised form, consumed raw
Anchor: `utils/validation.py:28`
Probe P3 confirms every stated case: `' evil.com '` → True, `'evil.com\n'` → True, `'evil-.com'` → True, `'münchen.de'` → False, `'пример.рф'` → False, `'example.com/login'` → False, `'example.com.'` → False, `'xn--mnchen-3ya.de'` → True.
The finding is honest that it found no live SSRF, and I agree — every route validates before URL construction and no base URL is user-controlled. On the CLI path `_cmd_domain` re-normalises via `urlparse`/`strip` anyway (`cli.py:205-206`), so the divergence is only reachable through `api/server.py:32`. It is a latent-hygiene finding with no demonstrated impact. **Correct severity: low.**

### 2.8 PARTIAL (severity) — File-target loading reads any readable path
Anchor: `cli.py:124-135`
Mechanism confirmed: silent mode-switch on `Path(value).is_file()`, no size or line cap, every unvalidated line echoed back as `target` in console and JSON. `tripper-recon ip /etc/passwd` does print the file's lines into the artefact.
But the file is one the analyst named, on the analyst's own machine, under the analyst's own privileges. Nothing is escalated. The valuable half is the *usability* consequence the analyst-lens agent isolated: a mistyped `./ips.tx` is silently investigated as an indicator and reports `Invalid IP address` instead of "file not found", and a file named `8.8.8.8` in CWD shadows the literal target. **Correct severity: low.** Duplicate of analyst-lens "A typo'd bulk filename is silently investigated as an indicator".

### 2.9 PARTIAL — `.env` loaded from the current working directory
Anchor: `utils/env.py:15-22`
Confirmed: CWD first, package root second, first match wins, `override=False`. The threat model is a stretch — it needs the analyst to run the tool from an attacker-supplied directory *and* the relevant variables to be absent from the real environment (because `override=False` means anything already exported wins). Consequences are bounded: base URLs are hard-coded so keys cannot be redirected. Real hygiene issue, speculative threat. Severity low is right; I would not raise it further.

### 2.10 PARTIAL — Third-party response bodies echoed into output
Anchors: `providers/cloudflare_radar.py:39`, `:64`; rendered at `cli.py:45`, `console.py:157`
Confirmed that `r.text[:500]` is copied into the error payload and rendered as `body=`. The finding's own confidence is "unsure" and it explicitly disclaims a key leak; I found no evidence one exists. This is the general redaction gap already covered by §1.3, not an independent defect. Keep it as a line item under the redaction fix, not a finding of its own.

### 2.11 PARTIAL — Neighbour lists truncated with no "and N more"
Anchor: `orchestrators.py:509-514`; `console.py:275-277`, `:213-221`
Mechanism confirmed: `_name_list` slices to `resolve_neighbors` (default 8, `cli.py:402`), `render_asn_bgp_panels` prefers the named list, and `_join_asns` computes `more` from the list it is handed — already truncated, so `more == 0` and no suffix prints. Resolving names silently loses information.
The illustration is wrong: for the stated 40-upstream ASN the raw path would print all 40 with **no** "and N more" (the `_join_asns` limit is 60), not "60 entries plus and 32 more". The numbers in the finding do not add up; the defect does.

### 2.12 PARTIAL — `_global_sem` cross-loop binding
Anchor: `utils/http.py:54`
Probe H4 (contended semaphore, repeated `asyncio.run`):
```
run #1: ok
run #2: RuntimeError: <asyncio.locks.Semaphore [locked]> is bound to a different event loop
```
Probe H5 (uncontended, the current behaviour): three consecutive `asyncio.run` calls all succeed — `_get_loop()` is only reached when a waiter is created. So the finding's central claim is right and its framing is right (dormant *only* because §1.4 means the limiter never blocks), but the reproduction detail differs: I hit it on run #2, not run #3. Latent, and it detonates the moment the limiter fix lands. Sequencing matters.

### 2.13 PARTIAL — `render_asn_header` `AttributeError` on a string organization
Anchor: `console.py:168`; `providers/ipinfo.py:77`; `orchestrators.py:436-440`
Probe R6:
```
render_asn_header(15169, {"organization": "Google LLC"})              -> AttributeError: 'str' object has no attribute 'get'
render_asn_header(15169, {"name":"GOOGLE","organization":"Google LLC"}) -> no exception
```
So the crash is real but strictly conditional on `meta["name"]` being falsy — Python short-circuits the `or` at line 168. IPinfo does return `org` as a plain string when `company` is not a dict (`ipinfo.py:77`), and the merge at `:436-440` fills any key Cloudflare left empty. The finding states the condition correctly in its body. `console.py:189`'s `isinstance(org, dict)` guard twenty-one lines later is good evidence of the oversight.

### 2.14 REFUTED — "Built package metadata declares License: Proprietary"
Anchor: `tripper_recon.egg-info/PKG-INFO:6`
The string is there. It does not describe the current package. `tripper_recon.egg-info/` is untracked build output (`git ls-files | grep egg-info` → 0 matches) generated before commit `c10dd8e` ("chore: apply MIT license"), which is what added `license = { text = "MIT" }` to `pyproject.toml:12`. A rebuild from the current tree will not emit `License: Proprietary`. The finding's own confidence is "unsure" and it names the right test.
The residue that survives: `PKG-INFO` has no `License-File` entry (verified, 0 matches), so `LICENSE` is not shipped in the distribution — but that is a `license-files` configuration gap in `pyproject.toml`, not a licensing contradiction. **Downgrade to low and re-scope to "add `license-files = ["LICENSE"]`".**

---

## 3. Verdicts — confirmed without correction (compressed)

Each verified by direct source reading or the probe noted. No corrections.

| Claim | Anchor | Evidence |
|---|---|---|
| JSON log records written to stdout, corrupting `-o json` | `utils/logging.py:42` | `sys.stdout.write(json.dumps(record))`; `cli.py:144/:161/:172` log unconditionally (not gated on `output`), `cli.py:196` writes the payload to the same stream |
| IDN / path-bearing / trailing-dot domains rejected | `utils/validation.py:24` | Probe P3, all cases |
| OTX queried with the IPv4 indicator endpoint for every address | `providers/otx.py:20` | Path literal `indicators/IPv4/`; no address-family branch anywhere; `investigate_ip` accepts IPv6 (`:104-113` rejects only private) |
| `--monochrome` and `--enrich` are no-ops | `cli.py:403`, `:405`; `console.py:167`, `:224` | `rg use_color` → 2 signatures + 2 call sites, zero body references; `orchestrators.py:529-537` self-labels "placeholder aggregation"; `rg inetnums` → written at `:537`, never rendered |
| Passive VT DNS merged with live-resolved IPs, no provenance; `ptr` always null | `orchestrators.py:249`, `:254`, `:309-318` | `ptr = None` never reassigned; `rg reverse_ptr` → definition only |
| WHOIS rendering drops every field outside a 14-key allow-list | `cli.py:76-89` | Parses all `key: value` lines, prints only `priority`; no omission notice |
| Certificate header prints for domains with no certificate | `cli.py:92`; `virustotal.py:84-95` | The dict is always constructed with all keys present, so it is always truthy |
| Dead code, dead params, unused imports, hardcoded API version | `console.py:10`; `cli.py:5-6,12`; `dns.py:5`; `api/server.py:3`, `:15` | `rg` confirms `_fmt_ports`, `reverse_ptr`, `use_color` uncalled/unread; `json`, `os`, `Panel` (cli), `Tuple`, `asyncio` (server) unused; `pyproject.toml:7` / `__init__.py:5` / `server.py:15` all `0.1.0` — no drift **today**, one bump from it |
| 23 duplicated try/await/except blocks | `orchestrators.py:132` | `grep -c "except Exception"` → **23** |
| `resolve_domain` untimed, serialises A then AAAA in one uncancellable thread | `utils/dns.py:12-23` | Two blocking `getaddrinfo` calls in one `to_thread`, no `wait_for`; on the critical path at `:248` |
| `investigate_asn` runs two serial waves; up to 24 unbounded neighbour lookups | `orchestrators.py:383-385`, `:493-501` | Wave 1 created `:341-353` and fully awaited `:355-381` before `:383` creates three independent RIPEstat calls; `to_resolve` is the union of three 8-element slices, gathered unbounded |
| `CancelledError` misclassified in `_cmd_ip` | `cli.py:158` | `isinstance(item, Exception)` is False for `CancelledError` (BaseException since 3.8); falls through to `res.ok` → `AttributeError`. Latent: nothing currently cancels a child |
| PeeringDB does 1+N serial GETs inside one retried closure | `providers/peeringdb.py:16`, `:27`, `:41` | Whole closure wrapped in `with_exponential_backoff`, so a failure on the last sub-request replays every earlier one; queried unauthenticated |
| Bulk output withheld until the slowest target completes; no progress indicator | `cli.py:150-157` | `asyncio.gather` then render loop; only `Processing N targets` is printed up front |
| Bulk summary counts plumbing, not threat | `cli.py:198-199` | `total= succeeded= failed=` only |
| Shodan `tags`/`cpe` and VT `vt_tags` collected then discarded | `shodan_api.py:29`; `virustotal.py:79` | `rg "tags\|cpe"` over `console.py` and `cli.py` → **zero matches** |
| No timestamp, tool version, or coverage line in any output | `console.py:163` | Header is `--- IP lookup for {ip} ---` and nothing else; `__version__` never reaches output |
| No markdown output format; README's markdown claim untrue | `cli.py:390/:395/:401`; `README.md:26` | `choices=["console","json"]`; `ip_example.md` is space-padded plain text |
| README advertises URL investigations; no `url` subcommand or route | `README.md:5`; `cli.py:388-407`; `api/server.py:23-44` | Three subparsers (`ip`, `domain`, `asn`), four routes |
| `--rate-limit` / `--user-agent` rejected after the subcommand and absent from subcommand help | `cli.py:383-384` | Probe P1: `ip 8.8.8.8 --rate-limit 5` → `SystemExit 2`, "unrecognized arguments" |
| No tests, CI, linter, type checker, pre-commit or secret scanning | `pyproject.toml:31` | `find . -name "*test*"` → none; no `.github/`; no `[tool.ruff]`/`[tool.mypy]`/`[tool.pytest…]`/`[project.optional-dependencies]`; 28 tracked files |
| Dependencies floor-pinned, no ceilings, no lockfile | `pyproject.toml:13-20` | All six `>=`. Note §1.3 and §1.8 are both httpx-version-dependent behaviours |
| `.gitignore` blocks legitimate files, misses the format the tool emits | `.gitignore:85-92` | `git check-ignore -v` confirms `tests/fixtures/sample.json`, `tests/data/expected.csv`, `package.json`, `CHANGELOG.txt`, `docs/notes.txt` all ignored; `ip_example.md` **not** ignored; the three untracked example captures are `.md` |
| No provenance or freshness on any fact | `types/models.py:35` | Envelope is `ok/data/warnings/errors`; `shodan_api.py:22-29` and `virustotal.py:24-35` discard `last_update` / `last_analysis_date` |
| Nothing discloses which third parties see each indicator; no OPSEC statement | `README.md:78`, `:16` | Words "passive", "OPSEC", "does not contact the target" appear nowhere in README. The VT half is right: only GETs of existing reports, no `POST /urls`, `/files` or `/analyses` |
| `--enrich` pre-authorises a whois path that does not exist | `cli.py:403`; `orchestrators.py:529-537` | Help says "whois/pWhois"; implementation slices already-fetched RIPE lists |
| No `CONTRIBUTING`/`CHANGELOG`/`SECURITY.md`; `domain_example.md` is 0 bytes | `README.md:108` | `ls -la` confirms 0-byte file; three example captures untracked |
| No subpackage `__init__.py`, no `py.typed` | `api/server.py:15` | `find tripper_recon -name __init__.py` → **one** file; no `py.typed` anywhere |

---

## 4. Duplicate map

Twelve distinct defects were reported between two and four times each across the six lenses. Consolidate before filing beads, or the backlog will carry ~40 redundant items.

| Canonical | Restated as |
|---|---|
| Green `0/0` for absent provider | analyst-lens "Missing API key renders as a green 0/0"; second half of async-lens "No per-provider rate budget" |
| RateLimiter no-op / `--rate-limit` dead | async-lens "RateLimiter constrains nothing"; opsec-lens "--rate-limit is silently ignored"; security-lens "Rate limiter is a no-op and file input fans out"; aggravating paragraph of analyst-lens "Bulk run shows no progress" |
| Keys in `_error_payload` | security-lens "Provider API keys echoed verbatim"; enabling half of security-lens "API binds 0.0.0.0" |
| Active DNS against target | opsec-lens "resolve_domain performs live recursive DNS" (critical); security-lens "Passive-only violation" (high); docs-lens "documented only as a convenience" (high); correctness-lens (medium) |
| API server `0.0.0.0` | opsec-lens, security-lens, docs-lens |
| Logs to stdout | correctness-lens, security-lens, analyst-lens, docs-lens (4×) |
| `TRIPPER_RECON_LOG_LEVEL` | correctness-lens, security-lens, analyst-lens, docs-lens (4×) |
| Global `-o/--format` shadowed | correctness-lens, analyst-lens, third clause of docs-lens "Three --help entries are wrong" |
| `--monochrome` / `--enrich` no-ops | correctness-lens, opsec-lens (`--enrich` only), analyst-lens (`--monochrome` only), docs-lens |
| UA spoofing | opsec-lens (high), security-lens (low), docs-lens (medium) |
| Passive/live IP merge without provenance | correctness-lens, analyst-lens, and the method half of opsec-lens "No provenance or freshness label" |
| No tests / CI | security-lens, docs-lens |
| `--prefixes-out` | security-lens (path containment), docs-lens (writes into site-packages) — same code, two framings |
| `reverse_ptr` dead + `ptr` always null | stated inside four separate findings across three lenses |
| README "URL" claim | correctness-lens (as a trailing note), analyst-lens, docs-lens (rated critical) |
| Sequential domain path | async-lens, docs-lens |

---

## 5. Sequencing note the findings imply but none state outright

Three defects are coupled and must land in one change or in a declared order:

1. Fixing the limiter (§1.4) alone makes the semaphore actually contend, which **activates** the dormant cross-loop `RuntimeError` (§2.12). Build the limiter inside the running loop in the same commit.
2. Fixing the limiter without a per-provider budget converts a slow bulk run into a faster quota breach (§2.2/§2.3).
3. Adding `asyncio.wait_for` per target (§1.15) makes the `CancelledError` misclassification (`cli.py:158`) reachable for the first time.

The redaction fix (§1.3) has no such coupling and is the highest value-per-line change in the set: one helper inside `_error_payload` covers all four rendering sinks at once.
