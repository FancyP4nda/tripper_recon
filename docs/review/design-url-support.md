# Design: URL and Indicator-Type Support for `tripper_recon`

Review scope: URL support, automatic indicator-type detection, defanged input, passive URL verdict
sources, url→host→IP→ASN pivoting, redirect/shortener handling, and bulk paste mode.

Repo state reviewed: `/home/echo/dev/tripper_recon` @ `feat/work-20260808-recon-hardening`. Read-only.
No tool execution against any live target; no network calls made. `.env` was never opened.

---

## 1. Headline

Build the URL command **behind a hard egress allowlist**, not alongside one. The single most
valuable change here is not the `url` subcommand — it is making "passive only" a property the code
*enforces* rather than a property the author *intends*. Today nothing in the codebase prevents any
provider module from connecting to an indicator, and one code path (`utils/dns.py:14`) already
does. A URL command multiplies that risk, because a URL literally carries a fetchable address as
its payload.

Ordering that matters: **egress allowlist first (§7), then indicator typing (§4), then the URL
command (§8–§10), then bulk mode (§11).** Shipping URL support before the allowlist ships the
capability and the footgun together.

---

## 2. What exists today

| Capability | Where | Notes |
|---|---|---|
| `ip` subcommand | `cli.py:388-391`, `cli.py:420-421` | Accepts a single IP **or a file path** of IPs (`cli.py:124-135`) |
| `domain` subcommand | `cli.py:393-396`, `cli.py:422-423` | Normalises via `urlparse` at `cli.py:205-206` |
| `asn` subcommand | `cli.py:399-407`, `cli.py:424-444` | Strips a leading `as`/`AS` at `cli.py:426-427` |
| Orchestrators | `orchestrators.py:103`, `:193`, `:334` | `investigate_ip`, `investigate_domain`, `investigate_asn` |
| Validators | `utils/validation.py:8-28` | `is_valid_ip`, `is_valid_asn`, `is_valid_domain` only |
| Query models | `types/models.py:23-33` | `IPQuery`, `DomainQuery`, `ASNQuery` only |
| REST routes | `api/server.py:23-44` | `/ip/{ip}`, `/domain/{domain}`, `/asn/{asn}` |
| Shared HTTP client | `utils/http.py:41-51` | One `create_client()` used by every provider |

**There is no URL support of any kind.** No `url` subcommand (`cli.py:386-407` defines exactly
three), no `investigate_url` (`orchestrators.py` defines exactly three orchestrators), no URL
validator, no URL query model, no URL route, and no VirusTotal URL provider function
(`providers/virustotal.py` exposes only `vt_ip_summary:13` and `vt_domain_summary:40`).

`README.md:5` nevertheless advertises the tool as *"an asynchronous OSINT toolkit for IP, Domain,
**URL**, and ASN investigations."* That is a documented capability that does not exist. The
operator's stated goal ("Is this IP / domain / **URL** malicious?") is currently answerable for two
of the three indicator classes.

---

## 3. Defects found while designing this

These are grounded observations, each anchored. They shape the design that follows.

### 3.1 [HIGH] Defanged input crashes the `domain` command

`cli.py:205` calls `urlparse(domain)` with no exception handling. Python's `urlsplit` raises on a
`[` in the netloc (`_check_bracketed_netloc`, "Invalid IPv6 URL"). Verified offline:

```
INPUT                                    | RESULT
hxxps://evil[.]com/pay                   | *** CRASH ValueError: Invalid IPv6 URL
```

An analyst pasting a defanged URL straight out of a phishing report — the single most common way a
URL arrives at a SOC analyst — gets an unhandled traceback. `_cmd_domain` has no `try`, and `main()`
(`cli.py:409-447`) has no top-level handler, so this exits with a stack trace rather than a message.

### 3.2 [HIGH] Active DNS resolution against the target on every domain investigation

`orchestrators.py:247-248` calls `resolve_domain(domain)` unconditionally. That lands in
`utils/dns.py:8-23`, which calls `socket.getaddrinfo(domain, ...)` for `AF_INET` and `AF_INET6`.

This is a live DNS lookup through the system resolver. Against attacker-controlled authoritative
nameservers this is an observable event: the operator's resolver (and, for many enterprise
configurations, an IP attributable to the operator's organisation) appears in the adversary's
authoritative query logs. Fast-flux and phishing kits are commonly instrumented to notice exactly
this. The task brief flags this as a grey area; on the evidence it is a real leak and the only code
in the repo that touches target-controlled infrastructure.

Note it is **not** gated, not flagged in output, and not documented — `README.md:55-56` describes it
neutrally as "automatically resolves IPs." Passive substitutes already exist in the same function:
`orchestrators.py:227-235` harvests A/AAAA records from VirusTotal's `last_dns_records`, and the two
sets are merged at `orchestrators.py:249` with no provenance marker distinguishing actively-resolved
IPs from passively-observed ones.

### 3.3 [MED] `RateLimiter` does not limit concurrency

`orchestrators.py:120-129` uses the limiter as `async with limiter: task = asyncio.create_task(...)`.
The semaphore is released the moment the task is *created*, not when the request completes. All five
provider calls therefore run fully concurrently regardless of the limit. Compounding this,
`utils/http.py:61-66` caches `_global_sem` on first construction, and `orchestrators.py:117` passes
`rate=5` explicitly — so the CLI's `--rate-limit` (`cli.py:383`, applied at `cli.py:415`) is silently
ignored on the IP path. This matters directly for bulk mode (§11), which cannot be built safely on a
limiter that does not limit.

### 3.4 [MED] Unbounded fan-out in the existing bulk path

`cli.py:150-151` builds one `investigate_ip` task per line of the input file and `asyncio.gather`s
them all at once. A 500-line paste from an alert issues 500 concurrent investigations × 5 providers.
With §3.3, nothing throttles this. Expect provider 429s and, on paid keys, quota burn.

### 3.5 [LOW] OTX indicator type is hardcoded to IPv4

`providers/otx.py:20` requests `/indicators/IPv4/{ip}/general` for every IP. `is_valid_ip`
(`validation.py:8-13`) accepts IPv6, and `investigate_ip` will happily proceed with one, sending an
IPv6 address to the IPv4 indicator endpoint. This is the existing code already needing the
indicator-type discrimination this design introduces.

### 3.6 [LOW] AbuseIPDB link emitted for domains

`cli.py:257` prints `https://www.abuseipdb.com/check/{norm_domain}`. AbuseIPDB is an IP reputation
service; a domain check link is misleading in an incident report.

### 3.7 [INFO] Browser User-Agent spoofing is the wrong default for a passive tool

`utils/http.py:10-14` defaults every outbound request to a Chrome/Edge UA string, echoed in
`.env.example`. For calls to VirusTotal and Shodan this is merely odd. It becomes dangerous the
moment any URL-fetching code exists: a browser UA is precisely what makes a request to an
adversary's server look like a real victim rather than a scanner, which is the opposite of what a
passive tool wants. Recommend defaulting to an honest `tripper-recon/<version>` UA for provider
calls and keeping the spoof flag documented as unnecessary.

---

## 4. Indicator model and automatic type detection

### 4.1 The goal

One command an analyst can paste *anything* into:

```bash
tripper-recon check 185.220.101.5
tripper-recon check 'hxxps://evil[.]com/login.php?id=7'
tripper-recon check AS15169
tripper-recon check 44d88612fea8a8f36de82e1278abb02f
```

Keep `ip` / `domain` / `asn` / `url` as explicit subcommands (they are unambiguous and scriptable);
add `check` as the auto-detecting front door. `check` never guesses silently — it prints the detected
type and, when detection was ambiguous, what it rejected and why.

### 4.2 Proposed type set

New module `tripper_recon/types/indicators.py`:

```python
class IndicatorType(str, Enum):
    IPV4 = "ipv4"; IPV6 = "ipv6"; CIDR = "cidr"
    DOMAIN = "domain"; URL = "url"; EMAIL = "email"; ASN = "asn"
    MD5 = "md5"; SHA1 = "sha1"; SHA256 = "sha256"
    UNKNOWN = "unknown"

@dataclass(frozen=True)
class Indicator:
    raw: str              # exactly as the analyst pasted it
    type: IndicatorType
    value: str            # normalised canonical form
    defanged_input: bool  # raw required refanging
    confidence: str       # "certain" | "probable"
    notes: list[str]      # e.g. "port 8080 stripped from host", "ambiguity: bare hex 32"
    parts: dict           # type-specific: url scheme/host/port/path/query, cidr prefixlen…
```

Carrying `raw` alongside `value` is not decoration — the incident report must be able to show what
was pasted and what was investigated. A tool that silently rewrites an analyst's input is a tool
whose output cannot be defended in a case write-up.

### 4.3 Detection order

Order matters because the classes overlap. Refang first (§6), then classify. Test most-specific
first:

1. **ASN** — `^AS\d+$` (case-insensitive) or bare integer in `1..4294967294`. Reuse
   `is_valid_asn:16` and the strip logic already at `cli.py:426-427`.
2. **CIDR** — `ipaddress.ip_network(v, strict=False)` succeeds. Verified: `ip_address()` rejects
   `185.220.101.0/24`, so today it falls through every validator to "Invalid domain".
3. **IP** — `ipaddress.ip_address()`; split IPV4/IPV6 by `.version` so `providers/otx.py:20` can
   finally select the right endpoint (§3.5).
4. **Hash** — `^[a-fA-F0-9]{32|40|64}$` → MD5 / SHA1 / SHA256.
5. **URL** — has a scheme in `{http, https, ftp}` **or** matches `host + '/' + path`. This second
   arm is what fixes `evil.com/a/b`, which today normalises to itself and fails `is_valid_domain`
   (verified below).
6. **Email** — single `@`, RHS is a valid domain.
7. **Domain** — `is_valid_domain:27`, after trimming a trailing root dot.
8. Else `UNKNOWN`, with an error listing what was tried.

### 4.4 Verified current behaviour (offline, no network)

Ran `urlparse` + the repo's exact `_domain_re` (`validation.py:24`) over realistic paste inputs.
The `cli _cmd_domain norm` column replicates `cli.py:205-206`:

```
INPUT                                    | norm                       | is_valid_domain
https://evil.com/a/b?x=1                 | evil.com                   | True
evil.com/a/b                             | evil.com/a/b               | False   <- bare URL rejected
hxxps://evil[.]com/pay                   | *** CRASH ValueError       | -       <- §3.1
evil[.]com                               | evil[.]com                 | False
evil(.)com                               | evil(.)com                 | False
http://185.220.101.5:8080/x              | 185.220.101.5              | False   <- IP host, wrong path
https://user:pw@evil.com/p               | evil.com                   | True    <- creds dropped silently
https://xn--80ak6aa92e.com/              | xn--80ak6aa92e.com         | True
1.2.3.4                                  | 1.2.3.4                    | False
AS15169                                  | AS15169                    | False
44d88612fea8a8f36de82e1278abb02f         | 44d8...                    | False
a@evil.com                               | a@evil.com                 | False
185.220.101.0/24                         | 185.220.101.0/24           | False
2001:4860:4860::8888                     | 2001:4860:4860::8888       | False
http://[2001:db8::1]:8080/x              | 2001:db8::1                | False
HTTPS://EVIL.COM/A                       | evil.com                   | True
evil.com.                                | evil.com.                  | False
```

Two conclusions. First, `_cmd_domain`'s `urlparse` is doing accidental, partial URL handling that
succeeds on the easy case and fails or crashes on most realistic ones. Second, a URL whose host is
an IP literal (`http://185.220.101.5:8080/x`) currently routes into the *domain* orchestrator and
dies at `is_valid_domain` — the design must route URL-with-IP-host to the IP path for the pivot.

### 4.5 Ambiguity — say so, do not guess

Genuinely ambiguous inputs and the required behaviour:

| Input | Ambiguity | Behaviour |
|---|---|---|
| `15169` | ASN or a label | Treat as ASN, `confidence="probable"`, note it. `AS15169` is `certain` |
| `example.co` | domain or truncated | Domain, `certain` (valid TLD) |
| 32 hex chars | MD5 or a hostname-shaped token | Hash, note "also parses as a bare label" |
| `1.2.3.4.5` | neither IP nor plausible domain | `UNKNOWN`, list attempts |
| `localhost`, `10.0.0.5` | private / non-routable | Reject **before** any provider call; `investigate_ip` already does this for private IPs at `orchestrators.py:109-110` — extend to the detector so it also covers loopback, link-local, CGNAT, and RFC1918 hosts inside URLs |

`--type <t>` forces classification and skips detection. `--explain` prints the detection trace. Both
are cheap and both save an analyst arguing with the tool under time pressure.

---

## 5. Parsing and normalising a URL without fetching it

Parsing is pure string work. Nothing here touches the network — but the code must be written so that
staying offline is obvious to a reviewer.

```python
def parse_url(raw: str) -> Indicator:
    refanged, was_defanged = refang(raw)          # §6
    if "://" not in refanged:
        refanged = "http://" + refanged           # note it; do NOT claim the scheme was observed
    p = urlsplit(refanged)                        # wrap in try/except -> §3.1
    host = (p.hostname or "").rstrip(".").lower() # IDNA-normalise, see below
    port = p.port or (443 if p.scheme == "https" else 80)
    ...
```

Rules:

- **Wrap `urlsplit` in `try/except ValueError`.** Non-negotiable given §3.1.
- **Assumed scheme is recorded, never asserted.** If the analyst pasted `evil.com/a`, the report says
  `scheme: http (assumed — not present in input)`. Getting this wrong changes the VirusTotal URL
  identifier (§8.2) and therefore whether a report is found at all.
- **Lowercase scheme and host only.** Path and query are case-sensitive and often carry the campaign
  identifier. `HTTPS://EVIL.COM/A` → `https://evil.com/A`.
- **Strip the trailing root dot** on the host (`evil.com.` → `evil.com`).
- **IDNA / punycode:** record both `xn--80ak6aa92e.com` and its Unicode form, and flag mixed-script
  hosts. Homograph phishing is a finding in itself, and the analyst needs both forms for the report.
- **Preserve userinfo separately.** `https://user:pw@evil.com/p` currently loses the credentials
  entirely. Embedded credentials are a phishing signal; surface them as
  `userinfo_present: true` and keep the value out of any logged URL string.
- **Keep the default port implicit but recorded.** `parts.port_explicit` distinguishes
  `http://evil.com:80/` from `http://evil.com/` — this changes the VT identifier.
- **Do not decode percent-escapes for the canonical value.** Decode only into a separate
  `path_decoded` display field. Re-encoding differently from the original breaks lookups.
- **Extract, do not follow:** flag `query` parameters that themselves contain URLs (open-redirect
  pattern, `?next=`, `?url=`, `?redirect=`) and offer them as *new candidate indicators* for the
  analyst to run, never as something the tool resolves itself (§10).

Everything above is stdlib. Add no dependency for this.

---

## 6. Defanged input

Analysts paste defanged indicators constantly; they are the normal case, not the edge case. Refanging
is a pure string transform and must run before detection.

Transform table (apply in this order, case-insensitively):

| Defanged | Refanged | Notes |
|---|---|---|
| `hxxp://`, `hxxps://`, `hXXp://` | `http://`, `https://` | Also `h**p`, `httx` seen in the wild |
| `[.]`, `(.)`, `{.}`, `[dot]`, `(dot)`, ` dot ` | `.` | `[dot]` is common in email-derived reports |
| `[:]`, `[://]` | `:`, `://` | |
| `[@]`, `(at)`, `[at]` | `@` | For emails |
| `[/]`, `[//]` | `/`, `//` | |
| Leading/trailing `<`, `>`, `"`, `'`, backticks | stripped | Paste artefacts from mail clients |
| Zero-width chars `U+200B/C/D`, `U+FEFF` | removed | Very common in copied HTML |
| Non-breaking space `U+00A0` | ordinary space | |

Rules:

1. **Set `defanged_input=True` and keep `raw`.** The report shows both. An analyst must be able to
   confirm the tool investigated the thing they meant.
2. **Refang only for lookup — never re-emit refanged.** All console and JSON output should print the
   URL **defanged** by default (`--fanged` to override), so an incident report, a ticket, or a chat
   message containing tool output cannot be click-launched by the next reader. This is a real
   incident-handling failure mode and cheap to prevent.
3. **Refang is not decoding.** Do not attempt base64/hex de-obfuscation of the whole indicator
   automatically; that guesses at intent. Offer `--decode-candidates` as an explicit, separate action.
4. **Idempotent and lossless-flagged.** `refang(refang(x)) == refang(x)`, and if a transform fires,
   record which one in `notes` so a mis-refang is debuggable.

Unit-testable in isolation with zero network. This is the easiest high-value component in the whole
design and should land first.

---

## 7. The passivity control: an egress allowlist (do this first)

Everything in §8–§11 is safe only if the tool structurally cannot connect to a target. Right now it
has no such control: `create_client()` (`utils/http.py:41-51`) returns a general-purpose
`httpx.AsyncClient` and any module may call `.get()` on any URL with it.

**Recommendation.** Enforce a provider allowlist at the single HTTP chokepoint:

```python
_ALLOWED_HOSTS = frozenset({
    "www.virustotal.com", "api.shodan.io", "api.abuseipdb.com", "ipinfo.io",
    "otx.alienvault.com", "api.cloudflare.com", "stat.ripe.net",
    "api.asrank.caida.org", "www.peeringdb.com",
    # URL additions:
    "urlhaus-api.abuse.ch", "safebrowsing.googleapis.com",
    "checkurl.phishtank.com", "urlscan.io",
})

async def _enforce_allowlist(request: httpx.Request) -> None:
    if request.url.host not in _ALLOWED_HOSTS:
        raise PassiveBoundaryViolation(
            f"blocked egress to non-provider host {request.url.host!r}"
        )
```

Wire it as an `httpx` request event hook on the client built in `create_client()` — one place, every
provider inherits it, and it fails closed. Add a test that asserts
`client.get("http://evil.example/")` raises. That test is the artefact that makes "passive only"
a claim the repo can *defend* rather than assert.

Two consequences worth accepting deliberately:

- **DNS (§3.2) must come under the same policy.** An allowlist on HTTP does not stop
  `socket.getaddrinfo`. Recommend: remove the active resolve from the default path, mark
  passively-sourced IPs with `source: "vt_passive_dns"`, and put active resolution behind an explicit
  `--active-dns` flag that prints a warning naming the leak. If the operator wants resolution without
  the leak, a passive substitute is a DoH query to a provider on the allowlist — that resolves via a
  third party rather than the target's authoritative servers, though it still discloses interest to
  that third party. State that tradeoff in the docs rather than hiding it.
- **The allowlist is a maintenance surface.** Provider hostnames change. Keep it in one module with a
  comment per entry naming the provider, and fail with an actionable message.

---

## 8. Passive sources for a URL verdict

### 8.1 The distinction that governs everything: who do you connect to?

The brief asks for the GET-vs-POST distinction to be made explicit. State it precisely, because the
naive version of the rule is wrong:

> **The HTTP verb is not what makes a lookup active. The destination is.**

- `GET https://www.virustotal.com/api/v3/urls/{id}` — connects to VirusTotal, asks for a report that
  already exists. **Passive.** The target learns nothing.
- `POST https://www.virustotal.com/api/v3/urls` with `url=<target>` — connects to VirusTotal, and
  **instructs VirusTotal to fetch the target URL**. The target's server receives a real HTTP request
  from VT infrastructure, with timing that correlates to the analyst's action. **Active by proxy**,
  and additionally it publishes the URL into VT's public corpus, which can tip off an adversary
  monitoring for their own indicators. **Never call this.**
- `POST https://safebrowsing.googleapis.com/v4/threatMatches:find` — a POST, but only ever to
  Google, which answers from its own blocklist. **Passive**, despite the verb.

So the rule the code enforces is the allowlist (§7): *never connect to the indicator*. The rule the
code must additionally enforce is: *never ask a provider to connect to the indicator on your behalf*.
The second one cannot be enforced by a hostname allowlist — it needs a per-provider audit, because
it is a property of the endpoint's semantics. Recommend annotating every provider function with an
explicit marker and asserting on it:

```python
@passive(reason="GET on existing report; 404 if VT has never seen the URL")
async def vt_url_summary(...): ...

# Endpoints deliberately NOT implemented, with the reason recorded in-repo:
#   POST /api/v3/urls              -> submits target for live fetch by VT
#   POST /api/v3/urls/{id}/analyse -> triggers re-scan (live fetch)
#   POST /api/v1/scan/ (urlscan)   -> live browser visit to target
```

Writing the forbidden endpoints down *in the source*, next to the allowed ones, is what stops a
future contributor from "improving" coverage by adding a submit call.

### 8.2 VirusTotal URL lookup

Identifier: VT v3 addresses a URL by an id derived from the URL string — the unpadded base64url
encoding of the exact URL. Verified the encoding locally:

```
https://evil.com/a/b?x=1  ->  aHR0cHM6Ly9ldmlsLmNvbS9hL2I_eD0x
http://evil.com/          ->  aHR0cDovL2V2aWwuY29tLw
```

(Note the `_` and the stripped `=` padding — a plain `b64encode` will produce a wrong id for URLs
containing `?` or `/` in the query.)

```python
def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
```

`GET {VT_BASE}/urls/{vt_url_id(url)}` with the `x-apikey` header, following the exact shape of
`vt_domain_summary` (`providers/virustotal.py:40-101`) — same `with_exponential_backoff` wrapper
(`utils/backoff.py:10`), same `{"ok": bool, "data"|"error"}` envelope, same `404 -> not_found`
handling at `virustotal.py:48-49`.

**A 404 here is a meaningful, reportable result, not an error:** "VirusTotal has no existing report
for this URL." The correct analyst-facing rendering is *unknown*, never *clean*. Suppressing it the
way `_should_suppress` (`orchestrators.py:73-89`) suppresses missing-key errors would be wrong —
this one belongs in the report.

Fields worth surfacing: `last_analysis_stats`, `reputation`, `categories`, `last_final_url`
(**read it, do not follow it** — see §10), `times_submitted`, `first_submission_date`,
`last_submission_date`, `title`, and the `tags`. Submission dates are load-bearing for an incident
timeline: "first seen by VT 40 minutes ago" is a much stronger phishing signal than the detection
count on a fresh URL.

> **Verify before implementing.** The base64url identifier scheme, the exact attribute names, and
> whether VT also accepts a SHA-256-of-URL identifier should be confirmed against the current
> VirusTotal v3 API documentation. I could not verify these against live docs within the constraints
> of this review, and the encoding test above only proves what Python produces, not what VT accepts.

### 8.3 URLhaus (abuse.ch)

Purpose-built for malicious-URL lookup and strong on malware distribution and payload linkage. The
lookup endpoint takes the URL as a form field and answers from abuse.ch's database — it does not
fetch the target. Useful returns: `url_status` (online/offline), `threat`, `tags`, `date_added`,
`reporter`, and the linked `payloads` with their hashes, which give the analyst a direct URL→sample
pivot no other source here provides.

> **Verify:** abuse.ch moved its APIs behind an `Auth-Key` requirement. Confirm the current auth
> model and endpoint path before implementing, and add `URLHAUS_AUTH_KEY` to `.env.example` alongside
> the existing keys (`.env.example` currently lists six).

### 8.4 Google Safe Browsing

The Lookup API (`threatMatches:find`) answers "is this URL on Google's blocklist" — the same verdict
that drives the browser interstitial, which is exactly the fact an analyst needs when a user says
"I clicked it."

Two caveats to document rather than bury:

1. **It transmits the full URL to Google.** That is a third-party disclosure of the indicator,
   including any tokens embedded in the path or query (phishing URLs routinely carry the victim's
   email address as a parameter). For some incidents that is an acceptable trade; for others it is
   not. Recommend a `--no-third-party-url-share` flag that skips GSB and PhishTank while keeping
   sources that take a hash or an already-public identifier.
2. The Update API is the hash-prefix variant that avoids sending the URL, at the cost of maintaining
   a local database. Out of scope for a CLI, but worth naming in the docs so the choice looks
   deliberate.

> **Verify:** current API version (v4 vs v5), the `threatTypes`/`platformTypes` enums, and quota
> terms before implementing.

### 8.5 PhishTank

Community phishing corpus; a positive hit is high-confidence and a *verified* hit carries a human
review. Value is narrow but the precision is good.

> **Verify:** PhishTank has restricted new API key registration at various points. Confirm key
> availability first — if unobtainable, implement it as a "link out only" source (emit the
> `phishtank.com/phish_search` URL, the way `cli.py:256-257` already emits VT and AbuseIPDB links)
> rather than a dead provider that always errors.

### 8.6 urlscan.io — search only, never scan

This is the sharpest active/passive boundary in the design.

- `GET /api/v1/search/?q=page.url:"<target>"` (or `page.domain:`, `task.url:`) — queries urlscan's
  index of **already-completed public scans**. **Passive.**
- `GET /api/v1/result/{uuid}/` — retrieves an existing result. **Passive.** This is extremely
  valuable: someone else's scan gives you the redirect chain, the final URL, the page title, the
  contacted domains and IPs, and a screenshot — *all of the things you would otherwise fetch the URL
  to learn*. A cached urlscan result is the passive answer to §10.
- `POST /api/v1/scan/` — **submits the URL for a live browser visit.** The target is fetched. On a
  public submission the URL also becomes visible in urlscan's public feed, which adversaries monitor.
  **Never implement this**, not even behind a flag, in a tool whose contract is passive-only.

Recommended output: number of prior scans, the most recent scan's date, its final URL and redirect
chain, the verdict/score if present, and the result link for the analyst to open in a browser
themselves.

### 8.7 Source summary

| Source | Endpoint kind | Passive? | Gives you |
|---|---|---|---|
| VirusTotal | `GET /urls/{b64id}` | Yes | Engine detections, categories, submission timeline |
| VirusTotal | `POST /urls`, `/analyse` | **No — forbidden** | (triggers live fetch of target) |
| URLhaus | DB lookup | Yes | Malware URL status, payload hashes |
| Safe Browsing | `threatMatches:find` | Yes (POST to Google) | Browser-blocklist verdict |
| PhishTank | `checkurl` | Yes | Verified phishing corpus hit |
| urlscan.io | `/search`, `/result` | Yes | Cached redirect chain, final URL, contacted hosts |
| urlscan.io | `POST /scan` | **No — forbidden** | (live browser visit to target) |

---

## 9. Report shape and verdict

Match the existing rendering conventions in `reporting/console.py` — borderless `Table`, `bold cyan`
keys, `Group(title, table, Text(""))`, red/green threshold colouring as at `console.py:78-79` and
`:95-96`. A new `render_url_analysis(...)` alongside `render_ip_analysis:24` keeps the house style.

```
--- URL lookup for hxxps://evil[.]com/login[.]php?id=7 ---

  raw_input            hxxps://evil[.]com/login[.]php?id=7   (defanged input, refanged for lookup)
  scheme               https
  host                 evil.com                              (domain)
  port                 443 (default, not explicit)
  path                 /login.php
  query                id=7
  userinfo_present     false

  virustotal           12/94 malicious          first_submitted 2026-08-08T09:14Z (41m ago)
  urlhaus              no record
  safe_browsing        SOCIAL_ENGINEERING
  phishtank            verified phish (2026-08-08)
  urlscan_prior_scans  3, most recent 2026-08-08T09:20Z -> final URL hxxps://evil[.]com/step2

  redirect_chain       NOT RESOLVED (active fetch required — see notes)
  assessment           MALICIOUS — 3 of 4 sources positive, newly registered infrastructure
```

Rules for the verdict line:

- **Never print a bare "clean."** Print `MALICIOUS` / `SUSPICIOUS` / `NO ADVERSE DATA` / `UNKNOWN
  (no source had a record)`. The last two are different facts and an analyst must not conflate them.
- **Show the denominator.** "3 of 4 sources positive; 1 source unavailable (no API key)" — the
  existing `_should_suppress` (`orchestrators.py:73-89`) hides missing-key errors, which is right for
  noise but wrong for a verdict: a verdict computed over 2 of 6 sources must say so.
- **Defang URLs in output** by default (§6, rule 2).
- **Timestamp everything**, in UTC ISO-8601. An incident report needs "as of when."

---

## 10. Pivoting url → host → IP → ASN

The pivot is where this tool already earns its keep — `investigate_domain` does exactly this today
(`orchestrators.py:294-307` pulls ASN metadata for each resolved IP via `fetch_asn_metadata`).
`investigate_url` should compose rather than duplicate:

```
parse URL  ->  host
   |
   +-- host is a domain  -> investigate_domain(host)   [orchestrators.py:193]
   +-- host is an IP     -> investigate_ip(host)       [orchestrators.py:103]
                                 |
                                 +-- ipinfo -> asn -> fetch_asn_metadata  [orchestrators.py:154-158]
```

`--depth` controls how far it walks: `url` (URL sources only), `host` (default: + domain/IP
intel), `full` (+ full ASN detail). Under time pressure the default should answer the question in
one screen; `full` is for the write-up.

Two design points:

- **Route URL-with-IP-host to the IP path.** Per §4.4, `http://185.220.101.5:8080/x` currently ends
  up in the domain orchestrator and fails validation. The detector must set
  `parts.host_type = ip|domain` and the orchestrator must branch on it.
- **Mark IP provenance.** When the pivot yields IPs, tag each with how it was obtained —
  `vt_passive_dns`, `urlscan_cached_result`, or `active_dns` (only if §3.2's flag was passed). Today
  `orchestrators.py:249` merges active and passive IPs into one undifferentiated list. In a report
  that distinction is the difference between "the domain resolved here at investigation time" and
  "the domain was observed resolving here on <date>."

Reuse the ASN pivot as-is. Do not add a fourth code path for it.

---

## 11. URL shorteners and redirect chains

**State the rule plainly: resolving a redirect is an active fetch.** Following a `301` means issuing
an HTTP request to the target's server and reading its `Location` header. This is true whether you
call it "resolving," "expanding," or "unshortening," and it is true even for a `HEAD` request —
`HEAD` is quieter, not passive. For a shortener like `bit.ly` the first hop goes to the shortener
(not the adversary), but the shortener is often adversary-controlled *for that link*, the request is
logged with the analyst's egress IP and UA, and single-use links can be burned by the lookup, which
destroys evidence for everyone downstream. Some phishing kits serve benign content to the first
visitor and malicious content thereafter — one careless expansion inverts the verdict for the whole
investigation.

Therefore:

1. **Detect and label shortener hosts** (`bit.ly`, `t.co`, `tinyurl.com`, `is.gd`, `ow.ly`,
   `buff.ly`, `rb.gy`, `cutt.ly`, `goo.gl`, `s.id`, …) from a small static list, plus a heuristic
   flag for "very short host + short opaque path." Print `shortener: yes (bit.ly)` prominently — the
   fact that a URL is shortened is itself reportable.
2. **Never resolve.** `redirect_chain: NOT RESOLVED (would require an active fetch)`.
3. **Get the chain passively instead.** This is the payoff from §8.6: a cached urlscan result
   contains the full redirect chain and final URL from *someone else's* browser visit. VT's
   `last_final_url` gives a second passive read on the same fact. Report them as
   `final_url (per urlscan scan of 2026-08-08, not verified live)` — provenance and staleness
   attached, because a cached chain may be days old and the adversary may have rotated.
4. **If — and only if — the operator later wants live expansion**, it must be a separate,
   loudly-named command (`tripper-recon expand --i-am-ok-with-active-contact <url>`), off by default,
   refusing shortener-of-shortener chains, capped at one hop, using an honest UA (§3.7), and printing
   an explicit warning naming the operator's egress exposure. Given the stated hard constraint, my
   recommendation is **do not build it at all** — the passive substitutes in point 3 cover most
   real cases, and an unbuilt feature cannot be misfired at 3am.
5. **Open-redirect parameters** found during parsing (§5) are surfaced as candidate indicators to
   investigate separately, never auto-followed.

---

## 12. Bulk / paste mode

The scenario: an analyst copies a whole phishing email, an alert body, or a threat report paragraph
and wants everything in it triaged.

### 12.1 Interface

```bash
tripper-recon bulk --file alert.txt
tripper-recon bulk --stdin < alert.eml
pbpaste | tripper-recon bulk --stdin
tripper-recon bulk --file report.txt --format json --max-concurrency 4
```

Note the existing `ip` command already accepts a file (`cli.py:124-135`) but only for IPs and only
one-per-line. `bulk` supersedes it: **extract indicators from arbitrary prose**, not just parse
clean lines.

### 12.2 Pipeline

1. **Extract** — regex sweep over the whole text for candidate substrings (URL-ish, IP-ish,
   domain-ish, hash-ish, email-ish, ASN-ish), refanged first (§6). Prose extraction must be
   deliberately greedy-then-validated: capture candidates loosely, then run each through the §4
   detector and drop `UNKNOWN`.
2. **Normalise and deduplicate** — dedupe on `(type, canonical_value)`, not on raw text, so
   `evil[.]com`, `EVIL.COM`, and `hxxp://evil.com` collapse. Keep every raw form and an occurrence
   count; `seen 4×` is a triage signal. `utils/validation.py:31` already has
   `dedupe_preserve_order` to build on.
3. **Filter noise** — this determines whether bulk mode is usable. Suppress by default, with
   `--no-filter` to disable: RFC1918/loopback/link-local/CGNAT addresses; the analyst's own
   allowlisted domains (`--allowlist-file`, a persistent org-asset list); mail-infrastructure
   domains that appear in every header (`outlook.com`, `protection.outlook.com`, `google.com`,
   `microsoft.com`, `schemas.microsoft.com`); `w3.org` and similar XML-namespace URLs, which
   otherwise flood every `.eml` paste. Report what was filtered and why — a suppressed indicator the
   analyst never sees is worse than noise.
4. **Triage-order** — investigate URLs and IPs before domains before hashes; within a type, order by
   occurrence count. The analyst reads top-down and should hit the answer first.
5. **Investigate with bounded concurrency** — `asyncio.Semaphore` held across the *await*, not just
   task creation (fixing §3.3), default `--max-concurrency 4`, applied per provider where free-tier
   limits are tight (VT public is famously ~4 req/min — a 60-indicator paste will exhaust it, so the
   tool must report "20 of 60 indicators: VT quota exhausted" rather than silently rendering zeros).
6. **Cache within the run** — the same host appearing in eight URLs must produce one domain
   investigation. A simple `dict` keyed on `(type, value)` for the process lifetime. Without it a
   realistic paste multiplies provider calls several-fold.
7. **Render a triage table first, details second.**

### 12.3 Output

```
Extracted 23 indicators (14 unique after dedupe; 6 filtered as internal/known-good)

  VERDICT      TYPE    INDICATOR                    SOURCES        SEEN
  MALICIOUS    url     hxxps://evil[.]com/login     VT 12/94, GSB     3
  MALICIOUS    ipv4    185.220.101[.]5              AB 100%, VT 8     1
  SUSPICIOUS   domain  cdn-evil[.]net               VT 2/94           2
  NO DATA      domain  benign-partner[.]com         -                 5
  UNKNOWN      sha256  44d886...                    no key: VT        1

  6 filtered: 10.0.0.0/8 (3), outlook.com (2), w3.org (1)  [--no-filter to include]
  2 incomplete: VT quota exhausted after 20 lookups

Details follow for MALICIOUS and SUSPICIOUS only (--details all).
```

Exit codes matter for pipeline use: `0` = no adverse findings, `1` = at least one malicious, `2` =
usage error, `3` = incomplete (quota/provider failure) — so a wrapper script can distinguish "clean"
from "we could not tell."

### 12.4 Constraint

Bulk mode is the highest-risk surface for accidental egress: it processes attacker-authored text,
and one bad regex or one unguarded `client.get` turns a paste into a callback. The §7 allowlist is a
hard prerequisite for shipping this, not a nice-to-have.

---

## 13. CLI and API surface

CLI additions to `cli.py:386-407`:

```
tripper-recon url <url>      [--depth url|host|full] [--fanged] [--no-third-party-url-share]
tripper-recon check <any>    [--type ip|ipv6|domain|url|hash|email|asn|cidr] [--explain]
tripper-recon bulk           [--file F | --stdin] [--max-concurrency N] [--allowlist-file F]
                             [--details all|adverse] [--no-filter]
```

Also fix `--format`: it is declared on the parent parser (`cli.py:382`) *and* on each subparser
(`cli.py:390`, `:395`, `:401`). The subparser value shadows the parent, so
`tripper-recon --format json ip 1.2.3.4` silently emits console output. Declare it once, on a shared
parent parser.

REST additions to `api/server.py:23-44`. **A URL cannot go in a path parameter** — it contains
slashes, and percent-encoding it round-trips badly. Use:

```
POST /url      {"url": "..."}            -> investigate_url
POST /check    {"indicator": "..."}      -> detect + dispatch
POST /bulk     {"text": "...", "max_concurrency": 4}
GET  /detect?indicator=...               -> type detection only, no provider calls
```

`GET /detect` is worth having on its own: it is free, instant, and lets a SOAR playbook route an
indicator without spending quota.

New models in `types/models.py:23-33`: `URLQuery`, `CheckQuery`, `BulkQuery`, and an `Indicator`
schema so the JSON contract is typed rather than a bare dict.

---

## 14. Suggested sequence

| # | Work | Depends on | Effort |
|---|---|---|---|
| 1 | Fix the `urlparse` crash (§3.1) — wrap in `try/except`, return a clean error | — | S |
| 2 | `refang()` + tests (§6) | — | S |
| 3 | Egress allowlist at `create_client()` + violation test (§7) | — | S |
| 4 | Gate active DNS behind `--active-dns`, mark IP provenance (§3.2) | 3 | S |
| 5 | `IndicatorType` + `detect()` + tests (§4) | 2 | M |
| 6 | `check` subcommand wiring detection to existing orchestrators (§4.1) | 5 | S |
| 7 | Fix `RateLimiter` to hold across the await; unify `--rate-limit` (§3.3) | — | S |
| 8 | `parse_url()` + `render_url_analysis()` (§5, §9) | 2, 5 | M |
| 9 | `vt_url_summary` — GET only, with forbidden endpoints documented in-source (§8.2) | 3, 8 | S |
| 10 | URLhaus + Safe Browsing providers (§8.3, §8.4) | 3, 8 | M |
| 11 | urlscan **search/result only** provider (§8.6) | 3, 8 | M |
| 12 | `investigate_url` composing the host/IP/ASN pivot (§10) | 8–11 | M |
| 13 | Shortener detection + passive redirect-chain reporting (§11) | 11, 12 | S |
| 14 | `bulk` extract/dedupe/filter/triage (§12) | 3, 5, 7, 12 | L |
| 15 | PhishTank or link-out fallback (§8.5) | 3 | S |
| 16 | README correction — remove or qualify the URL claim at `README.md:5` until §12 lands | — | S |

Items 1–4 are worth doing regardless of whether URL support is ever built.

---

## 15. Open questions and what I could not verify

Per the brief's instruction not to invent behaviour:

1. **Vendor API contracts are unverified.** The VT URL identifier scheme (§8.2), URLhaus auth model
   (§8.3), Safe Browsing API version (§8.4), PhishTank key availability (§8.5), and urlscan search
   query syntax (§8.6) are all stated from general knowledge and **must be confirmed against current
   vendor documentation before implementation.** I made no network calls during this review. The only
   thing I verified mechanically is what Python's `base64.urlsafe_b64encode` produces — not what
   VirusTotal accepts.
2. **Is active DNS (§3.2) an accepted risk or a defect?** I have treated it as a real leak because
   the brief instructs me to. If the operator has already decided that system-resolver lookups are
   acceptable, item 4 becomes documentation rather than a code change. This is an operator decision,
   not a technical one. **What would settle it:** a stated policy on whether the operator's resolver
   egress may appear in a target's authoritative logs.
3. **Which providers does the operator actually hold keys for?** `.env.example` lists six. Adding
   four URL sources widens the "no key configured" surface, which interacts with the verdict
   denominator problem in §9. I did not read `.env` and cannot tell which keys are live.
4. **Is the browser UA (§3.7) deliberate?** It is configured in both `utils/http.py:10-14` and
   `.env.example`, which suggests intent. If it exists to defeat provider bot-blocking, my
   recommendation to make it honest may break something — worth asking before changing.
5. **Verdict-scoring policy is out of scope here.** §9 proposes the report shape, not the weighting
   that turns four source opinions into one verdict. That needs its own design; naive
   "any source positive = malicious" will produce false positives on URL shorteners and CDNs.
