# tripper_recon — Security and Production-Hardening Audit

**Scope:** security of the tool itself — secret handling, the FastAPI surface, input validation at trust boundaries, repo hygiene, dependency and CI posture.
**Repo:** `/home/echo/dev/tripper_recon` @ `feat/work-20260808-recon-hardening` (`de277f4`), 2,238 LOC Python.
**Method:** static read of every source file plus three non-network reproductions (httpx URL/exception formatting, `is_valid_domain` behaviour, log-level parse). No network calls were made; no target was investigated; `.env` was never opened.
**Threat model applied:** (a) analyst workstation holding six live paid API keys, output pasted into tickets and chat; (b) `tripper-recon-api` running on a shared analysis host.

---

## Verification performed

Three claims below rest on executed checks rather than reading. Commands and outputs:

```
# 1. Does a query-string key survive into the exception text and request URL? (httpx 0.28.1)
req  = httpx.Request("GET", "https://api.shodan.io/shodan/host/1.2.3.4", params={"key":"SECRETKEY123"})
resp = httpx.Response(401, request=req); resp.raise_for_status()
-> str(e.request.url) == "https://api.shodan.io/shodan/host/1.2.3.4?key=SECRETKEY123"
-> str(e)             == "Client error '401 Unauthorized' for url 'https://api.shodan.io/shodan/host/1.2.3.4?key=SECRETKEY123'"

# 2. is_valid_domain normalisation
" evil.com "  -> True     "EVIL.COM" -> True    "evil.com\n" -> True
"evil-.com"   -> True     "1.2.3.4"  -> False   "evil.com\r\nX-Injected: 1" -> False

# 3. README-documented log level
TRIPPER_RECON_LOG_LEVEL=INFO  ->  ValueError: invalid literal for int() with base 10: 'INFO'
```

Also verified by `git check-ignore`: `tests/fixtures/sample.json`, `package.json`, `mypy.json`, `CHANGELOG.txt`, `docs/notes.txt`, `tests/data/expected.csv` are all ignored by the current `.gitignore`.
Also verified: `.env` has never been added in any commit reachable from any ref (`git log --all --diff-filter=A --name-only`), and the three `*_example.md` files in the working tree are **untracked**, not committed.

---

## Findings, ranked by real exploitability

### 1. CRITICAL — Provider API keys are echoed verbatim into console output, JSON output, logs, and HTTP API responses

Two providers put the secret in the **query string**:

- `tripper_recon/providers/ipinfo.py:18` — `client.get(f"{IPINFO_BASE}/{ip}", params={"token": token})`
- `tripper_recon/providers/ipinfo.py:62` — same for the ASN endpoint
- `tripper_recon/providers/shodan_api.py:18` — `client.get(f"{SHODAN_BASE}/shodan/host/{ip}", params={"key": api_key})`

Both call `r.raise_for_status()` (`ipinfo.py:19`, `shodan_api.py:21`), so any 401/403/429/5xx raises `httpx.HTTPStatusError`. That exception is caught in the orchestrator and rendered by `_error_payload`:

- `tripper_recon/orchestrators.py:38` — `"url": str(req.url) if req else None`
- `tripper_recon/orchestrators.py:39` — `"message": str(err)`
- `tripper_recon/orchestrators.py:47`, `:48` — same two fields on the `RequestError` branch

`str(req.url)` **is** the full URL including `?token=…` / `?key=…`, and `str(err)` embeds the same URL a second time — both confirmed against httpx 0.28.1 above. From there the payload propagates through every output path with no redaction:

| Sink | Anchor |
|---|---|
| `data["errors"]` in the result model | `orchestrators.py:174-176`, `:188` |
| `errors[]` summary strings (`message` is concatenated in) | `orchestrators.py:68-69`, `:177` |
| CLI console renderer | `cli.py:36` (`message=`), `cli.py:42` (`url=`) |
| IP panel renderer | `reporting/console.py:150-155` (`message=`, `url=`) |
| CLI `-o json` | `cli.py:196`, `cli.py:216`, `cli.py:323` |
| structured log line on stdout | `cli.py:172` (`errors=res.errors`) via `utils/logging.py:42` |
| HTTP API 200 response body | `api/server.py:28`, `:36`, `:44` (`res.model_dump()`) |

**Why this is the top finding for this operator.** The trigger is not exotic — an expired IPinfo token, a Shodan quota 429, or a free-tier VT/IPinfo 403 during a busy shift produces it. Note `_should_suppress` (`orchestrators.py:73-89`) suppresses `ipinfo_asn` 401/403 (line 80) but **not** the `ipinfo` provider name used by `investigate_ip` (`orchestrators.py:163`), so the IP path — the most-used path — is unsuppressed. The analyst then does exactly what the tool is designed for: copies the panel or the JSON into an incident ticket, a Slack channel, or a case-management system. The key is now in a shared system with a long retention period, and rotating six provider keys mid-incident is not a five-minute job.

**Fix (in order):**
1. Move the secret out of the URL where the provider supports it. Shodan and IPinfo both accept `Authorization: Bearer <token>` / header auth; IPinfo documents `Authorization: Bearer`. Verify against current provider docs before switching — if a provider only supports query auth, keep the query but apply step 2.
2. Add a single `redact(url_or_text) -> str` helper in `utils/` with a denylist of secret parameter names (`token`, `key`, `apikey`, `api_key`) plus the set of live key values read from env, and apply it inside `_error_payload` (`orchestrators.py:29-49`) so **every** downstream sink inherits it. Redacting at the source is the only version of this that stays correct as sinks are added.
3. Drop `"message": str(err)` entirely, or redact it — it is a duplicate of fields already structured.
4. Add a unit test that asserts a fabricated 401 from each provider produces an error payload containing no substring of any configured key. This is the test that would have caught it.

---

### 2. CRITICAL (on a shared host) — The API binds `0.0.0.0` with no authentication, no authorization, no rate limiting, and returns the leaked key from finding 1 to any caller

- `tripper_recon/api/server.py:50` — `uvicorn.run(app, host="0.0.0.0", port=8000)`
- `tripper_recon/api/server.py:15` — no middleware, no dependency, no API-key check on any route
- `tripper_recon/api/server.py:23`, `:31`, `:39` — three unauthenticated routes
- `tripper_recon/api/server.py:28`, `:36`, `:44` — return the full `model_dump()`, i.e. finding 1's payload
- `README.md:72-74` — documents `tripper-recon-api` as the integration path and advertises Swagger/ReDoc, which FastAPI serves unauthenticated at `/docs` and `/openapi.json` by default

Chained impact for an unauthenticated peer on the same network segment:
- **Quota and billing theft.** Every `GET /ip/<x>` burns the operator's VirusTotal, Shodan, AbuseIPDB, IPinfo, and OTX quota. There is no per-caller limit anywhere (see finding 3 — the internal limiter does not limit either), so a loop drains a paid VT/Shodan allowance and can get the operator's key rate-limited or banned by the provider.
- **Key disclosure.** Once quota is exhausted the providers return 401/403/429 → finding 1 fires → the 200 response body contains the key in `data.errors.<provider>.url`. Quota exhaustion is therefore not just a denial of service, it is the *precondition* for key disclosure. An attacker can drive it deliberately.
- **Attribution laundering.** Third parties can run OSINT lookups that appear, to every provider, to come from the operator's account and egress IP.
- **Unbounded fan-out.** One HTTP request to `/domain/<d>` triggers a DNS resolution plus 5 provider calls per resolved IP with no cap on the IP list (`orchestrators.py:253`) — a domain with many A records is an amplifier.

`HTTPException(status_code=400, detail=res.errors)` (`server.py:27`, `:35`, `:43`) is reachable only for invalid/private input (`orchestrators.py:105`, `:110`, `:195`, `:336`), so the 400 path leaks little; the **200** path is the leak.

**Fix:** default `host` to `127.0.0.1` and make the bind address an explicit opt-in flag/env var with a startup warning when it is not loopback; require a shared secret (`X-API-Key` compared with `secrets.compare_digest`) on all non-`/health` routes; add per-client rate limiting; disable `/docs` and `/openapi.json` unless a debug flag is set; and strip `data["errors"]`/`errors[]` from API responses (or gate them behind the authenticated debug flag) so the API is never a key oracle even if finding 1 regresses.

---

### 3. HIGH — The rate limiter does not limit anything, and file input fans out without bound

Three compounding defects:

- `tripper_recon/orchestrators.py:120-129` — the semaphore is held only around `asyncio.create_task(...)`. `async with limiter:` acquires, creates the task (which does not run yet), then releases. Every one of the five provider calls is therefore unthrottled; the block is decorative.
- `tripper_recon/utils/http.py:61-66` — `RateLimiter.__init__` sizes the process-global semaphore on **first** construction only. `RateLimiter(rate=5)` at `orchestrators.py:117` silently wins or loses depending on call order, and `configure_rate_limit()` (`http.py:57-59`, wired at `cli.py:415`) is ignored if a limiter was built first. `investigate_domain` and `investigate_asn` never construct a limiter at all — `--rate-limit` (`cli.py:383`) is inert for two of the three subcommands.
- `tripper_recon/cli.py:150-151` — `asyncio.gather(*[investigate_ip(t) for t in targets])` over the whole file with no chunking and no cap, fed by `_load_ip_targets` (`cli.py:124-135`) which imposes no line limit.

A 2,000-line target list therefore issues ~10,000 concurrent outbound requests. `httpx.Limits(max_connections=50)` (`http.py:42`) queues them at the socket layer but does nothing about per-provider request rate, so the practical outcomes are provider-side 429s, temporary or permanent key bans, and a burst from the analyst's egress that looks like abuse. Under time pressure — the operator's stated use case — the tool fails exactly when a bulk triage list is thrown at it.

**Fix:** make the semaphore a real gate by acquiring it *inside* each provider coroutine (or wrapping every `client.get`/`post` in `utils/http.py`), give each provider its own limiter sized to that provider's documented rate, and batch `_cmd_ip` through `asyncio.Semaphore`-bounded workers instead of one `gather`. Cap and warn on target-file length.

---

### 4. HIGH — Passive-only violation: the tool resolves the target domain against the target's own authoritative nameservers

- `tripper_recon/utils/dns.py:12-18` — `socket.getaddrinfo(domain, ...)` for both AF_INET and AF_INET6
- `tripper_recon/orchestrators.py:247-248` — called unconditionally on every domain investigation, before any IP enrichment, with no flag to disable it

The system recursive resolver will, on a cache miss, query the adversary's authoritative NS. For an actor who controls their own DNS — routine for phishing and C2 infrastructure — that query is a real-time notification that someone is investigating the domain, timestamped, with the resolver's IP (often attributable to the organisation) in the log. Some actors treat that signal as a trigger to rotate infrastructure or serve benign content. The tool already has a passive path for the same data — VT's `last_dns_records` (`providers/virustotal.py:57`, consumed at `orchestrators.py:228-235`) — and merges the two sources together (`orchestrators.py:249`), so the leak buys marginal freshness at the cost of the tool's core constraint.

Note also `reverse_ptr` (`utils/dns.py:26-34`) is defined but never called — `ptr` is hardcoded `None` at `orchestrators.py:254` and emitted at `:311`. Dead code that would add a second leak vector if anyone wired it up.

**Fix:** make passive resolution the default (VT/OTX passive DNS only), put live resolution behind an explicit `--resolve` / `allow_active_dns=True` flag, label every IP in the output with its provenance (`passive` vs `live-dns`) so the analyst can see which facts cost them an OPSEC leak, and print a one-line warning when the live path is used. If live resolution stays, route it through a neutral resolver (DoH to a large public resolver) rather than the host's configured one, and say so in the README. Delete or wire up `reverse_ptr`.

---

### 5. MEDIUM — Structured logs are written to stdout with no redaction, corrupting machine-readable output

- `tripper_recon/utils/logging.py:42-43` — `sys.stdout.write(json.dumps(record))`
- `tripper_recon/utils/logging.py:18-26` — `_parse_context` serialises **any** value it is handed; there is no key denylist, no value scrubbing, no hook where redaction could be added
- `tripper_recon/cli.py:172` — `log["error"](..., errors=res.errors)` writes finding 1's key-bearing strings into that stream
- `tripper_recon/cli.py:161`, `:144`, `:317`, `:370`, `:373` — other stdout log sites

Two consequences. First, `tripper-recon ip ... -o json | jq` breaks whenever a log line is emitted, because log JSON objects interleave with the result JSON (`cli.py:196`) on the same descriptor — the "programmatic integration" path advertised at `README.md:18` is not pipe-safe. Second, when the operator redirects stdout to a run log for case documentation, the key goes into the case file.

**Fix:** write logs to `sys.stderr`, keep stdout for results only; add a redaction pass in `_parse_context` that masks any value matching a configured key; make the log a real `logging.Logger` so level parsing, handlers, and filters are standard (this also fixes finding 9).

---

### 6. MEDIUM — `--prefixes-out` writes to any caller-supplied path, creating parent directories, with no containment check

- `tripper_recon/cli.py:360` — `out_path = Path(prefixes_out)` straight from argv (`cli.py:406`)
- `tripper_recon/cli.py:366` — `out_path.parent.mkdir(parents=True, exist_ok=True)` on the attacker-or-typo-supplied parent
- `tripper_recon/cli.py:369` — `out_path.write_text(...)` overwrites unconditionally, no `exists()` check, no extension restriction
- `tripper_recon/cli.py:298-301` — the bare-filename fallback writes into `Path(__file__).parent.parent / "outputs"`, i.e. **inside the installed package**; under `pip install .` that is `site-packages/`, which is either a permission error or a polluted install

Direct exploitability on a workstation is low — the analyst types the flag themselves. It becomes real when the CLI is driven by a wrapper script, a SOAR playbook, or a case-management integration that interpolates a case ID or filename into the flag: `--prefixes-out ~/.bashrc` (no `expanduser` here, unlike `cli.py:125`, so `~` is taken literally — an inconsistency worth noting on its own) or an absolute path silently clobbers a config file. `..` sequences are not filtered.

**Fix:** resolve the path, require it to sit under an explicit output root (or the CWD) and reject otherwise, refuse to overwrite without `--force`, apply `expanduser()` consistently, and default the output root to a user-writable location (`$XDG_DATA_HOME` or CWD) rather than the package directory.

---

### 7. MEDIUM — Domain input is validated in normalised form but consumed raw (validate-then-use divergence)

- `tripper_recon/utils/validation.py:28` — `_domain_re.match(value.strip().lower())` — validation runs against a **different string** than the caller holds
- `tripper_recon/orchestrators.py:194-195` — validates, then uses the original `domain` at `:204`, `:205`, `:248`, `:325`
- `tripper_recon/api/server.py:32` — passes the raw path parameter straight in

Confirmed behaviours: `" evil.com "` and `"evil.com\n"` pass validation, then reach `f"{VT_BASE}/domains/{domain}"` (`providers/virustotal.py:47`) and `getaddrinfo` with the whitespace intact. `"evil.com\r\nX-Injected: 1"` is correctly rejected (the regex has no `\r`), and httpx independently raises `InvalidURL` on non-printable ASCII — so I found **no** request-splitting or SSRF path, and I want to be explicit about that: the three API routes all validate before any URL construction (`orchestrators.py:104`, `:194`, `:335`), FastAPI path params cannot contain a raw `/`, and no provider base URL is user-controlled. SSRF is not present today. The defect is the divergence itself, which is a latent SSRF/injection enabler the next time a provider URL or a subprocess call is added.

Secondary validation weaknesses in the same regex (`validation.py:24`): trailing-hyphen labels pass (`evil-.com` -> True, confirmed), there is no per-label 63-octet check, and there is no IDN/punycode normalisation — an analyst pasting a Unicode homograph domain gets a flat "Invalid domain" rather than the punycode form, which is a usability failure in exactly the phishing-triage case the tool exists for.

**Fix:** have `is_valid_domain` return the normalised value (`Optional[str]`) or add `normalize_domain()`, and make every caller use the returned value; add per-label length checks and reject trailing hyphens; run IDNA encoding (`idna` package or `str.encode("idna")`) before validation so homograph domains are investigable.

---

### 8. MEDIUM — File-target loading reads any readable path, unbounded, and echoes its contents

- `tripper_recon/cli.py:124-127` — `Path(value).expanduser()`; if it is a file, it is read; otherwise the value is treated as a literal IP. The mode switch is implicit and silent.
- `tripper_recon/cli.py:130` — `read_text(errors="ignore")` with no size limit
- `tripper_recon/cli.py:163`, `:165`, `:176` — every unvalidated line is echoed back into console/JSON output as `target`

`tripper-recon ip /etc/passwd` reads the file, treats each line as a target, fails validation per line (`orchestrators.py:104`), and prints the file's contents back as error rows. Not a privilege boundary crossing — the process already has the analyst's rights — but it is an information-flow surprise: content from an arbitrary file lands in an output artifact that may be pasted into a ticket. Combined with finding 3, a large file is also a resource-exhaustion trigger. The implicit file-vs-literal switch also means a file named `8.8.8.8` in CWD shadows the literal target.

**Fix:** make file input an explicit flag (`--targets-file`), cap file size and line count with a clear error, validate each line before it enters the results structure, and truncate rejected input in output rather than echoing it.

---

### 9. MEDIUM — The log level documented in the README crashes the tool at import

- `tripper_recon/utils/logging.py:30` — `int(os.getenv("TRIPPER_RECON_LOG_LEVEL", "20"))`, unguarded
- `README.md:97` — documents `TRIPPER_RECON_LOG_LEVEL=INFO`
- `.env.example:22-23` — documents the numeric form, contradicting the README

`logger()` is called at module scope (`cli.py:21`, `orchestrators.py:26`), so an operator who follows the README gets `ValueError: invalid literal for int() with base 10: 'INFO'` before the CLI parses a single argument (reproduced above). No error handling, no fallback. The same line has a lesser bug: a level below 10 or a negative value silently disables the floor.

This one matters beyond availability — it is direct evidence that no test, no CI job, and no manual run has exercised the documented configuration, which is the case for finding 10.

**Fix:** accept both symbolic and numeric levels, fall back to INFO with a warning on unparseable input, and reconcile `README.md:97` with `.env.example`.

---

### 10. MEDIUM — No tests, no linter, no type checker, no CI, no pre-commit, no secret scanning

Confirmed absent: no `tests/` directory, no file matching `*test*`, no `.github/`, no `pyproject.toml` sections for ruff/mypy/pytest (`pyproject.toml:1-30`), no `.pre-commit-config.yaml`.

For a tool whose output is meant to be defensible in an incident report, this is the finding that makes all the others recur. Concretely: finding 1 is a five-line unit test (mock a 401, assert no key substring in the payload); finding 9 is a one-line test; finding 3's no-op semaphore is visible to any reviewer but survived because nothing asserts concurrency behaviour. A secret-scanning pre-commit hook (gitleaks or `detect-secrets`) is the compensating control for a repo whose whole purpose is handling six API keys.

**Fix, cheapest first:** `ruff check` + `ruff format` and `mypy --strict` on `tripper_recon/` in a `.github/workflows/ci.yml`; `pytest` with provider tests built on `httpx.MockTransport` (no network, so CI stays passive); a redaction test per provider; `gitleaks` in pre-commit and in CI. `pyproject.toml` needs a `[project.optional-dependencies] dev = [...]` group to make any of this installable.

---

### 11. MEDIUM/LOW — Dependencies are floor-pinned with no ceiling and no lockfile

- `pyproject.toml:13-20` — every dependency is `>=` with no upper bound: `httpx[http2]>=0.27.0`, `pydantic>=2.6.0`, `fastapi>=0.110.0`, `uvicorn>=0.29.0`, `python-dotenv>=1.0.1`, `rich>=13.0.0`

Two distinct risks. Supply chain: a compromised or malicious release of any of these is pulled automatically on the next clean install, into a process that holds six live API keys in its environment — the classic high-value target for a credential-stealing package. Reproducibility: `pip install .` today and in six months produce different behaviour, and finding 1's exact leak shape is httpx-version-dependent (I verified against 0.28.1; the message format has changed across httpx releases).

**Fix:** add upper bounds (`>=0.27,<0.29` style) for the libraries whose behaviour the code depends on, commit a lockfile (`requirements.lock` via `pip-compile`, or `uv.lock`) with hashes for the install path, and enable Dependabot. Also `pyproject.toml:10` still reads `authors = [{ name = "Your Name" }]` — a placeholder in a repo presented as portfolio work.

---

### 12. LOW/MEDIUM — `.gitignore` blocks legitimate project files while missing the format the tool actually emits

- `.gitignore:84-90` — `*.json`, `*.csv`, `*.tsv`, `*.sqlite`, `*.db`
- `.gitignore:91-94` — `*.txt` with only `requirements.txt` and `LICENSE.txt` re-included

Verified ignored by these rules: `tests/fixtures/sample.json`, `tests/data/expected.csv`, `package.json`, `mypy.json`, `CHANGELOG.txt`, `docs/notes.txt`. Every one of those is a file a hardening effort would want to commit — in particular the JSON fixtures that finding 10's provider tests need. The failure mode is silent: `git add tests/fixtures/sample.json` does nothing and CI later fails on a missing file.

Meanwhile the rules miss the actual risk. The tool's default output is a Rich console render, and the three investigation captures in the working tree — `ip_example.md`, `domain_example.md`, `ASN_Example.md` — are Markdown. `*.md` is not ignored. They are currently untracked (verified), so nothing has leaked, but the control the operator wrote to prevent committing investigation data does not cover the format the tool produces by default. `outputs/` (`.gitignore:81`) is ignored, but `cli.py:360-364` only routes bare filenames there.

**Fix:** replace the blanket extension bans with directory-scoped rules (`/outputs/`, `/results/`, `/reports/`, `/cases/`) and negate the paths tests need (`!tests/**/*.json`), or invert to an allowlist. Add a pre-commit secret/PII scan as the real control rather than relying on extension matching.

---

### 13. LOW — Browser User-Agent spoofing is the default, against commercial API endpoints

- `tripper_recon/utils/http.py:10-14` — default UA impersonates Chrome 141 / Edge on Windows
- `tripper_recon/utils/http.py:34-38` — applied to every outbound request, including VirusTotal, Shodan, AbuseIPDB, IPinfo and OTX
- `tripper_recon/cli.py:384` — the flag's own help text says "User-Agent string to **spoof**"
- `.env.example:29` — ships the spoofed UA as the documented default

All targets are authenticated third-party APIs where the key already identifies the caller, so the spoof buys nothing operationally. It costs three things: several providers' terms prohibit misrepresenting the client, and the operator is a federal employee using paid accounts; anomalous UA/key pairings are a common abuse signal that can get an account flagged; and "the tool lied about its identity to the data source" is a bad line in an incident report whose value is defensibility.

**Fix:** default to an honest UA — `tripper-recon/0.1.0 (+https://github.com/<user>/tripper_recon)` — and keep the override flag for the rare passive-dataset endpoint that needs it, renaming it from "spoof" to "override".

---

### 14. LOW — `.env` is loaded from the current working directory

- `tripper_recon/utils/env.py:15-22` — candidates are `Path(os.getcwd()) / ".env"` then the package root; first match wins, `override=False`

An analyst commonly runs triage tooling from a case directory, a mounted share, or an unpacked sample directory. A `.env` planted in such a directory is read by the tool. `override=False` and the hard-coded provider base URLs limit the damage — an attacker cannot redirect keys to their own host — but they can supply `TRIPPER_RECON_USER_AGENT` (fingerprinting the analyst to the provider) or, if the real keys are not already exported, supply their own keys so the operator's investigation runs on an attacker-observable account. Low likelihood, cheap to close.

**Fix:** load only from the package/project root or an explicit `--env-file`, or require `TRIPPER_RECON_ALLOW_CWD_ENV=1` to opt into CWD loading, and log which `.env` path was used at INFO.

---

### 15. LOW — Provider response bodies are echoed into output

- `tripper_recon/providers/cloudflare_radar.py:39` and `:64` — `"body": r.text[:500]` on any non-200
- `tripper_recon/cli.py:43-45` and `reporting/console.py:156-158` — rendered as `body=…`

Cloudflare error bodies are unlikely to contain the bearer token, so I am not claiming a key leak here and cannot confirm one without live calls. The general defect stands: unfiltered third-party response text is copied into an artifact destined for an incident ticket, and it is the same missing-redaction gap as finding 1. Truncate to a status/error-code summary, or pass it through the same redaction helper.

---

## Explicitly checked and *not* found

Stating these so the absence is not read as an omission:

- **SSRF via API path parameters** — not present. All three routes validate before any URL is built (`orchestrators.py:104`, `:194`, `:335`); no provider base URL is user-controlled; FastAPI path params cannot carry a raw `/`; httpx rejects non-printable ASCII in URLs (verified). Finding 7 is a latent enabler, not a live SSRF.
- **Command injection / `subprocess`** — no `subprocess`, `os.system`, `eval`, or `exec` anywhere in the tree.
- **Active contact with the target** — no code path fetches the target URL, opens a socket to the target, or submits a live scan. The only target-directed traffic is the DNS resolution in finding 4.
- **ReDoS in `_domain_re`** (`validation.py:24`) — the `(\.[A-Za-z0-9-]+)*` group is anchored by a literal `.` on each iteration, so there is no nested-quantifier ambiguity, and the `(?=.{1,253}$)` lookahead caps input length. Not a defect.
- **Secrets in git history** — `.env` was never added on any ref; only `.env.example` (placeholders only) is tracked. History does show an earlier `netintel/` tree including `enumerators/dns_subdomains.py`, `providers/iplyzer_wrapper.py`, and a committed `ip_list` target file; those are gone from HEAD but remain reachable in history. Worth a decision: if that subdomain enumerator was active-collection code, its presence in a public repo's history invites the wrong conclusion about the tool's passive claim, and the committed `ip_list` may contain real investigation targets. I did not read those blobs — confirm with `git show <rev>:ip_list` before deciding whether history rewriting is warranted.

---

## Recommended sequence

1. Finding 1 (redact at `_error_payload`) — one function, closes the credential leak across every sink at once.
2. Finding 2 (loopback default + auth + no error detail over HTTP) — removes the remote path to the same secret.
3. Finding 4 (passive DNS default, live behind a flag) — restores the tool's defining constraint.
4. Finding 3 (real concurrency limiting) — prevents the key ban that triggers finding 1 in the first place.
5. Finding 10 (ruff + mypy + pytest + gitleaks in CI) — with a regression test for 1 and 9 as the first two tests written.
6. Everything else.
