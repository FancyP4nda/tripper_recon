# Tripper Recon — Documentation Accuracy & Project Hygiene Audit

**Lens:** documentation accuracy and project hygiene
**Repo:** `/home/echo/dev/tripper_recon` @ `feat/work-20260808-recon-hardening` (HEAD `de277f4`)
**Method:** read-only. No tool execution against any indicator, no network calls, `.env` never opened.
**Date:** 2026-08-08

---

## Headline

The README is a **portfolio artifact on a public GitHub repo** (`origin` = `https://github.com/FancyP4nda/tripper_recon.git`). That raises the cost of every inaccuracy in it — a reviewing hiring manager who runs `tripper-recon url http://…` and gets `invalid choice: 'url'` has learned something about the author, not about the tool.

Counted against the code, the README currently makes **one claim for a subcommand that does not exist**, **three provider-capability claims the code does not implement**, **omits four of the ten providers it actually queries**, **documents one environment variable with a value that would crash the process**, and **says nothing at all about the tool's single most important design property — that it is passive**. Packaging metadata still carries `Your Name` in two files, and the built metadata on disk declares `License: Proprietary` while the repo ships MIT.

None of this is hard to fix. It is roughly a day of writing plus a `pyproject.toml` pass.

---

## 1. README claim-by-claim

### 1.1 The "URL" capability does not exist — **critical**

`README.md:5` — *"asynchronous OSINT toolkit for IP, Domain, URL, and ASN investigations."*

The subparsers registered in `cli.py` are exactly three: `ip` (`cli.py:388`), `domain` (`cli.py:393`), `asn` (`cli.py:399`). There is no `url` subcommand, no URL handling in `orchestrators.py`, and no URL route in `api/server.py:23-44` (`/ip`, `/domain`, `/asn`, `/health` only). `urlparse` appears once (`cli.py:205`) purely to strip a scheme off a domain argument before validation — that is URL *tolerance* on the domain path, not URL investigation.

This is the most consequential inaccuracy in the file and it is also **the one place where fixing the docs is safer than fixing the code**. Under the passive-only constraint, a `url` subcommand must never be implemented as "fetch the URL." If URL support is ever added it has to be VT `/urls/{id}` lookups of the *already-submitted* hash, plus urlscan.io **search** (never `/scan`). Until that exists, delete the word from line 5.

### 1.2 Provider capability claims vs. what the code extracts

| README claim | Line | What the code actually does | Verdict |
|---|---|---|---|
| Cloudflare Radar: *"ASN metadata, routing, and BGP prefixes"* | `README.md:82` | `cloudflare_radar.py:17-27` requests only `asn name countryCode caidaRank organization abuseContacts rir allocationDate ixps`. No routing, no prefixes. Routing status and announced prefixes come from **RIPEstat** (`ripestat.py:33`, `ripestat.py:41`); BGP hijack/leak events come from **`cloudflare_rest.py:19-20`**, a different module | **False as attributed.** Two of three capabilities exist but are sourced from providers the README never names |
| Shodan: *"Open ports, service banners, and SSL certificate fingerprints"* | `README.md:84` | `shodan_api.py:22-29` extracts `ports`, `org`/`isp`, `tags`, and de-duplicated `cpe`. Banners (`data[].data`) are discarded; `ssl.cert.fingerprint` is never read | **False on two of three.** No banners, no cert fingerprints anywhere in the codebase |
| VirusTotal: *"Detections, reputation scores, passive DNS, and Whois"* | `README.md:83` | True for the **domain** path (`virustotal.py:57-58` reads `last_dns_records` and `whois`). False for the **IP** path — `virustotal.py:28-35` returns stats, reputation, link only | **Scope-inaccurate.** Reads as if it applies to all target types |
| AbuseIPDB: *"Fraud and abuse confidence scoring"* | `README.md:85` | `abuseipdb.py:29-32` returns `totalReports` + `abuseConfidenceScore` over a 365-day window (`abuseipdb.py:23`) | **Accurate**, but the 365-day window is a material analyst detail and is undocumented |
| IPInfo: *"Core geolocation and network ownership details"* | `README.md:86` | `ipinfo.py:18` | **Accurate** |
| OTX: *"Pulse counts and associated threat intelligence"* | `README.md:87` | `otx.py:25-31` returns count + **first 5** pulse titles (`pulses[:5]`) | **Accurate but truncation undisclosed.** An analyst seeing 5 titles for a 50-pulse indicator (see `ip_example.md:17`) should be told the list is capped |

### 1.3 Four providers are queried and never documented — **high**

`README.md:78-87` promises the tool *"actively correlates data from the following industry-leading sources"* and lists six. `orchestrators.py:20-23` imports four more, all of which are called on the `asn` path:

| Undocumented provider | Module | Called at | Key required? |
|---|---|---|---|
| RIPEstat (`stat.ripe.net`) | `ripestat.py:10` | `orchestrators.py:342, 343, 383, 384, 385` | **No** |
| CAIDA ASRank (`api.asrank.caida.org`) | `caida.py:10` | `orchestrators.py:344` | **No** |
| PeeringDB (`www.peeringdb.com`) | `peeringdb.py:10` | `orchestrators.py:345` | **No** |
| Cloudflare REST BGP events | `cloudflare_rest.py:10` | `orchestrators.py:349` | Yes (`CLOUDFLARE_API_TOKEN`) |

Two consequences, and the second is the serious one:

1. The README **understates the tool.** RIPEstat + CAIDA + PeeringDB are the reason `tripper-recon asn` produces a real BGP picture with zero API keys configured. That is the single best "try it right now" story the project has and it is invisible.
2. An analyst reading this README **cannot enumerate the third parties that will observe their query.** In a passive-OSINT tool that is not a marketing gap, it is an OPSEC gap. Querying an indicator tells RIPE NCC, CAIDA, and PeeringDB that someone is interested in that ASN. The user is entitled to a complete list before they type an indicator from a live incident.

### 1.4 `TRIPPER_RECON_LOG_LEVEL=INFO` is an invalid value — **high**

`README.md:97` documents `TRIPPER_RECON_LOG_LEVEL=INFO`. `logging.py:30` does `int(os.getenv("TRIPPER_RECON_LOG_LEVEL", "20"))` — the value must be numeric. `.env.example:21-22` gets this right (`=20` with a legend). The README contradicts the shipped template and would raise `ValueError` at import if the user exported it in their shell.

It happens not to crash when set via `.env`, and the reason is itself a defect: `logger()` is called at module scope (`cli.py:21`, `orchestrators.py:26`) during import, while `load_env()` does not run until `cli.py:380` inside `main()`. The `.env` value is therefore read **after** every logger has already fixed its level, so `TRIPPER_RECON_LOG_LEVEL` in `.env` is silently ignored entirely. Both the documented value and the documented mechanism are wrong.

### 1.5 "Resilient Engine… handling rate limits (`429 Too Many Requests`) elegantly" — **overstatement**

`README.md:24`. There is **no 429-specific code path anywhere in the repo** — `grep -rn "429\|Retry-After" tripper_recon/` returns nothing. What exists is `backoff.py:10-29`: a blanket `except Exception` retry, 3 attempts, 0.5s base, 5s cap, jittered. It retries a 401 bad key, a 403 quota-exhausted, and a DNS failure with identical enthusiasm, and it ignores `Retry-After` headers that AbuseIPDB and VirusTotal both send.

The mechanism is real; the claim about *what it is for* is not. Rewrite as "jittered exponential backoff on transient provider failures," and file the 429/`Retry-After` handling as actual work.

### 1.6 "Concurrent Orchestration… simultaneously" is true for `ip`, false for `domain` — **medium**

`README.md:22`. On the IP path, `orchestrators.py:121-129` creates five provider tasks and `cli.py:150-151` gathers across all bulk targets — genuinely concurrent. On the domain path, `orchestrators.py:253-274` awaits VT → Shodan → IPInfo → AbuseIPDB → OTX **strictly sequentially, inside a sequential `for ip in ips` loop**. A domain resolving to 8 IPs performs 40 serialized round trips. For a tool whose pitch is "speed to answer," the README's headline feature is absent from the path an analyst uses to triage a phishing domain.

Related: `README.md:23` claims *"connection pooling to maximize throughput."* `create_client()` (`http.py:41-51`) is entered per investigation (`orchestrators.py:116`), so bulk IP mode builds a fresh pool per target — pooling is real within one target and non-existent across them.

### 1.7 "structured JSON logging for SIEM ingestion" collides with `--format json` — **medium**

`README.md:26`. `logging.py:42` writes log records to **stdout**. `cli.py:196` writes the machine-readable result to **stdout** via `console.print_json`. Piping `tripper-recon ip 8.8.8.8 -o json | jq` therefore risks interleaved NDJSON log lines and a pretty-printed result object in one stream. The README advertises both properties on the same line without noting they contend for the same file descriptor. Logs belong on stderr.

### 1.8 Documented but not verifiable, and undocumented but real

**Documented, works:** installation from clone, the three CLI examples (`README.md:53-59`), bulk-from-file (`README.md:64`, implemented at `cli.py:124-135`), `tripper-recon-api` entry point (`pyproject.toml:24`).

**Undocumented CLI surface** — every one of these is real and none appears in the README:

| Flag | Defined at | Notes |
|---|---|---|
| `--rate-limit` | `cli.py:383` | Added in commit `06b4fa3`; commit `3e4455d` claims "rate-limiting readme docs" but the current README has no mention of it |
| `--user-agent` | `cli.py:384` | See §4.2 — has OPSEC implications |
| `-V/--version` | `cli.py:385` | |
| `--ports-limit` | `cli.py:391, 396` | |
| `--neighbors`, `--enrich`, `--enrich-limit` | `cli.py:402-404` | `--enrich` help says "via whois/pWhois (slower)"; `orchestrators.py:529-537` is an explicit placeholder that just slices the existing prefix lists. **The `--help` text describes a feature that is not implemented** |
| `--monochrome` | `cli.py:405` | Help: "Disable ANSI colors in console output". `use_color` is a parameter of `render_asn_header` (`console.py:167`) and `render_asn_bgp_panels` (`console.py:224`) and is **never referenced in either body**. The flag is a no-op |
| `--prefixes-out`, `--prefixes` | `cli.py:406-407` | Output destination is undocumented and wrong — see §3.3 |

**Undocumented behaviour that surprises:** `_load_ip_targets` (`cli.py:124-127`) treats the positional argument as a file path *if a file of that name exists*, else as a literal IP. A target list is only supported for `ip`, never `domain` or `asn`, and the README's phrasing ("Feed the tool a text file of targets") implies otherwise.

**Undocumented refusal:** `orchestrators.py:109-110` rejects RFC1918 addresses outright. An analyst pasting an internal IP from a SIEM row gets a hard failure with no README warning. That refusal is *correct* — it prevents leaking internal addressing to third parties — but it deserves to be a documented, deliberate feature rather than a surprise.

---

## 2. `pyproject.toml` metadata

`pyproject.toml` is 31 lines and is missing most of what a package that people are meant to look at should carry.

### 2.1 Author placeholder — **high, portfolio-damaging**

`pyproject.toml:10` — `authors = [{ name = "Your Name" }]`. `LICENSE:3` — `Copyright (c) 2026 Your Name`. Both are template defaults surviving into a public repo whose README was explicitly rewritten "for portfolio" (commit `db11113`). The single highest effort-to-impact fix in this entire audit is replacing two strings.

### 2.2 Built metadata says `License: Proprietary` — **high, needs confirmation**

`tripper_recon.egg-info/PKG-INFO:6` reads `License: Proprietary`, while `pyproject.toml:12` declares `license = { text = "MIT" }`, `LICENSE:1` is the MIT text, and `README.md:8` renders an MIT badge.

**I cannot tell from inspection alone whether this is live or stale.** The `egg-info/` directory is gitignored and may predate commit `c10dd8e` ("chore: apply MIT license"). What settles it: `python -m build` (or `pip install -e .`) into a scratch venv, then re-read `PKG-INFO`. If it still says Proprietary, the license declaration is not reaching consumers and the MIT badge is unbacked. Either way `PKG-INFO` shows **no `License-File:` entry**, so `LICENSE` is not being packaged into the distribution — that part is certain and is fixed with `license-files = ["LICENSE"]`.

Also worth noting: `license = { text = "MIT" }` is the pre-PEP-639 table form. Modern setuptools prefers the SPDX string `license = "MIT"`.

### 2.3 No dev-dependency group, no tool config, no tests

`pyproject.toml` has no `[project.optional-dependencies]` / `[dependency-groups]`, no `[tool.ruff]`, no `[tool.mypy]`, no `[tool.pytest.ini_options]`, and the repo has **no `tests/` directory and not one test file** (`git ls-files` — 28 files, zero tests). `packages.find` excludes `tests*` (`pyproject.toml:31`) for a directory that does not exist.

For a tool whose selling point is defensibility of the answer, having no test proving that `is_valid_ip` rejects a malformed indicator, or that `investigate_ip` refuses RFC1918, is the gap a reviewer will notice first. The codebase is fully type-annotated and `from __future__ import annotations` is used consistently — mypy would likely pass with modest effort, which makes the absence of config a missed easy win rather than a large project.

### 2.4 Missing `[project.urls]`, classifiers, keywords

No `Homepage`, `Repository`, or `Issues` URLs; no `classifiers` (`Development Status`, `Intended Audience :: Information Technology`, `Topic :: Security`, `Programming Language :: Python :: 3.10/3.11/3.12`, `License :: OSI Approved :: MIT License`); no `keywords` (`osint`, `threat-intelligence`, `soc`, `dfir`, `asn`, `bgp`). On PyPI or on a GitHub sidebar these are what makes the project findable and legible.

### 2.5 No subpackage `__init__.py` files — **medium**

`find . -name "__init__.py"` returns exactly one: `tripper_recon/__init__.py`. `api/`, `providers/`, `reporting/`, `types/`, `utils/` are all PEP 420 implicit namespace packages. This currently **works** — `egg-info/SOURCES.txt` shows all 19 modules were collected, because `[tool.setuptools.packages.find]` defaults `namespaces = true`. The risk is that it works by default rather than by intent: anyone adding `namespaces = false`, or switching to a build backend with different defaults (hatchling, flit, poetry-core), silently ships a wheel containing `cli.py` and nothing it imports. Add five one-line `__init__.py` files.

Also absent: `py.typed`. The package is thoroughly annotated and downstream consumers get none of it.

### 2.6 Version declared in three places

`0.1.0` appears at `pyproject.toml:7`, `tripper_recon/__init__.py:5`, and hardcoded at `api/server.py:15` (`FastAPI(title=…, version="0.1.0")`). `cli.py:385` reads `__version__`, so CLI and package agree; the API server will drift on the first bump. Either use `dynamic = ["version"]` with `attr:` in `pyproject.toml`, or have `server.py` import `__version__`.

---

## 3. Project hygiene

### 3.1 No CI, no CHANGELOG, no CONTRIBUTING, no SECURITY.md

No `.github/` directory at all. For a public repo: no automated lint, no type check, no test run, no dependency audit, no PR template, no issue template, no vulnerability-reporting address. `git log` shows PRs are being merged (`b1c9292`, `6109091`, `fca0f16`) with nothing gating them.

### 3.2 Example outputs exist, are untracked, and one is empty

`ASN_Example.md` (20 lines), `ip_example.md` (20 lines), `domain_example.md` (**0 bytes**) sit in the working tree, all three untracked (`git status`), none referenced from the README. `ip_example.md` is genuinely good material — it is exactly the "what does the output look like" the README lacks — and it is invisible to everyone including the operator's future self.

Before committing them, confirm each was generated against a public reference indicator (`ip_example.md:1` uses `123.123.123.123`, which reads as deliberately chosen — good) and that no output from a real investigation is embedded.

### 3.3 `--prefixes-out` writes into the installed package directory — **medium**

`_default_output_dir()` (`cli.py:298-301`) returns `Path(__file__).resolve().parent.parent / "outputs"`. From a clone that is the repo root — fine. After the README's own recommended `pip install .` (`README.md:40`), `__file__` is inside `site-packages`, so a bare `--prefixes-out asn15169.txt` (`cli.py:361-364` takes the `_default_output_dir()` branch whenever the path has no directory component) writes analyst output into `site-packages/outputs/`. Undocumented, non-obvious, and lost on the next `pip install --upgrade`.

### 3.4 `.gitignore` OPSEC rules are good and unexplained

`.gitignore` blanket-ignores `*.json`, `*.csv`, `*.tsv`, `*.sqlite`, `*.db`, `*.txt`, `outputs/`, `results/`, `reports/` — a deliberate guard (commit `5d0b90d`) against committing investigation artifacts. It is the right call and it is documented nowhere, so the first contributor who wonders why their `requirements.txt`… actually gets an exception, but whose `notes.txt` vanishes, will "fix" it. It also means a user following the README's bulk-processing example cannot version their own target lists — surprising without a sentence of explanation.

Minor contradiction: `outputs/` is ignored while `outputs/.gitkeep` is tracked. Harmless, but it will confuse someone.

### 3.5 Install path is clone-only

`README.md:35-40` offers exactly one route: `git clone` + `pip install .`. No `pipx install git+https://…` (the right answer for a CLI tool — isolated env, on `$PATH`), no editable-install instructions for contributors, no lockfile or constraints file, no note that Python 3.10+ is required *because* `cli.py:419` uses `match`.

---

## 4. The passivity story is entirely missing

This is the gap I would fix first after the `url` claim, because it is where documentation and the operator's hard constraint intersect.

### 4.1 No OPSEC or passivity statement exists

Nowhere in `README.md` does the word passive, OPSEC, or "does not contact the target" appear. A SOC analyst evaluating this tool for use on a live incident has to read `orchestrators.py` to determine whether running it will tip off an adversary. That is the single most important question about an OSINT tool and the README does not answer it.

For the record, the code's actual posture is **good**: every provider module targets a third-party API endpoint (`virustotal.py:10`, `shodan_api.py:10`, `abuseipdb.py:10`, `ipinfo.py:10`, `otx.py:10`, `cloudflare_radar.py:10`, `cloudflare_rest.py:10`, `ripestat.py:10`, `caida.py:10`, `peeringdb.py:10`). There is no socket connect to a target, no port scan, no HTTP fetch of a target URL, no urlscan submission. That is a genuine design virtue and it should be stated on the tin.

### 4.2 Two behaviours need explicit disclosure

**Active DNS resolution against the target's own nameservers.** `orchestrators.py:248` calls `resolve_domain` (`dns.py:8-23`), which is `socket.getaddrinfo` through the **system resolver**. Depending on the analyst's resolver configuration, that query can reach the target domain's authoritative nameservers — meaning the investigation touches infrastructure the adversary may control, and does so from the analyst's egress. `README.md:56` mentions this only as a convenience feature ("automatically resolves IPs").

Note the code already collects a passive alternative: `orchestrators.py:227-235` harvests A/AAAA records from VirusTotal's `last_dns_records`, and `orchestrators.py:249` merges active + passive. So a `--no-resolve` / `--passive-only` mode is a small change on top of what exists. Until it exists, the README must warn.

**Browser User-Agent spoofing by default.** `http.py:10-14` hardcodes a Chrome-on-Windows UA and `default_headers()` (`http.py:34-38`) applies it to every outbound request, including authenticated API calls to VirusTotal, Shodan, AbuseIPDB, and Cloudflare. `.env.example:24-25` bakes the same string in as a template value. Two undocumented issues: masquerading as a browser on API endpoints is at best in tension with several providers' terms, and — more practically for a defender — a distinctive, fixed, slightly-stale UA is a *worse* signature than an honest `tripper-recon/0.1.0`. Whatever the intent, it needs to be written down and justified, and the honest default is arguably the identifying one.

### 4.3 The API server has no documented security posture — **high**

`api/server.py:50` binds `0.0.0.0:8000`. There is no authentication, no API key check, no CORS policy, no rate limiting on any of the four routes. `README.md:69-74` says "Launch the built-in FastAPI server for programmatic access" with no warning.

Anyone on the analyst's network segment can then spend the operator's paid VirusTotal and Shodan quota, and — worse — can use the endpoint as an anonymizing proxy that attributes their lookups to the operator's API keys. The README needs a bind-to-localhost instruction at minimum; the code needs `127.0.0.1` as the default.

---

## 5. `--help` is not man-page quality

`argparse.ArgumentParser` at `cli.py:381` supplies `prog` and a one-line `description` and nothing else. No `epilog` with examples, no environment-variable documentation, no exit-code table, no indication of which providers each subcommand consults or which keys unlock what. Under time pressure `--help` is the doc an analyst actually reads, and this one cannot answer "why is my output half empty?" (answer: unset keys are silently suppressed by `_should_suppress`, `orchestrators.py:73-89`).

Three specific `--help` defects, all cited above: `--monochrome` is a no-op (`cli.py:405` vs `console.py:167,224`); `--enrich` advertises whois/pWhois that `orchestrators.py:529-537` does not implement; and the global `-o/--format` at `cli.py:382` is **silently overridden** by the identically-named subparser option's default at `cli.py:390/395/401`.

That last one I verified against a standalone argparse replica rather than by running the tool:

```
tripper-recon -o json ip 8.8.8.8   →  Namespace(format='console', …)   # flag ignored
tripper-recon ip 8.8.8.8 -o json   →  Namespace(format='json',    …)   # works
```

`--help` advertises a global flag that does nothing in the position users will naturally type it. The README's own example (`README.md:64`) happens to use the working form, so this is a `--help` bug rather than a README bug — but a scripted pipeline built on the advertised flag will silently emit Rich-formatted console text into a JSON parser.

Same shadowing hazard exists for `--rate-limit` and `--user-agent`, which are global-only (`cli.py:383-384`) — those *must* precede the subcommand, and nothing tells the user so.

---

## 6. Documentation set to author

Ordered by value per hour. Everything here is a new file except where noted.

### Tier 1 — before this repo is shown to anyone

| File | Purpose | Contents |
|---|---|---|
| `README.md` *(edit)* | Stop the active inaccuracies | Delete "URL" from line 5. Re-attribute the provider capabilities per §1.2. Add RIPEstat/CAIDA/PeeringDB/Cloudflare-REST to the provider list. Fix `TRIPPER_RECON_LOG_LEVEL` to a numeric value. Soften the 429 claim. Add an **OPSEC & Passivity** section near the top (§4). Add a bind-to-localhost warning to the REST API section. Link out to the new docs below rather than absorbing them |
| `docs/OPSEC.md` | The passivity contract, in writing | What the tool never does (connect to target, scan, fetch URL, submit urlscan) with `file:line` evidence. The complete list of third parties that observe a query, per subcommand. The two disclosed exceptions: system-resolver DNS on the domain path (`dns.py:8`) and the spoofed browser UA (`http.py:10`). Guidance on API-key attribution — a VT lookup is visible to VT. The RFC1918 refusal as an intentional control. What "passive" does *not* protect against (provider-side logging, correlation by the provider) |
| `docs/PROVIDERS.md` | The matrix the operator asked for | One row per provider: env var, whether a key is required, which subcommands use it, what fields are extracted, what the free-tier quota is, source `file:line`. Explicitly flag the **no-key-required** set — RIPEstat, CAIDA, PeeringDB — because "`tripper-recon asn 15169` works with an empty `.env`" is the project's best first impression. Include the AbuseIPDB 365-day window and the OTX 5-title cap |
| `pyproject.toml` *(edit)* | Kill the placeholders | Real `authors`. `[project.urls]`. `classifiers`. `keywords`. `license-files = ["LICENSE"]`. Dev group (`ruff`, `mypy`, `pytest`, `pytest-asyncio`, `respx`). `[tool.ruff]`, `[tool.mypy]`, `[tool.pytest.ini_options]`. `dynamic = ["version"]` sourced from `__init__.py` |
| `LICENSE` *(edit)* | Same | Replace `Your Name` at line 3 |

### Tier 2 — makes it usable by someone who is not the author

| File | Purpose | Contents |
|---|---|---|
| `docs/RATE-LIMITS.md` | Quota survival | Per-provider free-tier limits with a retrieval date and a link (do not write these from memory — they change). What the tool does on 429 today (nothing specific — `backoff.py:10`) vs. what it should do. How `--rate-limit` interacts with per-provider quotas. Recommended batch sizes for bulk IP files. A worked "how many targets before VT free tier cuts me off" example |
| `docs/EXAMPLES.md` | Answers "what do I get?" | Commit and reference the existing `ip_example.md` and `ASN_Example.md`; **generate the missing domain example** (`domain_example.md` is empty). Add a `-o json` sample. Add a degraded-mode sample showing what output looks like with no keys set — that is the most common first-run experience and nothing documents it |
| `docs/THREAT-MODEL.md` | Why a defender should trust it | Assets: the API keys in `.env`, the analyst's egress IP, the indicator list itself (knowing what you are investigating is intelligence). Adversaries: the target infrastructure operator, a malicious provider, a LAN-local attacker against the unauthenticated `0.0.0.0:8000` server (`api/server.py:50`). Controls in place: `.env` gitignored, output-artifact gitignore rules, RFC1918 refusal, no active contact. Accepted risks: system-resolver DNS, provider-side query logging |
| `CONTRIBUTING.md` | Onboards contributors and future-you | Editable install, conda per the operator's convention, `ruff`/`mypy`/`pytest` invocations, Conventional Commits (already in use — `git log`), branch naming (already in use), the **passivity review rule**: any PR adding an outbound request must state whether the destination is a third-party API or the target, and target-directed requests are rejected. Explain the `.gitignore` artifact rules (§3.4) so nobody "fixes" them |
| `SECURITY.md` | Public repo table stakes | Where to report a vulnerability. A statement that the tool holds paid API credentials and that the REST server is unauthenticated by design and must not be exposed |

### Tier 3 — the professional finish

| File | Purpose | Contents |
|---|---|---|
| `.github/workflows/ci.yml` | Gate the rigor | `ruff check`, `ruff format --check`, `mypy tripper_recon/`, `pytest` on 3.10/3.11/3.12. **A grep-based passivity guard**: fail the build if a new outbound URL literal appears outside `providers/` and is not on an allowlist — this converts the hard constraint from a promise into a test |
| `tests/` | The defensibility argument | Start with the pure functions (`validation.py`, `backoff.py`, `cli.py:_load_ip_targets`, `cli.py:_fmt_provider_error`), then `respx`-mocked provider tests. One test that asserts `investigate_ip("10.0.0.1")` refuses. One that asserts no provider module contains a target-directed request |
| `CHANGELOG.md` | Release legibility | Keep-a-Changelog format, backfilled from `git log` (the history is clean enough — the user-agent, rate-limit, and Rich-rendering commits are all identifiable) |
| `cli.py` `--help` *(edit)* | Man-page quality | `epilog` with 5-6 worked examples. An `ENVIRONMENT` block listing every var. Per-subcommand notes naming which providers it consults. A pointer to `docs/PROVIDERS.md` for "why is my output empty". Fix or remove `--monochrome`; fix or re-word `--enrich`; resolve the global-vs-subparser `-o` shadowing |
| `.github/PULL_REQUEST_TEMPLATE.md` | Enforce the constraint at review | A required checkbox: "This PR adds no request to a target-controlled host" |
| `docs/ARCHITECTURE.md` | Optional, portfolio value | The orchestrator/provider/reporting split, the `{"ok": bool, "data"/"error"}` provider contract, the error-suppression policy (`orchestrators.py:73-89`) and why unset keys are silent |

---

## 7. Uncertainties, stated plainly

Three things I could not settle read-only, with what would settle each:

1. **`License: Proprietary` in `PKG-INFO:6`.** The `egg-info/` is gitignored build output and may predate commit `c10dd8e`. Settles it: build into a scratch venv and re-read `PKG-INFO`.
2. **Whether the browser-UA default is deliberate provider evasion or inherited boilerplate.** Commit `3e4455d` ("add user-agent spoofing config") suggests deliberate. The right documentation depends on the intent, and if the intent is evading provider rate limits on authenticated endpoints, that is a terms-of-service question before it is a documentation question. Settles it: operator states the intent.
3. **Whether `ip_example.md` / `ASN_Example.md` contain output from real investigations.** `123.123.123.123` reads as a deliberate placeholder, but I did not audit every line of both files against that standard. Settles it: operator confirms before they are committed.

Two things I verified by proxy rather than by execution, because running the tool was out of scope: the argparse shadowing (standalone replica, §5) and the `int("INFO")` failure (`logging.py:30`, from reading). Both are mechanical and I would call them certain.
