# tripper_recon — Analyst Experience Audit

**Lens:** analyst under time pressure. 02:00, alert fires, indicator pasted, answer needed in <30s, evidence pasted into a ticket.
**Scope read:** `tripper_recon/cli.py`, `tripper_recon/reporting/console.py`, plus `orchestrators.py`, `types/models.py`, `utils/{validation,dns,logging,http,env}.py`, `providers/{virustotal,shodan_api,abuseipdb}.py`, `README.md`, `ip_example.md`, `ASN_Example.md` for corroboration.
**Method:** static read + three isolated experiments in scratch (argparse precedence, `urlparse` on defanged input, `int()` on the documented log level). No repo file was modified. No network call was made. `.env` was never opened.
**Date:** 2026-08-08

---

## Verdict on the tool, in the tool's own idiom

> **DOES NOT ANSWER THE QUESTION — high confidence**
> The output is a provider dump, not an assessment. The only encoding of "malicious" anywhere in the codebase is an ANSI color on two rows, and that color disappears the moment the analyst redirects output into a report file. A missing API key renders as a green `0/0`, which reads as *clean* but means *never checked*.

Everything below is ordered by what would hurt most at 02:00.

---

## Critical

### C1. The tool never states a verdict — `reporting/console.py:24-164`

`render_ip_analysis` builds one flat two-column table of 15-ish rows and returns it (`console.py:35-164`). There is no assessment field, no score, no label, no summary sentence. The same is true of the domain path, which is hand-rolled `console.print` calls in the CLI (`cli.py:224-281`) and of `render_asn_header` (`console.py:167-210`).

`ip_example.md:1-21` is the operator's own captured output and is the proof: `virustotal_detections 5/91`, `virustotal_community_score -37`, `abuseipdb_reports 5`, `abuseipdb_confidence_score 0%`, `otx_pulse_count 50`. Five signals, three of them pointing different directions, and the analyst is left to adjudicate. At 02:00 that adjudication is exactly the work the tool exists to remove, and it is the work most likely to be done badly under pressure.

The data needed to answer the question is already in hand. `orchestrators.py:179-186` assembles VT stats, AbuseIPDB confidence, OTX pulse count, Shodan ports/tags and ASN metadata into one dict. Nothing scores it.

**Severity: critical.** This is the product gap, not a polish item.

### C2. A missing API key renders as a green "clean" result — `orchestrators.py:78-79`, `orchestrators.py:181`, `console.py:70-79`

The failure chain:

1. `virustotal.py:15` returns `{"ok": False, "error": "missing_api_key"}` when `VT_API_KEY` is unset.
2. `orchestrators.py:78-79` — `_should_suppress` returns `True` for `missing_api_key`, so the provider is dropped from `provider_errors` and from `result_errors` entirely.
3. `orchestrators.py:181` stores `"virustotal": {}` because `vt.get("ok")` is false.
4. `console.py:70-79`:
   ```python
   malicious = int(vt_stats.get("malicious", 0) or 0)   # -> 0
   total_engines = sum(...)                              # -> 0
   vt_color = "red" if malicious > 0 else "green"        # -> green
   table.add_row("virustotal_detections", f"[{vt_color}]{malicious}/{total_engines}[/]")
   ```

The analyst sees `virustotal_detections 0/0` in green, with no error row anywhere on screen, and reasonably concludes VirusTotal found nothing. The truth is that VirusTotal was never asked. The suppression at step 2 is deliberate and defensible on its own — nobody wants a wall of "no key" noise every run — but combined with step 4 it converts *absence of evidence* into *evidence of absence*, silently, in the one place the analyst is looking.

AbuseIPDB and OTX fail differently but no better: `console.py:86` (`if abuse:`) and `console.py:100` (`if otx:`) simply omit the rows. The analyst has to notice a *missing row* to notice a missing provider, at 02:00, on a screen of twenty rows that vary per target anyway.

**Severity: critical.** A false-negative on a real C2 because the Shodan key expired last Tuesday is the worst outcome this tool can produce, and today nothing on screen would tell you.

### C3. "Malicious" is encoded only in ANSI color, which is stripped on redirect — `console.py:78-79`, `console.py:95-96`

The sole malice signal in the IP report is `vt_color` / `ab_color`. There is no accompanying word. Rich's `Console` (instantiated bare at `cli.py:22`) auto-detects the output stream and disables color when stdout is not a terminal — which is precisely what happens when the analyst runs `tripper-recon ip 1.2.3.4 > incident-4471.md`, the exact workflow `ip_example.md` and `ASN_Example.md` are artifacts of. Look at `ip_example.md:10`: `virustotal_detections 5/91` — no color, no label, indistinguishable in weight from `postal_code 100000` two rows above.

So the report the analyst pastes into the ticket has had its only verdict signal removed in transit.

Same defect for colorblind analysts on a live terminal, and for anyone on a light-background theme where the red/green distinction at small point size is weak.

**Confidence: likely** on the Rich stripping behaviour — it is Rich's documented default but I could not execute it (`rich` is not installed in my shell). Settle it in one command: `tripper-recon ip 8.8.8.8 > /tmp/x; cat -v /tmp/x | head -20` and check for ESC sequences.

**Severity: high.**

---

## High

### H1. There is no exit-code contract a script can rely on — `cli.py:201`, `cli.py:295`, `cli.py:376`, `orchestrators.py:190`

What exists today:

| Path | Exit | Meaning |
|---|---|---|
| `_cmd_ip` (`cli.py:201`) | `0 if failed == 0 else 1` | 1 = the *investigation object* came back `ok=False` or the coroutine raised |
| `_cmd_domain` (`cli.py:295`) | always `0` on the success path | provider errors on every resolved IP are invisible to the exit code |
| `_cmd_asn` (`cli.py:376`) | always `0` on the success path | same |
| bad ASN string (`cli.py:433`) | `2` | the one honest code |

Two consequences.

First, **verdict is not in the exit code at all**, so `tripper-recon ip "$IOC" || open_case` is impossible. Any SOAR/bash integration must pipe to `jq`, which brings us to H2.

Second, **a completely failed lookup exits 0**. `investigate_ip` returns `InvestigationResult(ok=True, ...)` at `orchestrators.py:190` unconditionally once the IP parses — even if all five providers errored, in which case `data` is five empty dicts and `errors` is populated but never consulted by `cli.py:171`. So `succeeded += 1`, `failed` stays 0, exit 0. The script downstream believes it got an answer.

**Severity: high.**

### H2. JSON log lines are written to stdout and corrupt `--format json` — `utils/logging.py:42`, `cli.py:144`, `cli.py:161`, `cli.py:172`

`logging.py:42` is `sys.stdout.write(json.dumps(record) + "\n")`. `cli.py` calls `log["error"](...)` on the bulk-IP path at lines 144, 161 and 172 — all of which run *regardless* of `output == "json"`, unlike the guarded `console.print` calls beside them. `console.print_json` then emits the real payload to the same stream at `cli.py:196`.

Result: `tripper-recon ip suspicious.txt -o json | jq .` fails on any run where at least one target errors — which, on a real list of dead adversary infrastructure, is most runs. The workaround (`| tail -n +N`) is not one an analyst finds at 02:00.

Logs belong on stderr. This is a one-line change with no downside.

**Severity: high.**

### H3. `-o json` placed before the subcommand is silently ignored — `cli.py:382` vs `cli.py:390`, `395`, `401`

`-o/--format` is declared on the top-level parser (`cli.py:382`) *and* separately on all three subparsers (`390`, `395`, `401`). Since Python 3.7, `_SubParsersAction.__call__` parses the subcommand into a fresh namespace and then copies every key back over the parent namespace — including the subparser's *defaults*. The subparser's `default="console"` therefore overwrites a top-level `--format json`.

Verified on Python 3.12.13 with a faithful reproduction of the parser:

```
A) -o json BEFORE subcmd : {'format': 'console', ..., 'cmd': 'ip', 'ip': '8.8.8.8'}
B) -o json AFTER  subcmd : {'format': 'json',    ..., 'cmd': 'ip', 'ip': '8.8.8.8'}
```

`tripper-recon -o json ip 8.8.8.8` prints a Rich table. No warning. A pipeline built on that invocation gets human output and fails on parse, and the analyst's mental model ("flags go after the program name") is the one that breaks.

Fix: delete the top-level `-o/--format` at `cli.py:382`, or delete the three subparser copies and set `parents=`. One of them, not both.

**Severity: high.**

### H4. Pasting a defanged indicator crashes the tool with a traceback — `cli.py:205`

`_cmd_domain` begins `parsed = urlparse(domain)` with no guard. Defanged indicators are how IOCs arrive — in the ticket, in the email, in the vendor report. Verified:

```
'hxxp://evil[.]com'     -> RAISED ValueError: Invalid IPv6 URL
'evil[.]com'            -> hostname='evil[.]com'   valid_domain=False
'www.evil[.]com/path'   -> hostname='www.evil[.]com/path'  valid_domain=False
'123[.]123[.]123[.]123' -> valid_ip=False
```

The first case is an **unhandled exception** — `cli.py:205` is inside `asyncio.run(...)` at `cli.py:423` with no try/except anywhere up the stack, so the analyst gets a Python traceback. The others fail into `orchestrators.py:195` → `"Invalid domain"` → `cli.py:212` prints `Domain investigation failed: Invalid domain` with no hint that the brackets are the problem and no suggestion to refang.

There is no `refang()` anywhere in `utils/validation.py:1-38`.

At 02:00 this costs 60-90 seconds and a context switch, on the single most common input shape.

**Severity: high.**

### H5. No defanging on output — the pasted ticket becomes a set of live links to adversary infrastructure — `console.py:68, 84, 98, 106, 113, 132`; `cli.py:226, 255-257, 260, 264`

Every report emits fully live URLs, and the indicator itself is printed raw (`console.py:39`, title at `console.py:163`; domain title at `cli.py:224`). There is no `--defang` flag in the parser (`cli.py:379-407`) and no defang helper in the codebase.

Two distinct harms, both real:

1. **The indicator itself.** `--- IP lookup for 185.220.101.5 ---` pasted into Jira/ServiceNow/Slack is auto-linkified by most of them, and `evil.com` in a domain report becomes a one-click navigation for the next reader of the ticket. That is the ticket system defeating the tool's own passive-only constraint on someone else's behalf.
2. **The provider links are fine to click, but they are indistinguishable from the indicator.** Nothing in the layout separates "safe pivot link" from "hostile indicator".

For a tool whose stated hard constraint is *never touch adversary infrastructure*, shipping output that hands the next human a clickable link to it is an inconsistency worth closing.

**Severity: high.**

### H6. The decision-relevant signal is below the fold — `console.py:39-68` precede `console.py:79`

Row order today, from `render_ip_analysis`: `ip`, `city`, `country`, `isp`, `organization`, `coordinates`, `postal_code`, `cloudflare_radar_link`, *then* `virustotal_detections` at row 9.

`postal_code` (`console.py:65-66`) outranks the threat verdict. Latitude/longitude (`console.py:61-63`) outrank the threat verdict. On a 24-line terminal with a domain that resolved to six IPs, the first thing the analyst sees for IP #4 is Beijing's postal code.

Compare `ip_example.md:2-10` — eight rows of geolocation preamble before the first number that bears on the question.

**Severity: high** (cheap to fix, disproportionate payoff).

---

## Medium

### M1. A bulk run shows nothing until the slowest target finishes — `cli.py:150-151`

```python
tasks = [investigate_ip(t) for t in targets]
gathered = await asyncio.gather(*tasks, return_exceptions=True)
```

Every target is dispatched at once and *nothing* is rendered until all of them have returned; the render loop at `cli.py:157` runs only after `gather` completes. The analyst sees `Processing 500 targets from "..."` (`cli.py:148`) and then a frozen terminal. No spinner, no counter, no per-result streaming, no ETA, and no way to tell a slow run from a hung one. `rich.progress` is already a dependency.

Two aggravating factors:

- **Concurrency is not actually bounded per-target.** `RateLimiter` (`http.py:61-73`) lazily creates one process-global semaphore, but `orchestrators.py:117` constructs it as `RateLimiter(rate=5)` inside each investigation, so whichever investigation runs first fixes the global limit at 5 and `configure_rate_limit(args.rate_limit)` at `cli.py:415` is overridden for the whole process. The `--rate-limit` flag's help text — "Max concurrent outgoing API requests across global providers" (`cli.py:383`) — does not describe what happens.
- Results are printed in input order after the fact, so a malicious hit at line 400 stays invisible for the whole run.

**Severity: medium** (high if bulk lists are a routine workflow).

### M2. The bulk summary counts plumbing, not threat — `cli.py:198-199`

```
Summary: total=500 succeeded=498 failed=2
```

That tells the analyst the network worked. It does not tell them which two of the 500 IPs to look at. There is no verdict-ranked roll-up, which is the only thing a 500-line triage run is for.

**Severity: medium.**

### M3. Shodan tags and CPEs are collected, then discarded — `providers/shodan_api.py:29` vs `console.py` (absent)

`shodan_host` returns `{"ports", "org", "tags", "cpe"}`. `console.py:29` reads only `.get("ports", [])`. `grep` for `tags`/`cpe` across `console.py` and `cli.py` returns nothing.

Shodan tags include `malware`, `c2`, `compromised`, `honeypot`, `self-signed`, `tor`. Those are among the highest-signal, lowest-ambiguity facts the tool retrieves, and they are dropped on the floor while `postal_code` gets a row. Same story for VT's `vt_tags` (`virustotal.py:79`), fetched on the domain path and never printed (`cli.py:228-270` prints `vt_categories` only), and for `ptr`, which is set to `None` and carried through as dead weight (`orchestrators.py:254`, `orchestrators.py:310`) despite `utils/dns.py:26-34` implementing `reverse_ptr`.

**Severity: medium.**

### M4. No timestamp, no tool version, no provider-coverage line — evidence is not defensible — `console.py:163`

The report header is `--- IP lookup for {ip} ---` and nothing else. An incident report needs *when* the lookup ran (VT scores move daily), *what version* produced it, and *which providers answered*. None are emitted in any format. `--version` exists (`cli.py:385`) but never appears in output.

Six months later, in a post-incident review, `ip_example.md` cannot be dated or attributed. That is the "defensibility of the answer" half of the operator's goal, unaddressed.

**Severity: medium.**

### M5. Active vs passive resolution is not distinguished in the output — `orchestrators.py:248-249`, `cli.py:283`

```python
active_ips = await resolve_domain(domain)     # system resolver, against the target
ips = active_ips + passive_ips                # VT passive DNS
ips = dedupe_preserve_order(ips)
```

The merged list is then printed under one label: `- Resolving "{domain}"... {n} IP addresses found:` (`cli.py:283`).

Two problems in my lane. (a) The analyst cannot tell which IPs are *current* (live resolution) from which are *historical* (VT passive DNS) — a distinction that decides whether an IP goes on a blocklist. (b) The output gives no indication that a live DNS query was made at all, which matters because `utils/dns.py:8-23` uses `socket.getaddrinfo` against the target name — the passive-only grey area. The analyst deserves to know from the output that the tool touched DNS. (The leak question itself belongs to the passive-only lens; I flag only the transparency gap.)

**Severity: medium.**

### M6. `--monochrome` does nothing — `cli.py:405`, `console.py:167`, `console.py:224`

`use_color` is accepted by `render_asn_header` and `render_asn_bgp_panels` and never referenced in either body (`grep use_color` returns only the two signatures). Styles are hardcoded throughout. The comment at `cli.py:311` says the flag is "retained for flag compat", but it is still advertised in `--help` as "Disable ANSI colors in console output". An analyst who needs clean text for a ticket will try it, get colored output, and lose time. Rich honours `NO_COLOR`; either wire the flag to `Console(no_color=True)` or delete it from the parser.

**Severity: medium** (low impact, but it is documented behaviour that does not happen).

### M7. The documented log-level value crashes the tool at import — `utils/logging.py:30`, `README.md:97`

```python
min_level = int(os.getenv("TRIPPER_RECON_LOG_LEVEL", "20"))
```

`README.md:97` documents `TRIPPER_RECON_LOG_LEVEL=INFO`. Verified: `int("INFO")` → `ValueError: invalid literal for int() with base 10: 'INFO'`. Because `logger("cli")` executes at module import (`cli.py:21`, and `orchestrators.py:26`), an exported env var kills the tool before `main()` runs, with a raw traceback and no message about the variable.

Compounding it: `load_env()` is called at `cli.py:380`, *after* both module-level `logger()` calls, so a `TRIPPER_RECON_LOG_LEVEL` set in `.env` is read too late to have any effect at all. The knob is simultaneously non-functional via the documented mechanism and fatal via the shell.

Accept level names, or accept both, and defer `logger()` binding until after `load_env()`.

**Severity: medium.**

### M8. No ticket-ready output format — `cli.py:382`, `cli.py:390`, `cli.py:395`, `cli.py:401`

Choices are `console` and `json`. `README.md:26` claims "Clean, borderless console tables powered by `rich` for immediate markdown reporting", but the output is space-padded plain text (see `ip_example.md`), not markdown — pasted into any markdown-rendering ticket system the alignment collapses into one run-on paragraph. The `.md` example files in the repo root are the operator working around this by hand.

The second half of the analyst's job — "capture the key facts for an incident report" — has no supported path.

**Severity: medium.**

### M9. README advertises URL investigation; there is no `url` subcommand — `README.md:5` vs `cli.py:386-407`

"A high-performance, asynchronous OSINT toolkit for IP, Domain, URL, and ASN investigations." The subparsers are `ip`, `domain`, `asn`. An analyst holding a full URL (the most common phishing IOC) reads the README, tries `tripper-recon url hxxps://...`, gets `invalid choice`, and has to work out that they should strip to the hostname themselves. Note `_cmd_domain` *does* accept a URL and extract the hostname (`cli.py:205-206`) — the capability half-exists and is undiscoverable.

**Severity: medium.**

### M10. Global flags are rejected after the subcommand — `cli.py:383-384`

`--rate-limit` and `--user-agent` exist only on the top-level parser, so `tripper-recon ip 8.8.8.8 --rate-limit 5` fails. Verified: `error: unrecognized arguments: --rate-limit 5`, exit 2. They also do not appear in `tripper-recon ip --help`, so the analyst cannot discover them from the place they would look. Combined with H3 (where the *other* flag must go after), the tool has two global-ish flags with opposite and unmarked position rules.

**Severity: medium.**

---

## Low

### L1. A typo'd bulk filename is silently investigated as an indicator — `cli.py:124-135`

`_load_ip_targets` returns `([value], None)` when the path is not an existing file (`cli.py:126-127`). `tripper-recon ip ./ips.tx` (typo) therefore investigates the literal string `./ips.tx`, producing `IP: ./ips.tx` / `error: Invalid IP address` and exit 1. The real message ("that file does not exist") is never shown. Distinguish "looks like a path" (contains `/`, or ends `.txt`/`.csv`, or `--input-file` is explicit) from "looks like an indicator".

### L2. Bulk input is IP-only — `cli.py:141-142` vs `cli.py:204`

`domain` and `asn` take a single argument. An analyst with a list of 30 phishing domains has no path. Inconsistent surface for no stated reason.

### L3. `--ports-limit` swallows invalid values — `console.py:117-124`

`--ports-limit` is typed `str` (`cli.py:391`) and parsed inside the renderer, where `ValueError`/`TypeError` silently falls back to 25. `--ports-limit al` (typo for `all`) truncates without saying so. Validate in the parser with a custom type; the renderer should not be doing argument validation.

### L4. Domain-path exit code ignores per-IP provider failures — `cli.py:295`

`_cmd_domain` returns 0 whenever `res.ok`, and `investigate_domain` sets `ok=True` unconditionally on the success path (`orchestrators.py:331`) even when `result_errors` has an entry for every provider on every IP. Subsumed by H1, listed separately because the domain path needs its own fix.

### L5. Unused import — `cli.py:12`

`from rich.panel import Panel` — `Panel` is never used in `cli.py`. Cosmetic; noted because it suggests a panel-based layout was started and abandoned, which is roughly what I am recommending you finish.

---

## The output layout I would ship

Design rules, in priority order:

1. **The verdict is the first thing on screen, in words**, with color as reinforcement only.
2. **Two or three facts justify it, immediately below** — never an unexplained score.
3. **Coverage is stated, always** — "not checked" is a distinct and visible state from "clean".
4. **Detail comes after**, and geolocation is detail.
5. **Indicators are defanged; pivot links are not** — and the difference is visually obvious.
6. **A paste-ready block ends the report.**

### Target console output (IP)

```
━━ 185.220.101[.]5 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  MALICIOUS · confidence high · 4 of 5 sources agree
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WHY
  VirusTotal    14/94 malicious, 3 suspicious      reputation -87
  AbuseIPDB     100% confidence, 312 reports/365d
  AlienVault    7 pulses  · "Emotet C2 Nov 2025", "TA505 infra"
  Shodan tags   malware, c2

NETWORK
  AS205100 F3 Netze e.V. · DE · Berlin
  open ports    22, 80, 443, 9001, 9030   (5 of 5 shown)

PIVOTS
  virustotal    https://www.virustotal.com/gui/ip-address/185.220.101.5
  abuseipdb     https://www.abuseipdb.com/check/185.220.101.5
  shodan        https://www.shodan.io/host/185.220.101.5
  otx           https://otx.alienvault.com/indicator/ip/185.220.101.5

COVERAGE      virustotal ok · abuseipdb ok · otx ok · shodan ok · ipinfo ok
QUERIED       2026-08-08T06:12:44Z · tripper-recon 0.1.0 · passive sources only
```

Degraded case, which is the one that matters most:

```
━━ 91.240.118[.]172 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  UNDETERMINED · 3 of 5 sources unavailable
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WHY
  AbuseIPDB     0% confidence, 0 reports
  IPInfo        AS49505 Selectel · RU

NOT CHECKED
  VirusTotal    no API key (set VT_API_KEY)
  AlienVault    no API key (set OTX_API_KEY)
  Shodan        HTTP 401 unauthorized

COVERAGE      abuseipdb ok · ipinfo ok · virustotal NO KEY · otx NO KEY · shodan ERROR
```

That second screen is the whole point. Today it renders as a green `0/0` and reads as clean.

### Target paste block (`--format markdown`)

```markdown
**185.220.101[.]5** — **MALICIOUS** (high confidence)

| source | result |
|---|---|
| VirusTotal | 14/94 malicious, 3 suspicious (rep -87) |
| AbuseIPDB | 100% confidence, 312 reports / 365d |
| AlienVault OTX | 7 pulses — Emotet C2 Nov 2025, TA505 infra |
| Shodan | tags: malware, c2 · ports 22, 80, 443, 9001, 9030 |
| Network | AS205100 F3 Netze e.V. · DE |

Coverage: 5/5 sources responded.
Queried 2026-08-08T06:12:44Z with tripper-recon 0.1.0 (passive sources only).
```

---

## Exactly what changes, file by file

### New: `tripper_recon/reporting/verdict.py`

Pure functions, no I/O, unit-testable without network. This is the missing module.

```python
@dataclass(frozen=True)
class Verdict:
    label: str          # MALICIOUS | SUSPICIOUS | CLEAN | UNDETERMINED
    confidence: str     # high | medium | low
    reasons: list[str]  # one per rule that fired -> becomes the WHY block
    coverage: dict[str, str]   # provider -> ok | no_key | error | not_found

def score_ip(data: dict) -> Verdict: ...
def score_domain(data: dict) -> Verdict: ...
```

Thresholds as module-level named constants, not inline literals, so they are reviewable and tunable:

- `MALICIOUS` when VT malicious ≥ 4, **or** AbuseIPDB confidence ≥ 75, **or** (VT malicious ≥ 1 **and** OTX pulses ≥ 3), **or** a Shodan tag in `{malware, c2, compromised}`.
- `SUSPICIOUS` when VT malicious 1-3, **or** AbuseIPDB 25-74, **or** OTX pulses ≥ 1.
- `CLEAN` only when ≥ 2 reputation sources returned `ok` and all are zero.
- `UNDETERMINED` otherwise — **this is the default**, not `CLEAN`.

Every rule that fires appends its reason string. A verdict with an empty `reasons` list is a bug, and should be asserted as such. That property is what keeps the tool defensible: it can never show a label it cannot justify.

### `tripper_recon/orchestrators.py` — one addition, ~8 lines

At `orchestrators.py:169-177` the loop already knows each provider's outcome. Emit it:

```python
coverage[name] = ("ok" if payload.get("ok")
                  else "no_key" if payload.get("error", "").startswith("missing_")
                  else payload.get("error", "error"))
```

Add `data["coverage"] = coverage` alongside `data["errors"]` at `orchestrators.py:187-188`. Keep `_should_suppress` exactly as it is — it stays right for the *error* channel; coverage is a new, separate channel. Mirror in `investigate_domain` (`orchestrators.py:283-293`) and `investigate_asn` (`orchestrators.py:422-430`).

This single change is what turns C2 from a silent false-negative into a visible `NOT CHECKED`.

### `tripper_recon/reporting/console.py` — the substantive rewrite

1. **`console.py:24`** — change the signature to `render_ip_analysis(ip, data, *, ports_limit="25", defang=True, queried_at=None)` and, as the first statement, `v = score_ip(data)`.
2. **Insert a banner ahead of everything**, replacing the bare title at `console.py:163`:
   ```python
   banner = Text(f"  {v.label} · confidence {v.confidence} · {v.summary_line}  ",
                 style=f"bold white on {VERDICT_BG[v.label]}")
   ```
   The label word carries the meaning; the background carries the glance. Redirecting to a file keeps the word.
3. **Add a WHY table from `v.reasons`**, rendered immediately under the banner, before any existing row.
4. **Delete `console.py:70-79` in its current form.** Replace with a coverage-aware branch:
   ```python
   if coverage.get("virustotal") != "ok":
       table.add_row("virustotal", "[yellow]NOT CHECKED[/] — " + _why_missing(coverage["virustotal"]))
   else:
       table.add_row("virustotal", f"{malicious}/{total_engines} malicious")
   ```
   Do the same for the `if abuse:` branch at `console.py:86` and the `if otx:` branch at `console.py:100` — an absent provider gets a row saying so, never silence.
5. **Move `console.py:41-67`** (city, country, isp, organization, coordinates, postal_code) into a `NETWORK` group rendered *after* WHY. Drop `postal_code` and `coordinates` from the default view entirely behind a `--verbose`; neither has ever decided a triage.
6. **Add a `PIVOTS` group** and move `console.py:68, 84, 98, 106, 113, 132` (the six link rows) into it, so links are visually segregated from indicators.
7. **Render Shodan tags** — a one-row addition next to `open_ports` at `console.py:130`, reading `data["shodan"].get("tags")`. Highest signal-per-character in the whole payload and currently discarded.
8. **Add a `COVERAGE` / `QUERIED` footer** — `console.py:163-164` returns the `Group`; append two `Text` lines built from `v.coverage`, a UTC timestamp passed in by the caller, and `__version__`.
9. **New `render_ip_markdown(ip, data, ...) -> str`** in the same module, emitting the paste block above. Same `score_ip` call, so the console and the ticket can never disagree.
10. **`console.py:167` and `console.py:224`** — either honour `use_color` or delete the parameter and the `--monochrome` flag with it.

### New: `tripper_recon/reporting/defang.py`

```python
def defang(value: str) -> str:   # 1.2.3.4 -> 1.2.3[.]4 ; http -> hxxp
def refang(value: str) -> str:   # inverse, tolerant of [.] (.) {.} [:] hxxp
```

Apply `defang` at `console.py:39` (the `ip` row), the banner, and the report titles. Do **not** apply it to the pivot URLs — those are safe and must stay clickable. Default on for `console` and `markdown`; always off for `json` (machine consumers need the real value). Add `--fang` to opt out.

### `tripper_recon/utils/validation.py`

Add `refang()` here (it is input validation, and `cli.py` should not own string surgery).

### `tripper_recon/cli.py`

1. **`cli.py:205`** — `domain = refang(domain)` *before* `urlparse`, and wrap the `urlparse` call in `try/except ValueError` with the message `Could not parse "{domain}" as a domain or URL.` Fixes H4's traceback.
2. **`cli.py:142`** — same `refang` on each bulk target inside `_load_ip_targets` (`cli.py:130-134`).
3. **`cli.py:382`** — delete the top-level `-o/--format`, keeping only the subparser copies (fixes H3). Add `markdown` to all three `choices` lists (`390`, `395`, `401`).
4. **`cli.py:383-384`** — move `--rate-limit` and `--user-agent` onto a shared `parents=[common]` parser so they work in both positions and appear in `tripper-recon ip --help` (fixes M10).
5. **`cli.py:150-151`** — replace `asyncio.gather` with a bounded `asyncio.Semaphore(args.concurrency)` plus `asyncio.as_completed`, rendering each result the moment it lands. Wrap in `rich.progress.Progress(console=Console(stderr=True))` so stdout stays clean for redirect (fixes M1).
6. **`cli.py:198-199`** — replace the succeeded/failed line with a verdict-ranked table: `verdict | indicator | top reason`, MALICIOUS first, then SUSPICIOUS, then UNDETERMINED; CLEAN collapsed to a count (fixes M2).
7. **`cli.py:144, 161, 172`** — these are fine once `logging.py:42` moves to stderr.
8. **Exit codes.** Publish a contract in `--help` epilog and README:

   | code | meaning |
   |---|---|
   | 0 | ran to completion |
   | 2 | usage error / invalid indicator |
   | 3 | ran, but coverage insufficient for a verdict on ≥1 target |
   | 4 | internal error |

   Keep verdict *out* of the default exit code — non-zero-on-malicious silently breaks `set -e` pipelines and surprises people. Add an explicit opt-in, `--exit-on-verdict`, which maps `MALICIOUS → 1`, `SUSPICIOUS → 3`, `CLEAN → 0`, so `tripper-recon ip "$IOC" --exit-on-verdict || open_case` is available to anyone who asks for it. Highest severity across targets wins in bulk mode. Fixes H1.

### `tripper_recon/utils/logging.py`

1. **`logging.py:42`** — `sys.stdout` → `sys.stderr` (fixes H2).
2. **`logging.py:30`** — accept level *names* as well as ints, and defer the env read to first log call rather than import time so `load_env()` at `cli.py:380` has actually run (fixes M7).

### `README.md`

Correct line 5 (no URL subcommand exists — either build it as an alias for `domain` with hostname extraction, which is ~5 lines given `cli.py:205-206` already does the work, or remove the claim), line 26 (the output is not markdown until `--format markdown` ships), and line 97 (`TRIPPER_RECON_LOG_LEVEL=INFO` currently crashes the tool).

---

## Sequencing, if you only do part of it

The 80% of the value sits in a small, contained set:

1. `verdict.py` + the coverage field in `orchestrators.py` + the banner/WHY/NOT-CHECKED block in `console.py`. **C1, C2, C3, H6 all close together.** This is the change that turns a dumper into an answering tool.
2. `logging.py:42` stdout → stderr, and delete the duplicate `-o/--format`. **Two lines, closes H2 and H3.**
3. `refang()` + the `try/except` at `cli.py:205`. **Closes H4**, removes the most likely 02:00 dead end.
4. `defang.py` and `--format markdown`. **Closes H5 and M8** — the ticket half of the job.

Items 2 and 3 are under an hour combined and remove two hard stops. Item 1 is the real work and the real product.

---

## What I could not settle

- **Rich color stripping on redirect (C3).** `rich` is not installed in my environment, so I reasoned from documented default behaviour rather than observation. Settle with `tripper-recon ip 8.8.8.8 > /tmp/x && cat -v /tmp/x | head -20` — ESC sequences present or absent decides it. The *recommendation* (put the verdict in words, not only color) holds either way.
- **Whether bulk lists are a real workflow.** M1/M2 are scored medium on the assumption that the file-input path in `cli.py:124-135` gets used. If the operator only ever investigates single indicators, both drop to low; if bulk triage is routine, M1 is high.
- **Verdict thresholds.** The numbers in `score_ip` above are a starting proposal, not a validated model. They should be checked against a labelled sample of known-bad and known-good indicators before anyone trusts the label, and the constants should be visible at the top of `verdict.py` precisely so that check is easy to run and easy to revise.
- **`_should_suppress` intent.** I read the suppression at `orchestrators.py:73-89` as deliberate noise control and my recommendation preserves it, adding a parallel coverage channel rather than removing it. If the intent was instead "these providers are optional and their absence is immaterial", the fix is the same but the argument for it is stronger, not weaker.
