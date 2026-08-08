# tripper_recon — Correctness & Defect Audit

**Lens:** correctness and defects
**Repo:** `/home/echo/dev/tripper_recon` @ `feat/work-20260808-recon-hardening` (working tree at `de277f4` + 3 untracked example files)
**Scope read:** `cli.py`, `orchestrators.py`, `reporting/console.py`, `api/server.py`, `types/models.py`, all of `utils/*.py`, all 10 provider modules, `pyproject.toml`, `README.md`, `.env.example`
**Mode:** read-only. No file in the target repo was modified. `.env` was never opened. No network call was made to any indicator or provider.
**Verification method:** every "certain" finding below was reproduced by running the repo's own logic, copied verbatim into throwaway scripts under the scratchpad. Those scripts are listed in Appendix A.

---

## Judgment against the operator's goal

The tool's job is to answer *"is this IP / domain / URL malicious?"* fast and defensibly. Three of the defects below break that job directly rather than merely inconveniencing the user:

- **A failed or unconfigured provider renders as a green clean verdict** (F1). This is the single most damaging defect in the codebase — it produces a *wrong answer with high confidence*, which is worse than no answer.
- **Provider-controlled text is interpreted as rich markup** (F2), which both crashes batch runs and lets an attacker who can name an OTX pulse paint green text into an analyst's report.
- **BGP hijack attribution is fabricated by arithmetic on one page of results** (F6), so an ASN can be reported "always as a victim" when it is the hijacker.

Everything else is real but secondary.

---

## Findings

### F1 — CRITICAL — A dead provider renders as a green "0/0" clean verdict

**Anchor:** `tripper_recon/reporting/console.py:70-79`, with `tripper_recon/orchestrators.py:181` and `tripper_recon/orchestrators.py:78`

```python
# orchestrators.py:180-185 — a failed provider collapses to an empty dict
"virustotal": vt.get("data", {}) if vt.get("ok") else {},
```
```python
# console.py:70-79 — an empty dict is then arithmetic'd into a verdict
malicious = int(vt_stats.get("malicious", 0) or 0)
total_engines = sum(int(v or 0) for v in vt_stats.values())
vt_color = "red" if malicious > 0 else "green"
table.add_row("virustotal_detections", f"[{vt_color}]{malicious}/{total_engines}[/]")
```

`{}` and "94 engines all said harmless" are indistinguishable at this point. The row prints **`virustotal_detections: 0/0` in green**.

It gets worse: `_should_suppress` (`orchestrators.py:78`) returns `True` for `missing_api_key`, so when `VT_API_KEY` is absent the failure is stripped from `provider_errors` *and* from `result_errors`. The `provider_errors` table in `console.py:134-161` never renders. There is no visual difference whatsoever between "VirusTotal says clean" and "VirusTotal was never called".

**Reproduced:** `SIM3` → `virustotal_detections renders as [green]0/0[/]`.

**Failing input:** run `tripper-recon ip <any-ip>` with `VT_API_KEY` unset (or with the key rate-limited to 429, or expired → 401). The analyst sees a green zero-detection line and closes the ticket.

Same shape, different symptom, in three other places:
- AbuseIPDB: `console.py:86` — `if abuse:` is falsy on failure, so **both** the reports row and the confidence row vanish silently (`console.py:87-96`).
- Shodan: `console.py:115` — `if ports:` is falsy on failure, so the `open_ports` row vanishes, reading as "no open ports".
- OTX: `console.py:100-113` — on failure only the link is printed, no pulse count.

**Fix:** never let a missing measurement render as a measured zero. Carry per-provider status into the render layer and print `unavailable (no API key)` / `unavailable (HTTP 429)` in place of the number, in a distinct colour. Delete the `missing_api_key` branch from `_should_suppress` for any provider whose output feeds a verdict field, or gate the field on an explicit `queried: bool`.

---

### F2 — CRITICAL — Provider-controlled strings are parsed as rich markup: batch-killing crash + verdict spoofing

**Anchor:** `tripper_recon/reporting/console.py:39-132` (every `table.add_row(...)` with a provider string), reached from `tripper_recon/cli.py:183-184`

Rich interprets `[...]` in a plain `str` passed to `Table.add_row` as console markup. Two consequences, both verified against rich 14.3.2:

**(a) Unhandled crash.** A stray `[/]` anywhere in provider data raises `rich.errors.MarkupError`. Reproduced:

```
TEST2 RAISED: MarkupError closing tag '[/]' at position 10 has nothing to close
```

In `cli.py:183-184` the render is outside any `try`, and it runs *after* `asyncio.gather` has already completed every investigation (`cli.py:151`). So one poisoned field aborts the process, discarding every already-paid-for result for the remaining targets and the JSON summary at `cli.py:196`.

**Failing input:** an IP whose Shodan `org` (`shodan_api.py:24`), VT `whois` (`cli.py:88`) or OTX pulse title (`console.py:109`) contains `[/]`. Run it as target #3 of a 500-line file → 497 completed lookups discarded, API quota already spent.

**(b) Verdict spoofing.** Reproduced — the tags are consumed and the style applied:

```
TEST1: add_row("otx_pulse_titles", "[green]BENIGN - no detections[/]")
       renders as styled green text, brackets stripped
```

OTX pulse names are community-submitted. An attacker who publishes a pulse named `[green]0/94 — no detections[/]` gets that string rendered, in green, inside the analyst's terminal report, adjacent to the real detection rows. Shodan `org` and VT WHOIS fields are also adversary-influenceable.

**Fix:** `rich.markup.escape()` every provider-sourced value before it reaches `add_row` / `console.print`, or construct values as `rich.text.Text` (which never parses markup). Keep markup only for strings the tool itself authors.

---

### F3 — HIGH — `_should_suppress` raises `TypeError` on a Cloudflare GraphQL error, aborting the whole investigation

**Anchor:** `tripper_recon/orchestrators.py:78` (with `tripper_recon/providers/cloudflare_radar.py:42` and `:67`)

```python
# cloudflare_radar.py:42 — error is a LIST of GraphQL error objects
return {"ok": False, "error": j["errors"]}
```
```python
# orchestrators.py:78 — membership test against a set requires a hashable operand
if err in {"missing_api_key", "missing_api_token", "missing_token", "API key not configured"}:
```

`list in set` calls `hash()` on the list. **Reproduced:** `SIM1 CRASH: TypeError unhashable type: 'list'`.

The call sites are `orchestrators.py:425` (in `investigate_asn`) and `orchestrators.py:303` (in `investigate_domain`). Neither is wrapped in a `try`, so the exception propagates out of the orchestrator, out of `asyncio.run` (`cli.py:435`), and the analyst gets a Python traceback instead of a report. In `_cmd_ip` the equivalent path (`cli.py:158`) would catch it and report the investigation as crashed.

**Failing input:** any `tripper-recon asn <n>` where the Cloudflare Radar GraphQL endpoint returns a top-level `errors` array — an expired token, a token missing the Radar scope, or a schema change on Cloudflare's side. The `_call_str` fallback at `cloudflare_radar.py:61-71` returns the same list-valued `error`, so the fallback does not rescue it.

**Fix:** normalise the error field to a string in the provider (`"graphql_error"`, with the array under a separate `details` key), and defensively guard `_should_suppress` with `isinstance(err, str)`.

---

### F4 — HIGH — The rate limiter is a no-op and `--rate-limit` is ignored; bulk runs fan out without bound

**Anchor:** `tripper_recon/orchestrators.py:117-129`, `tripper_recon/utils/http.py:54-73`, `tripper_recon/cli.py:150-151`

Three compounding bugs:

1. **The semaphore is released before any request is issued.** `orchestrators.py:120-129` wraps only `asyncio.create_task(...)`, which schedules the coroutine and returns immediately. Acquire → schedule → release, all before the first byte leaves. The `async with limiter:` blocks do nothing.
2. **`--rate-limit` never reaches the IP path.** `cli.py:415` calls `configure_rate_limit(args.rate_limit)`, which sets `_init_rate` (`http.py:57-59`). But `investigate_ip` constructs `RateLimiter(rate=5)` with an explicit literal (`orchestrators.py:117`), and `RateLimiter.__init__` (`http.py:62-66`) only honours the *first* construction because `_global_sem` is a module singleton. The flag is dead.
3. **`_cmd_ip` fans out over every target at once.** `cli.py:150-151` gathers all targets with no bound, and each `investigate_ip` opens its own `AsyncClient` with `max_connections=50` (`http.py:42`).

**Reproduced** (`t_limiter.py`, faithful copy of the repo structure): with `--rate-limit 1` and a 20-target file, peak concurrent provider calls = **100**, and the semaphore's effective value was 5, not 1.

```
effective semaphore value at first construction: 5
peak concurrent provider calls with --rate-limit 1 : 100 (expected <=1 if the limiter worked)
```

**Failing input:** `tripper-recon --rate-limit 1 ip ./500_ips.txt`. 2,500 concurrent HTTP requests → mass 429s from VirusTotal (4 req/min on the public tier) and Shodan → F1 turns every one of those 429s into a green `0/0`. The two defects compound into a batch of confidently wrong clean verdicts.

**Fix:** acquire inside each provider coroutine (or wrap each provider call in `async with limiter:` around the `await`, not around `create_task`); drop the `rate=5` literal so `configure_rate_limit` wins; bound `_cmd_ip`'s target fan-out with a semaphore; share one `AsyncClient` across targets.

---

### F5 — HIGH — The global `-o/--format` flag is silently discarded

**Anchor:** `tripper_recon/cli.py:382` shadowed by `cli.py:390`, `cli.py:395`, `cli.py:401`

`--format` is declared on the top-level parser *and* on all three subparsers. argparse applies the subparser's default over the already-parsed parent value. **Reproduced on Python 3.12.13:**

```
tripper-recon -o json ip 1.2.3.4        -> Namespace(format='console', ...)   # request silently dropped
tripper-recon ip 1.2.3.4 -o json        -> Namespace(format='json', ...)      # works
tripper-recon -o json ip 1.2.3.4 -o console -> format='console'
```

**Failing input:** `tripper-recon -o json ip 8.8.8.8` — the analyst asked for JSON and gets a coloured console table. In a pipeline (`... | jq`) this is a hard, silent failure. The flag placement that works is the one the README happens to use (`README.md:64`), which is why it has not been noticed.

**Fix:** delete `cli.py:382` (and the per-subparser duplicates, or the global — one of the two), or use `parents=[common]` with a single definition.

---

### F6 — HIGH — BGP hijack victim/hijacker attribution is fabricated; absent data prints as "None"

**Anchor:** `tripper_recon/providers/cloudflare_rest.py:26-29` and `tripper_recon/reporting/console.py:244-255`

```python
# cloudflare_rest.py:26-29
total = j1.get("result_info", {}).get("total_count")     # count across ALL pages
events = j1.get("result", {}).get("events", [])          # ONE page, no per_page param sent
as_hijacker = len([e for e in events if e.get("hijacker_asn") == asn])
out["hijacks"] = {"total": total, "as_hijacker": as_hijacker,
                  "as_victim": (total - as_hijacker) if isinstance(total, int) else None}
```

`total` is the full-result count; `as_hijacker` is counted over the first page only. Subtracting one from the other produces a number that corresponds to nothing. **Reproduced:** `SIM4` → `total=100 as_hijacker=25 as_victim=75` when the true split is unknown.

`console.py:249` then converts that arithmetic into English:
```python
qual = " (always as a victim)" if as_h == 0 else (" (always as a hijacker)" if as_v == 0 else ...)
```
If page 1 happens to contain no events where this ASN is the hijacker, the report asserts **"always as a victim"** for an ASN that may be the hijacker in 99 of 100 incidents. That is a defensibility failure in an incident report.

Two more in the same block:
- `console.py:246` — `total_h = hj.get("total") or 0`, then `else: t1.add_row("BGP Hijacks (past 1y)", "None")`. A **missing** `result_info.total_count` renders as an affirmative **"None"**. Reproduced: `SIM5`.
- With no `CLOUDFLARE_API_TOKEN`, `orchestrators.py:381` sets `cf_bgp = {"ok": False, ...}`, `meta_bgp` never gets `hijacks`/`leaks`, and `console.py:244` `if hj:` is falsy — the hijack and leak rows are **omitted entirely with no warning**. The "token missing" note at `cli.py:330` only fires when `meta` is *completely* empty, which it is not once IPinfo/RIPE/CAIDA populate it.

**Fix:** either request all pages and count both sides from the events, or report only `total` and drop the hijacker/victim split. Distinguish `None`-the-value from `0`-the-count. Always render the hijack row, with `unavailable` when Cloudflare was not queried.

---

### F7 — HIGH — RIPE and PeeringDB failures are suppressed and rendered as "NONE"; `warnings` is computed and never shown

**Anchor:** `tripper_recon/orchestrators.py:87-88`, `tripper_recon/reporting/console.py:213-215`, `tripper_recon/reporting/console.py:206-207`, `tripper_recon/cli.py:322-341`

```python
# orchestrators.py:87-88 — RIPE network errors are swallowed entirely
if provider.startswith("ripe_") and err == "network_error":
    return True
```
```python
# console.py:214-215 — and missing data renders as an assertion of absence
if not asns:
    return "NONE"
```

A RIPEstat outage therefore produces a report reading `Upstream: NONE / Downstream: NONE / Uncertain: NONE`, with no error block, for an ASN with 40 upstreams. Identically, a PeeringDB failure yields `Peering @IXPs ──> NONE` (`console.py:207`).

`investigate_asn` *does* compute a `warnings` list for exactly this (`orchestrators.py:539-552`, entries such as `ripestat_overview_failed`, `peeringdb_failed`) and returns it (`orchestrators.py:558`) — but `_cmd_asn`'s console branch (`cli.py:322-341`) never reads `res.warnings`. The signal is computed, carried, and thrown away. It survives only in `--format json`, which is the mode F5 makes hard to reach.

**Fix:** print `res.warnings` in the console branch; render missing data as `unavailable` rather than `NONE`; stop suppressing `ripe_*` network errors — a transport failure to a data source is exactly what the analyst needs to know.

---

### F8 — MEDIUM — Neighbour lists are silently truncated to 8 with no "and N more"

**Anchor:** `tripper_recon/orchestrators.py:509-519` and `tripper_recon/reporting/console.py:213-221`

`_name_list` truncates to `resolve_neighbors` (default 8, `cli.py:402`). `console.py:275-277` prefers the *named* list over the raw list, and `_join_asns` computes its "and N more" suffix from the list it was handed — which is already truncated, so `more == 0` and no suffix is emitted.

**Reproduced** (`SIM6`), for an ASN with 40 upstreams:
```
named path: '1  2  3  4  5  6  7  8'                    <- no truncation marker
raw path  : '1  2  3  4  5  6  7  8  9  10  11  12  ...' <- would show 60 + "and N more"
```

Resolving names makes the report *lose* information, invisibly. An analyst reads "this ASN has 8 upstreams".

**Fix:** pass the true total into `_join_asns`, or name the first N and append the remaining raw ASNs.

**Adjacent, lower severity:** `orchestrators.py:500-502` builds `tasks` by iterating the set `to_resolve` and then `zip`s that same set against `results`. This is correct in CPython only because the set is unmodified between the two iterations; it is not guaranteed by the language contract. Materialise the set to a list once.

---

### F9 — MEDIUM — `TRIPPER_RECON_LOG_LEVEL=INFO` (the value the README documents) crashes at import; `.env` values never apply

**Anchor:** `tripper_recon/utils/logging.py:30`, `tripper_recon/cli.py:21`, `tripper_recon/cli.py:380`

```python
# logging.py:30
min_level = int(os.getenv("TRIPPER_RECON_LOG_LEVEL", "20"))
```

`README.md:97` tells the operator to set `TRIPPER_RECON_LOG_LEVEL=INFO`. **Reproduced:** `ValueError: invalid literal for int() with base 10: 'INFO'`. `logger()` is called at module scope (`cli.py:21`, `orchestrators.py:26`), so this is an *import-time* crash — the CLI dies with a traceback before parsing arguments. `.env.example:21-22` documents the numeric form, so the README and the example file disagree.

Second bug in the same area: `log = logger("cli")` runs at import (`cli.py:21`), while `load_env()` runs inside `main()` (`cli.py:380`). By the time `.env` is loaded, both loggers already captured `min_level`. **A `TRIPPER_RECON_LOG_LEVEL` set in `.env` has no effect at all** — only a shell-exported value is ever honoured, and that value crashes if non-numeric.

**Fix:** accept both names and numbers, wrap in `try/except ValueError` with a documented fallback, read the level lazily inside `_log`, and call `load_env()` before constructing loggers. Correct `README.md:97`.

---

### F10 — MEDIUM — JSON log records are written to stdout, corrupting `--format json`

**Anchor:** `tripper_recon/utils/logging.py:42`, with `tripper_recon/cli.py:161`, `:172`, `:196`

`_log` writes to `sys.stdout`. `_cmd_ip` logs failures (`cli.py:161`, `cli.py:172`) into the same stream that later receives `console.print_json(data=out)` (`cli.py:196`).

**Failing input:** `tripper-recon ip ./ips.txt --format json | jq .` where any one target fails. stdout becomes `{log record}\n{log record}\n{report JSON}` and `jq` errors out. `README.md:26` sells "structured JSON logging for SIEM ingestion" — which is only true if the logs are separable from the report, and they are not.

I checked the other half of this concern and it is **not** a defect: `Console.print_json` does not hard-wrap long string values even at width 80 (`TEST3` → output parsed cleanly with `json.loads`).

**Fix:** write log records to `sys.stderr`.

---

### F11 — MEDIUM — IDN/unicode domains, bare domains with a path, and trailing-dot FQDNs are all rejected

**Anchor:** `tripper_recon/utils/validation.py:24` and `tripper_recon/cli.py:205-206`

The regex is ASCII-only (`[A-Za-z0-9-]`) and there is no `idna` encoding step anywhere in the codebase. `cli.py:205-206` runs `urlparse` first, which only extracts a hostname when a scheme is present.

**Reproduced** (`SIM7`):

| input | normalised | accepted |
|---|---|---|
| `münchen.de` | `münchen.de` | **no** |
| `пример.рф` | `пример.рф` | **no** |
| `xn--mnchen-3ya.de` | `xn--mnchen-3ya.de` | yes |
| `example.com/login` | `example.com/login` | **no** |
| `example.com.` | `example.com.` | **no** |
| `https://evil.com/a` | `evil.com` | yes |

The first two are the ones that matter: IDN homograph domains are a routine phishing artefact, and the tool refuses them outright with `Domain investigation failed: Invalid domain` (`cli.py:212`). The analyst must know to punycode-encode by hand.

`example.com/login` is a natural paste from a proxy log and is also refused. Note also that `README.md:5` advertises "IP, Domain, **URL**, and ASN investigations" — there is no `url` subcommand in `cli.py:386-407`.

**Fix:** normalise with `value.encode("idna")` (or the `idna` package) before validation; strip a trailing dot; if the input contains `/` and has no scheme, re-parse as `//` + input to extract the host.

---

### F12 — MEDIUM — OTX is queried with the IPv4 indicator endpoint for every address, including IPv6

**Anchor:** `tripper_recon/providers/otx.py:20`

```python
r = await client.get(f"{OTX_BASE}/indicators/IPv4/{ip}/general", headers=headers, timeout=20.0)
```

The indicator type is hardcoded. There is no branch on address family anywhere in the call chain (`orchestrators.py:129`, `orchestrators.py:272`), and `investigate_ip` explicitly accepts IPv6 (`orchestrators.py:104-113` only rejects private addresses).

**Failing input:** `tripper-recon ip 2606:4700:4700::1111`. The request is made against the wrong indicator type. Whatever OTX returns, the result cannot be an IPv6 pulse lookup. Combined with F1, a non-`ok` response renders as no OTX row at all.

I have **not** confirmed OTX's response to this request, because doing so would require a live API call. What would settle it: one manual `curl` against `/indicators/IPv6/<addr>/general` versus `/indicators/IPv4/<addr>/general`. The code defect — no address-family branch — stands on the source alone.

**Fix:** `f"indicators/IPv{ip_address(ip).version}/{ip}/general"`.

---

### F13 — MEDIUM — `render_asn_header` raises `AttributeError` when `organization` is a string

**Anchor:** `tripper_recon/reporting/console.py:168`

```python
name = meta.get("name") or (meta.get("organization", {}) or {}).get("name") or ""
```

`organization` is a `dict` when it comes from Cloudflare Radar (`cloudflare_radar.py:22`, `organization { name }`) but a **plain string** when it comes from IPinfo (`ipinfo.py:77` returns `j.get("org")` whenever `company` is not a dict). `orchestrators.py:436-440` merges IPinfo into `meta` for any key Cloudflare left empty.

**Reproduced:** `SIM2 CRASH: AttributeError 'str' object has no attribute 'get'`.

Twenty-two lines later the same file gets this right — `console.py:189` uses `org.get("name") if isinstance(org, dict) else org` — which is strong evidence line 168 is an oversight rather than an invariant.

**Failing input:** an ASN where Cloudflare is unavailable or returns no `name`, IPinfo returns `org` as a string, and RIPE's `holder` is absent (`orchestrators.py:441-447`). Result: traceback instead of a report.

**Fix:** reuse the `isinstance` guard from line 189.

---

### F14 — MEDIUM — Exit code 0 and "succeeded" reported when every provider failed

**Anchor:** `tripper_recon/orchestrators.py:190`, `tripper_recon/cli.py:180`, `:194`, `:201`

`investigate_ip` returns `InvestigationResult(ok=True, ...)` unconditionally at line 190, regardless of how many providers failed — the failures go into `errors`, but `ok` stays `True`. `_cmd_ip` then counts the target as `succeeded` (`cli.py:180`), reports `"ok": failed == 0` as `True` (`cli.py:194`), and returns exit code 0 (`cli.py:201`).

`_cmd_domain` has the same shape: `investigate_domain` always returns `ok=True` past validation (`orchestrators.py:331`), and `_cmd_domain` returns 0 (`cli.py:295`) no matter how many per-IP provider errors accumulated in `result_errors`.

**Failing input:** `tripper-recon ip 8.8.8.8 && echo "clean"` with every API key expired → prints `succeeded=1 failed=0`, exits 0. Any automation keyed on exit status treats a total intelligence blackout as a successful clean lookup.

**Fix:** define `ok` as "at least one verdict-bearing provider returned data", or add a distinct exit code (e.g. 3) for "completed with degraded coverage" and surface a coverage count in the summary line.

---

### F15 — MEDIUM — `--monochrome` and `--enrich` do nothing; `--enrich`'s help text describes functionality that does not exist

**Anchor:** `tripper_recon/reporting/console.py:167`, `:224`; `tripper_recon/cli.py:403`; `tripper_recon/orchestrators.py:529-537`

- `--monochrome` (`cli.py:405`) is threaded through as `use_color` into `render_asn_header` (`console.py:167`) and `render_asn_bgp_panels` (`console.py:224`). **Neither function body references the parameter.** `rg use_color` returns only the two signatures and the two call sites. `cli.py:311` already carries a comment conceding the flag is "retained for flag compat". It is a no-op in a TTY.
- `--enrich` help reads *"Enrich prefix info via whois/pWhois (slower)"* (`cli.py:403`). The implementation (`orchestrators.py:529-537`) is labelled `# Optional enrichment: placeholder aggregation` and does nothing but slice the prefix lists it already had. No whois or pWhois call exists anywhere in the repo. The resulting `inetnums` key is never rendered by `reporting/console.py`, so `--enrich` is invisible outside `--format json` — which F5 makes hard to reach.

**Fix:** implement or remove. If retained as a stub, the help text must say so.

---

### F16 — MEDIUM — Passive VT DNS records are merged with live-resolved IPs with no provenance marker

**Anchor:** `tripper_recon/orchestrators.py:248-251` and `:309-318`

```python
active_ips = await resolve_domain(domain)
ips = active_ips + passive_ips
ips = dedupe_preserve_order(ips)
```

`passive_ips` comes from VT's `last_dns_records` (`orchestrators.py:227-235`), which can be months or years stale. The per-IP `entry` dict (`orchestrators.py:309-318`) records no source field, and `render_ip_analysis` displays none. Every IP is presented identically.

**Failing input:** a domain that migrated hosting a year ago. VT's passive records still list the old provider's IP; the tool presents it in the same panel format as the live A record. An analyst building a blocklist from the report blocks an IP that now belongs to an unrelated tenant.

Related: `entry["ptr"]` is hardcoded to `None` (`orchestrators.py:254`) and never populated — `utils/dns.py:26 reverse_ptr` is defined and **never called anywhere** (confirmed by `rg`). The JSON API therefore always emits `"ptr": null`, which a consumer will reasonably read as "no PTR record exists".

**Fix:** add `"source": "dns" | "vt_passive"` to each entry and render it; carry VT's record timestamp; either wire up `reverse_ptr` or drop the field from the schema.

---

### F17 — MEDIUM — Active DNS resolution against the target violates the passive-only constraint, unconditionally and with no opt-out

**Anchor:** `tripper_recon/utils/dns.py:8-23`, called from `tripper_recon/orchestrators.py:247-248`

```python
infos = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
```

`getaddrinfo` walks the system resolver, which for a domain the operator has never queried before will recurse to the target's own authoritative nameservers. The query — timestamped, sourced from the analyst's resolver — lands in the adversary's DNS logs. Every `tripper-recon domain <target>` run does this; there is no flag to suppress it and no warning in the output.

Flagging it here because the tool has a passive alternative already wired up and prefers the active one: VT's `last_dns_records` (`orchestrators.py:227-235`) supplies the same answer from a third party. Detailed treatment belongs to the opsec lens; the correctness angle is that the code offers no way to run the tool inside its own stated constraint.

**Fix:** make passive-only the default. Gate `resolve_domain` behind an explicit `--active-dns` flag, and label the resulting IPs as actively resolved in the output (see F16).

---

### F18 — LOW — WHOIS rendering silently drops every field outside a 14-key allow-list

**Anchor:** `tripper_recon/cli.py:76-89`

`_print_whois_block` parses all `key: value` lines into `entries`, then prints only keys appearing in the hardcoded `priority` list. Registrant/Admin/Tech organisation, address, country, and every registrar-specific field are parsed and discarded with no "N further fields omitted" note. For an incident report, registrant country and organisation are among the most useful WHOIS fields.

Adjacent cosmetic issue: `_print_certificate_block` (`cli.py:92-121`) is called with `vt_dom.get("vt_last_https_certificate") or {}`, but `virustotal.py:84-95` always constructs that dict with all keys present (values possibly `None`). The dict is therefore always truthy, so the `Last HTTPS Certificate` header prints even for domains with no certificate data, followed by nothing.

**Fix:** print the priority keys first, then the remainder under a `Other WHOIS fields` heading. Have the VT provider return `None` rather than an all-`None` dict.

---

### F19 — LOW — Backoff retries authentication failures and ignores `Retry-After`; half the providers get no 429 retry at all

**Anchor:** `tripper_recon/utils/backoff.py:18-27`, with `tripper_recon/providers/ripestat.py:18-19`, `caida.py:18-19`, `peeringdb.py:17-18`, `ipinfo.py:65-68`, `cloudflare_radar.py:38-39`

**Answering the explicit question: yes, `utils/backoff.py` is wired in** — `with_exponential_backoff` is imported and used by all ten provider modules (`rg -l` confirms). But its behaviour does not match `README.md:24`'s claim of handling 429 "elegantly":

- `except Exception` (`backoff.py:21`) retries *everything*, including `401`/`403` raised by `raise_for_status`. An expired VirusTotal key costs ~3.5 s of sleeping per IP before failing, multiplied across a bulk run.
- `Retry-After` is never read. The delay schedule (`backoff.py:25`) is fixed at 0.5/1/2 s regardless of what the provider asks for.
- Five providers (RIPEstat, CAIDA, PeeringDB, IPinfo-ASN, Cloudflare Radar) **return a dict** on `status >= 400` rather than raising, so `with_exponential_backoff` sees a normal return and never retries — a 429 from any of them is a hard, immediate failure.
- `peeringdb_ixps_for_asn` (`peeringdb.py:14-39`) issues N+1 requests inside one `_call`; a failure on the last one re-issues all of them on retry.

**Fix:** retry only on `429`, `5xx`, and transport errors; honour `Retry-After`; make the dict-returning providers raise so the wrapper can see the failure, or move the retry decision inside them.

---

### F20 — LOW — Dead code, dead parameters, and a drift-prone version literal

**Anchors:**
- `tripper_recon/utils/dns.py:26` — `reverse_ptr` is never called (see F16).
- `tripper_recon/reporting/console.py:10` — `_fmt_ports` is never called; `console.py:116` reimplements it inline.
- `tripper_recon/reporting/console.py:167`, `:224` — `use_color` parameter unused (see F15).
- `tripper_recon/cli.py:12`, `tripper_recon/reporting/console.py:5` — `Panel` imported, never used.
- `tripper_recon/api/server.py:3` — `asyncio` imported, never used. `tripper_recon/utils/dns.py:5` — `Tuple` imported, never used. `tripper_recon/cli.py:5-6` — `json`, `os` imported, never used.
- `tripper_recon/cli.py:361` — `if not out_path.parent or ...`: `Path` has no `__bool__`, so `Path(".")` is always truthy and the first clause is unreachable; the `str(...) == "."` clause carries the logic.

**Version drift check (explicitly requested): no drift found.** `pyproject.toml:7` = `0.1.0`, `tripper_recon/__init__.py:5` = `0.1.0`. `README.md:7` advertises Python 3.10+ and `pyproject.toml:9` requires `>=3.10`, consistent with the `match` statement at `cli.py:419`. However `api/server.py:15` hardcodes `version="0.1.0"` as a string literal instead of importing `__version__` — a drift hazard the next release will realise.

---

### F21 — LOW — `--ports-limit` silently swallows invalid and zero values

**Anchor:** `tripper_recon/reporting/console.py:117-124`

```python
limit = int(ports_limit)
max_show = limit if limit > 0 else 25
except (ValueError, TypeError):
    max_show = 25
```

`--ports-limit 0` and `--ports-limit -1` both silently mean 25, and `--ports-limit abc` is silently accepted and means 25. No message is emitted. An analyst who typed `0` intending "suppress the port list" gets 25 ports and no indication their flag was ignored.

**Fix:** validate in argparse (`type=` callable accepting an int or the literal `all`) so a bad value fails loudly at parse time.

---

## Non-findings (checked, no defect)

Recorded so a future reviewer does not re-spend the effort:

- `Console.print_json` does **not** wrap long string values at narrow widths; output round-trips through `json.loads` at width 80 (`TEST3`). The JSON report itself is well-formed — only F10's log interleaving breaks it.
- `pyproject.toml` / `__init__.py` versions agree (see F20).
- `utils/backoff.py` **is** wired into all ten providers (see F19 for the behavioural caveats).
- `asyncio.Semaphore` construction outside a running loop is safe on Python ≥3.10 (the `loop` binding was removed), so `utils/http.py:65`'s module-level singleton does not break under the FastAPI server's loop. The singleton is still wrong for the reasons in F4, but not for loop-affinity reasons.
- `orchestrators.py:104-113` correctly rejects private, loopback, link-local, and CGNAT addresses via `is_private`.
- `is_valid_asn` (`validation.py:16-21`) correctly excludes AS0 and values ≥ 2³².
- IPv6 prefix classification by `":" in prefix` (`orchestrators.py:523-524`) is sound for RIPEstat's output format.

---

## Appendix A — verification scripts

All under `/tmp/claude-1000/-home-echo-AI-Research/6c19a527-33b8-4224-baf6-25b0ed0b33c0/scratchpad/`. Each copies the relevant repo logic verbatim; none imports from or writes to the target repo, and none makes a network call.

| script | verifies |
|---|---|
| `t_argparse.py` | F5 — subparser `--format` shadowing (Python 3.12.13) |
| `t_rich.py` | F2 — markup interpretation (`TEST1`), `MarkupError` crash (`TEST2`); non-finding — `print_json` wrapping (`TEST3`). rich 14.3.2 |
| `t_sim.py` | F3 (`SIM1`), F13 (`SIM2`), F1 (`SIM3`), F6 (`SIM4`, `SIM5`), F8 (`SIM6`), F11 (`SIM7`) |
| `t_limiter.py` | F4 — 100 concurrent calls under `--rate-limit 1` |

Rich/pydantic/httpx were not installed in the default interpreter; `t_rich.py` and `t_sim.py` were run under `/home/echo/miniconda3/envs/AI_Scanner/bin/python`, an unrelated pre-existing environment. Nothing was installed.

## Appendix B — suggested fix ordering

1. **F1** — verdict fields must never fabricate a zero. Nothing else on this list changes an analyst's conclusion as directly.
2. **F2** — escape provider text. One-line-per-callsite fix that removes both a crash and a spoofing vector.
3. **F5, F9** — two trivial fixes that unblock the JSON path and stop an import-time crash.
4. **F3, F13** — two unhandled exceptions with one-line guards.
5. **F4** — rate limiting, before anyone runs a large list file.
6. **F6, F7, F8, F14** — the "absence renders as an assertion" family. These share a root cause and are best fixed as one pass over `reporting/console.py`.
7. Everything else.
