# tripper_recon — sequenced hardening and capability roadmap

Target: `/home/echo/dev/tripper_recon` @ branch `feat/work-20260808-recon-hardening`
Inputs: six audit lenses (98 raw findings, ~58 distinct), four design proposals, one adversarial verification pass.
Method: synthesis only. This document was produced read-only; nothing in the repo was edited, no target was investigated, `.env` was never opened.

Every item below carries a `file:line` anchor. One REFUTED finding (`PKG-INFO` "License: Proprietary") has been dropped and appears only in the deliberately-not-doing list. Severities are the critic's corrected values, not the original lenses'.

---

## 1. Summary

**The tool is a competent collector wrapped in a renderer that will occasionally tell an analyst something false.** The collection layer is genuinely sound — ten providers, all third-party, no scan, no target fetch, no urlscan submission. The passive-only constraint is met in thirteen of fourteen outbound paths. That is the hard part and it is already done.

What is missing is everything between "we got the data" and "here is the answer you can put in a ticket":

- It never states a verdict (`reporting/console.py:24`). The operator's stated purpose is unimplemented.
- When it does not know, it says zero in green (`console.py:70`). Absence renders as safety.
- The only malice signal is ANSI colour, which `rich` strips the moment output is redirected to the incident report it is meant to feed (`console.py:78`, verified probe R5).
- It leaks Shodan and IPinfo API keys into console output, JSON reports, and the REST API on any HTTP error (`orchestrators.py:38`).
- It exits 0 and reports "succeeded" when every provider failed (`orchestrators.py:190`).

Three things gate everything else and must land first: **a test harness** (the repo has zero tests, `pyproject.toml:31`), **an enforceable passive boundary** (currently an authorial intention with nothing checking it), and **a provider-interface refactor** (23 duplicated `try/await/except` blocks, `orchestrators.py:132`, and a rate limiter that limits nothing, `orchestrators.py:120`).

The two features that close the gap to the stated goal — the verdict engine and URL support — sit on top of all three. Sequencing them first would build them on sand.

**Minimum credible end-state: W0 through W5 plus W9.** W6 (URL) is the highest-value optional addition. W7 and W8 are where this project will over-build if it over-builds; they are correctly last and are individually skippable.

---

## 2. Current-state assessment

### What is already right

| Property | Evidence |
|---|---|
| Passive collection, honestly implemented | All ten provider modules target third-party hosts; no socket connect to target, no URL fetch, no urlscan submission, `reverse_ptr` has no callers (verification §0, exhaustive) |
| VirusTotal used correctly | GETs of existing reports only — no `POST /urls`, `/files`, `/analyses` |
| RFC1918 refusal on the IP path | `orchestrators.py:109-110` — a deliberate control, undocumented |
| Fully type-annotated, `from __future__ import annotations` throughout | mypy is cheap to add |
| `.gitignore` artifact rules | `.gitignore:85-92` blanket-ignores investigation output — right call, unexplained |
| Conventional Commits, feature branches | `git log` |

### What is wrong, by class

**Class 1 — the tool asserts things that are not true.** Green `0/0` for an unconfigured provider (`console.py:70`, critical). Exit 0 on total intelligence blackout (`orchestrators.py:190`). `NONE` rendered for suppressed RIPE/PeeringDB failures (`console.py:213`). BGP victim/hijacker attribution computed from page-1 arithmetic against an all-pages denominator (`cloudflare_rest.py:29`) and rendered as the prose "always as a victim" (`console.py:247`). `README.md:5` advertises URL support that does not exist.

**Class 2 — credentials and boundary.** Keys in `_error_payload` reach four sinks (`orchestrators.py:38`; sinks at `console.py:153`, `cli.py:41`, `cli.py:196`, `api/server.py:28`), critical. Unauthenticated `0.0.0.0` bind (`server.py:50`), high. Active DNS against the target with no opt-out (`dns.py:14`, `orchestrators.py:247`), high. Private IPs forwarded to five third parties on the domain path (`orchestrators.py:253`), high.

**Class 3 — it crashes on the inputs analysts actually paste.** Defanged indicator → unhandled `ValueError` (`cli.py:205`). Provider-controlled string with a stray `[/]` → `MarkupError` (`console.py:39`). Cloudflare GraphQL error array → `TypeError: unhashable type: 'list'` (`orchestrators.py:78`). IDN, path-bearing and trailing-dot domains rejected outright (`validation.py:24`).

**Class 4 — the async layer does not do what it claims.** `--rate-limit` is dead in all three subcommands (`orchestrators.py:120`, probe H6: requested 2, observed 10). `transport=` silently disables HTTP/2 and the 50-connection cap (`http.py:43`, probe H1) while `README.md:23` claims "Async & HTTP/2 First". The domain path is fully serial per IP (`orchestrators.py:253`) against `README.md:22`. No wall-clock deadline anywhere (`http.py:47`).

**Class 5 — nothing is defensible.** No timestamp, no tool version, no coverage line, no provenance, no freshness (`types/models.py:35`). Active and passive IPs merged into one undifferentiated list (`orchestrators.py:249`). VT `last_analysis_date` and Shodan `last_update` fetched and discarded.

**Class 6 — no gate.** No tests, no CI, no linter, no type checker, no pre-commit, no secret scanning (`pyproject.toml:31`). Three PRs merged with nothing checking them. This is why the other five classes recur: the credential leak is a five-line test against a mocked 401.

### Coupling the sequence must respect

The critic identified three couplings none of the lenses stated outright:

1. Fixing the limiter activates the dormant cross-loop `RuntimeError` (`http.py:54`, probes H4/H5). Build the limiter inside the running loop **in the same commit**.
2. Fixing the limiter without a per-provider budget converts a slow bulk run into a faster quota breach.
3. Adding `asyncio.wait_for` per target makes the `CancelledError` misclassification at `cli.py:158` reachable for the first time.

---

## 3. Sequenced workstreams

Ordered by dependency, then by value-per-effort. Every item is scoped to one commit or one focused session.

---

### W0 — Stop the bleeding · P0-now · effort M · depends on nothing

Nine small, independent commits. Every one is a defect that makes the tool actively misleading or crashes it on a routine input. None requires the refactor. Land these first regardless of what else happens to this project.

| # | Item | Anchor | Why |
|---|---|---|---|
| 0.1 | Redact credentials inside `_error_payload` — strip query params and auth headers from both the `url` field and `str(exc)` | `orchestrators.py:38-46` | Critical. Probe H2: `str(request.url)` **and** `str(HTTPStatusError)` both embed `?key=SECRET`. One helper covers all four sinks (`console.py:153`, `cli.py:41`, `cli.py:196`, `api/server.py:28`) plus the Cloudflare body echo at `cloudflare_radar.py:39`. Highest value-per-line change in the entire set |
| 0.2 | Never render a manufactured `0/0` — absent or failed VirusTotal renders `no data` / `not configured`, never a green zero | `console.py:70-79` | Critical. Probe R1/R2 reproduce `\x1b[32m0/0\x1b[0m` with `virustotal={}`. Requires a third branch in `vt_color`, and the `_should_suppress` decision (`orchestrators.py:78`) to stop discarding `missing_api_key` |
| 0.3 | Escape provider-controlled strings before `rich` sees them (`rich.markup.escape` or `Text`) | `console.py:39` and every `table.add_row` taking provider data | High. Probe R3 crashes on an OTX title `evil [/] campaign`; probe R4 renders `[green]0/94 - no detections[/]` as green text with the tags consumed. Crash plus display spoof |
| 0.4 | Guard `_should_suppress` against non-string error values | `orchestrators.py:78` | High. `err in {...}` with a list operand raises `TypeError` (probe P5). Reachable at `:425` (ASN) and `:303` (domain) via `cloudflare_radar.py:42,67` |
| 0.5 | Write structured logs to stderr | `utils/logging.py:42` | Medium, one line. `sys.stdout.write` collides with `print_json` at `cli.py:196`; log calls at `cli.py:144/161/172` are not gated on output format, so `-o json \| jq` breaks on any errored target |
| 0.6 | Resolve the `-o/--format` shadowing — drop the subparser duplicates or set their default to `SUPPRESS` | `cli.py:382` vs `:390/:395/:401` | High. Probe P1: `-o json ip 8.8.8.8` → `format='console'`. A scripted pipeline gets Rich text into a JSON parser silently. Also fix or document that `--rate-limit`/`--user-agent` are global-only (`cli.py:383-384`) |
| 0.7 | Wrap `urlparse` in try/except and emit a clean "looks defanged" error | `cli.py:205` | High. Probe P2: `hxxps://evil[.]com` → unhandled `ValueError: Invalid IPv6 URL`. `main()` has no top-level handler. Full refanging is W6.1; this is the crash guard |
| 0.8 | Bind the API server to `127.0.0.1` by default | `api/server.py:50` | High. Unauthenticated, no CORS policy, no rate limit, four routes returning `model_dump()` — which carries the leaked key from 0.1. `--host` stays available with a warning |
| 0.9 | Truth-in-advertising one-liners: delete "URL" from `README.md:5`; replace `Your Name` in `pyproject.toml:10` and `LICENSE:3` | as cited | Low effort, portfolio-damaging as-is. Grouped here because they are the same class of defect as the rest of W0 — the tool says something untrue about itself |

---

### W1 — Test harness and CI · P0-now · effort M · depends on nothing

Runs in parallel with W0; the W0 fixes get their regression tests here. **This is the workstream that stops the other nine from regressing.** The codebase is fully annotated, so mypy is nearly free.

| # | Item | Anchor | Why |
|---|---|---|---|
| 1.1 | `pyproject.toml`: dev dependency group (`pytest`, `pytest-asyncio`, `respx`, `ruff`, `mypy`) plus `[tool.ruff]`, `[tool.mypy]`, `[tool.pytest.ini_options]` | `pyproject.toml:31` | No config exists; `packages.find` already excludes a `tests*` directory that does not exist |
| 1.2 | `tests/` skeleton and regression tests for every W0 fix | new | Redaction against a mocked 401, `0/0` suppression, markup escape, list-valued suppress, argparse ordering, defanged-input handling. Each is under ten lines |
| 1.3 | Pure-function unit tests: `validation.py`, `backoff.py`, `cli.py:_load_ip_targets`, `cli.py:_fmt_provider_error` | as cited | Cheapest coverage available; these are the functions the verdict engine will depend on |
| 1.4 | `respx` provider fixtures — recorded once, key-redacted, committed | new `tests/fixtures/` | Zero network in the suite, so the suite cannot violate the passive constraint by accident. Also the input to W5.9 |
| 1.5 | Test asserting `investigate_ip("10.0.0.1")` refuses | `orchestrators.py:109` | Turns an undocumented control into a checked one |
| 1.6 | Passivity guard test: fail if an outbound URL literal appears outside `providers/` and is not on the allowlist | new + `utils/http.py` | Converts the hard constraint from a promise into a build gate. Pairs with W2.1 |
| 1.7 | `.github/workflows/ci.yml` — `ruff check`, `ruff format --check`, `mypy tripper_recon/`, `pytest` on 3.10/3.11/3.12 | new | No `.github/` exists at all; three PRs merged ungated |
| 1.8 | `.pre-commit-config.yaml` plus secret scanning (gitleaks or equivalent) | new | The repo holds paid credentials one directory away from the working tree |
| 1.9 | `.github/PULL_REQUEST_TEMPLATE.md` with a required "this PR adds no request to a target-controlled host" checkbox | new | Enforces the constraint at review, not just at test time |

---

### W2 — The passive boundary, made enforceable · P0-now · effort M · depends on W1 (for 2.1's test)

The one genuine breach plus the machinery that prevents the next one. Do this **before** URL support: shipping URL first ships the capability and the footgun together.

| # | Item | Anchor | Why |
|---|---|---|---|
| 2.1 | Egress allowlist as an httpx request event hook at the single client construction point; raise `PassiveBoundaryViolation` otherwise | `utils/http.py:41-51` | `create_client()` returns a general-purpose client any provider can point anywhere. The allowlist plus W1.6 is what makes "passive only" a property rather than a claim |
| 2.2 | Make passive DNS the default; put live resolution behind `--active-dns` with an in-output warning | `orchestrators.py:247-248`, `utils/dns.py:14` | High. `socket.getaddrinfo` on the target reaches the target's own authoritative NS through the org resolver. The passive substitute is **already parsed** at `:227-235` and merged at `:249`. See open question Q2 — if the operator accepts resolver egress, this becomes documentation instead |
| 2.3 | Tag each IP with `source: active\|passive` and stop merging blindly | `orchestrators.py:249`, `:309-318` | Medium. `ips = active_ips + passive_ips` destroys a distinction the author's own variable names show he understood. "Resolved now" and "seen historically on date X" are different evidentiary claims |
| 2.4 | Private/reserved/multicast guard on the domain path; widen the IP-path guard beyond `is_private` | `orchestrators.py:253`, `:109` | High. Split-horizon DNS and sinkholed domains resolving to RFC1918 currently forward internal addressing to five third parties under the operator's keys. `is_private` covers neither 224/4 nor 240/4 |
| 2.5 | Delete `reverse_ptr` and the always-null `ptr` field, or wire PTR deliberately with a passivity decision recorded | `utils/dns.py:26`, `orchestrators.py:254` | Dead code that pre-authorises a boundary decision. The JSON API emits `"ptr": null` today, which a consumer reads as "no PTR exists". Decide before it enters a published schema |
| 2.6 | Honest `tripper-recon/<version>` User-Agent by default; re-word the `--help` text away from "spoof" | `utils/http.py:10-14`, `cli.py:384`, `.env.example:24-25` | Low severity, real ToS and evidence-chain exposure. The key already authenticates the caller; `ripestat.py:26` already self-identifies correctly. See open question Q1 |
| 2.7 | In-source forbidden-endpoint register beside the allowed calls | `providers/*.py` | The allowlist cannot catch provider-proxied fetching. Record: VT `POST /urls` and `/analyse`, urlscan `POST /api/v1/scan/`, Pulsedive `probe=1`, MalwareBazaar `get_file`, Tor DNSEL per-IP, Spamhaus live `zen` DNSBL. Each has a passive sibling on the same API that is easy to reach for by accident |

---

### W3 — HTTP core and provider interface · P1-next · effort L · depends on W1

The refactor the verdict engine and URL support both sit on. Items 3.3 and 3.7 carry the couplings the critic flagged — respect the ordering inside this workstream.

| # | Item | Anchor | Why |
|---|---|---|---|
| 3.1 | Drop the explicit `transport=` | `utils/http.py:43` | High, one line. Probe H1: with it → `http2=False, max_connections=100`; without → `http2=True, max_connections=50`. `AsyncHTTPTransport`'s retries default is already 0, so the line buys nothing. `h2 4.3.0` is installed and unused; `README.md:23` is false as shipped |
| 3.2 | One `AsyncClient` for the run, not one per investigation | `orchestrators.py:116` | No pooling spans targets today, so every target in a bulk run re-handshakes six TLS connections |
| 3.3 | Rebuild the limiter **inside the running loop**, wrap the await not the `create_task`, and make `--rate-limit` reach all three subcommands | `orchestrators.py:117-129`, `utils/http.py:54-74`, `cli.py:415` | High. Probe H6: requested 2, observed 10 — `async with limiter:` wraps `create_task()`, which schedules without awaiting. `configure_rate_limit` is unreachable. **Must include the loop-binding fix in the same commit** (probe H4: `RuntimeError` on run #2 once the semaphore actually contends) |
| 3.4 | Per-provider rate budget expressed as rate, not concurrency | new, `utils/http.py` | A semaphore bounds concurrency and cannot express "4/min". **Retrieve each provider's published limits first** — see open question Q3; do not carry remembered quota numbers into code |
| 3.5 | Honour `Retry-After`; classify retryable vs non-retryable status codes | `utils/backoff.py:18-27` | Medium. `rg '429\|Retry-After'` over the package returns nothing. Today a 401 is retried four times (`virustotal.py:23`, `shodan_api.py:21`, `abuseipdb.py:25`, `ipinfo.py:19`, `otx.py:23`) while a transient 502 from RIPEstat is never retried (`ripestat.py:18` returns a dict). Retry policy is decided by each provider's error style rather than by status code |
| 3.6 | Uniform provider envelope plus one call helper replacing the 23 duplicated `try/await/except` blocks | `orchestrators.py:132` (`grep -c "except Exception"` → 23) | This is the interface the verdict engine consumes and the evidence envelope hooks into. Must preserve the ok/error distinction that `orchestrators.py:180-185` currently flattens to `{}` |
| 3.7 | Per-target wall-clock deadline via `asyncio.wait_for`, and fix the `CancelledError` misclassification it makes reachable | `utils/http.py:47`, `cli.py:158` | High. No elapsed-time awareness anywhere; OTX alone has a ~84s per-provider worst case (`otx.py:20,44` pass `timeout=20.0`). `isinstance(item, Exception)` is False for `CancelledError` since 3.8 |
| 3.8 | Parallelise the domain path — the five per-IP providers in one wave, IPs concurrently | `orchestrators.py:253-298` | High. Five bare awaits at `:256/:260/:264/:268/:272` plus a conditional Cloudflare call at `:298`, all serial, for work `investigate_ip` already does in one wave. `README.md:22` claims otherwise |
| 3.9 | Collapse the ASN two-wave; bound neighbour resolution | `orchestrators.py:383-385`, `:493-501` | Wave 1 is fully awaited before three independent RIPEstat calls are even created; up to 24 neighbour lookups gather unbounded |
| 3.10 | Fix PeeringDB 1+N inside a retried closure; time-bound `resolve_domain` | `providers/peeringdb.py:16,27,41`, `utils/dns.py:12-23` | A failure on the last sub-request replays every earlier one. `resolve_domain` runs two blocking `getaddrinfo` calls in one uncancellable thread on the critical path |

---

### W4 — Truthful output: coverage, provenance, exit codes · P1-next · effort M · depends on W3.6

Everything here is a prerequisite for a verdict that can be defended, and each item is independently valuable even if W5 never ships.

| # | Item | Anchor | Why |
|---|---|---|---|
| 4.1 | `ProviderStatus` on the result — `answered \| not_found \| error \| not_configured \| skipped` with detail | `types/models.py:35`, `orchestrators.py:73-89` | Suppression becomes a **rendering** decision instead of a data-loss decision. Without this the reader cannot distinguish "clean" from "never asked", which is the finding an adversarial reviewer hits first |
| 4.2 | `ok` reflects errors; publish an exit-code contract | `orchestrators.py:190`, `cli.py:171/201/295/376` | High. `investigate_ip` returns `ok=True` unconditionally once the IP parses, so automation keyed on exit status reads a total intelligence blackout as a clean lookup |
| 4.3 | Print `warnings` on the console ASN and domain paths | `orchestrators.py:539-558`, `cli.py:322-341` | High. Warnings are computed and returned, and the console branch never reads them. The JSON branch does carry them — this is a console-only signal loss |
| 4.4 | Coverage line in every render: "N of M providers answered" | `console.py:163` | The half of the operator's stated goal that is currently absent from the screen entirely |
| 4.5 | Timestamp, tool version, and run id in output | `console.py:163`, `__init__.py:5` | Header is `--- IP lookup for {ip} ---` and nothing else; `__version__` never reaches output. No `datetime` import exists anywhere in the codebase |
| 4.6 | Retain the provider fields currently discarded | `virustotal.py:24-35`, `abuseipdb.py:29-32`, `otx.py:29-31`, `shodan_api.py:29` | Keep VT `last_analysis_results` + `last_analysis_date`, AbuseIPDB `lastReportedAt`/`isWhitelisted`/`usageType`/`isTor`, OTX per-pulse author/created/modified, Shodan `vulns`/`tags`/`cpe`. **No new API calls, no new cost** — these are fields on responses already fetched. Highest ratio of unblocked capability to lines changed in the whole plan |
| 4.7 | Fix the BGP hijack victim/hijacker arithmetic, or stop rendering the claim | `cloudflare_rest.py:29`, `console.py:247-252` | High. `total` is all-pages `result_info.total_count`; `as_hijacker` is counted over one unpaginated response; `as_victim = total - as_hijacker`. `console.py:247` turns that into the prose "always as a victim". Also: `hj.get('total') or 0` renders the affirmative string `None` |
| 4.8 | `_join_asns` "and N more" marker; `render_asn_header` string-organization guard | `console.py:213-215`, `:168` | Medium each. The suffix is computed from the already-truncated list so it never fires; `render_asn_header` raises `AttributeError` when IPinfo returns `org` as a string (`ipinfo.py:77`) and nothing else supplied a name. The `isinstance(org, dict)` guard at `:189` shows `:168` is an oversight |
| 4.9 | Deterministic ordering — `resolve_domain` returns `list(set(...))` | `utils/dns.py:21` | Non-deterministic ordering flows into `data['ips']` and the rendered panels, so two runs on the same domain do not diff cleanly. Prerequisite for saved reports |

---

### W5 — The verdict engine · P1-next · effort L · depends on W1, W3.6, W4

The feature that closes the gap to the stated goal. Absolute rule throughout: **absent data never scores as clean.**

| # | Item | Anchor | Why |
|---|---|---|---|
| 5.1 | `Verdict` / `Signal` / `Coverage` / `ProviderStatus` pydantic models, exposed as a first-class field on `InvestigationResult` | `types/models.py:35-39` | Pydantic is already a dependency (`pyproject.toml:15`); serialises for free through `cli.py:216` and `api/server.py:28`. Five states — MALICIOUS / SUSPICIOUS / NO_ADVERSE_FINDINGS / INSUFFICIENT_DATA / KNOWN_INFRASTRUCTURE — folded to three console colours |
| 5.2 | `scoring.yaml` + validated `ScoringConfig`; zero scoring constants in `.py` | new | Every weight, threshold, band, decay constant and allowlist in config with a `version:` stamped into `Verdict.ruleset_version`. A verdict in a six-month-old ticket stays interpretable. Enforce in review: a scoring constant in a `.py` file is a defect |
| 5.3 | Pure `(payload, cfg) -> list[Signal]` extractors per provider, no I/O | new `reporting/verdict.py` | Purity is what makes the engine fixture-testable with no network, no keys, and no possibility of touching a target |
| 5.4 | Confidence as a separate axis, with a coverage floor | new | Coverage (answered/applicable, where a missing key is missing coverage, not an excuse), corroboration, freshness, decisiveness. LOW forced whenever coverage < 0.5. A MALICIOUS score at LOW confidence renders as SUSPICIOUS with the raw score beside it |
| 5.5 | Provider-family independence model | `scoring.yaml` | VT and OTX both re-ingest public feeds. Corroboration counts distinct **families**, never distinct providers; `network_meta` never corroborates. Prevents phantom confidence |
| 5.6 | Tier A/B/C overrides — absolute allowlist, CDN cap, vendor suppression | new | Tier A (public resolvers, root/TLD NS) forces KNOWN_INFRASTRUCTURE. Tier B (Cloudflare/AWS/GCP/Azure/Akamai/Fastly) does **not** force benign — it zeroes ASN and Shodan signals, caps the IP verdict at SUSPICIOUS, and leaves domain-level scoring untouched. Source lists carry a retrieval timestamp into every verdict so a stale allowlist is detectable |
| 5.7 | Contradictions surfaced, never averaged | new | `vt_vs_abuseipdb`, `stale_vs_fresh`, `cdn_vs_detection`, `age_vs_reputation`. Caps confidence at MEDIUM and sets `requires_analyst_review`; never cancels points. The operator's own `ip_example.md:10-17` (VT 5/91 red beside AbuseIPDB 0% green, 50 OTX pulses) is the case this adjudicates |
| 5.8 | Console rewrite — verdict word first, colour second; geolocation below the fold | `console.py:24`, `:39-67` vs `:79` | High. Probe R5 confirms `rich` strips colour when stdout is not a terminal, which is exactly the `> incident.md` workflow. Today `virustotal_detections 5/91` carries no more visual weight than `postal_code 100000` two rows above it |
| 5.9 | Golden-file fixture corpus with a zero-false-MALICIOUS CI gate | `tests/fixtures/`, `tests/golden/` | Weight changes become diffs instead of silent drift. The gate is build-breaking, not a metric. Capturing the corpus needs one live recording pass against third-party APIs only |
| 5.10 | Disclose collection mode in the verdict: `passive_only`, `active_collection[]`, `ruleset_version`, `evaluated_at` | `orchestrators.py:247-251` | A verdict built partly on active collection is a different artifact. The analyst must see which one they are holding before it goes in a report |
| 5.11 | Quality-adjusted OTX pulse count and weighted VT detection | `otx.py:29`, `virustotal.py:26-35` | Both blocked on W4.6. Harmonic author-diversity decay and recency decay collapse the `ip_example.md` fifty pulses to roughly three. **Do not ship a denylist of named low-quality VT engines** — no measured basis exists; weights must come from the corpus |

---

### W6 — Indicator detection, refanging, and URL support · P1-next · effort L · depends on W2.1, W3.6, W5

The second feature that closes the gap. Items 6.1, 6.2 and 6.5 are worth doing even if the `url` subcommand never ships.

| # | Item | Anchor | Why |
|---|---|---|---|
| 6.1 | `refang()` as a standalone tested transform | new `utils/refang.py` | Table-driven: `hxxp`, `[.]`/`(.)`/`[dot]`, `[:]`, `[@]`, `[/]`, zero-width chars, `U+00A0`. Idempotent; records which transforms fired; keeps `raw` alongside `value`. Defanged indicators are the normal case, not the edge case |
| 6.2 | Defang all indicators in human-facing output by default (`--fanged` to override); leave third-party pivot links live | `console.py:39`, `:163`; `cli.py:224` | Medium. Must be a per-field property in the model, **not** a regex pass over the finished document — a regex would mangle `radar.cloudflare.com/ip/1.2.3.4` and destroy the pivot links. Never defang the JSON export |
| 6.3 | `IndicatorType` enum + ordered `detect()` | new `types/indicators.py` | ASN, CIDR, IP, hash, URL, email, domain, else UNKNOWN with attempts listed. Ambiguity reported via confidence, never resolved silently. Closes verified gaps: CIDR, hashes, emails and bare `evil.com/a/b` all fail every validator today |
| 6.4 | Fix domain validation: IDN/punycode via `idna`, path-bearing input, trailing dot; add a per-label 63-octet check | `utils/validation.py:24` | Medium. Probe P3: `münchen.de` and `пример.рф` rejected, `evil-.com` accepted. IDN homographs are a routine phishing artefact and the tool refuses them with a bare "Invalid domain" |
| 6.5 | `parse_url()` — full decomposition, no fetch | new | Lowercase scheme and host only (path and query carry campaign IDs). Record assumed schemes as assumed. Surface `userinfo_present` — `https://user:pw@evil.com/p` silently drops credentials today at `cli.py:205-206` |
| 6.6 | `vt_url_summary` — GET on an existing report only, with the forbidden POSTs recorded in-source | new `providers/` fn, mirrors `virustotal.py:40-101` | `first_submission_date` is often more decisive than the detection count. A 404 renders as **unknown**, never clean, and must not route through `_should_suppress`. **Confirm the base64url identifier scheme and attribute names against current VT v3 docs before implementing** (open question Q7) |
| 6.7 | urlscan.io SEARCH and RESULT only | new provider | The passive answer to the redirect-chain problem: someone else's completed scan yields the chain, final URL, contacted hosts and screenshot. `POST /scan` must never exist in this codebase, not even behind a flag |
| 6.8 | `url` subcommand + `investigate_url` composing the existing host→IP→ASN pivot | `orchestrators.py:193`, `:103`, `:154-158` | Reuse the existing orchestrators; do not add a fourth code path. `--depth url\|host\|full`. Fixes a verified defect: `http://185.220.101.5:8080/x` currently routes to the domain orchestrator and dies at `is_valid_domain` |
| 6.9 | `check` subcommand and `GET /detect` (detection only, no provider calls) | `cli.py:388-407`, `api/server.py:23-44` | One command an analyst can paste anything into under pressure. `/detect` costs no quota and lets a playbook route an indicator for free. Keep the explicit subcommands — `check` is an addition |
| 6.10 | Bulk paste mode: extract from prose, dedupe on canonical value with occurrence counts, filter RFC1918 and mail infrastructure, triage-order | `cli.py:124-135` | The actual SOC workflow. **Highest-risk surface for accidental egress** — it processes attacker-authored text, so W2.1 is a hard prerequisite, as is W3.3 |

---

### W7 — Report artifact and case directory · P2-later · effort L · depends on W4, W5

Where this project is most likely to over-build. Items 7.1, 7.2 and 7.7 deliver most of the value; the rest is optional and should be justified by an actual need before it is built.

| # | Item | Anchor | Why |
|---|---|---|---|
| 7.1 | Typed `Report` model with `schema: "tripper-recon.report/1"` as first key | `types/models.py:35-39` | Three commands return three differently-shaped documents today (`orchestrators.py:179-186` vs `:325-329` vs `:554`) and `api/server.py:28` returns them verbatim, so any SOAR binds to an undocumented unversioned dict. **Trap: `.gitignore:85` is `*.json`** — a committed schema file is silently ignored without a `!schema/*.json` negation |
| 7.2 | Markdown output format with a verdict header and a `> Why:` / `Not established` block | `cli.py:390/395/401` (`choices=["console","json"]`) | The four lines an analyst pastes into a ticket. ATX headings and pipe tables only — no HTML, no box-drawing. `README.md:26`'s markdown claim is currently untrue |
| 7.3 | Fix `_default_output_dir` and add `--out` / `--case-dir` | `cli.py:298-301` | Resolves against `Path(__file__).parent.parent`, so after the README's own `pip install .` a bare `--prefixes-out foo.txt` writes into `site-packages/outputs/`. There is no `--out` for `ip` or `domain` at all |
| 7.4 | Dual timestamps: `queried_at` and `observed_at`, RFC 3339 UTC, with `Age` computed at render | `virustotal.py:24-35`, `shodan_api.py:22-29` | Collapsing the two hides exactly the staleness the report exists to expose. `vt_whois_timestamp` is already captured at `virustotal.py:83` and rendered nowhere |
| 7.5 | Deterministic `case_id` + per-execution `run_id` | `cli.py:425-427`, `:205-206` | SOAR dedupes on `case_id`; log correlation uses `run_id`. Deterministic derivation is what makes offline regeneration trustworthy |
| 7.6 | Evidence envelope: raw body, status, elapsed, sha256, captured once at the client hook | `utils/http.py:41-51` | Enables integrity hashing, offline regeneration and caching in one change. **Hard requirement: redaction (W0.1) must already be in place** — keys travel in query strings (`shodan_api.py:18`, `ipinfo.py:18`) and headers (`virustotal.py:17`, `abuseipdb.py:17`, `otx.py:17`, `cloudflare_radar.py:31`). A naive recorder writes credentials into evidence dirs that get attached to tickets |
| 7.7 | Case directory, per-provider TTL cache, `--offline`, `--max-age`, `report --from-case` | new | Immediate quota relief: a domain with 8 A records burns 9 VT calls per run (`orchestrators.py:253-274`). A cached fact must never claim to have been queried now |
| 7.8 | Pivot section behind `--pivots`, framed as runnable queries with explicit "would show / would not show" | `virustotal.py:87,96,80`; `shodan_api.py:29`; `ripestat.py:37` | Mostly rendering over data already fetched — no new quota, no new boundary risk. Auto-suppress the same-ASN pivot when `customer_cone_asns` (already collected, `caida.py:30`) is large; presenting it as a finding is guilt-by-netblock |
| 7.9 | CSV and newline-delimited indicator export; MISP event export later with `to_ids:false`, `distribution:0` | new | Cheaper and higher-yield than MISP first — every SIEM ingests them, and `--prefixes-out` already shows the appetite for that shape |

---

### W8 — New passive sources · P2-later · effort M · depends on W2, W3

Ordered by value per line. Every one is keyless or cheap. Skippable in whole or in part; do not treat this as a checklist to complete.

| # | Item | Anchor | Why |
|---|---|---|---|
| 8.1 | Shodan InternetDB (keyless) as the no-key fallback, with CVE IDs | copy `shodan_api.py:13`, drop the key check at `:15` | Restores exposed-services data when `SHODAN_API_KEY` is unset — today that path returns `missing_api_key` and is silently suppressed. Also adds CVEs the paid provider never surfaced |
| 8.2 | RDAP via rdap.org / IANA bootstrap | new provider, wire at `orchestrators.py:200` | **The biggest gap in the domain path**, which has only VT and OTX today. Domain creation date is the strongest cheap phishing signal available; registrar abuse contact is exactly the incident-report fact the mission calls for. Needs `follow_redirects=True` per-request |
| 8.3 | Tranco rank | new provider | False-positive suppressor; fastest way to close out "is microsoft.com malicious". 1 qps is a hard ceiling the global semaphore cannot express — needs W3.4 |
| 8.4 | CISA KEV enrichment (cached, joined in memory) | new enrichment module, not a provider | Turns 8.1's CVE list from unranked into prioritised. `knownRansomwareCampaignUse: Known` goes verbatim into a report. Low value without 8.1 |
| 8.5 | Tor bulk exit list (never the per-IP DNSEL) | new | Answers "is this a Tor exit" without paying for IPinfo Plus. IPv4-only, so the honest answer for IPv6 is **unknown**, not no — the output must say which |
| 8.6 | Spamhaus DROP / ASN-DROP JSON, with attribution text carried into output | new | The ASN path carries no reputation signal at all today. Attribution and the date/copyright line are a licence requirement and must surface in console **and** JSON |
| 8.7 | URLhaus + ThreatFox behind one abuse.ch Auth-Key | new provider, POST form-encoded | Highest accuracy gain per line available: actor-attributed, payload-backed observations. A live hit forces MALICIOUS at HIGH confidence. **Gate off in bulk mode** pending open question Q5 |
| ~~8.8~~ | ~~GreyNoise Community~~ **STRUCK (Q10)** -- no eligible non-consumer email address, so this can never be started. Removed rather than left filed | ~~new provider~~ | `noise` and `riot` answer the two questions that most often decide escalation. 10 lookups/day unauthenticated; consumer-email accounts get no key at all. Cannot be default-on in bulk mode |
| 8.9 | Cert Spotter primary, crt.sh fallback | new provider | Not the reverse: crt.sh returned 502 and 404 during the audit session. A SOC tool whose answer intermittently 502s is worse than one that omits the field |
| 8.10 | TTL disk cache for the bulk-file sources (KEV, Tor list, DROP) | new | Prerequisite for 8.4/8.5/8.6 not becoming a download per invocation |

---

### W9 — Documentation and packaging · P1-next · effort M · depends on W0-W6 landing for accuracy

Covers every file the docs lens identified. Two items (README URL claim, placeholder author) already landed in W0.9. **Write these against what the code does after each workstream, not before** — the current README's inaccuracies exist because it was written ahead of the code.

| # | Item | Files | Contents |
|---|---|---|---|
| 9.1 | `README.md` rewrite | `README.md` | Re-attribute provider capabilities (§1.2 of the docs lens); add RIPEstat, CAIDA, PeeringDB, Cloudflare-REST to the provider list — four providers are queried and undocumented; fix `TRIPPER_RECON_LOG_LEVEL` to the numeric form; soften the 429 claim; correct the HTTP/2 and concurrency claims after W3; add an **OPSEC & Passivity** section near the top; add the bind-to-localhost warning |
| 9.2 | `docs/OPSEC.md` | new | The passivity contract with `file:line` evidence. What the tool never does. Every third party that observes a query, per subcommand. The disclosed exceptions and their flags. API-key attribution — a VT lookup is visible to VT. The RFC1918 refusal as an intentional control. What "passive" does **not** protect against |
| 9.3 | `docs/PROVIDERS.md` | new | One row per provider: env var, key required, subcommands, fields extracted, free-tier quota, `file:line`. Flag the no-key set (RIPEstat, CAIDA, PeeringDB) — "`asn 15169` works with an empty `.env`" is the project's best first impression. Include the AbuseIPDB 365-day window and the OTX 5-title cap |
| 9.4 | `docs/RATE-LIMITS.md` | new | Per-provider limits **with a retrieval date and a link** — do not write these from memory. What the tool does on 429 after W3.5. How `--rate-limit` interacts with per-provider budgets. Recommended bulk batch sizes |
| 9.5 | `docs/EXAMPLES.md` + commit the captures | new; `ip_example.md`, `ASN_Example.md`, `domain_example.md` (0 bytes) | Regenerate the empty domain example. Add a `-o json` sample **and a degraded-mode sample with no keys set** — the most common first-run experience, documented nowhere. Confirm the captures are public reference indicators first (open question Q4) |
| 9.6 | `docs/THREAT-MODEL.md` | new | Assets: the `.env` keys, the analyst's egress IP, the indicator list itself. Adversaries: target operator, a malicious provider, a LAN-local attacker against the API server. Controls, and accepted risks stated plainly |
| 9.7 | `CONTRIBUTING.md` | new | Editable install, conda per the operator's convention, ruff/mypy/pytest invocations, Conventional Commits and branch naming (both already in use), and the **passivity review rule**. Explain the `.gitignore` artifact rules so nobody "fixes" them |
| 9.8 | `SECURITY.md` | new | Where to report. A statement that the tool holds paid credentials and that the REST server is unauthenticated by design and must not be exposed |
| 9.9 | `CHANGELOG.md` | new | Keep-a-Changelog, backfilled from `git log` — the history is clean enough that the UA, rate-limit and Rich-rendering commits are identifiable |
| 9.10 | `docs/ARCHITECTURE.md` | new | The orchestrator/provider/reporting split, the provider envelope contract, the suppression policy and why unset keys are silent. Portfolio value |
| 9.11 | `--help` to man-page quality | `cli.py:381` | `epilog` with 5-6 worked examples, an `ENVIRONMENT` block, an exit-code table (from W4.2), per-subcommand provider notes, and a pointer to `docs/PROVIDERS.md` for "why is my output empty". Remove `--monochrome` (dead: `rg use_color` → two signatures, two call sites, zero body references) and remove or re-scope `--enrich` (`orchestrators.py:529-537` is self-labelled "placeholder aggregation" and its output is rendered nowhere) |
| 9.12 | `pyproject.toml` packaging finish | `pyproject.toml` | `[project.urls]`, classifiers, keywords, `license-files = ["LICENSE"]` (PKG-INFO has no `License-File` entry — verified), SPDX `license = "MIT"`, five subpackage `__init__.py` files, `py.typed`, and a single version source (`0.1.0` is hardcoded at `api/server.py:15` and will drift on the first bump) |

---

## 4. Deliberately not doing

Each of these was proposed or implied by an input document and is being declined on the merits.

| Not doing | Why |
|---|---|
| **Live redirect / shortener expansion**, even behind a flag | A redirect resolution is an active fetch — true for HEAD as well as GET. Single-use links get burned by the lookup, destroying evidence downstream; kits that serve benign content to the first visitor invert the verdict. An unbuilt feature cannot be misfired at 3am. Report `redirect_chain: NOT RESOLVED` and source it passively from cached urlscan/VT `last_final_url` instead |
| **VT `POST /urls`, urlscan `POST /scan`, Pulsedive `probe=1`, MalwareBazaar `get_file`, Tor DNSEL, Spamhaus live DNSBL** | Each instructs a third party to contact the target, publishes the investigation, downloads live malware, or leaks the indicator per-query. Each has a passive sibling on the same API. Recorded as forbidden in-source (W2.7) rather than left to a future contributor's judgement |
| **STIX 2.1 export** | STIX wants indicator SDOs with patterns and confidence. Every number this tool produces is third-party reputation aggregation, not first-party observation, so any emitted confidence would be fabricated. A subtly-wrong STIX bundle imports without error and is quietly meaningless — the worst possible failure for a defensibility tool. Revisit only after W5 gives confidence a real definition |
| **Team Cymru IP-to-ASN** | Value is largely duplicative of IPinfo/RIPEstat; they null-route IPs making large numbers of individual whois queries; their bulk interface is a netcat session that does not fit the client contract at all |
| **Feodo Tracker** | Its own site currently states the datasets are empty. An empty feed produces a confident "no result" indistinguishable from "not malicious" — worse than no provider |
| **Implementing the whois/pWhois path `--enrich` advertises** | No whois or pWhois call exists anywhere. Rather than build what a placeholder flag promised, remove the flag. Its help text currently pre-authorises a future contributor to add a referral-following whois path, which is a fresh passivity question — settle that policy while the code is still a no-op |
| **`--prefixes-out` path containment / sandboxing** | The path comes from the analyst's own argv on the analyst's own workstation. No trust boundary is crossed and "no containment check" implies a boundary that does not exist for a local CLI. The two real defects — silent overwrite and the bare-filename fallback writing into `site-packages/outputs/` — are W7.3 |
| **Treating `tripper-recon ip /etc/passwd` as a vulnerability** | Self-inflicted display bug at the analyst's own privilege. The valuable half — a mistyped `./ips.tx` being investigated as a literal indicator and reported as "Invalid IP address" — is a usability fix inside W6.3 |
| **Hardening `.env` CWD loading** | Requires the analyst to run the tool from an attacker-supplied directory **and** the variables to be absent from the real environment (`override=False` means anything exported wins). Provider base URLs are hard-coded, so keys cannot be redirected. Real hygiene issue, speculative threat |
| **The raw-vs-normalised domain divergence as a security fix** | No live SSRF exists — every route validates before URL construction and no base URL is user-controlled. The CLI additionally re-normalises at `cli.py:205-206`. Folded into W6.4 as hygiene, not filed as a vulnerability |
| **`PKG-INFO` "License: Proprietary"** | **REFUTED.** `egg-info/` is untracked build output predating commit `c10dd8e`. A rebuild will not emit it. Only the surviving residue — the missing `License-File` entry — is actioned, in W9.12 |
| **Building authentication into the API server** | Bind to `127.0.0.1` (W0.8) and stop. Auth is a real project with a real maintenance surface; nothing yet justifies it. If the server has no user, deleting it is also on the table — see Q8 |
| **Optimising the Cloudflare Radar int→string fallback** | Low severity, and the inference that the Int query is routinely wrong does not follow from the evidence offered. Settling it needs one live request. Not worth a session |
| **A generic table/plugin framework for `console.py`** | Every new source costs a second edit in the renderer today, which is annoying but not a defect. Refactoring the renderer into a framework before the verdict engine defines what it renders is exactly backwards |
| **Publishing any accuracy figure before the held-out corpus exists** | The corpus is circular by construction — precision measured on a URLhaus-labelled set against a scorer that reads URLhaus is the engine grading its own answer key. Until hold-one-feed-out and temporal-split validation run, the tool ships with **no accuracy claim at all**. "Tuned against N labelled indicators, held-out precision X" is defensible; "accurate" is not |
| **A denylist of named low-quality VirusTotal engines** | No measured basis exists. Shipping an unsourced list of named vendors is both wrong and a liability. Weights come from the corpus or they do not exist |

---

## 4b. Operator decisions (settled 2026-08-09)

These were open questions. They are now answered and are **not to be re-litigated** by a future
session. Where a decision went against the recommendation in this document, the recommendation is
left in place above so the reasoning stays legible -- the decision below wins.

| # | Decision | Consequence |
|---|---|---|
| Q1 | User-Agent was inherited, not deliberate | Done in W2.6: `tripper-recon/<version>` |
| Q2 | **System-resolver egress is an ACCEPTED RISK** | 2.2 is documentation, not code. No `--active-dns` flag. Live resolution stays the default and is disclosed in `docs/OPSEC.md` section 3 |
| Q3 | Retrieve published limits with a retrieval date; never from memory | Blocks `docs/RATE-LIMITS.md` (9.4) and the per-provider budget (3.4) until retrieved |
| Q5 | **abuse.ch: build 8.7 in full, including bulk mode, no gate** | Operator accepts the terms-of-service exposure. Their Terms prohibit high-volume automated harvesting by "robots, spiders or scripts"; bulk mode is arguably that. Recorded in `docs/OPSEC.md` rather than mitigated |
| Q8 | **Nothing consumes the FastAPI server; delete it** | Done in W0.8. Removed a class of exposure and the schema-stability requirement in 7.1 |
| Q10 | **GreyNoise: STRUCK, no eligible address** | 8.8 removed from the plan rather than left filed as a task that can never start |
| Scope | **Value-ranked subset, not full W7+W8** | Order: W9 docs -> W8.2 RDAP + 8.1 InternetDB + 8.3 Tranco + 8.7 abuse.ch -> W7.7 caching + 7.2 markdown. Reassess after real use. The remaining W7/W8 items are deferred, not cancelled |
| W5.9 | **Build the recording harness; the operator runs it** | The quota spend and the provider-side log entries are his deliberate act. Until then the ruleset stays `calibration.status: unvalidated` with no accuracy claim |

---

## 5. Open questions for the operator

Ordered by how much downstream work they unblock.

1. **Q1 — Was the browser User-Agent deliberate?** Commit `3e4455d` ("add user-agent spoofing config") and `cli.py:384`'s "to spoof" wording suggest intent. If the intent is evading provider rate limits on authenticated endpoints, that is a terms-of-service question before it is a code question. W2.6 assumes the answer is "inherited, change it".
2. **Q2 — Is system-resolver egress an accepted risk in your environment?** If yes, W2.2 collapses from a code change to a documentation change and `--active-dns` becomes the default with disclosure. If no, passive-by-default is correct. This is the single biggest fork in the plan.
3. **Q3 — Provider free-tier limits.** W3.4 cannot be built on remembered numbers; the audit's own worked example was self-labelled unverified and its arithmetic is unusable. Retrieve VT, Shodan, AbuseIPDB, OTX and IPinfo published limits with a retrieval date before that item is claimed.
4. **Q4 — Do `ip_example.md` / `ASN_Example.md` contain output from real investigations?** `123.123.123.123` reads as a deliberate placeholder, but that was not audited line by line. Confirm before W9.5 commits them.
5. **Q5 — abuse.ch terms.** Their Terms of Use prohibit high-volume automated harvesting by "robots, spiders or scripts". Per-indicator interactive lookups plausibly sit inside fair use; the bulk-file mode is exactly what they name. Settle in writing before W8.7 ships, and gate it off in bulk mode until then.
6. **Q6 — Does Cloudflare Radar return HTTP 200 with a GraphQL `errors` array on a scope failure?** The `TypeError` at `orchestrators.py:78` is certain; the named trigger is not. W0.4 fixes it regardless — this only affects how the fix is tested.
7. **Q7 — VirusTotal v3 URL endpoint details.** The base64url identifier scheme and attribute names in the URL design were stated from general knowledge, not retrieved. Confirm against current VT docs before W6.6, or the implementation silently 404s.
8. **Q8 — Does the FastAPI server have a user?** It is an opt-in second entry point the CLI never starts. If nothing consumes it, deleting it removes an entire class of exposure and roughly a fifth of the security findings. If something does, say what, because that determines whether W7.1's schema stability matters.
9. **Q9 — Who is this tool for?** A personal portfolio artifact and a thing colleagues actually run have different documentation floors. W9 is scoped for the second; if it is the first, W9.4, W9.6 and W9.10 can be dropped.
10. **Q10 — GreyNoise account.** Consumer-email domains get no API key. If you have no non-consumer address, W8.8 is dead and should be struck rather than filed.
11. **Q11 — Scope discipline.** W7 and W8 together are more work than W0-W5 combined and deliver less against the stated goal. Per your standing instruction to be pulled back from over-engineering: if this project must stop somewhere, stop after W5 + W9 and ship a tool that answers the question and documents itself. W6 is the one addition that is clearly worth the extra effort.
12. **Q12 — Repo status.** This is a public portfolio repo. If it ever becomes a consulting deliverable or a revenue path, the agency ethics gate applies before any outside-income activity, per your standing rule. Nothing in this roadmap assumes otherwise.

---

## 6. Reading the sequence at a glance

```
W0 Stop the bleeding ──┐
W1 Tests + CI ─────────┼──► W2 Passive boundary ──┐
                       │                          │
                       └──► W3 HTTP + provider ───┼──► W4 Truthful output ──┬──► W5 Verdict engine ──┬──► W6 URL support
                                                  │                         │                       │
                                                  └─────────────────────────┴──► W8 New sources     └──► W7 Report artifact

W9 Documentation — tracks each workstream as it lands; two items ship inside W0
```

W0 and W1 have no dependencies and should run in the same session or in parallel. Nothing downstream is safe until both exist.
