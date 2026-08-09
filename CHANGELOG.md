# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Nothing has been released. The version in `pyproject.toml` is still `0.1.0` and no tag exists,
so every change below sits under Unreleased. Entries are grouped by effect on the user, not by
the workstream that produced them; the commit each one came from is named where the reasoning
there is worth reading.

**What these entries are measured against.** The baseline is the tree at `de277f4`, the last
commit before the hardening work began. Everything before that point is unrecorded here, and
this is not a description of the tool's whole feature set: the `ip`, `domain` and `asn`
subcommands, batch IP processing, Rich console rendering and the `--rate-limit` flag all predate
the baseline and appear below only where the hardening work changed them.

## Unreleased

### Security

- **API keys no longer reach output on the error path** (`ae59d18`). Shodan and IPinfo
  authenticate in the query string, so a failing request put the key into both
  `str(request.url)` and `str(HTTPStatusError)`. Both strings were copied into the
  investigation result, which reaches console output and `-o json`. `tripper_recon/utils/redact.py`
  now redacts sensitive query parameters by name and additionally substitutes any known key
  value read from the environment, so a key arriving by an unanticipated route is still caught.
  Cloudflare Radar's response-body echo is redacted the same way. **Anyone who saved console or
  JSON output from a failed Shodan or IPinfo lookup before this change should treat the affected
  keys as disclosed and rotate them.**
- **Non-public addressing is refused on the domain path, not only the IP path** (`8677b65`).
  A sinkholed or split-horizon domain resolving into RFC1918 previously forwarded the operator's
  internal addressing to third-party providers under the operator's own API keys. The guard also
  widened beyond `is_private` to cover multicast and reserved space.
- **Runtime egress allowlist** (`8677b65`). `tripper_recon/utils/http.py` registers an httpx
  request event hook at the single client construction point and raises `PassiveBoundaryViolation`
  before the request reaches the transport, so a rejected request never opens a socket. This
  covers the case a static scan cannot: a URL assembled at runtime from a target-derived value.
- **Secret scanning in CI** (`f7e9d4c`). A gitleaks job scans commit history, not only the
  working tree.
- **The unauthenticated network listener is gone.** See the FastAPI removal under Removed.
- **Provider credentials cannot reach an evidence file.** Evidence capture writes provider
  exchanges to disk precisely so they can be attached to a ticket, which makes a naive recorder a
  credential-distribution mechanism: Shodan and IPinfo authenticate in the query string;
  VirusTotal, AbuseIPDB, OTX, Cloudflare and abuse.ch authenticate in headers; and a provider's
  own 401 body routinely echoes the key it rejected. Three fail-closed controls: URLs go through
  `redact_url`, bodies through `redact_text`, and request headers are captured by **allowlist**
  rather than denylist — a denylist fails open on the next provider that invents a header name
  nobody anticipated, while the cost of failing closed is a missing diagnostic field. Verified
  adversarially with literal redaction disabled, so the structural controls were proven on their
  own rather than masked by the belt-and-braces layer.
- **A password embedded in an indicator URL is redacted before it is stored.** `redact_url`
  stripped credential-bearing query parameters but left the authority alone, so an analyst
  investigating a link carrying `user:pass@` in its userinfo wrote that password verbatim into
  the cache entry's stored indicator and the case record's subject — files on disk that outlive
  the run, in a function whose own documentation claimed userinfo was handled. The username is
  kept, because it is diagnostic and is not the secret. Found by adversarial review of the
  evidence-and-cache write path.
- **A cache entry stamped in the future is refused instead of being served as brand new.** Age
  arithmetic clamps at zero, so an entry whose `queried_at` sat ahead of the reading clock came
  back as a hit reporting `age: "0s"` and `"obtained 0s ago"` — the strongest freshness claim the
  tool can make, manufactured out of a wrong clock — and it walked straight past `--max-age`,
  because nothing is older than a limit when everything reports zero. Causes are mundane: a cache
  directory copied from another host, a VM resuming with a stepped clock. Skew beyond
  `FUTURE_SKEW_TOLERANCE_SECONDS` (5s, which absorbs ordinary NTP jitter) now discards the entry
  and names the skew. Found by adversarial review of the cache lane, not by a failing test.

### Added

- **Provider answers are cached on disk, and every replay is disclosed** (roadmap 7.7), in
  `tripper_recon/utils/cache.py`, with per-provider lifetimes in `utils/cache.yaml`. A domain with
  eight A records costs nine VirusTotal calls per run; re-running it an hour later used to pay
  again. **The rule that governs the whole feature: a cached fact never claims to have been
  queried now.** Every cached value carries the instant it was actually obtained; that instant is
  never rewritten on replay (`CacheEntry` is frozen — there is no setter and no `touch()`); and
  every replay is announced in three places — the first console warning,
  `provider_status[<name>].cache`, and a `freshness` block in `-o json` stating how many answers
  were queried now, how many were replayed, and how old the oldest one is. Only successful answers
  are cached: a 429 or an unset key is a state of the world at one instant, and replaying it would
  outlive its cause. The cache is **inert unless a caller installs a session**, so library callers
  see exactly the previous behaviour.
- **`--offline`, `--max-age`, `--no-cache`, `--cache-dir`.** `--offline` contacts nobody at all,
  **including the system resolver** — name resolution goes through the same cache lane under a
  `dns` pseudo-provider carrying the shortest lifetime in the ruleset, because a run that contacts
  no provider but still resolves the name has still told a nameserver what the operator is looking
  at. When it cannot answer from cache, `--offline` reports a stated gap with the reason rather
  than serving an expired value; that costs coverage, which is the honest price. `--offline` with
  `--no-cache` is refused at parse time: it would consult nobody and serve nothing, producing a run
  indistinguishable from a total intelligence blackout.
- **`-o markdown`** (roadmap 7.2), in `tripper_recon/reporting/markdown.py`. The form an analyst
  pastes into a ticket: ATX headings and GFM pipe tables, no HTML and no box drawing. The console
  format cannot fill this role because `rich` strips its colour the moment output is redirected,
  taking the only malice signal with it. Every provider-controlled value is escaped, so a pulse
  title containing `|`, a leading `#`, raw HTML or `rich` markup cannot break a table, inject a
  heading or arm a link. The module is pure: it reads no clock and touches no file.
- **The evidence envelope** (roadmap 7.6), in `tripper_recon/utils/evidence.py`, captured by a
  response hook on the one client factory so that every provider, retry and redirect hop yields
  the same record with no provider-side cooperation. It carries status, HTTP version, allowlisted
  headers, timings, the sha256 of the **full** body, and what was done to the stored copy.
  **Two timestamps, never one:** `queried_at` (when this tool sent the request) and `observed_at`
  (when the provider says it observed the fact), with `observed_at_source` naming the origin —
  collapsing them hides exactly the staleness the evidence exists to expose. Off by default.
- **`--out`, `--case-dir`, `--evidence`, and `report --from-case`** (roadmap 7.3/7.7). A case
  directory holds the result, the verdict, the cache record, the report and the evidence
  envelopes, so a report can be rebuilt weeks later with nobody contacted and no quota spent.
  **The regenerated report carries the original timestamps** — restamping it would be the same lie
  as a cache claiming a replayed answer was queried now, one artefact further downstream. The
  directory name is built from a hash of the indicator, never from the indicator itself, because
  on the bulk path that is attacker-authored text. `--evidence` without `--case-dir` is refused
  rather than capturing envelopes into memory that nothing will ever write out.
- **Calibration harness** (`tools/calibrate.py`), which records fixtures against live providers so
  the ruleset can eventually carry a held-out accuracy figure instead of none. It is **run by the
  operator by hand and by nothing else**: it refuses to start under a test runner or a CI job with
  no override of any kind, refuses without an explicit `--i-understand-this-spends-quota` flag,
  and refuses again when stdin is not a terminal. The one object that reaches the network
  self-guards in its own constructor, so a test cannot obtain one however it is written. Until the
  operator runs it, the ruleset stays `calibration.status: unvalidated` and the tool makes no
  accuracy claim.
- **Verdict engine** (`5e698d1`), in `tripper_recon/verdict/`. The tool now adjudicates rather
  than only collecting. Five states: `MALICIOUS`, `SUSPICIOUS`, `NO_ADVERSE_FINDINGS`,
  `INSUFFICIENT_DATA`, `KNOWN_INFRASTRUCTURE`. `NO_ADVERSE_FINDINGS` is deliberately not called
  "benign" — the tool reports what it found and does not certify innocence. Properties the design
  enforces:
  - Confidence is a **separate axis** from score. A `MALICIOUS` score at low confidence renders as
    `SUSPICIOUS` with the raw score beside it, and confidence is forced low below the coverage
    floor.
  - Absent data can never reach a benign label; only the known-infrastructure allowlist can, and
    the config loader rejects a ruleset that tries to disable that constraint.
  - Every weight, band, decay constant and threshold lives in `tripper_recon/verdict/scoring.yaml`
    with a comment explaining it. A stamped ruleset version travels in every verdict.
  - The engine is a pure function of (result data, ruleset, now) — no I/O, no network, no global
    clock — so it is testable offline and re-runnable over a saved case.
  - **No accuracy claim is made.** `calibration.status` is `unvalidated`, `fixture_count` is `0`,
    precision and recall are null, and the loader rejects a precision figure unless the status is
    `validated` and the corpus is held out. The weights are informed priors. The golden fixture
    corpus (roadmap W5.9) is not built.
- **`--explain`** on `ip`, `domain`, `url`, `check` and `bulk` (`5e698d1`): shows every signal,
  its points and its ruleset key, so a verdict can be audited rather than trusted. `asn` does not
  take it — the ASN path is a lookup, not an adjudication.
- **URL support** (`e193feb`). A real `url` subcommand exists — the README claimed one for months
  before any code backed it. `--depth url|host|full` composes URL analysis with the existing
  host → IP → ASN pivot, and the depth is a passivity control as well as a cost control:
  `--depth url` and `--depth host` resolve nothing, so the target's authoritative nameserver
  never sees a query. `tripper_recon/utils/urls.py` decomposes without fetching, records
  `scheme_assumed` rather than silently inventing a scheme, and surfaces `userinfo_present`,
  a phishing signal the CLI used to drop.
- **`check` subcommand** (`e193feb`): classifies an indicator of unknown shape and routes it to
  the right lookup. `check --detect-only` costs zero provider quota and constructs no HTTP client.
- **`bulk` subcommand** (`e193feb`): extracts and triages every indicator in a wall of pasted
  text. Local classification by default; `--investigate` is opt-in and hard-capped by
  `--max-targets` so a pasted mail thread cannot fan out.
- **Refang support** (`e193feb`), `tripper_recon/utils/refang.py`: table-driven and applied to a
  fixpoint, so idempotence is structural rather than asserted. Bracketed groups that parse as
  IPv6 are masked with sentinels before the rule table runs, so `http://[2001:db8::1]/x` survives
  byte-identical.
- **Indicator detection** (`e193feb`), `tripper_recon/types/indicators.py`: ordered `detect()`
  over ASN, CIDR, IP, hash, URL, email and domain. Ambiguity is reported, never silently
  resolved — a bare 32-hex string notes that it is also a valid DNS label, and `UNKNOWN` lists
  all seven attempts with a decline reason. CIDRs, hashes, emails and bare `evil.com/a/b`
  classified as nothing before.
- **urlscan.io provider** (`e193feb`), `tripper_recon/providers/urlscan.py`: Search and Result,
  both GET, public scans only. This is the passive answer to the redirect question — read the
  scan somebody else already ran. The screenshot is emitted as a link and never fetched. The
  submission endpoint is absent and the static gate greps for it.
- **VirusTotal URL report lookup** (`e193feb`), `vt_url_summary`: GET on an existing report only.
  A 404 is `UNKNOWN` and is explicitly excluded from error suppression, because a swallowed 404
  renders exactly like "we asked and it came back clean".
- **Provider coverage, provenance and run metadata** (`2894496`). Every result carries a
  `Coverage` (`result.coverage`, `data['coverage']`) naming which providers answered, which
  errored, which had no credential and which were never attempted, with a rendered headline such
  as "1 of 6 providers answered". The denominator comes from the declared provider sets, never
  from the calls that happened to be made. Every result also carries `RunMetadata`: tool,
  version, RFC 3339 UTC start, and a run id shared across every target in one invocation so a
  bulk run correlates.
- **Skipped addresses are reported** (`2894496`). A domain resolving to three internal addresses
  and one public one is no longer presented as a domain with one address; each refused address is
  reported with its reason.
- **Retained provider fields that were already being fetched and discarded** (`2894496`) — no new
  request, no new quota: VirusTotal per-engine results and `last_analysis_date`; AbuseIPDB
  `lastReportedAt`, `isWhitelisted`, `usageType` and `isTor`; OTX per-pulse author and dates;
  Shodan `vulns`, `hostnames` and `last_update`. A 100% AbuseIPDB score from 2019 is not a 100%
  score from yesterday.
- **Per-target wall-clock deadline** (`8677b65`). Nothing had elapsed-time awareness previously,
  and OTX alone carried a worst case near 84 seconds.
- **IP provenance tagging** (`8677b65`): each address is tagged active, passive, or both.
  "Resolved now" and "seen historically by VirusTotal" are different evidentiary claims.
- **Test suite, lint, type checking and CI** (`f7e9d4c`, grown through `e193feb`). The repo had
  no tests, no linter config, no type checker and no `.github/` directory; three PRs had merged
  with nothing checking them. It now has 2201 tests, `ruff` and `mypy` clean, and CI on Python
  3.10, 3.11 and 3.12, plus `.pre-commit-config.yaml` and a PR template carrying a required
  passive-boundary checkbox. `tests/test_passivity.py` is a build gate: it pins every outbound
  hostname to an explicit allowlist, asserts the forbidden submission endpoints appear nowhere in
  the source, and asserts name resolution happens only in `tripper_recon/utils/dns.py`.
- **Documentation set** (`503784a`): `docs/ROADMAP.md` (the sequenced hardening plan, W0–W9),
  `docs/OPSEC.md` (the passivity contract per provider, with its gaps stated), `docs/PROVIDERS.md`
  (provider matrix, extracted fields, credential handling), and `docs/review/` (eleven supporting
  audit, design and verification reports).
- **`pyyaml` as a hard runtime dependency** (`5e698d1`), with both YAML files declared as package
  data and verified present inside a built wheel. Without that, an installed tool imports fine and
  then refuses to adjudicate.

### Changed

- **Exit-code contract. This breaks automation keyed on the old behaviour** (`2894496`).
  A total intelligence blackout — no provider answered at all — now returns `ok=False` and exits
  `1`, where it previously exited `0` because the address merely parsed. A partial answer still
  exits `0` and carries the coverage that says how partial it was. Exit `2` is reserved for input
  the CLI rejected before any request left. The full table is documented in the
  `tripper_recon.cli` module docstring as the public interface it is. The exit code reports
  whether the lookup worked, not what it found: a `MALICIOUS` indicator with full coverage exits
  `0`, and a pipeline that wants to branch on maliciousness must read `data['verdict']`.
- **Exit code `1` additionally covers "the run completed but an artefact could not be written".**
  If `--out` or `--case-dir` was asked for and the write failed, the run exits `1` even though the
  lookup itself succeeded. Exiting `0` there would leave a pipeline believing it holds a report it
  does not hold, which is the same class of error as a clean-looking blackout.
- **`_default_output_dir` resolves against the working directory, not the installed package.** It
  previously resolved against `Path(__file__).parent.parent`, so after `pip install .` a bare
  `--prefixes-out foo.txt` wrote the analyst's evidence into `site-packages/outputs/` and reported
  success. Nothing failed, nothing warned, and the file was not where they looked for it.
- **`result.data` gains `freshness` and `cache` blocks, and `collection` is now published on the
  domain path too.** All three appear **only when a cache session is installed**, so every
  existing payload and every existing test is unchanged. `collection.passive_only` on the domain
  path reports whether the system resolver ran **on this run** — a replayed address list leaves it
  `true`, because no query left the host.
- **User-Agent no longer impersonates Chrome** (`8677b65`). The default is now
  `tripper-recon/<version>`. The API key already identifies the caller, so impersonation bought
  nothing and cost a terms-of-service exposure. `--user-agent` and `TRIPPER_RECON_USER_AGENT`
  still override it. The `--user-agent` help text, which still described the flag as spoofing,
  was corrected in `2894496`.
- **Defanged input is refanged and processed instead of being rejected** (`e193feb`). `url` and
  `domain` previously exited `2` and told the analyst to retype. A defanged indicator is the
  normal thing pasted at 02:00 — it arrives that way from email and tickets — so the tool now
  refangs, announces the transform (never silently), and displays the raw form in the report.
  14 tests that pinned the old refusal were rewritten to assert the new contract rather than
  deleted, and the markup-safety cases were kept because the hazard moved to the announcement
  path rather than going away.
- **Human-facing output is defanged by default** (`e193feb`). `--fanged` turns it off. Defanging
  is a per-field property, not a regex over the finished document, so third-party pivot links —
  which point at VirusTotal, Shodan, AbuseIPDB and Cloudflare Radar rather than at the target —
  stay clickable. **`-o json` is never defanged**, in either mode; machines consume it and
  `evil[.]example` is not a hostname.
- **HTTP/2 and connection pooling now actually apply** (`8677b65`). The explicit `transport=`
  argument made httpx discard the client's `http2` flag and `limits`. Removing it changed `http2`
  from `False` to `True` and `max_connections` from the 100 default to the 50 that had been
  configured all along.
- **The concurrency limiter now bounds real work** (`8677b65`). Three coupled defects were fixed
  together: it wrapped `asyncio.create_task()` rather than the await, so it constrained nothing
  (probe: requested 2, observed 10); `configure_rate_limit` never reached it, so `--rate-limit`
  did nothing; and the module-global semaphore was bound to one event loop, which was harmless
  only because it never contended. Peak concurrency now equals the requested rate, and two
  sequential `asyncio.run()` calls in one process both succeed.
- **Retries are decided by status code** (`8677b65`). 408, 425, 429 and 5xx retry; 401, 403, 404
  and other 4xx fail fast instead of being retried four times. A server-supplied `Retry-After` is
  honoured in both delta-seconds and HTTP-date form and clamped to 60 seconds, so a hostile or
  broken header cannot park a run.
- **Domain, ASN and PeeringDB paths parallelised with explicit ceilings** (`8677b65`): the domain
  path is bounded at 8 concurrent addresses, ASN neighbour resolution at 8 (previously up to 24
  unbounded), and `resolve_domain` is time-bounded, independently cancellable per address family,
  and deterministically ordered so two runs diff cleanly.
- **One shared provider-call helper** (`8677b65`) replaced 23 duplicated try/await/except blocks.
  The envelope preserves the ok/error distinction the old code flattened to `{}` — that
  flattening is precisely how "never asked" became indistinguishable from "came back clean" — and
  records provider outcome, error payload and elapsed time per provider.
- **Structured logs go to stderr** (`ae59d18`). They previously collided with JSON output on
  stdout and broke `-o json | jq` on any errored target. `TRIPPER_RECON_LOG_LEVEL` now accepts a
  level name as well as a number; the documented value `INFO` used to raise `ValueError` at
  import.
- **`-o/--format` is position-independent** (`ae59d18`). Subparser defaults overwrote the
  top-level value, so `-o json ip 8.8.8.8` silently emitted Rich text into a JSON parser.
  Subparser defaults are now `argparse.SUPPRESS`.
- **Console output rewritten for the 02:00 case** (`5e698d1`): the verdict word first, because
  rich strips colour exactly when output is redirected into the ticket it is meant to feed; then
  confidence, coverage, the signals that justify the verdict with their points, contradictions,
  and collection mode. Geolocation moved below the fold and is labelled "context, not evidence".
- **Packaging metadata** (`503784a`, `5e698d1`): real author and copyright holder, project URLs
  and classifiers; the licence key moved to the PEP 639 SPDX form. setuptools hard-errors on the
  old table form alongside `license-files`, so `pip wheel .` was broken before this and nothing
  noticed, because no CI job built the package.
- **`docs/` excluded from ruff** (`89150c0`). ruff 0.16 formats Python code blocks inside
  Markdown; the `ruff format` run in `da70e2d` silently rewrote source quoted verbatim in six
  review reports that cite it with `file:line` anchors as evidence of a defect. That is evidence
  corruption, not formatting. The six affected files were reverted before commit; nothing
  corrupted reached history.
- **One-time `ruff format` normalisation** (`da70e2d`), isolated in its own commit so it does not
  pollute the blame history of the functional changes around it. 27 files reformatted, no
  behavioural change, identical test results before and after.

### Fixed

- **An unasked provider no longer renders as a clean result** (`ae59d18`, extended in `2894496`).
  This was the most dangerous failure mode in the tool: absence reading as safety. An unset
  `VT_API_KEY` produced empty VirusTotal stats, summed them to `0/0`, and coloured the result
  green — indistinguishable, on screen, from a clean verdict. Fields with no data now render
  `no data - not queried or query failed`, and the coverage line names every provider that did
  not answer and why: no API key, skipped, or query failed. Empty coverage is a ratio of 0.0,
  never 1.0, and merge conflicts resolve toward less coverage, so the number can understate but
  never overstate what was learned.
- **Provider-controlled strings are escaped before rich parses them** (`ae59d18`, completed in
  `f7e9d4c`). An OTX pulse titled `evil [/] campaign` raised `MarkupError`, and a title
  containing `[green]0/94 clean[/]` rendered as green text with the tags consumed — a crash and a
  display spoof from the same root cause. `f7e9d4c` extended the escaping to `cli.py`, which had
  been missed: a target containing `[/]` still crashed, and `evil[dot]com` was displayed to the
  analyst as `evilcom`, which is the one string that message has to get right.
- **The error handler no longer crashes on an `httpx.RequestError` built without a request**
  (`f7e9d4c`). httpx implements `.request` as a property that raises when unset, and `getattr`'s
  default only swallows `AttributeError`.
- **Cancelled targets no longer raise `AttributeError`** (`f7e9d4c`). Results were narrowed with
  `isinstance(item, Exception)`, but `asyncio.CancelledError` has inherited from `BaseException`
  since Python 3.8. Narrowed to `BaseException`, re-raising `KeyboardInterrupt` and `SystemExit`.
- **Non-string provider error values no longer raise `TypeError`** (`ae59d18`). Cloudflare returns
  HTTP 200 with a GraphQL `errors` array, so the error value can be a list, and testing
  membership of an unhashable operand against a set raised.
- **Defanged input no longer raises an unhandled `ValueError`** from `urlparse` (`ae59d18`). It
  exited `2` with an instruction from that commit; `e193feb` replaced that with refang-and-proceed.
- **`render_asn_header` no longer raises `AttributeError`** when IPinfo returns `org` as a string
  (`ae59d18`).
- **ASN warnings are rendered** (`2894496`). The list was computed, returned, and never read by
  the console branch.
- **`_join_asns` computed its "and N more" suffix from the already-truncated list** (`2894496`),
  so the suffix never appeared.
- **The BGP victim/hijacker split no longer emits a number it cannot substantiate** (`8677b65`).
  It was arithmetic over mismatched denominators — an all-pages total minus a single-page count —
  which the console rendered as the prose "always as a victim".
- **Six domain-validation gaps** (`e193feb`), each of which had been pinned as an xfail in
  `f7e9d4c` asserting the desired behaviour: IDN, punycode TLDs, trailing dot, trailing-hyphen
  labels, the per-label 63-octet limit, and AS-prefixed ASNs. Validation encodes rather than
  folds, so a Cyrillic homograph stays distinct from its Latin twin. The suite now reports
  0 xfailed.
- **`.gitignore` no longer swallows test fixtures** (`f7e9d4c`). The blanket `*.json`, `*.csv`,
  `*.tsv` and `*.txt` rules were narrowed with negations scoped to `tests/` and a future
  `schema/` only;
  `outputs/`, `results/` and `reports/` stay ignored as directories, so no negation can resurrect
  investigation output.

### Removed

- **The FastAPI server** (`ae59d18`), by operator decision: nothing consumed it. Deletes
  `tripper_recon/api/`, the `tripper-recon-api` console-script entry point, and the `fastapi` and
  `uvicorn` dependencies. This removes an unauthenticated `0.0.0.0` bind in a process holding six
  API keys, and roughly a fifth of the security findings with it. **There is no REST API and no
  HTTP server. Anything that called it must be rewritten against the CLI**, whose `-o json`
  output is the machine-readable surface.
- **Browser User-Agent impersonation** — see the User-Agent entry under Changed.

### Notes on scope

Claims this changelog deliberately does not make, because the code does not support them:

- **No accuracy claim for the verdict engine.** Its weights are unvalidated informed priors and
  the golden fixture corpus is not built. See the Added entry.
- **System-resolver egress on the `domain` and `url --depth full` paths is an accepted risk**, not
  a fixed one. It is documented in `docs/OPSEC.md` section 3 and `docs/ROADMAP.md` section 4b.
  There is no flag that disables it; `--depth url` and `--depth host` are the paths that resolve
  nothing.
- **No markdown report output.** Output is console or JSON.
