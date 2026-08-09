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

### Added

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
