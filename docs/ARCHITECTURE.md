# Architecture

How the pieces fit, for a contributor or for a future you.

This document describes the code as it stands. Every claim below points at a file, and most
point at a line. If a statement here disagrees with the code, the code is right and this
document is the defect. Fix it in the same commit that moves the code.

Two companion documents cover what this one does not. [`OPSEC.md`](OPSEC.md) states the passive
boundary and every outbound destination. [`PROVIDERS.md`](PROVIDERS.md) states what each provider
returns and what it costs.

---

## 1. What the thing is

`tripper-recon` is a passive OSINT command-line tool. It investigates an IP address, a domain, a
URL or an ASN by asking third parties that already hold intelligence about the indicator. It
never contacts the indicator itself, with one disclosed exception covered in section 8.

There is no server and no REST API. An earlier FastAPI entry point was deleted, and
`tests/test_server_removed.py` fails the build if one comes back.

The tool ships fourteen provider modules plus urlscan.io, which is written but not wired. Six need
no credential at all (RIPEstat, CAIDA AS-Rank, PeeringDB, Shodan InternetDB, RDAP, Tranco), so
`tripper-recon asn 15169` works with an empty `.env` -- and, since 2026-08-09, an empty `.env` no
longer means a run makes no requests at all.

---

## 2. The layers

Five layers, and the dependency arrows only ever point one way.

```
  cli.py                      argument parsing, exit codes, output selection
    |
    v
  orchestrators.py            fan-out, envelopes, coverage, adjudication calls
    |
    +--> providers/*.py       one module per third party, one shape of return value
    |         |
    |         +--> utils/backoff.py     retry policy
    |         +--> utils/http.py        the one client factory + the egress allowlist
    |
    +--> verdict/             pure scoring over collected evidence
    |
    +--> types/models.py      the typed result surface

  reporting/console.py        renders result.data. Imports nothing from the layers above it.
```

The dependency direction is verifiable, not aspirational:

| Claim | Evidence |
|---|---|
| `cli.py` is the only module that imports `orchestrators` | `grep -rn "from tripper_recon.orchestrators" tripper_recon/` returns one hit, `cli.py:61` |
| `cli.py` is the only module that calls `asyncio.run` | six call sites, all in `cli.py` between lines 1360 and 1426 |
| `reporting/console.py` imports no orchestrator and no provider | its only package imports are `tripper_recon.__version__` and `tripper_recon.verdict.models` (`console.py:15-16`) |
| `verdict/` imports no provider, no orchestrator and no HTTP code | it imports `types.models.Coverage` and its own siblings, nothing else |
| Only one module builds an HTTP client | one `httpx.AsyncClient(` in the whole package, at `utils/http.py:168`, asserted by `tests/test_passivity.py:1017` |

`reporting/console.py` and `verdict/` are **consumers**. Both read the result the orchestrator
produced. Neither one collects anything, and neither one can reach the network. That is what
makes the renderer testable from a fixture dict and the engine testable with no API keys.

---

## 3. The request path for one indicator

This is `tripper-recon ip 8.8.8.8`. The domain, URL and ASN paths differ in which providers run
and in how many waves, and they share every box below.

```
  main()                                 cli.py:1401
    |  load_env()                        cli.py:1402   reads .env into os.environ
    |  configure_rate_limit(...)         cli.py:1571   process-wide concurrency ceiling
    v
  asyncio.run(_cmd_ip(...))              cli.py:1581
    v
  investigate_ip(ip)                     orchestrators.py:912
    |  is_valid_ip                       reject -> ok=False, empty data
    |  non_public_ip_reason              orchestrators.py:792  refuse RFC1918 and friends
    v
  _with_deadline(...)                    orchestrators.py:815  180s wall clock, then give up loudly
    v
  create_client()                        utils/http.py:159     THE only client construction
    |                                    installs _enforce_egress_allowlist as a request hook
    v
  _ip_provider_wave(...)                 orchestrators.py:846  five providers, one asyncio.gather
    |
    +--> _call_provider("virustotal", vt_ip_summary(...))      orchestrators.py:360
    +--> _call_provider("ipinfo",     ipinfo_ip(...))
    +--> _call_provider("shodan",     shodan_host(...))
    +--> _call_provider("abuseipdb",  abuseipdb_check(...))
    +--> _call_provider("otx",        otx_ip_pulses(...))
              |
              |  async with rate_limited():          utils/http.py:237
              |      payload = await provider(...)
              |          |
              |          +--> with_exponential_backoff(_call)  utils/backoff.py:142
              |                   |
              |                   +--> client.get(...)  --> [EGRESS HOOK] --> socket
              v
          ProviderCall envelope       _envelope, orchestrators.py:335
    v
  _asn_meta_for_ip(...)                  orchestrators.py:864  second wave, needs IPinfo's ASN
    v
  _finalise(...)                         orchestrators.py:528
    |  coverage_from_result_data         types/models.py:607   N of M, denominator declared
    |  _coverage_warnings                orchestrators.py:495  say the gaps out loud
    |  ok = not blackout                 orchestrators.py:574
    v
  _adjudicate_ip(result, ip=ip)          orchestrators.py:721
    |  _adjudicator()                    orchestrators.py:617  load ruleset + catalogue + clock
    |  extract_ip_signals(...)           verdict/signals.py    pure
    |  engine.evaluate(...)              verdict/engine.py:811 pure
    v
  InvestigationResult
    |
    +--> -o json    : model dump, never defanged
    +--> console    : reporting/console.py renders result.data
    v
  SystemExit(code)                       0, 1 or 2. See the cli.py module docstring.
```

Two properties of that path are worth stating plainly.

**Collection ends before adjudication starts.** `_adjudicate_ip` runs outside the
`async with create_client()` block (`orchestrators.py:959-961`). Nothing in `verdict/` can open
a socket, because by the time it runs there is no client.

**A scoring failure never becomes a clean report.** If the ruleset will not load, or the engine
raises, `_record_verdict_failure` (`orchestrators.py:676`) writes `data['verdict_error']`, adds a
warning, and leaves the collected data standing. A panel with no verdict line and no explanation
would read as a panel with nothing to report, and that is the failure this whole codebase exists
to remove.

---

## 4. The provider envelope contract

Every provider module exposes async functions with one return shape. Nothing else is permitted.

```python
# success
{"ok": True, "data": {...}}

# failure of any kind
{"ok": False, "error": "<code>", ...optional status, message, url}
```

Three rules bind a provider module.

**A missing credential returns, it does not raise.** The guard is the first statement in the
function, before any client work:

```python
# providers/shodan_api.py:63-65
async def shodan_host(*, client: httpx.AsyncClient, api_key: Optional[str], ip: str) -> Dict[str, Any]:
    if not api_key:
        return {"ok": False, "error": "missing_api_key"}
```

The spellings differ per provider for historical reasons, and `orchestrators.NOT_CONFIGURED_ERRORS`
(`orchestrators.py:173`) is the one place that knows all of them: `missing_api_key`,
`missing_api_token`, `missing_token` and `API key not configured`. If you add a provider, use one
of those four strings. A new spelling classifies as a hard error and misreports the run.

**The request is wrapped in `with_exponential_backoff`.** Every provider does this
(`utils/backoff.py:142`). The retry policy is deliberate and narrow. `utils/backoff.py:48` retries
408, 425, 429 and the 5xx family plus transport errors. Everything else, including 401, 403 and
404, raises on the first attempt with no sleep, because a retry burns three more rate-limit slots
and still fails. A server-supplied `Retry-After` wins over the local schedule and is clamped to 60
seconds (`utils/backoff.py:54`).

**The provider never sees an orchestrator type.** A provider takes a client, a credential and an
indicator, and returns a plain dict. It does not build a `ProviderCall`, does not know about
coverage, and does not log a verdict. That is what keeps `tests/test_providers_fields.py` able to
test a provider with a respx mock and nothing else.

`_call_provider` (`orchestrators.py:360`) is the only place in the package that awaits a provider.
It times the call, holds a concurrency permit for its whole duration including retries, catches
`Exception` so one provider cannot take the other four down, and converts whatever comes back into
a `ProviderCall`. Two things it deliberately does **not** absorb:

* `BaseException`, so a deadline cancellation reaches `_with_deadline` instead of being filed as a
  provider failure.
* `PassiveBoundaryViolation`, which is re-raised. See section 8.

---

## 5. The single client factory

`create_client()` at `utils/http.py:159` is the only place in the package that constructs an
`httpx.AsyncClient`. That is not a style preference. It is the chokepoint the egress hook needs.

```python
# utils/http.py:168-175
return httpx.AsyncClient(
    headers=default_headers(),
    http2=True,
    timeout=httpx.Timeout(timeout),
    limits=httpx.Limits(max_keepalive_connections=20, max_connections=50),
    event_hooks={"request": [_enforce_egress_allowlist]},
    verify=True,
)
```

`_enforce_egress_allowlist` (`utils/http.py:112`) reads the host of the request that is about to
go out. If the host is not in `ALLOWED_EGRESS_HOSTS` (`utils/http.py:63`), it raises
`PassiveBoundaryViolation` before the request reaches the transport. No socket opens. The URL in
the exception message is redacted first, because Shodan and IPinfo authenticate in the query
string and an exception message reaches logs.

Two tests hold this in place. `tests/test_passivity.py:1017` asserts that only `utils/http.py`
constructs a client. `tests/test_passivity.py:1056` asserts that the factory installs the hook.
A third, in `tests/test_http.py`, fails if the runtime allowlist and the static allowlist in
`tests/test_passivity.py:66` drift apart.

The same module owns two more process-wide concerns, for the same reason. `configure_user_agent`
sets the User-Agent the tool sends, and it defaults to `tripper-recon/<version>`. `rate_limited()`
(`utils/http.py:237`) holds one concurrency permit per in-flight provider call. Wrap the **await**
of a provider call with it, never `asyncio.create_task`. Creating a task schedules it without
awaiting it, so a limiter around task creation acquires and releases in the same tick and
constrains nothing.

**If you add a provider, you touch four files in one commit:** the provider module,
`ALLOWED_EGRESS_HOSTS` in `utils/http.py`, `ALLOWED_HOSTS` in `tests/test_passivity.py`, and the
destination table in `OPSEC.md` section 2. Miss the third and CI fails. Miss the second and the
provider raises at runtime.

---

## 6. Coverage, and the suppression policy

This is the part of the design most likely to be undone by accident, so it gets its own section.

The tool used to run with two of six credentials set and print one VirusTotal score, one Shodan
error, and nothing at all about the four providers it never asked. Sparse output reads as a clean
indicator. Nothing on the screen contradicted that reading.

The fix separates two decisions that used to be one.

**Suppression is a rendering decision.** `_should_suppress` (`orchestrators.py:296`) marks
expected noise: an unset API key, IPinfo's free tier refusing ASN lookups, a RIPEstat network
blip. `_collect_errors` (`orchestrators.py:397`) leaves suppressed failures out of the error list,
so an operator with three keys does not read three red lines that mean "you did not buy this."

**Suppression is never a coverage decision.** `_status_map` (`orchestrators.py:417`) records every
provider that was considered, with its outcome, its elapsed time and its redacted error, and marks
the suppressed ones with `suppressed: true` rather than dropping them. `Coverage.from_status_map`
(`types/models.py:272`) counts a suppressed provider in the denominator and never in the
numerator. `_suppressed_names` (`orchestrators.py:442`) then names them in a warning, so the
quieting is visible in the output that reports it.

The denominator comes from the declared provider tuples, not from the calls that happened:
`IP_PROVIDERS` (`orchestrators.py:185`), `DOMAIN_PROVIDERS` (`:188`), `URL_PROVIDERS` (`:201`) and
`ASN_PROVIDERS` (`:216`). This matters in exactly the case where it is easy to get wrong.
`cloudflare_asn` on the IP path is a second wave that only runs when IPinfo returned an ASN. When
IPinfo fails, Cloudflare is never attempted, and a denominator counted from attempts would shrink
from six to five and report **better** coverage for the **worse** run. `from_status_map` files an
expected provider with no status entry as `skipped`, which keeps it in the denominator.

Renderer side: `reporting/console.py` prefers the published `data['coverage']` over recomputing
from `provider_status` (`console.py:277`), so the screen and the JSON export never state the ratio
in two different numbers. `no_data_text` (`console.py:342`) is the one sentence for "this provider
did not answer," and every one of its outputs contains the substring `no data`. A provider that
was not asked is never rendered as a zero and never in green.

---

## 7. The verdict pipeline

```
  provider payloads (dicts)
        |
        v
  verdict/signals.py        (payload, cfg, now) -> List[Signal]        PURE
        |
        v
  verdict/engine.py         evaluate(signals, coverage, cfg, now, ...) PURE
        |
        v
  verdict/models.py         Verdict                                    validated record
```

**Both stages are pure functions.** No clock read, no file read, no network, no global state. The
engine takes `now` as an argument and rejects a naive datetime (`engine.py:135`). The ruleset and
the known-infrastructure catalogue are loaded by the **caller**, in `_adjudicator()`
(`orchestrators.py:617`), because loading is I/O. That is what lets the whole engine be tested
offline against committed fixtures, with no API keys, and with no way for a test to touch a
target.

Front doors, for callers that hold an orchestrator payload rather than a signal list:

| Function | Location | Scores |
|---|---|---|
| `evaluate` | `engine.py:811` | the general form, any scope |
| `evaluate_ip_analysis` | `engine.py:1212` | one per-address analysis dict |
| `evaluate_domain_intel` | `engine.py:1242` | the domain itself |

**Every constant lives in `verdict/scoring.yaml`.** Weights, thresholds, decay bands, confidence
floors, contradiction rules and override tiers are all in the YAML file. There is not one scoring
constant in the Python. `verdict/config.py` owns the shape of that file and refuses to load a
ruleset that is internally incoherent: `extra="forbid"` on every model catches a typo'd key, and a
coherence validator catches an overlapping band, a decay factor that grows with age, or an
override rule that can never fire. A dead rule must be written `enabled: false` rather than left
looking active.

Three version stamps move independently and each one is in the verdict record:
`ENGINE_VERSION` (`verdict/engine.py:102`) for the algorithm, `version` in `verdict/scoring.yaml:24`
for the numbers, and `VERDICT_SCHEMA_VERSION` (`verdict/models.py:83`) for the record shape.

The five labels are `MALICIOUS`, `SUSPICIOUS`, `NO_ADVERSE_FINDINGS`, `INSUFFICIENT_DATA` and
`KNOWN_INFRASTRUCTURE` (`config.py:170`). Only the first three are reachable by score
(`config.py:192`). Coverage produces `INSUFFICIENT_DATA`. The Tier A allowlist, which is a human
decision with a citation, produces `KNOWN_INFRASTRUCTURE`. Confidence is a separate axis with its
own three bands (`config.py:199`), and it is forced to the lowest band when coverage sits under
the ruleset floor. "Score 71, confidence LOW, 2 of 6 providers answered" is a real state, and the
model can express it.

**The engine makes no accuracy claim.** `scoring.yaml:33-43` carries `status: unvalidated`,
`fixture_count: 0`, and null precision and recall. No labelled corpus exists and nothing has run
on a held-out set. The loader rejects a ruleset that carries a precision or recall figure it has
not earned. Do not write, anywhere, that the engine is accurate.

---

## 8. Two invariants a contributor must not break

Everything else in this document is description. These two are rules.

### 8.1 Absent data never scores as clean

A provider that was not asked, that failed, or that has no key contributes nothing toward a benign
conclusion. Ever.

Where it is enforced:

| Layer | Mechanism | Location |
|---|---|---|
| Status | `NOT_CONFIGURED` is a distinct outcome from `OK` | `types/models.py:43` |
| Coverage | an empty `Coverage` has `ratio == 0.0`, not `1.0` | `types/models.py:235` |
| Coverage | zero applicable providers is never "sufficient", whatever the floor | `types/models.py:261` |
| Result | `coverage_or_unknown` returns zero coverage when coverage was never computed | `types/models.py:584` |
| Result | `ok=False` when providers were applicable and none answered | `_is_blackout`, `orchestrators.py:477` |
| Signals | an extractor handed an empty payload returns an empty list, not a zero-magnitude "looks fine" signal | `verdict/signals.py` |
| Engine | `NO_ADVERSE_FINDINGS` requires coverage above the floor **and** an affirmative negative | `verdict/engine.py` |
| Verdict | a model validator re-checks the rule on the finished record | `verdict/models.py:345` |
| Render | a provider that did not answer renders as `no data - ...`, never a green zero | `console.py:342` |

The general shape of the rule: **a benign reading has to be earned by an affirmative negative.**
VirusTotal answering that 0 of 94 engines flagged the indicator is evidence. VirusTotal returning
404 is not evidence, and emits nothing.

If you add a code path, ask what it does when the data is missing. If the answer is anything other
than "reports the gap," the path is wrong.

### 8.2 Every outbound request goes to a third party that already holds the data

The target is never contacted. `ALLOWED_EGRESS_HOSTS` (`utils/http.py:63`) is the complete list of
hosts this tool may reach, and the target can never be on it.

One provider has a destination that is genuinely dynamic. RDAP's authoritative server is chosen at
runtime from IANA's bootstrap files (RFC 9224), which a static allowlist cannot enumerate in
advance. That is resolved by refusing rather than by widening: `providers/rdap.py` bootstraps
client-side, follows no redirects, and checks the resolved host against this same set before it
builds a request -- returning `registry_not_allowlisted`, an explicit UNKNOWN, otherwise. No
registry host is allowlisted today (`docs/OPSEC.md` section 6, gap 9).

Two halves enforce this, and they are complementary rather than redundant:

* **The static gate fails the build.** `tests/test_passivity.py` parses the package source. It
  checks that every URL literal targets an allowlisted host, that no forbidden endpoint appears
  (`FORBIDDEN_MARKERS`, `test_passivity.py:148`, covering VirusTotal URL submission, urlscan scan
  submission, DNSBL lookups, redirect following and more), that every non-GET request goes to one
  of the pinned read-only query endpoints (`NON_GET_DESTINATIONS`: Cloudflare's Radar GraphQL and
  the two abuse.ch platforms, each pinned by constant NAME and by resolved VALUE), and that name
  resolution appears in exactly one module.
* **The runtime hook fails the run.** A static scan sees literals. It cannot see a host assembled
  at run time, and `client.get("https://" + target_host + "/")` passes every static check while
  being a direct fetch of the target. The event hook in `create_client` catches that one.

`PassiveBoundaryViolation` is re-raised by `_call_provider` rather than filed as a provider error
(`orchestrators.py:382`). Recording it as one more line in an error list would turn the loudest
signal the codebase has into routine noise. It is a defect in the tool and it is meant to stop the
run.

**The one disclosed exception.** `utils/dns.py:63` resolves a domain through the system resolver
on the `domain` path, and on the `url` path at `--depth full`. That recursive lookup can terminate
at the target's own authoritative nameserver. The operator has **accepted** this risk. It is
documented in `OPSEC.md` section 3 and recorded as decision Q2 in `ROADMAP.md` section 4b. There
is no flag to turn it off, and there is no `--active-dns` flag. `--depth url` and `--depth host`
on the `url` subcommand resolve nothing at all, which is what makes them fully passive.

`tests/test_passivity.py:932` fails the build if any module other than `utils/dns.py` resolves a
name. An accepted risk is only auditable while it lives in exactly one place.

---

## 9. The `types/models.py` surface

This module is the typed contract between the collector, the renderer and the engine. Four types
carry most of the weight.

### `ProviderStatus` (`models.py:43`)

What happened when one provider was asked about one indicator. Five members: `OK`, `NOT_FOUND`,
`ERROR`, `NOT_CONFIGURED`, `SKIPPED`. Two properties carry the semantics so no caller re-derives
them: `is_observation` (the provider was consulted and its answer means something) and
`is_missing_coverage`. They are exact complements.

Accuracy note for a contributor reading the code: `_envelope` (`orchestrators.py:335`) produces
exactly three of the five today, which are `OK`, `NOT_CONFIGURED` and `ERROR`. `SKIPPED` is
produced by `Coverage.from_status_map` for a provider that was expected and never attempted.
Nothing emits `NOT_FOUND` at present. A provider returning `{"ok": False, "error": "not_found"}`
classifies as `ERROR`, which under-states its evidence and over-states the gap. That is the safe
direction to be wrong in, and it is a known rough edge rather than a design intent.

### `Coverage` (`models.py:162`)

"N of M providers answered," with the names in each bucket. Buckets: `answered`, `not_found`
(a documented subset of `answered`), `errored`, `unconfigured`, `skipped`. Computed fields give
`answered_count`, `applicable_count`, `missing`, `ratio`, `is_complete` and `headline`.

Three design rules you cannot switch off:

1. A provider with no API key is **missing coverage**, not an excuse. There is no flag that
   shrinks the denominator to the providers that happened to be configured.
2. Conflicts resolve toward **less** coverage. If a name appears in `answered` and in any missing
   bucket, the model validator drops it from `answered` (`models.py:200`). A merge can understate
   coverage and can never overstate it.
3. `Coverage()` has `ratio` 0.0, `is_complete` False and `is_sufficient` False. Zero applicable
   providers yields 0.0, not 1.0 and not a `ZeroDivisionError` that a caller papers over with a
   default of 1.0.

`merge` (`models.py:320`) unions several coverages. Callers namespace the names first with the
`prefix` argument, because the domain path has one status map per resolved address plus one for
the domain itself.

### `RunMetadata` (`models.py:443`)

Tool, version, run id and a timezone-aware UTC start time. `started_at` rejects a naive datetime
rather than assuming UTC, and serializes as RFC 3339 in both `model_dump()` and
`model_dump_json()`. `current_run()` (`models.py:511`) caches one instance per process, so every
target in a bulk run carries the same run id and the lines correlate afterwards.

### `SkippedAddress` (`models.py:382`)

An address that was resolved and then deliberately not investigated, because the non-public guard
refused it. Carries the address, a normalized `SkipReason`, the provenance tag (`active`,
`passive` or `active+passive`) and one analyst-facing `explanation` sentence.

This type exists because a domain that resolves to three internal addresses and one public one is
not a domain with one address. The skipped addresses used to vanish from the output. A skipped
address is missing coverage in the same sense as an unconfigured provider: no question was asked,
so no answer may be inferred.

### `InvestigationResult` (`models.py:561`)

The whole result: `ok`, `data`, `warnings`, `errors`, plus `run`, `coverage` and
`skipped_addresses`. Read `coverage` through `coverage_or_unknown` (`models.py:584`) in any code
that scores or renders confidence. `coverage is None` means coverage was not computed, which is
not the same as full coverage.

The `ok` contract is a public interface, because `cli.py` maps `not result.ok` onto exit code 1.
It is stated in full in the `orchestrators.py` module docstring. The short version: `ok=False`
means the target was rejected, the deadline fired, or no provider answered. **`ok=True` is not a
claim that the lookup was complete.** A partial answer of two providers out of six is `ok=True`,
and `coverage.is_complete` is the flag that says the answer is whole.

Coverage and run metadata are written into `data` **as well as** onto the model fields. The model
fields are the typed interface. The `data` copies exist because the console renderers receive
`result.data` and nothing else, which is exactly why the ASN path's warnings once reached the JSON
consumer and never reached the screen.

---

## 10. Where things live

| Path | Holds |
|---|---|
| `tripper_recon/cli.py` | argparse wiring, six subcommands, exit-code contract, defanging switch |
| `tripper_recon/orchestrators.py` | four entry points, fan-out, envelopes, coverage, adjudication calls |
| `tripper_recon/providers/` | one module per third party. No shared state, no orchestrator types |
| `tripper_recon/reporting/console.py` | every rich renderer. Reads `result.data`, imports nothing above it |
| `tripper_recon/types/models.py` | the typed result surface described in section 9 |
| `tripper_recon/types/indicators.py` | `detect()`, the pure classifier behind `check` and `bulk` |
| `tripper_recon/utils/http.py` | the client factory, the egress allowlist, the concurrency limiter |
| `tripper_recon/utils/backoff.py` | the retry policy every provider uses |
| `tripper_recon/utils/dns.py` | the one sanctioned resolution site |
| `tripper_recon/utils/urls.py` | URL parsing, anomaly detection, redirect-chain provenance |
| `tripper_recon/utils/refang.py` | turning `evil[.]com` back into something the tool can look up |
| `tripper_recon/utils/redact.py` | stripping credentials out of URLs and exception text |
| `tripper_recon/verdict/` | the scoring engine, its ruleset and its known-infrastructure catalogue |
| `tests/test_passivity.py` | the static passive-boundary gate |

Two YAML files ship inside the package and are loaded through `importlib.resources`:
`verdict/scoring.yaml` (the ruleset) and `verdict/known_infrastructure.yaml` (the allowlist
catalogue). Both are declared in `pyproject.toml` under `[tool.setuptools.package-data]`, because a
wheel that omits them produces a tool that imports fine and then refuses to adjudicate anything.

---

## 11. What is not here

State this accurately, because the first version of this project's README claimed features that
did not exist.

* **No REST API and no server.** Deleted. `tests/test_server_removed.py` keeps it deleted.
* **urlscan.io is written but not wired in.** `providers/urlscan.py` exists and is tested, and its
  host is allowlisted in both places. It is **not** in `URL_PROVIDERS` (`orchestrators.py:201`),
  which is the denominator of the URL-scope coverage ratio. Nothing calls it yet.
* **The URL scope is unscored.** `scoring.yaml` declares no signal whose `applies_to` includes
  `url`, so `_adjudicate_url` hands the engine an empty signal list and gets `INSUFFICIENT_DATA`.
  That is the true answer, not a degradation. The scope is wired so the day `url.*` signals land
  needs no change in `orchestrators.py`.
* **abuse.ch is planned, not built.** Decision Q5 in `ROADMAP.md` section 4b accepts the
  terms-of-service exposure and commits to building it in full, including bulk mode. No code for
  it exists today.
* **GreyNoise is struck**, not deferred. See the same table.
* **No `--active-dns` flag.** See section 8.2.
* **No accuracy claim for the verdict engine.** See section 7.

---

## 12. Adding things

**A provider.** Write the module against the envelope contract in section 4. Add the host to
`ALLOWED_EGRESS_HOSTS` and to `tests/test_passivity.py:ALLOWED_HOSTS` in the same commit. Add the
row to `OPSEC.md` section 2 and the entry to `PROVIDERS.md`. Add the provider name to the relevant
`*_PROVIDERS` tuple in `orchestrators.py`, which changes the coverage denominator. Wire the call
into the right wave with `_call_provider`.

**A signal.** Add the id to `SignalId` (`verdict/config.py:139`), the weight and its ceiling to
`scoring.yaml`, and the extractor to `verdict/signals.py`. Do not put a number in the Python. An
extractor handed an empty payload returns an empty list.

**A renderer.** Read `result.data`. Do not import an orchestrator. Use `no_data_text` for any
"this provider did not answer" cell, so the whole tool keeps one vocabulary for absence.

**A subcommand.** Parse in `cli.py`, orchestrate in `orchestrators.py`, render in
`reporting/console.py`. Return an exit code that matches the table in the `cli.py` module
docstring, and remember that the exit code reports whether the lookup worked, never what the
lookup found.

---

## 13. Verification

```bash
python -m pytest -q
python -m ruff check .
python -m mypy tripper_recon/
```

CI runs the same three on Python 3.10, 3.11 and 3.12, with every provider credential explicitly
unset, so a test that forgot its respx mock fails loudly instead of billing a real API key.
`docs/` is excluded from ruff, because ruff 0.16 and later rewrite Python code blocks inside
Markdown and this directory quotes source verbatim as evidence.

No test in this repo makes a network call. If you need sample output while developing, build it
with respx-mocked providers. Do not run the CLI against a real target to produce a screenshot for
a document.
