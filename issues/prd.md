# Product Requirements Document: Passive-First Tripper Recon Refactor

## 1. Executive Summary
- **Target Persona:** Security analysts, CISO reporting users, and AI agents that need deterministic, non-contact OSINT enrichment for IPs, domains, URLs, and ASNs.
- **Core Problem:** `tripper_recon` currently exposes legacy `ok/data/errors` results, mixes human and machine output paths, and performs live DNS resolution during domain investigation. This makes passive use ambiguous and unsafe for AI callers that must avoid target-controlled contact.
- **Business Goal:** Convert `tripper_recon` into a passive-first investigation tool whose default mode never touches target-controlled infrastructure, whose CLI/API share one result contract, and whose JSON/JSONL output can be consumed reliably by downstream automation.

## 2. Agentic Execution Sizing
*Notice to orchestrators: The features below have been explicitly scoped into phases representing 5-15 minutes of autonomous execution time to prevent context saturation.*

### Phase 1: Contract and Guardrails
Introduce mode, capability, profile, and schema v1 models; route all provider execution through enforceable capability checks; and remove live DNS from the default domain path. This phase should produce a stable result object even before provider expansion.

### Phase 2: Interface Alignment
Update the CLI and FastAPI routes to accept `mode`, `profile`, `include_raw`, requested providers, profile completeness, and cache controls. Ensure machine modes emit JSON or JSONL on stdout/body only, while logs and summaries go to stderr or explicit summary channels.

### Phase 3: Evidence, Scoring, and Cache
Normalize provider evidence, add deterministic scoring with evidence-linked reasons, add sanitized raw evidence controls, and introduce a SQLite TTL cache keyed by normalized target, target type, mode, provider, and schema version.

### Phase 4: Verification Harness
Add schema snapshots, mocked provider coverage, non-contact tests, redaction tests, cache tests, and deterministic scoring tests. Live provider tests remain opt-in via environment variables only.

## 3. BDD User Stories

**Feature:** Passive Mode Capability Enforcement  
**Scenario:** Default domain investigation blocks live DNS  
*   **Given** the caller investigates `example.com` without passing a mode  
*   **And** the provider registry marks local DNS resolution as `analyst_resolver`  
*   **When** the domain investigation service executes  
*   **Then** no function in `tripper_recon.utils.dns` must be called  
*   **And** the result must include `mode` set to `passive`.

**Feature:** Explicit Resolver Passive Mode  
**Scenario:** Analyst opts into live DNS only  
*   **Given** the caller investigates `example.com` with `mode=resolver-passive`  
*   **When** domain enrichment requires IP relationships  
*   **Then** analyst-controlled DNS or PTR resolution may execute  
*   **And** HTTP, TLS, redirects, screenshots, crawling, sandbox submissions, and port probing must remain blocked.

**Feature:** Disallowed Explicit Provider Failure  
**Scenario:** Caller explicitly requests a provider that is not allowed in passive mode  
*   **Given** `urlscan_submit` is registered with capability `brokered_active`  
*   **And** the caller passes `mode=passive` and explicitly requests `urlscan_submit`  
*   **When** the investigation request is validated  
*   **Then** the service must return `execution_status=failed`  
*   **And** `errors` must identify the provider and the mode/capability mismatch.

**Feature:** Disallowed Default Provider Skip  
**Scenario:** Default profile includes a provider unavailable under the selected mode  
*   **Given** a default provider set contains a mode-disallowed provider  
*   **And** the caller did not explicitly request that provider  
*   **When** a passive investigation runs  
*   **Then** the provider must not execute  
*   **And** `provider_status` must record the provider as skipped with a structured reason.

**Feature:** Schema V1 Machine Output  
**Scenario:** CLI emits JSON for a single IP target  
*   **Given** the caller runs `tripper-recon ip 8.8.8.8 --mode passive --profile best_effort --json`  
*   **When** the command completes  
*   **Then** stdout must contain exactly one valid JSON object  
*   **And** the object must include `schema_version`, `target_type`, `input`, `normalized_target`, `mode`, `profile`, `execution_status`, `verdict`, `score`, `confidence`, `findings`, `relationships`, `provider_status`, `evidence`, `cache`, `errors`, and `warnings`  
*   **And** the object must not include top-level `ok`.

**Feature:** JSONL Batch Output  
**Scenario:** Mixed indicator batch investigation  
*   **Given** an input file contains one IP, one domain, one URL, and one ASN  
*   **When** the caller runs `tripper-recon investigate INPUT_FILE --mode passive --profile best_effort --json`  
*   **Then** stdout must contain one complete schema v1 result object per line  
*   **And** batch summaries must not be mixed into stdout.

**Feature:** Typed Command Validation  
**Scenario:** Domain command receives a URL  
*   **Given** the caller runs `tripper-recon domain https://example.com/path --mode passive --json`  
*   **When** target validation runs  
*   **Then** the command must reject the input as the wrong target type  
*   **And** it must not silently coerce the URL into a domain.

**Feature:** URL Passive Investigation  
**Scenario:** URL has no prior passive observations  
*   **Given** a URL target has no matching read-only provider observations  
*   **When** the caller runs a passive URL investigation  
*   **Then** the result must set `execution_status=completed` and `verdict=unknown`  
*   **And** the service must not submit, fetch, resolve, render, or screenshot the URL.

**Feature:** Sanitized Raw Evidence  
**Scenario:** Caller requests raw provider evidence  
*   **Given** provider payloads contain request headers and query parameters named `token`, `key`, `api_key`, or `apikey`  
*   **When** the caller passes `include_raw=true`  
*   **Then** emitted raw evidence must omit request headers  
*   **And** sensitive query parameters and body fields must be redacted  
*   **And** oversized payloads must be truncated with truncation metadata.

**Feature:** Deterministic Verdict Scoring  
**Scenario:** Context-only evidence is present  
*   **Given** provider evidence contains only context and relationship signals  
*   **And** no reputation evidence supports maliciousness  
*   **When** scoring runs  
*   **Then** the verdict must not be `malicious`  
*   **And** the scoring reasons must reference evidence IDs used in the calculation.

**Feature:** Cache Disclosure  
**Scenario:** Cached provider evidence is reused  
*   **Given** a cached provider observation exists for the normalized target, target type, mode, provider, and schema version  
*   **When** the same investigation runs before TTL expiry  
*   **Then** provider execution may be skipped  
*   **And** the result must disclose cache hit status and retrieval timestamps.

**Feature:** Profile Completeness  
**Scenario:** CISO profile minimum evidence is unavailable  
*   **Given** the caller uses `profile=ciso_daily` with `require_profile_complete=true`  
*   **And** the configured minimum source coverage for the target type is unavailable  
*   **When** the investigation completes provider selection  
*   **Then** the result must fail with a structured profile completeness error.

## 4. Technical Constants and Constraints
- **Supported APIs:** Existing providers under `tripper_recon.providers` including VirusTotal, OTX, Shodan, AbuseIPDB, IPinfo, Cloudflare Radar/REST, RIPEstat, CAIDA, and PeeringDB. First-slice provider expansion is out of scope; later candidates are crt.sh, GreyNoise, URLhaus local feed, ip-api fallback, and urlscan search-only only if proven non-submitting.
- **Security Protocols:** Default `passive` mode permits only provider reads of already-existing observations. `resolver-passive` permits provider observations plus analyst-controlled DNS/PTR only. API keys, tokens, credentials, sensitive query parameters, and request headers must be redacted from logs, errors, cache metadata, JSON output, and raw evidence.
- **Prohibited Libraries:** No browser automation, screenshot, crawler, port scanner, TLS probing, sandbox submission, or active target-contact libraries may be introduced for schema v1 passive workflows. SQLite from the Python standard library is allowed for the cache; new third-party dependencies require justification in `pyproject.toml`.

## 5. Machine Learning / AI Parameters
- **Tolerable Hallucination Rate:** 0% for schema fields, provider capability classifications, and mode enforcement decisions. Missing baseline data: no measured model hallucination benchmark exists for downstream AI callers.
- **Precision Target:** Deterministic exact-match schema validation for machine-readable output. Numeric precision for verdict quality is not yet baselined and must not be invented.
- **Max Latency Under Load (p95):** No baseline exists. The implementation must preserve bounded concurrency and shared `httpx.AsyncClient` usage per run/request scope before latency targets are established.

## 6. Implementation Decisions
- Keep one public CLI and one FastAPI service surface, but split investigation logic internally by target type: IP, domain, URL, and ASN.
- Add central enums/models for `Mode`, `Capability`, provider registry entries, provider profiles, provider statuses, evidence, relationships, cache metadata, scoring, and schema v1 results.
- Replace top-level `ok` with `execution_status=completed|partial|failed` and `verdict=malicious|suspicious|benign_contextual|unknown`.
- Treat missing provider credentials and optional provider outages as partial coverage under `best_effort`, recorded in `provider_status`.
- Add `ciso_daily` as a report-grade profile with target-type-specific minimum evidence requirements; fail only when `require_profile_complete` is set.
- Preserve human console output, but render it from the normalized schema v1 result model rather than maintaining separate ad hoc formatting contracts.
- CLI machine modes must use stdout only for JSON or JSONL. Logs, diagnostics, and batch summaries must use stderr or an explicit file.
- Batch `investigate` is the primary mixed-indicator path. Typed commands remain strict and reject wrong target types.
- URL investigation must normalize the URL, query URL-specific read-only observations when available, extract domain relationships, enrich only passively discovered related indicators, and preserve provenance.
- Cache keys must include normalized target, target type, mode, provider, and schema version. Output must disclose cache hits, `retrieved_at`, and provider-native timestamps such as `observed_at`, `first_seen`, or `last_seen` when available.
- Apply rate limiting around awaited provider calls and use bounded concurrency for batch and related-indicator enrichment.
- Defer Tor relay/exit identification from v1.

## 7. Testing Decisions
- Add mocked provider tests for IP, domain, URL, and ASN investigations.
- Add schema snapshot tests for single-result JSON and batch JSONL.
- Add non-contact tests proving `mode=passive` never calls local DNS/PTR, HTTP/TLS target-origin code, screenshots, sandbox submissions, or port probing.
- Add `resolver-passive` tests proving DNS/PTR runs only when explicitly selected.
- Add provider capability tests proving default disallowed providers are skipped and explicitly requested disallowed providers fail.
- Add stdout/stderr separation tests for CLI machine modes.
- Add redaction tests for API keys, tokens, credentials, request headers, sensitive query parameters, body fields, errors, logs, cache metadata, and raw evidence.
- Add cache tests for hit/miss behavior, TTL expiry, provider-specific TTLs, evidence-class defaults, and schema-version separation.
- Add deterministic scoring tests for fixed provider inputs, including a case where context and relationship evidence cannot directly create a malicious verdict.
- Add target validation tests proving typed commands reject wrong target types and `investigate` accepts mixed indicators.
- Live provider tests must be opt-in only via environment variables.

## 8. Out of Scope
- Adding new providers in the first implementation slice.
- Active or brokered-active URL submission, sandboxing, crawling, screenshots, redirects, HTTP HEAD/GET, TLS certificate grabs, or port probing.
- Tor relay and exit-node identification.
- Backward compatibility beyond a possible one-release `--legacy-json` escape hatch.
- Submitting artifacts to GitHub, Jira, or other external systems.
- Establishing production p95 latency or verdict precision targets before baseline measurements exist.

## 9. Further Notes
- Repository grounding found the current package under `tripper_recon/tripper_recon`, with public entry points in `cli.py` and `api/server.py`, shared legacy models in `types/models.py`, orchestration in `orchestrators.py`, and direct DNS helpers in `utils/dns.py`.
- The current domain orchestrator imports and calls `resolve_domain(domain)`, so removing live DNS from passive mode is a required first-slice change rather than a future optimization.
- The current CLI uses Rich console output for JSON; schema v1 should ensure machine output is valid without log or formatting contamination.
- Existing `pyproject.toml` declares runtime dependencies but no test framework. Add test dependencies deliberately as part of the verification harness.
- Missing baseline metrics are intentional dependencies, not product assumptions.
