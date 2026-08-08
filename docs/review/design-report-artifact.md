# Tripper Recon — The Report Artifact

Design review, read-only. Target: `/home/echo/dev/tripper_recon` @ `feat/work-20260808-recon-hardening` (`de277f4`).

Scope: what the tool should **emit** so an analyst can paste it into a ticket, a case file, or a hunt writeup — and defend it six weeks later. Every claim below is anchored to `file:line`. Where I could not settle a question by reading, I say so and name the test.

---

## 0. Headline

**The tool currently has no report artifact at all.** It has a terminal renderer. `outputs/` holds one byte (`outputs/.gitkeep`) and is written by exactly one code path — `--prefixes-out`, an ASN prefix dump (`tripper_recon/cli.py:342-374`). Nothing in the codebase records a timestamp, a run identifier, a schema version, a provider query time, a raw response, or a hash. I grepped for all of them and the only hits are VirusTotal's certificate thumbprint field (`tripper_recon/providers/virustotal.py:67-69,87`) and IPinfo's `timezone` string (`tripper_recon/providers/ipinfo.py:49`) — neither is a report timestamp.

That is the gap. The intent is visible (`outputs/`, `ip_example.md`, `ASN_Example.md`), the mechanism is absent.

Two things must be built before any export format is worth arguing about:

1. **An evidence envelope** at the provider boundary that captures `queried_at`, HTTP status, and a hash of the raw response. Every provider currently discards the raw body and returns a hand-picked dict (`providers/virustotal.py:28-35` keeps 3 fields of a ~40-field object; `providers/shodan_api.py:22-29` keeps 4). Once discarded, integrity hashing and offline regeneration are both impossible. This is the load-bearing change, and it is the *only* one that must happen at the provider layer.
2. **A separated output stream.** `console.print_json` (`cli.py:196,216,323`) and the structured logger (`utils/logging.py:42`, `sys.stdout.write`) both write to **stdout**. Any log line emitted during a run interleaves with the JSON document. `tripper-recon ip 1.2.3.4 -o json | jq` is broken the moment the logger fires at INFO — and `log["error"]` fires on any provider failure (`cli.py:161,172`). SIEM/SOAR ingestion of the current JSON is not viable until logs move to stderr.

Everything else in this document is layered on those two.

---

## 1. What exists today, precisely

### 1.1 The `outputs/` directory and the example files

`outputs/` contains only `.gitkeep` (1 byte). It is gitignored (`.gitignore:80`). The only writer is:

```
cli.py:298-301   _default_output_dir()  ->  Path(__file__).resolve().parent.parent / "outputs"
cli.py:360-374   --prefixes-out, bare filename lands in that dir
```

**Defect (grounded):** `_default_output_dir()` resolves relative to the *installed package location*, not the working directory. `pyproject.toml:22-24` installs `tripper-recon` as a console script, so after `pip install .` a bare `--prefixes-out foo.txt` writes into `site-packages/outputs/`, which the analyst will never find and which may not be writable. It should resolve against `Path.cwd()` or an explicit `--case-dir`.

**The example files are evidence of intent, and they are also broken as evidence:**

- `ip_example.md` and `ASN_Example.md` are **byte-identical** (`md5 d61cbd5f...` for both). `ASN_Example.md` is titled `--- IP lookup for 123.123.123.123 ---` at line 1. It is a mislabelled copy, not an ASN example.
- `domain_example.md` is **0 bytes** (`md5 d41d8cd9...`, the empty-file hash).
- Neither file is markdown. They are raw terminal captures with `.md` extensions — no headings, no tables, no front matter. Pasted into a ticket they render as one undifferentiated paragraph unless fenced.
- All three are untracked (`git status`: `?? ip_example.md` etc.), so they are not even a committed contract.

The intent reads clearly as "the output should be dropped into a document." The artifact does not yet do that.

### 1.2 The renderer is the model

`reporting/console.py` is the only place investigation data is shaped for a human, and it does the shaping inline with the rendering. Every fact selection, ordering, colour, and truncation decision lives inside `rich` calls:

- verdict colouring: `console.py:78` (`vt_color = "red" if malicious > 0 else "green"`), `console.py:95`
- field selection and order: `console.py:39-132`
- truncation: `console.py:116-129` (ports), `console.py:109` (OTX titles, hard-capped at 5)

There is no intermediate report object. Any second output format written against `console.py` would have to reimplement all of it. The fix is a `Report` model (§3) that both the console renderer and every exporter consume.

### 1.3 The data model carries no metadata

```
types/models.py:35-39
class InvestigationResult(BaseModel):
    ok: bool
    data: Dict[str, Any]
    warnings: List[str]
    errors: List[str]
```

`data` is untyped `Dict[str, Any]`. The FastAPI server returns this verbatim (`api/server.py:28,36,44`), so any SOAR integration is binding to an undocumented, unversioned, freely-mutable dict. There is no schema to validate against and no version field to gate on.

### 1.4 Six specific defects that a report artifact makes visible

These matter because a report is a durable claim. A terminal panel that is slightly wrong scrolls away; a report that is slightly wrong gets attached to a ticket.

**(a) `ok: true` when every provider failed.** `investigate_ip` returns `InvestigationResult(ok=True, ...)` unconditionally at `orchestrators.py:190`, regardless of `result_errors`. `cli.py:171` tests `if not res.ok` — always false — so `succeeded += 1` at `cli.py:180` even when nothing was retrieved, and the bulk envelope reports `"ok": failed == 0` → `true` at `cli.py:189`. A report generated from a run where the network was down would assert success.

**(b) Suppressed providers are indistinguishable from clean results.** `_should_suppress` (`orchestrators.py:73-89`) silently drops missing-key and selected HTTP failures. The suppressed provider's data becomes `{}` (`orchestrators.py:180-186`), so `console.py:86` (`if abuse:`) skips the score rows — **but `console.py:98` still prints `abuseipdb_analysis_link` unconditionally.** The reader sees an AbuseIPDB link and no score, and cannot tell whether that means "0% confidence, clean" or "we never asked, no API key". Same pattern for OTX at `console.py:100-113`. This single behaviour is the strongest argument for the provenance appendix in §2.4.

**(c) Computed warnings are discarded in console mode.** `investigate_asn` builds a `warnings` list (`orchestrators.py:539-552`: `caida_failed`, `peeringdb_failed`, …) and returns it (`orchestrators.py:558`). `_cmd_asn` never reads `res.warnings` (`cli.py:322-341`). They survive only in `-o json`.

**(d) Non-deterministic ordering.** `resolve_domain` builds a `set` and returns `list(addrs)` (`utils/dns.py:12-21`). Set iteration order for strings is not stable across processes. `dedupe_preserve_order` (`validation.py:31-38`) faithfully preserves that arbitrary order into `data["ips"]` (`orchestrators.py:249-251`) and therefore into the rendered per-IP panels (`cli.py:289-293`). Two runs against the same domain produce reports whose sections are in different orders — they will not diff cleanly, which defeats the point of saving them.

**(e) `ptr` is a permanently-null field.** `orchestrators.py:254` sets `ptr = None` and nothing assigns it; `entry["ptr"]` is always `None` (`orchestrators.py:310`). `utils/dns.py:26-34` defines `reverse_ptr` and **nothing calls it** (no import in `orchestrators.py:247`, which imports only `resolve_domain`). A null `ptr` key ships in every domain JSON result. Either wire it or drop it before it becomes part of a published schema.

**(f) Staleness fields are collected and thrown away.** `virustotal.py:83` captures `vt_whois_timestamp` — never rendered anywhere. VT's `last_analysis_date` and Shodan's `last_update` are the two fields that answer "how old is this verdict?" and neither is captured at all (`virustotal.py:24-35`, `shodan_api.py:22-29` select fields explicitly and omit them). See §2.5.

---

## 2. The markdown report

### 2.1 Design constraints

- **Paste-safe.** Ticketing systems (Jira, ServiceNow, TheHive, GitHub) render a common markdown subset. Use ATX headings, pipe tables, fenced code. No HTML, no nested tables, no Unicode box-drawing (`console.py:186` uses `──>`, `console.py:205` uses `•`, `cli.py:353` uses `─────` — all fine in a terminal, all noise in a ticket).
- **Verdict first, evidence second, provenance last.** The analyst under time pressure reads the first six lines. The reviewer six weeks later reads the appendix.
- **Every fact carries its source and its age.** A fact without a provider name and a timestamp is not defensible.
- **Defanged throughout.** §2.6.

### 2.2 Template

```markdown
---
schema: tripper-recon.report/1
case_id: TR-20260808-a3f19c2e
target: 185.199.108.153
target_type: ipv4
generated_at: 2026-08-08T14:22:07Z
tool_version: 0.1.0
verdict: SUSPICIOUS
confidence: medium
---

# 185[.]199[.]108[.]153 — SUSPICIOUS (medium confidence)

**Case** `TR-20260808-a3f19c2e` · **Generated** 2026-08-08 14:22:07 UTC ·
**Providers** 4 answered / 1 failed / 1 not configured

> **Why:** VirusTotal 5/91 engines malicious (observed 2026-08-06, 2d old);
> AbuseIPDB 0% confidence over 5 reports; OTX 50 pulses.
> **Not established:** no provider attests current activity. Shodan data is 11d old.

## Verdict inputs

| Signal | Value | Provider | Observed (UTC) | Age |
|---|---|---|---|---|
| Malicious detections | 5 / 91 | virustotal | 2026-08-06T03:11:00Z | 2d 11h |
| Suspicious detections | 2 / 91 | virustotal | 2026-08-06T03:11:00Z | 2d 11h |
| Community reputation | -37 | virustotal | 2026-08-08T14:22:05Z | live |
| Abuse confidence | 0% (5 reports / 365d) | abuseipdb | 2026-08-08T14:22:05Z | live |
| Threat pulses | 50 | otx | 2026-08-08T14:22:06Z | live |

## Infrastructure

| Field | Value | Provider |
|---|---|---|
| ASN | AS4808 | ipinfo |
| AS name | China Unicom Beijing Province Network | cloudflare_radar |
| Country | CN | ipinfo |
| City | Beijing | ipinfo |
| Open ports | 53 | shodan (observed 2026-07-28T09:02:00Z, 11d) |
| Reverse DNS | *not collected* | — |

## Indicators

| Indicator | Type | Role | First seen here |
|---|---|---|---|
| `185[.]199[.]108[.]153` | ipv4-addr | target | 2026-08-08 |
| `AS4808` | autonomous-system | hosting | 2026-08-08 |
| `185.199.108.0/22` | ipv4-net | announced prefix | 2026-08-08 |

## Pivots — next-step queries (not conclusions)

See §5. Rendered as a table of runnable queries, each labelled with what it
would prove and what it would not.

## Analyst notes

<!-- free text; preserved across regeneration -->

---

## Appendix A — Provenance

| Provider | Status | Queried (UTC) | HTTP | Latency | Evidence hash (sha256/12) |
|---|---|---|---|---|---|
| virustotal | answered | 2026-08-08T14:22:05Z | 200 | 412ms | `9f2a1c04b7e8` |
| ipinfo | answered | 2026-08-08T14:22:05Z | 200 | 118ms | `c41d0e77aa02` |
| abuseipdb | answered | 2026-08-08T14:22:05Z | 200 | 203ms | `7b8e5510cc3a` |
| otx | answered | 2026-08-08T14:22:06Z | 200 | 890ms | `2ea99f31d704` |
| shodan | **failed** | 2026-08-08T14:22:05Z | 502 | 1.2s | — |
| cloudflare_radar | **not configured** | — | — | — | — |

**Not configured** means no API key was present. It is not evidence of a clean
result. Absent providers constrain the verdict; see Confidence below.

## Appendix B — Method and integrity

- Collection mode: **passive** — third-party APIs only. No connection to the target.
- Active local DNS resolution: **not performed** (target is an IP).
- Raw responses: `./evidence/TR-20260808-a3f19c2e/*.json`
- Manifest: `./evidence/TR-20260808-a3f19c2e/manifest.json` (sha256 per response)
- Bundle hash: `sha256:4c1e...` over the sorted manifest
- Regenerate offline: `tripper-recon report --from-case TR-20260808-a3f19c2e`

## Appendix C — Confidence rationale

Verdict `SUSPICIOUS` at `medium` confidence.
Raised by: VT malicious > 0 (5 engines). Lowered by: AbuseIPDB 0%,
VT analysis 2d stale, Shodan unavailable, Cloudflare Radar not configured.
Rule set: `builtin/v1`. Verdicts are heuristic aggregations of third-party
scores, not an independent determination.
```

### 2.3 Notes on the template

- **Front matter is the machine hook.** Obsidian, Hugo, and TheHive all tolerate YAML front matter; ticket systems ignore it. It makes the markdown greppable without parsing prose. This matches the operator's Obsidian workflow.
- **The `> Why:` block is the ticket comment.** If an analyst copies four lines, it should be those four. It must include the **"Not established"** half — the current tool has no vocabulary for what it *failed* to learn, and that is exactly what a reviewer challenges.
- **`Age` is a rendered column, not stored.** Store `observed_at`; compute age at render. A report regenerated from cache six weeks later must show `Age: 43d`, not the age at collection.
- **Two distinct times per fact.** `queried_at` (when we asked) and `observed_at` (when the provider saw it). For VT `observed_at` is `last_analysis_date`; for Shodan it is `last_update`; for AbuseIPDB the score is computed live so `observed_at == queried_at`. Collapsing them hides exactly the staleness the prompt asks to expose.

### 2.4 Why the provenance appendix is mandatory, not optional

Because of `orchestrators.py:73-89` (`_should_suppress`). Today, "AbuseIPDB has no key" and "AbuseIPDB says 0%" produce visually near-identical output — both show the link at `console.py:98` and no score. Appendix A is the only place that difference can be recorded. A report that cannot distinguish *clean* from *unasked* is not defensible, and an adversarial reviewer will find it immediately.

The three states are distinct and all three must be rendered:

| State | Meaning | Effect on verdict |
|---|---|---|
| `answered` | provider returned data | contributes |
| `failed` | provider was asked, errored | reduces confidence, named in output |
| `not_configured` | no credential, never asked | reduces confidence, named in output |
| `cached` | served from a prior run | contributes, age shown |

### 2.5 Timestamps

All UTC, RFC 3339 with explicit `Z`. Never local time, never naive. The current code has no `datetime` import anywhere (grep confirmed) — the only time source is `utils/logging.py:10-11`, `int(time.time() * 1000)`, epoch millis in log records. Report timestamps must be a separate concern from log timestamps.

Recommended fields:
- `generated_at` — report render time, changes on regeneration
- `collected_at` — when the run that produced the evidence started; **immutable**, carried through regeneration
- per-provider `queried_at` and `observed_at`

The distinction between `generated_at` and `collected_at` is what makes a regenerated report honest.

### 2.6 Defanging

No defanging exists anywhere (grep for `defang` returns nothing). The current output emits live URLs and bare indicators:

- `console.py:68` `https://radar.cloudflare.com/ip/{ip}` — third-party, safe to leave live
- `console.py:98,106,113,132` — same, third-party lookup links
- `cli.py:224` prints the raw target domain
- `cli.py:226,255-257,260-264` build third-party links containing the target domain in the path
- `console.py:118-121` cert `subject` / `issuer` DNs, which contain target hostnames

Rule to apply:

| Content | Treatment |
|---|---|
| Target IP, domain, URL in prose/tables | **Defang**: `185[.]199[.]108[.]153`, `evil[.]com`, `hxxps://` |
| Passive-DNS siblings, cert SANs, resolved IPs | **Defang** |
| Third-party pivot links (VT/Shodan/OTX/Radar GUI) | **Leave live** — clicking them is the intended action, and defanging them destroys the fastest path to the next step |
| JSON export | **Never defang** — machines consume it; defanging corrupts the value |

The split matters. Defanging the VirusTotal link makes the report worse; not defanging the target makes it dangerous in an email client. This must be a per-field property in the report model, not a regex pass over the finished document. A regex pass would mangle `radar.cloudflare.com/ip/1.2.3.4` and the analyst would lose the pivot.

Escalate to full defanging (including link text) when the target is a **URL** — the tool does not currently accept URL targets at all (`cli.py:386-407` defines only `ip`, `domain`, `asn` subcommands), but the README and the operator's stated goal both mention URLs, so the report model should reserve `target_type: url` now.

### 2.7 Case / run identity

Requirement: deterministic, collision-resistant, human-quotable, and stable across regeneration.

```
case_id = "TR-" + YYYYMMDD + "-" + sha256(
    canonical_target || "\n" || target_type || "\n" || collected_at_iso
)[:8]
```

Properties:
- Derived from inputs, so regenerating from cache reproduces the same id — this is what makes "regenerate offline" trustworthy.
- Date prefix sorts and greps naturally in a case directory.
- 8 hex chars is enough for one operator's case load; the full digest goes in the JSON.
- `canonical_target` means lowercased domain, compressed IPv6, ASN as bare integer. Note `cli.py:425-427` already strips an `AS` prefix from ASN input and `cli.py:205-206` normalises domains through `urlparse` — reuse both, do not reimplement.

Add a separate `run_id` (UUIDv4 or ULID) for the *execution*, distinct from `case_id` for the *investigation*. Regenerating a report gives a new `run_id` and the same `case_id`. SOAR dedupes on `case_id`; log correlation uses `run_id`.

---

## 3. The JSON schema

### 3.1 Principles

- **Versioned in the payload**, first key: `"schema": "tripper-recon.report/1"`. A SOAR playbook must be able to branch on it without a heuristic. `types/models.py:35-39` has nowhere to put this today.
- **Flat, predictable, no `Any`.** The current `data: Dict[str, Any]` (`types/models.py:37`) means each of the three commands returns a differently-shaped document (`orchestrators.py:179-186` vs `:325-329` vs `:554`). One report envelope, one shape, target-type-specific detail nested under a typed key.
- **Nulls, not omissions.** Absent keys force consumers into `if "x" in doc`. An explicit `null` plus a provenance entry saying why is unambiguous.
- **Never defanged.** §2.6.
- **Stable key ordering + sorted collections** so two runs diff cleanly. Fix `utils/dns.py:21` (§1.4d) or the diff property is unattainable.

### 3.2 Shape

```json
{
  "schema": "tripper-recon.report/1",
  "case_id": "TR-20260808-a3f19c2e",
  "run_id": "01J9X2K7QF8N3M5P0V4R6T8W1Z",
  "tool": { "name": "tripper-recon", "version": "0.1.0" },
  "target": {
    "value": "185.199.108.153",
    "type": "ipv4",
    "canonical": "185.199.108.153"
  },
  "collected_at": "2026-08-08T14:22:04Z",
  "generated_at": "2026-08-08T14:22:07Z",
  "collection_mode": "passive",
  "active_operations": [],

  "verdict": {
    "label": "suspicious",
    "confidence": "medium",
    "ruleset": "builtin/v1",
    "raised_by": ["virustotal.malicious>0"],
    "lowered_by": ["abuseipdb.confidence==0", "virustotal.stale>24h",
                   "shodan.unavailable", "cloudflare_radar.not_configured"],
    "not_established": ["current_activity", "current_open_ports"]
  },

  "signals": [
    {
      "key": "virustotal.malicious",
      "label": "Malicious detections",
      "value": 5,
      "denominator": 91,
      "unit": "engines",
      "provider": "virustotal",
      "queried_at": "2026-08-08T14:22:05Z",
      "observed_at": "2026-08-06T03:11:00Z",
      "source_ref": "evidence/virustotal.json#/data/attributes/last_analysis_stats/malicious"
    }
  ],

  "infrastructure": {
    "asn": 4808,
    "as_name": "China Unicom Beijing Province Network",
    "country": "CN",
    "city": "Beijing",
    "prefix": "185.199.108.0/22",
    "reverse_dns": null,
    "open_ports": [53]
  },

  "indicators": [
    { "value": "185.199.108.153", "type": "ipv4-addr", "role": "target" },
    { "value": "AS4808", "type": "autonomous-system", "role": "hosting" }
  ],

  "pivots": [
    {
      "id": "same-asn-neighbours",
      "rationale": "Other hosts in AS4808 with recent malicious verdicts",
      "kind": "next-step-query",
      "queries": [
        { "system": "virustotal", "query": "entity:ip asn:4808 p:5+" },
        { "system": "shodan", "query": "asn:AS4808" }
      ],
      "would_show": "clustering of malicious hosts in the same AS",
      "would_not_show": "attribution; large transit ASNs contain unrelated hosts"
    }
  ],

  "provenance": [
    {
      "provider": "virustotal",
      "status": "answered",
      "queried_at": "2026-08-08T14:22:05Z",
      "http_status": 200,
      "latency_ms": 412,
      "from_cache": false,
      "endpoint": "https://www.virustotal.com/api/v3/ip_addresses/{target}",
      "evidence_sha256": "9f2a1c04b7e8...",
      "evidence_path": "evidence/virustotal.json"
    },
    {
      "provider": "shodan",
      "status": "failed",
      "queried_at": "2026-08-08T14:22:05Z",
      "http_status": 502,
      "error": { "kind": "http_error", "message": "Bad Gateway" },
      "evidence_sha256": null
    },
    {
      "provider": "cloudflare_radar",
      "status": "not_configured",
      "queried_at": null,
      "reason": "CLOUDFLARE_API_TOKEN not set"
    }
  ],

  "integrity": {
    "manifest_sha256": "4c1e...",
    "algorithm": "sha256",
    "canonicalization": "RFC8785/JCS",
    "note": "Hashes cover raw provider responses as received. They attest what was returned, not that it was true."
  },

  "errors": [],
  "warnings": ["shodan_unavailable"]
}
```

### 3.3 Notes

- `provenance[].status` is a **closed enum**: `answered | failed | not_configured | cached | skipped`. This is the schema-level fix for §1.4b. `_should_suppress` (`orchestrators.py:73-89`) then becomes a *rendering* decision, not a data-loss decision — the suppressed provider still appears in `provenance` with `not_configured`.
- `verdict.not_established` is unusual and worth keeping. It is the machine-readable form of "we did not prove this," and it is what stops a downstream playbook from treating absence of evidence as evidence of absence.
- `signals[].source_ref` is a JSON Pointer into the retained raw response. That is the chain from a number in a ticket back to the bytes a provider returned — the whole point of the integrity story.
- `collection_mode` and `active_operations` exist to make the passive constraint auditable. For a domain investigation `active_operations` would contain `{"kind": "dns_resolution", "resolver": "system", "note": "may reach target's authoritative nameservers"}` — see §7.
- **`.gitignore:85` is `*.json`.** A committed `schema/report-v1.schema.json` would be silently ignored. Whoever implements this must add a negation (`!schema/*.json`) or the schema never lands in the repo. Same trap for `.gitignore:92` `*.txt`.

### 3.4 Compatibility policy

State it once, in the README, and honour it:

- Additive changes (new optional key) — same major version.
- Removing or retyping a key — bump to `tripper-recon.report/2`, keep `/1` emitting for one minor release.
- `schema` is always the first key, always present.

`api/server.py:28,36,44` returns `res.model_dump()` today with no version marker at all. Any consumer built against it now is building against nothing.

---

## 4. STIX 2.1 and MISP — worth it?

### 4.1 Assessment

**MISP: yes, but scoped. STIX 2.1: not yet.**

The asymmetry comes from what the tool actually knows. Look at what the providers return: VT analysis stats and reputation (`virustotal.py:30-34`), AbuseIPDB report count and confidence (`abuseipdb.py:29-32`), OTX pulse count and up-to-5 titles (`otx.py:27-31`), Shodan ports/org/tags/cpe (`shodan_api.py:29`), IPinfo geo (`ipinfo.py:38-52`), plus ASN/BGP context. That is **third-party reputation aggregation**. It is not first-party observation, and the tool asserts no independent judgement.

**MISP fits that shape.** A MISP event is a flat container of typed attributes with tags — `ip-dst`, `domain`, `AS`, `port`, `x509-fingerprint-sha256` — and MISP's model explicitly accommodates "here is what these sources said." The mapping is nearly mechanical from the §3.2 `indicators` array. Effort: small once the report model exists. Value: real — MISP is what a SOC actually ingests for sharing, and the operator's target users are more likely to run MISP than a bare TAXII consumer.

**STIX 2.1 fits it badly, for four reasons:**

1. A meaningful STIX bundle wants `indicator` SDOs carrying **STIX patterns** with a confidence. The tool has no confidence model to express — the only verdict logic in the codebase is a colour ternary at `console.py:78`. Emitting `indicator` objects with fabricated confidence is worse than emitting nothing.
2. Doing it honestly means `observed-data` + `sighting`-style modelling with per-source `identity` objects and `marking-definition` for TLP — a large object graph for content that is one dictionary.
3. STIX 2.1 correctness is fiddly (deterministic UUIDv5 for SCOs, spec-version handling, bundle vs collection semantics). Getting it subtly wrong produces a bundle that imports without error and is quietly meaningless — the worst failure mode for a defensibility-focused tool.
4. Nobody has asked for it. There is no consumer in the operator's stated workflow.

**Recommendation:** implement MISP export behind `--export misp` after the report model lands. Defer STIX 2.1 until (a) a real verdict/confidence model exists and (b) a named consumer wants it. Record the deferral with the reasoning so it is a decision, not an omission.

### 4.2 If MISP is built

- Map `indicators[]` → MISP attributes; `target` gets `to_ids: false` by default. A reputation-derived indicator is context, not a detection rule, and shipping `to_ids: true` by default puts noise into someone's IDS.
- One MISP object per provider, so provenance survives the export.
- Default `distribution: 0` (your organisation only). Never default to community sharing from a tool that has no review step.
- TLP tag from a CLI flag, defaulting to `tlp:amber`.
- Same `.gitignore:85` trap applies to any `.json` fixture used to test the export.

### 4.3 Cheaper exports that beat both

Before either: **CSV of indicators** and **plain newline-delimited indicator list**. Every SIEM ingests those, they take an afternoon, and they cover the "make a watchlist out of this" use case that MISP and STIX are being asked to cover by proxy. `--prefixes-out` (`cli.py:342-374`) already demonstrates the pattern and the appetite.

---

## 5. Pivots — what the hunter needs and the responder does not

### 5.1 The distinction

An incident responder asks a **closed** question: *is this bad, and what do I write in the ticket?* They want the verdict block and the evidence table, and they want to stop reading.

A threat hunter asks an **open** one: *what else looks like this?* They want the target's properties reframed as **queries against other datasets**. The failure mode is presenting a pivot as a finding — "this IP is in AS4808, which also hosts malware, therefore this IP is malicious" is guilt by netblock, and it is how hunts go wrong.

So: **pivots are rendered as runnable queries with an explicit "what this would and would not show," never as conclusions.** Segregate them in their own section so they cannot be mistaken for evidence.

### 5.2 The data is nearly all present already

| Pivot | Source in repo | Status |
|---|---|---|
| Same-ASN neighbours | `providers/ripestat.py:37` `asn_neighbours` | fetched for ASN command, **not surfaced for IP** |
| Announced prefixes | `providers/ripestat.py:41` `announced_prefixes` | fetched, rendered at `console.py:288-311` |
| Passive DNS siblings | `virustotal.py:80` `vt_dns_records` | **fetched, partially used** — only A/AAAA extracted (`orchestrators.py:227-235`, `cli.py:248-253`); NS/MX/CNAME discarded |
| Shared certificate | `virustotal.py:87` `thumbprint_sha256` | **fetched, printed only** (`cli.py:101-106`) — never offered as a pivot |
| JARM fingerprint | `virustotal.py:96` | **fetched, printed only** (`cli.py:96-97`) |
| Shodan tags / CPE | `shodan_api.py:29` | **fetched, never rendered** — `console.py` reads only `ports` (`console.py:29`) |
| CAIDA AS rank / cone | `providers/caida.py:24-33` | fetched, rendered for ASN |
| IXP presence | `providers/peeringdb.py:38` | fetched, rendered for ASN |

Three of those — cert thumbprint, JARM, Shodan tags/CPE — are already retrieved and either printed decoratively or dropped entirely. The pivot section is mostly a *rendering* change, not a collection change. That is a strong argument for building it: high value, low new-quota cost, and no new passive-boundary risk.

### 5.3 Rendering

```markdown
## Pivots — next-step queries

These are leads, not findings. Nothing below is evidence about the target.

### Shared TLS certificate
`sha256:3f9a...c21e` (issuer: Let's Encrypt R3, valid 2026-06-01 → 2026-08-30)

| Where | Query |
|---|---|
| Censys | `services.tls.certificates.leaf_data.fingerprint_sha256:3f9a...c21e` |
| Shodan | `ssl.cert.fingerprint:3f9a...c21e` |
| crt.sh | `https://crt.sh/?q=3f9a...c21e` |

**Would show:** other hosts presenting the same leaf certificate — strong
co-tenancy or shared-operator signal.
**Would not show:** anything, if this is a shared CDN or hosting certificate.
Check the SAN count first; a cert with 200 SANs is a hosting artefact.

### Same-ASN neighbours — AS4808 (China Unicom Beijing)
CAIDA rank #142 · customer cone 1,204 ASNs · **large transit AS**

| Where | Query |
|---|---|
| VirusTotal | `entity:ip asn:4808 p:5+` |
| Shodan | `asn:AS4808 port:53` |

**Would show:** whether malicious hosts cluster in this AS.
**Would not show:** any relationship between hosts. This AS announces 1,204
ASNs of cone; co-residence here is not a link. Prefer the /24 to the AS.

### Passive DNS siblings
3 domains resolved here in the last 90 days (virustotal, observed 2026-08-06)
| Domain | Last resolved |
|---|---|
| `example-a[.]com` | 2026-08-05 |

**Would show:** hostnames sharing the infrastructure.
**Would not show:** current resolution. Passive DNS is historical by construction.
```

The self-limiting note per pivot is the part that matters, and it is what stops the same-ASN pivot from becoming the guilt-by-netblock error. Suppress or down-rank the ASN pivot automatically when `customer_cone_asns` (already collected, `caida.py:30`) exceeds a threshold — the tool knows it is a large transit AS and should say so.

### 5.4 Two flags

`--pivots` (off by default for IR speed, on for hunting) and `--pivot-depth`. An incident responder does not want three extra screens; a hunter wants nothing else.

---

## 6. Offline cache and evidence integrity

### 6.1 Case directory

```
outputs/TR-20260808-a3f19c2e/
  report.md
  report.json
  evidence/
    virustotal.json          # raw response body, unmodified
    ipinfo.json
    abuseipdb.json
    otx.json
    manifest.json            # per-file sha256, queried_at, endpoint, http status
  run.log                    # structured log lines for this run
```

Rules:
- Evidence files are **raw response bodies, byte-for-byte**. Any normalisation destroys the value of the hash.
- `manifest.json` records `{path, sha256, bytes, queried_at, endpoint_template, http_status}`. Endpoint template with `{target}` substituted out — see §6.4.
- The bundle hash is sha256 over the JCS-canonicalised manifest, so it is stable across key ordering.
- `tripper-recon report --from-case <id>` regenerates `report.md` / `report.json` from `evidence/` with **zero network calls**, updating `generated_at` and all `Age` columns while preserving `collected_at`.

### 6.2 Why this must go in `utils/http.py`, not each provider

Every provider discards the raw body. `virustotal.py:24-35` calls `r.json()`, plucks three fields, and the rest is gone. Ten providers × per-provider capture = ten places to get it wrong, and the two providers that make multiple calls (`cloudflare_rest.py:19-20` fires two requests; `peeringdb.py:16,27` fires 1+N) would need bespoke handling.

Do it once, in the HTTP layer. `create_client()` (`utils/http.py:41-51`) is the single construction point and already the right seam — an `httpx` event hook or a custom transport wrapping `AsyncHTTPTransport` (`utils/http.py:43`) can record every response: URL, status, elapsed, body bytes, sha256. Providers stay untouched.

**Caveat that must be handled:** API keys travel in query strings for Shodan (`shodan_api.py:18`, `params={"key": api_key}`) and IPinfo (`ipinfo.py:18,62`, `params={"token": token}`). A naive transport-level recorder writes those keys into `manifest.json` and into the report's `endpoint` field. **Redact query parameters and the `Authorization` / `x-apikey` / `Key` / `X-OTX-API-KEY` headers before recording** (those header names appear at `cloudflare_radar.py:31`, `virustotal.py:17`, `abuseipdb.py:17`, `otx.py:17`). Store a templated endpoint, never the sent URL. This is a hard requirement, not a nicety — evidence directories get attached to tickets.

### 6.3 Cache semantics

- Cache key: `sha256(provider || endpoint_template || canonical_target)`.
- TTL per provider, not global. Sensible defaults: IPinfo/RIPE/CAIDA/PeeringDB long (hours-to-days, this data barely moves); VT/AbuseIPDB/OTX short (minutes); Shodan medium.
- `--offline` refuses all network calls and works from cache only, failing loudly on a miss rather than silently degrading.
- `--max-age <duration>` for "use cache if fresher than this."
- Every cache hit sets `provenance[].from_cache: true` and keeps the **original** `queried_at`. A cached fact must not claim to have been queried now — that is precisely the stale-cache invisibility the report is meant to prevent.

Quota relief is the practical driver: VT's free tier is 4 requests/minute, and `investigate_domain` (`orchestrators.py:253-274`) issues one VT call **per resolved IP** in a serial loop, plus one for the domain. A domain with 8 A records burns 9 VT calls per run. Re-running the same investigation twice while writing a ticket doubles that. A cache pays for itself on day one.

### 6.4 What the hash does and does not prove

State this in the report (the template does, Appendix B). The hash proves the report was generated from the bytes stored in `evidence/`. It does **not** prove those bytes are what the provider sent, and it is not tamper-evident against someone with write access to the case directory. It is an internal consistency and non-repudiation-of-self control: it stops "the tool must have mangled it" and stops accidental drift between the saved evidence and the rendered claim. Overclaiming here would be worse than not doing it — a reader who thinks the hash is a signature will trust the report more than it deserves.

---

## 7. The passive constraint, as a reporting concern

Not my primary topic, but it lands in the report artifact and must be stated.

`utils/dns.py:8-23` `resolve_domain` calls `socket.getaddrinfo`, invoked at `orchestrators.py:248` for every domain investigation. This is an **active local resolution** that, on a cache miss, walks the delegation chain to the target's own authoritative nameservers. The prompt names this a grey area; from a reporting standpoint the resolution is straightforward:

**The report must record it.** `collection_mode: "mixed"` with an `active_operations` entry naming the DNS resolution, the resolver used, and the leak risk. A report that says `passive` while having queried the target's nameservers is a false statement in an artifact whose whole purpose is defensibility.

Two design consequences:
1. `collection_mode` is computed from what actually ran, not from a constant.
2. If a `--passive-only` flag is added (it should be), it disables `resolve_domain` and the report falls back to VT passive DNS (`vt_dns_records`, `virustotal.py:80`) alone, recording `active_operations: []` and noting the reduced IP coverage in `verdict.not_established`.

Also worth noting for the artifact: `investigate_domain` merges active and passive IPs into one list (`orchestrators.py:249`) with no marker for which is which. The report should distinguish them — "resolved now" and "seen historically" are different claims with different evidentiary weight, and one of them carries a leak.

---

## 8. Recommended sequence

1. **Logs to stderr** (`utils/logging.py:42`). One line. Unblocks every machine-readable output. Do it first.
2. **Report model** — a typed `Report` in `types/models.py` with `schema`, `case_id`, `collected_at`, `verdict`, `signals[]`, `provenance[]`, replacing `data: Dict[str, Any]` (`types/models.py:37`). Everything else consumes it.
3. **Evidence envelope in `utils/http.py`** with header/query redaction (§6.2). Enables hashing, caching, and offline regeneration together.
4. **Markdown writer + `--out` / `--case-dir`**, and fix `_default_output_dir()` (`cli.py:298-301`) to resolve against cwd.
5. **Provenance appendix**, including the `not_configured` state that `_should_suppress` (`orchestrators.py:73-89`) currently erases.
6. **Defanging** as a per-field property (§2.6).
7. **Cache + `--offline` + `--from-case`**.
8. **Pivots section** — mostly rendering of data already fetched (§5.2).
9. **MISP export**; **STIX deferred** with the reason recorded (§4.1).

Items 1-5 are the difference between "a terminal tool" and "a tool that produces a report." Items 6-9 are the difference between "a report" and "a report a hunter reaches for."

---

## 9. Things I could not settle by reading

| Question | Why it matters | How to settle it |
|---|---|---|
| Does `console.print_json` (`cli.py:196,216,323`) wrap or colour long string values when stdout is not a TTY? | If it wraps, the current JSON output is already invalid for piping, independent of the stdout-logging collision. | `tripper-recon ip <ip> -o json > /tmp/o.json 2>/dev/null; python -c "import json;json.load(open('/tmp/o.json'))"` against a target with a long OTX title. Use an IP you already have cached results for — no new live query needed. |
| Does the logger actually emit at default level during a normal successful run? | Determines whether the stdout collision is constant or only on error. `TRIPPER_RECON_LOG_LEVEL` defaults to 20/INFO (`utils/logging.py:30`, `.env.example:22`) and I found `log["info"]` only at `cli.py:370`. | Read the run output; or grep for `log["info"]` — I count one call site, so the collision may be error-path-only. Either way it is a latent break. |
| Whether VT's `last_analysis_date` and Shodan's `last_update` are present in the operator's actual API tier responses. | The entire staleness column depends on them. | Inspect one cached raw response per provider once §6 exists. Do not query live to find out. |
| Whether `resolve_domain`'s set-ordering (`utils/dns.py:21`) actually varies run-to-run in practice. | Determines whether §1.4(d) is a real diff problem or theoretical. | `for i in 1 2 3; do python -c "import asyncio,socket; ..."` on a multi-A-record domain. String set ordering is hash-seed dependent, and `PYTHONHASHSEED` is randomised per process by default — so I expect variation, but I have not run it. |
