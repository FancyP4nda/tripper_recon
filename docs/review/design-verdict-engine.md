# Design: the verdict engine for `tripper_recon`

Review date: 2026-08-08. Repo: `/home/echo/dev/tripper_recon`, branch `feat/work-20260808-recon-hardening`.
Read-only review. No files were modified. `.env` was not opened.

---

## 0. The headline

The tool collects six providers' worth of evidence and then renders it. It never adjudicates.
`render_ip_analysis` (`tripper_recon/reporting/console.py:24-164`) prints VirusTotal in red when
`malicious > 0` (`console.py:78`) and AbuseIPDB in green when the confidence score is `0`
(`console.py:95`), on the same screen, with no arbitration between them. The analyst does the
correlation in their head, under time pressure, every time.

The repo contains its own best argument. `ip_example.md` is a committed real output:

```
ip_example.md:10   virustotal_detections         5/91
ip_example.md:11   virustotal_community_score    -37
ip_example.md:13   abuseipdb_reports             5
ip_example.md:14   abuseipdb_confidence_score    0%
ip_example.md:16   otx_pulse_count               50
ip_example.md:18   otx_pulse_titles              IOC Records Provided by @NextRayAI; jan2,2025 clone
                                                 Auto-generated Pulse ... by AlessandroFiori;
                                                 jan2.2025clone-Auto-generated Pulse ... by AlessandroFiori;
ip_example.md:19                                 jan 2 25 clone Auto-generated Pulse ... by AlessandroFiori;
                                                 jan 2 25 clone Auto-generated Pulse ... by AlessandroFiori
```

Three facts an analyst needs and does not get:

1. **VT and AbuseIPDB directly contradict each other.** Five VT engines flag it; AbuseIPDB has five
   reports and still assigns 0% confidence. One of them is wrong. The tool shows red and green and
   walks away.
2. **`otx_pulse_count 50` is nearly meaningless here.** Four of the five sampled titles
   (`ip_example.md:18-19`) are near-duplicate auto-generated clones from a single author. Fifty
   pulses from one bulk-importing account is one observation, not fifty.
3. **Nothing states what is missing.** If Shodan had no key, its absence is silently swallowed
   (`orchestrators.py:78`, `_should_suppress`) and the output looks identical to a Shodan answer of
   "nothing here."

Point 3 is the structural one, and it drives the whole design below.

---

## 1. Verdict taxonomy

Five states, not four. The extra state pays for itself; the argument is below.

| Verdict | Meaning | How it is reached |
|---|---|---|
| `MALICIOUS` | Affirmative, corroborated adverse evidence | Score ≥ `malicious_threshold` **and** confidence ≥ MEDIUM, **or** an escalation override fired |
| `SUSPICIOUS` | Adverse evidence present but thin, stale, single-sourced, or contradicted | Score ≥ `suspicious_threshold`; or score ≥ malicious threshold but confidence is LOW; or a contradiction demoted it |
| `NO_ADVERSE_FINDINGS` | Providers answered. None reported anything adverse | Coverage ≥ `min_coverage` **and** every answering provider returned an affirmative negative |
| `INSUFFICIENT_DATA` | Not enough of the panel answered to say anything | Coverage < `min_coverage` (default 0.5), or the only answering providers carry no decisive signal |
| `KNOWN_INFRASTRUCTURE` | Indicator is on a curated allowlist of infrastructure that is definitionally not the adversary | Suppression override fired (public resolvers, root/TLD nameservers) |

### The absent-data rule, stated so it can be enforced

> **Absence of evidence never lowers the score and never produces a clean verdict.**
> A provider that errored, was rate-limited, had no API key, or returned `not_found` contributes
> **zero points** and **reduces coverage**. It is never treated as a vote for benign.
> A clean verdict requires an *affirmative negative*: "VirusTotal has a record for this IP and 0 of
> 91 engines flag it" is evidence. "VirusTotal 404'd" is not. "VT_API_KEY is unset" is not.

The name `NO_ADVERSE_FINDINGS` rather than `BENIGN` is deliberate. `BENIGN` is a claim the tool
cannot support — six commercial feeds agreeing they have never seen an indicator is exactly what a
freshly-registered, purpose-built C2 domain looks like on day one. `NO_ADVERSE_FINDINGS` is a
statement about the panel, which is the only thing the tool actually knows. It also survives being
pasted into an incident report and read back at a review board six months later.

`KNOWN_INFRASTRUCTURE` is the only state that means "this is fine," and it is reachable only by
allowlist, never by scoring. That asymmetry is the point: the tool can earn its way *up* to
`MALICIOUS` but cannot earn its way *down* to safe.

**Console mapping** (three colours, so scanning stays fast despite five states):
red = `MALICIOUS`; yellow = `SUSPICIOUS`; grey/dim = `INSUFFICIENT_DATA`; green =
`NO_ADVERSE_FINDINGS` and `KNOWN_INFRASTRUCTURE`.

**Tradeoff, stated honestly:** five states is more taxonomy than a rushed analyst wants. The
alternative — folding `INSUFFICIENT_DATA` into `SUSPICIOUS` — is worse, because it trains analysts
to ignore yellow. The alternative of folding `KNOWN_INFRASTRUCTURE` into `NO_ADVERSE_FINDINGS`
loses the ability to say "the allowlist saved you from a false positive here," which is the line
that builds trust in the engine.

---

## 2. Scoring model

### 2.1 Shape

Additive, bounded, explainable. Each signal is a pure function of one provider's payload that emits
zero or more `Signal` objects, each carrying `points`, `max_points`, and a human-readable
`observation` string. The engine sums points, clamps to 0-100, and keeps `raw_score` so ceiling
saturation stays visible.

Explicitly rejected alternatives, with reasons:

- **Averaging across providers.** Destroys exactly the information the analyst needs. Averaging VT
  5/91 with AbuseIPDB 0% produces a number that describes neither. See §5.
- **Multiplicative / Bayesian combination.** Defensible in principle, but it requires per-provider
  likelihood ratios that this repo has no data to estimate, and it turns every score into something
  the analyst cannot re-derive on a whiteboard. Reconsider once the fixture corpus (§7) has enough
  labelled volume to fit real base rates.
- **Highest-single-signal ("max") scoring.** Cannot express corroboration, which is the main thing
  a six-provider panel buys you.

### 2.2 IP signal table

Every number below is a **starting value written into `scoring.yaml`, not a constant in Python**
(see §6). They are informed guesses to be tuned against the corpus in §7, and the report of record
must say so.

| Signal id | Provider | Max pts | Reasoning for the weight |
|---|---:|---:|---|
| `vt.weighted_detections` | VirusTotal | 35 | Broadest engine panel available; weighted, not raw (§2.4). Highest single weight because it is the only signal with dozens of semi-independent contributors, but capped below 50 so it can never reach `MALICIOUS` alone. |
| `abuseipdb.confidence` | AbuseIPDB | 25 | Human-reported abuse with a vendor-computed confidence that already discounts single-reporter noise. Second-highest because it is behaviourally grounded (someone was actually attacked) rather than signature-derived. |
| `abuseipdb.volume_recency` | AbuseIPDB | 10 | Report count and recency **decayed** — 200 reports last week is a different object than 200 reports in 2019. Small weight because it is largely redundant with the confidence score; it exists to separate active from historical. **Blocked, see §3.** |
| `otx.pulse_quality` | OTX | 15 | Community threat-intel corroboration, after deduplication and author-diversity correction (§2.5). Modest weight: OTX quality varies enormously and much of it re-ingests other feeds. |
| `shodan.exposure` | Shodan | 10 | Exposed services describe *what the host is*, not *whether it is hostile*. **Ceiling-only signal:** it can push `NO_ADVERSE_FINDINGS` → `SUSPICIOUS` but by config it can never contribute to a `MALICIOUS` verdict on its own. An exposed RDP box is a risk, not a threat. |
| `asn.reputation` | ipinfo + Cloudflare Radar + CAIDA | 10 | Bulletproof-hosting ASNs are a genuine prior. Deliberately small: ASN-level guilt-by-association is where naive scorers manufacture their false positives, and hosting ASNs contain both the C2 and the victim. |
| `vt.community_reputation` | VirusTotal `reputation` | 5 | The `-37` at `ip_example.md:11`. Crowd-sourced, gameable, unversioned. Directional colour only. |
| `asn.bgp_incidents` | Cloudflare Radar | 5 | Hijack/leak involvement as hijacker (`cloudflare_rest.py:33`) is weak evidence of an ASN that tolerates abuse. Note the provider already distinguishes hijacker from victim — score only the hijacker count. |

### 2.3 Domain-additional signals

| Signal id | Provider | Max pts | Reasoning |
|---|---:|---:|---|
| `domain.age` | VT whois (`virustotal.py:58-59`) | 15 | The highest-value single domain signal in phishing triage. Age bands, not a curve: <7d = 15, <30d = 10, <90d = 5, ≥1y = 0. Never negative — an old domain is not clean, it is compromised-eligible. |
| `vt.categories` | VT `categories` (`virustotal.py:55`) | 10 | Vendor categorisation hitting malware/phishing/spam is a direct adverse label from a named vendor. |
| `cert.anomaly` | VT `last_https_certificate` (`virustotal.py:62-95`) | 10 | Composite: validity window < 90 days combined with a domain younger than the cert issuance; subject CN not matching the queried domain; self-signed issuer; expired-but-serving. Each sub-check emits its own `Signal` so the console can name which one fired. |
| `otx.malware_count` | OTX (`otx.py:59`) | 5 | Already collected for domains only. Direct malware association. |

Domain verdict is computed at two levels — the domain itself, and each resolved IP — and they are
**not merged into one number**. A phishing site on Cloudflare produces a `MALICIOUS` domain and a
`KNOWN_INFRASTRUCTURE` IP, and both statements are true. The console renders the domain verdict as
the banner and each IP verdict as a per-IP badge.

### 2.4 The VirusTotal noise problem — the mechanism

`5/91` is not a measurement. It is 91 measurements with a lossy aggregation applied. The fix is a
**weighted detection ratio** over the per-engine results:

```
vt_weighted = Σ w[engine] for engines returning "malicious"
            + 0.5 · Σ w[engine] for engines returning "suspicious"

points = min(35, 35 · (vt_weighted / vt_saturation))     # vt_saturation configurable, start at 8.0
```

with two config-driven guards:

- `engine_weights: {}` — default `1.0` for every engine, with per-engine overrides in
  `scoring.yaml`. Weights are **derived empirically from the fixture corpus** (§7), not asserted.
  I am deliberately not naming specific "low-quality" engines in this document: I have no measured
  basis for such a list, and shipping an unsourced denylist of named vendors is both wrong and a
  liability. The mechanism is the deliverable; the table is filled in by measurement.
- `high_confidence_engines: [...]` — a small named set, also corpus-derived. A `MALICIOUS` verdict
  driven by VT alone requires at least one hit from this set. Without it, VT tops out at
  `SUSPICIOUS`. This is the rule that makes "a handful of low-quality engines flagged it" render as
  yellow instead of red.

The `Signal.observation` string must name the engines: `"VT: 5/91 malicious (weighted 2.1/8.0); no
high-confidence engine flagged"`. That sentence is what goes into the incident report, and it is
defensible in a way that `5/91` is not.

**Prerequisite (blocking):** `vt_ip_summary` keeps only `last_analysis_stats`
(`tripper_recon/providers/virustotal.py:26-35`) and discards `last_analysis_results`. Per-engine
weighting is therefore impossible for IPs today. `vt_domain_summary` already retains it as
`vt_security_results` (`virustotal.py:60, 81`) — and never renders it. Extending `vt_ip_summary` to
return the same field is a one-line change and unblocks the highest-weight signal in the model.

### 2.5 The OTX pulse-count problem — the mechanism

`otx_pulse_count` (`otx.py:29`) counts pulses, and `ip_example.md:16-19` shows why that is the
wrong unit. Replace it with a quality-adjusted count:

```
effective_pulses = Σ over pulses of:
      author_diversity_factor        # 1/n for the n-th pulse from the same author, harmonic decay
    · recency_factor                 # 1.0 <90d, 0.6 <1y, 0.25 older, from pulse.modified
    · title_novelty_factor           # 0.25 if title near-duplicates an already-counted pulse
```

Applied to the `ip_example.md` case, four clone pulses from `AlessandroFiori` collapse toward the
weight of one, and being a year old (`ip_example.md:18`, "CREATED 1 YEAR AGO") halves it again.
`50` becomes something like `3`, and the signal correctly stops shouting.

**Prerequisite (blocking):** `otx_ip_pulses` returns only the count and the first five titles
(`otx.py:29-31`). Author, `created`, `modified`, `TLP`, and subscriber count are all discarded.
Retain a per-pulse record — `{id, name, author_name, created, modified, TLP}` — for the first N
pulses. Without it, none of the above is computable.

---

## 3. Data the engine needs that the providers currently throw away

These are cheap collection changes, each blocking a signal above. All are additional fields on
responses the tool already fetches — no new API calls, no new cost, no change to the passive
posture.

| Field | Where dropped | Unblocks |
|---|---|---|
| `last_analysis_results` on IPs | `providers/virustotal.py:26-35` | `vt.weighted_detections` (35 pts — the largest signal) |
| `lastReportedAt` | `providers/abuseipdb.py:29-32` | `abuseipdb.volume_recency`; all recency decay |
| `isWhitelisted` | `providers/abuseipdb.py:29-32` | A vendor-supplied suppression override (§4) |
| `usageType`, `isTor` | `providers/abuseipdb.py:29-32` | Tor exit / hosting-vs-residential context, which changes what a verdict *means* |
| `numDistinctUsers` | `providers/abuseipdb.py:29-32` | Reporter-diversity correction; one angry reporter filing 200 times is one observation |
| pulse `author_name` / `created` / `modified` | `providers/otx.py:29-31` | `otx.pulse_quality` in full |
| Shodan `vulns`, per-service `product`/`version` | `providers/shodan_api.py:29` (keeps ports/org/tags/cpe only) | Exposure severity rather than a flat port count |

Also note `maxAgeInDays=365` is hard-coded at `providers/abuseipdb.py:23`. That is a scoring
parameter wearing a provider-module costume; it belongs in `scoring.yaml`.

---

## 4. Hard overrides

Overrides are evaluated **before and after** scoring and are always recorded in the verdict object
with a rule id and a source-list version, so the analyst can defend the call and the maintainer can
audit it later.

### 4.1 Suppression — and the distinction that matters

**Tier A — absolute allowlist → `KNOWN_INFRASTRUCTURE`, scoring short-circuited.**
Public recursive resolvers (Google, Cloudflare, Quad9, OpenDNS), root and TLD nameservers, and
RFC-designated special-use ranges. These carry permanent nonzero VT and AbuseIPDB residue from
DNS-tunnelling and scanning reports. A SOC tool that returns `MALICIOUS` for `1.1.1.1` even once is
finished — the analyst stops believing every other verdict it ever produces. This tier is worth
being blunt about.

**Tier B — CDN / cloud ranges → *cap and annotate*, do NOT force benign.**
Cloudflare, AWS, GCP, Azure, Akamai, Fastly. This is where naive engines get it exactly backwards
in both directions. The correct behaviour:

- zero out `asn.reputation` and `asn.bgp_incidents` (the ASN tells you nothing about the tenant);
- zero out `shodan.exposure` (you are scoring the edge, not the origin);
- attach `attribution_warning: "shared infrastructure — this verdict does not transfer between the
  IP and the domains hosted on it"`;
- cap the **IP-level** verdict at `SUSPICIOUS`;
- leave **domain-level and URL-level** scoring completely untouched.

A phishing kit on Cloudflare Pages is real and must still render red at the domain level. Scoring
the shared IP as malicious would indict every other tenant behind it. Both halves of that sentence
are failure modes, and Tier B is the only structure that avoids both.

**Tier C — vendor-supplied suppression.** AbuseIPDB `isWhitelisted` contributes a suppression
signal (not an override) once collected. Weak, so it demotes rather than short-circuits.

Source lists must be fetched from the publishers' own machine-readable endpoints (Cloudflare
`/ips-v4`, AWS `ip-ranges.json`, GCP `cloud.json`, Azure Service Tags), cached locally with a
retrieval timestamp, and the timestamp stamped into the verdict. A stale allowlist that silently
suppresses a reassigned range is its own defect class; the timestamp is what makes it detectable.

### 4.2 Escalation

**URLhaus / ThreatFox live hit → `MALICIOUS`, confidence `HIGH`, scoring short-circuited.**
These are specific, current, actor-attributed observations with a payload hash or a C2 role behind
them. Nothing else in the panel carries that quality of evidence, and they should dominate.

> **These providers do not exist in the repo.** There is no `urlhaus.py` or `threatfox.py` under
> `tripper_recon/providers/` (directory listing verified; the ten present providers are enumerated
> in `orchestrators.py:10-23`). Both abuse.ch services offer passive lookup APIs — URLhaus
> unauthenticated, ThreatFox with a free key — and both fit the passive-only constraint cleanly
> because they are database lookups, not target contact. **Adding them is the highest
> value-per-line-of-code change available to this tool**, and it is a hard prerequisite for the
> escalation override as specified. Until they exist, the override rule is dead config.

**VT high-confidence consensus → `MALICIOUS`.** `high_confidence_engines` hits ≥
`vt_consensus_threshold` (start at 3).

**Corroboration escalation.** Adverse signals from ≥ 3 *independent provider families* (§5.2) at
above-materiality strength, even where no single one is decisive.

### 4.3 Precedence

```
Tier A allowlist  >  escalation overrides  >  Tier B cap  >  score-derived verdict
```

Tier A beating escalation is a deliberate choice for predictability: if a feed reports that a public
resolver is serving malware, the feed is wrong far more often than the resolver is compromised, and
an engine that flips on feed error is worse than one that is stubborn. **But it must not be
silent** — the conflict is emitted as a first-class `contradictions[]` entry
(`"URLhaus reports a live hit on an address in the public-resolver allowlist; allowlist applied,
verify manually"`) and sets `requires_analyst_review: true`. Being predictable and being loud are
compatible; being predictable and being quiet is not.

---

## 5. Confidence — a separate axis

Confidence answers "how much of the panel did we actually hear from, and did they agree," and it is
computed **without reference to the score**. A high score with low confidence is a real and common
state, and the analyst must be able to see it at a glance.

### 5.1 Components

```
coverage      = providers_answered / providers_applicable
```

`providers_applicable`, not `providers_configured`. A missing API key is missing coverage, not an
excuse. This directly contradicts current behaviour: `_should_suppress`
(`orchestrators.py:73-89`) discards `missing_api_key` errors entirely (`orchestrators.py:78`), so
today an unconfigured OTX is indistinguishable from an OTX that answered "nothing known." For
rendering, that suppression is reasonable. For scoring it is fatal, and the verdict engine must
read the pre-suppression payloads.

```
corroboration = count of independent provider families with adverse signals
freshness     = age of the newest adverse observation
decisiveness  = whether any single signal exceeds its own high-confidence threshold
```

### 5.2 Provider independence

Corroboration only counts if the sources are actually independent, and several of these are not.
VirusTotal and OTX both re-ingest public feeds, including abuse.ch. Two providers echoing the same
upstream is one observation wearing two hats. Declare families in config:

```yaml
provider_families:
  multiscanner:   [virustotal]
  abuse_reports:  [abuseipdb]
  community_ti:   [otx]
  curated_feeds:  [urlhaus, threatfox]     # once they exist
  exposure:       [shodan]
  network_meta:   [ipinfo, cloudflare_radar, caida, peeringdb, ripestat]
```

`corroboration` counts distinct **families**, never distinct providers. The `network_meta` family
never counts toward corroboration at all — it is context, not evidence.

### 5.3 Bands

| Band | Rule |
|---|---|
| `HIGH` | coverage ≥ 0.8 **and** corroboration ≥ 2 families **and** no unresolved contradiction |
| `MEDIUM` | coverage ≥ 0.5 **and** (corroboration ≥ 2 **or** one decisive signal) |
| `LOW` | anything else. **Forced** when coverage < 0.5, regardless of every other input |

A `MALICIOUS` score with `LOW` confidence renders as `SUSPICIOUS` with the score shown alongside, so
the analyst sees the raw strength and the discount separately.

### 5.4 The console line

The task named the target output; here it is concretely:

```
VERDICT  SUSPICIOUS   score 71/100   confidence LOW   coverage 2/6 providers answered
         ! demoted from MALICIOUS: coverage below 50%
         ! not queried: shodan (no API key), otx (no API key)
         ! failed:      abuseipdb (429), ipinfo (timeout)
         top signals:   VT 5/91 weighted 2.1/8.0 (+14)  ·  VT community score -37 (+5)
```

The "not queried" and "failed" lines are the whole point of the exercise. They are the difference
between a tool that reports what it knows and one that reports what it looked at.

---

## 6. Contradiction handling

Contradictions are surfaced, never averaged away.

### 6.1 Detection

After all signals are emitted, run pairwise rules over signals from **different families** where one
is materially adverse and the other is materially exculpatory. Starting rule set (config-driven):

| Rule id | Fires when | Analyst hint emitted |
|---|---|---|
| `vt_vs_abuseipdb` | VT weighted ≥ threshold while AbuseIPDB confidence = 0 with ≥ 1 report | "Signature detection without corroborating abuse reports — check whether VT hits are generic-heuristic" |
| `stale_vs_fresh` | Newest adverse observation > 1y while another family reports activity < 30d | "Historical badness, current activity — likely re-used or reassigned address" |
| `cdn_vs_detection` | Tier B range with adverse domain-level signals | "Detection is about the tenant, not the address — do not block the IP" |
| `age_vs_reputation` | Domain < 30d old with clean VT | "Too new to have been evaluated — absence of detection is expected, not reassuring" |

`age_vs_reputation` is worth its own mention: it converts the single most common analyst error
("VT is clean, moving on") into an explicit warning, and it costs one comparison.

### 6.2 Effect on the verdict

- Any unresolved contradiction **caps confidence at `MEDIUM`**.
- A contradiction between two signals *both* above their high-materiality threshold **demotes the
  verdict one step** and sets `requires_analyst_review: true`.
- A contradiction **never cancels points**. The score keeps its full raw value; the contradiction
  is expressed in the confidence and the review flag. Cancelling would reproduce the averaging
  failure in slower motion.

The `ip_example.md` case would render as: score in the 40s, `SUSPICIOUS`, one contradiction listed
by name, `requires_analyst_review: true`. That is the correct answer for that indicator, and it is
an answer — which is more than the tool produces today.

---

## 7. The verdict object

Add to `tripper_recon/types/models.py` (which today holds only `ApiKeys`, `Settings`, the three
query models, and `InvestigationResult` at `models.py:35-39`). Pydantic v2 is already a dependency
(`pyproject.toml:15`), so `model_dump()` gives JSON serialisation for free — the same path
`cli.py:216` and `api/server.py:28` already use.

```python
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class VerdictLabel(str, Enum):
    MALICIOUS             = "MALICIOUS"
    SUSPICIOUS            = "SUSPICIOUS"
    NO_ADVERSE_FINDINGS   = "NO_ADVERSE_FINDINGS"
    INSUFFICIENT_DATA     = "INSUFFICIENT_DATA"
    KNOWN_INFRASTRUCTURE  = "KNOWN_INFRASTRUCTURE"

class Confidence(str, Enum):
    HIGH = "HIGH"; MEDIUM = "MEDIUM"; LOW = "LOW"

class SignalDirection(str, Enum):
    ADVERSE = "adverse"; EXCULPATORY = "exculpatory"; CONTEXT = "context"

class Signal(BaseModel):
    id: str                                   # "vt.weighted_detections"
    provider: str                             # "virustotal"
    family: str                               # "multiscanner"
    direction: SignalDirection
    observation: str                          # report-pasteable sentence
    raw_value: Any = None                     # the untransformed provider value
    points: float                             # contribution after weighting
    max_points: float                         # ceiling for this signal
    weight_source: str                        # "scoring.yaml#signals.vt.weighted_detections"
    observed_at: Optional[str] = None         # ISO8601, when the provider observed it
    source_url: Optional[str] = None          # deep link the analyst can click

class ProviderStatus(BaseModel):
    provider: str
    family: str
    state: str                                # answered | not_found | error | not_configured | skipped
    detail: Optional[str] = None              # "429 Too Many Requests"
    latency_ms: Optional[int] = None

class Coverage(BaseModel):
    applicable: int
    answered: int
    ratio: float
    providers: List[ProviderStatus]

class Contradiction(BaseModel):
    rule_id: str
    summary: str
    left: str                                 # Signal.id
    right: str                                # Signal.id
    analyst_hint: str

class OverrideApplied(BaseModel):
    rule_id: str                              # "allowlist.public_resolver"
    tier: str                                 # A | B | C | escalation
    effect: str                               # "verdict_forced" | "verdict_capped" | "signal_zeroed"
    source_list: Optional[str] = None         # "cloudflare/ips-v4"
    source_retrieved_at: Optional[str] = None
    note: Optional[str] = None

class Verdict(BaseModel):
    schema_version: str = "1.0"
    indicator: str
    indicator_type: str                       # ip | domain | url | asn

    verdict: VerdictLabel
    score: int                                # 0-100, clamped
    raw_score: float                          # pre-clamp, so saturation is visible
    confidence: Confidence
    confidence_score: float                   # 0.0-1.0

    coverage: Coverage
    signals: List[Signal] = Field(default_factory=list)
    contradictions: List[Contradiction] = Field(default_factory=list)
    overrides_applied: List[OverrideApplied] = Field(default_factory=list)

    requires_analyst_review: bool = False
    attribution_warning: Optional[str] = None

    summary: str                              # one line, for the incident report
    rationale: List[str] = Field(default_factory=list)   # ordered, highest contribution first

    passive_only: bool = True
    active_collection: List[str] = Field(default_factory=list)

    ruleset_version: str                      # scoring.yaml version
    engine_version: str
    evaluated_at: str                         # ISO8601
```

Design notes on the shape:

- **`signals` is the explanation, and it is data, not prose.** The console renders the top N by
  `points`; the JSON keeps all of them. A verdict whose reasoning cannot be reconstructed from its
  own serialised form is not defensible, and defensibility was half the stated goal.
- **`source_url` per signal** is what makes the pasted incident report survive scrutiny. Every line
  the analyst writes has a click-through behind it. The links are already being constructed for
  display (`console.py:68, 84, 98, 106, 132`); this just attaches them to the evidence instead of
  to the layout.
- **`coverage.providers` carries the negative space** — every provider, including the ones that said
  nothing and why. This is the field that makes the absent-data rule auditable rather than
  aspirational.
- **`ruleset_version` on every verdict.** Two verdicts produced by different tunings are different
  claims, and a verdict in a six-month-old ticket has to be interpretable against the ruleset that
  produced it.
- **`passive_only` / `active_collection`** — see §9.

### 7.1 Wiring

- New package `tripper_recon/scoring/` — `engine.py`, `signals_ip.py`, `signals_domain.py`,
  `overrides.py`, `config.py`, `contradictions.py`.
- Add `verdict: Optional[Verdict]` as a first-class field on `InvestigationResult`
  (`models.py:35-39`), not buried in `data`. API consumers (`api/server.py:23-36`) then get it
  without digging, and the `model_dump()` calls already in place carry it automatically.
- **Call site, with a blocker.** For IPs the natural insertion is `orchestrators.py:179-190`. But
  the dict built at `orchestrators.py:180-185` flattens every failed provider to `{}`, destroying
  the `ok`/`error` distinction the engine depends on. The scorer must be handed the raw `vt`, `ipi`,
  `sh`, `ab`, `otx` payloads (`orchestrators.py:133-151`), which still carry `{"ok": False,
  "error": ...}`. Same problem in the domain path at `orchestrators.py:309-321`. This is the one
  place where the verdict engine forces a change to existing code rather than adding alongside it.
- **Console.** Verdict banner emitted *first* in `render_ip_analysis` (`console.py:24`), above the
  detail table. An analyst under time pressure reads line one; make line one the answer.
- **CLI.** `--fail-on {malicious,suspicious}` for pipeline use, and `--verdict-only` for triage
  loops over a target file (`cli.py:141-201` already handles bulk input).

---

## 8. This is a heuristic. Build it like one.

### 8.1 No magic numbers in Python

Every threshold, weight, band boundary, allowlist, engine weight, and decay constant lives in
`tripper_recon/scoring/config/scoring.yaml`, shipped in-package, overridable by
`--scoring-config PATH` and `TRIPPER_RECON_SCORING_CONFIG`. The file carries a `version:` string
that is stamped into every `Verdict.ruleset_version`. Python code takes a validated `ScoringConfig`
pydantic model and contains no literals.

The rule to enforce in review: **a scoring constant appearing in a `.py` file is a defect.** It is
worth stating that plainly, because this is exactly the code that accretes magic numbers under
deadline.

### 8.2 Pure functions

Every signal extractor has signature `(payload: dict, cfg: ScoringConfig) -> list[Signal]` and
performs no I/O. The engine composes them. This is what makes the whole thing fixture-testable
without a network, without keys, and without touching a target — which the passive constraint
requires anyway.

### 8.3 Fixture corpus

The repo currently has **no tests and no test directory** (verified: `find . -iname "*test*"`
returns nothing outside `.git`), and no test dependency in `pyproject.toml:13-20`. The corpus is
therefore greenfield, and its structure should be decided now rather than grown:

```
tests/fixtures/
  known_bad/<indicator>.json          # raw provider payloads, key-redacted
  known_good/<indicator>.json
  ambiguous/<indicator>.json
  edge/<indicator>.json               # all-providers-down, single-provider, allowlist hits
tests/golden/<indicator>.verdict.json # expected Verdict, byte-compared
```

Fixtures hold **raw provider responses**, captured once by a recording harness and committed with
credentials stripped. Two consequences worth being explicit about: (a) the corpus is a permanent
asset that survives provider outages and key expiry; (b) tests never make network calls, so the
suite cannot violate the passive constraint by accident.

Label sources: `known_bad` from URLhaus/ThreatFox confirmed entries and retired-but-documented
campaign IOCs; `known_good` from Tranco top-1k domains plus the public resolver and CDN sets;
`ambiguous` from real analyst queue samples where the ground truth was established afterwards.

### 8.4 Validation

Report per verdict class: precision, recall, F1, confusion matrix. Plus three things that matter
more operationally than F1:

1. **Zero false `MALICIOUS` on the `known_good` set. Treat as a build-breaking gate, not a metric.**
   Precision on the bad set can be traded; a single `MALICIOUS` verdict on `1.1.1.1` cannot. Wire
   it as a test that fails CI.
2. **Coverage-stratified recall.** Compute recall separately at coverage = 1.0, 0.5-0.99, and
   < 0.5. This proves the engine degrades gracefully instead of silently, and it is the number that
   answers "what happens when Shodan is down."
3. **Calibration.** Bucket verdicts by score decile and plot the observed malicious rate per
   bucket. If the 80-90 bucket is not roughly 80-90% bad, the weights are miscalibrated regardless
   of what F1 says. This is the check that tells you the score means something rather than merely
   ranking correctly.

Golden-file tests make weight changes visible: every tuning change produces a diff in
`tests/golden/`, and the PR must report the confusion-matrix delta. That workflow is the thing that
keeps a heuristic honest over years.

### 8.5 The validity threat to name out loud

**The corpus is circular by construction.** If `known_bad` is labelled from URLhaus and the scorer
reads URLhaus, measured precision is meaningless — the engine is being graded on its own answer key.
Mitigations, in order of strength:

- **Hold-one-feed-out.** Label from feed A, score with feed A excluded from the panel, report both
  the full-panel and held-out numbers. The held-out number is the real one.
- **Temporal split.** Label from feed state at time T, score against provider payloads captured at
  T−30d. Measures whether the engine would have caught it *before* the feed did, which is the
  actual operational question.
- State the residual circularity in the README next to any accuracy claim. Do not publish a
  precision figure without the held-out condition beside it.

Until the corpus exists, the engine ships with **no accuracy claim at all**. "Tuned against a
labelled corpus of N indicators, held-out precision X" is a defensible sentence. "Accurate" is not.

---

## 9. Interaction with the passive-only constraint

The verdict object must state whether any active collection contributed to it, because a verdict
built partly on active collection is a different artifact — legally, operationally, and in terms of
what it told the adversary.

`investigate_domain` calls `resolve_domain` (`orchestrators.py:247-248`), which uses
`socket.getaddrinfo` via the system resolver (`utils/dns.py:8-23`). That is a recursive lookup that
terminates at the target's own authoritative nameservers. The IPs it returns are merged with the VT
passive-DNS set (`orchestrators.py:249-251`) and then drive per-IP enrichment and scoring
(`orchestrators.py:253-321`). So today, an actively-obtained artifact can be the basis of a verdict,
and nothing in the output says so.

Requirements on the engine:

- Set `passive_only: false` and `active_collection: ["system_dns_resolution"]` whenever the
  resolver path contributed an IP that fed a signal.
- Support a `--passive-only` mode in which `resolve_domain` is skipped and IPs come solely from VT
  passive DNS (`virustotal.py:80` → `orchestrators.py:227-235`). Coverage drops accordingly, and the
  verdict must show the drop rather than absorb it — which is exactly what the coverage model in
  §5.1 already does.
- Never let `passive_only` be inferred at render time. It is a property of how the evidence was
  obtained and belongs in the object.

Whether the resolver behaviour should change at all is outside this document's scope; whether the
verdict must *disclose* it is not, and it must.

---

## 10. Recommended build order

Sequenced so each step ships something usable, and the cheap unblockers come first.

| # | Step | Effort | Ships |
|---|---|---|---|
| 1 | Retain the dropped provider fields (§3) | S | Nothing visible, unblocks everything |
| 2 | `Verdict` models + `scoring.yaml` + pure-function scaffold | M | JSON shape frozen early |
| 3 | Coverage + provider-status tracking, no scoring | S | "2 of 6 answered" — value on its own |
| 4 | IP signals + score + confidence + console banner | M | The feature |
| 5 | Overrides, Tier A and B (§4.1) | M | Kills the class of false positive that destroys trust |
| 6 | Add URLhaus + ThreatFox providers, wire escalation | M | Largest single accuracy gain available |
| 7 | Contradiction rules (§6) | S | The `ip_example.md` case renders correctly |
| 8 | Domain signals: age, categories, cert (§2.3) | M | Phishing triage |
| 9 | Fixture corpus + golden tests + known-good FP gate | L | Makes it defensible |
| 10 | Corpus-derived engine weights, held-out validation | L | Makes it accurate |

Steps 1-4 are the minimum viable verdict. Steps 5-7 are what make it trustworthy. Steps 9-10 are
what let anyone state an accuracy number without overclaiming.

---

## 11. Uncertainties — things I could not settle from the repo

Stated rather than guessed:

- **Which VT engines are low-quality.** Not determinable from this codebase, and I will not assert a
  vendor denylist without measurement. §2.4 specifies the mechanism; §7/§8.4 specify how the table
  gets filled. Settled by: building the corpus and computing per-engine precision.
- **Whether the proposed starting weights are right.** They are informed priors, not measurements.
  Settled by: §8.4 calibration against the labelled corpus. Anyone shipping them as truth before
  that is overclaiming.
- **The exact `not_found` semantics per provider.** VT returns 404 for unseen indicators
  (`virustotal.py:21, 48`) and OTX likewise (`otx.py:21, 45`), and both are mapped to
  `{"ok": False, "error": "not_found"}`. Whether AbuseIPDB and Shodan `not_found` mean "never
  observed" (an affirmative negative, worth coverage credit) or "no record retained" (not evidence)
  affects the coverage denominator. Settled by: reading each provider's API documentation on the
  404/empty semantics, then encoding the answer per provider in `scoring.yaml`.
- **Whether the ASN-reputation signal is worth its 10 points.** ASN-level guilt-by-association is
  the most likely source of systematic bias in the model. Settled by: an ablation on the corpus —
  measure precision/recall with the signal at 10, 5, and 0, and keep whichever wins. If it does not
  earn its place, delete it; a signal that cannot beat zero is worse than absent because it looks
  like reasoning.
