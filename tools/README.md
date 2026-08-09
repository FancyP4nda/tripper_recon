# tools/

Operator scripts. Not part of the package, not imported by it, not exercised by the test suite
except as a subject.

| File | What it does |
|---|---|
| `calibrate.py` | Records real provider responses for labelled indicators, and replays them against the verdict engine offline (roadmap W5.9) |

---

# calibrate.py — the calibration recording harness

**Read this whole file before you run `record`. It spends your API quota and writes every
indicator you feed it into the providers' logs, under your own API keys. Those log entries cannot
be withdrawn.**

Roadmap decision 4b, W5.9: *build the recording harness; the operator runs it*. That decision is
why this is a script and not a make target. Nothing automates it, nothing schedules it, and it
refuses to run inside pytest or CI.

---

## 1. What it is for

`verdict/scoring.yaml` carries `calibration.status: unvalidated`. Every weight, threshold and
decay constant in the ruleset is an informed prior — a considered guess — and the ruleset says so
in every verdict it emits. The only way to change that is to record real provider answers for
indicators whose ground truth is already known, then replay the engine against them offline.

That gives two things:

1. **A regression corpus.** A weight change becomes a diff in replayed verdicts instead of silent
   drift.
2. **The possibility of an honest accuracy figure** — but only under the conditions in §6, and
   only after the traps in §5 have been dealt with. Recording alone validates nothing.

---

## 2. What it costs, and what it discloses

### Quota

The harness prints an exact plan before it does anything. Read it. In summary:

| Indicator kind | Provider calls | Notes |
|---|---|---|
| `ip` | 8 | one per entry in `orchestrators.IP_PROVIDERS` |
| `domain` | 5, **plus 8 per resolved address** | a domain with eight A records costs 5 + 64 |
| `url` (`--url-depth url`) | 2 | fully passive |
| `url` (`--url-depth host`) | 2 + 5 | fully passive |
| `url` (`--url-depth full`) | 2 + 5, **plus 8 per resolved address** | resolves |

The printed figure is a **floor**, never an estimate. The address count behind a domain is not
knowable before the lookup, so the harness says "and MORE" rather than inventing a number.

A 200-indicator run of mixed types is comfortably four figures of provider calls. Check your free
tiers (`docs/RATE-LIMITS.md`) against that before you confirm.

### Disclosure

Every indicator you record is sent to every provider listed for its scope. Each provider logs:

- the indicator,
- the time,
- your egress address,
- and, where a credential is configured, **your account**.

If you are recording known-bad indicators, you are telling VirusTotal, AbuseIPDB, OTX, Shodan,
abuse.ch and IPinfo that your account looked at that specific set of indicators on that specific
day. That is a normal thing for an analyst to do and a permanent thing for a log to hold. It is
also a pattern: a batch of 200 lookups in fifteen minutes reads differently from an
investigation.

### Active collection

`domain` indicators, and `url` indicators at `--url-depth full`, use the **system resolver**. A
recursive lookup terminates at the target's own nameservers, so the target learns that its name
was resolved. This is the one documented exception to the passive contract
(`docs/OPSEC.md` §3, operator decision Q2 — accepted risk).

Use `--url-depth host` to keep URL rows fully passive. There is no equivalent for `domain` rows:
resolving is what that path does.

### Credentials

Everything the harness writes is redacted through `tripper_recon/utils/redact.py` — the package's
redactor, not a second copy — and the write is then **verified** to contain no credential value.
A credential that survives redaction aborts the run rather than being cleaned up after the fact.

Two providers authenticate in the query string (Shodan `?key=`, IPinfo `?token=`) and several in
headers, so a failing request URL or a library traceback genuinely can carry a key. That is why
the verification exists.

---

## 3. Running it

Environment: the project conda env, with the package installed.

```bash
conda activate tripper
cd /path/to/tripper_recon
```

### Step 1 — build a labelled indicator set

A CSV with a header. Required columns: `indicator`, `label`, `label_source`. Optional:
`first_seen`, `note`.

```csv
indicator,label,label_source,first_seen,note
198.51.100.7,malicious,urlhaus,2026-05-01,C2 from the 2026-05 batch
hxxp://evil[.]test/payload.bin,malicious,urlhaus,2026-05-02,defanged is fine
93.184.216.34,benign,tranco,2026-01-02,top-1k
example.test,benign,operator,2026-01-02,hand-verified
```

- `label` is `malicious` or `benign` (aliases: `bad`/`good`, `known-bad`/`known-good`,
  `clean`, `positive`/`negative`).
- `label_source` is **required and must be a known feed** — `urlhaus`, `threatfox`, `abusech`,
  `virustotal`, `otx`, `abuseipdb`, `shodan`, `tranco`, `rdap`, `operator`. This is the field
  hold-one-feed-out keys off. A row whose label source you cannot name is a row you cannot
  evaluate honestly, so the harness refuses it rather than accepting a blank.
- `first_seen` is RFC 3339 (`2026-05-01` or `2026-05-01T00:00:00Z`). **Required for a temporal
  split.** A naive datetime is rejected — a split that moves by your UTC offset is the one error
  a split exists to prevent.
- Defanged indicators are refanged on the way in; both forms are recorded.
- Duplicates are collapsed and reported. Unusable rows are reported with the reason, never
  silently dropped.

**Keep this file out of the repository.** `.gitignore` ignores `*.csv` outside `tests/`, which is
the right default: a labelled list of live malware indicators is not portfolio material. Put it
somewhere like `~/calibration/labels.csv`.

### Step 2 — dry run, and read the plan

```bash
python tools/calibrate.py plan --labels ~/calibration/labels.csv
```

Contacts nothing, writes nothing. Prints exactly what `record` would print, including which
providers will be asked, which of them will log against your account, and the floor on the call
count. **This is the step where you decide.**

### Step 3 — record

```bash
python tools/calibrate.py record \
  --labels ~/calibration/labels.csv \
  --i-understand-this-spends-quota
```

Without the flag it refuses and exits 2. With the flag it prints the plan again and then asks you
to type `spend my quota` verbatim. Anything else aborts before a single request is made. A
non-interactive stdin is also refused — a process that cannot be asked has not agreed.

Useful options:

| Option | Effect |
|---|---|
| `--limit N` | record at most N new indicators this run. Start with `--limit 5` |
| `--min-interval S` | seconds between indicators (default 5). Lower it deliberately or not at all |
| `--url-depth {url,host,full}` | `url`/`host` stay fully passive; `full` resolves |
| `--fixture-dir DIR` | where fixtures land (default `tests/fixtures/calibration`) |
| `--deadline S` | wall-clock ceiling per indicator (default 120) |
| `--overwrite` | re-record indicators that already have a fixture. **Spends quota again** |

**It is resumable, and interrupting it is safe.** Each fixture is written atomically and
journalled before the next indicator is touched, so `Ctrl-C` loses at most the indicator in
flight. Re-running the same command picks up where it stopped and does not re-ask providers about
anything already recorded. An indicator that *failed* is retried, because a failure produced no
evidence and skipping it would quietly shrink the corpus.

### Step 4 — replay, offline

```bash
python tools/calibrate.py evaluate --hold-out-feed urlhaus --evaluate-after 2026-06-01
```

Contacts nothing. Reads the recorded fixtures, re-scores them through the verdict engine, and
prints a report. `--report-out PATH` also writes the full report as JSON.

---

## 4. What gets written

```
tests/fixtures/calibration/
├── MANIFEST.jsonl          # append-only journal; the resume state
└── records/
    └── ip-3f2a91c4be07d5a8.json
```

Filenames are `<scope>-<sha256(indicator)[:16]>`. The indicator is **never** used as a filename:
this harness processes attacker-authored text by design, and building a path out of it invites
traversal and control characters. The indicator lives inside the file, where it is data.

Each fixture holds the label, the label source, the raw provider payloads exactly as collected
(redacted), the coverage, and — the load-bearing field — **`recorded_at`**.

### Why `recorded_at` is the point

**A cached fact must never claim to have been queried now.** Everything downstream reports the
recording time beside the replay time, and the report states the age of the evidence it rests on.
A three-week-old cached answer presented as a fresh lookup is worse than no answer, because it
launders staleness into apparent currency. If you see a replayed verdict quoted without its
`recorded_at`, that quote is wrong.

`verdict_at_record` holds the verdict the engine reached at recording time. It is what turns a
weight change into a visible diff. It is never read as evidence.

### Committing fixtures — a decision, not a default

The default fixture directory is `tests/fixtures/calibration` for a mechanical reason:
`.gitignore` blanket-ignores `*.json` and negates exactly two paths, `tests/**/*.json` and
`schema/**/*.json`. A fixture written anywhere else is silently untracked — it looks recorded and
will never reach a remote.

Committable is not the same as "commit it". **This repository is public.** A committed fixture
publishes the indicator, the third-party payloads about it, and the fact that you investigated it
on that date. Review the diff before `git add`. Recording and publishing are separate decisions.

---

## 5. The methodological trap — read this before quoting any number

**Measuring precision on a URLhaus-labelled set against a scorer that reads URLhaus is the engine
grading its own answer key.** The corpus is circular by construction. This is not a subtle effect:
the ruleset's strongest URL-scope signal *is* the URLhaus listing, so on a URLhaus-labelled corpus
the engine will score near-perfectly and mean nothing by it.

`docs/ROADMAP.md` §4 records the same conclusion and the decision that follows from it: until a
held-out evaluation has run, the tool ships with **no accuracy claim at all**.

Two controls exist for it, and both are partial.

### Hold-one-feed-out — `--hold-out-feed FEED`

Disables the provider that supplied the labels before scoring, and evaluates only rows that feed
labelled. `--hold-out-feed urlhaus` disables the `abusech` provider entirely (URLhaus and
ThreatFox are one call, one organisation, one family) and scores those rows from what *everyone
else* said.

Disabling is done the way a genuinely un-consulted provider looks: the payload is emptied, the
status becomes `skipped`, and coverage is recomputed — so the provider stays in the denominator
and the confidence floor that follows is a true statement about the held-out run. It is not done
by zeroing a weight, which would leave the provider counted as having answered and would inflate
confidence on precisely the run whose point is to measure without it.

**Residual circularity survives this and cannot be removed here.** VirusTotal and OTX re-ingest
public feeds *including abuse.ch*. A VT detection on a held-out URLhaus row may be an echo of the
same record that supplied the label. Holding out a feed removes its direct signal, not its
downstream reflections. Every report says this, every time.

### Temporal split — `--evaluate-after DATE` / `--evaluate-before DATE`

A scorer tested on indicators it has already seen reported is measuring memory, not judgement.
Tune on rows before the cut; evaluate on rows after it. Rows with no `first_seen` are excluded
and counted, never assumed into the window.

A report with no temporal split carries a caveat saying so.

---

## 6. Reading the output — what you may and may not claim

The report leads with **the claim this run supports**, and that line is computed, not chosen.

### Precision and recall are emitted only when all three hold

1. **A feed was held out.** No hold-out means the engine may have read the same feed that supplied
   the labels.
2. **Every evaluated row was labelled by a held-out feed.** One contaminated row makes the whole
   figure circular, so one is enough to withhold it.
3. **The held-out feed actually answered somewhere in the corpus.** Holding out a provider that
   never responded removes nothing. That is not a hold-out; it only looks like one, which is
   worse.

Fail any of the three and the report prints confusion counts under the heading **"ACCURACY
WITHHELD — THE COUNTS ABOVE ARE IN-SAMPLE AGREEMENT, NOT ACCURACY"**, plus the specific reason.
This is not overridable by a flag, and that is deliberate.

### The claim, in words

> **Until a held-out evaluation has been run, the correct public claim is
> "tuned against N fixtures, not yet validated" — never "accurate".**

After a clean held-out run, this is defensible:

> "Tuned against 180 fixtures. Held-out precision 0.87, recall 0.71 with abuse.ch disabled,
> replayed from fixtures recorded 2026-08-09..2026-08-14. Residual circularity: VirusTotal and OTX
> re-ingest abuse.ch."

These are not:

> ~~"87% accurate"~~ — no such measurement exists; precision and recall are not accuracy, and
> neither is a property of the tool independent of the corpus it was measured on.
>
> ~~"Validated against a labelled corpus"~~ — unless the corpus was held out, in which case say
> which feed was held out and over how many rows.
>
> Any figure at all from a run where the report withheld one.

### Other things the report tells you

- **Coverage is not accuracy.** A row scored `INSUFFICIENT_DATA` counts against recall in the
  arithmetic; read the per-label verdict breakdown to see how many of your misses are "the panel
  did not answer" rather than "the panel was wrong". Those are different problems with different
  fixes.
- **Evidence age.** Reports over fixtures more than 30 days old carry a staleness caveat. Provider
  records move; an old fixture measures the ruleset against the world as it was on the recording
  date.
- **`hold_out_answering_fixtures`.** If this is much lower than the evaluated count, most of your
  corpus never had the held-out feed's evidence in the first place and the hold-out is doing less
  work than the headline suggests.

---

## 7. What this harness will not do

- **It does not edit `verdict/scoring.yaml`.** It never has a write path to it, and a test asserts
  the file is byte-identical after a full evaluation. Moving `calibration.status` off
  `unvalidated` is your own edit, made after reading a held-out report — and the config loader
  will reject a precision figure unless `status: validated` *and* `held_out: true`, which is a
  second, independent barrier to publishing an unearned number.
- **It does not run in pytest or CI.** `main()` refuses before parsing arguments, and
  `LiveRecorder` — the only class that reaches the network — refuses to be constructed. There is
  no flag or environment variable that disables the guard.
- **It does not tune anything.** It records and it replays. Choosing weights from what it shows
  you is a separate, deliberate act.
- **It adds no new way to reach a target.** It drives the existing orchestrators and nothing else,
  so the passive contract in `docs/OPSEC.md` §1 holds unchanged, with the resolver exception in §3
  disclosed in the plan.

---

## 8. Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | an error: an indicator failed to record, or there was nothing to evaluate |
| 2 | refused: the quota flag was missing, confirmation was not given, or an input was rejected |
| 3 | refused: the test/CI guard fired |
