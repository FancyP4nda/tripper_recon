# Contributing

Tripper Recon is a passive OSINT CLI. It looks up intelligence that third parties already
hold, and it never touches the target. Almost everything below exists to keep that sentence
true.

**The rule that outranks the rest: a claim must be true of the code as it stands.** This
repository once shipped a README that promised URL support that did not exist, HTTP/2 that was
switched off, and a config value that crashed the tool. Verify each statement against a file
before you write it. A document that overstates is worse than no document, because a reader
trusts it.

---

## 1. Setup

The maintainer uses conda only. Python 3.10 is the floor (`pyproject.toml`, `requires-python`),
and CI runs 3.10, 3.11 and 3.12.

```bash
conda create -n tripper python=3.12
conda activate tripper

git clone https://github.com/FancyP4nda/tripper_recon.git
cd tripper_recon

pip install -e ".[dev]"     # dev extra: pytest, pytest-asyncio, respx, ruff, mypy
pre-commit install
```

You do not need API keys to develop. The test suite is offline by contract and every provider
credential is unset before each test (`tests/conftest.py`, the autouse `clear_provider_env`
fixture). Three providers need no key at all, so `tripper-recon asn 15169` works against an
empty `.env`.

If you do keep a real `.env`, read [SECURITY.md](SECURITY.md) first. `load_env()` reads a `.env`
from the current directory and from the repository root (`tripper_recon/utils/env.py`), so any
CLI invocation from inside a clone spends the quota on those keys and logs the indicators under
the account that owns them.

---

## 2. The three gates

Run all three before you open a pull request. They cover what CI checks, in one pass over the
whole repository rather than CI's split between `tests/` and `tripper_recon/`.

```bash
python -m pytest -q
python -m ruff check .
python -m mypy tripper_recon/
```

When this file was written, on 2026-08-09 on `feat/work-20260808-recon-hardening`, the suite
reported 2201 passing tests, `ruff check` reported no findings, `mypy` reported no issues over 32
source files, and `ruff format --check` reported 61 files already formatted. Re-measure on your
own branch, because the test count moves as work lands. What must not move is that all three
commands report no findings. A pull request that breaks one of them needs an explanation in the
pull request body.

Two things about CI that surprise people (`.github/workflows/ci.yml`):

- The lint, format and type steps over `tripper_recon/` still carry `continue-on-error: true`.
  They were advisory because the package source predated any linter. They pass today. Removing
  the flag is a deliberate change and belongs in its own commit, not in a feature branch.
- `pytest` is blocking on every interpreter, and a separate job runs `gitleaks` over the full
  history.

### Tests never reach the network

A test that opens a socket breaks the passive-only contract in `docs/OPSEC.md`. Mock every HTTP
call with `respx`. CI blanks every provider credential, so a test that escapes its mock fails on
a missing key instead of billing a real account.

Do not produce sample output by running the CLI against a live provider. Write a scratch script
that drives the code under `respx` instead.

---

## 3. Commits, branches and pull requests

**Conventional Commits.** The types in use in this history are `feat`, `fix`, `docs`, `chore`,
`refactor`, `style` and `test`.

**Branch names.** New work uses `<type>/work-YYYYMMDD-<description>`, for example
`feat/work-20260808-recon-hardening`. Older branches use the short form `<type>/<description>`.
Never commit to `main`.

**Pull requests.** `.github/PULL_REQUEST_TEMPLATE.md` is filled in, not deleted. The two boxes
under "Passivity and credential gate" are required, and a reviewer who cannot confirm both must
request changes.

### Pre-commit hooks

`pre-commit install` gives you the cheap half of CI before a commit is written
(`.pre-commit-config.yaml`):

| Hook | What it does |
|---|---|
| `ruff-check --fix` | Lints and applies the safe autofixes. |
| `ruff-format` | Rewrites files in place, unlike CI, which only checks. |
| `check-added-large-files` | Rejects anything over 500 KB. An investigation dump is usually large. |
| `detect-private-key` | A private key in a commit is unrecoverable once pushed. |
| `end-of-file-fixer`, `trailing-whitespace` | Hygiene. |
| `check-yaml`, `check-toml` | The two config formats this repository uses. |
| `check-merge-conflict`, `check-case-conflict` | The two mistakes that produce corrupt commits. |
| `gitleaks` | Secret scan, because two providers carry the key in the query string. |

Two cautions, both recorded at the config itself:

1. `pre-commit run --all-files` runs `ruff-format`, which rewrites in place. The per-commit path
   is safe, because a hook only receives the staged files. Scope a manual run with
   `pre-commit run --files <paths>`.
2. The `gitleaks` hook runs with its upstream default arguments, which do not include
   `--redact`. A match can echo the matched string into your terminal and into the hook output.
   Do not paste that output anywhere.

---

## 4. Project rules

These four are specific to this tool. None of them is obvious from reading the code alone.

### 4.1 The passivity review rule

A pull request that adds an outbound request must do all of the following **in the same
commit**:

1. Add the host to `ALLOWED_EGRESS_HOSTS` in `tripper_recon/utils/http.py`, with a comment
   naming the provider and the module that contacts it.
2. Add the same host to `ALLOWED_HOSTS` in `tests/test_passivity.py`.
3. Add a row to the table in `docs/OPSEC.md` section 2.
4. State in the pull request body **why the endpoint returns data the provider already holds**.

The fourth item is the actual review. The first three are mechanical. A reviewer approves a new
destination on the strength of one question: does this call read a record the provider collected
already, or does it ask the provider to go and look at the target now? A submission endpoint, a
live scan, a redirect expansion and a `HEAD` request are all the second kind, and the second kind
is forbidden without a flag and without an exception (`docs/OPSEC.md` section 7).

The two halves of the boundary protect each other, and neither replaces the other:

- **The static gate** (`tests/test_passivity.py`) parses the package source and fails the build.
  It sees URL literals, forbidden endpoint markers, resolved request paths, POST call sites and
  name-resolution sites. It cannot see a host assembled at run time.
- **The runtime hook** (`_enforce_egress_allowlist` in `tripper_recon/utils/http.py`) inspects
  the URL that is actually about to leave and raises `PassiveBoundaryViolation` before a socket
  opens. It catches exactly the case the static gate cannot.

Four further constraints the gate enforces, so that you meet them on purpose rather than by
accident:

- Only `utils/http.create_client()` may construct an HTTP client. The hook lives on the client
  instance, so a client built anywhere else enforces nothing. Every provider takes
  `client: httpx.AsyncClient` as a keyword parameter.
- Every request destination comes from a module-level constant. A destination the static
  resolver cannot resolve fails the build, because no gate can see where it goes.
- The only non-GET destination permitted is the Cloudflare Radar GraphQL endpoint, which reads
  data Cloudflare already holds despite the verb. New POST call sites are pinned by module and
  by constant name in `PINNED_POST_SITES`.
- Name resolution lives in `tripper_recon/utils/dns.py` and nowhere else. Live resolution on the
  `domain` path, and on `url --depth full`, is the one documented exception, and the maintainer
  has **accepted** it as a known risk (`docs/ROADMAP.md` section 4b, Q2). An accepted risk stays
  auditable only while it lives in one module. A second resolution site widens a risk past what
  was accepted.

When a provider is removed, delete its allowlist entries and its `docs/OPSEC.md` row too. A
leftover entry fails `test_allowlist_has_no_dead_entries`, and it deserves to: it is a standing
permission that nobody re-approved.

### 4.2 A scoring constant in a `.py` file is a defect

Every tunable in the verdict engine lives in `tripper_recon/verdict/scoring.yaml`: weights,
thresholds, bands, decay curves, family maps and override tiers. `verdict/config.py` holds the
*shape* of that file and the coherence rules that reject an incoherent one. It holds no numbers.

This is not tidiness. A verdict that an analyst pasted into a ticket six months ago has to stay
interpretable, and that is only possible while the numbers that produced it are versioned data
rather than a diff buried in a commit.

Two consequences:

- **Change any number in `scoring.yaml` and bump `version:`.** It is stamped into every verdict
  as `ruleset_version`. Two verdicts produced under different tunings are different claims and
  must not compare equal by accident.
- **Never state an accuracy.** `calibration.status` is `unvalidated`, `fixture_count` is 0, and
  no held-out evaluation has been run. The loader rejects a config that carries a precision or
  recall figure while the status is `unvalidated`. The weights are informed priors. Write them
  that way in code, in docs and in a pull request body.

### 4.3 Never make absent data look clean

A provider that was never asked, that failed, or that has no configured key produced **no
evidence**. A provider that answered and found nothing produced evidence. Collapsing the two is
how "never asked" starts rendering as "came back clean".

The failure mode is concrete. VirusTotal returns a stats block, and the console sums it into an
`n/total` detection ratio colored green when `n` is zero. When VirusTotal was never asked, the
stats block is empty and the sum is zero, so the row renders as a green `0/0`: a clean scan that
never happened. An analyst reads green and moves on. The IP path shipped that defect, and the
domain path kept its own copy of it for two workstreams after the IP path lost it.

What the code does instead, and what your change must keep doing:

- A row with no data prints `no data` with the provider outcome beside it, never a zero and
  never in green (`provider_outcome` and `_no_data_cell` in `tripper_recon/reporting/console.py`).
- `ProviderStatus` separates `OK`, `NOT_FOUND`, `ERROR`, `NOT_CONFIGURED` and `SKIPPED`
  (`tripper_recon/types/models.py`). `NOT_FOUND` means the provider was asked and holds no
  record, which is an observation. `NOT_CONFIGURED` means nothing at all.
- Coverage denominators are **declared** tuples (`IP_PROVIDERS`, `DOMAIN_PROVIDERS`,
  `URL_PROVIDERS` in `tripper_recon/orchestrators.py`), not counted from the calls that
  happened. A denominator derived from attempts shrinks in exactly the case that matters and
  reports better coverage for the worse run.
- The verdict engine refuses `NO_ADVERSE_FINDINGS` below the coverage floor and returns
  `INSUFFICIENT_DATA` instead. No setting in `scoring.yaml` can switch that off.

If you add a rendering path, add the absence case with it, and add a test that asserts the
absent case does not render as a zero.

### 4.4 Do not "fix" the `.gitignore` artifact rules

`.gitignore` blanket-ignores `*.json`, `*.csv`, `*.tsv`, `*.txt`, `*.sqlite` and `*.db`, and it
ignores `outputs/`, `results/` and `reports/` as directories. This looks broken to anyone who
expects to commit a JSON fixture. It is deliberate.

The reason is that this repository's working output is investigation data. An indicator list
reveals an ongoing incident before anyone is ready to disclose it, and a target list pushed to a
public remote is not recoverable. The blanket rules mean a stray dump is ignored by default,
wherever it lands.

The negations are scoped on purpose:

```
!tests/**/*.json      !tests/**/*.csv      !tests/**/*.tsv      !tests/**/*.txt
!schema/**/*.json     !requirements.txt    !LICENSE.txt
```

Two named directories, plus two named files. Recorded provider fixtures under `tests/` and a
future report schema under `schema/` are source, not output, so they are re-included by
extension in those paths only. The directory ignores are unaffected, because git does not
descend into an ignored directory, so no negation can resurrect anything under `outputs/`,
`results/` or `reports/`.

Verify before you change anything here:

```bash
git check-ignore -v outputs/run.json      # ignored
git check-ignore -v scan.json             # ignored
git check-ignore -v tests/fixtures/vt.json  # not ignored
```

If you need to commit a new data file, add a scoped negation for its directory. Do not widen the
blanket rule, and do not delete it.

---

## 5. Adding a provider

Read the "Adding a provider" section of [`docs/PROVIDERS.md`](docs/PROVIDERS.md) first. It
covers the envelope and the failure semantics. The full sequence, including the parts that live
outside `providers/`:

1. **Confirm the endpoint is passive.** It must return data the provider already holds. Check it
   against the forbidden list in `docs/OPSEC.md` section 7. If the provider would fetch the
   target on your behalf, stop - that belongs in a different tool.
2. **Write the module** under `tripper_recon/providers/`, one async function per endpoint. Take
   `client: httpx.AsyncClient` as a keyword parameter. Never construct a client.
3. **Name the destination with a module-level constant.** Build paths from it with an f-string.
   The static gate resolves through constants, and an unresolvable destination fails the build.
4. **Return the envelope**: `{"ok": True, "data": {...}}` on success, or
   `{"ok": False, "error": "...", ...}` on failure.
5. **Return an envelope when the credential is missing, never raise.** Use one of the strings in
   `NOT_CONFIGURED_ERRORS` (`tripper_recon/orchestrators.py`), currently `missing_api_key`,
   `missing_api_token`, `missing_token` and `API key not configured`. Any other string maps to
   `ProviderStatus.ERROR`, which reports a configuration gap as an incident.
6. **Wrap each request in `with_exponential_backoff`.** Retry policy, `Retry-After` handling and
   jitter live in `tripper_recon/utils/backoff.py`. Wrap each request separately, not the whole
   sequence, so one late failure does not replay every earlier request.
7. **Apply the passivity review rule** in section 4.1: both allowlists and the `docs/OPSEC.md`
   row, in the same commit.
8. **Wire the orchestrator, and update the coverage denominator.** If a path consults the new
   provider, add it to `IP_PROVIDERS`, `DOMAIN_PROVIDERS` or `URL_PROVIDERS` in the same change.
   A provider that answers but is missing from the tuple never appears in "N of M answered".
9. **Test it with `respx`.** Cover the success shape, the missing-credential shape and at least
   one error status. Add a payload fixture to `tests/conftest.py` if the renderer consumes it.
10. **If it feeds a verdict**, write an `extract_<provider>_signals` function in
    `verdict/signals.py`, add its identifier to the `SignalId` enum in `verdict/config.py`, and
    put the weight in the `signals:` table of `verdict/scoring.yaml`. Bump `version:`. No number
    goes in a `.py` file.
11. **Update `docs/PROVIDERS.md` and the README provider list** in the same commit.

---

## 6. Where to look

| File | Holds |
|---|---|
| `docs/OPSEC.md` | The passivity contract, every outbound destination, the forbidden endpoints, and the gaps it does not paper over. |
| `docs/PROVIDERS.md` | Per-provider fields, credential handling, rate limits, adding a provider. |
| `docs/ROADMAP.md` | The sequenced hardening plan, the known-defect list, and the settled operator decisions in section 4b. |
| `docs/review/` | The audit reports the roadmap was built from. |
| `SECURITY.md` | Reporting a vulnerability, and how credentials and investigation output are handled. |
