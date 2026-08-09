# Threat Model

Who can hurt you when you run this tool, what they would have to do, and which of it the code
actually stops.

This document describes the code as it stands on branch `feat/work-20260808-recon-hardening`.
Every control claim carries a `file:line` anchor so you can check it yourself rather than take it
from prose. Line numbers were verified against the working tree on 2026-08-09; where one has since
drifted, the **named symbol** is the durable anchor and the line is a hint.

It is the companion to [`OPSEC.md`](OPSEC.md), not a replacement. `OPSEC.md` answers *what leaves
this machine and who sees it*. This file answers *what an adversary can do about it*. Where the two
overlap, `OPSEC.md` is the authority on egress and this file is the authority on adversary
capability. If you change a provider, a renderer, or the egress allowlist, change both in the same
commit.

**One thing this model is not.** It says nothing about whether the verdict is *right*. The scoring
weights are unvalidated priors and the shipped ruleset says so in its own config
(`tripper_recon/verdict/scoring.yaml:34`, `calibration.status: unvalidated`). A wrong verdict is a
correctness problem, and correctness is out of scope here — see section 8.

---

## 1. What this tool is, for modelling purposes

A single-user local CLI. No server, no daemon, no listening socket, no multi-tenancy — the FastAPI
server that once existed was deleted outright (`docs/ROADMAP.md` §4b, Q8), and its absence is a
build gate: `tests/test_server_removed.py` fails if the module returns, if any web framework is
imported or declared, or if a server entry point reappears. Subcommands are `ip`,
`domain`, `asn`, `url`, `check` and `bulk`, registered at `tripper_recon/cli.py:1439-1532` inside
`main`. It reads indicators, calls third-party APIs over HTTPS, and prints a report.

That shape does most of the work of a threat model on its own: there is no request an attacker can
send to you, no session to hijack, and no privilege to escalate into. Everything below is therefore
about **data an adversary can put in front of you**, **traffic they can observe**, and **secrets
sitting on your disk**.

---

## 2. Assets

Three, in the order they will hurt.

### A1 — The provider credentials in `.env`

Six provider credentials: `VT_API_KEY`, `SHODAN_API_KEY`, `ABUSEIPDB_API_KEY`,
`IPINFO_TOKEN`, `OTX_API_KEY`, `CLOUDFLARE_API_TOKEN` (enumerated at
`tripper_recon/utils/redact.py:40`, read at `tripper_recon/orchestrators.py:319`, `_env_keys`).

Loss is not merely financial. Two of them travel **in the query string** — Shodan's `?key=`
(`tripper_recon/providers/shodan_api.py:68`) and IPinfo's `?token=`
(`tripper_recon/providers/ipinfo.py:17`, `:61`) — which means the credential is inside every
failing request URL, every `httpx` exception string, and anything that copies either. A stolen key
also lets the thief make lookups *as you*, which contaminates the provider-side record of what you
investigated.

### A2 — The analyst's egress IP

Every provider sees it. So does anyone who can observe the network path. It ties a real
organisation to a set of indicators at a set of timestamps.

### A3 — The indicator list itself

The most under-rated of the three. The *set* of things you are looking at can reveal an ongoing
incident before your organisation is ready to disclose it, and it does so without a single
indicator being sensitive on its own. Three IPs and a domain, queried in one minute, is an
incident. It leaks to providers by construction (§6.2), and locally through argv, shell history,
the stderr log stream, and any file you write.

---

## 3. Adversaries

| # | Adversary | What they have | What they want |
|---|---|---|---|
| **T1** | **The target operator, watching their own logs** | Authoritative DNS logs for their domain; web logs for their infrastructure; the ability to serve different content to different visitors | To learn they are under investigation, in time to rotate infrastructure or burn a single-use link |
| **T2** | **A hostile or compromised provider** | Full control of the JSON body this tool parses and renders; the ability to return anything at all under a valid TLS certificate for an allowlisted host | To crash the tool, spoof a verdict, or turn the report into a delivery mechanism |
| **T3** | **Anyone with access to provider-side logs** | The per-account query record: which indicators, from which egress IP, at which times. Includes the provider's staff, their breach, a lawful-process reader, and — for a shared corporate account — colleagues | A2 and A3 without touching your network at all |
| **T4** | **A local attacker on the analyst workstation** | Code execution as the same UID, or read access to the filesystem | A1 directly; A3 as a bonus |

T1 is the adversary the whole product is built against. T2 is the one the input-handling code is
built against. T3 is largely **unmitigated by design** — see §6.2. T4 is barely mitigated at all:
the tool keeps six credentials in a plaintext file whose permissions it neither sets nor checks
(residual 7), and it prints the indicator under investigation to a log stream (residual 8).

Deliberately excluded: a network attacker between you and the provider (TLS, §4), and a supply
chain attacker (§8).

---

## 4. Controls that exist in the code

Each row is a control that is present and enforced, not a plan.

| # | Control | Adversary it answers | Anchor |
|---|---|---|---|
| C1 | **Runtime egress allowlist.** An `httpx` request event hook rejects any host not on a hard-coded set, raising `PassiveBoundaryViolation` before the request reaches the transport | T1 | `utils/http.py:63` (`ALLOWED_EGRESS_HOSTS`), `:112` (`_enforce_egress_allowlist`), `:119` (the check), `:173` (installed on the one client factory) |
| C2 | **Only one place builds a client**, so no code path can obtain an unhooked one; and a separate test asserts the factory still installs the hook, so C1 cannot pass vacuously | T1 | `tests/test_passivity.py::test_only_utils_http_constructs_a_client`, `::test_the_factory_actually_installs_the_hook` |
| C3 | **Static passivity gate.** Build-time scan of the package for URL literals off the allowlist, forbidden endpoints, non-GET verbs, resolved request paths ending at a submission collection, and name resolution outside one module | T1 | `tests/test_passivity.py` (sections 1–5) |
| C4 | **Credential redaction on the error path.** Sensitive query parameters are replaced by name, and the literal values of the six credential env vars are replaced wherever they appear. Both entry points are wrapped so redaction can never raise and mask the original failure | A1, T2 | `utils/redact.py:70` (`redact_url`), `:97` (`redact_text`), `:86` and `:108` (never-raise), `:51` (`_MIN_SECRET_LEN`, guards against a short or blank env var causing runaway substitution) |
| C5 | **Every error payload leaving the orchestrator is redacted**, including the failing request URL read defensively off an `httpx` object that raises on attribute access | A1 | `orchestrators.py:235` (`_safe_request_url`), `:251` (`_error_payload`), `:355` (the human summary is built from the redacted payload, so log lines inherit it) |
| C6 | **Rich markup escaping of provider-controlled strings.** One function every renderer routes through, so a hostile field cannot crash the render *with markup* or paint a colour the tool never computed. It is a markup escaper, not a terminal sanitiser — see §5.1 | T2 | `reporting/console.py:171` (`esc`), `:137` (`indicator_text`, the single call site for indicator fields), `cli.py:641` (OTX pulse titles) |
| C7 | **Non-public address guard.** Six categories — private, loopback, link-local, multicast, reserved, unspecified — refused before any address is forwarded to a provider, on the IP path, the domain path and the URL path | A3, T3 | `orchestrators.py:782` (`_NON_PUBLIC_CATEGORIES`), `:792` (`non_public_ip_reason`), `:923` (IP), `:1131` (domain), `:1353` (URL host), `cli.py:1114`–`:1116` (bulk triage, so the withheld table agrees with the orchestrator) |
| C8 | **Refused addresses are reported, never dropped.** A domain resolving to three internal addresses and one public one renders as four, with reasons | A3 | `orchestrators.py:1024` (`_skipped_address`), `types/models.py:385` |
| C9 | **TLS verification on and never disabled.** `verify=True` is explicit at the one construction point, and the string `verify=False` appears nowhere in the package or the tests | network observer | `utils/http.py:174` |
| C10 | **Honest User-Agent.** The tool names itself rather than impersonating a browser, which removes a terms-of-service and evidence-chain problem that bought nothing — the API key already identifies the caller | T3 | `utils/http.py:128` (`DEFAULT_USER_AGENT`) |
| C11 | **Secret scanning, locally and in CI.** `gitleaks` runs as a pre-commit hook and again in CI over the **full history**, because a key that was committed and later removed is still a key that leaked. `detect-private-key` runs alongside | A1 | `.pre-commit-config.yaml:81-84`, `:52`; `.github/workflows/ci.yml:152` (job), `:165` (`fetch-depth: 0`), `:170` (action) |
| C12 | **`.env` is gitignored, and so is investigation output** | A1, A3 | `.gitignore:71-73` (`.env`, `.env.*`, with `.env.example` re-included), `:80` (`outputs/`) |
| C13 | **The test suite runs with every provider credential explicitly blanked**, so a test that escapes its `respx` mock fails on a missing key instead of billing a live account and logging your indicators against it | A1, A3 | `.github/workflows/ci.yml:140-150` |
| C14 | **Human-facing output is defanged by default.** `--fanged` opts out; `-o json` is never defanged either way, because a machine consumes it | onward-transmission | `cli.py:1428` (the flag), `:1577` (`defang = not getattr(args, "fanged", False)` in `main`), `reporting/console.py:137` |
| C15 | **Large-file and private-key accident guards** on commit | A1, A3 | `.pre-commit-config.yaml:48` (500 KB ceiling), `:52` |

Two notes on what C1 and C3 are worth **together**, which is the reason both exist. The static scan
sees URL *literals* and is blind to a host assembled at runtime; the hook sees the host a request
is actually about to leave for, but only the host — it is blind to the path (residual 2 in §7), and
it lives or dies with the one factory. The static gate fails the build, the hook fails the run, and
`tests/test_http.py::test_runtime_allowlist_is_a_subset_of_the_static_allowlist` fails if the two
lists drift apart. Remove either half and the build stays green — that is stated as an open gap in
`OPSEC.md` §6 and it is still true.

---

## 5. The hostile-input surface

This is the section that matters most for T2, and it is the one most easily under-read, because the
inputs do not look like attacker input.

**Everything below is attacker-influenced text.** Not "could theoretically be" — routinely is:

- **Every provider response field.** A Shodan `org`, an IPinfo `city`, a WHOIS blob, an OTX pulse
  title, a urlscan page title, a VirusTotal engine name. Several of these are *registrant-supplied*
  or *community-supplied*, meaning the person you are investigating can often write them directly.
- **Every pasted indicator.** The `bulk` command exists so an analyst can paste an entire phishing
  email into it. That text is authored by the adversary, in full, by definition.

Both then get **rendered to a terminal** and **interpolated into URLs and query languages**. Here is
what stops each of the resulting problems, and what does not.

### 5.1 Provider text rendered to a terminal

`rich` parses square brackets as markup. Two distinct failures follow from that, and both were
observed rather than imagined: a pulse title such as `evil [/] campaign` raised `MarkupError`
mid-render, and `[green]0/94 clean[/]` painted a verdict the tool never computed
(`reporting/console.py:171-181`, `cli.py:639-641`).

**Control:** one escaping function, `esc()`, applied at every renderer's single call site, so the
flag cannot be honoured in one row and forgotten in the next. It is both a crash guard and a
display-spoof guard. Pinned by tests, including for the specific fields an attacker most easily
controls: `tests/test_console_render.py::test_hostile_org_name_is_escaped`,
`::test_hostile_ipinfo_city_is_escaped`, `::test_otx_pulse_title_colour_tags_render_as_literal_text`,
`::test_provider_errors_escapes_hostile_detail`, `::test_hijack_reason_is_escaped`,
`::test_hostile_source_tag_is_escaped`.

**What it does not stop — read this one.** `rich.markup.escape` is a *markup* escaper, not a
terminal sanitiser. Rich strips some C0 control characters on the way out but **not `ESC`
(`0x1b`)**. Verified against this working tree:

```
$ python - <<'PY'
import io
from rich.console import Console
from tripper_recon.reporting.console import esc
c = Console(file=io.StringIO(), force_terminal=False, width=120, highlight=False)
c.print(esc("ACME\x07BELL\x1b[31mRED[bold]not-bold[/]"))
out = c.file.getvalue()
print(repr(out), "BEL:", "\x07" in out, "ESC:", "\x1b" in out)
PY
'ACMEBELL\x1b[31mRED[bold]not-bold[/]\n' BEL: False ESC: True
```

Markup is neutralised (`[bold]` printed literally) and BEL is gone, but the `ESC` byte survives into
the output stream. No test in this repo asserts anything about a provider string containing `0x1b`
(verified by grep across `tripper_recon/` and `tests/`). What a given terminal emulator then does
with it is outside this repo's control and is not characterised here. Treat "the report renders
inertly in any terminal" as **unproven**, and prefer `-o json` when handling output from a provider
you have reason to distrust.

### 5.2 Indicator text interpolated into a URL

Every provider builds its request path from a module-level constant plus the indicator:
`f"{VT_BASE}/ip_addresses/{ip}"` (`providers/virustotal.py:167`), `f"{VT_BASE}/domains/{domain}"`
(`:200`), `f"{SHODAN_BASE}/shodan/host/{ip}"` (`providers/shodan_api.py:68`),
`f"{IPINFO_BASE}/{ip}"` (`providers/ipinfo.py:17`). Interpolating attacker text into a URL is the
classic route to SSRF, and there is no per-provider quoting call.

**Control, in three layers:**

1. **Validation before construction.** Each orchestrator entry point gates on
   `utils/validation.py` before any provider is called: `is_valid_ip` at `orchestrators.py:920`,
   `is_valid_domain` at `:1057`, `normalize_asn` bounding the ASN to `0 < n < 2**32`
   (`validation.py:56-78`). A domain is IDNA-encoded to A-labels and every label re-checked against
   `^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$` (`validation.py:37`, `:100-141`), so a value carrying `/`,
   `?`, `#`, `@` or whitespace cannot survive to become part of a path.
2. **No base URL is attacker-controlled.** Every destination is a module constant, and the static
   gate resolves those constants and asserts the real path (`tests/test_passivity.py`, section 5,
   `EXPECTED_RESOLVED_ENDPOINTS`).
3. **The egress hook is the backstop.** If a target-derived value ever did become the *host*, C1
   raises before a socket opens — and the exception message says so in as many words
   (`utils/http.py:107-108`: "If the host came from a target-derived value interpolated into a URL,
   that is the violation itself").

**Normalisation is not folding, and that is deliberate.** `аpple.com` with a Cyrillic U+0430
normalises to `xn--pple-43d.com` and stays a different name from `apple.com`
(`validation.py:15-19`). Folding homographs together would make the tool report on the wrong
domain, which is precisely the domain the analyst is looking at.

### 5.3 Indicator text interpolated into a query language

urlscan's Search API takes an ElasticSearch query string, in which `+ - = && || > < ! ( ) { } [ ] ^
" ~ * ? : \ /` are reserved — and a URL under investigation contains several of them **by
construction**. An unescaped indicator becomes a syntactically valid *different* query, and a query
that returns somebody else's scans is worse than one that returns none.

**Control:** `_quoted_term` wraps the value in a quoted phrase, which neutralises every reserved
character except the quote and the backslash, and escapes those two
(`providers/urlscan.py:103` `_PHRASE_ESCAPES`, `:172-186`). Pinned by
`tests/test_providers_urlscan.py::test_search_escapes_elasticsearch_reserved_characters`.

Note the current wiring state, because it changes who is exposed today: `providers/urlscan.py` is
written, tested and allowlisted, but **no orchestrator calls it** — `URL_PROVIDERS` has one entry
and it is VirusTotal (`orchestrators.py:192-201`). The urlscan allowlist entry is a standing egress
permission for a code path nothing exercises. That is recorded as gap 3 in `OPSEC.md` §6.

### 5.4 Pasted text that reaches the filesystem API

`bulk` accepts a path, `-` for stdin, or the text itself. `Path.is_file()` does not reliably return
`False` for a string that cannot be a path — it can *raise*. The function's own docstring
enumerates three cases (`cli.py:1202-1209`): `OSError` for a paste longer than `PATH_MAX`,
`ValueError` for a paste containing a NUL byte, and `RuntimeError` from `expanduser()` for an
unresolvable `~user`. All three are attacker-reachable in principle, because the entire point of the
command is that hostile text is pasted into it.

One correction to that docstring, measured on the interpreter used here (CPython 3.12.12): the overlong
case does raise (transcript below), but the NUL case does **not** —
`_load_ip_targets("a\x00b")` returns normally, because `pathlib.Path.is_file` swallows `ValueError`
on this version. The guard is therefore broader than this interpreter requires, which is the correct
direction for a guard to err in.

**Control:** the probe is guarded and the fallthrough treats a non-path as text
(`cli.py:1195-1216`, `_read_bulk_text`; the guard is `except (OSError, ValueError, RuntimeError)` at
`:1216`).

**The same guard is missing one door down.** `_load_ip_targets` performs the identical unguarded
probe (`cli.py:435-437`), and it raises. Verified against this working tree:

```
$ python -c "from tripper_recon.cli import _load_ip_targets; _load_ip_targets('A'*5000)"
  File ".../pathlib.py", line 840, in stat
    return os.stat(self, follow_symlinks=follow_symlinks)
OSError: [Errno 36] File name too long: 'AAAA...'   (traceback abridged)
```

Severity is low — the string has to arrive in `argv`, so this is an analyst crashing their own
process, not an attacker crashing it remotely — but it is the same defect class the `bulk` path
fixed, and it is currently uncaught. It is listed as a residual in §7.

### 5.5 Hostile text that becomes a routing decision

`bulk` classifies pasted text and decides what to look up. Two properties keep that honest under
adversarial input: an indicator that arrived defanged is annotated as such rather than silently
refanged (`cli.py:550` logs the transform; the triage note says "arrived defanged — somebody
already judged this hostile"), and **triage makes no request at all** — extraction and
classification are pure, and `--investigate` is the opt-in, capped by `--max-targets`
(`cli.py:1223` onward, `_cmd_bulk`). Pasting an entire phishing email costs nothing and reaches
nobody.

### 5.6 Hostile response bodies that are merely *shaped* wrong

Every field read out of a provider response goes through a coercion helper whose contract is that a
missing field reads as **absent**, never as a benign value (`providers/urlscan.py:106-116` states
the rule; `providers/virustotal.py:275` and `:420` apply it). This is a correctness control that
happens to be a security control: a hostile provider that omits a field must not be able to make it
render as a clean zero. `reporting/console.py:196-217` carries the same rule into the renderer, and
an outcome the renderer does not recognise **fails closed** — counted as a gap and named on screen,
never silently counted as coverage.

---

## 6. Accepted risks

These are decisions, not oversights. They were settled by the operator and recorded in
`docs/ROADMAP.md` §4b, and they are **not to be re-litigated by a future session**.

### 6.1 System-resolver egress on the `domain` and `url --depth full` paths

`tripper-recon domain <target>` calls `socket.getaddrinfo()` on the target
(`utils/dns.py:41`, invoked at `orchestrators.py:1126`). Your recursive resolver walks the
delegation chain and queries **the nameserver the target operator runs**. That nameserver logs a
query for their own domain at the moment your investigation started. For a live actor watching
their own DNS logs, that is a tell; for a single-use phishing domain, it can be *the* tell. This is
T1 succeeding.

**Decided: accepted.** Live resolution stays the default and is disclosed
(`ROADMAP.md` §4b, Q2). There is **no `--active-dns` flag** and none is planned. What limits the
exposure instead:

- The two shallower URL depths do not resolve at all (`orchestrators.py:203-210`, `URL_DEPTHS`):
  `--depth url` asks only about the link, `--depth host` adds the host's reputation. If resolver
  egress is the risk you are managing, **the depth flag is the control**.
- Resolution is confined to one module and a build gate keeps it there
  (`tests/test_passivity.py::test_name_resolution_only_in_utils_dns`, with
  `::test_utils_dns_is_the_module_that_resolves` guarding against the first passing vacuously). An
  accepted risk is only auditable while it lives in exactly one place; a second resolution site
  would widen the accepted risk past what was accepted.
- What it does **not** leak: your workstation IP. The query arrives at the target's nameserver from
  your recursive resolver.

### 6.2 Every provider sees every query

Passive means the *target* does not see you. The providers do, and so does T3.

- Every query is attributable to your API key and logged against your account.
- Your egress IP (A2) is visible to every provider contacted.
- The indicator list (A3) is disclosed by construction — that is what a lookup *is*.

**Decided: accepted**, as the cost of the tool existing. There is no mitigation inside this
codebase, and none is planned. Two things are worth knowing:

- **Lookups are not submissions.** Nothing here contributes your indicators to a public corpus; the
  entire submission class is forbidden and gated (`OPSEC.md` §7, enforced by
  `tests/test_passivity.py` sections 2, 3 and 5).
- **A proxy is possible but unsupported.** `create_client()` does not set `trust_env`, so httpx's
  default is left in place; on the constructed client it reads `True`, and setting `HTTPS_PROXY`
  produces an `https://` transport mount (both observed against this working tree). The egress
  allowlist inspects the *request* URL host, not the proxy, so a proxy and C1 coexist. But nothing
  in this repo tests, documents or supports that as a control — treat it as an httpx behaviour you
  are relying on, not a feature this tool offers.

If an investigation is sensitive enough that provider visibility is itself a risk, **this tool is
the wrong instrument.** Use an offline data set.

### 6.3 abuse.ch terms-of-service exposure — *once 8.7 lands*

**Not yet built.** No abuse.ch provider exists in `tripper_recon/providers/` (verified by grep). It
is planned as roadmap item 8.7.

The decision recorded ahead of the build: abuse.ch will be implemented **in full, including bulk
mode, with no gate** (`ROADMAP.md` §4b, Q5). The roadmap records that their Terms of Use prohibit
high-volume automated harvesting by "robots, spiders or scripts", and that bulk mode is arguably
exactly that (`ROADMAP.md` §5, Q5) — that reading of the terms is inherited from the roadmap and has
not been re-verified against the live terms here. The operator **accepts that exposure**; it is
recorded rather than mitigated. The adversary here is neither T1
nor T2 — it is the provider's own enforcement, and the loss is access, not confidentiality. When
8.7 ships, this section and `OPSEC.md` §2 must both be updated in the same commit.

### 6.4 `.env` is loaded from the current working directory first

`load_env()` checks `$CWD/.env` before the project root (`utils/env.py:15-22`). Running the tool
from an attacker-supplied directory could therefore load an attacker-supplied `.env`.

**Decided: declined as a security fix** (`ROADMAP.md` §4, "Hardening `.env` CWD loading"). The
reasoning, which holds: `override=False` means anything already exported in the real environment
wins, provider base URLs are hard-coded so keys cannot be redirected to an attacker's endpoint, and
the attack requires the analyst to `cd` into hostile territory first. Real hygiene issue,
speculative threat.

---

## 7. Residual risks the controls do not close

Open, and stated because a control list without one is marketing.

1. **ESC bytes from a provider reach the terminal unfiltered.** §5.1. No test covers it, and no
   claim is made about how a terminal handles it. This is the largest untested hostile-input path.
2. **The egress allowlist is host-level, not path-level.** `www.virustotal.com` and `urlscan.io`
   are permitted hosts and each carries a submission route the allowlist alone would not stop. What
   stops those is the static gate's resolved-path check and the per-provider tests — belt and
   braces, not one control (`OPSEC.md` §6, gap 2).
3. **Each half of the passive boundary can be removed without the other noticing.** Delete the hook
   and the build stays green; delete the static gate and the runtime check still runs but nothing
   fails a PR (`OPSEC.md` §6, gap 1).
4. **`_load_ip_targets` raises on an overlong argument** (§5.4, `cli.py:435-437`). Low severity and
   self-inflicted — it has to arrive in `argv` — and the guard that fixes it already exists in
   `_read_bulk_text`.
5. **A provider could be wrong about its own API.** Every claim that an endpoint is read-only comes
   from that provider's documentation. If VirusTotal or urlscan changed a `GET` route to trigger a
   fetch, nothing here would detect it (`OPSEC.md` §6, gap 5).
6. **`--prefixes-out` overwrites silently and inherits the umask.** `out_path.write_text(...)` at
   `cli.py:1391`, in the `asn` command — no existence check, no explicit mode. An investigation artefact (A3) lands on
   disk at whatever permissions the environment gives it. Tracked as W7.3; the roadmap explicitly
   declines *path containment* for this flag (the path is the analyst's own argv, no trust boundary
   is crossed) but the overwrite and the default location are real.
7. **Nothing manages `.env` permissions.** The tool neither creates nor `chmod`s the file. Whether
   your credentials are group- or world-readable is whatever your umask produced, and the tool does
   not check or warn. Against T4 this is the whole ballgame — check it yourself.
8. **A same-UID process on the workstation reads everything.** Environment variables of a running
   process, the `.env` on disk, `argv` (so the indicator under investigation is visible to anything
   that can read `/proc`), shell history, and the structured log stream on stderr — which carries
   indicators by design (`cli.py:550` refang, `:494`/`:673`/`:811` failure lines,
   `orchestrators.py:833` deadline). Error *text* on that stream is credential-redacted (C5);
   indicator text is not, and is not meant to be.
9. **An IDN homograph is displayed in its Unicode form in `bulk` triage.** `аpple.com` renders
   identically to `apple.com`. The A-label is computed and `HOST_MIXED_SCRIPT` is recorded in
   `utils/urls.parse_url`, but neither is carried into the triage row (`OPSEC.md` §6, gap 7). This
   is a spoof that reaches the analyst's eye, not the network.
10. **An over-long hostname is routed to VirusTotal**, spending a quota unit on a string that cannot
    have a report (`OPSEC.md` §6, gap 6; pinned as current behaviour in
    `tests/test_w6_passivity_audit.py`). Not a passivity breach — the request goes to VirusTotal,
    not the target.

---

## 8. What this threat model does not cover

Named so their absence is a decision rather than an oversight.

- **Whether the answer is correct.** Verdict weights are unvalidated priors
  (`verdict/scoring.yaml:34`) and the tool makes **no accuracy claim at all** — deliberately, until
  a held-out corpus exists (`ROADMAP.md` §4). An analyst acting on a wrong verdict is a real harm
  and it is not modelled here.
- **Supply chain.** Dependencies are floor-pinned with no lockfile, no hashes and no SBOM
  (`pyproject.toml:32-42`: `httpx[http2]>=0.27.0`, `pydantic>=2.6.0`, `python-dotenv>=1.0.1`,
  `pyyaml>=6.0`, `rich>=13.0.0`). A compromised release of any of them executes with the tool's
  privileges and reads `.env`. Nothing in this repo defends against that. The CI tool versions are
  floor-pinned too and merely *printed* for diagnosis (`ci.yml:75-83`); pre-commit revs, by
  contrast, are pinned exactly (`.pre-commit-config.yaml:32`, `:44`, `:82`).
- **The transport, beyond verifying TLS.** No certificate pinning, no CT monitoring. A CA-level
  adversary is out of scope.
- **Workstation compromise beyond file and process reads.** Kernel-level attackers, malicious
  Python packages already installed, and a keylogger are all game over for A1 and A3, and no CLI
  control changes that.
- **Data at rest.** Reports and `--prefixes-out` files are plaintext. No encryption, no retention
  policy, no shredding.
- **The rendering surface you paste the report into.** Defanging (C14) stops a URL being clickable
  in a terminal or a ticket; it is not a sanitiser for an arbitrary downstream renderer, and it is
  off for `-o json` by design.
- **Availability.** Rate limits, provider outages and the wall-clock deadline
  (`orchestrators.py:815`, `_with_deadline`) are reliability concerns. Nobody is denying you
  service by attacking this tool.
- **Multi-user or hosted operation.** There is no server. If one ever returns, this document is
  wrong from section 1 down.
- **Formal method.** This is a qualitative asset-and-adversary model, not STRIDE, not an attack
  tree, and not quantified. It is meant to be read and checked, not scored.

---

## 9. Keeping this document true

The failure mode this repo has already lived through is documentation written ahead of the code —
a README that claimed URL support that did not exist and a config value that crashed the tool. The
rule that follows:

- **Adding an egress destination** touches four places in one commit: `ALLOWED_EGRESS_HOSTS`
  (`utils/http.py:63`), `ALLOWED_HOSTS` (`tests/test_passivity.py:66`), `OPSEC.md` §2, and §3/§6.2
  here if the new provider changes who learns what.
- **Adding a renderer** that prints a provider-controlled string routes it through `esc()`
  (C6) and adds a hostile-input test beside the existing ones in `tests/test_console_render.py`.
- **Adding a provider that interpolates an indicator into a query language** adds a quoting helper
  and its test, in the shape of `providers/urlscan._quoted_term` (§5.3).
- **Closing a residual in §7** deletes the row rather than softening it. **Accepting a new risk**
  adds a row to §6 with the decision recorded in `ROADMAP.md` §4b, not a hedge in prose.
- **A claim here with no `file:line` behind it is a defect in this file.** Delete it or anchor it.
