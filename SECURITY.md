# Security Policy

Tripper Recon is a single-maintainer passive OSINT CLI. This policy says what is actually true
of it. There is no CVE process here, no bounty, and no response-time commitment, because none of
those could be honored.

## Supported versions

The tip of `main` only. The project is at version 0.1.0 and is marked alpha in `pyproject.toml`.
Nothing is released, so nothing can be backported.

## Reporting a vulnerability

1. Preferred: GitHub private vulnerability reporting on
   [FancyP4nda/tripper_recon](https://github.com/FancyP4nda/tripper_recon). Use the **Security**
   tab, then **Report a vulnerability**. This keeps the report private until a fix exists.
2. If private reporting is not enabled on the repository, open an issue at
   [the issue tracker](https://github.com/FancyP4nda/tripper_recon/issues) that names the
   affected file and asks for a private channel. **Do not put the details in the issue.**

Include what a maintainer needs to reproduce it: the file, the code path, and the conditions.
Leave out credentials, real target indicators, and raw tool output. See "Do not paste raw output"
below.

Expect a reply when the maintainer next works on the project. That is the honest commitment.

## What counts as a security issue here

Two properties are the contract of this tool, so a way to break either is a security issue and
not a bug report:

- **The passive boundary.** Any code path that contacts the target, or that asks a provider to
  fetch the target, breaks the one claim the tool makes. That includes a submission endpoint, a
  live scan, a redirect expansion, and a `HEAD` request. `docs/OPSEC.md` sections 1 and 7 state
  the contract, and `tests/test_passivity.py` plus the runtime allowlist in
  `tripper_recon/utils/http.py` enforce it.
- **Credential containment.** Any path that lets an API key reach console output, `-o json`
  output, a log line, an error payload, or a commit.

Two things are **not** vulnerabilities, because they are documented and accepted:

- **System-resolver egress.** The `domain` command, and `url --depth full`, resolve the target
  name with the system resolver, so the target's authoritative nameserver can see the query.
  This is disclosed in `docs/OPSEC.md` section 3 and accepted by the maintainer in
  `docs/ROADMAP.md` section 4b, decision Q2. A **second** resolution site outside
  `tripper_recon/utils/dns.py` is a defect, because it widens a risk past what was accepted.
- **Provider visibility.** Every lookup is attributable to your API key and exposes your egress
  IP to the provider. Passive means the target does not see you. It does not mean nobody does
  (`docs/OPSEC.md` section 4).

## The tool holds third-party credentials

A working install carries API keys for VirusTotal, Shodan, AbuseIPDB, IPInfo, AlienVault OTX and
Cloudflare in a `.env` file — the six variables in `_SECRET_ENV_VARS`
(`tripper_recon/utils/redact.py`). Those keys are quota-limited and attributable to a person.
Whether a given key sits on a free or a paid tier, every lookup spends against it and is logged
against its owner.

- `load_env()` reads `.env` from the current directory and from the repository root
  (`tripper_recon/utils/env.py`). Any CLI invocation from inside a clone loads whatever keys are
  there. Treat running the tool as spending someone's quota and writing their indicator list into
  six providers' logs.
- `.env` and `.env.*` are gitignored, with `.env.example` re-included. Never commit a filled-in
  `.env`, and never paste one into an issue.
- The `gitleaks` and `detect-private-key` pre-commit hooks, plus a `gitleaks` job in CI over the
  full history, exist because a key that was committed and then removed is still a key that
  leaked.
- The test suite never needs a key. `tests/conftest.py` unsets every provider variable before
  each test, so a real key in your environment cannot leak into pytest output or into a pasted
  failure.

## Do not paste raw output publicly

Two providers authenticate in the query string: Shodan uses `?key=`, IPInfo uses `?token=`. A
failing request URL therefore contains the API key, and `httpx` embeds that URL again inside the
exception text.

The code redacts both. `tripper_recon/utils/redact.py` replaces credential-bearing query
parameter values and also replaces known secret values literally wherever they appear, and
`_error_payload` in `tripper_recon/orchestrators.py` passes every string it emits through it.

Redaction has limits worth knowing before you paste anything:

- Literal redaction only knows the six credential environment variables the package reads, and
  only replaces values of eight characters or more. A credential that arrives by another route
  can survive.
- The `gitleaks` pre-commit hook runs with upstream defaults, which do not include `--redact`.
  When it matches, it can echo the matched string into your terminal and into its own output.

So: read error output before you share it, and prefer a description of the failure over a paste.
If you must paste, redact by hand as well.

## Investigation output is gitignored on purpose

`.gitignore` ignores `outputs/`, `results/` and `reports/` as directories and blanket-ignores
`*.json`, `*.csv`, `*.tsv`, `*.txt`, `*.sqlite` and `*.db`. The re-inclusions are scoped to
recorded fixtures under `tests/`, a future schema under `schema/`, and two named files.

This is a security control, not a housekeeping preference. The output of this tool is an
indicator list, and an indicator list can reveal an ongoing incident before anyone is ready to
disclose it. A target list pushed to a public remote cannot be recalled.

Do not widen those rules to make a file committable. Add a scoped negation for its directory
instead. `CONTRIBUTING.md` section 4.4 has the detail and the verification commands.

## No server, no listening socket

The package ships a CLI only. A bundled FastAPI server existed once, had no authentication, and
was deleted. `tests/test_server_removed.py` fails the build if the module, its dependencies, or
its console entry point come back. A change that makes this tool listen on a socket is a change
to what the tool is, and it needs that conversation first.
