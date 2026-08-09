"""Command-line entry point, and the exit-code contract automation keys on.

**Exit codes.** These are a public interface. A playbook that branches on them is relying on
the rules below, so they are stated here rather than left to be inferred from the code:

===== =========================================================================================
Code  Meaning
===== =========================================================================================
``0`` The investigation ran and at least one provider answered. **This is not a claim that the
      indicator is clean, and not a claim that the lookup was complete.** A run with two of six
      credentials configured exits 0. Read ``coverage`` -- rendered as the ``provider_coverage``
      line on every console block and carried as ``coverage.headline`` in ``-o json`` -- before
      drawing any conclusion from sparse output.
``1`` The orchestrator returned ``ok=False``: an intelligence blackout (no provider answered at
      all), a wall-clock deadline breach, a non-public target this tool refuses to forward to a
      third party, or a target the orchestrator rejected as malformed. Nothing was learned, and
      the console prints the coverage line so the operator can see which providers to fix.
``2`` The CLI rejected the input before any provider was consulted: an unparseable or defanged
      target, a non-numeric ASN, an indicator type no subcommand can investigate, or no
      subcommand.
===== =========================================================================================

**Zero-quota modes.** ``check --detect-only`` and ``bulk`` (without ``--investigate``) classify
locally and consult nobody. They exit ``0`` on a successful classification and ``2`` when the
input could not be classified at all. Nothing in either path constructs an HTTP client.

**Defanging.** Human-facing output brackets the indicator by default -- ``evil[.]example``,
``hxxps[://]…`` -- because a recon report gets pasted into tickets and chat, where a live URL is
one click from a compromise and, for a single-use link, one click from burning the
investigation. ``--fanged`` turns it off. Third-party pivot links are never defanged: they point
at VirusTotal, Shodan, AbuseIPDB and Cloudflare Radar rather than at the target, and being
clickable is the point of them. **``-o json`` is never defanged either** -- machines consume it
and ``evil[.]example`` is not a hostname.

The ``ok`` rule itself belongs to :mod:`tripper_recon.orchestrators`; see the ``ok`` contract in
its module docstring. Code ``1`` versus code ``2`` is the only distinction this module adds:
``2`` means no request ever left, ``1`` means requests left and taught us nothing.

**The exit code is not the verdict.** It reports whether the lookup worked, not what the lookup
found: a ``MALICIOUS`` indicator with every provider answering exits ``0``. Read
``data['verdict']`` -- printed as the first line of every console block and carried whole in
``-o json`` -- for the answer. A pipeline that wants to branch on maliciousness reads that
field. ``docs/review/design-verdict-engine.md`` §7.1 proposes a ``--fail-on`` flag that would
fold the verdict into the exit code; it is not implemented, and until it is, the codes above
mean exactly what this table says and nothing more.

One extension to code ``1``, added with the artefact flags (roadmap 7.3/7.7): a run that
completed but could not write an artefact the operator explicitly asked for -- ``--out`` or
``--case-dir`` -- also exits ``1``. Exiting ``0`` there would leave a pipeline believing it holds
a report it does not hold, which is the same class of error as a clean-looking blackout.

**Caching, and the one rule that governs it** (roadmap 7.7). A domain with eight A records costs
nine VirusTotal calls per run, and re-running the same investigation an hour later pays for it
again, so answers are cached on disk with a per-provider lifetime. The rule that makes that
defensible rather than dangerous: **a cached fact must never claim to have been queried now.**

* Every cached value carries the instant it was actually obtained, and that instant is never
  rewritten on replay.
* Every replay is disclosed -- on ``provider_status[<name>]['cache']``, in the ``freshness``
  block of ``-o json``, and as the first warning on the console.
* ``--offline`` contacts nobody, including the system resolver. When it cannot answer from cache
  it says so and loses the coverage, rather than serving an expired value as though it were
  current.
* ``--max-age`` is the analyst's freshness demand: anything older is re-queried, or, offline,
  refused.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any, Coroutine, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlparse

from rich.console import Console

from tripper_recon import __version__
from tripper_recon.orchestrators import (
    DEFAULT_URL_DEPTH,
    SCOPE_ASN,
    SCOPE_DOMAIN,
    SCOPE_IP,
    SCOPE_URL,
    URL_DEPTHS,
    investigate_asn,
    investigate_domain,
    investigate_ip,
    investigate_url,
    non_public_ip_reason,
)
from tripper_recon.reporting.console import (
    TRIAGE_CAVEAT,
    defang_indicator,
    esc,
    indicator_text,
    no_data_text,
    provider_outcome,
    render_asn_bgp_panels,
    render_asn_header,
    render_coverage,
    render_detection,
    render_domain_header,
    render_filtered_indicators,
    render_ip_analysis,
    render_triage_table,
    render_url_analysis,
    render_verdict,
    run_fields,
)
from tripper_recon.reporting.markdown import MarkdownOptions, md_code, md_escape, md_table, render_markdown
from tripper_recon.types.indicators import Indicator, IndicatorType, detect
from tripper_recon.types.models import InvestigationResult
from tripper_recon.utils.cache import (
    CacheError,
    CacheSession,
    CacheStore,
    default_cache_root,
    default_case_root,
    load_case,
    parse_duration,
    use_cache,
    write_case,
)
from tripper_recon.utils.env import load_env
from tripper_recon.utils.evidence import EvidenceRecorder, active_recorder, capture_evidence
from tripper_recon.utils.http import configure_rate_limit, configure_user_agent
from tripper_recon.utils.logging import logger
from tripper_recon.utils.refang import refang

log = logger("cli")
console = Console()

#: ``--explain``. The flag exists because a verdict an analyst cannot audit is a verdict a SOC
#: learns to ignore: it prints every signal, the points it was worth out of its own ceiling, the
#: ruleset key that set that ceiling, the provider values behind it, and every confidence
#: criterion the engine asked. Console output only -- ``-o json`` already carries all of it.
_EXPLAIN_HELP = "Show the full signal breakdown behind the verdict: every weight, its ruleset key, and its evidence"

#: The output formats every investigating subcommand accepts.
#:
#: ``markdown`` is the form that survives the workflow the tool exists for -- an analyst pasting
#: the answer into a ticket. ``console`` paints a terminal and `rich` strips its colour the moment
#: the output is redirected, taking the only malice signal with it; ``json`` feeds a machine.
_FORMATS = ["console", "json", "markdown"]

#: What ``report --from-case`` accepts. ``console`` is deliberately absent: see :func:`_cmd_report`.
_REPORT_FORMATS = ["json", "markdown"]


# --------------------------------------------------------------------------------------
# --help (roadmap 9.11)
#
# `--help` is the only documentation an analyst reads at 02:00, so the three things that get
# a run misread live in it rather than in a file nobody opens: what the exit code does and
# does not claim, which variable feeds which provider, and why an empty panel is not a clean
# result. The blocks below are assembled into the top-level `epilog`; each subparser carries
# its own note naming the providers that path consults.
#
# Every provider list here is a transcription of the declared tuples in `orchestrators` --
# IP_PROVIDERS, DOMAIN_PROVIDERS, URL_PROVIDERS, ASN_PROVIDERS -- and not of the calls a run
# happens to make. Those tuples are the denominator of the coverage ratio the help text tells
# the reader to trust, so the two have to be the same list.
# --------------------------------------------------------------------------------------

#: The exit-code contract, in the wording of this module's docstring. Duplicated into the help
#: text on purpose: the docstring is for whoever reads the source, and a playbook author
#: branching on `$?` reads `--help`. The full contract, with the reasoning, stays in the
#: docstring; this is the operative summary.
_EXIT_CODES = """\
exit codes:
  0   A provider answered. This is NOT a claim that the indicator is clean and NOT a claim
      that the lookup was complete -- a run with two of six credentials set exits 0. Read the
      provider_coverage line ("N of M providers answered") before concluding anything.
  1   Nothing was learned: no provider answered at all, the wall-clock deadline was breached,
      the target is not public and this tool will not forward it to a third party, or the
      orchestrator rejected it as malformed. Also: the run completed but an artefact you asked
      for (--out, --case-dir) could not be written.
  2   The input was rejected before any provider was consulted: an unparseable target, a
      non-numeric ASN, an indicator type no subcommand investigates, or no subcommand at all.
      `check --detect-only` and `bulk` also exit 2 when nothing could be classified.

  The exit code is not the verdict. It says whether the lookup worked, not what it found: a
  MALICIOUS indicator with every provider answering exits 0. The verdict is the first line of
  every console block and the `verdict` key in `-o json`."""

#: Every variable this package reads. Credentials come from `orchestrators._env_keys`, the two
#: behaviour knobs from `utils.http` and `utils.logging`, and the two path overrides from
#: `verdict.config` and `verdict.known_infrastructure`.
_ENVIRONMENT = """\
environment:
  Read from the process environment, and from a .env file in the current directory or the
  package root -- whichever is found first (utils/env.py).

  Provider credentials. A variable that is unset means that provider is never asked:
    VT_API_KEY             VirusTotal v3 reports          ip, domain, url
    SHODAN_API_KEY         Shodan host records            ip, domain, url
    ABUSEIPDB_API_KEY      AbuseIPDB /check               ip, domain, url
    OTX_API_KEY            AlienVault OTX pulses          ip, domain, url
    IPINFO_TOKEN           IPinfo address records         ip, domain, url, asn
                           (the ASN record needs a paid plan; a 401/403 there is suppressed)
    CLOUDFLARE_API_TOKEN   Cloudflare Radar and BGP       ip, domain, url, asn

  RIPEstat, CAIDA AS-Rank and PeeringDB need no credential, which is why
  `tripper-recon asn 15169` works with an empty .env.

  Behaviour:
    TRIPPER_RECON_LOG_LEVEL   DEBUG, INFO, WARN, ERROR, or a number. Default 20 (INFO).
                              Logs go to stderr so they never mix with `-o json` on stdout.
    TRIPPER_RECON_USER_AGENT  User-Agent sent to providers. `--user-agent` overrides it.

  Verdict engine:
    TRIPPER_RECON_SCORING_CONFIG        A scoring ruleset to load instead of
                                        $XDG_CONFIG_HOME/tripper_recon/scoring.yaml and the
                                        packaged default. A path that does not exist is an
                                        error, never a silent fallback.
    TRIPPER_RECON_KNOWN_INFRASTRUCTURE  A known-infrastructure catalogue to load instead of
                                        the packaged one.
    XDG_CONFIG_HOME                     Where the user ruleset is looked for. Defaults to
                                        ~/.config.

  Cache:
    TRIPPER_RECON_CACHE_DIR             Where cached provider answers live. `--cache-dir`
                                        overrides it. Defaults to
                                        $XDG_CACHE_HOME/tripper_recon.
    TRIPPER_RECON_CACHE_CONFIG          A per-provider TTL ruleset to load instead of
                                        $XDG_CONFIG_HOME/tripper_recon/cache.yaml and the
                                        packaged default. A path that does not exist is an
                                        error, never a silent fallback.
    XDG_CACHE_HOME                      Where the cache is looked for. Defaults to ~/.cache."""

#: The "why is my output empty" answer, and the pointer to the file that answers it in full.
_EMPTY_OUTPUT = """\
why is my output empty:
  A provider with no credential is never asked, and a provider that was not asked renders as
  "no data" -- never as a zero, and never in green. Absence does not score as clean. The
  provider_coverage line on every console block, and coverage.headline in `-o json`, say how
  many of the expected providers answered.

  docs/PROVIDERS.md lists every provider, the variable it needs, the commands that use it and
  the fields it keeps. Start there when a panel is thinner than expected.

  The verdict engine's weights are unvalidated priors -- calibration.status is "unvalidated"
  and the tool makes no accuracy claim. Treat a verdict as a ranked reading of the evidence
  shown, not as a measurement."""

#: The cache, and the honesty rules that make it safe to ship.
_CACHING = """\
caching and freshness:
  Provider answers are cached on disk with a per-provider lifetime, because a domain with eight
  A records costs nine VirusTotal calls per run and re-running it an hour later pays again.
  The lifetimes are policy, not code: they live in cache.yaml, longest for registration data
  and shortest for reputation feeds and DNS.

  A CACHED FACT NEVER CLAIMS TO HAVE BEEN QUERIED NOW. Every cached value carries the instant
  it was actually obtained; that instant is never rewritten on replay; and every replay is
  disclosed in three places -- the first console warning, provider_status[<name>].cache, and
  the `freshness` block in `-o json`, which states how many answers were queried now, how many
  were replayed, and how old the oldest one is.

    --offline     Contact nobody at all, including the system resolver. Answers come from
                  cache or not at all. A question the cache cannot answer is reported as
                  missing coverage with the reason -- never served from an expired entry.
    --max-age D   Refuse anything cached older than D (30, 90s, 15m, 6h, 7d, 2w). Online this
                  forces a fresh lookup; offline it turns a stale entry into a stated gap.
                  `--max-age 0` means "query everything now".
    --no-cache    Read nothing from the cache and write nothing to it.
    --cache-dir   Where cached answers live. Outside the repo by default.

  Only successful answers are cached. An error is a state of the world at one instant, and
  replaying it would outlive its cause."""

#: Where a report can be written, and what regenerating one does and does not re-query.
_ARTEFACTS = """\
saving a report:
    --out PATH        Write the report to PATH. `-o json` writes JSON; `-o markdown` and the
                      default `-o console` both write Markdown, because console output is
                      ANSI-decorated and box-drawn and is not a document. A bare filename
                      lands in ./outputs/ -- the working directory's, never the package's.
    --case-dir DIR    Write the whole run to DIR/<scope>-<case id>/<run id>/: case.json (the
                      result, the verdict, the cache record), report.md, and the evidence
                      envelopes when --evidence is on. Defaults to ./outputs/cases.
    --evidence        Capture the raw provider exchanges -- status, timings, hashes, redacted
                      bodies -- into the case directory. Requires --case-dir.

  tripper-recon report --from-case DIR
      Rebuild the report from a case directory. Contacts nobody and spends no quota, and the
      timestamps are the ORIGINAL ones: regenerating a report does not make its facts newer."""

#: Worked examples. Each one is a command that runs as written against the parser below.
_EXAMPLES = """\
examples:
  tripper-recon asn 15169
      ASN identity, routing status, neighbours and IXP presence. Runs against an empty .env:
      RIPEstat, CAIDA and PeeringDB carry this command on their own.

  tripper-recon ip 8.8.8.8 --explain
      One address, with the full signal breakdown behind the verdict -- every weight, the
      ruleset key that set its ceiling, and the provider value behind it.

  tripper-recon domain example.com -o json
      Domain report as JSON. `-o json` is never defanged, and may be given before or after
      the subcommand.

  tripper-recon url 'hxxps://evil[.]example/login' --depth host
      A defanged link is refanged and looked up. `--depth host` adds the host's reputation
      and still resolves nothing; the default `--depth full` resolves the host through the
      system resolver.

  tripper-recon check '1[.]2[.]3[.]4' --detect-only
      Classify a pasted string and stop. Costs no provider quota -- detection is a pure
      function over the string and no HTTP client is built.

  tripper-recon bulk phishing-email.txt --investigate --max-targets 5
      Extract and triage every indicator in a wall of pasted text, then look up the first
      five routable ones. Triage alone costs no provider quota; `--investigate` is the opt-in
      that spends it.

  tripper-recon --offline domain evil.example
      Answer from cache only. Nothing is contacted -- not a provider, not the resolver -- and
      any question the cache cannot answer is reported as missing coverage with the reason.

  tripper-recon --max-age 15m ip 8.8.8.8 -o markdown --case-dir ./cases --evidence
      Refuse anything cached older than fifteen minutes, print the ticket-ready markdown, and
      save the result, the report and the raw provider exchanges for later regeneration.

  (`report --from-case`, which rebuilds a saved case, is in the "saving a report" section
  below: its example names a real case directory and so cannot be a copy-paste line here.)"""

_EPILOG = "\n\n".join((_EXAMPLES, _EXIT_CODES, _ENVIRONMENT, _EMPTY_OUTPUT, _CACHING, _ARTEFACTS))

_IP_EPILOG = """\
providers consulted (the denominator of the coverage ratio):
  VirusTotal, IPinfo, Shodan, AbuseIPDB, OTX, then Cloudflare Radar for the ASN IPinfo
  reported. Cloudflare runs in a second wave and is only reachable when IPinfo answered with
  an ASN -- it stays in the denominator either way, so a failed IPinfo lookup does not
  quietly improve the coverage ratio.

  Nothing here contacts the address. Every call reads a report the provider already holds."""

_DOMAIN_EPILOG = """\
providers consulted (the denominator of the coverage ratio):
  About the name itself: VirusTotal and OTX.
  Then, for every public address the name resolves to: VirusTotal, IPinfo, Shodan, AbuseIPDB,
  OTX and Cloudflare Radar -- the full `ip` set, per address.

  Addresses come from two sources and are labelled with which: VirusTotal's passive A/AAAA
  records, and the system resolver. This command always resolves. That resolver egress is the
  one documented exception to passivity and an accepted risk, not an oversight -- see
  docs/OPSEC.md. Private and reserved addresses are refused before any provider sees them and
  are reported as skipped rather than dropped.

  A domain with eight addresses costs eight times the per-address provider set, plus the two
  domain-level calls."""

_ASN_EPILOG = """\
providers consulted (the denominator of the coverage ratio):
  IPinfo (/AS{n}, paid plan), five RIPEstat endpoints (as-overview, abuse-contact-finder,
  routing-status, asn-neighbours, announced-prefixes), CAIDA AS-Rank, PeeringDB, Cloudflare
  Radar ASN metadata and Cloudflare BGP incidents.

  RIPEstat, CAIDA and PeeringDB need no credential, so this command produces a usable report
  against an empty .env. `--prefixes-out` writes the full announced-prefix list RIPEstat
  returned; the console panel never prints it in full."""

_URL_EPILOG = """\
providers consulted (the denominator of the coverage ratio):
  About the link itself: VirusTotal's URL report. That is the whole URL-scope set today.
  urlscan.io is implemented and its host is allowlisted, but it is not yet wired into this
  path -- see docs/PROVIDERS.md.

  `--depth` decides how much further it goes:
    url    the link's own report only.
    host   plus the host's reputation (VirusTotal and OTX about the name). Resolves nothing.
    full   plus every public address the host resolves to, each through the `ip` provider
           set. This is the default and the only depth that uses the system resolver.

  A 404 from VirusTotal means nobody has ever submitted this URL. For a freshly registered
  phishing link that is the ordinary state of the world: it is UNKNOWN, not clean. Nothing in
  this path asks a provider to go and fetch the target."""

_CHECK_EPILOG = """\
  `check` classifies the string, prints what it read, then routes to `ip`, `domain`, `url` or
  `asn` -- so the providers consulted are that subcommand's. `--detect-only` stops after the
  classification and consults nobody.

  An analyst who knows what they are holding should keep saying so: `ip 1.2.3.4` cannot be
  misrouted and `check 1.2.3.4` theoretically can. `check` is for the string of unknown shape,
  possibly defanged, pasted under time pressure."""

_REPORT_EPILOG = """\
  Rebuilds a report from a case directory written by --case-dir. It contacts nobody, builds no
  HTTP client, and spends no quota -- regeneration is a pure function from the saved record to
  a document.

  The timestamps are the ORIGINAL ones. A regenerated report says when the evidence was
  collected, not when it was re-rendered; re-stamping it would be the same lie as a cache that
  claims a replayed answer was queried now.

  `console` is not an output format here. The console renderers are driven from a live result
  through six code paths, and a half-supported reimplementation would differ from what the run
  actually printed."""

_BULK_EPILOG = """\
  Triage is the default and it costs nothing: extraction and classification are pure, so a run
  without `--investigate` makes no request at all. It is safe to paste an entire phishing
  email into this command.

  `--investigate` routes each surviving indicator through `check`, so the providers consulted
  are those of the subcommand each one routes to. `--max-targets` caps how many are looked up.

  Nothing is deleted. Indicators withheld by the RFC1918 guard or the mail-infrastructure
  heuristic are printed in their own table with the reason."""


def _fmt_provider_error(detail: Any) -> str:
    if isinstance(detail, dict):
        parts: list[str] = []
        status = detail.get("status_code") or detail.get("status")
        if status is not None:
            parts.append(f"status={status}")
        reason = detail.get("reason")
        if reason:
            parts.append(f"reason={reason}")
        message = detail.get("message")
        if message:
            parts.append(f"message={message}")
        url = detail.get("url")
        if url and not status and not reason and not message:
            # Just an empty URL without a real error gets noisy
            return "Connection Timeout / Network Error"
        elif url:
            parts.append(f"url={url}")
        body = detail.get("body")
        if body:
            parts.append(f"body={body}")
        return " | ".join(parts) if parts else "Unknown error"
    return str(detail)


def _fmt_dn(value: Any) -> str:
    if isinstance(value, dict):
        parts: List[str] = []
        for k, v in value.items():
            if isinstance(v, list):
                joined = ", ".join(str(item) for item in v)
                parts.append(f"{k}={joined}")
            else:
                parts.append(f"{k}={v}")
        return ", ".join(parts)
    return str(value)


def _print_whois_block(whois: Any) -> None:
    if not whois:
        return
    entries: List[tuple[str, str]] = []
    for raw_line in str(whois).splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        entries.append((key.strip(), value.strip()))
    if not entries:
        return

    priority = [
        "Domain Name",
        "Registry Domain ID",
        "Registrar",
        "Registrar IANA ID",
        "Registrar URL",
        "Registrar WHOIS Server",
        "Registrar Abuse Contact Email",
        "Registrar Abuse Contact Phone",
        "Updated Date",
        "Creation Date",
        "Registry Expiry Date",
        "Domain Status",
        "Name Server",
        "DNSSEC",
    ]

    console.print("\n[bold white]Whois Lookup[/]")
    for key in priority:
        target = key.lower()
        for k, v in entries:
            if k.lower() == target:
                console.print(f"  [cyan]{esc(k)}[/]: {esc(v)}")
    console.print()


def _has_cert_value(value: Any) -> bool:
    """True when a certificate field actually carries something.

    Nested one level because ``vt_last_https_certificate`` holds ``issuer``, ``subject`` and
    ``validity`` sub-dicts that are themselves present-but-empty when VirusTotal held no
    certificate.
    """
    if isinstance(value, dict):
        return any(_has_cert_value(item) for item in value.values())
    return bool(value)


def _print_certificate_block(cert: Dict[str, Any], jarm: Any) -> None:
    # `vt_domain_summary` always emits this key as a fully-shaped dict whose values are all
    # None when VirusTotal held no certificate, so `if not cert` never fired and the report
    # carried a "Last HTTPS Certificate" heading with nothing under it. An empty heading reads
    # as a rendering failure, and a reader cannot tell it from a certificate the tool dropped.
    has_cert = bool(cert) and any(_has_cert_value(value) for value in cert.values())
    if not has_cert and not jarm:
        return
    console.print("[bold white]Last HTTPS Certificate[/]")
    if jarm:
        console.print(f"  [cyan]JARM fingerprint[/]: {esc(jarm)}")
    for key, label in [
        ("version", "Version"),
        ("serial_number", "Serial Number"),
        ("thumbprint_sha256", "Thumbprint"),
        ("signature_algorithm", "Signature Algorithm"),
    ]:
        val = cert.get(key)
        if val:
            console.print(f"  [cyan]{label}[/]: {esc(val)}")

    issuer = cert.get("issuer")
    if issuer:
        console.print(f"  [cyan]Issuer[/]: {esc(_fmt_dn(issuer))}")

    validity = cert.get("validity") or {}
    if validity.get("not_before"):
        console.print(f"  [cyan]Not Before[/]: {esc(validity.get('not_before'))}")
    if validity.get("not_after"):
        console.print(f"  [cyan]Not After[/]: {esc(validity.get('not_after'))}")

    subject = cert.get("subject")
    if subject:
        console.print(f"  [cyan]Subject[/]: {esc(_fmt_dn(subject))}")
    console.print()


def _print_failure_coverage(data: Dict[str, Any]) -> None:
    """Name the providers behind a failed lookup, when the orchestrator recorded them.

    ``ok=False`` for an intelligence blackout still returns the full ``data`` -- coverage, run
    metadata and per-provider status -- precisely so the operator can see *why* nothing came
    back. Printing the error sentence alone throws that away and leaves "the lookup failed"
    with no attribution, which for a blackout caused entirely by unset API keys is the least
    actionable message the tool can produce.
    """
    if not isinstance(data, dict):
        return
    source = data.get("coverage") or data.get("provider_status") or data.get("domain_provider_status")
    if source:
        console.print(render_coverage(source))
        console.print()


# --------------------------------------------------------------------------------------
# Artefacts: --out, --case-dir, and the markdown document form (roadmap 7.2, 7.3, 7.7)
# --------------------------------------------------------------------------------------


def _default_output_dir() -> Path:
    """``<cwd>/outputs``. The **working** directory's, which is roadmap 7.3's whole point.

    This used to resolve against ``Path(__file__).parent.parent``. After the README's own
    ``pip install .`` that is ``site-packages``, so a bare ``--prefixes-out foo.txt`` wrote the
    analyst's evidence into the installed package and reported success. Nothing failed, nothing
    warned, and the file was not where they looked for it.

    ``outputs/`` is also the one directory ``.gitignore`` ignores wholesale, so a bare filename
    lands somewhere that cannot be committed by accident.
    """
    return Path.cwd() / "outputs"


def _resolve_artefact_path(value: str) -> Path:
    """A bare filename lands in ``./outputs/``; anything with a directory is taken literally.

    The path comes from the analyst's own argv on the analyst's own workstation, so there is no
    containment check here and no trust boundary to enforce -- see the roadmap's "deliberately
    not doing" entry. What there is: the parent directory is created, so ``--out reports/x.md``
    does not fail on a directory that does not exist yet.
    """
    path = Path(value).expanduser()
    if path.parent == Path("."):
        return _default_output_dir() / path.name
    return path


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")


def _result_payload(result: Any) -> Dict[str, Any]:
    """The ``data`` mapping, whether ``result`` is the model, its dump, or the bare data."""
    if isinstance(result, InvestigationResult):
        return result.data
    if isinstance(result, Mapping):
        inner = result.get("data")
        if isinstance(inner, Mapping):
            return dict(inner)
        return dict(result)
    return {}


def _report_clock(result: Any) -> Optional[dt.datetime]:
    """When collection started, as a datetime, or ``None``.

    ``MarkdownOptions.now`` is the renderer's only clock, and handing it the collection start is
    deliberate: a report regenerated from a case months later must carry the time the evidence
    was gathered, not the time somebody re-rendered it. ``None`` renders as "not recorded",
    which is the honest output when the payload never carried a run block -- the renderer will
    not read the wall clock to fill the gap, and neither will this function.
    """
    if isinstance(result, InvestigationResult) and result.run is not None:
        return result.run.started_at
    run: Any = result.get("run") if isinstance(result, Mapping) else None
    if not isinstance(run, Mapping):
        run = _result_payload(result).get("run")
    if not isinstance(run, Mapping):
        return None
    raw = run.get("started_at")
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip()
    if text.endswith(("Z", "z")):
        text = f"{text[:-1]}+00:00"
    try:
        return dt.datetime.fromisoformat(text)
    except ValueError:
        return None


def _freshness_markdown(data: Mapping[str, Any]) -> List[str]:
    """The freshness disclosure, as a markdown section. Empty when no cache was in use.

    **This is the artefact the rule is ultimately about.** The console warning scrolls away and
    the JSON is read by a machine; the markdown is what gets pasted into a ticket and read three
    weeks later by somebody who was not there. If it does not say which answers were replayed and
    how old they were, the disclosure chain ends one step short of the reader who needs it.

    Emitted only when ``data['freshness']`` exists -- that is, only when a cache session was in
    force -- so a report from a run that cached nothing looks exactly as it did before.
    """
    freshness = data.get("freshness")
    if not isinstance(freshness, Mapping):
        return []

    lines: List[str] = ["## Freshness", "", f"**{md_escape(freshness.get('headline'))}**", ""]

    cached = [row for row in (freshness.get("from_cache") or []) if isinstance(row, Mapping)]
    if cached:
        lines.extend(
            md_table(
                ["provider", "actually queried at", "age when this report was produced"],
                [
                    [
                        md_code(row.get("provider"), in_table=True),
                        md_escape(row.get("queried_at") or "not recorded"),
                        md_escape(row.get("age") or "unknown"),
                    ]
                    for row in cached
                ],
            )
        )
        lines.extend(
            [
                "",
                "Each row above was **replayed from cache**. It was obtained at the time shown and was "
                "**not** queried when this report was produced.",
                "",
            ]
        )

    refused = [row for row in (freshness.get("unanswerable_offline") or []) if isinstance(row, Mapping)]
    if refused:
        lines.extend(
            md_table(
                ["not asked", "why"],
                [[md_code(row.get("provider"), in_table=True), md_escape(row.get("reason"))] for row in refused],
            )
        )
        lines.extend(
            [
                "",
                "These questions were not put to anyone. That is missing coverage, not a clean result.",
                "",
            ]
        )

    if not cached and not refused:
        lines.append("Every answer in this report was queried during the run that produced it.")
    while lines and lines[-1] == "":
        lines.pop()
    return lines


def _markdown_report(result: Any, *, indicator: str, scope: str, defang: bool) -> str:
    """The ticket-ready document form of one result, per-address blocks included.

    ``render_markdown`` renders exactly one subject and says so; composing a domain's or a URL's
    per-address blocks underneath it is the caller's decision, which is here. Each address block
    is rendered one heading level deeper so the whole thing is a single well-formed document
    rather than four reports stapled together.
    """
    now = _report_clock(result)
    data = _result_payload(result)
    blocks = [
        render_markdown(
            result,
            MarkdownOptions(indicator=indicator, indicator_type=scope, now=now, defang=defang),
        )
    ]
    freshness = _freshness_markdown(data)
    if freshness:
        blocks.append("\n".join(freshness) + "\n")
    for entry in _result_payload(result).get("ips") or []:
        if not isinstance(entry, Mapping):
            continue
        address = str(entry.get("ip") or "").strip()
        if not address:
            continue
        blocks.append(
            render_markdown(
                entry,
                MarkdownOptions(indicator=address, indicator_type=SCOPE_IP, now=now, defang=defang, heading_level=2),
            )
        )
    return "\n".join(blocks)


def _report_document(result: Any, *, indicator: str, scope: str, output: str, defang: bool) -> str:
    """What ``--out`` writes: JSON for ``-o json``, markdown for everything else.

    ``-o console`` deliberately writes markdown rather than the terminal rendering. The console
    form is ANSI-decorated and box-drawn; `rich` strips the colour the moment it is redirected,
    which leaves a file whose only malice signal has silently vanished -- the exact defect the
    markdown lane was built to fix.
    """
    if output == "json":
        payload = result.model_dump(mode="json") if isinstance(result, InvestigationResult) else result
        return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    return _markdown_report(result, indicator=indicator, scope=scope, defang=defang)


def _persist_artefacts(
    result: Any,
    *,
    indicator: str,
    scope: str,
    output: str,
    defang: bool,
    out: Optional[str],
    case_dir: Optional[str],
) -> bool:
    """Write ``--out`` and ``--case-dir``. Returns False when either was asked for and failed.

    The failure is loud and it changes the exit code, because the alternative is a pipeline that
    believes it holds a report it does not hold. Notices go to the LOG (stderr) rather than to
    the console, so they cannot land in the middle of ``-o json`` on stdout.
    """
    if not out and not case_dir:
        return True

    ok = True
    if out:
        path = _resolve_artefact_path(out)
        try:
            _write_text(path, _report_document(result, indicator=indicator, scope=scope, output=output, defang=defang))
            log["info"]("Wrote report", path=str(path), format="json" if output == "json" else "markdown")
        except OSError as exc:
            log["error"]("Failed writing the report", path=str(path), error=str(exc))
            ok = False

    if case_dir:
        recorder = active_recorder()
        run_id, _started, _version = run_fields(_result_payload(result).get("run"))
        try:
            paths = write_case(
                Path(case_dir).expanduser(),
                result=result,
                indicator=indicator,
                scope=scope,
                run_id=run_id,
                evidence=recorder.records if recorder is not None else (),
                evidence_complete=recorder.is_complete if recorder is not None else True,
                evidence_dropped=recorder.dropped if recorder is not None else 0,
                report=_markdown_report(result, indicator=indicator, scope=scope, defang=defang),
                cache_summary=_result_payload(result).get("cache"),
            )
            log["info"](
                "Wrote case directory",
                path=str(paths.directory),
                evidence=paths.evidence_written,
                git_ignored=str(paths.directory).find("outputs") >= 0,
            )
            if recorder is not None and not recorder.is_complete:
                log["warn"](
                    "The evidence set is INCOMPLETE: records were dropped at the recorder's ceiling",
                    dropped=recorder.dropped,
                )
        except (CacheError, OSError) as exc:
            log["error"]("Failed writing the case directory", path=str(case_dir), error=str(exc))
            ok = False

    return ok


def _load_ip_targets(value: str) -> tuple[List[str], str | None]:
    p = Path(value).expanduser()
    if not p.is_file():
        return [value], None

    targets: List[str] = []
    for raw in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line)
    return list(dict.fromkeys(targets)), str(p)


async def _cmd_ip(
    ip: str,
    *,
    output: str = "console",
    ports_limit: str = "25",
    explain: bool = False,
    defang: bool = False,
    out: Optional[str] = None,
    case_dir: Optional[str] = None,
) -> int:
    targets, source_file = _load_ip_targets(ip)
    if source_file and not targets:
        log["error"]("IP list file is empty", file=source_file)
        return 1

    if output == "console" and source_file:
        console.print(f'\n[bold green]Processing {len(targets)} targets from "{source_file}"[/]\n')

    tasks = [investigate_ip(t) for t in targets]
    gathered = await asyncio.gather(*tasks, return_exceptions=True)

    results: List[Dict[str, Any]] = []
    answered: List[Tuple[str, InvestigationResult]] = []
    failed = 0
    succeeded = 0

    for target, item in zip(targets, gathered, strict=True):
        # BaseException, not Exception. asyncio.CancelledError has inherited from BaseException
        # since 3.8, so an `isinstance(item, Exception)` test lets a cancelled target fall
        # through to `res.ok` and raise AttributeError. That is currently unreachable, but a
        # per-target deadline (roadmap 3.7) makes cancellation routine -- narrow it now.
        if isinstance(item, BaseException):
            # An interrupt is the operator asking to stop, not a target that failed to resolve.
            if isinstance(item, (KeyboardInterrupt, SystemExit)):
                raise item
            err = item
            msg = f"{type(err).__name__}: {err}"
            log["error"]("IP investigation crashed", ip=target, error=msg)
            failed += 1
            results.append({"target": target, "ok": False, "warnings": [], "errors": [msg], "data": {}})
            if output == "console":
                console.print(f"[bold red]IP: {indicator_text(target, defang=defang)}[/]")
                console.print(f"  error: {esc(msg)}\n")
            continue

        res = item

        if not res.ok:
            log["error"]("IP investigation failed", ip=target, errors=res.errors)
            failed += 1
            results.append({"target": target, **res.model_dump()})
            if output == "console":
                console.print(f"[bold red]IP: {indicator_text(target, defang=defang)}[/]")
                console.print(f"  error: {esc('; '.join(res.errors)) if res.errors else 'Investigation failed'}\n")
                _print_failure_coverage(res.data)
            continue

        succeeded += 1
        results.append({"target": target, **res.model_dump()})
        answered.append((target, res))
        if output == "console":
            panel = render_ip_analysis(target, res.data, ports_limit=ports_limit, explain=explain, defang=defang)
            console.print(panel)
            console.print()
        elif output == "markdown":
            # Written raw, never through the console: `rich` would re-wrap the tables and reparse
            # the brackets defanging deliberately puts in.
            sys.stdout.write(_markdown_report(res, indicator=target, scope=SCOPE_IP, defang=defang))
            sys.stdout.write("\n")

    if output == "json":
        payload = {
            "ok": failed == 0,
            "source_file": source_file,
            "total": len(targets),
            "succeeded": succeeded,
            "failed": failed,
            "results": results,
        }
        console.print_json(data=payload)
    elif output == "console":
        color = "green" if failed == 0 else "yellow"
        console.print(f"[{color}]Summary:[/] total={len(targets)} succeeded={succeeded} failed={failed}")

    # One case directory per target, because a case is about an indicator. `--out`, which is one
    # file, gets every target's report concatenated -- for a single address, the common case,
    # the two are the same thing.
    written = True
    for target, res in answered:
        if case_dir and not _persist_artefacts(
            res, indicator=target, scope=SCOPE_IP, output=output, defang=defang, out=None, case_dir=case_dir
        ):
            written = False
    if out and answered:
        if output == "json":
            document = json.dumps(results, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        else:
            document = "\n".join(
                _markdown_report(res, indicator=target, scope=SCOPE_IP, defang=defang) for target, res in answered
            )
        path = _resolve_artefact_path(out)
        try:
            _write_text(path, document)
            log["info"]("Wrote report", path=str(path), targets=len(answered))
        except OSError as exc:
            log["error"]("Failed writing the report", path=str(path), error=str(exc))
            written = False

    if not written:
        return 1
    return 0 if failed == 0 else 1


_DEFANG_MARKERS = ("hxxp", "hxxps", "[.]", "(.)", "[dot]", "[:]", "[//]")


def _looks_defanged(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in _DEFANG_MARKERS)


def _refang_target(value: str, *, output: str) -> tuple[str, str | None]:
    """Refang a pasted indicator and announce the change.

    Defanged indicators are the normal form an analyst pastes -- they arrive that way from email,
    tickets and threat reports. Refusing them and demanding a retype is friction at the worst
    possible moment, and the tool already carries a tested, idempotent refang transform.

    The change is never silent: the console says exactly which transforms fired, and the raw form
    is preserved for anything that renders a report (roadmap 6.1, 6.2). Returns the value to
    investigate and the human-readable note, or the input unchanged when nothing was defanged.
    """
    result = refang(value)
    if not result.was_defanged:
        return value, None
    note = f"refanged for lookup ({', '.join(result.transforms)}): {result.raw} -> {result.value}"
    log["info"]("Refanged target", raw=result.raw, value=result.value, transforms=list(result.transforms))
    if output == "console":
        console.print(f"[yellow]note:[/] {esc(note)}")
    return result.value, note


def _print_domain_intel(
    norm_domain: str,
    domain_intel: Any,
    domain_status: Any,
    *,
    defang: bool,
) -> Dict[str, Any]:
    """Print the domain-level intelligence rows and return VirusTotal's block for the caller.

    Extracted so the ``url`` subcommand shows the same host-level rows the ``domain``
    subcommand does, from the same code. The alternative -- a second copy for the URL path --
    would drift, and the rows it would drift on are the "no data" rows that stop an unset API
    key from rendering as a clean result.

    Pivot links are printed live and undefanged on purpose: every one of them points at a
    third party that already holds the data, never at the target.
    """
    console.print("[bold]domain_intelligence:[/]")
    console.print(f"  [cyan]domain[/]: {indicator_text(norm_domain, defang=defang)}")
    console.print(f"  [cyan]cloudflare_radar_link[/]: https://radar.cloudflare.com/domain/{norm_domain}")

    vt_dom_raw = domain_intel.get("virustotal") if isinstance(domain_intel, dict) else None
    vt_dom: Dict[str, Any] = vt_dom_raw if isinstance(vt_dom_raw, dict) else {}
    vt_stats = vt_dom.get("vt_last_analysis_stats") or {}
    vt_total = 0
    if isinstance(vt_stats, dict):
        vt_total = sum(int(v or 0) for v in vt_stats.values() if str(v).isdigit())
    vt_mal = int(vt_stats.get("malicious", 0) or 0) if isinstance(vt_stats, dict) else 0

    if vt_total <= 0:
        # The IP path stopped rendering a manufactured `0/0` in W0.2; the domain path kept
        # doing it for two more workstreams. An unset VT key summed an absent stats dict to
        # zero and printed a green `0/0`, which is the exact equivalence -- absence rendered as
        # a clean verdict -- that this whole workstream exists to remove.
        vt_no_data = no_data_text(provider_outcome(domain_status, "virustotal"))
        console.print(f"  [cyan]virustotal_detections[/]: [yellow]{esc(vt_no_data)}[/]")
    else:
        vt_color = "red" if vt_mal > 0 else "green"
        console.print(f"  [cyan]virustotal_detections[/]: [{vt_color}]{vt_mal}/{vt_total}[/]")
        stamp = vt_dom.get("vt_last_analysis_date_iso")
        stamp_text = esc(stamp) if stamp else "unknown - VirusTotal supplied no date"
        console.print(f"  [cyan]virustotal_last_analysis[/]: {stamp_text}")

    if vt_dom:
        if vt_dom.get("vt_reputation") is not None:
            console.print(f"  [cyan]virustotal_community_score[/]: {esc(vt_dom.get('vt_reputation'))}")

        cats = vt_dom.get("vt_categories") or {}
        if isinstance(cats, dict) and cats:
            j_cats = ", ".join(sorted({esc(val) for val in cats.values() if val}))
            if j_cats:
                console.print(f"  [cyan]virustotal_categories[/]: {j_cats}")

        dns_records = vt_dom.get("vt_dns_records") or []
        passive_ips = [
            str(r.get("value"))
            for r in dns_records
            if isinstance(r, dict) and r.get("type") in {"A", "AAAA"} and r.get("value")
        ]
        if passive_ips:
            preview = ", ".join(indicator_text(value, defang=defang) for value in passive_ips[:5])
            suffix = "" if len(passive_ips) <= 5 else f" ... (+{len(passive_ips) - 5} more)"
            console.print(f"  [cyan]virustotal_passive_ips[/]: {preview}{suffix}")

    vt_link = vt_dom.get("vt_link") or f"https://www.virustotal.com/gui/domain/{norm_domain}"
    console.print(f"  [cyan]virustotal_analysis_link[/]: {esc(vt_link)}")
    console.print(f"  [cyan]abuseipdb_analysis_link[/]: https://www.abuseipdb.com/check/{esc(norm_domain)}")

    otx_dom_raw = domain_intel.get("otx") if isinstance(domain_intel, dict) else None
    otx_dom: Dict[str, Any] = otx_dom_raw if isinstance(otx_dom_raw, dict) else {}
    otx_link = f"https://otx.alienvault.com/indicator/domain/{esc(norm_domain)}"
    if otx_dom.get("otx_pulse_count") is not None:
        console.print(f"  [cyan]otx_pulse_count[/]: {esc(otx_dom.get('otx_pulse_count'))}")
    else:
        # Same rule as the VirusTotal row above and as every row on the IP path: an OTX that
        # was never asked must not render as an OTX that had nothing. Dropping the count row
        # and printing the pivot link on its own reads as the second.
        otx_no_data = no_data_text(provider_outcome(domain_status, "otx"))
        console.print(f"  [cyan]otx_pulse_count[/]: [yellow]{esc(otx_no_data)}[/]")
    console.print(f"  [cyan]otx_pulse_link[/]: {otx_link}")
    titles = otx_dom.get("otx_pulse_titles") or []
    if isinstance(titles, list) and titles:
        # Pulse titles are attacker-influenced free text. Unescaped, `evil [/] campaign` raised
        # MarkupError mid-render and `[green]0/94 clean[/]` painted a verdict the tool never
        # computed. W0.3 fixed this in reporting/console.py; this call site was missed.
        console.print(f"  [cyan]otx_pulse_titles[/]: {'; '.join(esc(t) for t in titles)}")

    console.print()
    return vt_dom


async def _cmd_domain(
    domain: str,
    *,
    output: str = "console",
    ports_limit: str = "25",
    explain: bool = False,
    defang: bool = False,
    out: Optional[str] = None,
    case_dir: Optional[str] = None,
) -> int:
    # A defanged indicator is the normal thing to paste at 02:00 -- it arrives that way from
    # email, tickets and threat reports. Refang it and say so, rather than refusing and making
    # the analyst retype under pressure. The transform is announced, never silent, and the raw
    # form is what a report displays (roadmap 6.1, 6.2).
    domain, refang_note = _refang_target(domain, output=output)

    try:
        parsed = urlparse(domain)
        norm_domain = parsed.hostname or domain.strip().strip("/")
    except ValueError:
        log["error"]("Could not parse target", domain=domain)
        if output == "console":
            console.print(f"[bold red]Could not parse target:[/] {esc(domain)}")
        return 2
    _ = refang_note

    res = await investigate_domain(norm_domain)
    if not res.ok:
        log["error"]("Domain investigation failed", domain=domain, errors=res.errors)
        if output == "console":
            console.print(f"[bold red]Domain investigation failed:[/] {esc('; '.join(res.errors))}")
            _print_failure_coverage(res.data)
        return 1

    saved = _persist_artefacts(
        res, indicator=norm_domain, scope=SCOPE_DOMAIN, output=output, defang=defang, out=out, case_dir=case_dir
    )
    failure_code = 0 if saved else 1

    if output == "json":
        console.print_json(data=res.model_dump())
        return failure_code
    if output == "markdown":
        sys.stdout.write(_markdown_report(res, indicator=norm_domain, scope=SCOPE_DOMAIN, defang=defang))
        return failure_code

    data = res.data
    domain_intel = data.get("domain_intel") or {}
    domain_errors = data.get("domain_errors") or {}
    ips = data.get("ips") or []
    domain_status = data.get("domain_provider_status") or {}
    run_id, started_at, tool_version = run_fields(data.get("run"))

    # The header carries everything a reader who stops after the first screen must still have
    # seen: which build produced this and when, how much of the intended provider set answered,
    # the collector's warnings, and every address that was resolved and deliberately not
    # investigated. `coverage` here is the whole-run figure the JSON export also carries -- its
    # names are namespaced `domain:` and `<address>:` -- so the two can never state different
    # ratios. See render_domain_header on why the label has to match that scope.
    console.print()
    console.print(
        render_domain_header(
            norm_domain,
            coverage=data.get("coverage") or domain_status,
            coverage_label="provider_coverage",
            warnings=res.warnings or data.get("warnings"),
            skipped_ips=data.get("skipped_ips"),
            run_id=run_id,
            generated_at=started_at,
            version=tool_version,
            # The domain's OWN verdict. Each address's verdict rides on its own panel below;
            # the two are never merged, because a phishing kit on a CDN is a malicious domain
            # on a shared address and both statements have to survive to the screen.
            verdict=data.get("verdict"),
            verdict_error=data.get("verdict_error"),
            explain=explain,
            defang=defang,
        )
    )

    vt_dom = _print_domain_intel(norm_domain, domain_intel, domain_status, defang=defang)

    if vt_dom:
        _print_whois_block(vt_dom.get("vt_whois"))
        _print_certificate_block(
            vt_dom.get("vt_last_https_certificate") or {}, vt_dom.get("vt_last_https_certificate_jarm")
        )

    if domain_errors:
        console.print("[bold red]domain_provider_errors:[/]")
        for name, detail in domain_errors.items():
            console.print(f"  - [bold]{esc(name)}[/]: {esc(_fmt_provider_error(detail))}")
        console.print()

    # "N IP addresses found" counted only the addresses that survived the private/reserved
    # guard, so a domain resolving to three internal addresses and one public one reported one
    # address and never mentioned the other three. The orchestrator publishes the real
    # accounting; print all three numbers, and say plainly that the skipped ones were not
    # investigated rather than letting them disappear.
    accounting = data.get("addresses") or {}
    resolved = accounting.get("resolved", len(ips))
    investigated = accounting.get("investigated", len(ips))
    skipped_count = accounting.get("skipped", 0)
    shown_domain = defang_indicator(norm_domain) if defang else norm_domain
    line = f'- Resolving "{shown_domain}"... {resolved} addresses resolved, {investigated} investigated'
    if skipped_count:
        line += f", {skipped_count} skipped as non-public and never sent to a provider"
    console.print(f"\n[bold]{esc(line)}:[/]\n")

    if not ips:
        if skipped_count:
            console.print(
                "[yellow]No address was investigated: every address this domain resolved to is "
                "non-public. Nothing above is evidence that this domain is clean.[/]\n"
            )
        else:
            console.print("No IPs available for IP-level enrichment.\n")
        return failure_code

    for item in ips:
        item_ip = item.get("ip", "")
        # show_run_line=False: the header printed the version, timestamp and run id once
        # already. run_id still travels so a per-address panel lifted out of this report on its
        # own can still be tied back to the run that produced it.
        panel = render_ip_analysis(
            item_ip,
            item,
            ports_limit=ports_limit,
            run_id=run_id,
            generated_at=started_at,
            show_run_line=False,
            explain=explain,
            defang=defang,
        )
        console.print(panel)
        console.print()

    return failure_code


# --------------------------------------------------------------------------------------
# url (roadmap 6.8)
# --------------------------------------------------------------------------------------


async def _cmd_url(
    url: str,
    *,
    output: str = "console",
    depth: str = DEFAULT_URL_DEPTH,
    ports_limit: str = "25",
    explain: bool = False,
    defang: bool = True,
    out: Optional[str] = None,
    case_dir: Optional[str] = None,
) -> int:
    """Investigate a URL, then its host, then the addresses its host resolves to.

    The three depths are a passivity control as much as a cost control. ``--depth url`` and
    ``--depth host`` resolve nothing, so the target's authoritative nameserver never sees a
    query; only ``--depth full`` exercises the one documented exception (``docs/OPSEC.md`` §3).
    Nothing at any depth fetches the link, follows a redirect, expands a shortener, or submits
    the URL for analysis.

    A ``--depth url`` run against a link nobody has submitted to VirusTotal exits ``1``: the
    single URL-scope provider held no report, so nothing was learned. That is the honest
    reading and the warning above the coverage line says so in words -- it is not a claim that
    the link is clean, and for a link that went live an hour ago it is the expected result.
    """
    # Refang and proceed rather than refusing -- see the note in _cmd_domain. `check` already
    # behaved this way; making the explicit verbs refuse the same input was friction at exactly
    # the wrong moment, and the tool already knows how to refang it.
    url, _ = _refang_target(url, output=output)

    res = await investigate_url(url, depth=depth)
    if not res.ok:
        log["error"]("URL investigation failed", url=url, errors=res.errors)
        if output == "console":
            console.print(f"[bold red]URL investigation failed:[/] {esc('; '.join(res.errors))}")
            _print_failure_coverage(res.data)
        return 1

    # `url_display`, not `url`: the case record and the report name the link the way a human
    # reads it, with any password masked. The evidence form stays byte-for-byte in `data['url']`.
    subject = str(res.data.get("url_display") or res.data.get("url") or url)
    saved = _persist_artefacts(
        res, indicator=subject, scope=SCOPE_URL, output=output, defang=defang, out=out, case_dir=case_dir
    )
    failure_code = 0 if saved else 1

    if output == "json":
        # Never defanged. The export carries the URL byte-for-byte because a machine consumes
        # it and `evil[.]example` is not a hostname.
        console.print_json(data=res.model_dump())
        return failure_code
    if output == "markdown":
        sys.stdout.write(_markdown_report(res, indicator=subject, scope=SCOPE_URL, defang=defang))
        return failure_code

    data = res.data
    console.print()
    console.print(render_url_analysis(data, explain=explain, defang=defang))

    # The host stage, printed below the URL and never merged into it: a phishing page on a
    # compromised site is a malicious URL on a host that is itself a victim, and both
    # statements have to reach the screen.
    if data.get("domain_provider_status") is not None:
        host_verdict = data.get("host_verdict")
        if host_verdict is not None:
            console.print(render_verdict(host_verdict, explain=explain, show_calibration=False))
            console.print()
        vt_dom = _print_domain_intel(
            str(data.get("host") or ""),
            data.get("domain_intel") or {},
            data.get("domain_provider_status") or {},
            defang=defang,
        )
        if vt_dom:
            _print_whois_block(vt_dom.get("vt_whois"))
            _print_certificate_block(
                vt_dom.get("vt_last_https_certificate") or {}, vt_dom.get("vt_last_https_certificate_jarm")
            )

    run_id, started_at, _version = run_fields(data.get("run"))
    for entry in data.get("ips") or []:
        console.print(
            render_ip_analysis(
                entry.get("ip", ""),
                entry,
                ports_limit=ports_limit,
                run_id=run_id,
                generated_at=started_at,
                show_run_line=False,
                explain=explain,
                defang=defang,
            )
        )
        console.print()

    return failure_code


# --------------------------------------------------------------------------------------
# check (roadmap 6.9) -- one verb an analyst can paste anything into
# --------------------------------------------------------------------------------------

#: Indicator types `check` can hand to an orchestrator. Everything else classifies fine and has
#: nowhere to go, which is a different failure from "I could not read that" and is reported as
#: one: the detection block still prints, so the analyst learns what they pasted.
_ROUTABLE: Dict[IndicatorType, str] = {
    IndicatorType.IPV4: "ip",
    IndicatorType.IPV6: "ip",
    IndicatorType.DOMAIN: "domain",
    IndicatorType.URL: "url",
    IndicatorType.ASN: "asn",
}

#: Why a type that classified cleanly still has no subcommand behind it. Stated per type rather
#: than as one generic sentence, because "no provider here holds file intelligence" and "a CIDR
#: is a range, investigate a member of it" send the analyst to different next steps.
_UNROUTABLE_REASON: Dict[IndicatorType, str] = {
    IndicatorType.MD5: "no provider wired into this tool holds file intelligence; take the hash to a malware service",
    IndicatorType.SHA1: "no provider wired into this tool holds file intelligence; take the hash to a malware service",
    IndicatorType.SHA256: (
        "no provider wired into this tool holds file intelligence; take the hash to a malware service"
    ),
    IndicatorType.EMAIL: "no provider here investigates mailboxes; investigate the domain to the right of the @",
    IndicatorType.CIDR: "a CIDR is a range, not a host; investigate a specific address inside it, or its ASN",
    IndicatorType.UNKNOWN: "no classifier matched; the attempt list above states why each one declined",
}


async def _cmd_check(
    target: str,
    *,
    output: str = "console",
    detect_only: bool = False,
    depth: str = DEFAULT_URL_DEPTH,
    ports_limit: str = "25",
    explain: bool = False,
    defang: bool = True,
) -> int:
    """Classify one pasted indicator and route it to the subcommand that investigates it.

    ``check`` is an addition to the explicit verbs, never a replacement: an analyst who knows
    what they are holding should keep saying so, because `ip 1.2.3.4` cannot be misrouted and
    `check 1.2.3.4` theoretically can. What `check` buys is the 02:00 case -- a string of
    unknown shape, possibly defanged, pasted under time pressure.

    ``--detect-only`` classifies and stops. It costs **zero provider quota**: detection is a
    pure function over the string (:func:`tripper_recon.types.indicators.detect`) and this
    branch returns before any orchestrator, and therefore before any HTTP client, exists.
    """
    indicator = detect(target)

    if detect_only:
        if output == "json":
            console.print_json(data=_detection_payload(indicator))
        elif output == "markdown":
            sys.stdout.write(_detection_markdown(indicator, defang=defang))
        else:
            console.print(render_detection(indicator, defang=defang, explain=explain))
        return 0 if indicator.is_known else 2

    route = _ROUTABLE.get(indicator.type)
    if route is None:
        reason = _UNROUTABLE_REASON.get(indicator.type, "no subcommand investigates this indicator type")
        log["error"]("Indicator has no route", indicator=indicator.value, type=indicator.type.value)
        if output == "json":
            console.print_json(data={**_detection_payload(indicator), "routed_to": None, "reason": reason})
        elif output == "markdown":
            sys.stdout.write(_detection_markdown(indicator, defang=defang, note=f"Not investigated: {reason}"))
        else:
            console.print(render_detection(indicator, defang=defang, explain=explain))
            console.print(f"\n[bold yellow]Not investigated:[/] {esc(reason)}")
        return 2

    if output == "console":
        # Say what was read out of the paste before spending quota on it. An ambiguous reading
        # that turns out wrong is cheap to notice here and expensive to notice three screens
        # further down.
        console.print(render_detection(indicator, defang=defang, explain=explain))
        console.print(f"\n[bold]routing to:[/] {esc(route)}\n")

    if route == "ip":
        return await _cmd_ip(indicator.value, output=output, ports_limit=ports_limit, explain=explain, defang=defang)
    if route == "domain":
        return await _cmd_domain(
            indicator.value, output=output, ports_limit=ports_limit, explain=explain, defang=defang
        )
    if route == "url":
        return await _cmd_url(
            indicator.value, output=output, depth=depth, ports_limit=ports_limit, explain=explain, defang=defang
        )
    asn_number = indicator.parts.get("asn")
    if not isinstance(asn_number, int):
        # Unreachable while the ASN classifier keeps its contract; asserted rather than assumed
        # because the alternative is an int() that raises out of a command function.
        console.print("[bold red]Error:[/] the ASN classifier matched but reported no number")
        return 2
    return await _cmd_asn(asn_number, output=output)


def _detection_markdown(indicator: Indicator, *, defang: bool, note: Optional[str] = None) -> str:
    """The zero-quota classification, as a markdown block.

    Small on purpose: this is not a report, it is the answer to "what did you read out of that
    string". Everything paste-controlled goes through the markdown escapers, for the same reason
    the report does -- a pasted token containing a pipe splits a table row, and one containing a
    leading ``#`` becomes a heading.
    """
    shown = defang_indicator(indicator.value) if defang else indicator.value
    rows = [
        ["type", md_code(indicator.type.value, in_table=True)],
        ["value", md_code(shown, in_table=True)],
        ["raw", md_code(indicator.raw, in_table=True)],
        ["confidence", md_escape(indicator.confidence.value)],
        ["arrived defanged", "yes" if indicator.defanged_input else "no"],
    ]
    if indicator.alternatives:
        rows.append(["also parses as", md_escape(", ".join(a.value for a in indicator.alternatives))])
    lines = ["# Tripper Recon detection", "", *md_table(["field", "value"], rows)]
    if indicator.notes:
        lines.extend(["", "Notes:", *[f"- {md_escape(text)}" for text in indicator.notes]])
    if note:
        lines.extend(["", f"> {md_escape(note)}"])
    return "\n".join(lines) + "\n"


def _triage_markdown(kept: Sequence[Mapping[str, Any]], withheld: Sequence[Mapping[str, Any]], *, defang: bool) -> str:
    """The bulk triage list, as markdown. Withheld indicators are shown, never dropped.

    Same rule as the console table: a filter that removes evidence silently is indistinguishable
    from evidence that was never there, and the RFC1918 address a filter binned is sometimes the
    pivot the incident turns on.
    """

    def _value(row: Mapping[str, Any]) -> str:
        raw = str(row.get("value") or "")
        return md_code(defang_indicator(raw) if defang else raw, in_table=True)

    lines = ["# Tripper Recon triage", "", f"> {md_escape(TRIAGE_CAVEAT)}", ""]
    if kept:
        lines.extend(
            md_table(
                ["type", "indicator", "seen", "confidence", "note"],
                [
                    [
                        md_escape(row.get("type")),
                        _value(row),
                        str(row.get("occurrences") or 1),
                        md_escape(row.get("confidence")),
                        md_escape(row.get("note") or ""),
                    ]
                    for row in kept
                ],
            )
        )
    else:
        lines.append("No indicator was extracted from the input.")
    if withheld:
        lines.extend(
            [
                "",
                "## Withheld from triage",
                "",
                *md_table(
                    ["type", "indicator", "reason"],
                    [[md_escape(row.get("type")), _value(row), md_escape(row.get("reason") or "")] for row in withheld],
                ),
            ]
        )
    return "\n".join(lines) + "\n"


def _detection_payload(indicator: Indicator) -> Dict[str, Any]:
    """The machine form of one detection. Never defanged -- see the module docstring."""
    return {
        "raw": indicator.raw,
        "type": indicator.type.value,
        "value": indicator.value,
        "confidence": indicator.confidence.value,
        "defanged_input": indicator.defanged_input,
        "refang_transforms": list(indicator.refang_transforms),
        "alternatives": [alternative.value for alternative in indicator.alternatives],
        "notes": list(indicator.notes),
        "parts": indicator.parts,
    }


# --------------------------------------------------------------------------------------
# bulk (roadmap 6.10) -- a wall of mixed indicators pasted out of an email or an alert
#
# **This is the most hostile input surface in the tool.** Every string extracted here was
# authored by whoever wrote the email, and each one is a candidate for interpolation into a
# provider URL. Three things keep that safe and none of them may be bypassed here:
#
# 1. Extraction and classification are pure -- `refang` and `detect` do no I/O at all -- so the
#    default mode of this command cannot make a request no matter what the text contains.
# 2. `--investigate` is opt-in and hard-capped by `--max-targets`. A pasted mail thread can
#    carry hundreds of hosts, and an unbounded fan-out would be a quota incident at best.
# 3. Every request that does leave goes through `utils.http.create_client`, whose egress hook
#    refuses any host that is not on the allowlist -- before a socket opens. Nothing in this
#    file constructs a client or bypasses the rate limiter.
# --------------------------------------------------------------------------------------

#: Characters that separate candidates in prose. Deliberately does NOT include `[`, `]`, `(` or
#: `)`: those are the defanging characters, and splitting on them would shred `evil[.]com` into
#: three tokens that classify as nothing.
_CANDIDATE_SPLIT = re.compile(r"[\s,;<>\"'`|\\]+")

#: Trailing sentence punctuation, always safe to shed: no indicator ends in one of these.
_TRAILING_PUNCTUATION = ".,;:!?"

#: Bracket pairs, used to shed prose wrapping without shedding a defang.
_BRACKET_PAIRS: Dict[str, str] = {"(": ")", "[": "]", "{": "}", "<": ">"}

#: Types that are never worth a lookup from a bulk paste, whatever the text said.
_BULK_UNROUTABLE = frozenset({IndicatorType.UNKNOWN, IndicatorType.CIDR, IndicatorType.EMAIL})

#: Order the triage list is presented in: what an analyst working an email alert opens first.
#:
#: URLs lead because they are the click that starts the incident; hosts and addresses follow
#: because they are the pivot; hashes, mailboxes, ranges and ASNs are context. Within a type,
#: an indicator the sender or a previous analyst had already DEFANGED sorts first -- somebody
#: bothered to neuter that one, which is a human judgement worth surfacing for free.
_TRIAGE_ORDER: Tuple[IndicatorType, ...] = (
    IndicatorType.URL,
    IndicatorType.DOMAIN,
    IndicatorType.IPV4,
    IndicatorType.IPV6,
    IndicatorType.SHA256,
    IndicatorType.SHA1,
    IndicatorType.MD5,
    IndicatorType.EMAIL,
    IndicatorType.CIDR,
    IndicatorType.ASN,
    IndicatorType.UNKNOWN,
)

#: Host suffixes that are mail transport rather than a subject of investigation.
#:
#: **A heuristic, and the wrong answer sometimes.** A phishing kit really does get hosted on a
#: bulk-mail provider, and this list would withhold it. That is why nothing here is deleted:
#: every withheld indicator is printed in its own table with the reason, and `--no-filter`
#: turns the whole thing off. The list is unsourced by nature -- it is the mail infrastructure
#: that shows up in every Received: chain -- so it orders triage and never scores anything.
_MAIL_INFRASTRUCTURE_SUFFIXES: Tuple[str, ...] = (
    "mail.protection.outlook.com",
    "protection.outlook.com",
    "pphosted.com",
    "mimecast.com",
    "messagelabs.com",
    "barracudanetworks.com",
    "amazonses.com",
    "sendgrid.net",
    "mailgun.org",
    "mcsv.net",
    "mandrillapp.com",
    "spf.protection.outlook.com",
)

_MAIL_INFRASTRUCTURE_REASON = "looks like mail transport infrastructure, not a subject of investigation"
_NON_PUBLIC_REASON = "non-public addressing; this tool never forwards internal addresses to a third party"


def _clean_candidate(token: str) -> str:
    """Trim prose wrapping off one token without trimming a defang.

    Three passes, in order, each repeated until it stops changing anything:

    1. trailing sentence punctuation, which no indicator ends in;
    2. a matched pair wrapping the whole token -- ``(10.0.0.5)`` in a ``Received:`` line, and
       equally ``[2001:db8::1]``, whose brackets are URL syntax rather than part of the address;
    3. a trailing closer whose opener is absent, so ``evil.com)`` sheds its parenthesis.

    What it must never do is strip the brackets out of ``evil[.]com``. That is why the token
    splitter does not treat brackets as separators and why every rule here is anchored to the
    ends of the token rather than applied throughout it.
    """
    value = token.strip()
    changed = True
    while value and changed:
        changed = False
        while value and value[-1] in _TRAILING_PUNCTUATION:
            value, changed = value[:-1], True
        if len(value) > 1 and _BRACKET_PAIRS.get(value[0]) == value[-1]:
            value, changed = value[1:-1], True
            continue
        if value and value[-1] in _BRACKET_PAIRS.values():
            opener = next(open_ for open_, close in _BRACKET_PAIRS.items() if close == value[-1])
            if opener not in value:
                value, changed = value[:-1], True
    return value


def extract_indicators(text: str) -> List[Indicator]:
    """Classify every candidate token in a wall of pasted prose. Pure: no I/O, no resolution.

    Best-effort by construction, and it says so: a token that classifies as nothing becomes an
    ``UNKNOWN`` indicator carrying the reason each classifier declined, rather than being
    dropped. Silently discarding a token an analyst pasted is how the one string that mattered
    goes missing between the email and the report.
    """
    found: List[Indicator] = []
    for token in _CANDIDATE_SPLIT.split(text or ""):
        candidate = _clean_candidate(token)
        if not candidate:
            continue
        indicator = detect(candidate)
        if indicator.is_known:
            found.append(indicator)
    return found


def _withhold_reason(indicator: Indicator, *, filter_infrastructure: bool) -> Optional[str]:
    """Why this indicator is held back from the triage list, or ``None`` to keep it.

    The non-public check runs against a URL's HOST as well as against a bare address. A pasted
    ``hxxp://10.0.0.5/admin`` used to be listed as routable here: ``investigate_url`` refuses it
    a moment later, so nothing internal ever reached a provider, but the triage table announced
    an investigation that would not happen and the withheld table -- the one an analyst reads to
    see what was held back and why -- did not mention it at all. Both layers now say the same
    thing, which is the property that makes the withheld table trustworthy.
    """
    url_host = str(indicator.parts.get("host") or "") if indicator.type is IndicatorType.URL else ""
    if indicator.type in {IndicatorType.IPV4, IndicatorType.IPV6} and non_public_ip_reason(indicator.value):
        return _NON_PUBLIC_REASON
    if url_host and non_public_ip_reason(url_host):
        return _NON_PUBLIC_REASON
    if not filter_infrastructure:
        return None
    if indicator.type is IndicatorType.URL:
        host = url_host
    elif indicator.type is IndicatorType.DOMAIN:
        host = indicator.value
    else:
        return None
    host = host.lower().rstrip(".")
    if any(host == suffix or host.endswith(f".{suffix}") for suffix in _MAIL_INFRASTRUCTURE_SUFFIXES):
        return _MAIL_INFRASTRUCTURE_REASON
    return None


def _triage(
    indicators: Sequence[Indicator],
    *,
    filter_infrastructure: bool = True,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Dedupe on the canonical value, count occurrences, and order by what to look at first.

    Returns ``(kept, withheld)``. Deduplication is on ``Indicator.key`` -- the ``(type, value)``
    pair -- and the occurrence count travels with the survivor, because "this host appears once
    in the body" and "this host appears in every Received: header" are different starting
    points and collapsing the two destroys the difference.
    """
    counts: Dict[Tuple[IndicatorType, str], int] = {}
    first: Dict[Tuple[IndicatorType, str], Indicator] = {}
    for indicator in indicators:
        counts[indicator.key] = counts.get(indicator.key, 0) + 1
        first.setdefault(indicator.key, indicator)

    kept: List[Dict[str, Any]] = []
    withheld: List[Dict[str, Any]] = []
    for key, indicator in first.items():
        row: Dict[str, Any] = {
            "type": indicator.type.value,
            "value": indicator.value,
            "raw": indicator.raw,
            "occurrences": counts[key],
            "confidence": indicator.confidence.value,
            "defanged_input": indicator.defanged_input,
            "routable": indicator.type not in _BULK_UNROUTABLE,
        }
        reason = _withhold_reason(indicator, filter_infrastructure=filter_infrastructure)
        if reason is not None:
            withheld.append({**row, "reason": reason})
            continue
        row["note"] = _triage_note(indicator)
        kept.append(row)

    order = {kind: position for position, kind in enumerate(_TRIAGE_ORDER)}
    kept.sort(
        key=lambda row: (
            order.get(IndicatorType(row["type"]), len(order)),
            not row["defanged_input"],
            -int(row["occurrences"]),
            str(row["value"]),
        )
    )
    withheld.sort(key=lambda row: (order.get(IndicatorType(row["type"]), len(order)), str(row["value"])))
    return kept, withheld


def _triage_note(indicator: Indicator) -> str:
    """The one thing about this reading an analyst should know before acting on it."""
    if indicator.defanged_input:
        return "arrived defanged - somebody already judged this hostile"
    if indicator.alternatives:
        return "ambiguous: also parses as " + ", ".join(alternative.value for alternative in indicator.alternatives)
    if indicator.type in _BULK_UNROUTABLE:
        return _UNROUTABLE_REASON.get(indicator.type, "no subcommand investigates this type")
    if indicator.confidence.value != "certain":
        return "reading is probable, not certain - see `check --detect-only` for why"
    return ""


def _read_bulk_text(source: Optional[str]) -> str:
    """Read pasted text from a file, from stdin, or from the argument itself.

    ``-`` and an omitted argument both mean stdin, which is the shape of the actual workflow:
    an analyst pipes or pastes an email body in. A path that exists is read; anything else is
    treated as the text, so `bulk "1.2.3.4 evil.example"` works without a here-doc.

    **The path probe is guarded, and the guard is load-bearing.** ``Path.is_file()`` does not
    return ``False`` for a string that cannot be a path -- it raises. A pasted email body longer
    than ``PATH_MAX`` raises ``OSError: [Errno 36] File name too long``, and a paste containing a
    NUL byte raises ``ValueError``; ``expanduser()`` raises ``RuntimeError`` for a ``~user`` it
    cannot resolve. Every one of those is attacker-reachable, because the whole point of this
    command is that an analyst pastes hostile text into it, and every one of them was an uncaught
    traceback before this guard. A string that cannot be a path is simply not a path, which is
    the case the fallthrough already handles.
    """
    if source is None or source == "-":
        return sys.stdin.read()
    try:
        path = Path(source).expanduser()
        is_file = path.is_file()
    except (OSError, ValueError, RuntimeError):
        is_file = False
    if is_file:
        return path.read_text(encoding="utf-8", errors="replace")
    return source


async def _cmd_bulk(
    source: Optional[str],
    *,
    output: str = "console",
    investigate: bool = False,
    max_targets: int = 10,
    filter_infrastructure: bool = True,
    ports_limit: str = "25",
    explain: bool = False,
    defang: bool = True,
) -> int:
    """Triage a wall of pasted indicators, and optionally investigate the top few.

    **Triage is the default and it costs nothing.** Extraction and classification are pure, so
    the default run makes no request at all: it is safe to paste an entire phishing email into
    this command and read the result. ``--investigate`` is the opt-in that spends quota, capped
    by ``--max-targets`` so a pasted mail thread carrying two hundred hosts cannot fan out.

    Nothing is deleted. Indicators withheld by the RFC1918 guard or the mail-infrastructure
    heuristic are printed in their own table with the reason, because a filter that removes
    evidence silently is indistinguishable from evidence that was never there -- and the
    RFC1918 address a filter binned is sometimes the pivot the incident turns on.
    """
    text = _read_bulk_text(source)
    kept, withheld = _triage(extract_indicators(text), filter_infrastructure=filter_infrastructure)

    if output == "json" and not investigate:
        console.print_json(data={"ok": True, "caveat": TRIAGE_CAVEAT, "indicators": kept, "withheld": withheld})
        return 0 if kept else 2
    if output == "markdown" and not investigate:
        sys.stdout.write(_triage_markdown(kept, withheld, defang=defang))
        return 0 if kept else 2

    if output == "markdown":
        sys.stdout.write(_triage_markdown(kept, withheld, defang=defang))
        sys.stdout.write("\n")
    if output == "console":
        console.print()
        console.print(render_triage_table(kept, defang=defang))
        withheld_block = render_filtered_indicators(withheld)
        if withheld_block is not None:
            console.print()
            console.print(withheld_block)
        console.print()

    if not kept:
        log["error"]("No indicators extracted", characters=len(text))
        return 2
    if not investigate:
        return 0

    routable = [row for row in kept if row["routable"]][:max_targets]
    if output == "console":
        held_back = len([row for row in kept if row["routable"]]) - len(routable)
        console.print(
            f"[bold]investigating {len(routable)} of {len(kept)} indicators[/]"
            + (f", {held_back} above the --max-targets cap of {max_targets} were not looked up" if held_back else "")
            + "\n"
        )

    # Sequential on purpose. The global rate limiter already bounds requests in flight; running
    # the reports concurrently would interleave their console output into something unreadable,
    # and an unreadable report is a report nobody checks the coverage line on.
    codes: List[int] = []
    for row in routable:
        codes.append(
            await _cmd_check(
                row["value"],
                output=output,
                ports_limit=ports_limit,
                explain=explain,
                defang=defang,
            )
        )
    return 0 if all(code == 0 for code in codes) else 1


async def _cmd_asn(
    asn: int,
    *,
    output: str = "console",
    neighbors: int = 8,
    prefixes_out: str | None = None,
    prefixes: str = "both",
) -> int:
    res = await investigate_asn(asn, resolve_neighbors=neighbors)
    if not res.ok:
        log["error"]("ASN lookup failed", asn=asn, errors=res.errors)
        if output == "console":
            console.print(f"[bold red]ASN lookup failed:[/] {esc('; '.join(res.errors))}")
            _print_failure_coverage(res.data)
        return 1

    if output == "json":
        console.print_json(data=res.model_dump())
    elif output == "markdown":
        sys.stdout.write(_markdown_report(res, indicator=f"AS{asn}", scope=SCOPE_ASN, defang=False))
    else:
        meta = res.data.get("meta", {})
        run_id, started_at, tool_version = run_fields(res.data.get("run"))
        # Roadmap 4.3 for the ASN path closes here. The orchestrator has always computed these
        # warnings and only the JSON branch ever read them, so a failed CAIDA or PeeringDB
        # lookup degraded the panel silently -- and without `coverage` the header renders the
        # ratio as "unknown", which is honest but is not the point of the workstream.
        console.print(
            render_asn_header(
                asn,
                meta,
                coverage=res.data.get("coverage") or res.data.get("provider_status"),
                warnings=res.warnings or res.data.get("warnings"),
                run_id=run_id,
                generated_at=started_at,
                version=tool_version,
            )
        )
        console.print()

        if not meta:
            console.print(
                "[yellow]Note: Cloudflare Radar API token missing or request failed. Set CLOUDFLARE_API_TOKEN in .env for full ASN details.[/]\n"
            )

        bgp = res.data.get("bgp", {})
        if bgp:
            console.print(render_asn_bgp_panels(asn, meta, bgp))

        errors = res.data.get("errors") or {}
        if errors:
            console.print("\n[bold red]provider_errors:[/]")
            for name, detail in errors.items():
                console.print(f"  - [bold]{esc(name)}[/]: {esc(_fmt_provider_error(detail))}")

        if prefixes_out:
            v4_full = (res.data.get("bgp", {}) or {}).get("ripe_prefixes_v4") or []
            v6_full = (res.data.get("bgp", {}) or {}).get("ripe_prefixes_v6") or []

            out_lines: list[str] = []
            name = meta.get("name") or ""
            title = (
                f"--- Aggregated IP resources for AS{asn} ({name}) ---"
                if name
                else f"--- Aggregated IP resources for AS{asn} ---"
            )
            out_lines.append(title)
            out_lines.append("")

            if prefixes in ("v4", "both"):
                out_lines.append("───── IPv4 ─────")
                if v4_full:
                    out_lines.extend(str(p) for p in v4_full)
                else:
                    out_lines.append("NONE")
                if prefixes == "both":
                    out_lines.append("")
            if prefixes in ("v6", "both"):
                out_lines.append("───── IPv6 ─────")
                if v6_full:
                    out_lines.extend(str(p) for p in v6_full)
                else:
                    out_lines.append("NONE")

            out_path = Path(prefixes_out)
            if not out_path.parent or str(out_path.parent) == ".":
                out_dir = _default_output_dir()
                out_dir.mkdir(parents=True, exist_ok=True)
                out_path = out_dir / out_path.name
            else:
                out_path.parent.mkdir(parents=True, exist_ok=True)

            try:
                out_path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
                log["info"]("Wrote prefix list", path=str(out_path))
                console.print(f"\n[bold green]Success:[/] Wrote prefix list to {out_path}")
            except Exception as e:
                log["error"]("Failed writing prefixes file", path=str(out_path), error=str(e))
                console.print(f"\n[bold red]Error:[/] Failed writing prefixes file to {out_path}")

    return 0


# --------------------------------------------------------------------------------------
# report --from-case (roadmap 7.7)
# --------------------------------------------------------------------------------------


def _cmd_report(source: str, *, output: str = "markdown", defang: bool = True, out: Optional[str] = None) -> int:
    """Rebuild a report from a saved case. Contacts nobody and spends no quota.

    Not a coroutine, and it never constructs an HTTP client: regeneration is a pure function from
    the case record to a document. That is the property that makes a case worth keeping -- an
    incident reviewed in three months can be re-read without asking a provider anything.

    **The timestamps are the originals.** ``MarkdownOptions.now`` is fed from the saved run's
    ``started_at``, so a regenerated report says when the evidence was collected rather than when
    somebody re-rendered it. Restamping here would be the same lie as a cache that claims a
    replayed answer was queried now, one artefact further downstream.

    ``-o console`` is not offered. The console renderers are driven from a live
    ``InvestigationResult`` through six different code paths, and half-supporting them here would
    produce a rendering that silently differs from the one the run produced.
    """
    try:
        record = load_case(Path(source))
    except CacheError as exc:
        log["error"]("Could not read the case", path=source, error=str(exc))
        console.print(f"[bold red]Could not read the case:[/] {esc(str(exc))}")
        return 2

    result = record.get("result")
    indicator = str(record.get("indicator") or "")
    scope = str(record.get("scope") or "")

    if output == "json":
        document = json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    else:
        document = _markdown_report(result, indicator=indicator, scope=scope, defang=defang)

    if out:
        path = _resolve_artefact_path(out)
        try:
            _write_text(path, document)
            log["info"]("Wrote regenerated report", path=str(path), case=str(source))
        except OSError as exc:
            log["error"]("Failed writing the regenerated report", path=str(path), error=str(exc))
            return 1
    else:
        sys.stdout.write(document)
    return 0


def main() -> None:
    load_env()
    parser = argparse.ArgumentParser(
        prog="tripper-recon",
        description="Passive OSINT investigations of IPs, domains, URLs and ASNs",
        epilog=_EPILOG,
        # Raw, because the epilog is hand-wrapped: argparse's default formatter reflows every
        # paragraph into one blob and the exit-code and environment tables stop being tables.
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-o",
        "--format",
        choices=_FORMATS,
        default="console",
        help="Output format (may also be given after the subcommand)",
    )
    parser.add_argument(
        "--rate-limit", type=int, default=10, help="Max concurrent outgoing API requests across global providers"
    )
    parser.add_argument(
        "--user-agent",
        type=str,
        default=None,
        help="Override the User-Agent sent to providers (default: tripper-recon/<version>)",
    )
    parser.add_argument(
        "--fanged",
        action="store_true",
        help=(
            "Print indicators live instead of defanged. Human-facing output brackets the "
            "indicator by default so a pasted report is not one click from a compromise; "
            "-o json is never defanged either way"
        ),
    )
    # --- cache and freshness (roadmap 7.7) ------------------------------------------------
    #
    # Top-level rather than per-subcommand: they are properties of the RUN, and `check` and
    # `bulk` route into the other verbs, so a per-subcommand flag would silently not apply to
    # the two commands most likely to spend a lot of quota.
    parser.add_argument(
        "--offline",
        action="store_true",
        help=(
            "Answer from cache only. Contacts nobody -- not a provider, not the system resolver. "
            "A question the cache cannot answer is reported as missing coverage with the reason, "
            "never served from an expired entry"
        ),
    )
    parser.add_argument(
        "--max-age",
        type=str,
        default=None,
        metavar="DURATION",
        help=(
            "Refuse anything cached older than this (30, 90s, 15m, 6h, 7d, 2w). Online it forces "
            "a fresh lookup; offline it turns a stale entry into a stated gap. 0 means query now"
        ),
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Read nothing from the cache and write nothing to it. Every answer is queried now",
    )
    parser.add_argument(
        "--cache-dir",
        type=str,
        default=None,
        help="Where cached provider answers live (default: $XDG_CACHE_HOME/tripper_recon)",
    )
    parser.add_argument("-V", "--version", action="version", version=f"tripper-recon {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    p_ip = sub.add_parser(
        "ip",
        help="Investigate an IP address",
        epilog=_IP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_ip.add_argument("ip", type=str)
    # default=SUPPRESS so an omitted subcommand flag leaves the top-level value in place.
    # With a real default, argparse overwrote it and `-o json ip 8.8.8.8` silently emitted console text.
    p_ip.add_argument("-o", "--format", choices=_FORMATS, default=argparse.SUPPRESS, help="Output format")
    p_ip.add_argument(
        "--ports-limit", type=str, default="25", help="Limit number of ports shown (use 'all' to show all)"
    )
    p_ip.add_argument("--explain", action="store_true", help=_EXPLAIN_HELP)
    p_ip.add_argument(
        "--out",
        type=str,
        default=None,
        help=(
            "Write the report to this path. -o json writes JSON; console and markdown both "
            "write Markdown. A bare filename lands in ./outputs/"
        ),
    )
    p_ip.add_argument(
        "--case-dir",
        type=str,
        nargs="?",
        const=str(default_case_root()),
        default=None,
        metavar="DIR",
        help=(
            "Save the run (result, verdict, report, cache record) so the report can be "
            "regenerated later without re-querying. Defaults to ./outputs/cases"
        ),
    )
    p_ip.add_argument(
        "--evidence",
        action="store_true",
        help="Also capture the raw provider exchanges into the case directory. Requires --case-dir",
    )

    p_domain = sub.add_parser(
        "domain",
        help="Investigate a domain",
        epilog=_DOMAIN_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_domain.add_argument("domain", type=str)
    p_domain.add_argument("-o", "--format", choices=_FORMATS, default=argparse.SUPPRESS, help="Output format")
    p_domain.add_argument(
        "--ports-limit",
        type=str,
        default="25",
        help="Limit number of ports shown per IP in console (use 'all' to show all)",
    )
    p_domain.add_argument("--explain", action="store_true", help=_EXPLAIN_HELP)
    p_domain.add_argument(
        "--out",
        type=str,
        default=None,
        help=(
            "Write the report to this path. -o json writes JSON; console and markdown both "
            "write Markdown. A bare filename lands in ./outputs/"
        ),
    )
    p_domain.add_argument(
        "--case-dir",
        type=str,
        nargs="?",
        const=str(default_case_root()),
        default=None,
        metavar="DIR",
        help=(
            "Save the run (result, verdict, report, cache record) so the report can be "
            "regenerated later without re-querying. Defaults to ./outputs/cases"
        ),
    )
    p_domain.add_argument(
        "--evidence",
        action="store_true",
        help="Also capture the raw provider exchanges into the case directory. Requires --case-dir",
    )

    p_asn = sub.add_parser(
        "asn",
        help="Lookup ASN details",
        epilog=_ASN_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_asn.add_argument("asn", type=str)
    p_asn.add_argument("-o", "--format", choices=_FORMATS, default=argparse.SUPPRESS, help="Output format")
    p_asn.add_argument("--neighbors", type=int, default=8, help="Resolve first N neighbors to names")
    # `--enrich`, `--enrich-limit` and `--monochrome` were removed here (roadmap 9.11). All three
    # advertised behaviour the code did not have: `--enrich`'s help named a whois/pWhois path that
    # exists nowhere in the package -- the orchestrator branch it set is self-labelled "placeholder
    # aggregation" and only re-emitted a truncated copy of the announced-prefix lists that are
    # already present -- and `--monochrome` fed a `use_color` parameter that neither renderer body
    # reads. A flag that promises a capability the tool lacks is worse than a missing flag.
    p_asn.add_argument("--prefixes-out", type=str, default=None, help="Write full prefix list to a text file")
    p_asn.add_argument(
        "--prefixes",
        choices=["v4", "v6", "both"],
        default="both",
        help="Which prefixes to include when writing --prefixes-out",
    )

    p_url = sub.add_parser(
        "url",
        help="Investigate a URL, its host, and the addresses it resolves to",
        epilog=_URL_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_url.add_argument("url", type=str)
    p_url.add_argument("-o", "--format", choices=_FORMATS, default=argparse.SUPPRESS, help="Output format")
    p_url.add_argument(
        "--depth",
        choices=list(URL_DEPTHS),
        default=DEFAULT_URL_DEPTH,
        help=(
            "How far to pivot: 'url' is the link's own report, 'host' adds the host's reputation "
            "(both resolve nothing), 'full' adds the addresses the host resolves to"
        ),
    )
    p_url.add_argument("--ports-limit", type=str, default="25", help="Limit ports shown per address")
    p_url.add_argument("--explain", action="store_true", help=_EXPLAIN_HELP)
    p_url.add_argument(
        "--out",
        type=str,
        default=None,
        help=(
            "Write the report to this path. -o json writes JSON; console and markdown both "
            "write Markdown. A bare filename lands in ./outputs/"
        ),
    )
    p_url.add_argument(
        "--case-dir",
        type=str,
        nargs="?",
        const=str(default_case_root()),
        default=None,
        metavar="DIR",
        help=(
            "Save the run (result, verdict, report, cache record) so the report can be "
            "regenerated later without re-querying. Defaults to ./outputs/cases"
        ),
    )
    p_url.add_argument(
        "--evidence",
        action="store_true",
        help="Also capture the raw provider exchanges into the case directory. Requires --case-dir",
    )

    p_check = sub.add_parser(
        "check",
        help="Detect what an indicator is and route it to the right lookup",
        epilog=_CHECK_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_check.add_argument("target", type=str)
    p_check.add_argument("-o", "--format", choices=_FORMATS, default=argparse.SUPPRESS, help="Output format")
    p_check.add_argument(
        "--detect-only",
        action="store_true",
        help="Classify and stop. Costs no provider quota: detection is a pure function over the string",
    )
    p_check.add_argument("--depth", choices=list(URL_DEPTHS), default=DEFAULT_URL_DEPTH, help="Depth, if it is a URL")
    p_check.add_argument("--ports-limit", type=str, default="25", help="Limit ports shown per address")
    p_check.add_argument("--explain", action="store_true", help=_EXPLAIN_HELP)

    p_bulk = sub.add_parser(
        "bulk",
        help="Extract and triage every indicator in a wall of pasted text",
        epilog=_BULK_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_bulk.add_argument(
        "source",
        type=str,
        nargs="?",
        default=None,
        help="A file to read, '-' or omitted for stdin, or the text itself",
    )
    p_bulk.add_argument("-o", "--format", choices=_FORMATS, default=argparse.SUPPRESS, help="Output format")
    p_bulk.add_argument(
        "--investigate",
        action="store_true",
        help="Also look the indicators up. Off by default: triage alone costs no provider quota",
    )
    p_bulk.add_argument(
        "--max-targets",
        type=int,
        default=10,
        help="Hard cap on how many indicators --investigate looks up, so a pasted thread cannot fan out",
    )
    p_bulk.add_argument(
        "--no-filter",
        action="store_true",
        help="Keep mail infrastructure in the triage list instead of withholding it (RFC1918 stays withheld)",
    )
    p_bulk.add_argument("--ports-limit", type=str, default="25", help="Limit ports shown per address")
    p_bulk.add_argument("--explain", action="store_true", help=_EXPLAIN_HELP)

    p_report = sub.add_parser(
        "report",
        help="Rebuild a report from a saved case directory, without re-querying anything",
        epilog=_REPORT_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_report.add_argument(
        "--from-case",
        dest="from_case",
        type=str,
        required=True,
        metavar="PATH",
        help="A case directory written by --case-dir, or the case.json inside it",
    )
    # No SUPPRESS here, unlike every other subcommand: `console` is not a format this command
    # can produce, so a top-level `-o console` must not survive into it.
    p_report.add_argument(
        "-o", "--format", choices=_REPORT_FORMATS, default="markdown", help="Output format (default: markdown)"
    )
    p_report.add_argument("--out", type=str, default=None, help="Write to this path instead of stdout")

    args = parser.parse_args()

    if args.cmd is None:
        parser.print_help()
        raise SystemExit(2)

    configure_rate_limit(args.rate_limit)
    if getattr(args, "user_agent", None):
        configure_user_agent(args.user_agent)

    # Defanged unless the operator says otherwise. `-o json` ignores this entirely; the JSON
    # branch of each command dumps the model and never routes through a renderer.
    defang = not getattr(args, "fanged", False)

    # `report` contacts nobody by construction, so it runs before any cache session or event
    # loop exists. Nothing below this line applies to it.
    if args.cmd == "report":
        raise SystemExit(_cmd_report(args.from_case, output=args.format, defang=defang, out=getattr(args, "out", None)))

    session, setup_error = _build_cache_session(args)
    if setup_error is not None:
        log["error"]("Cache options rejected", error=setup_error)
        console.print(f"[bold red]Error:[/] {esc(setup_error)}")
        raise SystemExit(2)

    recorder, evidence_error = _build_evidence_recorder(args)
    if evidence_error is not None:
        log["error"]("Evidence options rejected", error=evidence_error)
        console.print(f"[bold red]Error:[/] {esc(evidence_error)}")
        raise SystemExit(2)

    case_dir = getattr(args, "case_dir", None)
    out = getattr(args, "out", None)

    coro: Optional[Coroutine[Any, Any, int]] = None
    code = 2
    match args.cmd:
        case "ip":
            coro = _cmd_ip(
                args.ip,
                output=args.format,
                ports_limit=getattr(args, "ports_limit", "25"),
                explain=getattr(args, "explain", False),
                defang=defang,
                out=out,
                case_dir=case_dir,
            )
        case "domain":
            coro = _cmd_domain(
                args.domain,
                output=args.format,
                ports_limit=getattr(args, "ports_limit", "25"),
                explain=getattr(args, "explain", False),
                defang=defang,
                out=out,
                case_dir=case_dir,
            )
        case "url":
            coro = _cmd_url(
                args.url,
                output=args.format,
                depth=getattr(args, "depth", DEFAULT_URL_DEPTH),
                ports_limit=getattr(args, "ports_limit", "25"),
                explain=getattr(args, "explain", False),
                defang=defang,
                out=out,
                case_dir=case_dir,
            )
        case "check":
            coro = _cmd_check(
                args.target,
                output=args.format,
                detect_only=getattr(args, "detect_only", False),
                depth=getattr(args, "depth", DEFAULT_URL_DEPTH),
                ports_limit=getattr(args, "ports_limit", "25"),
                explain=getattr(args, "explain", False),
                defang=defang,
            )
        case "bulk":
            coro = _cmd_bulk(
                args.source,
                output=args.format,
                investigate=getattr(args, "investigate", False),
                max_targets=getattr(args, "max_targets", 10),
                filter_infrastructure=not getattr(args, "no_filter", False),
                ports_limit=getattr(args, "ports_limit", "25"),
                explain=getattr(args, "explain", False),
                defang=defang,
            )
        case "asn":
            asn_str = str(args.asn).strip()
            if asn_str.lower().startswith("as"):
                asn_str = asn_str[2:]
            try:
                asn_int = int(asn_str)
            except Exception:
                log["error"]("Invalid ASN provided", asn=args.asn)
                console.print(f"[bold red]Error:[/] Invalid ASN provided: {args.asn}")
                code = 2
            else:
                coro = _cmd_asn(
                    asn_int,
                    output=args.format,
                    neighbors=args.neighbors,
                    prefixes_out=getattr(args, "prefixes_out", None),
                    prefixes=getattr(args, "prefixes", "both"),
                )
        case _:
            code = 2

    if coro is not None:
        code = _run(coro, session=session, recorder=recorder)
    raise SystemExit(code)


def _run(
    coro: Coroutine[Any, Any, int],
    *,
    session: Optional[CacheSession],
    recorder: Optional[EvidenceRecorder],
) -> int:
    """Run one command with the cache session and evidence recorder installed.

    Both context managers are entered **outside** ``asyncio.run``, and that ordering is load
    bearing rather than stylistic: a task copies the current context when it is CREATED, so a
    ContextVar set inside the loop is invisible to everything the loop already started.
    """
    with use_cache(session):
        if recorder is None:
            return asyncio.run(coro)
        with capture_evidence(recorder):
            return asyncio.run(coro)


def _build_cache_session(args: argparse.Namespace) -> Tuple[Optional[CacheSession], Optional[str]]:
    """Turn the cache flags into a session, or into the reason they were refused.

    ``--offline --no-cache`` is refused rather than obeyed. Obeying it would consult nobody and
    serve nothing, so every provider would report a gap -- a run that cannot answer anything and
    looks, from the exit code, exactly like a total intelligence blackout. Refusing at parse time
    costs nothing and says which of the two flags to drop.
    """
    offline = bool(getattr(args, "offline", False))
    no_cache = bool(getattr(args, "no_cache", False))
    if offline and no_cache:
        return None, "--offline with --no-cache would consult nobody and serve nothing. Drop one of them"

    max_age: Optional[float] = None
    raw_max_age = getattr(args, "max_age", None)
    if raw_max_age is not None:
        try:
            max_age = parse_duration(str(raw_max_age))
        except ValueError as exc:
            return None, f"--max-age: {exc}"

    store = None if no_cache else CacheStore(Path(getattr(args, "cache_dir", None) or default_cache_root()))
    return CacheSession(store, offline=offline, max_age_seconds=max_age), None


def _build_evidence_recorder(args: argparse.Namespace) -> Tuple[Optional[EvidenceRecorder], Optional[str]]:
    """Mint a recorder when ``--evidence`` was asked for, or say why it cannot be honoured.

    ``--evidence`` without ``--case-dir`` is refused instead of quietly capturing envelopes into
    memory that nothing will ever write out. An operator who asked to preserve evidence and was
    given none, silently, is worse off than one who was told to add a flag.
    """
    if not getattr(args, "evidence", False):
        return None, None
    if not getattr(args, "case_dir", None):
        return None, "--evidence needs somewhere to write: add --case-dir"
    return EvidenceRecorder(max_body_bytes=262144, max_records=2000), None


if __name__ == "__main__":
    main()
