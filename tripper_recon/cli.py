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
"""

from __future__ import annotations

import argparse
import asyncio
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from rich.console import Console

from tripper_recon import __version__
from tripper_recon.orchestrators import (
    DEFAULT_URL_DEPTH,
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
from tripper_recon.types.indicators import Indicator, IndicatorType, detect
from tripper_recon.utils.env import load_env
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
        if output == "console":
            panel = render_ip_analysis(target, res.data, ports_limit=ports_limit, explain=explain, defang=defang)
            console.print(panel)
            console.print()

    if output == "json":
        out = {
            "ok": failed == 0,
            "source_file": source_file,
            "total": len(targets),
            "succeeded": succeeded,
            "failed": failed,
            "results": results,
        }
        console.print_json(data=out)
    else:
        color = "green" if failed == 0 else "yellow"
        console.print(f"[{color}]Summary:[/] total={len(targets)} succeeded={succeeded} failed={failed}")

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

    if output == "json":
        console.print_json(data=res.model_dump())
        return 0

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
        return 0

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

    return 0


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

    if output == "json":
        # Never defanged. The export carries the URL byte-for-byte because a machine consumes
        # it and `evil[.]example` is not a hostname.
        console.print_json(data=res.model_dump())
        return 0

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

    return 0


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
        else:
            console.print(render_detection(indicator, defang=defang, explain=explain))
        return 0 if indicator.is_known else 2

    route = _ROUTABLE.get(indicator.type)
    if route is None:
        reason = _UNROUTABLE_REASON.get(indicator.type, "no subcommand investigates this indicator type")
        log["error"]("Indicator has no route", indicator=indicator.value, type=indicator.type.value)
        if output == "json":
            console.print_json(data={**_detection_payload(indicator), "routed_to": None, "reason": reason})
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


def _default_output_dir() -> Path:
    here = Path(__file__).resolve()
    root = here.parent.parent
    return root / "outputs"


async def _cmd_asn(
    asn: int,
    *,
    output: str = "console",
    neighbors: int = 8,
    enrich: bool = False,
    enrich_limit: int = 50,
    monochrome: bool = False,  # retained for flag compat, rich handles this via terminal settings or NO_COLOR
    prefixes_out: str | None = None,
    prefixes: str = "both",
) -> int:
    res = await investigate_asn(asn, resolve_neighbors=neighbors, enrich=enrich, enrich_limit=enrich_limit)
    if not res.ok:
        log["error"]("ASN lookup failed", asn=asn, errors=res.errors)
        if output == "console":
            console.print(f"[bold red]ASN lookup failed:[/] {esc('; '.join(res.errors))}")
            _print_failure_coverage(res.data)
        return 1

    if output == "json":
        console.print_json(data=res.model_dump())
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
                use_color=not monochrome,
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
            console.print(render_asn_bgp_panels(asn, meta, bgp, use_color=not monochrome))

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


def main() -> None:
    load_env()
    parser = argparse.ArgumentParser(
        prog="tripper-recon", description="Passive OSINT investigations of IPs, domains, URLs and ASNs"
    )
    parser.add_argument(
        "-o",
        "--format",
        choices=["console", "json"],
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
    parser.add_argument("-V", "--version", action="version", version=f"tripper-recon {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    p_ip = sub.add_parser("ip", help="Investigate an IP address")
    p_ip.add_argument("ip", type=str)
    # default=SUPPRESS so an omitted subcommand flag leaves the top-level value in place.
    # With a real default, argparse overwrote it and `-o json ip 8.8.8.8` silently emitted console text.
    p_ip.add_argument("-o", "--format", choices=["console", "json"], default=argparse.SUPPRESS, help="Output format")
    p_ip.add_argument(
        "--ports-limit", type=str, default="25", help="Limit number of ports shown (use 'all' to show all)"
    )
    p_ip.add_argument("--explain", action="store_true", help=_EXPLAIN_HELP)

    p_domain = sub.add_parser("domain", help="Investigate a domain")
    p_domain.add_argument("domain", type=str)
    p_domain.add_argument(
        "-o", "--format", choices=["console", "json"], default=argparse.SUPPRESS, help="Output format"
    )
    p_domain.add_argument(
        "--ports-limit",
        type=str,
        default="25",
        help="Limit number of ports shown per IP in console (use 'all' to show all)",
    )
    p_domain.add_argument("--explain", action="store_true", help=_EXPLAIN_HELP)

    p_asn = sub.add_parser("asn", help="Lookup ASN details")
    p_asn.add_argument("asn", type=str)
    p_asn.add_argument("-o", "--format", choices=["console", "json"], default=argparse.SUPPRESS, help="Output format")
    p_asn.add_argument("--neighbors", type=int, default=8, help="Resolve first N neighbors to names")
    p_asn.add_argument("--enrich", action="store_true", help="Enrich prefix info via whois/pWhois (slower)")
    p_asn.add_argument("--enrich-limit", type=int, default=50, help="Limit inetnum lines during enrichment")
    p_asn.add_argument("--monochrome", action="store_true", help="Disable ANSI colors in console output")
    p_asn.add_argument("--prefixes-out", type=str, default=None, help="Write full prefix list to a text file")
    p_asn.add_argument(
        "--prefixes",
        choices=["v4", "v6", "both"],
        default="both",
        help="Which prefixes to include when writing --prefixes-out",
    )

    p_url = sub.add_parser("url", help="Investigate a URL, its host, and the addresses it resolves to")
    p_url.add_argument("url", type=str)
    p_url.add_argument("-o", "--format", choices=["console", "json"], default=argparse.SUPPRESS, help="Output format")
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

    p_check = sub.add_parser("check", help="Detect what an indicator is and route it to the right lookup")
    p_check.add_argument("target", type=str)
    p_check.add_argument("-o", "--format", choices=["console", "json"], default=argparse.SUPPRESS, help="Output format")
    p_check.add_argument(
        "--detect-only",
        action="store_true",
        help="Classify and stop. Costs no provider quota: detection is a pure function over the string",
    )
    p_check.add_argument("--depth", choices=list(URL_DEPTHS), default=DEFAULT_URL_DEPTH, help="Depth, if it is a URL")
    p_check.add_argument("--ports-limit", type=str, default="25", help="Limit ports shown per address")
    p_check.add_argument("--explain", action="store_true", help=_EXPLAIN_HELP)

    p_bulk = sub.add_parser("bulk", help="Extract and triage every indicator in a wall of pasted text")
    p_bulk.add_argument(
        "source",
        type=str,
        nargs="?",
        default=None,
        help="A file to read, '-' or omitted for stdin, or the text itself",
    )
    p_bulk.add_argument("-o", "--format", choices=["console", "json"], default=argparse.SUPPRESS, help="Output format")
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

    match args.cmd:
        case "ip":
            code = asyncio.run(
                _cmd_ip(
                    args.ip,
                    output=args.format,
                    ports_limit=getattr(args, "ports_limit", "25"),
                    explain=getattr(args, "explain", False),
                    defang=defang,
                )
            )
        case "domain":
            code = asyncio.run(
                _cmd_domain(
                    args.domain,
                    output=args.format,
                    ports_limit=getattr(args, "ports_limit", "25"),
                    explain=getattr(args, "explain", False),
                    defang=defang,
                )
            )
        case "url":
            code = asyncio.run(
                _cmd_url(
                    args.url,
                    output=args.format,
                    depth=getattr(args, "depth", DEFAULT_URL_DEPTH),
                    ports_limit=getattr(args, "ports_limit", "25"),
                    explain=getattr(args, "explain", False),
                    defang=defang,
                )
            )
        case "check":
            code = asyncio.run(
                _cmd_check(
                    args.target,
                    output=args.format,
                    detect_only=getattr(args, "detect_only", False),
                    depth=getattr(args, "depth", DEFAULT_URL_DEPTH),
                    ports_limit=getattr(args, "ports_limit", "25"),
                    explain=getattr(args, "explain", False),
                    defang=defang,
                )
            )
        case "bulk":
            code = asyncio.run(
                _cmd_bulk(
                    args.source,
                    output=args.format,
                    investigate=getattr(args, "investigate", False),
                    max_targets=getattr(args, "max_targets", 10),
                    filter_infrastructure=not getattr(args, "no_filter", False),
                    ports_limit=getattr(args, "ports_limit", "25"),
                    explain=getattr(args, "explain", False),
                    defang=defang,
                )
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
                code = asyncio.run(
                    _cmd_asn(
                        asn_int,
                        output=args.format,
                        neighbors=args.neighbors,
                        enrich=args.enrich,
                        enrich_limit=args.enrich_limit,
                        monochrome=args.monochrome,
                        prefixes_out=getattr(args, "prefixes_out", None),
                        prefixes=getattr(args, "prefixes", "both"),
                    )
                )
        case _:
            code = 2
    raise SystemExit(code)


if __name__ == "__main__":
    main()
