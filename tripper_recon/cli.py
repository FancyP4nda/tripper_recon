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
      target, a non-numeric ASN, or no subcommand.
===== =========================================================================================

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
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

from rich.console import Console

from tripper_recon import __version__
from tripper_recon.orchestrators import investigate_asn, investigate_domain, investigate_ip
from tripper_recon.reporting.console import (
    esc,
    no_data_text,
    provider_outcome,
    render_asn_bgp_panels,
    render_asn_header,
    render_coverage,
    render_domain_header,
    render_ip_analysis,
    run_fields,
)
from tripper_recon.utils.env import load_env
from tripper_recon.utils.http import configure_rate_limit, configure_user_agent
from tripper_recon.utils.logging import logger

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


async def _cmd_ip(ip: str, *, output: str = "console", ports_limit: str = "25", explain: bool = False) -> int:
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
                console.print(f"[bold red]IP: {esc(target)}[/]")
                console.print(f"  error: {esc(msg)}\n")
            continue

        res = item

        if not res.ok:
            log["error"]("IP investigation failed", ip=target, errors=res.errors)
            failed += 1
            results.append({"target": target, **res.model_dump()})
            if output == "console":
                console.print(f"[bold red]IP: {esc(target)}[/]")
                console.print(f"  error: {esc('; '.join(res.errors)) if res.errors else 'Investigation failed'}\n")
                _print_failure_coverage(res.data)
            continue

        succeeded += 1
        results.append({"target": target, **res.model_dump()})
        if output == "console":
            panel = render_ip_analysis(target, res.data, ports_limit=ports_limit, explain=explain)
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


async def _cmd_domain(domain: str, *, output: str = "console", ports_limit: str = "25", explain: bool = False) -> int:
    # urlparse raises on some malformed input -- notably a defanged indicator such as
    # `hxxps://evil[.]com`, which reads as an invalid IPv6 literal. Analysts paste defanged
    # indicators routinely, so fail with an instruction instead of a traceback.
    try:
        parsed = urlparse(domain)
        norm_domain = parsed.hostname or domain.strip().strip("/")
    except ValueError:
        hint = " It looks defanged - refang it first." if _looks_defanged(domain) else ""
        log["error"]("Could not parse target", domain=domain)
        if output == "console":
            console.print(f"[bold red]Could not parse target:[/] {esc(domain)}.{hint}")
        return 2

    if _looks_defanged(norm_domain):
        log["error"]("Target looks defanged", domain=norm_domain)
        if output == "console":
            console.print(
                f"[bold red]Target looks defanged:[/] {esc(norm_domain)}\n"
                "Refang it first, e.g. hxxps://evil[.]com -> evil.com"
            )
        return 2

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
        )
    )

    console.print("[bold]domain_intelligence:[/]")
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
            preview = ", ".join(esc(value) for value in passive_ips[:5])
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
    line = f'- Resolving "{norm_domain}"... {resolved} addresses resolved, {investigated} investigated'
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
        )
        console.print(panel)
        console.print()

    return 0


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
    parser = argparse.ArgumentParser(prog="tripper-recon", description="Passive OSINT IP/Domain/ASN investigations")
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

    args = parser.parse_args()

    if args.cmd is None:
        parser.print_help()
        raise SystemExit(2)

    configure_rate_limit(args.rate_limit)
    if getattr(args, "user_agent", None):
        configure_user_agent(args.user_agent)

    match args.cmd:
        case "ip":
            code = asyncio.run(
                _cmd_ip(
                    args.ip,
                    output=args.format,
                    ports_limit=getattr(args, "ports_limit", "25"),
                    explain=getattr(args, "explain", False),
                )
            )
        case "domain":
            code = asyncio.run(
                _cmd_domain(
                    args.domain,
                    output=args.format,
                    ports_limit=getattr(args, "ports_limit", "25"),
                    explain=getattr(args, "explain", False),
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
