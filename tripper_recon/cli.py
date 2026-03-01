from __future__ import annotations

import argparse
import asyncio
import json
import os
from typing import Any, Dict, List
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel

from tripper_recon import __version__
from tripper_recon.orchestrators import investigate_asn, investigate_domain, investigate_ip
from tripper_recon.reporting.console import render_ip_analysis, render_asn_header, render_asn_bgp_panels
from tripper_recon.utils.http import configure_rate_limit, configure_user_agent
from tripper_recon.utils.logging import logger
from tripper_recon.utils.env import load_env

log = logger("cli")
console = Console()


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
        "Domain Name", "Registry Domain ID", "Registrar", "Registrar IANA ID",
        "Registrar URL", "Registrar WHOIS Server", "Registrar Abuse Contact Email",
        "Registrar Abuse Contact Phone", "Updated Date", "Creation Date",
        "Registry Expiry Date", "Domain Status", "Name Server", "DNSSEC",
    ]

    console.print("\n[bold white]Whois Lookup[/]")
    for key in priority:
        target = key.lower()
        for k, v in entries:
            if k.lower() == target:
                console.print(f"  [cyan]{k}[/]: {v}")
    console.print()


def _print_certificate_block(cert: Dict[str, Any], jarm: Any) -> None:
    if not cert:
        return
    console.print("[bold white]Last HTTPS Certificate[/]")
    if jarm:
        console.print(f"  [cyan]JARM fingerprint[/]: {jarm}")
    for key, label in [
        ("version", "Version"),
        ("serial_number", "Serial Number"),
        ("thumbprint_sha256", "Thumbprint"),
        ("signature_algorithm", "Signature Algorithm")
    ]:
        val = cert.get(key)
        if val:
            console.print(f"  [cyan]{label}[/]: {val}")
    
    issuer = cert.get("issuer")
    if issuer:
        console.print(f"  [cyan]Issuer[/]: {_fmt_dn(issuer)}")
        
    validity = cert.get("validity") or {}
    if validity.get("not_before"):
        console.print(f"  [cyan]Not Before[/]: {validity.get('not_before')}")
    if validity.get("not_after"):
        console.print(f"  [cyan]Not After[/]: {validity.get('not_after')}")
        
    subject = cert.get("subject")
    if subject:
        console.print(f"  [cyan]Subject[/]: {_fmt_dn(subject)}")
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





async def _cmd_ip(ip: str, *, output: str = "console", ports_limit: str = "25") -> int:
    targets, source_file = _load_ip_targets(ip)
    if source_file and not targets:
        log["error"]("IP list file is empty", file=source_file)
        return 1

    if output == "console" and source_file:
        console.print(f"\n[bold green]Processing {len(targets)} targets from \"{source_file}\"[/]\n")

    tasks = [investigate_ip(t) for t in targets]
    gathered = await asyncio.gather(*tasks, return_exceptions=True)

    results: List[Dict[str, Any]] = []
    failed = 0
    succeeded = 0

    for target, item in zip(targets, gathered):
        if isinstance(item, Exception):
            err = item
            msg = f"{type(err).__name__}: {err}"
            log["error"]("IP investigation crashed", ip=target, error=msg)
            failed += 1
            results.append({"target": target, "ok": False, "warnings": [], "errors": [msg], "data": {}})
            if output == "console":
                console.print(f"[bold red]IP: {target}[/]")
                console.print(f"  error: {msg}\n")
            continue

        res = item

        if not res.ok:
            log["error"]("IP investigation failed", ip=target, errors=res.errors)
            failed += 1
            results.append({"target": target, **res.model_dump()})
            if output == "console":
                console.print(f"[bold red]IP: {target}[/]")
                console.print(f"  error: {'; '.join(res.errors) if res.errors else 'Investigation failed'}\n")
            continue
            
        succeeded += 1
        results.append({"target": target, **res.model_dump()})
        if output == "console":
            panel = render_ip_analysis(target, res.data, ports_limit=ports_limit)
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


async def _cmd_domain(domain: str, *, output: str = "console", ports_limit: str = "25") -> int:
    parsed = urlparse(domain)
    norm_domain = parsed.hostname or domain.strip().strip("/")

    res = await investigate_domain(norm_domain)
    if not res.ok:
        log["error"]("Domain investigation failed", domain=domain, errors=res.errors)
        if output == "console":
            console.print(f"[bold red]Domain investigation failed:[/] {'; '.join(res.errors)}")
        return 1

    if output == "json":
        console.print_json(data=res.model_dump())
        return 0

    data = res.data
    domain_intel = data.get("domain_intel", {})
    domain_errors = data.get("domain_errors", {})
    ips = data.get("ips", [])

    console.print(f"\n[bold white]--- Domain lookup for {norm_domain} ---[/]")
    console.print("\n[bold]domain_intelligence:[/]")
    console.print(f"  [cyan]cloudflare_radar_link[/]: https://radar.cloudflare.com/domain/{norm_domain}")
    
    vt_dom = domain_intel.get("virustotal", {}) if isinstance(domain_intel, dict) else {}
    if vt_dom:
        vt_stats = vt_dom.get("vt_last_analysis_stats", {}) or {}
        vt_total = 0
        if isinstance(vt_stats, dict):
            vt_total = sum(int(v or 0) for v in vt_stats.values() if str(v).isdigit())
        vt_mal = int(vt_stats.get("malicious", 0) or 0)
        
        vt_color = "red" if vt_mal > 0 else "green"
        console.print(f"  [cyan]virustotal_detections[/]: [{vt_color}]{vt_mal}/{vt_total}[/]")
        
        if vt_dom.get("vt_reputation") is not None:
            console.print(f"  [cyan]virustotal_community_score[/]: {vt_dom.get('vt_reputation')}")
            
        cats = vt_dom.get("vt_categories") or {}
        if isinstance(cats, dict) and cats:
            j_cats = ", ".join(sorted({str(val) for val in cats.values() if val}))
            if j_cats:
                console.print(f"  [cyan]virustotal_categories[/]: {j_cats}")
                
        dns_records = vt_dom.get("vt_dns_records") or []
        passive_ips = [str(r.get("value")) for r in dns_records if isinstance(r, dict) and r.get("type") in {"A", "AAAA"} and r.get("value")]
        if passive_ips:
            preview = ", ".join(passive_ips[:5])
            suffix = "" if len(passive_ips) <= 5 else f" ... (+{len(passive_ips) - 5} more)"
            console.print(f"  [cyan]virustotal_passive_ips[/]: {preview}{suffix}")
            
    vt_link = (vt_dom.get("vt_link") if isinstance(vt_dom, dict) else None) or f"https://www.virustotal.com/gui/domain/{norm_domain}"
    console.print(f"  [cyan]virustotal_analysis_link[/]: {vt_link}")
    console.print(f"  [cyan]abuseipdb_analysis_link[/]: https://www.abuseipdb.com/check/{norm_domain}")

    otx_dom = domain_intel.get("otx", {}) if isinstance(domain_intel, dict) else {}
    otx_link = f"https://otx.alienvault.com/indicator/domain/{norm_domain}"
    if otx_dom:
        if otx_dom.get("otx_pulse_count") is not None:
            console.print(f"  [cyan]otx_pulse_count[/]: {otx_dom.get('otx_pulse_count')}")
        console.print(f"  [cyan]otx_pulse_link[/]: {otx_link}")
        titles = otx_dom.get("otx_pulse_titles") or []
        if isinstance(titles, list) and titles:
            console.print(f"  [cyan]otx_pulse_titles[/]: {'; '.join(str(t) for t in titles)}")
    else:
        console.print(f"  [cyan]otx_pulse_link[/]: {otx_link}")
        
    console.print()

    if vt_dom:
        _print_whois_block(vt_dom.get("vt_whois"))
        _print_certificate_block(vt_dom.get("vt_last_https_certificate") or {}, vt_dom.get("vt_last_https_certificate_jarm"))

    if domain_errors:
        console.print("[bold red]domain_provider_errors:[/]")
        for name, detail in domain_errors.items():
            console.print(f"  - [bold]{name}[/]: {_fmt_provider_error(detail)}")
        console.print()

    console.print(f'\n[bold]- Resolving "{norm_domain}"... {len(ips)} IP addresses found:[/]\n\n')

    if not ips:
        console.print("No IPs available for IP-level enrichment.\n")
        return 0

    for item in ips:
        item_ip = item.get("ip", "")
        panel = render_ip_analysis(item_ip, item, ports_limit=ports_limit)
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
    monochrome: bool = False, # retained for flag compat, rich handles this via terminal settings or NO_COLOR
    prefixes_out: str | None = None,
    prefixes: str = "both",
) -> int:
    res = await investigate_asn(asn, resolve_neighbors=neighbors, enrich=enrich, enrich_limit=enrich_limit)
    if not res.ok:
        log["error"]("ASN lookup failed", asn=asn, errors=res.errors)
        if output == "console":
            console.print(f"[bold red]ASN lookup failed:[/] {'; '.join(res.errors)}")
        return 1
        
    if output == "json":
        console.print_json(data=res.model_dump())
    else:
        meta = res.data.get("meta", {})
        console.print(render_asn_header(asn, meta, use_color=not monochrome))
        console.print()

        if not meta:
            console.print("[yellow]Note: Cloudflare Radar API token missing or request failed. Set CLOUDFLARE_API_TOKEN in .env for full ASN details.[/]\n")
            
        bgp = res.data.get("bgp", {})
        if bgp:
            console.print(render_asn_bgp_panels(asn, meta, bgp, use_color=not monochrome))
            
        errors = res.data.get("errors") or {}
        if errors:
            console.print("\n[bold red]provider_errors:[/]")
            for name, detail in errors.items():
                console.print(f"  - [bold]{name}[/]: {_fmt_provider_error(detail)}")

        if prefixes_out:
            v4_full = (res.data.get("bgp", {}) or {}).get("ripe_prefixes_v4") or []
            v6_full = (res.data.get("bgp", {}) or {}).get("ripe_prefixes_v6") or []
            
            out_lines: list[str] = []
            name = meta.get("name") or ""
            title = f"--- Aggregated IP resources for AS{asn} ({name}) ---" if name else f"--- Aggregated IP resources for AS{asn} ---"
            out_lines.append(title)
            out_lines.append("")
            
            if prefixes in ("v4", "both"):
                out_lines.append("───── IPv4 ─────")
                out_lines.extend(str(p) for p in v4_full) if v4_full else out_lines.append("NONE")
                if prefixes == "both": out_lines.append("")
            if prefixes in ("v6", "both"):
                out_lines.append("───── IPv6 ─────")
                out_lines.extend(str(p) for p in v6_full) if v6_full else out_lines.append("NONE")

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
    parser = argparse.ArgumentParser(prog="tripper-recon", description="Unified OSINT IP/Domain/ASN investigations")
    parser.add_argument("-o", "--format", choices=["console", "json"], default="console", help="Output format")
    parser.add_argument("--rate-limit", type=int, default=10, help="Max concurrent outgoing API requests across global providers")
    parser.add_argument("--user-agent", type=str, default=None, help="Custom User-Agent string to spoof in HTTP requests")
    parser.add_argument("-V", "--version", action="version", version=f"tripper-recon {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    p_ip = sub.add_parser("ip", help="Investigate an IP address")
    p_ip.add_argument("ip", type=str)
    p_ip.add_argument("-o", "--format", choices=["console", "json"], default="console", help="Output format")
    p_ip.add_argument("--ports-limit", type=str, default="25", help="Limit number of ports shown (use 'all' to show all)")

    p_domain = sub.add_parser("domain", help="Investigate a domain")
    p_domain.add_argument("domain", type=str)
    p_domain.add_argument("-o", "--format", choices=["console", "json"], default="console", help="Output format")
    p_domain.add_argument("--ports-limit", type=str, default="25", help="Limit number of ports shown per IP in console (use 'all' to show all)")


    p_asn = sub.add_parser("asn", help="Lookup ASN details")
    p_asn.add_argument("asn", type=str)
    p_asn.add_argument("-o", "--format", choices=["console", "json"], default="console", help="Output format")
    p_asn.add_argument("--neighbors", type=int, default=8, help="Resolve first N neighbors to names")
    p_asn.add_argument("--enrich", action="store_true", help="Enrich prefix info via whois/pWhois (slower)")
    p_asn.add_argument("--enrich-limit", type=int, default=50, help="Limit inetnum lines during enrichment")
    p_asn.add_argument("--monochrome", action="store_true", help="Disable ANSI colors in console output")
    p_asn.add_argument("--prefixes-out", type=str, default=None, help="Write full prefix list to a text file")
    p_asn.add_argument("--prefixes", choices=["v4", "v6", "both"], default="both", help="Which prefixes to include when writing --prefixes-out")

    args = parser.parse_args()

    if args.cmd is None:
        parser.print_help()
        raise SystemExit(2)

    configure_rate_limit(args.rate_limit)
    if getattr(args, "user_agent", None):
        configure_user_agent(args.user_agent)

    match args.cmd:
        case "ip":
            code = asyncio.run(_cmd_ip(args.ip, output=args.format, ports_limit=getattr(args, "ports_limit", "25")))
        case "domain":
            code = asyncio.run(_cmd_domain(args.domain, output=args.format, ports_limit=getattr(args, "ports_limit", "25")))
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
                code = asyncio.run(_cmd_asn(
                    asn_int,
                    output=args.format or "console",
                    neighbors=args.neighbors,
                    enrich=args.enrich,
                    enrich_limit=args.enrich_limit,
                    monochrome=args.monochrome,
                    prefixes_out=getattr(args, "prefixes_out", None),
                    prefixes=getattr(args, "prefixes", "both"),
                ))
        case _:
            code = 2
    raise SystemExit(code)


if __name__ == "__main__":
    main()
