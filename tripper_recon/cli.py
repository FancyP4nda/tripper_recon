from __future__ import annotations

import argparse
import asyncio
import os
from typing import Any, Dict, List
from pathlib import Path
from urllib.parse import urlparse

from tripper_recon import __version__
from tripper_recon.orchestrators import investigate_asn, investigate_domain, investigate_ip
from tripper_recon.reporting.console import render_ip_analysis, render_asn_header
from tripper_recon.utils.logging import logger
from tripper_recon.utils.env import load_env


log = logger("cli")


def _print(s: str) -> None:
    os.sys.stdout.write(s)


def _fmt_provider_error(detail: Any) -> str:
    if isinstance(detail, dict):
        parts: list[str] = []
        status = detail.get("status_code")
        if status is None:
            status = detail.get("status")
        if status is not None:
            parts.append(f"status={status}")
        reason = detail.get("reason")
        if reason:
            parts.append(f"reason={reason}")
        message = detail.get("message")
        if message:
            parts.append(f"message={message}")
        url = detail.get("url")
        if url:
            parts.append(f"url={url}")
        body = detail.get("body")
        if body:
            parts.append(f"body={body}")
        return " | ".join(parts) if parts else "error"
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

    _print("Whois Lookup\n")
    for key in priority:
        target = key.lower()
        for k, v in entries:
            if k.lower() == target:
                _print(f"{k}: {v}\n")
    _print("\n")


def _print_certificate_block(cert: Dict[str, Any], jarm: Any) -> None:
    if not cert:
        return
    _print("Last HTTPS Certificate\n")
    if jarm:
        _print(f"JARM fingerprint: {jarm}\n")
    version = cert.get("version")
    if version is not None:
        _print(f"Version: {version}\n")
    serial = cert.get("serial_number")
    if serial:
        _print(f"Serial Number: {serial}\n")
    thumbprint = cert.get("thumbprint_sha256")
    if thumbprint:
        _print(f"Thumbprint: {thumbprint}\n")
    sig_alg = cert.get("signature_algorithm")
    if sig_alg:
        _print(f"Signature Algorithm: {sig_alg}\n")
    issuer = cert.get("issuer")
    if issuer:
        _print(f"Issuer: {_fmt_dn(issuer)}\n")
    validity = cert.get("validity") or {}
    not_before = validity.get("not_before")
    if not_before:
        _print(f"Not Before: {not_before}\n")
    not_after = validity.get("not_after")
    if not_after:
        _print(f"Not After: {not_after}\n")
    subject = cert.get("subject")
    if subject:
        _print(f"Subject: {_fmt_dn(subject)}\n")
    _print("\n")


async def _cmd_ip(ip: str, *, output: str = "console", ports_limit: str = "25") -> int:
    res = await investigate_ip(ip)
    if not res.ok:
        log["error"]("IP investigation failed", ip=ip, errors=res.errors)
        return 1
    if output == "json":
        _print(res.model_dump_json(indent=2) + "\n")
    else:
        line = f"| IP lookup for {ip} |"
        top = "+" + ("-" * (len(line) - 2)) + "+"
        bottom = "+" + ("-" * (len(line) - 2)) + "+"
        _print(top + "\n" + line + "\n" + bottom + "\n\n")
        _print("ip_intelligence:\n")
        block = render_ip_analysis(ip, res.data, ports_limit=ports_limit).strip().splitlines()
        for entry in block:
            _print(f"  {entry}\n")
        _print("\n")
    return 0


async def _cmd_domain(domain: str, *, output: str = "console", ports_limit: str = "25") -> int:
    from urllib.parse import urlparse
    parsed = urlparse(domain)
    norm_domain = parsed.hostname or domain.strip().strip("/")

    res = await investigate_domain(norm_domain)
    if not res.ok:
        log["error"]("Domain investigation failed", domain=domain, errors=res.errors)
        return 1

    if output == "json":
        _print(res.model_dump_json(indent=2) + "\n")
        return 0

    data = res.data
    domain_intel = data.get("domain_intel", {})
    domain_errors = data.get("domain_errors", {})
    ips = data.get("ips", [])

# Dynamic boxed header (ASCII to avoid encoding issues)
    line = f"| Domain lookup for {norm_domain} |"
    top = "+" + ("-" * (len(line) - 2)) + "+"
    bottom = "+" + ("-" * (len(line) - 2)) + "+"
    _print(top + "\n" + line + "\n" + bottom + "\n\n")

    radar_domain_link = f"https://radar.cloudflare.com/domain/{norm_domain}"
    _print("domain_intelligence:\n")
    _print(f"  cloudflare_radar_link: {radar_domain_link}\n")
    vt_dom = domain_intel.get("virustotal", {}) if isinstance(domain_intel, dict) else {}
    if vt_dom:
        vt_stats = vt_dom.get("vt_last_analysis_stats", {}) or {}
        vt_total = 0
        if isinstance(vt_stats, dict):
            for v in vt_stats.values():
                try:
                    vt_total += int(v or 0)
                except Exception:
                    continue
        try:
            vt_mal = int(vt_stats.get("malicious", 0) or 0)
        except Exception:
            vt_mal = 0
        _print(f"  virustotal_detections: {vt_mal}/{vt_total}\n")
        vt_reputation = vt_dom.get("vt_reputation")
        if vt_reputation is not None:
            _print(f"  virustotal_community_score: {vt_reputation}\n")
        categories = vt_dom.get("vt_categories") or {}
        if isinstance(categories, dict) and categories:
            cats = ", ".join(sorted({str(val) for val in categories.values() if val}))
            if cats:
                _print(f"  virustotal_categories: {cats}\n")
        dns_records = vt_dom.get("vt_dns_records") or []
        passive_ips = []
        if isinstance(dns_records, list):
            for rec in dns_records:
                if isinstance(rec, dict) and rec.get("type") in {"A", "AAAA"} and rec.get("value"):
                    passive_ips.append(str(rec.get("value")))
        if passive_ips:
            preview = ", ".join(passive_ips[:5])
            suffix = "" if len(passive_ips) <= 5 else f" ... (+{len(passive_ips) - 5} more)"
            _print(f"  virustotal_passive_ips: {preview}{suffix}\n")
    vt_link_domain = (vt_dom.get("vt_link") if isinstance(vt_dom, dict) else None) or f"https://www.virustotal.com/gui/domain/{norm_domain}"
    _print(f"  virustotal_analysis_link: {vt_link_domain}\n")
    _print(f"  abuseipdb_analysis_link: https://www.abuseipdb.com/check/{norm_domain}\n")

    otx_dom = domain_intel.get("otx", {}) if isinstance(domain_intel, dict) else {}
    otx_link_domain = f"https://otx.alienvault.com/indicator/domain/{norm_domain}"
    if otx_dom:
        pulse_count = otx_dom.get("otx_pulse_count")
        if pulse_count is not None:
            _print(f"  otx_pulse_count: {pulse_count}\n")
        _print(f"  otx_pulse_link: {otx_link_domain}\n")
        titles = otx_dom.get("otx_pulse_titles") or []
        if isinstance(titles, list) and titles:
            _print(f"  otx_pulse_titles: {'; '.join(str(t) for t in titles)}\n")
    else:
        _print(f"  otx_pulse_link: {otx_link_domain}\n")
    _print("\n")

    if vt_dom:
        _print_whois_block(vt_dom.get("vt_whois"))
        cert_info = vt_dom.get("vt_last_https_certificate") or {}
        jarm_value = vt_dom.get("vt_last_https_certificate_jarm")
        _print_certificate_block(cert_info, jarm_value)

    if domain_errors:
        _print("domain_provider_errors:\n")
        for name, detail in domain_errors.items():
            _print(f"  - {name}: {_fmt_provider_error(detail)}\n")
        _print("\n")

    _print(f'- Resolving "{norm_domain}"... {len(ips)} IP addresses found:\n\n\n')

    if not ips:
        _print("No IPs available for IP-level enrichment.\n")
        return 0

    for item in ips:
        item_ip = item.get("ip", "")
        block = render_ip_analysis(item_ip, item, ports_limit=ports_limit).strip()
        _print(block + "\n\n")

    return 0

 


def _default_output_dir() -> Path:
    # Standard output directory at project root: tripper_recon/outputs
    here = Path(__file__).resolve()
    root = here.parent.parent  # tripper_recon/
    out_dir = root / "outputs"
    return out_dir


async def _cmd_asn(
    asn: int,
    *,
    output: str = "console",
    neighbors: int = 8,
    enrich: bool = False,
    enrich_limit: int = 50,
    monochrome: bool = False,
    prefixes_out: str | None = None,
    prefixes: str = "both",
) -> int:
    res = await investigate_asn(asn, resolve_neighbors=neighbors, enrich=enrich, enrich_limit=enrich_limit)
    if not res.ok:
        log["error"]("ASN lookup failed", asn=asn, errors=res.errors)
        return 1
    if output == "json":
        _print(res.model_dump_json(indent=2) + "\n")
    else:
        meta = res.data.get("meta", {})
        from tripper_recon.reporting.console import render_asn_header, render_asn_bgp_panels
        # Print a boxed header matching the BGP panel style
        name = meta.get("name") or ""
        _print("╭───────────────────────────────────────────╮\n")
        _print((f"│ ASN lookup for AS{asn} ({name}) │\n") if name else (f"│ ASN lookup for AS{asn} │\n"))
        # Exactly one blank line after the boxed heading
        _print("╰───────────────────────────────────────────╯\n\n")
        # Then print details from renderer, skipping its internal header lines
        hdr = render_asn_header(asn, meta, use_color=(not monochrome))
        hdr_lines = hdr.splitlines()
        # Defensive: skip first two lines if they are the internal header; otherwise print all
        if len(hdr_lines) >= 3 and (hdr_lines[0].strip().startswith("ASN lookup") or ("AS Number" in (hdr_lines[2] if len(hdr_lines) > 2 else ""))):
            _print("\n".join(hdr_lines[2:]) + "\n")
        else:
            _print(hdr)
        # Ensure Peering @IXPs line is present
        if "Peering @IXPs" not in hdr:
            ixps = meta.get("ixps") or []
            ixp_names = []
            if isinstance(ixps, list):
                for i in ixps:
                    if isinstance(i, dict) and i.get("name"):
                        ixp_names.append(str(i.get("name")))
            if ixp_names:
                _print(f" Peering @IXPs ──> {' • '.join(ixp_names)}\n")
            else:
                _print(" Peering @IXPs ──> NONE\n")
        if not meta:
            _print("Note: Cloudflare Radar API token missing or request failed. Set CLOUDFLARE_API_TOKEN in .env for full ASN details.\n")
        bgp = res.data.get("bgp", {})
        if bgp:
            # Ensure a blank line before the BGP informations heading
            _print("\n")
            _print(render_asn_bgp_panels(asn, meta, bgp, use_color=(not monochrome)))
        errors = res.data.get("errors") or {}
        if errors:
            _print("provider_errors:\n")
            for name, detail in errors.items():
                _print(f"  - {name}: {_fmt_provider_error(detail)}\n")
        # Optional: write full prefix lists to a text file
        if prefixes_out:
            v4_full = (res.data.get("bgp", {}) or {}).get("ripe_prefixes_v4") or []
            v6_full = (res.data.get("bgp", {}) or {}).get("ripe_prefixes_v6") or []
            name = meta.get("name") or ""
            out_lines: list[str] = []
            out_lines.append("╭──────────────────────────────────────────────────╮")
            title = f"│ Aggregated IP resources for AS{asn} ({name}) │" if name else f"│ Aggregated IP resources for AS{asn} │"
            out_lines.append(title)
            out_lines.append("╰──────────────────────────────────────────────────╯")
            out_lines.append("")
            if prefixes in ("v4", "both"):
                out_lines.append("───── IPv4 ─────")
                if v4_full:
                    out_lines.extend([str(p) for p in v4_full])
                else:
                    out_lines.append("NONE")
                if prefixes == "both":
                    out_lines.append("")
            if prefixes in ("v6", "both"):
                out_lines.append("───── IPv6 ─────")
                if v6_full:
                    out_lines.extend([str(p) for p in v6_full])
                else:
                    out_lines.append("NONE")

            # Resolve output path: if only a filename is provided, write to the standard outputs/ directory
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
            except Exception as e:
                log["error"]("Failed writing prefixes file", path=str(out_path), error=str(e))
    return 0


def main() -> None:
    # Load .env if present
    load_env()
    parser = argparse.ArgumentParser(prog="tripper-recon", description="Unified OSINT IP/Domain/ASN investigations")
    parser.add_argument("-o", "--format", choices=["console", "json"], default="console", help="Output format")
    parser.add_argument("-V", "--version", action="version", version=f"tripper-recon {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    p_ip = sub.add_parser("ip", help="Investigate an IP address")
    p_ip.add_argument("ip", type=str)
    p_ip.add_argument("-o", "--format", choices=["console", "json"], default=None, help="Output format")
    p_ip.add_argument("--ports-limit", type=str, default="25", help="Limit number of ports shown (use 'all' to show all)")

    p_domain = sub.add_parser("domain", help="Investigate a domain")
    p_domain.add_argument("domain", type=str)
    p_domain.add_argument("-o", "--format", choices=["console", "json"], default=None, help="Output format")
    p_domain.add_argument("--ports-limit", type=str, default="25", help="Limit number of ports shown per IP in console (use 'all' to show all)")


    p_asn = sub.add_parser("asn", help="Lookup ASN details")
    p_asn.add_argument("asn", type=str)
    p_asn.add_argument("-o", "--format", choices=["console", "json"], default=None, help="Output format")
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

