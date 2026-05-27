from __future__ import annotations

import argparse
import asyncio
import os
import sys
from typing import Any, Dict, List
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from tripper_recon import __version__
from tripper_recon.orchestrators import investigate_asn, investigate_domain, investigate_ip
from tripper_recon.reporting.console import render_ip_analysis, render_asn_header, render_asn_bgp_panels
from tripper_recon.provider_registry import ProviderSelectionError, select_providers
from tripper_recon.schema_v1 import (
    ProviderStatus,
    domain_result_to_schema_v1,
    failed_domain_result_v1,
    failed_result_v1,
    failed_ip_result_v1,
    failed_url_result_v1,
    ip_result_to_schema_v1,
)
from tripper_recon.service import InvestigationOptions, classify_target, schema_result_for_target, url_schema_result, validate_typed_target
from tripper_recon.utils.http import configure_rate_limit, configure_user_agent
from tripper_recon.utils.logging import logger
from tripper_recon.utils.env import load_env

log = logger("cli")
console = Console()


def _add_machine_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--mode", choices=["passive", "resolver-passive"], default="passive", help="Investigation mode for schema v1 output")
    parser.add_argument("--profile", choices=["best_effort"], default="best_effort", help="Provider profile for schema v1 output")
    parser.add_argument("--provider", action="append", dest="providers", help="Request a specific provider by registry name")
    parser.add_argument("--include-raw", action="store_true", help="Accept raw evidence flag for schema v1 paths; raw payload emission is implemented in a later slice")
    parser.add_argument("--require-profile-complete", action="store_true", help="Accept profile completeness flag for schema v1 paths; enforcement is implemented in a later slice")
    cache_group = parser.add_mutually_exclusive_group()
    cache_group.add_argument("--cache", action="store_true", dest="cache", default=True, help="Enable cache reads for schema v1 paths when cache support is available")
    cache_group.add_argument("--no-cache", action="store_false", dest="cache", help="Disable cache reads for schema v1 paths when cache support is available")


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


def _load_targets(value: str) -> tuple[List[str], str | None]:
    p = Path(value).expanduser()
    if not p.is_file():
        return [value], None

    targets: List[str] = []
    for raw in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line)
    return targets, str(p)



async def _cmd_ip(
    ip: str,
    *,
    output: str = "console",
    ports_limit: str = "25",
    mode: str = "passive",
    profile: str = "best_effort",
    providers: list[str] | None = None,
    include_raw: bool = False,
) -> int:
    targets, source_file = _load_ip_targets(ip)
    if source_file and not targets:
        log["error"]("IP list file is empty", file=source_file)
        return 1
    invalid_targets = []
    for target in targets:
        valid, _normalized, error = validate_typed_target("ip", target)
        if not valid:
            invalid_targets.append((target, error or f"Invalid IP target: {target}"))
    if invalid_targets:
        if output == "json" and len(targets) == 1:
            target, error = invalid_targets[0]
            sys.stdout.write(failed_ip_result_v1(target=target, error=error, mode=mode, profile=profile).model_dump_json(indent=2) + "\n")
        else:
            for target, error in invalid_targets:
                log["error"]("Invalid IP target", target=target, error=error)
                if output == "console":
                    console.print(f"[bold red]Invalid IP target:[/] {target}")
        return 1

    if output == "console" and source_file:
        console.print(f"\n[bold green]Processing {len(targets)} targets from \"{source_file}\"[/]\n")

    try:
        provider_selection = select_providers(
            target_type="ip",
            mode=mode,
            profile=profile,
            requested_providers=providers,
        )
    except ProviderSelectionError as exc:
        if output == "json" and len(targets) == 1:
            status = ProviderStatus(provider=exc.provider, status="failed", reason=str(exc))
            sys.stdout.write(
                failed_ip_result_v1(
                    target=targets[0],
                    error=str(exc),
                    mode=mode,
                    profile=profile,
                    provider_status=status,
                ).model_dump_json(indent=2)
                + "\n"
            )
        else:
            log["error"]("Provider selection failed", error=str(exc))
        return 1
    except ValueError as exc:
        if output == "json" and len(targets) == 1:
            sys.stdout.write(
                failed_ip_result_v1(
                    target=targets[0],
                    error=str(exc),
                    mode=mode,
                    profile=profile,
                ).model_dump_json(indent=2)
                + "\n"
            )
        else:
            log["error"]("Provider selection failed", error=str(exc))
        return 1

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

    if output == "json" and len(targets) == 1 and gathered:
        target = targets[0]
        if isinstance(gathered[0], Exception):
            msg = results[0]["errors"][0] if results[0].get("errors") else "IP investigation crashed"
            from tripper_recon.types.models import InvestigationResult
            schema_result = ip_result_to_schema_v1(
                target=target,
                result=InvestigationResult(ok=False, errors=[msg], data={}),
                mode=mode,
                profile=profile,
                provider_names=provider_selection.executable,
                extra_provider_statuses=provider_selection.skipped,
                include_raw=include_raw,
            )
        else:
            schema_result = ip_result_to_schema_v1(
                target=target,
                result=gathered[0],
                mode=mode,
                profile=profile,
                provider_names=provider_selection.executable,
                extra_provider_statuses=provider_selection.skipped,
                include_raw=include_raw,
            )
        sys.stdout.write(schema_result.model_dump_json(indent=2) + "\n")
    elif output == "json":
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


async def _cmd_domain(
    domain: str,
    *,
    output: str = "console",
    ports_limit: str = "25",
    mode: str = "passive",
    profile: str = "best_effort",
    providers: list[str] | None = None,
    include_raw: bool = False,
) -> int:
    valid, norm_domain, validation_error = validate_typed_target("domain", domain)
    if not valid:
        if output == "json":
            sys.stdout.write(
                failed_domain_result_v1(
                    target=domain,
                    normalized_target=norm_domain,
                    error=validation_error or f"Invalid domain target: {domain}",
                    mode=mode,
                    profile=profile,
                ).model_dump_json(indent=2)
                + "\n"
            )
        else:
            log["error"]("Invalid domain target", target=domain, error=validation_error)
            console.print(f"[bold red]Invalid domain target:[/] {domain}")
        return 1

    try:
        provider_selection = select_providers(
            target_type="domain",
            mode=mode,
            profile=profile,
            requested_providers=providers,
        )
    except ProviderSelectionError as exc:
        if output == "json":
            status = ProviderStatus(provider=exc.provider, status="failed", reason=str(exc))
            sys.stdout.write(
                failed_domain_result_v1(
                    target=domain,
                    normalized_target=norm_domain,
                    error=str(exc),
                    mode=mode,
                    profile=profile,
                    provider_status=status,
                ).model_dump_json(indent=2)
                + "\n"
            )
        else:
            log["error"]("Provider selection failed", error=str(exc))
        return 1
    except ValueError as exc:
        if output == "json":
            sys.stdout.write(
                failed_domain_result_v1(
                    target=domain,
                    normalized_target=norm_domain,
                    error=str(exc),
                    mode=mode,
                    profile=profile,
                ).model_dump_json(indent=2)
                + "\n"
            )
        else:
            log["error"]("Provider selection failed", error=str(exc))
        return 1

    res = await investigate_domain(norm_domain, mode=mode)
    if not res.ok:
        log["error"]("Domain investigation failed", domain=domain, errors=res.errors)
        if output == "json":
            sys.stdout.write(
                domain_result_to_schema_v1(
                    target=domain,
                    normalized_target=norm_domain,
                    result=res,
                    mode=mode,
                    profile=profile,
                    provider_names=provider_selection.executable,
                    extra_provider_statuses=provider_selection.skipped,
                    include_raw=include_raw,
                ).model_dump_json(indent=2)
                + "\n"
            )
        elif output == "console":
            console.print(f"[bold red]Domain investigation failed:[/] {'; '.join(res.errors)}")
        return 1

    if output == "json":
        schema_result = domain_result_to_schema_v1(
            target=domain,
            normalized_target=norm_domain,
            result=res,
            mode=mode,
            profile=profile,
            provider_names=provider_selection.executable,
            extra_provider_statuses=provider_selection.skipped,
            include_raw=include_raw,
        )
        sys.stdout.write(schema_result.model_dump_json(indent=2) + "\n")
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

    source_label = "Resolving" if mode == "resolver-passive" else "Passive IP relationships for"
    console.print(f'\n[bold]- {source_label} "{norm_domain}"... {len(ips)} IP addresses found:[/]\n\n')

    if not ips:
        console.print("No IPs available for IP-level enrichment.\n")
        return 0

    for item in ips:
        item_ip = item.get("ip", "")
        panel = render_ip_analysis(item_ip, item, ports_limit=ports_limit)
        console.print(panel)
        console.print()

    return 0


async def _cmd_investigate(
    target_or_file: str,
    *,
    output: str = "console",
    mode: str = "passive",
    profile: str = "best_effort",
    providers: list[str] | None = None,
    include_raw: bool = False,
) -> int:
    targets, source_file = _load_targets(target_or_file)
    if not targets:
        log["error"]("Investigation target list is empty", file=source_file)
        return 1

    if output == "json":
        failed = 0
        for target in targets:
            result = await schema_result_for_target(
                target,
                InvestigationOptions(
                    mode=mode,
                    profile=profile,
                    providers=tuple(providers) if providers else None,
                    include_raw=include_raw,
                ),
            )
            if result.execution_status == "failed":
                failed += 1
            sys.stdout.write(result.model_dump_json() + "\n")
        return 0 if failed == 0 else 1

    if source_file:
        console.print(f"\n[bold green]Processing {len(targets)} targets from \"{source_file}\"[/]\n")
    failed = 0
    for target in targets:
        target_type, _normalized = classify_target(target)
        if target_type == "ip":
            failed += int(await _cmd_ip(target, output=output, mode=mode, profile=profile, providers=providers, include_raw=include_raw) != 0)
        elif target_type == "domain":
            failed += int(await _cmd_domain(target, output=output, mode=mode, profile=profile, providers=providers, include_raw=include_raw) != 0)
        else:
            failed += 1
            console.print(f"[bold red]Unsupported target for console investigate:[/] {target}")
    color = "green" if failed == 0 else "yellow"
    console.print(f"[{color}]Summary:[/] total={len(targets)} failed={failed}")
    return 0 if failed == 0 else 1


async def _cmd_url(
    url: str,
    *,
    output: str = "console",
    mode: str = "passive",
    profile: str = "best_effort",
    providers: list[str] | None = None,
    include_raw: bool = False,
) -> int:
    valid, normalized_url, validation_error = validate_typed_target("url", url)
    if not valid:
        result = failed_url_result_v1(
            target=url,
            normalized_target=normalized_url,
            mode=mode,
            profile=profile,
            error=validation_error or f"Invalid URL target: {url}",
        )
    else:
        result = await url_schema_result(
            url,
            InvestigationOptions(
                mode=mode,
                profile=profile,
                providers=tuple(providers) if providers else None,
                include_raw=include_raw,
            ),
        )
    if output == "json":
        sys.stdout.write(result.model_dump_json(indent=2) + "\n")
    else:
        if result.execution_status == "failed":
            console.print(f"[bold red]{result.errors[0]}[/]")
        else:
            console.print(result.model_dump_json(indent=2))
    return 1 if result.execution_status == "failed" else 0


def _default_output_dir() -> Path:
    here = Path(__file__).resolve()
    root = here.parent.parent
    return root / "outputs"


async def _cmd_asn(
    asn: int | str,
    *,
    output: str = "console",
    neighbors: int = 8,
    enrich: bool = False,
    enrich_limit: int = 50,
    monochrome: bool = False, # retained for flag compat, rich handles this via terminal settings or NO_COLOR
    prefixes_out: str | None = None,
    prefixes: str = "both",
) -> int:
    valid, normalized_asn, validation_error = validate_typed_target("asn", str(asn))
    if not valid:
        log["error"]("Invalid ASN provided", asn=asn, error=validation_error)
        if output == "json":
            result = failed_result_v1(
                target_type="asn",
                target=str(asn),
                normalized_target=normalized_asn,
                error=validation_error or f"Invalid ASN provided: {asn}",
            )
            sys.stdout.write(result.model_dump_json(indent=2) + "\n")
        elif output == "console":
            console.print(f"[bold red]Error:[/] Invalid ASN provided: {asn}")
        return 2
    asn = int(normalized_asn)
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
    p_ip.add_argument("--json", action="store_const", const="json", dest="format", help="Emit schema v1 JSON for a single IP target")
    _add_machine_options(p_ip)
    p_ip.add_argument("--ports-limit", type=str, default="25", help="Limit number of ports shown (use 'all' to show all)")

    p_domain = sub.add_parser("domain", help="Investigate a domain")
    p_domain.add_argument("domain", type=str)
    p_domain.add_argument("-o", "--format", choices=["console", "json"], default="console", help="Output format")
    p_domain.add_argument("--json", action="store_const", const="json", dest="format", help="Emit schema v1 JSON for a domain target")
    _add_machine_options(p_domain)
    p_domain.add_argument("--ports-limit", type=str, default="25", help="Limit number of ports shown per IP in console (use 'all' to show all)")

    p_url = sub.add_parser("url", help="Investigate a URL")
    p_url.add_argument("url", type=str)
    p_url.add_argument("-o", "--format", choices=["console", "json"], default="console", help="Output format")
    p_url.add_argument("--json", action="store_const", const="json", dest="format", help="Emit schema v1 JSON for a URL target")
    _add_machine_options(p_url)

    p_investigate = sub.add_parser("investigate", help="Investigate a target or file of mixed indicators")
    p_investigate.add_argument("target_or_file", type=str)
    p_investigate.add_argument("-o", "--format", choices=["console", "json"], default="console", help="Output format")
    p_investigate.add_argument("--json", action="store_const", const="json", dest="format", help="Emit schema v1 JSONL")
    _add_machine_options(p_investigate)

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
            code = asyncio.run(_cmd_ip(
                args.ip,
                output=args.format,
                ports_limit=getattr(args, "ports_limit", "25"),
                mode=getattr(args, "mode", "passive"),
                profile=getattr(args, "profile", "best_effort"),
                providers=getattr(args, "providers", None),
                include_raw=getattr(args, "include_raw", False),
            ))
        case "domain":
            code = asyncio.run(_cmd_domain(
                args.domain,
                output=args.format,
                ports_limit=getattr(args, "ports_limit", "25"),
                mode=getattr(args, "mode", "passive"),
                profile=getattr(args, "profile", "best_effort"),
                providers=getattr(args, "providers", None),
                include_raw=getattr(args, "include_raw", False),
            ))
        case "url":
            code = asyncio.run(_cmd_url(
                args.url,
                output=args.format,
                mode=getattr(args, "mode", "passive"),
                profile=getattr(args, "profile", "best_effort"),
                providers=getattr(args, "providers", None),
                include_raw=getattr(args, "include_raw", False),
            ))
        case "investigate":
            code = asyncio.run(_cmd_investigate(
                args.target_or_file,
                output=args.format,
                mode=getattr(args, "mode", "passive"),
                profile=getattr(args, "profile", "best_effort"),
                providers=getattr(args, "providers", None),
                include_raw=getattr(args, "include_raw", False),
            ))
        case "asn":
            asn_str = str(args.asn).strip()
            code = asyncio.run(_cmd_asn(
                asn_str,
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
