from __future__ import annotations

from typing import Any, Dict, Iterable, List
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


def _fmt_ports(ports: Iterable[int]) -> str:
    return ", ".join(str(p) for p in sorted({int(p) for p in ports if isinstance(p, int) or str(p).isdigit()}))


def _fmt_coords(coords: Dict[str, Any] | None) -> str:
    if not coords:
        return ""
    lat = coords.get("lat")
    lon = coords.get("lon")
    if lat is None or lon is None:
        return ""
    return f"{lat}, {lon}"


def render_ip_analysis(ip: str, data: Dict[str, Any], *, ports_limit: str = "25") -> RenderableType:
    vt = data.get("virustotal", {})
    vt_stats = vt.get("vt_last_analysis_stats", {})
    vt_reputation = vt.get("vt_reputation")
    vt_link = vt.get("vt_link")
    ports = data.get("shodan", {}).get("ports", [])
    abuse = data.get("abuseipdb", {})
    ipinfo = data.get("ipinfo", {})
    asn_meta = data.get("asn_meta", {})
    otx = data.get("otx", {})

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold cyan")
    table.add_column("Value", style="none")

    table.add_row("ip", ip)
    city = ipinfo.get("city")
    if city:
        table.add_row("city", city)
    country = ipinfo.get("country")
    if country:
        table.add_row("country", country)
    
    isp_line = None
    asn_id = asn_meta.get("asn")
    asn_name = asn_meta.get("name")
    if asn_id and asn_name:
        isp_line = f"AS{asn_id} {asn_name}"
    elif ipinfo.get("org"):
        isp_line = ipinfo.get("org")
    if isp_line:
        table.add_row("isp", isp_line)
    
    org = asn_meta.get("organization") or ipinfo.get("org")
    if org:
        table.add_row("organization", org)
    
    coords = _fmt_coords(ipinfo.get("coordinates"))
    if coords:
        table.add_row("coordinates", coords)
    
    if ipinfo.get("postal"):
        table.add_row("postal_code", str(ipinfo.get("postal")))
        
    table.add_row("cloudflare_radar_link", f"https://radar.cloudflare.com/ip/{ip}")
    
    malicious = int(vt_stats.get("malicious", 0) or 0)
    total_engines = 0
    if isinstance(vt_stats, dict):
        try:
            total_engines = sum(int(v or 0) for v in vt_stats.values())
        except Exception:
            total_engines = 0
            
    vt_color = "red" if malicious > 0 else "green"
    table.add_row("virustotal_detections", f"[{vt_color}]{malicious}/{total_engines}[/]")
    
    if vt_reputation is not None:
        table.add_row("virustotal_community_score", str(vt_reputation))
    if vt_link:
        table.add_row("virustotal_analysis_link", vt_link)
        
    if abuse:
        reports = abuse.get('abuseipdb_reports', 0)
        table.add_row("abuseipdb_reports", str(reports))
        conf_val = abuse.get('abuseipdb_confidence_score', 0)
        try:
            conf_int = int(conf_val)
        except Exception:
            conf_int = 0
        conf_int = max(0, min(100, conf_int))
        ab_color = "red" if conf_int > 0 else "green"
        table.add_row("abuseipdb_confidence_score", f"[{ab_color}]{conf_int}%[/]")
        
    table.add_row("abuseipdb_analysis_link", f"https://www.abuseipdb.com/check/{ip}")
    
    if otx:
        try:
            pulse_count = int(otx.get("otx_pulse_count", 0) or 0)
        except Exception:
            pulse_count = 0
        table.add_row("otx_pulse_count", str(pulse_count))
        table.add_row("otx_pulse_link", f"https://otx.alienvault.com/indicator/ip/{ip}")
        titles = otx.get("otx_pulse_titles") or []
        if isinstance(titles, list) and titles:
            joined = "; ".join(str(t) for t in titles[:5] if t)
            if joined:
                table.add_row("otx_pulse_titles", joined)
    else:
        table.add_row("otx_pulse_link", f"https://otx.alienvault.com/indicator/ip/{ip}")
        
    if ports:
        ports_sorted = sorted({int(p) for p in ports if isinstance(p, int) or str(p).isdigit()})
        if str(ports_limit).lower() == 'all':
            max_show = len(ports_sorted)
        else:
            try:
                limit = int(ports_limit)
                max_show = limit if limit > 0 else 25
            except (ValueError, TypeError):
                max_show = 25
        shown = ports_sorted[:max_show]
        more = len(ports_sorted) - len(shown)
        ports_str = ", ".join(str(p) for p in shown)
        if more > 0:
            ports_str += f" ... and {more} more"
        table.add_row("open_ports", ports_str)
        
    table.add_row("shodan_link", f"https://www.shodan.io/host/{ip}")
    
    errors = data.get("errors") or {}
    if errors:
        error_table = Table(show_header=False, box=None, padding=(0, 2))
        error_table.add_column("Provider", style="bold red")
        error_table.add_column("Error")
        for name, detail in errors.items():
            if not isinstance(detail, dict):
                error_table.add_row(name, str(detail))
                continue
            parts: List[str] = []
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
            if url:
                parts.append(f"url={url}")
            body = detail.get("body")
            if body:
                parts.append(f"body={body}")
            joined = " | ".join(parts) if parts else "error"
            error_table.add_row(name, joined)
        table.add_row("provider_errors", error_table)

    return Panel(table, title=f"IP lookup for [bold white]{ip}[/]", border_style="blue", expand=False)


def render_asn_header(asn: int, meta: Dict[str, Any], use_color: bool = False) -> RenderableType:
    name = meta.get("name") or (meta.get("organization", {}) or {}).get("name") or ""
    org = meta.get("organization")
    org_name = org.get("name") if isinstance(org, dict) else org
    rir = meta.get("rir")
    rir_desc_map = {
        "ARIN": "ARIN (USA, Canada, many Caribbean and North Atlantic islands)",
        "RIPE": "RIPE NCC (Europe, Middle East, parts of Central Asia)",
        "APNIC": "APNIC (Asia Pacific)",
        "LACNIC": "LACNIC (Latin America and parts of Caribbean)",
        "AFRINIC": "AFRINIC (Africa)",
    }
    rir_line = rir_desc_map.get(rir.upper(), rir) if isinstance(rir, str) and rir else None

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold cyan")
    table.add_column("Arrow", style="none")
    table.add_column("Value", style="none")

    table.add_row("AS Number", "──>", str(asn))
    if name:
        table.add_row("AS Name", "──>", name)
    if org_name:
        table.add_row("Organization", "──>", str(org_name))
    if meta.get("caidaRank"):
        table.add_row("CAIDA AS Rank", "──>", f"#{meta.get('caidaRank')}")
    if meta.get("abuseContacts"):
        table.add_row("Abuse contact", "──>", str(meta["abuseContacts"][0]))
    alloc = meta.get("allocationDate") or meta.get("allocated") or meta.get("allocation")
    if alloc:
        table.add_row("AS Reg. date", "──>", str(alloc))
    if rir_line:
        table.add_row("RIR (Region)", "──>", rir_line)
        
    ixps = meta.get("ixps") or []
    if isinstance(ixps, list) and ixps:
        ixp_names = [i.get("name") for i in ixps if isinstance(i, dict) and i.get("name")]
        if ixp_names:
            table.add_row("Peering @IXPs", "──>", " • ".join(str(n) for n in ixp_names))
    else:
        table.add_row("Peering @IXPs", "──>", "NONE")

    title = f"ASN lookup for AS{asn} ({name})" if name else f"ASN lookup for AS{asn}"
    return Panel(table, title=f"[bold white]{title}[/]", border_style="magenta", expand=False)


def _join_asns(asns: list[int] | None, limit: int = 60) -> str:
    if not asns:
        return "NONE"
    shown = [str(x) for x in asns[:limit]]
    more = len(asns) - len(shown)
    s = "  ".join(shown)
    if more > 0:
        s += f"\nand {more} more"
    return s


def render_asn_bgp_panels(asn: int, meta: Dict[str, Any], bgp: Dict[str, Any], use_color: bool = False) -> RenderableType:
    name = meta.get("name") or ""
    panels: List[RenderableType] = []

    # Panel 1: BGP informations
    t1 = Table(show_header=False, box=None, padding=(0, 2))
    t1.add_column("Key", style="bold cyan")
    t1.add_column("Value")
    total = meta.get("degree_total")
    prov = meta.get("degree_provider")
    peer = meta.get("degree_peer")
    cust = meta.get("degree_customer")
    if total is not None:
        t1.add_row("BGP Neighbors", f"{total} ({prov or 0} Transits • {peer or 0} Peers • {cust or 0} Customers)")
    cone = meta.get("customer_cone_asns")
    if cone is not None:
        t1.add_row("Customer cone", f"{cone} (# of ASNs observed in the customer cone)")

    hj = bgp.get("hijacks", {}) if isinstance(bgp, dict) else {}
    leaks = bgp.get("leaks", {}) if isinstance(bgp, dict) else {}
    if hj:
        total_h = hj.get("total") or 0
        as_h = hj.get("as_hijacker") or 0
        as_v = hj.get("as_victim") if hj.get("as_victim") is not None else (total_h - as_h)
        if total_h:
            qual = " (always as a victim)" if as_h == 0 else (" (always as a hijacker)" if as_v == 0 else f" ({as_h} as hijacker • {as_v} as victim)")
            t1.add_row("BGP Hijacks (past 1y)", f"Involved in {total_h} incident{'' if total_h==1 else 's'}{qual}")
        else:
            t1.add_row("BGP Hijacks (past 1y)", "None")
    if leaks:
        total_l = leaks.get("total") or 0
        t1.add_row("BGP Route leaks (past 1y)", "None" if total_l == 0 else str(total_l))
    t1.add_row("In-depth BGP info", f"https://radar.cloudflare.com/routing/as{asn}?dateRange=52w")
    panels.append(Panel(t1, title=f"BGP informations for AS{asn}", border_style="cyan", expand=False))

    # Panel 2: Prefix informations
    t2 = Table(show_header=False, box=None, padding=(0, 2))
    v4c = bgp.get("ripe_announced_prefixes_v4")
    v6c = bgp.get("ripe_announced_prefixes_v6")
    if v4c is not None:
        t2.add_row("IPv4 Prefixes announced", str(v4c))
    if v6c is not None:
        t2.add_row("IPv6 Prefixes announced", str(v6c))
    if v4c is not None or v6c is not None:
        panels.append(Panel(t2, title=f"Prefix informations for AS{asn}", border_style="cyan", expand=False))

    # Panel 3: Peering informations
    up = bgp.get("ripe_upstream_named") or bgp.get("ripe_upstream_asns") or []
    dn = bgp.get("ripe_downstream_named") or bgp.get("ripe_downstream_asns") or []
    un = bgp.get("ripe_uncertain_named") or bgp.get("ripe_uncertain_asns") or []
    t3 = Table(show_header=False, box=None, padding=(0, 2))
    t3.add_column("Category", style="bold green")
    t3.add_column("Peers")
    t3.add_row("Upstream", _join_asns(up))
    t3.add_row("Downstream", _join_asns(dn))
    t3.add_row("Uncertain", _join_asns(un))
    panels.append(Panel(t3, title=f"Peering informations for AS{asn}", border_style="cyan", expand=False))

    # Panel 4: Aggregated IP resources
    v4_list = bgp.get("ripe_prefixes_v4") or []
    v6_list = bgp.get("ripe_prefixes_v6") or []
    if v4_list or v6_list:
        t4 = Table(show_header=False, box=None, padding=(0, 2))
        t4.add_column("Protocol", style="bold yellow")
        t4.add_column("Prefixes")
        
        v4_str = "NONE"
        if v4_list:
            v4_str = "\n".join(str(p) for p in v4_list[:50])
            if len(v4_list) > 50:
                v4_str += f"\n… and {len(v4_list)-50} more"
        t4.add_row("IPv4", v4_str)

        v6_str = "NONE"
        if v6_list:
            v6_str = "\n".join(str(p) for p in v6_list[:50])
            if len(v6_list) > 50:
                v6_str += f"\n… and {len(v6_list)-50} more"
        t4.add_row("IPv6", v6_str)
        panels.append(Panel(t4, title=f"Aggregated IP resources for AS{asn}", border_style="cyan", expand=False))

    return Group(*panels)
