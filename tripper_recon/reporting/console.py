from __future__ import annotations

from typing import Any, Dict, Iterable, List


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


def render_ip_analysis(ip: str, data: Dict[str, Any], *, ports_limit: str = "25") -> str:
    vt = data.get("virustotal", {})
    vt_stats = vt.get("vt_last_analysis_stats", {})
    vt_reputation = vt.get("vt_reputation")
    vt_link = vt.get("vt_link")
    ports = data.get("shodan", {}).get("ports", [])
    abuse = data.get("abuseipdb", {})
    ipinfo = data.get("ipinfo", {})
    asn_meta = data.get("asn_meta", {})
    otx = data.get("otx", {})

    lines: List[str] = []
    lines.append(f"ip: {ip}")
    city = ipinfo.get("city")
    if city:
        lines.append(f"city: {city}")
    country = ipinfo.get("country")
    if country:
        lines.append(f"country: {country}")
    isp_line = None
    asn_id = asn_meta.get("asn")
    asn_name = asn_meta.get("name")
    if asn_id and asn_name:
        isp_line = f"AS{asn_id} {asn_name}"
    elif ipinfo.get("org"):
        isp_line = ipinfo.get("org")
    if isp_line:
        lines.append(f"isp: {isp_line}")
    org = asn_meta.get("organization") or ipinfo.get("org")
    if org:
        lines.append(f"organization: {org}")
    coords = _fmt_coords(ipinfo.get("coordinates"))
    if coords:
        lines.append(f"coordinates: {coords}")
    if ipinfo.get("postal"):
        lines.append(f"postal_code: {ipinfo.get('postal')}")
    lines.append(f"cloudflare_radar_link: https://radar.cloudflare.com/ip/{ip}")
    malicious = int(vt_stats.get("malicious", 0) or 0)
    total_engines = 0
    if isinstance(vt_stats, dict):
        try:
            total_engines = sum(int(v or 0) for v in vt_stats.values())
        except Exception:
            total_engines = 0
    lines.append(f"virustotal_detections: {malicious}/{total_engines}")
    if vt_reputation is not None:
        lines.append(f"virustotal_community_score: {vt_reputation}")
    if vt_link:
        lines.append(f"virustotal_analysis_link: {vt_link}")
    if abuse:
        lines.append(f"abuseipdb_reports: {abuse.get('abuseipdb_reports', 0)}")
        conf_val = abuse.get('abuseipdb_confidence_score', 0)
        try:
            conf_int = int(conf_val)
        except Exception:
            conf_int = 0
        conf_int = max(0, min(100, conf_int))
        lines.append(f"abuseipdb_confidence_score: {conf_int}%")
    lines.append(f"abuseipdb_analysis_link: https://www.abuseipdb.com/check/{ip}")
    # AlienVault OTX pulse summary, if available
    if otx:
        try:
            pulse_count = int(otx.get("otx_pulse_count", 0) or 0)
        except Exception:
            pulse_count = 0
        lines.append(f"otx_pulse_count: {pulse_count}")
        lines.append(f"otx_pulse_link: https://otx.alienvault.com/indicator/ip/{ip}")
        titles = otx.get("otx_pulse_titles") or []
        if isinstance(titles, list) and titles:
            # Join up to 5 titles with '; ' for brevity
            joined = "; ".join(str(t) for t in titles[:5] if t)
            if joined:
                lines.append(f"otx_pulse_titles: {joined}")
    else:
        lines.append(f"otx_pulse_link: https://otx.alienvault.com/indicator/ip/{ip}")
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
        lines.append(f"open_ports: {ports_str}")
    lines.append(f"shodan_link: https://www.shodan.io/host/{ip}")
    errors = data.get("errors") or {}
    if errors:
        lines.append("provider_errors:")
        for name, detail in errors.items():
            if not isinstance(detail, dict):
                lines.append(f"  - {name}: {detail}")
                continue
            parts: List[str] = []
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
            joined = " | ".join(parts) if parts else "error"
            lines.append(f"  - {name}: {joined}")
    return "\n".join(lines) + "\n"


def render_asn_header(asn: int, meta: Dict[str, Any], use_color: bool = False) -> str:
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
    rir_line = None
    if isinstance(rir, str) and rir:
        rir_line = rir_desc_map.get(rir.upper(), rir)
    lines = []
    lines.append(f" ASN lookup for {asn} │")
    lines.append("╰──────────────────────╯\n")
    lines.append(f" AS Number     ──> {asn}")
    if name:
        lines.append(f" AS Name       ──> {name}")
    if org_name:
        lines.append(f" Organization  ──> {org_name}")
    if meta.get("caidaRank"):
        lines.append(f" CAIDA AS Rank ──> #{meta.get('caidaRank')}")
    if meta.get("abuseContacts"):
        first = meta["abuseContacts"][0]
        lines.append(f" Abuse contact ──> {first}")
    alloc = meta.get("allocationDate") or meta.get("allocated") or meta.get("allocation")
    if alloc:
        lines.append(f" AS Reg. date  ──> {alloc}")
    if rir_line:
        lines.append(f" RIR (Region)  ──> {rir_line}")
    ixps = meta.get("ixps") or []
    if isinstance(ixps, list) and ixps:
        ixp_names = [i.get("name") for i in ixps if isinstance(i, dict) and i.get("name")]
        if ixp_names:
            lines.append(f" Peering @IXPs ──> {' • '.join(ixp_names)}")
    return "\n".join(lines) + "\n"


def _join_asns(asns: list[int] | None, limit: int = 60) -> str:
    if not asns:
        return ""
    shown = [str(x) for x in asns[:limit]]
    more = len(asns) - len(shown)
    s = "  ".join(shown)
    if more > 0:
        s += f"\nand more: {more} more"
    return s


def render_asn_bgp_panels(asn: int, meta: Dict[str, Any], bgp: Dict[str, Any], use_color: bool = False) -> str:
    lines: list[str] = []
    name = meta.get("name") or ""
    # Panel 1: BGP informations
    lines.append("╭───────────────────────────────────────────╮")
    title = f"│ BGP informations for AS{asn} ({name}) │" if name else f"│ BGP informations for AS{asn} │"
    lines.append(title)
    lines.append("╰───────────────────────────────────────────╯\n")

    total = meta.get("degree_total")
    prov = meta.get("degree_provider")
    peer = meta.get("degree_peer")
    cust = meta.get("degree_customer")
    if total is not None:
        lines.append(f" BGP Neighbors           ────> {total} ({prov or 0} Transits • {peer or 0} Peers • {cust or 0} Customers)")
    cone = meta.get("customer_cone_asns")
    if cone is not None:
        lines.append(f" Customer cone           ────> {cone} (# of ASNs observed in the customer cone for this AS)")

    hj = bgp.get("hijacks", {}) if isinstance(bgp, dict) else {}
    leaks = bgp.get("leaks", {}) if isinstance(bgp, dict) else {}
    if hj:
        total_h = hj.get("total") or 0
        as_h = hj.get("as_hijacker") or 0
        as_v = hj.get("as_victim") if hj.get("as_victim") is not None else (total_h - as_h)
        if total_h:
            qual = " (always as a victim)" if as_h == 0 else (" (always as a hijacker)" if as_v == 0 else f" ({as_h} as hijacker • {as_v} as victim)")
            lines.append(f" BGP Hijacks (past 1y)   ────> Involved in {total_h} BGP hijack incident{'' if total_h==1 else 's'}{qual}")
        else:
            lines.append(" BGP Hijacks (past 1y)   ────> None")
    if leaks:
        total_l = leaks.get("total") or 0
        lines.append(f" BGP Route leaks (past 1y) ──> {'None' if total_l == 0 else str(total_l)}")

    lines.append(f" In-depth BGP incident info ─> ➜ https://radar.cloudflare.com/routing/as{asn}?dateRange=52w\n")

    # Panel 2: Prefix informations
    lines.append("╭──────────────────────────────────────────────╮")
    title2 = f"│ Prefix informations for AS{asn} ({name}) │" if name else f"│ Prefix informations for AS{asn} │"
    lines.append(title2)
    lines.append("╰──────────────────────────────────────────────╯\n")
    v4c = bgp.get("ripe_announced_prefixes_v4")
    v6c = bgp.get("ripe_announced_prefixes_v6")
    if v4c is not None:
        lines.append(f" IPv4 Prefixes announced ──> {v4c}")
    if v6c is not None:
        lines.append(f" IPv6 Prefixes announced ──> {v6c}")
    lines.append("")

    # Panel 3: Peering informations
    lines.append("╭───────────────────────────────────────────────╮")
    title3 = f"│ Peering informations for AS{asn} ({name}) │" if name else f"│ Peering informations for AS{asn} │"
    lines.append(title3)
    lines.append("╰───────────────────────────────────────────────╯\n")
    up = bgp.get("ripe_upstream_named") or bgp.get("ripe_upstream_asns") or []
    dn = bgp.get("ripe_downstream_named") or bgp.get("ripe_downstream_asns") or []
    un = bgp.get("ripe_uncertain_named") or bgp.get("ripe_uncertain_asns") or []
    lines.append("──────────────── Upstream Peers ────────────────\n")
    lines.append(_join_asns(up))
    lines.append("\n─────────────── Downstream Peers ───────────────\n")
    lines.append(_join_asns(dn))
    lines.append("\n─────────────── Uncertain  Peers ───────────────\n")
    lines.append(_join_asns(un))
    lines.append("")

    # Panel 4: Aggregated IP resources
    v4_list = bgp.get("ripe_prefixes_v4") or []
    v6_list = bgp.get("ripe_prefixes_v6") or []
    if v4_list or v6_list:
        lines.append("╭──────────────────────────────────────────────────╮")
        title4 = f"│ Aggregated IP resources for AS{asn} ({name}) │" if name else f"│ Aggregated IP resources for AS{asn} │"
        lines.append(title4)
        lines.append("╰──────────────────────────────────────────────────╯\n")
        lines.append("───── IPv4 ─────\n")
        if v4_list:
            for p in v4_list[:50]:
                lines.append(p)
            if len(v4_list) > 50:
                lines.append(f"… and {len(v4_list)-50} more")
        else:
            lines.append("NONE")
        lines.append("\n───── IPv6 ─────\n")
        if v6_list:
            for p in v6_list[:50]:
                lines.append(p)
            if len(v6_list) > 50:
                lines.append(f"… and {len(v6_list)-50} more")
        else:
            lines.append("NONE")

    return "\n".join(lines) + "\n"

