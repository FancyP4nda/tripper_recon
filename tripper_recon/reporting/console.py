from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover - fallback for older Python
    ZoneInfo = None


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


def _format_local_time(ipapi: Dict[str, Any], location: Dict[str, Any]) -> str:
    tz_name = location.get("timezone") or ipapi.get("timezone")
    local_iso = location.get("local_time") or ipapi.get("local_time")
    local_unix = location.get("local_time_unix") or ipapi.get("local_time_unix")

    dt: datetime | None = None
    tz_label: str | None = None

    if local_iso:
        iso_val = str(local_iso).replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(iso_val)
        except ValueError:
            dt = None

    if dt and tz_name and ZoneInfo:
        try:
            tz = ZoneInfo(tz_name)
            dt = dt.astimezone(tz)
            tz_label = dt.tzname()
        except Exception:
            tz_label = tz_name
    elif dt and dt.tzinfo:
        tz_label = dt.tzname()
    elif dt:
        tz_label = tz_name or "UTC"

    if dt is None and local_unix is not None:
        try:
            unix_val = int(local_unix)
        except Exception:
            unix_val = None
        if unix_val is not None:
            try:
                tz = ZoneInfo(tz_name) if tz_name and ZoneInfo else timezone.utc
                dt = datetime.fromtimestamp(unix_val, tz=tz)
                tz_label = dt.tzname() or tz_name or "UTC"
            except Exception:
                dt = None

    if not dt:
        return "Unknown"

    formatted = dt.strftime("%b %d, %Y, %I:%M %p")
    if tz_label:
        formatted = f"{formatted} ({tz_label})"
    return formatted


def _format_ports(ports: Iterable[int], ports_limit: str) -> str:
    port_names = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3389: "RDP",
    }
    ports_sorted = sorted({int(p) for p in ports if isinstance(p, int) or str(p).isdigit()})
    if not ports_sorted:
        return "None"

    if str(ports_limit).lower() == "all":
        max_show = len(ports_sorted)
    else:
        try:
            limit = int(ports_limit)
            max_show = limit if limit > 0 else 25
        except (ValueError, TypeError):
            max_show = 25

    shown = ports_sorted[:max_show]
    more = len(ports_sorted) - len(shown)
    parts = []
    for port in shown:
        name = port_names.get(port)
        parts.append(f"{port} ({name})" if name else str(port))
    ports_str = ", ".join(parts)
    if more > 0:
        ports_str += f" ... and {more} more"
    return ports_str


def _flag_label(key: str) -> str:
    cleaned = key.strip().lower()
    if cleaned.startswith("is_"):
        cleaned = cleaned[3:]
    mapping = {
        "abuser": "Abuser Flagged",
        "datacenter": "Datacenter",
        "hosting": "Hosting",
        "proxy": "Proxy",
        "relay": "Relay",
        "tor": "Tor",
        "vpn": "VPN",
        "bogon": "Bogon",
        "mobile": "Mobile",
        "crawler": "Crawler",
        "satellite": "Satellite",
    }
    if cleaned in mapping:
        return mapping[cleaned]
    return cleaned.replace("_", " ").title()


def _value_or_unknown(value: Any) -> str:
    if value is None or value == "":
        return "Unknown"
    return str(value)


def render_ip_analysis(ip: str, data: Dict[str, Any], *, ports_limit: str = "25") -> str:
    vt = data.get("virustotal", {})
    vt_stats = vt.get("vt_last_analysis_stats", {})
    vt_reputation = vt.get("vt_reputation")
    vt_link = vt.get("vt_link") or f"https://www.virustotal.com/gui/ip-address/{ip}"
    ports = data.get("shodan", {}).get("ports", [])
    abuse = data.get("abuseipdb", {})
    ipapi = data.get("ipapi", {})
    asn_meta = data.get("asn_meta", {})
    otx = data.get("otx", {})

    location = ipapi.get("location") if isinstance(ipapi.get("location"), dict) else {}
    asn_details = ipapi.get("asn_details") if isinstance(ipapi.get("asn_details"), dict) else {}
    connection = ipapi.get("connection") if isinstance(ipapi.get("connection"), dict) else {}
    company = ipapi.get("company") if isinstance(ipapi.get("company"), dict) else {}
    abuse_contact = ipapi.get("abuse_contact") if isinstance(ipapi.get("abuse_contact"), dict) else {}

    org_value = asn_meta.get("organization")
    if isinstance(org_value, dict):
        org_value = org_value.get("name")
    org_value = org_value or ipapi.get("org") or ipapi.get("isp") or company.get("name")
    org_line = _value_or_unknown(org_value)
    domain_value = ipapi.get("asn_domain") or company.get("domain")
    if domain_value:
        org_line = f"{org_line} ({domain_value})"

    asn_id = asn_meta.get("asn") or ipapi.get("asn")
    asn_label = f"AS{asn_id}" if asn_id else "Unknown"
    asn_desc = (
        asn_details.get("descr")
        or asn_details.get("description")
        or asn_meta.get("name")
        or ipapi.get("asn_name")
    )
    asn_desc = _value_or_unknown(asn_desc)

    conn_type = ipapi.get("asn_type") or connection.get("type")
    conn_parts = []
    if conn_type:
        conn_parts.append(str(conn_type).replace("_", " ").title())
    flags = ipapi.get("security_flag_statuses") if isinstance(ipapi.get("security_flag_statuses"), dict) else None
    if flags is None:
        flags = ipapi.get("flags") if isinstance(ipapi.get("flags"), dict) else {}
    if flags.get("is_datacenter") is True and "Datacenter" not in conn_parts:
        conn_parts.append("Datacenter")
    conn_line = " / ".join(conn_parts) if conn_parts else "Unknown"

    route = asn_details.get("route") or connection.get("route") or connection.get("prefix")
    route = _value_or_unknown(route)
    rir = ipapi.get("rir") or asn_details.get("rir")
    rir = _value_or_unknown(rir)
    created = _value_or_unknown(asn_details.get("created"))
    ports_str = _format_ports(ports, ports_limit)

    city = location.get("city") or ipapi.get("city")
    region = (
        location.get("state")
        or location.get("region")
        or ipapi.get("region")
        or location.get("region_name")
    )
    country = location.get("country") or ipapi.get("country")
    location_parts = [p for p in (city, region, country) if p]
    location_line = ", ".join(location_parts) if location_parts else "Unknown"

    coords = ipapi.get("coordinates")
    if not isinstance(coords, dict):
        lat = location.get("latitude") or ipapi.get("latitude")
        lon = location.get("longitude") or ipapi.get("longitude")
        if lat is not None and lon is not None:
            coords = {"lat": lat, "lon": lon}
        else:
            coords = None
    coords_line = _fmt_coords(coords) if coords else "Unknown"
    timezone_line = _value_or_unknown(location.get("timezone") or ipapi.get("timezone"))
    local_time_line = _format_local_time(ipapi, location)
    postal_line = _value_or_unknown(location.get("zip") or location.get("postal") or ipapi.get("postal"))

    status_flags: List[str] = []
    if isinstance(flags, dict):
        order = [
            "is_datacenter",
            "is_hosting",
            "is_vpn",
            "is_proxy",
            "is_tor",
            "is_relay",
            "is_abuser",
            "is_bogon",
            "is_mobile",
            "is_crawler",
            "is_satellite",
        ]
        for key in order:
            if flags.get(key) is True:
                status_flags.append(_flag_label(key))
        remaining = [k for k, v in flags.items() if v is True and k not in order]
        for key in sorted(remaining):
            status_flags.append(_flag_label(key))
    status_line = " | ".join(status_flags) if status_flags else "None"

    abuse_reports = abuse.get("abuseipdb_reports", 0)
    conf_val = abuse.get("abuseipdb_confidence_score", 0)
    try:
        conf_int = int(conf_val)
    except Exception:
        conf_int = 0
    conf_int = max(0, min(100, conf_int))
    abuse_line = f"{abuse_reports} Reports ({conf_int}% Confidence Score)"

    malicious = int(vt_stats.get("malicious", 0) or 0)
    total_engines = 0
    if isinstance(vt_stats, dict):
        try:
            total_engines = sum(int(v or 0) for v in vt_stats.values())
        except Exception:
            total_engines = 0
    vt_score = _value_or_unknown(vt_reputation)
    vt_line = f"{malicious}/{total_engines} Detections (Community Score: {vt_score})"

    abuser_raw = asn_details.get("abuser_score")
    if abuser_raw is None:
        abuser_score = "Unknown"
        abuser_rating = "Unknown"
    else:
        abuser_str = str(abuser_raw).strip()
        if "(" in abuser_str and abuser_str.endswith(")"):
            score_part, rating_part = abuser_str.rsplit("(", 1)
            abuser_score = score_part.strip() or "Unknown"
            abuser_rating = rating_part[:-1].strip() or "Unknown"
        else:
            abuser_score = abuser_str or "Unknown"
            abuser_rating = "Unknown"
    abuser_line = f"{abuser_score} ({abuser_rating})"

    try:
        otx_count = int(otx.get("otx_pulse_count", 0) or 0)
    except Exception:
        otx_count = 0

    shodan_link = f"https://www.shodan.io/host/{ip}"
    cf_link = f"https://radar.cloudflare.com/ip/{ip}"
    abuse_link = f"https://www.abuseipdb.com/check/{ip}"
    otx_link = f"https://otx.alienvault.com/indicator/ip/{ip}"

    lines: List[str] = []
    lines.append(f"IP Intelligence Report: {ip}")
    lines.append("")
    lines.append("Network & Ownership")
    lines.append("")
    lines.append(f"Organization: {org_line}")
    lines.append(f"ASN: {asn_label} ({asn_desc})")
    lines.append(f"Connection Type: {conn_line}")
    lines.append(f"Route: {route}")
    lines.append(f"RIR: {rir} (Created: {created})")
    lines.append(f"Open Ports: {ports_str}")
    lines.append("")
    lines.append("")
    lines.append("Geographical Information")
    lines.append("")
    lines.append(f"Location: {location_line}")
    lines.append(f"Coordinates: {coords_line}")
    lines.append(f"Timezone: {timezone_line}")
    lines.append(f"Local Time: {local_time_line}")
    lines.append(f"Postal Code: {postal_line}")
    lines.append("")
    lines.append("")
    lines.append("Security & Reputation")
    lines.append("")
    lines.append(f"Status: {status_line}")
    lines.append(f"AbuseIPDB: {abuse_line}")
    lines.append(f"VirusTotal: {vt_line}")
    lines.append(f"ASN Abuser Score: {abuser_line}")
    lines.append(f"OTX Pulses: {otx_count}")
    lines.append("")
    lines.append("")
    lines.append("Abuse Contact Details")
    lines.append("")
    lines.append(f"Name: {_value_or_unknown(abuse_contact.get('name'))}")
    lines.append(f"Email: {_value_or_unknown(abuse_contact.get('email'))}")
    lines.append(f"Phone: {_value_or_unknown(abuse_contact.get('phone'))}")
    lines.append(f"Address: {_value_or_unknown(abuse_contact.get('address'))}")
    lines.append("")
    lines.append("")
    lines.append("External Analysis Links")
    lines.append("")
    lines.append(f"Shodan Host Profile: {shodan_link}")
    lines.append(f"VirusTotal Analysis: {vt_link}")
    lines.append(f"Cloudflare Radar: {cf_link}")
    lines.append(f"AbuseIPDB Analysis: {abuse_link}")
    lines.append(f"OTX Pulse Link: {otx_link}")
    return "\n".join(lines).rstrip() + "\n"


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
    lines.append(f"AS Number: {asn}")
    if name:
        lines.append(f"AS Name: {name}")
    if org_name:
        lines.append(f"Organization: {org_name}")
    if meta.get("caidaRank"):
        lines.append(f"CAIDA AS Rank: #{meta.get('caidaRank')}")
    if meta.get("abuseContacts"):
        first = meta["abuseContacts"][0]
        lines.append(f"Abuse contact: {first}")
    alloc = meta.get("allocationDate") or meta.get("allocated") or meta.get("allocation")
    if alloc:
        lines.append(f"AS Reg. date: {alloc}")
    if rir_line:
        lines.append(f"RIR (Region): {rir_line}")
    ixps = meta.get("ixps") or []
    if isinstance(ixps, list) and ixps:
        ixp_names = [i.get("name") for i in ixps if isinstance(i, dict) and i.get("name")]
        if ixp_names:
            lines.append(f"Peering @IXPs: {', '.join(ixp_names)}")
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

    title = f"BGP informations for AS{asn} ({name})" if name else f"BGP informations for AS{asn}"
    lines.append(title)
    lines.append("")

    total = meta.get("degree_total")
    prov = meta.get("degree_provider")
    peer = meta.get("degree_peer")
    cust = meta.get("degree_customer")
    if total is not None:
        lines.append(
            f"BGP Neighbors: {total} ({prov or 0} Transits, {peer or 0} Peers, {cust or 0} Customers)"
        )
    cone = meta.get("customer_cone_asns")
    if cone is not None:
        lines.append(f"Customer cone: {cone} (# of ASNs observed in the customer cone for this AS)")

    hj = bgp.get("hijacks", {}) if isinstance(bgp, dict) else {}
    leaks = bgp.get("leaks", {}) if isinstance(bgp, dict) else {}
    if hj:
        total_h = hj.get("total") or 0
        as_h = hj.get("as_hijacker") or 0
        as_v = hj.get("as_victim") if hj.get("as_victim") is not None else (total_h - as_h)
        if total_h:
            qual = (
                " (always as a victim)"
                if as_h == 0
                else (" (always as a hijacker)" if as_v == 0 else f" ({as_h} as hijacker, {as_v} as victim)")
            )
            lines.append(
                f"BGP Hijacks (past 1y): Involved in {total_h} BGP hijack incident{'' if total_h==1 else 's'}{qual}"
            )
        else:
            lines.append("BGP Hijacks (past 1y): None")
    if leaks:
        total_l = leaks.get("total") or 0
        lines.append(f"BGP Route leaks (past 1y): {'None' if total_l == 0 else str(total_l)}")

    lines.append(f"In-depth BGP incident info: https://radar.cloudflare.com/routing/as{asn}?dateRange=52w")
    lines.append("")

    title2 = f"Prefix informations for AS{asn} ({name})" if name else f"Prefix informations for AS{asn}"
    lines.append(title2)
    lines.append("")
    v4c = bgp.get("ripe_announced_prefixes_v4")
    v6c = bgp.get("ripe_announced_prefixes_v6")
    if v4c is not None:
        lines.append(f"IPv4 Prefixes announced: {v4c}")
    if v6c is not None:
        lines.append(f"IPv6 Prefixes announced: {v6c}")
    lines.append("")

    title3 = f"Peering informations for AS{asn} ({name})" if name else f"Peering informations for AS{asn}"
    lines.append(title3)
    lines.append("")
    up = bgp.get("ripe_upstream_named") or bgp.get("ripe_upstream_asns") or []
    dn = bgp.get("ripe_downstream_named") or bgp.get("ripe_downstream_asns") or []
    un = bgp.get("ripe_uncertain_named") or bgp.get("ripe_uncertain_asns") or []
    lines.append("Upstream Peers:")
    lines.append(_join_asns(up) or "NONE")
    lines.append("")
    lines.append("Downstream Peers:")
    lines.append(_join_asns(dn) or "NONE")
    lines.append("")
    lines.append("Uncertain Peers:")
    lines.append(_join_asns(un) or "NONE")
    lines.append("")

    v4_list = bgp.get("ripe_prefixes_v4") or []
    v6_list = bgp.get("ripe_prefixes_v6") or []
    if v4_list or v6_list:
        title4 = f"Aggregated IP resources for AS{asn} ({name})" if name else f"Aggregated IP resources for AS{asn}"
        lines.append(title4)
        lines.append("")
        lines.append("IPv4:")
        if v4_list:
            for p in v4_list[:50]:
                lines.append(p)
            if len(v4_list) > 50:
                lines.append(f". and {len(v4_list)-50} more")
        else:
            lines.append("NONE")
        lines.append("")
        lines.append("IPv6:")
        if v6_list:
            for p in v6_list[:50]:
                lines.append(p)
            if len(v6_list) > 50:
                lines.append(f". and {len(v6_list)-50} more")
        else:
            lines.append("NONE")

    return "\n".join(lines) + "\n"

