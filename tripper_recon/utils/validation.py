from __future__ import annotations

import ipaddress
import re
from typing import Iterable


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_asn(value: str | int) -> bool:
    try:
        n = int(value)
        return 0 < n < 2**32
    except Exception:
        return False


_domain_re = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,63}$")


def is_valid_domain(value: str) -> bool:
    return bool(_domain_re.match(value.strip().lower()))


def dedupe_preserve_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out


