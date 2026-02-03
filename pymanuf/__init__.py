import os
import re
from typing import Dict, Tuple

__all__ = ["lookup"]

__MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")


def __mac_to_u64(mac: str) -> int | None:
    hex_str = mac.replace(":", "")
    if len(hex_str) == 6:
        hex_str += "000000"
    if len(hex_str) != 12:
        return None
    try:
        return int(hex_str, 16)
    except ValueError:
        return None


# Intentionally not match-case because of Python 3.9
def __mask_mac(mac: int, cidr: int) -> int:
    if cidr == 24:
        mask = 0xFFFFFF000000
    elif cidr == 28:
        mask = 0xFFFFFFF00000
    elif cidr == 36:
        mask = 0xFFFFFFFFF000
    else:
        mask = 0xFFFFFFFFFFFF
    return mac & mask


def __parse_content(source: str) -> Dict[Tuple[int, int], str]:
    data: Dict[Tuple[int, int], str] = {}

    for line in source.splitlines():
        line = line.replace("\t\t", "\t")

        if not line or line.startswith("#"):
            continue

        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        mac, manuf = parts

        if "/" in mac:
            mac_prefix, cidr_str = mac.split("/", 1)
            try:
                cidr = int(cidr_str)
            except ValueError:
                continue

            if cidr not in (28, 36):
                continue

            mac_val = __mac_to_u64(mac_prefix)
            if mac_val is None:
                continue

            data[(__mask_mac(mac_val, cidr), cidr)] = manuf
        else:
            mac_val = __mac_to_u64(mac)
            if mac_val is None:
                continue

            cidr = 24
            data[(__mask_mac(mac_val, cidr), cidr)] = manuf

    return data


with open(
    os.path.join(os.path.dirname(__file__), "manuf.txt"), "r", encoding="utf-8"
) as f:
    __CONTENT = __parse_content(f.read())


def lookup(mac: str) -> str:
    new_mac = mac.upper().replace("-", ":")

    if not __MAC_RE.match(new_mac):
        raise ValueError("Invalid MAC address")

    mac_val = __mac_to_u64(new_mac)
    if mac_val is None:
        raise ValueError("Invalid MAC format")

    for cidr in (36, 28, 24):
        masked = __mask_mac(mac_val, cidr)
        if (masked, cidr) in __CONTENT:
            return __CONTENT[(masked, cidr)]

    return "unknown"
