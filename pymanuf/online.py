import os
import re
import time
from threading import Lock

import requests

from . import __MAC_RE, __mac_to_u64, __mask_mac, __parse_content

__TTL = 3600
__LAST_FETCHED = 0
__CONTENT_LOCK = Lock()
__CONTENT = {}


def __fetch_manuf():
    global __LAST_FETCHED, __CONTENT
    response = requests.get(
        "https://raw.githubusercontent.com/kkrypt0nn/manuf/refs/heads/main/manuf.txt",
        timeout=5,
    )
    if response.status_code == 200:
        with __CONTENT_LOCK:
            __CONTENT = __parse_content(response.text)
            __LAST_FETCHED = time.time()
    else:
        raise Exception("Failed to fetch online manuf.txt")


try:
    __fetch_manuf()
except Exception:
    with open(
        os.path.join(os.path.dirname(__file__), "manuf.txt"), "r", encoding="utf-8"
    ) as f:
        __CONTENT = __parse_content(f.read())
        __LAST_FETCHED = time.time()


def lookup(mac: str) -> str:
    global __LAST_FETCHED
    if time.time() - __LAST_FETCHED > __TTL:
        __fetch_manuf()

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
