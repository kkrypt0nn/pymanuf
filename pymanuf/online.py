import os
import re
import time
from threading import Lock

import requests

from . import __parse_content

__TTL = 3600
__LAST_FETCHED = 0
__CONTENT_LOCK = Lock()
__CONTENT = None


def __fetch_manuf():
    global __LAST_FETCHED, __CONTENT
    response = requests.get(
        "https://raw.githubusercontent.com/kkrypt0nn/pymanuf/refs/heads/main/pymanuf/manuf.txt",
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

    if not re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", new_mac):
        raise ValueError("Invalid MAC address")

    if new_mac in __CONTENT.data:
        return __CONTENT.data[new_mac]
    if res := __CONTENT.slash_28.get(f"{new_mac[:10]}0:00:00/28"):
        return res
    if res := __CONTENT.slash_36.get(f"{new_mac[:13]}0:00/36"):
        return res

    prefix = new_mac[:8]
    return next(
        (
            __CONTENT.data[key]
            for key in sorted(__CONTENT.data)
            if key.startswith(prefix)
        ),
        "unknown",
    )
