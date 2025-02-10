import os
import re

__all__ = ["lookup"]


class Content:
    def __init__(self):
        self.data = {}
        self.slash_28 = {}
        self.slash_36 = {}


def __parse_content(source: str) -> Content:
    content = Content()

    for line in source.splitlines():
        line = line.replace("\t\t", "\t")
        fields = line.split(maxsplit=1)

        if not fields or fields[0].startswith("#"):
            continue

        mac, manuf = fields

        if mac.endswith(":00/28"):
            content.slash_28[mac] = manuf
        elif mac.endswith(":00/36"):
            content.slash_36[mac] = manuf

        content.data[mac] = manuf

    return content


with open(
    os.path.join(os.path.dirname(__file__), "manuf.txt"), "r", encoding="utf-8"
) as f:
    __CONTENT = __parse_content(f.read())


def lookup(mac: str) -> str:
    new_mac = mac.upper().replace("-", ":")

    if not re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", new_mac):
        raise ValueError("Invalid MAC address")

    if res := __CONTENT.slash_28.get(f"{new_mac[:10]}0:00:00/28"):
        return res
    if res := __CONTENT.slash_36.get(f"{new_mac[:13]}0:00/36"):
        return res
    if new_mac in __CONTENT.data:
        return __CONTENT.data[new_mac]

    prefix = mac[:8]
    return next(
        (
            __CONTENT.data[key]
            for key in sorted(__CONTENT.data)
            if key.startswith(prefix)
        ),
        "unknown",
    )
