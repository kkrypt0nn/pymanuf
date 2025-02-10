import csv
import html

import requests

file_header = """# This file was generated by running ./tools/make-manuf.py for the pymanuf library
# 
# The data below has been assembled from the following sources:
#
# The IEEE public OUI listings available from:
# <http://standards-oui.ieee.org/oui/oui.csv>
# <http://standards-oui.ieee.org/cid/cid.csv>
# <http://standards-oui.ieee.org/iab/iab.csv>
# <http://standards-oui.ieee.org/oui28/mam.csv>
# <http://standards-oui.ieee.org/oui36/oui36.csv>
#
# You can get the latest version of this file from
# https://github.com/kkrypt0nn/pymanuf/blob/main/src/manuf.txt

"""

urls = [
    "http://standards-oui.ieee.org/oui/oui.csv",
    "http://standards-oui.ieee.org/cid/cid.csv",
    "http://standards-oui.ieee.org/iab/iab.csv",
    "http://standards-oui.ieee.org/oui28/mam.csv",
    "http://standards-oui.ieee.org/oui36/oui36.csv",
]


def get_csv(url: str) -> str:
    response = requests.get(
        url=url,
        headers={"User-Agent": "pymanuf (https://github.com/kkrypt0nn/pymanuf)"},
    )
    return response.text


def assignment_to_prefix(assignment: str) -> str:
    suffix = ""
    match len(assignment):
        case 7:
            suffix = "0:00:00/28"
        case 9:
            suffix = "0:00/36"
    return (
        ":".join(assignment[i : i + 2] for i in range(0, len(assignment), 2)) + suffix
    )


def format_manufacturer(organization_name: str) -> str:
    manufacturer = organization_name.strip()  # Strip unnecessary whitespaces
    manufacturer = html.unescape(
        manufacturer
    )  # Unescape some HTML that is in some organization names
    if manufacturer.upper() == manufacturer:
        manufacturer = manufacturer.title()  # Let's not scream the organization names
    return manufacturer


def main() -> None:
    content = {}
    for url in urls:
        csv_content = get_csv(url)
        reader = csv.reader(csv_content.splitlines())
        next(reader)  # We ignore the title row
        for row in reader:
            # Row format: Registry,Assignment,Organization Name,Organization Address
            # We only need the Assignment && Organization Name
            prefix = assignment_to_prefix(row[1].upper())
            manufacturer = format_manufacturer(row[2])
            content[prefix] = manufacturer
    keys = list(content.keys())
    keys.sort()
    sorted_content = {i: content[i] for i in keys}
    with open("src/manuf.txt", "w+", encoding="utf-8") as manuf_file:
        manuf_file.write(file_header)
        for k, v in sorted_content.items():
            separator = "\t" * 2
            if "/" in k:
                separator = "\t"
            manuf_file.write(f"{k}{separator}{v}\n")


if __name__ == "__main__":
    main()
