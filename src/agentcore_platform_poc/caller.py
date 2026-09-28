"""Pure helpers for the caller CLI: research briefs and a private token store."""

from __future__ import annotations

import json
import os
from pathlib import Path

REGIONS: dict[str, tuple[str, list[str]]] = {
    "sea": (
        "Southeast Asia",
        ["BRN", "KHM", "IDN", "LAO", "MYS", "MMR", "PHL", "SGP", "THA", "TLS", "VNM"],
    ),
    "ca": ("Central America", ["BLZ", "CRI", "SLV", "GTM", "HND", "NIC", "PAN"]),
}


def brief_text(region: str, marker: str) -> str:
    name, countries = REGIONS[region]
    codes = ",".join(countries)
    url_codes = codes.replace(",", ";")
    return (
        f"# Research brief\n\nMarker: {marker}\n\n"
        f"Region: {name}\nCountries (ISO3): {codes}\n\n"
        "Indicator: GDP per capita, PPP (current international $), "
        "World Bank code NY.GDP.PCAP.PP.CD.\n"
        f"Get it in one call: https://api.worldbank.org/v2/country/{url_codes}/indicator/"
        "NY.GDP.PCAP.PP.CD?format=json&mrnev=1&per_page=100\n"
        "Year rule: for each country use its most recent non-empty value (mrnev=1); "
        "the year may differ.\n\n"
        "Deliverables in this workspace:\n"
        "1. data.csv with columns iso3,country,year,value (one row per country with a value).\n"
        "2. chart.png: a bar chart of value by country; label each bar with its year.\n"
        "3. report.md: a short summary, and list any country with no value as missing.\n"
    )


class TokenStore:
    def __init__(self, path: Path = Path(".poc3-tokens.json")) -> None:
        self._path = path

    def _read(self) -> dict[str, dict[str, str]]:
        return json.loads(self._path.read_text()) if self._path.exists() else {}

    def save(self, user: str, kind: str, token: str) -> None:
        data = self._read()
        data.setdefault(user, {})[kind] = token
        fd = os.open(self._path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(data, handle)
        os.chmod(self._path, 0o600)

    def load(self, user: str, kind: str) -> str:
        return self._read()[user][kind]
