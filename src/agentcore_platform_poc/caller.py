"""Pure helpers for the caller CLI: research briefs and a private token store."""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import jwt

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
        if self._path.is_symlink():
            raise OSError(f"{self._path} is a symlink; refusing to use it for tokens")
        return json.loads(self._path.read_text()) if self._path.exists() else {}

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        # One writer at a time (for example A and B signing in at once).
        fd = os.open(f"{self._path}.lock", os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _update(self, change: Callable[[dict[str, dict[str, str]]], None]) -> None:
        with self._locked():
            data = self._read()
            change(data)
            # Write a private temporary file, then replace: never a readable or half-written store.
            fd, tmp = tempfile.mkstemp(dir=self._path.parent, prefix=f".{self._path.name}.")
            try:
                with os.fdopen(fd, "w") as handle:
                    json.dump(data, handle)
                os.replace(tmp, self._path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
                raise

    def save(self, user: str, kind: str, token: str) -> None:
        self._update(lambda data: data.setdefault(user, {}).__setitem__(kind, token))

    def load(self, user: str, kind: str) -> str:
        return self._read()[user][kind]

    def bind_identity(self, user: str, api_token: str, hub_token: str) -> str:
        """Tie the --user label to one Entra account, so A's tokens never land under B."""
        oids = {str(_claims(token).get("oid", "")) for token in (api_token, hub_token)}
        if len(oids) != 1 or "" in oids:
            raise ValueError("the API and Hub tokens are not for the same signed-in user")
        oid = oids.pop()
        data = self._read()
        bound = data.get(user, {}).get("oid")
        if bound is not None and bound != oid:
            raise ValueError(f"user {user} is bound to another account; sign in as that account")
        if any(other != user and entry.get("oid") == oid for other, entry in data.items()):
            raise ValueError("this account is already bound to a different user label")
        self.save(user, "oid", oid)
        return oid


def _claims(token: str) -> dict[str, Any]:
    # Local label check only; the unified API and the Hub verify the signature.
    return dict(jwt.decode(token, options={"verify_signature": False}))
