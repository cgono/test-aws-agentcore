from __future__ import annotations

import stat
from pathlib import Path

import pytest

from agentcore_platform_poc.caller import REGIONS, TokenStore, brief_text


def test_regions_match_spec() -> None:
    assert REGIONS["sea"][1] == [
        "BRN",
        "KHM",
        "IDN",
        "LAO",
        "MYS",
        "MMR",
        "PHL",
        "SGP",
        "THA",
        "TLS",
        "VNM",
    ]
    assert REGIONS["ca"][1] == ["BLZ", "CRI", "SLV", "GTM", "HND", "NIC", "PAN"]


def test_brief_names_indicator_rule_outputs_and_marker() -> None:
    text = brief_text("ca", "marker-b-123")
    for needle in (
        "Central America",
        "NY.GDP.PCAP.PP.CD",
        "mrnev=1",
        "data.csv",
        "chart.png",
        "report.md",
        "marker-b-123",
        "BLZ,CRI",
    ):
        assert needle in text


def test_unknown_region() -> None:
    with pytest.raises(KeyError):
        brief_text("xx", "m")


def test_token_store_private(tmp_path: Path) -> None:
    store = TokenStore(tmp_path / "t.json")
    store.save("a", "api", "tok")
    store.save("a", "hub", "tok2")
    assert store.load("a", "api") == "tok" and store.load("a", "hub") == "tok2"
    assert stat.S_IMODE((tmp_path / "t.json").stat().st_mode) == 0o600
    with pytest.raises(KeyError):
        store.load("b", "api")
