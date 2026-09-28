from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import jwt
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


def test_token_store_refuses_a_symlink(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.txt"
    target.write_text("keep")
    (tmp_path / "t.json").symlink_to(target)
    with pytest.raises(OSError):
        TokenStore(tmp_path / "t.json").save("a", "api", "tok")
    assert target.read_text() == "keep"


def test_token_store_never_exposes_tokens_in_a_readable_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "t.json"
    path.write_text("{}")
    path.chmod(0o644)
    modes: list[int] = []
    real_dump = json.dump

    def spy(data: object, handle: Any) -> None:
        modes.append(stat.S_IMODE(os.fstat(handle.fileno()).st_mode))
        real_dump(data, handle)

    monkeypatch.setattr("agentcore_platform_poc.caller.json.dump", spy)
    TokenStore(path).save("a", "api", "tok")
    assert modes == [0o600]


def test_interrupted_save_keeps_the_old_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = TokenStore(tmp_path / "t.json")
    store.save("a", "api", "tok")

    def boom(data: object, handle: Any) -> None:
        handle.write('{"a": {"ap')
        raise KeyboardInterrupt

    monkeypatch.setattr("agentcore_platform_poc.caller.json.dump", boom)
    with pytest.raises(KeyboardInterrupt):
        store.save("b", "api", "tok-b")
    assert store.load("a", "api") == "tok"
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".t.json.")]  # no temp left


def _jwt(oid: str) -> str:
    return jwt.encode({"oid": oid}, "k" * 32, algorithm="HS256")


def test_identity_binding(tmp_path: Path) -> None:
    store = TokenStore(tmp_path / "t.json")
    assert store.bind_identity("a", _jwt("oid-a"), _jwt("oid-a")) == "oid-a"
    assert store.bind_identity("a", _jwt("oid-a"), _jwt("oid-a")) == "oid-a"  # same person again
    with pytest.raises(ValueError, match="different"):
        store.bind_identity("b", _jwt("oid-a"), _jwt("oid-a"))  # A's account under label b
    with pytest.raises(ValueError, match="bound"):
        store.bind_identity("a", _jwt("oid-c"), _jwt("oid-c"))  # label a already names oid-a
    with pytest.raises(ValueError, match="same"):
        store.bind_identity("b", _jwt("oid-b"), _jwt("oid-x"))  # API and Hub tokens disagree
