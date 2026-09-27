from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from agentcore_platform_poc.packaging import COMPONENTS, build_component_zip
from agentcore_runtime_poc.packaging import PackagingError, verify_agent_zip

SRC = Path("src")


def _fake_installer(target: Path, index_url: str) -> None:
    (target / "fakedep").mkdir()
    (target / "fakedep" / "__init__.py").write_text("")


@pytest.mark.parametrize("name", ["research", "bench", "probe", "resource-hub"])
def test_component_zip_contains_entry_and_platform_code(name: str, tmp_path: Path) -> None:
    out = build_component_zip(
        name,
        tmp_path / f"{name}.zip",
        source_root=SRC,
        index_url="https://pypi.example.test/simple",
        installer=_fake_installer,
        workdir=tmp_path / "work",
        build_id="20260927T000000Z-abc1234",
        fetch=lambda url, sha: _tar_with_rg(),  # ripgrep download is stubbed
    )
    with zipfile.ZipFile(out) as archive:
        names = set(archive.namelist())
        assert (
            archive.read("agentcore_platform_poc/BUILD_ID").decode()
            == "20260927T000000Z-abc1234"
        )
    assert COMPONENTS[name].required_members <= names
    assert "fakedep/__init__.py" in names
    assert not any("gateway_sim" in n or "unified_api" in n for n in names)


def test_research_zip_excludes_bench_and_resource_hub(tmp_path: Path) -> None:
    out = build_component_zip(
        "research", tmp_path / "r.zip", source_root=SRC,
        index_url="https://pypi.example.test/simple", installer=_fake_installer,
        workdir=tmp_path / "w", build_id="b", fetch=lambda url, sha: b"",
    )
    names = zipfile.ZipFile(out).namelist()
    assert not any(n.startswith("agentcore_platform_poc/bench_agent/") for n in names)
    assert not any(n.startswith("agentcore_platform_poc/resource_hub/") for n in names)


def test_bench_zip_carries_executable_ripgrep(tmp_path: Path) -> None:
    out = build_component_zip(
        "bench", tmp_path / "b.zip", source_root=SRC,
        index_url="https://pypi.example.test/simple", installer=_fake_installer,
        workdir=tmp_path / "w", build_id="b", fetch=lambda url, sha: _tar_with_rg(),
    )
    info = zipfile.ZipFile(out).getinfo("bin/rg")
    assert (info.external_attr >> 16) & 0o111


def test_verify_rejects_zip_missing_component_entry(tmp_path: Path) -> None:
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w") as archive:
        archive.writestr("main.py", "")
    with pytest.raises(PackagingError, match="missing"):
        verify_agent_zip(bad, spec=COMPONENTS["research"])


def test_component_zip_allows_dependency_test_modules(tmp_path: Path) -> None:
    def installer(target: Path, index_url: str) -> None:
        tests = target / "certifi" / "tests"
        tests.mkdir(parents=True)
        (tests / "__init__.py").write_text("")

    out = build_component_zip(
        "research",
        tmp_path / "research.zip",
        source_root=SRC,
        index_url="https://pypi.example.test/simple",
        installer=installer,
        workdir=tmp_path / "work",
        build_id="b",
    )
    with zipfile.ZipFile(out) as archive:
        assert "certifi/tests/__init__.py" in archive.namelist()


def test_component_zip_rejects_first_party_tests(tmp_path: Path) -> None:
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w") as archive:
        for name in COMPONENTS["research"].required_members:
            archive.writestr(name, "")
        archive.writestr("agentcore_platform_poc/tests/leak.py", "")
    with pytest.raises(PackagingError, match="must not contain"):
        verify_agent_zip(bad, spec=COMPONENTS["research"])


def test_mirage_components_select_newer_arm64_wheel_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agentcore_platform_poc import packaging

    selected: list[str] = []

    def fake_uv_installer(requirements: Path, *, platform: str):
        selected.append(platform)
        return _fake_installer

    monkeypatch.setattr(packaging, "uv_installer_for_platform", fake_uv_installer)
    for name in ("probe", "bench"):
        build_component_zip(
            name,
            tmp_path / f"{name}.zip",
            source_root=SRC,
            index_url="https://pypi.example.test/simple",
            workdir=tmp_path / name,
            build_id="b",
            fetch=lambda url, sha: _tar_with_rg(),
        )
    assert selected == ["aarch64-manylinux_2_28"] * 2


def _tar_with_rg() -> bytes:
    import io
    import tarfile

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        data = b"#!/bin/sh\n"
        info = tarfile.TarInfo("ripgrep-14.1.1-aarch64-unknown-linux-gnu/rg")
        info.size = len(data)
        info.mode = 0o755
        tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()
