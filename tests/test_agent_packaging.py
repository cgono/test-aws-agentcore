from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path
from typing import Any

import pytest

from agentcore_runtime_poc import packaging


def _source_tree(root: Path) -> Path:
    package = root / "src" / "agentcore_runtime_poc"
    (package / "runtime_agent").mkdir(parents=True)
    (package / "gateway_sim").mkdir()
    (package / "__init__.py").write_text('"""pkg"""\n')
    (package / "runtime_agent" / "__init__.py").write_text("")
    (package / "runtime_agent" / "entrypoint.py").write_text("def main() -> None: ...\n")
    (package / "runtime_agent" / "requirements.txt").write_text("httpx==0.28.1\n")
    (package / "gateway_sim" / "app.py").write_text("SECRET_ROUTE = 1\n")
    (root / "src" / ".env").write_text("OPENAI_API_KEY=never\n")
    return root / "src"


def _fake_installer(target: Path, index_url: str) -> None:
    (target / "httpx").mkdir(parents=True)
    (target / "httpx" / "__init__.py").write_text("VERSION = 1\n")
    (target / "httpx" / "__pycache__").mkdir()
    (target / "httpx" / "__pycache__" / "x.cpython-313.pyc").write_bytes(b"\x00")
    tool = target / "bin" / "tool"
    tool.parent.mkdir()
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)


def _build(tmp_path: Path) -> Path:
    return packaging.build_agent_zip(
        tmp_path / "out" / "agent.zip",
        source_root=_source_tree(tmp_path),
        index_url="https://pypi.org/simple",
        installer=_fake_installer,
        workdir=tmp_path / "work",
    )


def test_zip_has_deps_agent_sources_and_main_at_root(tmp_path: Path) -> None:
    with zipfile.ZipFile(_build(tmp_path)) as archive:
        names = set(archive.namelist())
        main = archive.read("main.py").decode()

    assert {
        "main.py",
        "httpx/__init__.py",
        "bin/tool",
        "agentcore_runtime_poc/__init__.py",
        "agentcore_runtime_poc/runtime_agent/__init__.py",
        "agentcore_runtime_poc/runtime_agent/entrypoint.py",
    } <= names
    assert "from agentcore_runtime_poc.runtime_agent.entrypoint import main" in main


def test_zip_excludes_gateway_sim_env_and_bytecode(tmp_path: Path) -> None:
    with zipfile.ZipFile(_build(tmp_path)) as archive:
        names = archive.namelist()

    assert not [n for n in names if "gateway_sim" in n or n.endswith(".pyc") or ".env" in n]
    assert not [n for n in names if n.endswith("requirements.txt")]


def test_zip_permissions_are_644_or_755(tmp_path: Path) -> None:
    with zipfile.ZipFile(_build(tmp_path)) as archive:
        modes = {info.filename: (info.external_attr >> 16) & 0o777 for info in archive.infolist()}

    assert modes["bin/tool"] == 0o755
    assert modes["main.py"] == 0o644
    assert set(modes.values()) <= {0o644, 0o755}


def test_zip_is_deterministic(tmp_path: Path) -> None:
    first = _build(tmp_path / "a").read_bytes()
    second = _build(tmp_path / "b").read_bytes()

    assert first == second


def _zip_with(path: Path, names: list[str]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name in names:
            archive.writestr(name, "x")
    return path


@pytest.mark.parametrize(
    "extra",
    [
        ".env",
        "nested/.poc-state.json",
        "agentcore_runtime_poc/gateway_sim/app.py",
        "a/__pycache__/b.pyc",
    ],
)
def test_verify_rejects_forbidden_members(tmp_path: Path, extra: str) -> None:
    path = _zip_with(
        tmp_path / "bad.zip",
        ["main.py", "agentcore_runtime_poc/runtime_agent/entrypoint.py", extra],
    )

    with pytest.raises(packaging.PackagingError, match="must not contain"):
        packaging.verify_agent_zip(path)


def test_verify_requires_main_and_entrypoint(tmp_path: Path) -> None:
    with pytest.raises(packaging.PackagingError, match="missing"):
        packaging.verify_agent_zip(_zip_with(tmp_path / "bad.zip", ["main.py"]))


def test_verify_enforces_size_limit(tmp_path: Path) -> None:
    path = _zip_with(
        tmp_path / "big.zip", ["main.py", "agentcore_runtime_poc/runtime_agent/entrypoint.py"]
    )

    with pytest.raises(packaging.PackagingError, match="limit"):
        packaging.verify_agent_zip(path, max_bytes=10)


def test_uv_installer_targets_linux_arm64_wheels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def fake_run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["args"] = args
        seen["kwargs"] = kwargs
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(packaging.shutil, "which", lambda name: "/usr/local/bin/uv")
    install = packaging.uv_installer(tmp_path / "requirements.txt", run=fake_run)

    install(tmp_path / "deps", "https://mirror.example.test/simple")

    args = seen["args"]
    assert args[:3] == ["/usr/local/bin/uv", "pip", "install"]
    assert args[args.index("--python-platform") + 1] == "aarch64-manylinux2014"
    assert args[args.index("--python-version") + 1] == "3.13"
    assert "https://mirror.example.test/simple" not in args
    assert seen["kwargs"]["env"]["UV_DEFAULT_INDEX"] == "https://mirror.example.test/simple"
    assert "--only-binary=:all:" in args
    assert seen["kwargs"]["check"] is True


def test_uv_installer_requires_uv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(packaging.shutil, "which", lambda name: None)

    with pytest.raises(packaging.PackagingError, match="uv"):
        packaging.uv_installer(tmp_path / "r.txt")(tmp_path, "https://pypi.org/simple")


def test_real_source_tree_ships_only_runtime_agent() -> None:
    files = packaging.agent_source_files(Path("src"))

    assert Path("agentcore_runtime_poc/runtime_agent/entrypoint.py") in files
    assert all("gateway_sim" not in path.parts for path in files)


def test_build_rejects_symlinks_in_dependencies(tmp_path: Path) -> None:
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("never")

    def linking_installer(target: Path, index_url: str) -> None:
        _fake_installer(target, index_url)
        (target / "httpx" / "leak.txt").symlink_to(outside)

    with pytest.raises(packaging.PackagingError, match="symlink"):
        packaging.build_agent_zip(
            tmp_path / "out" / "agent.zip",
            source_root=_source_tree(tmp_path),
            index_url="https://pypi.org/simple",
            installer=linking_installer,
            workdir=tmp_path / "work",
        )


def test_build_rejects_symlinked_agent_source(tmp_path: Path) -> None:
    source_root = _source_tree(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("SECRET = 1\n")
    (source_root / "agentcore_runtime_poc" / "runtime_agent" / "linked.py").symlink_to(outside)

    with pytest.raises(packaging.PackagingError, match="symlink"):
        packaging.build_agent_zip(
            tmp_path / "out" / "agent.zip",
            source_root=source_root,
            index_url="https://pypi.org/simple",
            installer=_fake_installer,
            workdir=tmp_path / "work",
        )


def test_build_refuses_a_reused_workdir(tmp_path: Path) -> None:
    stale = tmp_path / "work" / "deps" / "stale.py"
    stale.parent.mkdir(parents=True)
    stale.write_text("OLD = 1\n")

    with pytest.raises(packaging.PackagingError, match="empty"):
        _build(tmp_path)


def test_zip_entries_record_unix_create_system(tmp_path: Path) -> None:
    with zipfile.ZipFile(_build(tmp_path)) as archive:
        assert {info.create_system for info in archive.infolist()} == {3}


@pytest.mark.parametrize("name", ["../escape.py", "/abs.py", "a/../../b.py", "a\\..\\b.py"])
def test_verify_rejects_unsafe_member_paths(tmp_path: Path, name: str) -> None:
    path = _zip_with(
        tmp_path / "bad.zip",
        ["main.py", "agentcore_runtime_poc/runtime_agent/entrypoint.py", name],
    )

    with pytest.raises(packaging.PackagingError, match="unsafe"):
        packaging.verify_agent_zip(path)


def test_uv_installer_ignores_ambient_index_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def fake_run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["args"] = args
        seen["env"] = kwargs["env"]
        return subprocess.CompletedProcess(args, 0)

    for name in ("UV_INDEX", "UV_INDEX_URL", "UV_EXTRA_INDEX_URL"):
        monkeypatch.setenv(name, "https://other.example.test/simple")
    monkeypatch.setattr(packaging.shutil, "which", lambda name: "/usr/local/bin/uv")

    packaging.uv_installer(tmp_path / "r.txt", run=fake_run)(tmp_path, "https://pypi.org/simple")

    assert "--no-config" in seen["args"]
    assert not {"UV_INDEX", "UV_INDEX_URL", "UV_EXTRA_INDEX_URL"} & set(seen["env"])
