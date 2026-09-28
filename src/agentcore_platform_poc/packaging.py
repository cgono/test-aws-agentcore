"""Zip specs for the Phase 3a components (Runtime agents and the Resource Hub Lambda)."""

from __future__ import annotations

import hashlib
import io
import tarfile
from collections.abc import Callable
from pathlib import Path

import httpx

from agentcore_runtime_poc.packaging import (
    Installer,
    PackagingError,
    ZipSpec,
    build_agent_zip,
    uv_installer,
    uv_installer_for_platform,
)

PACKAGE_DIR = Path(__file__).resolve().parent
RIPGREP_URL = (
    "https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/"
    "ripgrep-14.1.1-aarch64-unknown-linux-gnu.tar.gz"
)
RIPGREP_SHA256 = "c827481c4ff4ea10c9dc7a4022c8de5db34a5737cb74484d62eb94a95841ab2f"
_FORBIDDEN = frozenset({"gateway_sim", "unified_api", "tests"})
MIRAGE_PLATFORM = "aarch64-manylinux_2_28"

Fetch = Callable[[str, str], bytes]


def _files(source_root: Path, *relative: str) -> list[Path]:
    out: list[Path] = []
    for item in relative:
        path = source_root / item
        if path.is_dir():
            out.extend(sorted(p for p in path.glob("*.py")))
        else:
            out.append(path)
    return [p.relative_to(source_root) for p in out]


_COMMON = (
    "agentcore_platform_poc/__init__.py",
    "agentcore_platform_poc/agent_platform",
    "agentcore_code_interpreter_poc/__init__.py",
    "agentcore_code_interpreter_poc/results.py",
)


def _entry(module: str) -> str:
    return f'from {module} import main\n\nif __name__ == "__main__":\n    main()\n'


def _spec(name: str, package: str, extra_sources: tuple[str, ...] = ()) -> ZipSpec:
    return ZipSpec(
        name=name,
        source_files=lambda root: _files(
            root, *_COMMON, f"agentcore_platform_poc/{package}", *extra_sources
        ),
        entry_script=_entry(f"agentcore_platform_poc.{package}.entrypoint"),
        required_members=frozenset(
            {
                "main.py",
                f"agentcore_platform_poc/{package}/entrypoint.py",
                "agentcore_platform_poc/BUILD_ID",
            }
        ),
        forbidden_parts=_FORBIDDEN,
        requirements=PACKAGE_DIR / package / "requirements.txt",
    )


def _resource_hub_spec() -> ZipSpec:
    return ZipSpec(
        name="resource-hub",
        source_files=lambda root: _files(
            root,
            "agentcore_platform_poc/__init__.py",
            "agentcore_platform_poc/grant.py",
            "agentcore_platform_poc/entra.py",
            "agentcore_platform_poc/resource_hub",
            "agentcore_identity_poc/__init__.py",
            "agentcore_identity_poc/jwt_validation.py",
        ),
        # Lambda calls agentcore_platform_poc.resource_hub.handler.handler; main.py is unused there
        # but keeps the shared verifier's required-member rule uniform.
        entry_script="",
        required_members=frozenset(
            {"agentcore_platform_poc/resource_hub/handler.py", "agentcore_platform_poc/BUILD_ID"}
        ),
        forbidden_parts=_FORBIDDEN | {"research_agent", "bench_agent", "agent_platform"},
        requirements=PACKAGE_DIR / "resource_hub" / "requirements.txt",
    )


COMPONENTS: dict[str, ZipSpec] = {
    "research": _spec("research", "research_agent"),
    # The bench methods filter with the Hub's own glob rules (paths.py has no Hub dependencies).
    "bench": _spec(
        "bench",
        "bench_agent",
        (
            "agentcore_platform_poc/resource_hub/__init__.py",
            "agentcore_platform_poc/resource_hub/paths.py",
        ),
    ),
    "probe": _spec("probe", "probe_agent"),
    "resource-hub": _resource_hub_spec(),
}


def http_fetch(url: str, sha256: str) -> bytes:
    data = httpx.get(url, follow_redirects=True, timeout=60.0).raise_for_status().content
    if hashlib.sha256(data).hexdigest() != sha256:
        raise PackagingError("ripgrep archive checksum mismatch")
    return data


def _ripgrep(fetch: Fetch) -> bytes:
    archive = fetch(RIPGREP_URL, RIPGREP_SHA256)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        member = next(m for m in tar.getmembers() if m.name.endswith("/rg") and m.isfile())
        handle = tar.extractfile(member)
        if handle is None:
            raise PackagingError("rg missing from ripgrep archive")
        return handle.read()


def build_component_zip(
    name: str,
    output: Path,
    *,
    source_root: Path,
    index_url: str,
    installer: Installer | None = None,
    workdir: Path,
    build_id: str,
    fetch: Fetch = http_fetch,
) -> Path:
    base = COMPONENTS[name]
    default_installer = (
        uv_installer_for_platform(base.requirements, platform=MIRAGE_PLATFORM)
        if name in {"bench", "probe"}
        else uv_installer(base.requirements)
    )

    def extra(_: Path) -> dict[str, tuple[bytes, bool]]:
        files = {"agentcore_platform_poc/BUILD_ID": (build_id.encode(), False)}
        if name == "bench":
            files["bin/rg"] = (_ripgrep(fetch), True)
        return files

    spec = ZipSpec(
        name=base.name,
        source_files=base.source_files,
        entry_script=base.entry_script,
        required_members=base.required_members,
        forbidden_parts=base.forbidden_parts,
        requirements=base.requirements,
        extra_files=extra,
    )
    return build_agent_zip(
        output,
        source_root=source_root,
        index_url=index_url,
        installer=installer or default_installer,
        workdir=workdir,
        spec=spec,
    )
