"""Build the Runtime direct-code-deployment zip: Linux ARM64 wheels, agent sources, main.py."""

from __future__ import annotations

import os
import shutil
import subprocess
import zipfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath

AGENT_REQUIREMENTS = Path(__file__).resolve().parent / "runtime_agent" / "requirements.txt"
PLATFORM = "aarch64-manylinux2014"
PYTHON_VERSION = "3.13"
MAX_ZIP_BYTES = 250 * 1024 * 1024
ENTRY_SCRIPT = (
    "from agentcore_runtime_poc.runtime_agent.entrypoint import main\n"
    "\n"
    'if __name__ == "__main__":\n'
    "    main()\n"
)
REQUIRED_MEMBERS = frozenset({"main.py", "agentcore_runtime_poc/runtime_agent/entrypoint.py"})
FORBIDDEN_BASENAMES = frozenset(
    {".env", ".poc-state.json", ".poc-expiry-state.json", "terraform.tfstate", "terraform.tfvars"}
)
# uv settings that could add or replace indexes behind AGENT_PACKAGE_INDEX_URL.
_AMBIENT_INDEX_VARIABLES = frozenset({"UV_INDEX", "UV_INDEX_URL", "UV_EXTRA_INDEX_URL"})
# Fixed timestamps keep the zip byte-identical across builds, so Terraform only redeploys on change.
_FIXED_TIME = (1980, 1, 1, 0, 0, 0)

Installer = Callable[[Path, str], None]


class PackagingError(RuntimeError):
    """The agent zip could not be built or failed verification."""


def uv_installer(
    requirements: Path = AGENT_REQUIREMENTS,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> Installer:
    def install(target: Path, index_url: str) -> None:
        uv = shutil.which("uv")
        if uv is None:
            raise PackagingError("uv is required to fetch Linux ARM64 wheels")
        run(  # noqa: S603 - uv is resolved from PATH; arguments are fixed.
            [
                uv,
                "pip",
                "install",
                "--no-config",
                "--python-platform",
                PLATFORM,
                "--python-version",
                PYTHON_VERSION,
                "--target",
                str(target),
                "--only-binary=:all:",
                "-r",
                str(requirements),
            ],
            check=True,
            # Via env, not argv: at work the index URL can carry Artifactory credentials.
            env={
                **{k: v for k, v in os.environ.items() if k not in _AMBIENT_INDEX_VARIABLES},
                "UV_DEFAULT_INDEX": index_url,
            },
        )

    return install


def agent_source_files(source_root: Path) -> list[Path]:
    package = source_root / "agentcore_runtime_poc"
    files = [package / "__init__.py", *sorted((package / "runtime_agent").glob("*.py"))]
    return [path.relative_to(source_root) for path in files]


def _read_regular(path: Path) -> bytes:
    # A symlink could pull a file from outside the intended inputs (a secret) into the zip.
    if path.is_symlink():
        raise PackagingError(f"refusing to package symlink {path.name}")
    return path.read_bytes()


def _is_packable(relative: Path) -> bool:
    return "__pycache__" not in relative.parts and relative.suffix != ".pyc"


def _write(archive: zipfile.ZipFile, name: str, data: bytes, *, executable: bool) -> None:
    info = zipfile.ZipInfo(name, date_time=_FIXED_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3  # Unix, so external_attr permissions mean the same on every host.
    info.external_attr = (0o100755 if executable else 0o100644) << 16
    archive.writestr(info, data)


def build_agent_zip(
    output: Path, *, source_root: Path, index_url: str, installer: Installer, workdir: Path
) -> Path:
    deps = workdir / "deps"
    if deps.exists() and any(deps.iterdir()):
        raise PackagingError("workdir deps directory must be empty")
    deps.mkdir(parents=True, exist_ok=True)
    installer(deps, index_url)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(deps.rglob("*")):
            relative = path.relative_to(deps)
            if (path.is_symlink() or path.is_file()) and _is_packable(relative):
                _write(
                    archive,
                    relative.as_posix(),
                    _read_regular(path),
                    executable=os.access(path, os.X_OK),
                )
        for relative in agent_source_files(source_root):
            _write(
                archive,
                relative.as_posix(),
                _read_regular(source_root / relative),
                executable=False,
            )
        _write(archive, "main.py", ENTRY_SCRIPT.encode(), executable=False)
    verify_agent_zip(output)
    return output


def verify_agent_zip(path: Path, *, max_bytes: int = MAX_ZIP_BYTES) -> None:
    size = path.stat().st_size
    if size > max_bytes:
        raise PackagingError(f"zip is {size} bytes; limit is {max_bytes}")
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
    missing = REQUIRED_MEMBERS - set(names)
    if missing:
        raise PackagingError(f"zip is missing {sorted(missing)}")
    for name in names:
        parts = PurePosixPath(name).parts
        if name.startswith("/") or "\\" in name or ".." in parts:
            raise PackagingError(f"zip has unsafe member path {name}")
        if (
            parts[-1] in FORBIDDEN_BASENAMES
            or "__pycache__" in parts
            or name.endswith(".pyc")
            or "gateway_sim" in parts
        ):
            raise PackagingError(f"zip must not contain {name}")
