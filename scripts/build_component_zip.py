"""Build build/<component>/<component>.zip. Usage: -m scripts.build_component_zip research"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from agentcore_platform_poc.packaging import COMPONENTS, build_component_zip


def current_build_id() -> str:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to build component zips")
    sha = subprocess.run(  # noqa: S603 - resolved executable, fixed arguments
        [git, "rev-parse", "--short", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    return f"{dt.datetime.now(dt.UTC):%Y%m%dT%H%M%SZ}-{sha}"


def build(name: str, build_id: str | None = None) -> Path:
    index_url = os.environ.get("AGENT_PACKAGE_INDEX_URL", "https://pypi.org/simple")
    with tempfile.TemporaryDirectory() as workdir:
        return build_component_zip(
            name,
            Path("build") / name / f"{name}.zip",
            source_root=Path("src"),
            index_url=index_url,
            workdir=Path(workdir),
            build_id=build_id or current_build_id(),
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", choices=sorted(COMPONENTS))
    args = parser.parse_args(argv)
    path = build(args.component)
    checksum = hashlib.sha256(path.read_bytes()).hexdigest()
    print(f"{path} {path.stat().st_size} bytes sha256={checksum}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
