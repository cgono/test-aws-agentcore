"""Build build/agent/agent.zip for the AgentCore Runtime direct code deployment."""

from __future__ import annotations

import argparse
import hashlib
import os
import tempfile
from pathlib import Path

from agentcore_runtime_poc.packaging import build_agent_zip, uv_installer

DEFAULT_OUTPUT = Path("build/agent/agent.zip")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    # Taken from the environment only: at work this URL may embed Artifactory credentials.
    index_url = os.environ.get("AGENT_PACKAGE_INDEX_URL", "https://pypi.org/simple")
    with tempfile.TemporaryDirectory() as workdir:
        path = build_agent_zip(
            args.output,
            source_root=Path("src"),
            index_url=index_url,
            installer=uv_installer(),
            workdir=Path(workdir),
        )
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    print(f"{path} {path.stat().st_size} bytes sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
