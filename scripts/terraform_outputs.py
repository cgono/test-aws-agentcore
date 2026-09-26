"""Read non-sensitive string outputs from a Terraform root module."""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path


def load_terraform_outputs(
    root: Path,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, str]:
    terraform = shutil.which("terraform") or "terraform"
    completed = run(
        [terraform, f"-chdir={root}", "output", "-json"],
        check=True,
        capture_output=True,
        text=True,
    )
    raw = json.loads(completed.stdout)
    return {
        name: entry["value"]
        for name, entry in raw.items()
        if not entry.get("sensitive") and isinstance(entry.get("value"), str)
    }
