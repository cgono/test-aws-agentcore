from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from scripts.terraform_outputs import load_terraform_outputs


def test_returns_only_non_sensitive_string_outputs() -> None:
    seen: dict[str, Any] = {}

    def fake_run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["args"] = args
        seen["kwargs"] = kwargs
        payload = {
            "aws_region": {"value": "ap-southeast-1", "sensitive": False},
            "secret_thing": {"value": "hidden", "sensitive": True},
            "a_list": {"value": ["x"], "sensitive": False},
        }
        return subprocess.CompletedProcess(args, 0, stdout=json.dumps(payload), stderr="")

    outputs = load_terraform_outputs(Path("infra/terraform/poc"), run=fake_run)

    assert outputs == {"aws_region": "ap-southeast-1"}
    assert seen["args"][1:] == ["-chdir=infra/terraform/poc", "output", "-json"]
    assert seen["args"][0].endswith("terraform")
    assert seen["kwargs"]["check"] is True
