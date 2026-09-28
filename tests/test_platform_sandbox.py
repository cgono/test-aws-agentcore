# tests/test_platform_sandbox.py
from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from agentcore_platform_poc.agent_platform.sandbox import Sandbox, SandboxError


class FakeCI:
    def __init__(self, region: str) -> None:
        self.files: dict[str, bytes | str] = {}
        self.started = self.stopped = 0
        self.code: list[str] = []

    def start(self, identifier: str) -> None:
        self.started += 1

    def stop(self) -> bool:
        self.stopped += 1
        return True

    def upload_file(self, path: str, content: bytes | str) -> dict[str, Any]:
        self.files[path] = content
        return {}

    def download_file(self, path: str) -> bytes | str:
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def execute_code(self, code: str) -> dict[str, Any]:
        self.code.append(code)
        self.files["chart.png"] = b"\x89PNG"
        return {
            "stream": [
                {"result": {"structuredContent": {"stdout": "ok", "stderr": "", "exitCode": 0}}}
            ]
        }


def test_run_copies_in_and_out_and_starts_once() -> None:
    fakes: list[FakeCI] = []
    sandbox = Sandbox(
        "r", "ci-1", client_factory=lambda region: fakes.append(FakeCI(region)) or fakes[-1]
    )
    result = sandbox.run("plot()", {"data.csv": b"a,b"}, ["chart.png", "nope.txt"])
    sandbox.run("again()", {}, [])
    assert fakes[0].started == 1 and fakes[0].files["data.csv"] == b"a,b"
    assert result.files == {"chart.png": b"\x89PNG"} and result.missing == ["nope.txt"]
    assert (result.stdout, result.exit_code, result.failed) == ("ok", 0, False)
    sandbox.stop()
    sandbox.stop()
    assert fakes[0].stopped == 1


def test_text_download_is_encoded() -> None:
    ci = FakeCI("r")
    ci.files["out.txt"] = "héllo"
    sandbox = Sandbox("r", "ci", client_factory=lambda _: ci)
    assert sandbox.run("x", {}, ["out.txt"]).files["out.txt"] == "héllo".encode()


@pytest.mark.parametrize("bad", ["/abs.csv", "../x.csv", "a/../b"])
def test_bad_sandbox_paths(bad: str) -> None:
    sandbox = Sandbox("r", "ci", client_factory=FakeCI)
    with pytest.raises(SandboxError, match="bad_path"):
        sandbox.run("x", {bad: b""}, [])


def test_stop_before_start_is_noop() -> None:
    Sandbox("r", "ci", client_factory=FakeCI).stop()


class SlowStartCI(FakeCI):
    def start(self, identifier: str) -> None:
        time.sleep(0.1)
        super().start(identifier)


def test_concurrent_first_runs_start_one_session() -> None:
    made: list[FakeCI] = []

    def factory(region: str) -> FakeCI:
        made.append(SlowStartCI(region))
        return made[-1]

    sandbox = Sandbox("r", "ci", client_factory=factory)
    threads = [threading.Thread(target=sandbox.run, args=("x", {}, [])) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    sandbox.stop()
    assert len(made) == 1 and made[0].stopped == 1
