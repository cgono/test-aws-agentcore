# src/agentcore_platform_poc/agent_platform/sandbox.py
"""Code Interpreter wrapper: copy workspace files in, run code, copy outputs back out."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from bedrock_agentcore.tools.code_interpreter_client import CodeInterpreter

from agentcore_code_interpreter_poc.results import parse_tool_result


class SandboxError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class RunResult:
    stdout: str
    stderr: str
    exit_code: int | None
    failed: bool
    files: dict[str, bytes]
    missing: list[str]


def _check(path: str) -> str:
    if (
        not path
        or path.startswith("/")
        or "\\" in path
        or any(p in ("", ".", "..") for p in path.split("/"))
    ):
        raise SandboxError("bad_path")
    return path


class Sandbox:
    def __init__(
        self,
        region: str,
        identifier: str,
        *,
        client_factory: Callable[[str], Any] = CodeInterpreter,
    ) -> None:
        self._region = region
        self._identifier = identifier
        self._factory = client_factory
        self._client: Any = None

    def _started(self) -> Any:
        if self._client is None:
            client = self._factory(self._region)
            client.start(identifier=self._identifier)
            self._client = client
        return self._client

    def run(self, code: str, inputs: dict[str, bytes], outputs: list[str]) -> RunResult:
        for path in [*inputs, *outputs]:
            _check(path)
        client = self._started()
        for path, data in inputs.items():
            client.upload_file(path, data)
        parsed = parse_tool_result(client.execute_code(code))
        files: dict[str, bytes] = {}
        missing: list[str] = []
        for path in outputs:
            try:
                content = client.download_file(path)
            except FileNotFoundError:
                missing.append(path)
                continue
            files[path] = content.encode() if isinstance(content, str) else content
        return RunResult(
            parsed.stdout, parsed.stderr, parsed.exit_code, parsed.failed, files, missing
        )

    def stop(self) -> None:
        if self._client is not None:
            client, self._client = self._client, None
            client.stop()
