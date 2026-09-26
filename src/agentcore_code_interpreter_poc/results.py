"""Flatten Code Interpreter tool responses into a small, testable shape."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

# Terminal TaskStatus values (botocore bedrock-agentcore model) that mean the run did not succeed.
_FAILED_TASK_STATUSES = frozenset({"failed", "canceled"})


@dataclass(frozen=True)
class ToolResult:
    stdout: str
    stderr: str
    text: str
    exit_code: int | None
    is_error: bool
    shape: tuple[str, ...]

    @property
    def output(self) -> str:
        return "\n".join(part for part in (self.stdout, self.stderr, self.text) if part)

    @property
    def failed(self) -> bool:
        return self.is_error or (self.exit_code is not None and self.exit_code != 0)


def parse_tool_result(response: Mapping[str, Any]) -> ToolResult:
    stdout: list[str] = []
    stderr: list[str] = []
    text: list[str] = []
    exit_code: int | None = None
    is_error = False
    shape: set[str] = set()

    for event in response.get("stream") or ():
        if not isinstance(event, Mapping):
            continue
        for key, value in event.items():
            if key != "result":
                shape.add(f"event:{key}")
                is_error = True
                continue
            if not isinstance(value, Mapping):
                continue
            shape.update(str(name) for name in value)
            is_error = is_error or bool(value.get("isError"))
            structured = value.get("structuredContent")
            if isinstance(structured, Mapping):
                stdout.append(str(structured.get("stdout") or ""))
                stderr.append(str(structured.get("stderr") or ""))
                is_error = is_error or structured.get("taskStatus") in _FAILED_TASK_STATUSES
                code = structured.get("exitCode")
                if isinstance(code, int) and not isinstance(code, bool):
                    exit_code = code
            for item in value.get("content") or ():
                if isinstance(item, Mapping) and item.get("type") == "text":
                    text.append(str(item.get("text") or ""))

    return ToolResult(
        stdout="".join(stdout),
        stderr="".join(stderr),
        text="".join(text),
        exit_code=exit_code,
        is_error=is_error,
        shape=tuple(sorted(shape)),
    )
