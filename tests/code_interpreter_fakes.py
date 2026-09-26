from __future__ import annotations

import contextlib
from collections.abc import Callable, Iterator
from typing import Any

Responder = Callable[["FakeSession", str, str], dict[str, Any]]


def ok(stdout: str) -> dict[str, Any]:
    return {
        "stream": [
            {"result": {"structuredContent": {"stdout": stdout, "stderr": "", "exitCode": 0}}}
        ]
    }


def err(stderr: str) -> dict[str, Any]:
    return {
        "stream": [
            {
                "result": {
                    "structuredContent": {"stdout": "", "stderr": stderr, "exitCode": 1},
                    "isError": True,
                }
            }
        ]
    }


class FakeSession:
    def __init__(self, responder: Responder) -> None:
        self.responder = responder
        self.files: dict[str, str | bytes] = {}
        self.calls: list[tuple[str, str]] = []

    def execute_code(
        self, code: str, language: str = "python", clear_context: bool = False
    ) -> dict[str, Any]:
        self.calls.append((language, code))
        return self.responder(self, language, code)

    def execute_command(self, command: str) -> dict[str, Any]:
        self.calls.append(("shell", command))
        return self.responder(self, "shell", command)

    def upload_file(self, path: str, content: str | bytes, description: str = "") -> dict[str, Any]:
        self.files[path] = content
        return {}

    def download_file(self, path: str) -> str | bytes:
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def get_session(self) -> dict[str, Any]:
        self.calls.append(("get_session", ""))
        return {"status": "READY"}


def factory_of(
    *sessions: FakeSession,
) -> Callable[[], contextlib.AbstractContextManager[FakeSession]]:
    remaining: Iterator[FakeSession] = iter(sessions)

    def open_next() -> contextlib.AbstractContextManager[FakeSession]:
        return contextlib.nullcontext(next(remaining))

    return open_next
