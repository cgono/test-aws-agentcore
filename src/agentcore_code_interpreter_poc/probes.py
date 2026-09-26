"""Probe functions for Phase 1. Each returns observations; none raises on an expected outcome."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from typing import Any, Protocol

from botocore.exceptions import ClientError  # type: ignore[import-untyped]

from agentcore_code_interpreter_poc.observations import Observation, Status
from agentcore_code_interpreter_poc.results import ToolResult, parse_tool_result


class Session(Protocol):
    def execute_code(
        self, code: str, language: str = ..., clear_context: bool = ...
    ) -> dict[str, Any]: ...

    def execute_command(self, command: str) -> dict[str, Any]: ...

    def upload_file(
        self, path: str, content: str | bytes, description: str = ...
    ) -> dict[str, Any]: ...

    def download_file(self, path: str) -> str | bytes: ...

    def get_session(self) -> dict[str, Any]: ...


SessionFactory = Callable[[], AbstractContextManager[Session]]
Config = Mapping[str, str]


def clip(value: str, limit: int = 300) -> str:
    return value if len(value) <= limit else f"{value[:limit]}...[{len(value)} chars]"


def error_code(error: Exception) -> str:
    if isinstance(error, ClientError):
        return str(error.response.get("Error", {}).get("Code", "ClientError"))
    return type(error).__name__


def _status(ok: bool) -> Status:
    return "pass" if ok else "fail"


def _classify(*, ok: bool, conclusive: bool) -> Status:
    """Report blocked, not fail, when an unrelated error prevented a conclusion."""
    if ok:
        return "pass"
    return "fail" if conclusive else "blocked"


def _run(session: Session, code: str, language: str = "python") -> ToolResult:
    return parse_tool_result(session.execute_code(code, language=language))


def _as_text(value: str | bytes) -> str:
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value


def probe_state_persistence(factory: SessionFactory, config: Config) -> list[Observation]:
    with factory() as session:
        _run(session, "poc_marker = 41")
        same = _run(session, "print(poc_marker + 1)")
    with factory() as session:
        other = _run(session, "print(poc_marker)")
    return [
        Observation(
            "Q1.1",
            "state_persists_within_session",
            _status("42" in same.output and not same.failed),
            "a variable set in one call is readable in a later call of the same session",
            clip(same.output),
            config,
        ),
        Observation(
            "Q1.1",
            "state_isolated_across_sessions",
            _classify(ok="NameError" in other.output, conclusive=not other.failed),
            "a new session cannot see the variable",
            clip(other.output),
            config,
        ),
    ]


def probe_languages(factory: SessionFactory, config: Config) -> list[Observation]:
    observations: list[Observation] = []
    snippets = (
        ("javascript", "console.log(6 * 7)"),
        ("typescript", "const n: number = 6 * 7;\nconsole.log(n);"),
    )
    with factory() as session:
        for language, code in snippets:
            result = _run(session, code, language)
            observations.append(
                Observation(
                    "Q1.2",
                    f"{language}_executes",
                    _status("42" in result.output and not result.failed),
                    "prints 42",
                    clip(result.output),
                    config,
                )
            )
        shell = parse_tool_result(session.execute_command("echo poc-shell-ok && uname -m"))
        observations.append(
            Observation(
                "Q1.2",
                "shell_command_executes",
                _status("poc-shell-ok" in shell.output and not shell.failed),
                "echo output is returned; uname -m shows the CPU architecture",
                clip(shell.output),
                config,
            )
        )
        back = _run(session, "print('python-after-js')")
        observations.append(
            Observation(
                "Q1.2",
                "python_after_other_languages",
                _status("python-after-js" in back.output and not back.failed),
                "switching back to Python in the same session works",
                clip(back.output),
                config,
            )
        )
    return observations


def probe_files(factory: SessionFactory, config: Config) -> list[Observation]:
    blob = bytes(range(256))
    with factory() as session:
        _run(session, "open('poc_internal.txt', 'w').write('internal-marker')")
        internal = _as_text(session.download_file("poc_internal.txt"))
        session.upload_file("poc_input.csv", "a,b\n1,2\n3,4\n")
        _run(
            session,
            "import csv, json\n"
            "rows = list(csv.DictReader(open('poc_input.csv')))\n"
            "json.dump({'sum_b': sum(int(r['b']) for r in rows)}, open('poc_output.json', 'w'))\n"
            "print('written')",
        )
        produced = _as_text(session.download_file("poc_output.json"))
        session.upload_file("poc_blob.bin", blob)
        blob_back = session.download_file("poc_blob.bin")
    with factory() as session:
        try:
            leaked: str = _as_text(session.download_file("poc_internal.txt"))
        except FileNotFoundError:
            leaked = "absent:FileNotFoundError"
        except ClientError as error:
            leaked = f"blocked:{error_code(error)}"

    try:
        sum_b = json.loads(produced).get("sum_b")
    except (ValueError, AttributeError):
        sum_b = None

    return [
        Observation(
            "Q1.3",
            "internal_file_persists_within_session",
            _status(internal == "internal-marker"),
            "a file written by code is readable later in the same session",
            clip(internal),
            config,
        ),
        Observation(
            "Q1.3",
            "internal_file_absent_in_new_session",
            _classify(
                ok=leaked.startswith("absent:"), conclusive=not leaked.startswith("blocked:")
            ),
            "a new session does not see the file",
            clip(leaked),
            config,
        ),
        Observation(
            "Q1.3",
            "caller_upload_compute_download",
            _status(sum_b == 6),
            "caller uploads a CSV, code writes JSON, caller downloads sum_b == 6",
            clip(produced),
            config,
        ),
        Observation(
            "Q1.3",
            "binary_round_trip",
            _status(blob_back == blob),
            "256 raw bytes survive upload then download unchanged",
            f"type={type(blob_back).__name__} length={len(blob_back)}",
            config,
        ),
    ]
