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


def _sdk_error(error: ClientError) -> ToolResult:
    return ToolResult("", "", "", None, True, (f"error:{error_code(error)}",))


def _run(session: Session, code: str, language: str = "python") -> ToolResult:
    return parse_tool_result(session.execute_code(code, language=language))


def _invoke(call: Callable[..., dict[str, Any]], *args: Any, **kwargs: Any) -> ToolResult:
    """Like _run, but an SDK error becomes a result, so the probe can report it as blocked."""
    try:
        return parse_tool_result(call(*args, **kwargs))
    except ClientError as error:
        return _sdk_error(error)


def _gated(*, controls: bool, ok: bool, conclusive: bool = True) -> Status:
    """Report pass or fail only when every control step succeeded; otherwise blocked."""
    return _classify(ok=controls and ok, conclusive=controls and conclusive)


def _service_errors(result: ToolResult) -> list[str]:
    """Stream exception events and SDK errors: unrelated to the code under test."""
    return [part for part in result.shape if part.startswith(("event:", "error:"))]


def _observed(result: ToolResult) -> str:
    """Record only error codes for service errors, never their messages."""
    errors = _service_errors(result)
    return ",".join(errors) if errors else clip(result.output)


def _download(session: Session, path: str) -> tuple[str | bytes | None, str]:
    """Return the content, or None with the reason ("FileNotFoundError" or an error code).

    The SDK raises FileNotFoundError for any readFiles response without a file resource,
    including a tool error, so a failed download is never proof that the file is missing.
    """
    try:
        return session.download_file(path), "ok"
    except FileNotFoundError:
        return None, "FileNotFoundError"
    except ClientError as error:
        return None, error_code(error)


def _as_text(value: str | bytes) -> str:
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value


def probe_state_persistence(factory: SessionFactory, config: Config) -> list[Observation]:
    with factory() as session:
        setup = _invoke(session.execute_code, "poc_marker = 41")
        same = _invoke(session.execute_code, "print(poc_marker + 1)")
    with factory() as session:
        other = _invoke(session.execute_code, "print(poc_marker)")
    persisted = _gated(
        controls=not setup.failed,
        ok="42" in same.output and not same.failed,
        conclusive=not _service_errors(same),
    )
    # Isolation is shown only when the variable existed and the new session fails naming it.
    missing = other.failed and "NameError" in other.output and "poc_marker" in other.output
    return [
        Observation(
            "Q1.1",
            "state_persists_within_session",
            persisted,
            "a variable set in one call is readable in a later call of the same session",
            _observed(same),
            config,
        ),
        Observation(
            "Q1.1",
            "state_isolated_across_sessions",
            # A successful read in the new session is the leak; other errors are inconclusive.
            _gated(controls=persisted == "pass", ok=missing, conclusive=not other.failed),
            "a new session cannot see the variable",
            _observed(other),
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
            result = _invoke(session.execute_code, code, language=language)
            observations.append(
                Observation(
                    "Q1.2",
                    f"{language}_executes",
                    _classify(
                        ok="42" in result.output and not result.failed,
                        conclusive=not _service_errors(result),
                    ),
                    "prints 42",
                    _observed(result),
                    config,
                )
            )
        shell = _invoke(session.execute_command, "echo poc-shell-ok && uname -m")
        observations.append(
            Observation(
                "Q1.2",
                "shell_command_executes",
                _classify(
                    ok="poc-shell-ok" in shell.output and not shell.failed,
                    conclusive=not _service_errors(shell),
                ),
                "echo output is returned; uname -m shows the CPU architecture",
                _observed(shell),
                config,
            )
        )
        back = _invoke(session.execute_code, "print('python-after-js')")
        observations.append(
            Observation(
                "Q1.2",
                "python_after_other_languages",
                _classify(
                    ok="python-after-js" in back.output and not back.failed,
                    conclusive=not _service_errors(back),
                ),
                "switching back to Python in the same session works",
                _observed(back),
                config,
            )
        )
    return observations


_ABSENCE_CHECK = (
    "import os\nprint('poc-present' if os.path.exists('poc_internal.txt') else 'poc-absent')"
)


def probe_files(factory: SessionFactory, config: Config) -> list[Observation]:
    blob = bytes(range(256))
    with factory() as session:
        wrote = _invoke(
            session.execute_code, "open('poc_internal.txt', 'w').write('internal-marker')"
        )
        internal, internal_outcome = _download(session, "poc_internal.txt")
        csv_upload = _invoke(session.upload_file, "poc_input.csv", "a,b\n1,2\n3,4\n")
        computed = _invoke(
            session.execute_code,
            "import csv, json\n"
            "rows = list(csv.DictReader(open('poc_input.csv')))\n"
            "json.dump({'sum_b': sum(int(r['b']) for r in rows)}, open('poc_output.json', 'w'))\n"
            "print('written')",
        )
        produced, produced_outcome = _download(session, "poc_output.json")
        blob_upload = _invoke(session.upload_file, "poc_blob.bin", blob)
        blob_back, blob_outcome = _download(session, "poc_blob.bin")
    with factory() as session:
        # Ask the sandbox directly: a failed download cannot tell "absent" from "read failed".
        absence = _invoke(session.execute_code, _ABSENCE_CHECK)

    internal_text = internal_outcome if internal is None else _as_text(internal)
    persisted = _gated(
        controls=not wrote.failed and internal is not None,
        ok=internal_text == "internal-marker",
    )
    produced_text = produced_outcome if produced is None else _as_text(produced)
    try:
        sum_b = json.loads(produced_text).get("sum_b")
    except (ValueError, AttributeError):
        sum_b = None

    return [
        Observation(
            "Q1.3",
            "internal_file_persists_within_session",
            persisted,
            "a file written by code is readable later in the same session",
            _observed(wrote) if wrote.failed else clip(internal_text),
            config,
        ),
        Observation(
            "Q1.3",
            "internal_file_absent_in_new_session",
            _gated(
                controls=persisted == "pass" and not absence.failed,
                ok="poc-absent" in absence.output,
                conclusive="poc-present" in absence.output,
            ),
            "a new session does not see the file",
            _observed(absence),
            config,
        ),
        Observation(
            "Q1.3",
            "caller_upload_compute_download",
            _gated(
                controls=not csv_upload.failed
                and not _service_errors(computed)
                and produced is not None,
                ok=sum_b == 6 and not computed.failed,
            ),
            "caller uploads a CSV, code writes JSON, caller downloads sum_b == 6",
            _observed(csv_upload) if csv_upload.failed else clip(produced_text),
            config,
        ),
        Observation(
            "Q1.3",
            "binary_round_trip",
            _gated(controls=not blob_upload.failed and blob_back is not None, ok=blob_back == blob),
            "256 raw bytes survive upload then download unchanged",
            _observed(blob_upload)
            if blob_upload.failed
            else blob_outcome
            if blob_back is None
            else f"type={type(blob_back).__name__} length={len(blob_back)}",
            config,
        ),
    ]
