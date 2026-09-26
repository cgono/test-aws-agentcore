"""Probe functions for Phase 1. Each returns observations; none raises on an expected outcome."""

from __future__ import annotations

import json
import time
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


INVOKE_EXCLUDED_SESSION_POLICY: dict[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "bedrock-agentcore:StartCodeInterpreterSession",
                "bedrock-agentcore:StopCodeInterpreterSession",
                "bedrock-agentcore:GetCodeInterpreterSession",
            ],
            "Resource": "*",
        }
    ],
}

_EGRESS_CODE = (
    "import urllib.error, urllib.request\n"
    "try:\n"
    "    print('status', urllib.request.urlopen('https://aws.amazon.com', timeout=10).status)\n"
    "except urllib.error.HTTPError as error:\n"
    "    print('status', error.code)\n"
    "except Exception as error:\n"
    "    print('blocked', type(error).__name__)\n"
)
_BLOCKING_CODES = frozenset(
    {
        "AccessDeniedException",
        "accessDeniedException",
        "ThrottlingException",
        "throttlingException",
        "InternalServerException",
        "internalServerException",
    }
)


# The error code an invoke on an expired session is expected to return. Any other code is
# inconclusive, so the TTL probe reports it as blocked and records the code for the write-up.
_EXPIRED_CODES = frozenset({"ResourceNotFoundException", "resourceNotFoundException"})


def _codes(result: ToolResult) -> set[str]:
    """Service error codes, without the "error:" or "event:" prefix."""
    return {part.split(":", 1)[1] for part in _service_errors(result)}


def _markers(result: ToolResult, *markers: str) -> str:
    """Record which expected markers appeared and any error codes, never raw result text."""
    found = ",".join(marker for marker in markers if marker in result.output) or "none"
    errors = _service_errors(result)
    return " ".join([f"failed={result.failed}", f"markers={found}", *errors])


def _recorded(result: ToolResult) -> Status:
    """A record-only check passes when it produced a record; service errors block it."""
    return "blocked" if _service_errors(result) else "pass"


def probe_egress(
    factory: SessionFactory, config: Config, *, expected_reachable: bool
) -> list[Observation]:
    with factory() as session:
        result = _invoke(session.execute_code, _EGRESS_CODE)
    # The probe code prints exactly one of these lines; anything else is inconclusive.
    line = next(
        (part for part in result.output.splitlines() if part.startswith(("status ", "blocked "))),
        "",
    )
    ran = bool(line) and not _service_errors(result)
    return [
        Observation(
            "Q1.4",
            "public_internet_egress",
            _gated(controls=ran, ok=line.startswith("status ") == expected_reachable),
            f"reachable={expected_reachable}",
            line if ran else ",".join(_service_errors(result)) or "no-result",
            config,
        )
    ]


def probe_failure_modes(
    factory: SessionFactory, config: Config, *, clock: Callable[[], float] = time.monotonic
) -> list[Observation]:
    with factory() as session:
        syntax = _invoke(session.execute_code, "def broken(:\n    pass")
        raised = _invoke(session.execute_code, "raise ValueError('poc-boom')")
        big = _invoke(session.execute_code, "print('a' * 2_000_000)")
        started = clock()
        slow = _invoke(session.execute_code, "import time\ntime.sleep(60)\nprint('slept')")
        slow_seconds = clock() - started
        memory = _invoke(
            session.execute_code,
            "block = bytearray(1024 * 1024 * 1024)\nprint('allocated', len(block))",
        )
    returned = len(big.stdout or big.text)
    return [
        Observation(
            "Q1.5",
            "syntax_error_surfaces",
            _gated(
                controls=not _service_errors(syntax),
                ok=syntax.failed and "SyntaxError" in syntax.output,
            ),
            "a syntax error is reported as a failed execution",
            _markers(syntax, "SyntaxError"),
            config,
        ),
        Observation(
            "Q1.5",
            "exception_surfaces",
            _gated(
                controls=not _service_errors(raised),
                ok=raised.failed and "poc-boom" in raised.output,
            ),
            "an uncaught exception is reported with its message",
            _markers(raised, "ValueError", "poc-boom"),
            config,
        ),
        Observation(
            "Q1.5",
            "large_output",
            _recorded(big),
            "the call returns; record whether 2,000,000 chars are truncated",
            _observed(big) if _service_errors(big) else f"returned {returned} of 2000000 chars",
            config,
        ),
        Observation(
            "Q1.5",
            "sixty_second_execution",
            _gated(
                controls=not _service_errors(slow),
                ok="slept" in slow.output and not slow.failed,
            ),
            "a 60 s execution completes within the per-execution limit",
            f"{slow_seconds:.1f}s {_markers(slow, 'slept')}",
            config,
        ),
        Observation(
            "Q1.5",
            "one_gib_allocation",
            _recorded(memory),
            "record whether a 1 GiB allocation fits in the sandbox",
            _markers(memory, "allocated", "MemoryError"),
            config,
        ),
    ]


def _attempt(session: Session) -> str:
    """Return "ok", or the error code that stopped a trivial execution."""
    try:
        result = _run(session, "print('alive')")
    except ClientError as error:
        return error_code(error)
    if result.failed or "alive" not in result.output:
        return ",".join(sorted(_codes(result))) or "failed"
    return "ok"


def _expired(outcome: str) -> Status:
    if outcome == "ok":
        return "fail"
    return "pass" if outcome in _EXPIRED_CODES else "blocked"


def probe_session_ttl(
    open_with_timeout: Callable[[int], AbstractContextManager[Session]],
    config: Config,
    *,
    ttl_seconds: int = 60,
    sleep: Callable[[float], None] = time.sleep,
) -> list[Observation]:
    wait = ttl_seconds + 20
    with open_with_timeout(ttl_seconds) as session:
        idle_before = _attempt(session)
        sleep(wait)
        idle_after = _attempt(session)
    keepalives: list[tuple[int, str]] = []
    with open_with_timeout(ttl_seconds) as session:
        active_before = _attempt(session)
        for step in range(1, wait // 15 + 1):
            sleep(15)
            keepalives.append((step * 15, _attempt(session)))
        active_after = _attempt(session)
    # The session is shown active only if every keepalive before the TTL succeeded.
    kept_alive = active_before == "ok" and all(
        outcome == "ok" for elapsed, outcome in keepalives if elapsed < ttl_seconds
    )
    return [
        Observation(
            "Q1.5",
            "idle_session_ends_at_ttl",
            _expired(idle_after) if idle_before == "ok" else "blocked",
            f"an idle session is gone {wait}s after start (TTL {ttl_seconds}s)",
            f"before={idle_before} after={idle_after}",
            config,
        ),
        Observation(
            "Q1.5",
            "active_session_ends_at_ttl",
            _expired(active_after) if kept_alive else "blocked",
            "sessionTimeoutSeconds is a fixed lifetime: activity does not extend it",
            f"before={active_before} "
            f"keepalives={','.join(outcome for _, outcome in keepalives)} after={active_after}",
            config,
        ),
    ]


def probe_execution_limit(
    factory: SessionFactory,
    config: Config,
    *,
    seconds: int = 600,
    clock: Callable[[], float] = time.monotonic,
) -> list[Observation]:
    with factory() as session:
        started = clock()
        codes: set[str] = set()
        try:
            result = _run(session, f"import time\ntime.sleep({seconds})\nprint('slept')")
            if "slept" in result.output and not result.failed:
                outcome = "completed"
            else:
                codes = _codes(result)
                outcome = "error:" + (",".join(result.shape) or "failed")
        except Exception as error:
            codes = {error_code(error)}
            outcome = f"raised:{error_code(error)}"
        elapsed = clock() - started
    return [
        Observation(
            "Q1.5",
            "per_execution_limit",
            # Record-only, unless an unrelated error (throttling, access) ended the call.
            "blocked" if codes & _BLOCKING_CODES else "pass",
            f"record what ends a {seconds}s execution "
            "(service limit or the SDK's 300s read timeout)",
            f"outcome={outcome} after {elapsed:.0f}s",
            config,
        )
    ]


def probe_scoped_caller(
    allowed: SessionFactory, denied: SessionFactory, config: Config
) -> list[Observation]:
    described: dict[str, Any] = {}
    try:
        with allowed() as session:
            allowed_result = _invoke(session.execute_code, "print('scoped-ok')")
            described = session.get_session()
    except ClientError as error:
        allowed_result = _sdk_error(error)
    try:
        with denied() as session:
            denied_result = _invoke(session.execute_code, "print('should-not-run')")
    except ClientError as error:
        denied_result = _sdk_error(error)
    # The SDK delivers a denial either as a ClientError or as a stream exception event.
    denied_codes = sorted(_codes(denied_result))
    access_denied = any("accessdenied" in code.lower() for code in denied_codes)
    ran = "should-not-run" in denied_result.output and not denied_result.failed
    return [
        Observation(
            "Q1.6",
            "scoped_role_can_execute",
            _gated(
                controls=not _service_errors(allowed_result) and "status" in described,
                ok="scoped-ok" in allowed_result.output and not allowed_result.failed,
            ),
            "the scoped caller role (4 session actions only) can start, execute, get, and stop",
            f"output={_markers(allowed_result, 'scoped-ok')} "
            f"session_status={described.get('status')}",
            config,
        ),
        Observation(
            "Q1.6",
            "invoke_denied_without_permission",
            _classify(ok=access_denied, conclusive=ran),
            "without InvokeCodeInterpreter, execution is denied",
            ",".join(denied_codes) or ("ran" if ran else "failed"),
            config,
        ),
    ]
