from __future__ import annotations

import json
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

from agentcore_code_interpreter_poc import probes
from agentcore_code_interpreter_poc.observations import Observation, append_observations
from tests.code_interpreter_fakes import FakeSession, client_error, err, event, factory_of, ok

CONFIG = {"identifier": "aws.codeinterpreter.v1"}


def _by_check(observations: list[Observation]) -> dict[str, Observation]:
    return {observation.check: observation for observation in observations}


def test_state_persists_within_and_not_across_sessions() -> None:
    def first(session: FakeSession, language: str, code: str) -> dict[str, object]:
        return ok("42\n") if "print" in code else ok("")

    def second(session: FakeSession, language: str, code: str) -> dict[str, object]:
        return err("NameError: name 'poc_marker' is not defined")

    observations = _by_check(
        probes.probe_state_persistence(
            factory_of(FakeSession(first), FakeSession(second)), CONFIG
        )
    )

    assert observations["state_persists_within_session"].status == "pass"
    assert observations["state_isolated_across_sessions"].status == "pass"
    assert observations["state_isolated_across_sessions"].question == "Q1.1"


def test_state_leak_across_sessions_is_a_failure() -> None:
    def leaky(session: FakeSession, language: str, code: str) -> dict[str, object]:
        return ok("42\n") if "print" in code else ok("")

    observations = _by_check(
        probes.probe_state_persistence(factory_of(FakeSession(leaky), FakeSession(leaky)), CONFIG)
    )

    assert observations["state_isolated_across_sessions"].status == "fail"


def test_unrelated_error_in_new_session_is_blocked_not_pass() -> None:
    def first(session: FakeSession, language: str, code: str) -> dict[str, object]:
        return ok("42\n") if "print" in code else ok("")

    def throttled(session: FakeSession, language: str, code: str) -> dict[str, object]:
        return err("ThrottlingException: slow down")

    observations = _by_check(
        probes.probe_state_persistence(
            factory_of(FakeSession(first), FakeSession(throttled)), CONFIG
        )
    )

    assert observations["state_isolated_across_sessions"].status == "blocked"


def test_languages_probe_covers_js_ts_shell_and_switch_back() -> None:
    def respond(session: FakeSession, language: str, code: str) -> dict[str, object]:
        if language == "shell":
            return ok("poc-shell-ok\naarch64\n")
        if language == "python":
            return ok("python-after-js\n")
        return ok("42\n")

    session = FakeSession(respond)
    observations = _by_check(probes.probe_languages(factory_of(session), CONFIG))

    assert {name: o.status for name, o in observations.items()} == {
        "javascript_executes": "pass",
        "typescript_executes": "pass",
        "shell_command_executes": "pass",
        "python_after_other_languages": "pass",
    }
    assert [language for language, _ in session.calls] == [
        "javascript",
        "typescript",
        "shell",
        "python",
    ]


def _files_respond(session: FakeSession, language: str, code: str) -> dict[str, object]:
    if "os.path.exists" in code:
        present = "poc_internal.txt" in session.files
        return ok("poc-present\n" if present else "poc-absent\n")
    if "poc_internal.txt" in code:
        session.files["poc_internal.txt"] = "internal-marker"
    if "poc_output.json" in code:
        session.files["poc_output.json"] = json.dumps({"sum_b": 6})
    return ok("written\n")


def _file_statuses(*sessions: FakeSession) -> dict[str, str]:
    observations = probes.probe_files(factory_of(*sessions), CONFIG)
    return {o.check: o.status for o in observations}


def test_files_probe_covers_internal_caller_and_binary_paths() -> None:
    observations = _by_check(
        probes.probe_files(
            factory_of(FakeSession(_files_respond), FakeSession(_files_respond)), CONFIG
        )
    )

    assert {name: o.status for name, o in observations.items()} == {
        "internal_file_persists_within_session": "pass",
        "internal_file_absent_in_new_session": "pass",
        "caller_upload_compute_download": "pass",
        "binary_round_trip": "pass",
    }
    assert all(o.question == "Q1.3" for o in observations.values())


def test_file_visible_in_new_session_is_a_failure() -> None:
    leaky = FakeSession(_files_respond)
    leaky.files["poc_internal.txt"] = "internal-marker"

    statuses = _file_statuses(FakeSession(_files_respond), leaky)

    assert statuses["internal_file_absent_in_new_session"] == "fail"


def test_failed_read_in_new_session_is_blocked_not_absent() -> None:
    def broken(session: FakeSession, language: str, code: str) -> dict[str, object]:
        return event("accessDeniedException")

    statuses = _file_statuses(FakeSession(_files_respond), FakeSession(broken))

    assert statuses["internal_file_absent_in_new_session"] == "blocked"


def test_failed_internal_write_blocks_both_internal_checks() -> None:
    def no_write(session: FakeSession, language: str, code: str) -> dict[str, object]:
        if "open('poc_internal.txt', 'w')" in code:
            return event("throttlingException")
        return _files_respond(session, language, code)

    statuses = _file_statuses(FakeSession(no_write), FakeSession(_files_respond))

    assert statuses["internal_file_persists_within_session"] == "blocked"
    assert statuses["internal_file_absent_in_new_session"] == "blocked"


class DownloadDenied(FakeSession):
    def download_file(self, path: str) -> str | bytes:
        raise client_error("AccessDeniedException")


def test_sdk_errors_in_file_calls_are_blocked_not_raised() -> None:
    statuses = _file_statuses(DownloadDenied(_files_respond), FakeSession(_files_respond))

    assert statuses == {
        "internal_file_persists_within_session": "blocked",
        "internal_file_absent_in_new_session": "blocked",
        "caller_upload_compute_download": "blocked",
        "binary_round_trip": "blocked",
    }


def test_setup_failure_blocks_state_checks() -> None:
    def throttled(session: FakeSession, language: str, code: str) -> dict[str, object]:
        return event("throttlingException")

    def isolated(session: FakeSession, language: str, code: str) -> dict[str, object]:
        return err("NameError: name 'poc_marker' is not defined")

    observations = _by_check(
        probes.probe_state_persistence(
            factory_of(FakeSession(throttled), FakeSession(isolated)), CONFIG
        )
    )

    assert observations["state_persists_within_session"].status == "blocked"
    assert observations["state_isolated_across_sessions"].status == "blocked"
    assert observations["state_persists_within_session"].observed == "event:throttlingException"


def test_name_error_for_another_name_is_blocked() -> None:
    def first(session: FakeSession, language: str, code: str) -> dict[str, object]:
        return ok("42\n") if "print" in code else ok("")

    def unrelated(session: FakeSession, language: str, code: str) -> dict[str, object]:
        return err("NameError: name 'np' is not defined")

    observations = _by_check(
        probes.probe_state_persistence(
            factory_of(FakeSession(first), FakeSession(unrelated)), CONFIG
        )
    )

    assert observations["state_isolated_across_sessions"].status == "blocked"


def test_language_service_errors_are_blocked_not_failed() -> None:
    class Denied(FakeSession):
        def execute_command(self, command: str) -> dict[str, object]:
            raise client_error("AccessDeniedException")

    def respond(session: FakeSession, language: str, code: str) -> dict[str, object]:
        if language == "javascript":
            return event("throttlingException")
        if language == "typescript":
            return err("SyntaxError: bad code")
        return ok("python-after-js\n")

    observations = _by_check(probes.probe_languages(factory_of(Denied(respond)), CONFIG))

    assert observations["javascript_executes"].status == "blocked"
    assert observations["typescript_executes"].status == "fail"
    assert observations["shell_command_executes"].status == "blocked"
    assert observations["shell_command_executes"].observed == "error:AccessDeniedException"
    assert "raw service text" not in json.dumps([o.as_dict() for o in observations.values()])


def test_append_observations_writes_one_json_line_each(tmp_path: Path) -> None:
    path = tmp_path / "raw" / "observations.jsonl"
    observation = Observation("Q1.1", "check", "pass", "expected", "observed", {"k": "v"})

    append_observations(path, [observation, observation])

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0]) == {
        "check": "check",
        "config": {"k": "v"},
        "expected": "expected",
        "observed": "observed",
        "question": "Q1.1",
        "status": "pass",
    }


def test_long_observed_output_is_clipped() -> None:
    assert probes.clip("a" * 1000).endswith("...[1000 chars]")
    assert probes.clip("short") == "short"


def test_run_still_raises_sdk_errors_for_probes_that_expect_them() -> None:
    class Denied(FakeSession):
        def execute_code(
            self, code: str, language: str = "python", clear_context: bool = False
        ) -> dict[str, object]:
            raise client_error("AccessDeniedException")

    with pytest.raises(ClientError):
        probes._run(Denied(_files_respond), "print('x')")


def test_setup_error_blocks_state_checks_even_when_later_output_looks_right() -> None:
    def setup_throttled(session: FakeSession, language: str, code: str) -> dict[str, object]:
        return event("throttlingException") if "= 41" in code else ok("42\n")

    def isolated(session: FakeSession, language: str, code: str) -> dict[str, object]:
        return err("NameError: name 'poc_marker' is not defined")

    observations = _by_check(
        probes.probe_state_persistence(
            factory_of(FakeSession(setup_throttled), FakeSession(isolated)), CONFIG
        )
    )

    assert observations["state_persists_within_session"].status == "blocked"
    assert observations["state_isolated_across_sessions"].status == "blocked"


def test_successful_output_that_mentions_name_error_is_not_isolation() -> None:
    def first(session: FakeSession, language: str, code: str) -> dict[str, object]:
        return ok("42\n") if "print" in code else ok("")

    def printed(session: FakeSession, language: str, code: str) -> dict[str, object]:
        return ok("NameError poc_marker\n")

    observations = _by_check(
        probes.probe_state_persistence(factory_of(FakeSession(first), FakeSession(printed)), CONFIG)
    )

    assert observations["state_isolated_across_sessions"].status != "pass"


class UploadThrottled(FakeSession):
    def upload_file(
        self, path: str, content: str | bytes, description: str = ""
    ) -> dict[str, object]:
        self.files[path] = content
        return event("throttlingException")


def test_upload_stream_error_blocks_upload_checks() -> None:
    statuses = _file_statuses(UploadThrottled(_files_respond), FakeSession(_files_respond))

    assert statuses["caller_upload_compute_download"] == "blocked"
    assert statuses["binary_round_trip"] == "blocked"


def test_ambiguous_missing_file_in_first_session_is_blocked_not_fail() -> None:
    def writes_nothing(session: FakeSession, language: str, code: str) -> dict[str, object]:
        return ok("written\n")

    statuses = _file_statuses(FakeSession(writes_nothing), FakeSession(_files_respond))

    assert statuses["internal_file_persists_within_session"] == "blocked"
    assert statuses["caller_upload_compute_download"] == "blocked"
