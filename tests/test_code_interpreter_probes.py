from __future__ import annotations

import contextlib
import json
from collections.abc import Callable
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
        probes.probe_state_persistence(factory_of(FakeSession(first), FakeSession(second)), CONFIG)
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


@pytest.mark.parametrize(
    ("stdout", "expected_reachable", "status"),
    [
        ("status 200\n", True, "pass"),
        ("blocked URLError\n", False, "pass"),
        ("status 200\n", False, "fail"),
        ("status 403\n", True, "pass"),
        ("Traceback (most recent call last)\n", True, "blocked"),
    ],
)
def test_egress_compares_reachability_with_expectation(
    stdout: str, expected_reachable: bool, status: str
) -> None:
    session = FakeSession(lambda s, language, code: ok(stdout))

    [observation] = probes.probe_egress(
        factory_of(session), CONFIG, expected_reachable=expected_reachable
    )

    assert observation.question == "Q1.4"
    assert observation.status == status


def test_failure_modes_record_each_behavior() -> None:
    def respond(session: FakeSession, language: str, code: str) -> dict[str, object]:
        if "def broken" in code:
            return err("SyntaxError: invalid syntax")
        if "poc-boom" in code:
            return err("ValueError: poc-boom")
        if "2_000_000" in code:
            return ok("a" * 1000)
        if "time.sleep" in code:
            return ok("slept\n")
        return ok("allocated 1073741824\n")

    ticks = iter([100.0, 161.5])
    observations = _by_check(
        probes.probe_failure_modes(
            factory_of(FakeSession(respond)), CONFIG, clock=lambda: next(ticks)
        )
    )

    assert observations["syntax_error_surfaces"].status == "pass"
    assert observations["exception_surfaces"].status == "pass"
    assert observations["large_output"].observed == "returned 1000 of 2000000 chars"
    assert observations["sixty_second_execution"].status == "pass"
    assert "61.5s" in observations["sixty_second_execution"].observed
    assert "allocated" in observations["one_gib_allocation"].observed
    assert all(o.question == "Q1.5" for o in observations.values())


def test_session_ttl_expires_when_idle_and_when_active() -> None:
    clock = {"now": 0.0}

    def respond(session: FakeSession, language: str, code: str) -> dict[str, object]:
        if clock["now"] > 60:
            raise client_error("ResourceNotFoundException")
        return ok("alive\n")

    def open_with_timeout(ttl: int) -> contextlib.AbstractContextManager[FakeSession]:
        assert ttl == 60
        clock["now"] = 0.0
        return contextlib.nullcontext(FakeSession(respond))

    def sleep(seconds: float) -> None:
        clock["now"] += seconds

    observations = _by_check(probes.probe_session_ttl(open_with_timeout, CONFIG, sleep=sleep))

    assert observations["idle_session_ends_at_ttl"].status == "pass"
    assert observations["active_session_ends_at_ttl"].status == "pass"
    assert "ResourceNotFoundException" in observations["idle_session_ends_at_ttl"].observed


def test_session_ttl_throttling_after_wait_is_blocked() -> None:
    clock = {"now": 0.0}

    def respond(session: FakeSession, language: str, code: str) -> dict[str, object]:
        if clock["now"] > 60:
            raise client_error("ThrottlingException")
        return ok("alive\n")

    def open_with_timeout(ttl: int) -> contextlib.AbstractContextManager[FakeSession]:
        clock["now"] = 0.0
        return contextlib.nullcontext(FakeSession(respond))

    def sleep(seconds: float) -> None:
        clock["now"] += seconds

    observations = _by_check(probes.probe_session_ttl(open_with_timeout, CONFIG, sleep=sleep))

    assert observations["idle_session_ends_at_ttl"].status == "blocked"


def test_session_ttl_extended_by_activity_is_reported_as_fail() -> None:
    def open_with_timeout(ttl: int) -> contextlib.AbstractContextManager[FakeSession]:
        return contextlib.nullcontext(FakeSession(lambda s, language, code: ok("alive\n")))

    observations = _by_check(
        probes.probe_session_ttl(open_with_timeout, CONFIG, sleep=lambda seconds: None)
    )

    assert observations["active_session_ends_at_ttl"].status == "fail"


def test_scoped_caller_allowed_runs_and_denied_invoke_is_access_denied() -> None:
    allowed = FakeSession(lambda s, language, code: ok("scoped-ok\n"))

    def deny(session: FakeSession, language: str, code: str) -> dict[str, object]:
        raise client_error("accessDeniedException")

    observations = _by_check(
        probes.probe_scoped_caller(factory_of(allowed), factory_of(FakeSession(deny)), CONFIG)
    )

    assert observations["scoped_role_can_execute"].status == "pass"
    assert "session_status=READY" in observations["scoped_role_can_execute"].observed
    assert ("get_session", "") in allowed.calls
    assert observations["invoke_denied_without_permission"].status == "pass"
    assert observations["invoke_denied_without_permission"].observed == "accessDeniedException"


def test_scoped_caller_denied_session_that_runs_is_a_failure() -> None:
    runs = FakeSession(lambda s, language, code: ok("should-not-run\n"))

    observations = _by_check(probes.probe_scoped_caller(factory_of(runs), factory_of(runs), CONFIG))

    assert observations["invoke_denied_without_permission"].status == "fail"


def test_execution_limit_records_completion_or_client_timeout() -> None:
    ticks = iter([0.0, 600.4])
    done = probes.probe_execution_limit(
        factory_of(FakeSession(lambda s, language, code: ok("slept\n"))),
        CONFIG,
        clock=lambda: next(ticks),
    )
    assert done[0].observed == "outcome=completed after 600s"

    def time_out(session: FakeSession, language: str, code: str) -> dict[str, object]:
        raise TimeoutError("read timeout")

    ticks = iter([0.0, 300.2])
    timed_out = probes.probe_execution_limit(
        factory_of(FakeSession(time_out)), CONFIG, clock=lambda: next(ticks)
    )
    assert timed_out[0].observed == "outcome=raised:TimeoutError after 300s"


def test_session_policy_excludes_invoke() -> None:
    actions = probes.INVOKE_EXCLUDED_SESSION_POLICY["Statement"][0]["Action"]

    assert "bedrock-agentcore:InvokeCodeInterpreter" not in actions
    assert "bedrock-agentcore:StartCodeInterpreterSession" in actions


def test_egress_sdk_error_is_blocked() -> None:
    def throttle(session: FakeSession, language: str, code: str) -> dict[str, object]:
        raise client_error("ThrottlingException")

    [observation] = probes.probe_egress(
        factory_of(FakeSession(throttle)), CONFIG, expected_reachable=True
    )

    assert observation.status == "blocked"
    assert observation.observed == "error:ThrottlingException"


def test_failure_modes_service_errors_are_blocked() -> None:
    session = FakeSession(lambda s, language, code: event("throttlingException"))

    observations = probes.probe_failure_modes(factory_of(session), CONFIG, clock=lambda: 0.0)

    assert {o.status for o in observations} == {"blocked"}
    assert all("raw service text" not in o.observed for o in observations)


def test_scoped_caller_unrelated_denied_error_is_blocked() -> None:
    allowed = FakeSession(lambda s, language, code: ok("scoped-ok\n"))

    def throttle(session: FakeSession, language: str, code: str) -> dict[str, object]:
        raise client_error("ThrottlingException")

    observations = _by_check(
        probes.probe_scoped_caller(factory_of(allowed), factory_of(FakeSession(throttle)), CONFIG)
    )

    assert observations["invoke_denied_without_permission"].status == "blocked"


@pytest.mark.parametrize(
    "response",
    [{"stream": []}, event("throttlingException")],
)
def test_egress_expected_blocked_but_inconclusive_is_blocked(response: dict[str, object]) -> None:
    [observation] = probes.probe_egress(
        factory_of(FakeSession(lambda s, language, code: response)),
        CONFIG,
        expected_reachable=False,
    )

    assert observation.status == "blocked"


def test_failure_modes_expected_text_with_service_event_is_blocked() -> None:
    def respond(session: FakeSession, language: str, code: str) -> dict[str, object]:
        mixed = err("SyntaxError: invalid syntax ValueError: poc-boom")
        mixed["stream"].append({"throttlingException": {"message": "raw service text"}})  # type: ignore[attr-defined]
        return mixed

    observations = _by_check(
        probes.probe_failure_modes(factory_of(FakeSession(respond)), CONFIG, clock=lambda: 0.0)
    )

    assert observations["syntax_error_surfaces"].status == "blocked"
    assert observations["exception_surfaces"].status == "blocked"


def test_failure_modes_never_record_raw_failed_text() -> None:
    def respond(session: FakeSession, language: str, code: str) -> dict[str, object]:
        return {
            "stream": [
                {
                    "result": {
                        "isError": True,
                        "content": [{"type": "text", "text": "SyntaxError poc-boom secret-value"}],
                    }
                }
            ]
        }

    observations = probes.probe_failure_modes(
        factory_of(FakeSession(respond)), CONFIG, clock=lambda: 0.0
    )

    assert all("secret-value" not in o.observed for o in observations)


def _ttl_run(respond: Callable[[dict[str, float]], dict[str, object]]) -> dict[str, Observation]:
    clock = {"now": 0.0}

    def open_with_timeout(ttl: int) -> contextlib.AbstractContextManager[FakeSession]:
        clock["now"] = 0.0
        return contextlib.nullcontext(FakeSession(lambda s, language, code: respond(clock)))

    def sleep(seconds: float) -> None:
        clock["now"] += seconds

    return _by_check(probes.probe_session_ttl(open_with_timeout, CONFIG, sleep=sleep))


def test_session_ttl_unrecognized_error_after_wait_is_blocked() -> None:
    def respond(clock: dict[str, float]) -> dict[str, object]:
        if clock["now"] > 60:
            raise client_error("ValidationException")
        return ok("alive\n")

    observations = _ttl_run(respond)

    assert observations["idle_session_ends_at_ttl"].status == "blocked"
    assert observations["active_session_ends_at_ttl"].status == "blocked"


def test_session_ttl_failed_keepalive_before_ttl_is_blocked() -> None:
    def respond(clock: dict[str, float]) -> dict[str, object]:
        if clock["now"] > 60 or clock["now"] == 30:
            raise client_error("ResourceNotFoundException")
        return ok("alive\n")

    observations = _ttl_run(respond)

    assert observations["active_session_ends_at_ttl"].status == "blocked"
    assert "keepalives=" in observations["active_session_ends_at_ttl"].observed


def test_scoped_caller_denial_as_stream_event_is_pass() -> None:
    allowed = FakeSession(lambda s, language, code: ok("scoped-ok\n"))
    denied = FakeSession(lambda s, language, code: event("accessDeniedException"))

    observations = _by_check(
        probes.probe_scoped_caller(factory_of(allowed), factory_of(denied), CONFIG)
    )

    assert observations["invoke_denied_without_permission"].status == "pass"


def test_scoped_caller_allowed_path_error_is_blocked() -> None:
    def throttle(session: FakeSession, language: str, code: str) -> dict[str, object]:
        raise client_error("ThrottlingException")

    denied = FakeSession(lambda s, language, code: event("accessDeniedException"))

    observations = _by_check(
        probes.probe_scoped_caller(factory_of(FakeSession(throttle)), factory_of(denied), CONFIG)
    )

    assert observations["scoped_role_can_execute"].status == "blocked"


def test_execution_limit_unrelated_error_is_blocked() -> None:
    def throttle(session: FakeSession, language: str, code: str) -> dict[str, object]:
        raise client_error("ThrottlingException")

    [observation] = probes.probe_execution_limit(
        factory_of(FakeSession(throttle)), CONFIG, clock=lambda: 0.0
    )

    assert observation.status == "blocked"
    assert "ThrottlingException" in observation.observed
