from __future__ import annotations

import json
from pathlib import Path

from agentcore_code_interpreter_poc import probes
from agentcore_code_interpreter_poc.observations import Observation, append_observations
from tests.code_interpreter_fakes import FakeSession, err, factory_of, ok

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


def test_files_probe_covers_internal_caller_and_binary_paths() -> None:
    def respond(session: FakeSession, language: str, code: str) -> dict[str, object]:
        if "poc_internal.txt" in code:
            session.files["poc_internal.txt"] = "internal-marker"
        if "poc_output.json" in code:
            session.files["poc_output.json"] = json.dumps({"sum_b": 6})
        return ok("written\n")

    observations = _by_check(
        probes.probe_files(factory_of(FakeSession(respond), FakeSession(respond)), CONFIG)
    )

    assert {name: o.status for name, o in observations.items()} == {
        "internal_file_persists_within_session": "pass",
        "internal_file_absent_in_new_session": "pass",
        "caller_upload_compute_download": "pass",
        "binary_round_trip": "pass",
    }
    assert all(o.question == "Q1.3" for o in observations.values())


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
