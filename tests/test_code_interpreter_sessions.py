from __future__ import annotations

import json
from typing import Any

import pytest
from botocore.exceptions import ClientError

from agentcore_code_interpreter_poc import sessions


class FakeInterpreter:
    instances: list[FakeInterpreter] = []

    def __init__(self, region: str, session: Any = None) -> None:
        self.region = region
        self.started: dict[str, object] = {}
        self.stopped = False
        self.stop_error: Exception | None = None
        FakeInterpreter.instances.append(self)

    def start(self, identifier: str, session_timeout_seconds: int) -> str:
        self.started = {"identifier": identifier, "timeout": session_timeout_seconds}
        return "session-1"

    def stop(self) -> bool:
        self.stopped = True
        if self.stop_error is not None:
            raise self.stop_error
        return True


@pytest.fixture(autouse=True)
def fake_interpreter(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeInterpreter.instances = []
    monkeypatch.setattr(sessions, "CodeInterpreter", FakeInterpreter)


def test_open_session_starts_with_identifier_and_timeout_and_stops() -> None:
    with sessions.open_session("ap-southeast-1", identifier="custom_ci", timeout_seconds=60):
        pass

    interpreter = FakeInterpreter.instances[0]
    assert interpreter.started == {"identifier": "custom_ci", "timeout": 60}
    assert interpreter.stopped is True


def test_open_session_stops_even_when_body_raises() -> None:
    with pytest.raises(RuntimeError), sessions.open_session("ap-southeast-1"):
        raise RuntimeError("probe failed")

    assert FakeInterpreter.instances[0].stopped is True


def _gone() -> ClientError:
    return ClientError(
        {"Error": {"Code": "ResourceNotFoundException", "Message": "gone"}},
        "StopCodeInterpreterSession",
    )


def test_stop_failure_is_suppressed_only_when_tolerated() -> None:
    with sessions.open_session("ap-southeast-1", tolerate_stop_errors=True) as interpreter:
        interpreter.stop_error = _gone()

    assert FakeInterpreter.instances[0].stopped is True


def test_stop_failure_raises_by_default() -> None:
    with pytest.raises(ClientError), sessions.open_session("ap-southeast-1") as interpreter:
        interpreter.stop_error = _gone()


def test_builtin_identifier_is_the_aws_default() -> None:
    assert sessions.BUILTIN_IDENTIFIER == "aws.codeinterpreter.v1"


class FakeSts:
    def __init__(self) -> None:
        self.kwargs: dict[str, Any] = {}

    def assume_role(self, **kwargs: Any) -> dict[str, Any]:
        self.kwargs = kwargs
        return {
            "Credentials": {
                "AccessKeyId": "example-access-key",
                "SecretAccessKey": "example-secret",
                "SessionToken": "example-session",
            }
        }


class FakeBaseSession:
    def __init__(self, sts: FakeSts) -> None:
        self.sts = sts

    def client(self, name: str, region_name: str) -> FakeSts:
        assert name == "sts"
        return self.sts


def test_assume_role_session_passes_session_policy_as_json() -> None:
    sts = FakeSts()
    policy = {"Version": "2012-10-17", "Statement": []}

    session = sessions.assume_role_session(
        "arn:aws:iam::123456789012:role/example",
        "ap-southeast-1",
        session_policy=policy,
        base_session=FakeBaseSession(sts),
    )

    assert sts.kwargs["RoleArn"] == "arn:aws:iam::123456789012:role/example"
    assert json.loads(sts.kwargs["Policy"]) == policy
    assert session.region_name == "ap-southeast-1"


def test_assume_role_session_omits_policy_when_not_given() -> None:
    sts = FakeSts()

    sessions.assume_role_session(
        "arn:aws:iam::123456789012:role/example",
        "ap-southeast-1",
        base_session=FakeBaseSession(sts),
    )

    assert "Policy" not in sts.kwargs
