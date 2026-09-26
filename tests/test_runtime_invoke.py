from __future__ import annotations

import io
import json
from typing import Any

from agentcore_runtime_poc.invoke import RuntimeInvoker, new_session_id

ARN = "arn:aws:bedrock-agentcore:ap-southeast-1:123456789012:runtime/ci_rt_poc_agent-abc"


class FakeClient:
    def __init__(self, raw: bytes, status: int = 200) -> None:
        self.raw = raw
        self.status = status
        self.invoke_kwargs: dict[str, Any] = {}
        self.stop_kwargs: dict[str, Any] = {}

    def invoke_agent_runtime(self, **kwargs: Any) -> dict[str, Any]:
        self.invoke_kwargs = kwargs
        return {"response": io.BytesIO(self.raw), "statusCode": self.status}

    def stop_runtime_session(self, **kwargs: Any) -> dict[str, Any]:
        self.stop_kwargs = kwargs
        return {}


def test_session_ids_are_long_enough_and_unique() -> None:
    first, second = new_session_id(), new_session_id()

    assert len(first) >= 33
    assert first != second


def test_invoke_sends_json_payload_and_parses_body() -> None:
    client = FakeClient(b'{"boot_id": "b1"}')
    ticks = iter([1.0, 1.25])
    invoker = RuntimeInvoker(client, ARN, clock=lambda: next(ticks))

    result = invoker.invoke({"action": "whoami"}, "s" * 36)

    assert result.body == {"boot_id": "b1"}
    assert result.status_code == 200
    assert result.elapsed_ms == 250.0
    assert client.invoke_kwargs["agentRuntimeArn"] == ARN
    assert client.invoke_kwargs["runtimeSessionId"] == "s" * 36
    assert client.invoke_kwargs["qualifier"] == "DEFAULT"
    assert client.invoke_kwargs["contentType"] == "application/json"
    assert json.loads(client.invoke_kwargs["payload"]) == {"action": "whoami"}


def test_empty_and_non_object_bodies() -> None:
    assert RuntimeInvoker(FakeClient(b""), ARN).invoke({}, "s" * 36).body == {}
    assert RuntimeInvoker(FakeClient(b"[1]"), ARN).invoke({}, "s" * 36).body == {"value": [1]}


def test_stop_targets_the_session() -> None:
    client = FakeClient(b"{}")

    RuntimeInvoker(client, ARN).stop("s" * 36)

    assert client.stop_kwargs == {
        "agentRuntimeArn": ARN,
        "runtimeSessionId": "s" * 36,
        "qualifier": "DEFAULT",
    }


def test_non_json_body_is_reported_not_raised() -> None:
    class EventStream(FakeClient):
        def invoke_agent_runtime(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "response": io.BytesIO(b"data: partial\n\n"),
                "statusCode": 200,
                "contentType": "text/event-stream",
            }

    result = RuntimeInvoker(EventStream(b""), ARN).invoke({"action": "whoami"}, "s" * 36)

    assert result.body == {"error": "non_json_body", "content_type": "text/event-stream"}


def test_invoke_client_config_never_retries_and_outlasts_the_in_flight_probe() -> None:
    from agentcore_runtime_poc.invoke import INVOKE_CLIENT_CONFIG

    assert INVOKE_CLIENT_CONFIG.retries == {"total_max_attempts": 1}
    assert INVOKE_CLIENT_CONFIG.read_timeout >= 180
