"""Invoke the deployed Runtime agent with the caller's own AWS credentials (SigV4)."""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from botocore.config import Config  # type: ignore[import-untyped]

# botocore's default 60 s read timeout would cut off the 110 s in-flight probe (Task 10), and a
# retry would replay a side-effecting invocation (set_marker, chat).
INVOKE_CLIENT_CONFIG = Config(read_timeout=180, retries={"total_max_attempts": 1})


def new_session_id() -> str:
    return f"poc-{uuid.uuid4().hex}"


@dataclass(frozen=True)
class InvokeResult:
    status_code: int
    body: dict[str, Any]
    elapsed_ms: float
    session_id: str


class RuntimeInvoker:
    def __init__(
        self,
        client: Any,
        agent_runtime_arn: str,
        clock: Callable[[], float] = time.perf_counter,
    ) -> None:
        self._client = client
        self._arn = agent_runtime_arn
        self._clock = clock

    def invoke(self, payload: Mapping[str, Any], session_id: str) -> InvokeResult:
        started = self._clock()
        response = self._client.invoke_agent_runtime(
            agentRuntimeArn=self._arn,
            runtimeSessionId=session_id,
            qualifier="DEFAULT",
            contentType="application/json",
            accept="application/json",
            payload=json.dumps(dict(payload)).encode("utf-8"),
        )
        raw = response["response"].read()
        elapsed_ms = round((self._clock() - started) * 1000, 1)
        try:
            parsed: Any = json.loads(raw) if raw else {}
        except ValueError:
            # For example text/event-stream: report it rather than lose the rest of the result.
            parsed = {"error": "non_json_body", "content_type": response.get("contentType")}
        body = parsed if isinstance(parsed, dict) else {"value": parsed}
        return InvokeResult(int(response.get("statusCode", 200)), body, elapsed_ms, session_id)

    def stop(self, session_id: str) -> None:
        self._client.stop_runtime_session(
            agentRuntimeArn=self._arn, runtimeSessionId=session_id, qualifier="DEFAULT"
        )
