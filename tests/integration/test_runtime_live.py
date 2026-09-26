"""Opt-in Phase 2 live gate. OPERATOR-RUN after apply, secret write, and gateway + tunnel start."""

from __future__ import annotations

import contextlib
import os
import re
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import boto3
import httpx
import pytest

from agentcore_code_interpreter_poc.observations import Observation, Status, append_observations
from agentcore_runtime_poc.inventory import container_inventory, load_inventory, new_resources
from agentcore_runtime_poc.invoke import (
    INVOKE_CLIENT_CONFIG,
    InvokeResult,
    RuntimeInvoker,
    new_session_id,
)
from scripts.container_inventory import BEFORE_PATH
from scripts.terraform_outputs import load_terraform_outputs

pytestmark = pytest.mark.integration

OBSERVATIONS = Path("evidence/raw/runtime-observations.jsonl")
_JWT_SHAPE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.")


def _status(ok: bool) -> Status:
    return "pass" if ok else "fail"


def _valid(result: InvokeResult, action: str, *required: str) -> bool:
    body = result.body
    return (
        result.status_code == 200
        and body.get("action") == action
        and body.get("session_id") == result.session_id
        and "error" not in body
        and bool(body.get("boot_id"))
        and all(key in body for key in required)
    )


@pytest.fixture(scope="module")
def outputs() -> dict[str, str]:
    if "AGENTCORE_POC_LIVE" not in os.environ:
        pytest.skip("set AGENTCORE_POC_LIVE=1 after apply, secret write, gateway and tunnel start")
    values = load_terraform_outputs(Path("infra/terraform/poc"))
    if not values.get("agent_runtime_arn"):
        pytest.fail("agent_runtime_arn is empty: apply with TF_VAR_deploy_runtime=true first")
    return values


@pytest.fixture(scope="module")
def invoker(outputs: dict[str, str]) -> RuntimeInvoker:
    client = boto3.client(
        "bedrock-agentcore", region_name=outputs["aws_region"], config=INVOKE_CLIENT_CONFIG
    )
    return RuntimeInvoker(client, outputs["agent_runtime_arn"])


@pytest.fixture
def opened(invoker: RuntimeInvoker) -> Iterator[list[str]]:
    sessions: list[str] = []
    yield sessions
    for session_id in sessions:
        with contextlib.suppress(Exception):
            invoker.stop(session_id)


def _session(opened: list[str]) -> str:
    session_id = new_session_id()
    opened.append(session_id)
    return session_id


def _config(outputs: dict[str, str]) -> dict[str, str]:
    return {
        "region": outputs["aws_region"],
        "runtime_id": outputs["agent_runtime_id"],
        "runtime_version": outputs.get("agent_runtime_version", ""),
    }


def _record(observations: list[Observation]) -> None:
    append_observations(OBSERVATIONS, observations)
    for observation in observations:
        print(observation.as_dict())
    failed = [o.as_dict() for o in observations if o.status != "pass"]
    assert not failed, failed


def _pick(body: dict[str, Any], *keys: str) -> str:
    return str({key: body.get(key) for key in keys})


def test_q2_1_runtime_reaches_external_gateway(
    invoker: RuntimeInvoker, opened: list[str], outputs: dict[str, str]
) -> None:
    result = invoker.invoke({"action": "probe_egress"}, _session(opened))
    status: Status = (
        _status(result.body.get("healthz_status") == 200)
        if _valid(result, "probe_egress", "healthz_status")
        else "blocked"
    )
    _record(
        [
            Observation(
                "Q2.1",
                "egress_to_external_https",
                status,
                "the tunnel URL's /healthz returns 200 from inside Runtime (PUBLIC network mode)",
                _pick(result.body, "healthz_status", "error"),
                _config(outputs),
            )
        ]
    )


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_q2_2_round_trip_through_gateway(
    provider: str, invoker: RuntimeInvoker, opened: list[str], outputs: dict[str, str]
) -> None:
    result = invoker.invoke(
        {"action": "chat", "provider": provider, "prompt": "Reply with the single word: pong"},
        _session(opened),
    )
    body = result.body
    text = str(body.get("text") or "")
    # The invocation itself is the control; token or gateway errors are round-trip failures.
    invoked = (
        result.status_code == 200
        and body.get("action") == "chat"
        and body.get("session_id") == result.session_id
    )
    round_trip_ok = (
        _valid(result, "chat", "text") and body.get("gateway_status") == 200 and bool(text.strip())
    )
    _record(
        [
            Observation(
                "Q2.2",
                f"{provider}_round_trip",
                _status(round_trip_ok) if invoked else "blocked",
                "Runtime -> Entra token -> gateway -> provider -> back to caller",
                f"gateway_status={body.get('gateway_status')} text_chars={len(text)} "
                f"timings_ms={body.get('timings_ms')} client_ms={result.elapsed_ms} "
                f"error={body.get('error')}",
                _config(outputs),
            )
        ]
    )


def test_q2_2_gateway_rejects_unauthenticated_call_from_runtime(
    invoker: RuntimeInvoker, opened: list[str], outputs: dict[str, str]
) -> None:
    result = invoker.invoke(
        {"action": "chat_unauthenticated", "provider": "openai", "prompt": "ping"},
        _session(opened),
    )
    status: Status = (
        _status(result.body.get("gateway_status") == 401)
        if _valid(result, "chat_unauthenticated", "gateway_status")
        else "blocked"
    )
    _record(
        [
            Observation(
                "Q2.2",
                "unauthenticated_call_rejected",
                status,
                "a gateway call without a JWT is rejected with 401",
                _pick(result.body, "gateway_status", "error"),
                _config(outputs),
            )
        ]
    )


def test_q2_2_gateway_rejects_bad_tokens_directly(outputs: dict[str, str]) -> None:
    url = os.environ["GATEWAY_BASE_URL"].rstrip("/") + "/openai/v1/chat/completions"
    body = {"model": "any", "messages": []}
    no_token = httpx.post(url, json=body, timeout=15).status_code
    garbage = httpx.post(
        url, json=body, headers={"Authorization": "Bearer not-a-real-token"}, timeout=15
    ).status_code
    _record(
        [
            Observation(
                "Q2.2",
                "direct_bad_tokens_rejected",
                _status(no_token == 401 and garbage == 401),
                "missing and malformed tokens get 401 at the public gateway URL",
                f"no_token={no_token} garbage={garbage}",
                _config(outputs),
            )
        ]
    )


def test_q2_3_isolation_is_per_session(
    invoker: RuntimeInvoker, opened: list[str], outputs: dict[str, str]
) -> None:
    first, second = _session(opened), _session(opened)
    marker = uuid.uuid4().hex
    set_result = invoker.invoke({"action": "set_marker", "marker": marker}, first)
    same = invoker.invoke({"action": "get_marker"}, first)
    other = invoker.invoke({"action": "get_marker"}, second)
    controls_ok = (
        _valid(set_result, "set_marker", "marker")
        and set_result.body["marker"] == marker
        and _valid(same, "get_marker", "marker")
        and _valid(other, "get_marker", "marker")
    )
    same_ok = same.body.get("marker") == marker and (
        same.body.get("boot_id") == set_result.body.get("boot_id")
    )
    other_ok = other.body.get("marker") is None and (
        other.body.get("boot_id") != same.body.get("boot_id")
    )
    _record(
        [
            Observation(
                "Q2.3",
                "state_persists_within_session",
                _status(same_ok) if controls_ok else "blocked",
                "same runtimeSessionId reaches the same process and sees the marker",
                f"controls_ok={controls_ok} same_boot="
                f"{same.body.get('boot_id') == set_result.body.get('boot_id')} "
                f"marker_seen={same.body.get('marker') == marker}",
                _config(outputs),
            ),
            Observation(
                "Q2.3",
                "state_isolated_across_sessions",
                _status(other_ok) if controls_ok else "blocked",
                "a different runtimeSessionId gets a different environment and no marker",
                f"controls_ok={controls_ok} different_boot="
                f"{other.body.get('boot_id') != same.body.get('boot_id')} "
                f"marker_present={other.body.get('marker') is not None}",
                _config(outputs),
            ),
        ]
    )


def test_q2_4_cold_warm_and_token_cache(
    invoker: RuntimeInvoker, opened: list[str], outputs: dict[str, str]
) -> None:
    session_id = _session(opened)
    cold = invoker.invoke({"action": "whoami"}, session_id)
    warm = invoker.invoke({"action": "whoami"}, session_id)
    chat = {"action": "chat", "provider": "anthropic", "prompt": "Reply ok"}
    first_chat = invoker.invoke(chat, session_id)
    second_chat = invoker.invoke(chat, session_id)
    whoami_ok = _valid(cold, "whoami") and _valid(warm, "whoami")
    chats_ok = _valid(first_chat, "chat", "token_cached") and _valid(
        second_chat, "chat", "token_cached"
    )
    first_timings = first_chat.body.get("timings_ms") or {}
    second_timings = second_chat.body.get("timings_ms") or {}
    _record(
        [
            Observation(
                "Q2.4",
                "cold_vs_warm_latency",
                _status(cold.body["boot_id"] == warm.body["boot_id"]) if whoami_ok else "blocked",
                "record cold (first call in a new session) vs warm client latency",
                f"cold_ms={cold.elapsed_ms} warm_ms={warm.elapsed_ms} "
                f"uptime_at_first_call_s={cold.body.get('uptime_s')}",
                _config(outputs),
            ),
            Observation(
                "Q2.4",
                "token_cached_across_invocations",
                _status(second_chat.body["token_cached"] is True) if chats_ok else "blocked",
                "the second call in a warm session reuses the MSAL-cached token",
                f"gateway_statuses={first_chat.body.get('gateway_status')},"
                f"{second_chat.body.get('gateway_status')} "
                f"first_token_ms={first_timings.get('token')} "
                f"second_token_ms={second_timings.get('token')} "
                f"gateway_ms={second_timings.get('gateway')}",
                _config(outputs),
            ),
        ]
    )


def test_q2_4_idle_timeout_reclaims_session(
    invoker: RuntimeInvoker, opened: list[str], outputs: dict[str, str]
) -> None:
    if "AGENTCORE_POC_SLOW" not in os.environ:
        pytest.skip("set AGENTCORE_POC_SLOW=1 to run the idle-timeout probe (~3 minutes)")
    idle = int(outputs["runtime_idle_session_timeout_seconds"])
    session_id = _session(opened)
    before = invoker.invoke({"action": "set_marker", "marker": "idle-check"}, session_id)
    time.sleep(idle + 45)
    after = invoker.invoke({"action": "get_marker"}, session_id)
    controls_ok = (
        _valid(before, "set_marker", "marker")
        and before.body["marker"] == "idle-check"
        and _valid(after, "get_marker", "marker")
    )
    reclaimed = after.body.get("boot_id") != before.body.get("boot_id") and (
        after.body.get("marker") is None
    )
    _record(
        [
            Observation(
                "Q2.4",
                "idle_session_reclaimed",
                _status(reclaimed) if controls_ok else "blocked",
                f"after {idle + 45}s idle (configured timeout {idle}s) the same session id "
                "gets a fresh environment",
                f"controls_ok={controls_ok} "
                f"same_boot={after.body.get('boot_id') == before.body.get('boot_id')} "
                f"marker_present={after.body.get('marker') is not None}",
                _config(outputs),
            )
        ]
    )


def _log_messages(logs: Any, prefix: str, start_ms: int) -> tuple[list[str], list[str]]:
    groups = [
        group["logGroupName"]
        for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=prefix)
        for group in page.get("logGroups", [])
    ]
    messages = [
        event["message"]
        for group in groups
        for page in logs.get_paginator("filter_log_events").paginate(
            logGroupName=group, startTime=start_ms
        )
        for event in page.get("events", [])
    ]
    return groups, messages


def test_q2_5_logs_hold_no_tokens_secrets_or_prompts(
    invoker: RuntimeInvoker, opened: list[str], outputs: dict[str, str]
) -> None:
    marker = f"prompt-marker-{uuid.uuid4().hex}"
    session_id = _session(opened)
    start_ms = int(time.time() * 1000) - 60_000
    reply = uuid.uuid4().hex
    # Asking for upper case makes the completion differ from the prompt, so the two leaks differ.
    chat = invoker.invoke(
        {
            "action": "chat",
            "provider": "anthropic",
            "prompt": f"Ignore {marker}. Reply with only this text in upper case: {reply}",
        },
        session_id,
    )
    denied = invoker.invoke(
        {"action": "chat_unauthenticated", "provider": "openai", "prompt": marker}, session_id
    )
    logs = boto3.client("logs", region_name=outputs["aws_region"])
    prefix = f"/aws/bedrock-agentcore/runtimes/{outputs['agent_runtime_id']}"
    groups: list[str] = []
    messages: list[str] = []
    correlated: list[str] = []
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        groups, messages = _log_messages(logs, prefix, start_ms)
        correlated = [m for m in messages if f"session={session_id}" in m]
        if any("action=chat " in m for m in correlated) and any(
            "action=chat_unauthenticated" in m for m in correlated
        ):
            break
        time.sleep(15)
    secret = os.environ.get("GATEWAY_CALLER_CLIENT_SECRET", "")
    completion = str(chat.body.get("text") or "")
    checks = {
        "jwt": any(_JWT_SHAPE.search(message) for message in messages),
        "prompt": any(marker in message for message in messages),
        "client_secret": bool(secret) and any(secret in message for message in messages),
        "completion": bool(completion) and any(completion in m for m in messages),
    }
    leaks = [name for name, hit in checks.items() if hit]
    evidence_ok = (
        bool(secret)
        and len(completion.strip()) >= 12
        and _valid(chat, "chat")
        and chat.body.get("gateway_status") == 200
        and _valid(denied, "chat_unauthenticated")
        and denied.body.get("gateway_status") == 401
        and any("action=chat " in m for m in correlated)
        and any("action=chat_unauthenticated" in m for m in correlated)
    )
    _record(
        [
            Observation(
                "Q2.5",
                "runtime_logs_redacted",
                _status(not leaks) if evidence_ok else "blocked",
                "agent log lines for this session reach CloudWatch (success and failure paths) "
                "and no log holds a JWT, the client secret, the prompt, or the completion",
                f"log_groups={groups} events={len(messages)} correlated={len(correlated)} "
                f"secret_canary={bool(secret)} completion_chars={len(completion.strip())} "
                f"leaks={leaks}",
                _config(outputs),
            )
        ]
    )


def test_q2_6_no_container_resources_created(outputs: dict[str, str]) -> None:
    if not BEFORE_PATH.exists():
        pytest.fail(
            f"{BEFORE_PATH} missing: run python -m scripts.container_inventory before apply"
        )
    region = outputs["aws_region"]
    after = container_inventory(
        boto3.client("ecr", region_name=region), boto3.client("codebuild", region_name=region)
    )
    created = new_resources(load_inventory(BEFORE_PATH), after)
    _record(
        [
            Observation(
                "Q2.6",
                "no_ecr_or_codebuild_created",
                _status(not any(created.values())),
                "no ECR repository or CodeBuild project appeared between the pre-apply snapshot "
                "and now",
                f"created={created} totals={ {key: len(value) for key, value in after.items()} }",
                _config(outputs),
            )
        ]
    )
