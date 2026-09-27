from __future__ import annotations

import asyncio
import base64
import json
import subprocess
import sys
import threading
import time
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
from botocore.exceptions import ClientError

from agentcore_platform_poc.probe_agent import entrypoint, probes
from agentcore_platform_poc.probe_agent.probes import header_summary, safe_claims

GRANT = "X-Amzn-Bedrock-AgentCore-Runtime-Custom-Grant"


def _jwt(claims: dict[str, object]) -> str:
    part = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJub25lIn0.{part}.sig"


def test_header_summary_reports_names_and_grant_length_only() -> None:
    summary = header_summary({GRANT: "abc.def.ghi", "Authorization": "Bearer x", "X-Other": "v"})
    assert summary == {"names": sorted([GRANT, "Authorization", "X-Other"]), "grant_length": 11}
    assert "abc.def.ghi" not in json.dumps(summary)


def test_safe_claims_keeps_only_non_secret_claims() -> None:
    token = _jwt(
        {"aud": "a", "azp": "b", "roles": ["r"], "ver": "2.0", "exp": 1, "oid": "x", "uti": "y"}
    )
    assert safe_claims(token) == {"aud": "a", "azp": "b", "roles": ["r"], "ver": "2.0", "exp": 1}


def test_identity_probe_returns_allowlisted_claims(monkeypatch: Any) -> None:
    class FakeSource:
        def __init__(self, provider_name: str, scope: str, region: str) -> None:
            assert (provider_name, region) == ("provider", "ap-southeast-1")
            self.scope = scope

        async def get(self) -> str:
            return _jwt({"aud": self.scope, "roles": ["r"], "secret": "hidden"})

    module = ModuleType("agentcore_platform_poc.agent_platform.tokens")
    module.IdentityTokenSource = FakeSource  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setenv("IDENTITY_PROVIDER", "provider")
    monkeypatch.setenv("POC_REGION", "ap-southeast-1")
    result = asyncio.run(probes.identity_probe(["hub", "gateway"]))
    assert result == {
        "hub": {"aud": "hub", "roles": ["r"]},
        "gateway": {"aud": "gateway", "roles": ["r"]},
    }


def test_s3_denied_probe_reports_both_denials(monkeypatch: Any) -> None:
    class FakeS3:
        def get_object(self, **_: Any) -> None:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetObject")

        def put_object(self, **_: Any) -> None:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "PutObject")

    monkeypatch.setattr("boto3.client", lambda *args, **kwargs: FakeS3())
    monkeypatch.setenv("POC_REGION", "ap-southeast-1")
    monkeypatch.setenv("WORKSPACE_BUCKET", "example-workspace")
    assert probes.s3_denied_probe() == {"get": "AccessDenied", "put": "AccessDenied"}


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("['get:AccessDenied', 'put:AccessDenied']", True),
        ("['get:NoCredentialsError', 'put:NoCredentialsError']", True),
        ("['get:allowed', 'put:AccessDenied']", False),
    ],
)
def test_sandbox_probe_checks_bytes_and_both_failures(
    monkeypatch: Any, output: str, expected: bool
) -> None:
    class FakeInterpreter:
        def __init__(self, region: str) -> None:
            assert region == "ap-southeast-1"

        def start(self, *, identifier: str) -> None:
            assert identifier == "sandbox-id"

        def upload_file(self, name: str, data: bytes) -> None:
            assert name == "probe.png" and data == probes.PNG_1X1

        def download_file(self, name: str) -> bytes:
            assert name == "probe.png"
            return probes.PNG_1X1

        def execute_code(self, script: str) -> dict[str, Any]:
            assert "get_object" in script and "put_object" in script
            return {"stream": [{"result": {"structuredContent": {
                "stdout": output
            }}}]}

        def stop(self) -> None:
            pass

    monkeypatch.setattr(
        "bedrock_agentcore.tools.code_interpreter_client.CodeInterpreter", FakeInterpreter
    )
    monkeypatch.setenv("POC_REGION", "ap-southeast-1")
    monkeypatch.setenv("CODE_INTERPRETER_ID", "sandbox-id")
    monkeypatch.setenv("WORKSPACE_BUCKET", "example-workspace")
    result = probes.sandbox_probe()
    assert result["png_round_trip"] is True
    assert result["s3_call_failed"] is expected


def test_fuse_probe_requires_a_real_mount_with_seeded_file(monkeypatch: Any) -> None:
    closed: list[bool] = []

    class FakeFS:
        async def write(self, path: str, data: bytes) -> None:
            assert path == "/data/probe.txt" and data == b"probe"

    class FakeWorkspace:
        def __init__(self, resources: dict[str, Any], *, mode: str) -> None:
            assert list(resources) == ["/data"] and mode == "write"
            self.fs = FakeFS()

        def add_fuse_mount(self, prefix: str) -> str:
            assert prefix == "/data"
            return "/probe-mount"

        def remove_fuse_mount(self, prefix: str) -> None:
            assert prefix == "/data"

        async def close(self) -> None:
            closed.append(True)

    mirage = ModuleType("mirage")
    mirage.MountMode = SimpleNamespace(WRITE="write")  # type: ignore[attr-defined]
    mirage.RAMResource = lambda: object()  # type: ignore[attr-defined]
    mirage.Workspace = FakeWorkspace  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "mirage", mirage)
    monkeypatch.setattr(
        probes.shutil, "disk_usage", lambda path: SimpleNamespace(total=100, free=50)
    )
    monkeypatch.setattr(probes.os.path, "exists", lambda path: False)
    monkeypatch.setattr(probes.os.path, "ismount", lambda path: True)
    monkeypatch.setattr(probes.os, "listdir", lambda path: ["probe.txt"])
    assert asyncio.run(probes.fuse_probe())["mount"] == "ok"

    monkeypatch.setattr(probes.os.path, "ismount", lambda path: False)
    assert asyncio.run(probes.fuse_probe())["mount"] == "not_visible"

    def timed_out(_: Any, prefix: str) -> str:
        raise TimeoutError("mount did not become ready")

    monkeypatch.setattr(FakeWorkspace, "add_fuse_mount", timed_out)
    assert asyncio.run(probes.fuse_probe())["mount"].startswith("TimeoutError:")

    release = threading.Event()

    def blocked_mount(_: Any, prefix: str) -> str:
        release.wait(timeout=1)
        return "/probe-mount"

    monkeypatch.setattr(FakeWorkspace, "add_fuse_mount", blocked_mount)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        started = time.monotonic()
        result = loop.run_until_complete(probes.fuse_probe(mount_timeout_s=0.01))
        assert time.monotonic() - started < 0.2
    finally:
        release.set()
        loop.run_until_complete(loop.shutdown_default_executor())
        loop.close()
        asyncio.set_event_loop(None)
    assert result["mount"].startswith("TimeoutError:")
    assert result["cleanup"] == "skipped_unfinished_mount"

    closed.clear()
    monkeypatch.setattr(FakeWorkspace, "add_fuse_mount", lambda self, prefix: "/probe-mount")
    release_remove = threading.Event()

    def blocked_remove(_: Any, prefix: str) -> None:
        release_remove.wait(timeout=1)

    monkeypatch.setattr(FakeWorkspace, "remove_fuse_mount", blocked_remove)
    monkeypatch.setattr(probes.os.path, "ismount", lambda path: True)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        started = time.monotonic()
        result = loop.run_until_complete(probes.fuse_probe(mount_timeout_s=0.01))
        assert time.monotonic() - started < 0.2
    finally:
        release_remove.set()
        loop.run_until_complete(loop.shutdown_default_executor())
        loop.close()
        asyncio.set_event_loop(None)
    assert result["cleanup"] == "TimeoutError"
    assert not closed


def test_claude_cli_probe_reports_tools_and_helper_refresh(monkeypatch: Any, tmp_path: Any) -> None:
    token_file = tmp_path / "gateway-token"
    token_file.write_text("fake-token")
    monkeypatch.setenv("GATEWAY_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("GATEWAY_URL", "https://gateway.example.test/anthropic")
    monkeypatch.setenv("AGENT_MODEL", "claude-sonnet-5")

    class FakeSystemMessage:
        subtype = "init"
        data = {"tools": ["mcp__probe__ping"]}

    class FakeToolUseBlock:
        name = "mcp__probe__ping"

    class FakeAssistantMessage:
        content = [FakeToolUseBlock()]

    class FakeClient:
        def __init__(self, options: Any) -> None:
            self.options = options
            self.turn = 0

        async def __aenter__(self) -> FakeClient:
            return self

        async def __aexit__(self, *_: Any) -> None:
            pass

        async def query(self, _: str) -> None:
            self.turn += 1
            assert self.options.tools == [] and self.options.strict_mcp_config is True
            helper = json.loads(self.options.settings)["apiKeyHelper"]
            completed = subprocess.run(  # noqa: S603 - helper path is created by the probe
                [helper], check=True, capture_output=True
            )
            assert completed.stdout == b"fake-token"
            if self.turn == 1:
                await self.options.mcp_servers["probe"][0]({})

        async def receive_response(self) -> Any:
            if self.turn == 1:
                yield FakeSystemMessage()
                yield FakeAssistantMessage()

    async def no_sleep(_: float) -> None:
        pass

    sdk = ModuleType("claude_agent_sdk")
    sdk.AssistantMessage = FakeAssistantMessage  # type: ignore[attr-defined]
    sdk.SystemMessage = FakeSystemMessage  # type: ignore[attr-defined]
    sdk.ToolUseBlock = FakeToolUseBlock  # type: ignore[attr-defined]
    sdk.ClaudeAgentOptions = lambda **kw: SimpleNamespace(**kw)  # type: ignore[attr-defined]
    sdk.ClaudeSDKClient = FakeClient  # type: ignore[attr-defined]
    sdk.create_sdk_mcp_server = lambda name, tools: tools  # type: ignore[attr-defined]
    sdk.tool = lambda *args: lambda fn: fn  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", sdk)
    monkeypatch.setattr(probes.asyncio, "sleep", no_sleep)
    result = asyncio.run(probes.claude_cli_probe(helper_ttl_ms=1))
    assert result == {
        "cli_started": True,
        "tool_names_seen": ["mcp__probe__ping"],
        "tool_calls": ["mcp__probe__ping"],
        "builtin_called": [],
        "ping_ran": True,
        "helper_calls_before_ttl": 1,
        "helper_calls": 2,
    }


def test_entrypoint_dispatch_and_error_shape(monkeypatch: Any) -> None:
    monkeypatch.setenv("HUB_SCOPE", "hub")
    monkeypatch.setenv("GATEWAY_SCOPE", "gateway")
    monkeypatch.setenv("IDENTITY_PROVIDER", "provider")
    monkeypatch.setenv("POC_REGION", "ap-southeast-1")
    monkeypatch.setattr(probes, "identity_probe", lambda scopes: _async_result({"scopes": scopes}))
    monkeypatch.setattr(probes, "claude_cli_probe", lambda: _async_result({"ping_ran": True}))
    monkeypatch.setattr(probes, "fuse_probe", lambda: _async_result({"mount": "ok"}))
    monkeypatch.setattr(probes, "sandbox_probe", lambda: {"png_round_trip": True})
    monkeypatch.setattr(probes, "s3_denied_probe", lambda: {"get": "AccessDenied"})

    class FakeSource:
        def __init__(self, *args: Any) -> None:
            pass

        async def get(self) -> str:
            return "token"

    module = ModuleType("agentcore_platform_poc.agent_platform.tokens")
    module.IdentityTokenSource = FakeSource  # type: ignore[attr-defined]
    module.write_token_file = lambda token: "/probe-token"  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, module.__name__, module)
    context = SimpleNamespace(request_headers={GRANT: "abc"})
    for name in ("headers", "identity", "claude_cli", "fuse", "sandbox", "s3_denied"):
        result = asyncio.run(entrypoint.invoke({"probe": name}, context))
        assert result["probe"] == name and result["ok"] is True and result["detail"]
    unknown = asyncio.run(entrypoint.invoke({"probe": "unknown"}, context))
    assert unknown["ok"] is False and unknown["detail"] == {"error": "unknown_probe"}

    def broken_probe() -> dict[str, Any]:
        raise RuntimeError("secret-token-must-not-leak")

    monkeypatch.setattr(probes, "s3_denied_probe", broken_probe)
    failed = asyncio.run(entrypoint.invoke({"probe": "s3_denied"}, context))
    assert failed["ok"] is False and failed["detail"] == {"error": "RuntimeError"}


async def _async_result(value: dict[str, Any]) -> dict[str, Any]:
    return value
