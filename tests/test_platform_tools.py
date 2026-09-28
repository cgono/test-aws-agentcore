# tests/test_platform_tools.py
from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from agentcore_platform_poc.agent_platform.hub_client import HubError
from agentcore_platform_poc.agent_platform.sandbox import RunResult
from agentcore_platform_poc.agent_platform.tools import (
    MAX_LIST_ENTRIES,
    MAX_RUN_INPUT_BYTES,
    MAX_UPLOAD_BYTES,
    ToolContext,
    build_tools,
)


class FakeHub:
    def __init__(self) -> None:
        self.files: dict[str, bytes] = {"brief.md": b"Southeast Asia", "big.txt": b"x" * 30_000}

    async def list(self, path: str = "") -> list[dict[str, Any]]:
        return [{"path": p, "size": len(d), "modified": "t"} for p, d in sorted(self.files.items())]

    async def read(self, path: str, offset: int = 0, length: int | None = None) -> bytes:
        if path not in self.files:
            raise HubError(404, "not_found")
        data = self.files[path][offset:]
        return data if length is None else data[:length]

    async def stat(self, path: str) -> int:
        return len(self.files[path])

    async def write(self, path: str, data: bytes) -> None:
        if path.startswith("forbidden"):
            raise HubError(403, "agent_mismatch")
        self.files[path] = data

    async def search(
        self, text: str, glob: str | None = None, ignore_case: bool = False
    ) -> dict[str, Any]:
        return {
            "matches": [{"path": "brief.md", "line_no": 1, "line": "Southeast Asia"}],
            "truncated": None,
        }


class FakeSandbox:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, bytes], list[str]]] = []

    def run(self, code: str, inputs: dict[str, bytes], outputs: list[str]) -> RunResult:
        self.calls.append((code, inputs, outputs))
        return RunResult("done", "", 0, False, {"chart.png": b"\x89PNG"}, [])


@pytest.fixture
def tools() -> tuple[dict[str, Any], ToolContext]:
    ctx = ToolContext(hub=FakeHub(), sandbox=FakeSandbox(), http=httpx.AsyncClient())  # type: ignore[arg-type]
    return {t.name: t for t in build_tools(ctx)}, ctx


def test_tool_names_and_schemas(tools: tuple[dict[str, Any], ToolContext]) -> None:
    specs, _ = tools
    assert sorted(specs) == ["fetch_url", "run_code", "ws_list", "ws_read", "ws_search", "ws_write"]
    for spec in specs.values():
        assert spec.input_schema["type"] == "object" and spec.description


async def test_ws_read_truncates(tools: tuple[dict[str, Any], ToolContext]) -> None:
    specs, _ = tools
    result = await specs["ws_read"].handler({"path": "big.txt"})
    assert "[truncated" in result.text and len(result.text) < 20_200


async def test_hub_errors_are_tool_errors(tools: tuple[dict[str, Any], ToolContext]) -> None:
    specs, _ = tools
    result = await specs["ws_read"].handler({"path": "missing"})
    assert result.is_error and json.loads(result.text) == {"error": "not_found", "status": 404}
    result = await specs["ws_write"].handler({"path": "forbidden/x", "content": "a"})
    assert result.is_error and json.loads(result.text)["error"] == "agent_mismatch"


async def test_ws_write_records_files(tools: tuple[dict[str, Any], ToolContext]) -> None:
    specs, ctx = tools
    await specs["ws_write"].handler({"path": "report.md", "content": "# r"})
    assert ctx.files_written == ["report.md"]


async def test_run_code_copies_inputs_and_writes_outputs(
    tools: tuple[dict[str, Any], ToolContext],
) -> None:
    specs, ctx = tools
    result = await specs["run_code"].handler(
        {"code": "plot()", "inputs": ["brief.md"], "outputs": ["chart.png"]}
    )
    assert not result.is_error
    assert ctx.sandbox.calls[0][1] == {"brief.md": b"Southeast Asia"}  # type: ignore[attr-defined]
    assert ctx.hub.files["chart.png"] == b"\x89PNG"  # type: ignore[attr-defined]
    assert ctx.files_written == ["chart.png"]


async def test_bad_arguments_are_tool_errors(tools: tuple[dict[str, Any], ToolContext]) -> None:
    specs, _ = tools
    result = await specs["ws_read"].handler({})
    assert result.is_error and json.loads(result.text)["error"] == "bad_arguments"


async def test_fetch_rejection_is_tool_error(tools: tuple[dict[str, Any], ToolContext]) -> None:
    specs, _ = tools
    result = await specs["fetch_url"].handler({"url": "https://evil.example.test/"})
    assert result.is_error and json.loads(result.text)["error"] == "host_not_allowed"


class HugeInputHub(FakeHub):
    async def stat(self, path: str) -> int:
        return MAX_RUN_INPUT_BYTES + 1 if path == "huge.bin" else await super().stat(path)

    async def read(self, path: str, offset: int = 0, length: int | None = None) -> bytes:
        assert path != "huge.bin", "an oversized input must not be read"
        return await super().read(path, offset, length)


async def test_run_code_refuses_oversized_inputs_before_reading() -> None:
    ctx = ToolContext(hub=HugeInputHub(), sandbox=FakeSandbox(), http=httpx.AsyncClient())  # type: ignore[arg-type]
    run_code = {t.name: t for t in build_tools(ctx)}["run_code"]
    result = await run_code.handler({"code": "x", "inputs": ["brief.md", "huge.bin"]})
    assert result.is_error and json.loads(result.text)["error"] == "inputs_too_large"
    assert ctx.sandbox.calls == []  # type: ignore[attr-defined]


class FailingSandbox(FakeSandbox):
    def run(self, code: str, inputs: dict[str, bytes], outputs: list[str]) -> RunResult:
        raise RuntimeError("secret upstream detail")


async def test_unexpected_sandbox_error_is_a_safe_tool_error() -> None:
    ctx = ToolContext(hub=FakeHub(), sandbox=FailingSandbox(), http=httpx.AsyncClient())  # type: ignore[arg-type]
    result = await {t.name: t for t in build_tools(ctx)}["run_code"].handler({"code": "x"})
    assert result.is_error and json.loads(result.text) == {"error": "tool_failed"}


async def test_network_error_is_a_safe_tool_error() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("secret detail", request=request)

    http = httpx.AsyncClient(transport=httpx.MockTransport(refuse))
    ctx = ToolContext(hub=FakeHub(), sandbox=FakeSandbox(), http=http)  # type: ignore[arg-type]
    fetch = {t.name: t for t in build_tools(ctx)}["fetch_url"]
    result = await fetch.handler({"url": "https://api.worldbank.org/v2/country"})
    assert result.is_error and json.loads(result.text) == {"error": "network_error"}


class BigOutputSandbox(FakeSandbox):
    def run(self, code: str, inputs: dict[str, bytes], outputs: list[str]) -> RunResult:
        files = {"a.png": b"a", "big.bin": b"x" * (MAX_UPLOAD_BYTES + 1), "forbidden/x": b"f"}
        return RunResult("", "", 0, False, files, [])


async def test_outputs_over_the_upload_limit_and_failed_writes_are_reported() -> None:
    ctx = ToolContext(hub=FakeHub(), sandbox=BigOutputSandbox(), http=httpx.AsyncClient())  # type: ignore[arg-type]
    run_code = {t.name: t for t in build_tools(ctx)}["run_code"]
    result = await run_code.handler({"code": "x", "outputs": ["a.png", "big.bin", "forbidden/x"]})
    body = json.loads(result.text)
    assert result.is_error and body["saved"] == ["a.png"] and ctx.files_written == ["a.png"]
    assert body["too_large"] == ["big.bin"] and body["not_saved"] == {
        "forbidden/x": "agent_mismatch"
    }
    assert "big.bin" not in ctx.hub.files  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("name", "args"),
    [
        ("run_code", {"code": "x", "inputs": "abc"}),
        ("run_code", {"code": "x", "outputs": [1]}),
        ("ws_read", {"path": "brief.md", "offset": 2.9}),
        ("ws_read", {"path": "brief.md", "offset": -1}),
        ("ws_read", {"path": "brief.md", "offset": True}),
        ("ws_search", {"text": "a", "ignore_case": "false"}),
        ("ws_list", {"path": ["a"]}),
        ("ws_write", {"path": "a", "content": "b", "extra": 1}),
    ],
)
async def test_wrong_argument_types_are_rejected(
    tools: tuple[dict[str, Any], ToolContext], name: str, args: dict[str, Any]
) -> None:
    specs, ctx = tools
    result = await specs[name].handler(args)
    assert result.is_error and json.loads(result.text)["error"] == "bad_arguments"
    assert ctx.sandbox.calls == []  # type: ignore[attr-defined]


async def test_ws_list_is_bounded(tools: tuple[dict[str, Any], ToolContext]) -> None:
    specs, ctx = tools
    ctx.hub.files.update({f"f{i:04d}.txt": b"x" for i in range(MAX_LIST_ENTRIES + 10)})  # type: ignore[attr-defined]
    body = json.loads((await specs["ws_list"].handler({})).text)
    assert len(body["entries"]) == MAX_LIST_ENTRIES and body["more"] == 12
