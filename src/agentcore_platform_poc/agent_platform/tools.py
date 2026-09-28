# src/agentcore_platform_poc/agent_platform/tools.py
"""The framework-neutral tool contract. Adapters turn ToolSpecs into framework tools."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from agentcore_platform_poc.agent_platform.fetch import FetchRejected, fetch_url
from agentcore_platform_poc.agent_platform.hub_client import HubError, ResourceHubClient
from agentcore_platform_poc.agent_platform.sandbox import Sandbox, SandboxError

MAX_READ_CHARS = 20_000
MAX_OUTPUT_CHARS = 8_000


@dataclass(frozen=True)
class ToolResult:
    text: str
    is_error: bool = False


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], Awaitable[ToolResult]]


@dataclass
class ToolContext:
    hub: ResourceHubClient
    sandbox: Sandbox
    http: httpx.AsyncClient
    files_written: list[str] = field(default_factory=list)


def _error(code: str, **extra: Any) -> ToolResult:
    return ToolResult(json.dumps({"error": code, **extra}), is_error=True)


def _cut(text: str, limit: int) -> str:
    return (
        text
        if len(text) <= limit
        else text[:limit] + f"\n[truncated: {len(text) - limit} more characters]"
    )


def _schema(**properties: dict[str, Any]) -> dict[str, Any]:
    required = [name for name, prop in properties.items() if not prop.pop("optional", False)]
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


def _guard(
    fn: Callable[[dict[str, Any]], Awaitable[ToolResult]],
) -> Callable[[dict[str, Any]], Awaitable[ToolResult]]:
    async def wrapped(args: dict[str, Any]) -> ToolResult:
        try:
            return await fn(args)
        except HubError as error:
            return _error(error.code, status=error.status)
        except FetchRejected as error:
            return _error(error.code)
        except SandboxError as error:
            return _error(error.code)
        except (KeyError, TypeError, ValueError):
            return _error("bad_arguments")

    return wrapped


def build_tools(ctx: ToolContext) -> list[ToolSpec]:
    async def ws_list(args: dict[str, Any]) -> ToolResult:
        return ToolResult(json.dumps(await ctx.hub.list(str(args.get("path", "")))))

    async def ws_read(args: dict[str, Any]) -> ToolResult:
        data = await ctx.hub.read(str(args["path"]), int(args.get("offset", 0)), MAX_READ_CHARS * 4)
        return ToolResult(_cut(data.decode("utf-8", errors="replace"), MAX_READ_CHARS))

    async def ws_write(args: dict[str, Any]) -> ToolResult:
        path, content = str(args["path"]), args["content"]
        if not isinstance(content, str):
            raise TypeError("content")
        await ctx.hub.write(path, content.encode())
        ctx.files_written.append(path)
        return ToolResult(json.dumps({"written": path, "bytes": len(content.encode())}))

    async def ws_search(args: dict[str, Any]) -> ToolResult:
        result = await ctx.hub.search(
            str(args["text"]), args.get("glob"), bool(args.get("ignore_case", False))
        )
        return ToolResult(_cut(json.dumps(result), MAX_OUTPUT_CHARS))

    async def fetch(args: dict[str, Any]) -> ToolResult:
        return ToolResult(_cut(await fetch_url(str(args["url"]), http=ctx.http), MAX_READ_CHARS))

    async def run_code(args: dict[str, Any]) -> ToolResult:
        code, inputs, outputs = (
            str(args["code"]),
            list(args.get("inputs", [])),
            list(args.get("outputs", [])),
        )
        payload = {str(p): await ctx.hub.read(str(p)) for p in inputs}
        result = await asyncio.to_thread(ctx.sandbox.run, code, payload, [str(p) for p in outputs])
        for path, data in result.files.items():
            await ctx.hub.write(path, data)
            ctx.files_written.append(path)
        body = {
            "exit_code": result.exit_code,
            "failed": result.failed,
            "stdout": _cut(result.stdout, MAX_OUTPUT_CHARS),
            "stderr": _cut(result.stderr, MAX_OUTPUT_CHARS),
            "saved": sorted(result.files),
            "missing": result.missing,
        }
        return ToolResult(json.dumps(body), is_error=result.failed)

    text = {"type": "string"}
    return [
        ToolSpec(
            "ws_list",
            "List files in the user's workspace under an optional folder path.",
            _schema(path={**text, "optional": True}),
            _guard(ws_list),
        ),
        ToolSpec(
            "ws_read",
            "Read a text file from the user's workspace.",
            _schema(path=dict(text), offset={"type": "integer", "optional": True}),
            _guard(ws_read),
        ),
        ToolSpec(
            "ws_write",
            "Write a text file to the user's workspace.",
            _schema(path=dict(text), content=dict(text)),
            _guard(ws_write),
        ),
        ToolSpec(
            "ws_search",
            "Find lines containing exact text in the user's workspace files.",
            _schema(
                text=dict(text),
                glob={**text, "optional": True},
                ignore_case={"type": "boolean", "optional": True},
            ),
            _guard(ws_search),
        ),
        ToolSpec(
            "fetch_url",
            "HTTPS GET from an allowed data API (api.worldbank.org).",
            _schema(url=dict(text)),
            _guard(fetch),
        ),
        ToolSpec(
            "run_code",
            "Run Python in an isolated sandbox with no internet. "
            "'inputs' are workspace paths copied in; "
            "'outputs' are sandbox paths copied back to the workspace. matplotlib is available.",
            _schema(
                code=dict(text),
                inputs={"type": "array", "items": text, "optional": True},
                outputs={"type": "array", "items": text, "optional": True},
            ),
            _guard(run_code),
        ),
    ]
