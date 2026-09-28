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
MAX_LIST_ENTRIES = 500
MAX_RUN_INPUT_BYTES = 32 * 1024 * 1024  # total bytes run_code copies into the sandbox
MAX_UPLOAD_BYTES = 4 * 1024 * 1024  # the Resource Hub upload limit


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


def _valid_value(prop: dict[str, Any], value: Any) -> bool:
    kind = prop["type"]
    if kind == "string":
        return isinstance(value, str)
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "integer":
        is_int = isinstance(value, int) and not isinstance(value, bool)
        return is_int and value >= prop.get("minimum", value)
    if kind == "array":
        return isinstance(value, list) and all(_valid_value(prop["items"], v) for v in value)
    return False


def _valid(schema: dict[str, Any], args: Any) -> bool:
    """Models send arguments that do not match the schema; never coerce them."""
    if not isinstance(args, dict):
        return False
    props = schema["properties"]
    if set(args) - set(props) or any(name not in args for name in schema["required"]):
        return False
    return all(_valid_value(props[name], value) for name, value in args.items())


def _guard(
    schema: dict[str, Any],
    fn: Callable[[dict[str, Any]], Awaitable[ToolResult]],
) -> Callable[[dict[str, Any]], Awaitable[ToolResult]]:
    async def wrapped(args: dict[str, Any]) -> ToolResult:
        if not _valid(schema, args):
            return _error("bad_arguments")
        try:
            return await fn(args)
        except HubError as error:
            return _error(error.code, status=error.status)
        except FetchRejected as error:
            return _error(error.code)
        except SandboxError as error:
            return _error(error.code)
        except httpx.HTTPError:
            return _error("network_error")
        except Exception:  # the text may carry request details; the model gets a code only
            return _error("tool_failed")

    return wrapped


def _tool(
    name: str,
    description: str,
    schema: dict[str, Any],
    fn: Callable[[dict[str, Any]], Awaitable[ToolResult]],
) -> ToolSpec:
    return ToolSpec(name, description, schema, _guard(schema, fn))


def build_tools(ctx: ToolContext) -> list[ToolSpec]:
    # Handlers run only after _guard checked args against the tool's schema.
    async def ws_list(args: dict[str, Any]) -> ToolResult:
        entries = await ctx.hub.list(args.get("path", ""))
        more = max(len(entries) - MAX_LIST_ENTRIES, 0)
        return ToolResult(json.dumps({"entries": entries[:MAX_LIST_ENTRIES], "more": more}))

    async def ws_read(args: dict[str, Any]) -> ToolResult:
        data = await ctx.hub.read(args["path"], args.get("offset", 0), MAX_READ_CHARS * 4)
        return ToolResult(_cut(data.decode("utf-8", errors="replace"), MAX_READ_CHARS))

    async def ws_write(args: dict[str, Any]) -> ToolResult:
        path, data = args["path"], args["content"].encode()
        await ctx.hub.write(path, data)
        ctx.files_written.append(path)
        return ToolResult(json.dumps({"written": path, "bytes": len(data)}))

    async def ws_search(args: dict[str, Any]) -> ToolResult:
        result = await ctx.hub.search(
            args["text"], args.get("glob"), args.get("ignore_case", False)
        )
        return ToolResult(_cut(json.dumps(result), MAX_OUTPUT_CHARS))

    async def fetch(args: dict[str, Any]) -> ToolResult:
        return ToolResult(_cut(await fetch_url(args["url"], http=ctx.http), MAX_READ_CHARS))

    async def run_code(args: dict[str, Any]) -> ToolResult:
        code, inputs, outputs = args["code"], args.get("inputs", []), args.get("outputs", [])
        total = sum([await ctx.hub.stat(path) for path in inputs])
        if total > MAX_RUN_INPUT_BYTES:  # checked before any input is read into memory
            return _error("inputs_too_large", limit=MAX_RUN_INPUT_BYTES)
        payload = {path: await ctx.hub.read(path) for path in inputs}
        result = await asyncio.to_thread(ctx.sandbox.run, code, payload, outputs)
        saved: list[str] = []
        too_large: list[str] = []
        not_saved: dict[str, str] = {}
        for path, data in result.files.items():
            if len(data) > MAX_UPLOAD_BYTES:
                too_large.append(path)
                continue
            try:
                await ctx.hub.write(path, data)
            except HubError as error:
                not_saved[path] = error.code
                continue
            saved.append(path)
            ctx.files_written.append(path)
        body = {
            "exit_code": result.exit_code,
            "failed": result.failed,
            "stdout": _cut(result.stdout, MAX_OUTPUT_CHARS),
            "stderr": _cut(result.stderr, MAX_OUTPUT_CHARS),
            "saved": sorted(saved),
            "too_large": too_large,
            "not_saved": not_saved,
            "missing": result.missing,
        }
        return ToolResult(json.dumps(body), is_error=result.failed or bool(too_large or not_saved))

    text = {"type": "string"}
    return [
        _tool(
            "ws_list",
            "List files in the user's workspace under an optional folder path.",
            _schema(path={**text, "optional": True}),
            ws_list,
        ),
        _tool(
            "ws_read",
            "Read a text file from the user's workspace.",
            _schema(path=dict(text), offset={"type": "integer", "minimum": 0, "optional": True}),
            ws_read,
        ),
        _tool(
            "ws_write",
            "Write a text file to the user's workspace.",
            _schema(path=dict(text), content=dict(text)),
            ws_write,
        ),
        _tool(
            "ws_search",
            "Find lines containing exact text in the user's workspace files.",
            _schema(
                text=dict(text),
                glob={**text, "optional": True},
                ignore_case={"type": "boolean", "optional": True},
            ),
            ws_search,
        ),
        _tool(
            "fetch_url",
            "HTTPS GET from an allowed data API (api.worldbank.org).",
            _schema(url=dict(text)),
            fetch,
        ),
        _tool(
            "run_code",
            "Run Python in an isolated sandbox with no internet. "
            "'inputs' are workspace paths copied in; "
            "'outputs' are sandbox paths copied back to the workspace. matplotlib is available.",
            _schema(
                code=dict(text),
                inputs={"type": "array", "items": text, "optional": True},
                outputs={"type": "array", "items": text, "optional": True},
            ),
            run_code,
        ),
    ]
