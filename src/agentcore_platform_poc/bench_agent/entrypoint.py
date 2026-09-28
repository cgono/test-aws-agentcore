"""Benchmark agent: one (method, op, target) case per request, timed inside Runtime."""

from __future__ import annotations

import os
import time
from typing import Any

import httpx
from bedrock_agentcore.runtime import BedrockAgentCoreApp
from bedrock_agentcore.runtime.context import RequestContext

from agentcore_platform_poc import build_id
from agentcore_platform_poc.agent_platform.hub_client import HubError, ResourceHubClient
from agentcore_platform_poc.agent_platform.tokens import IdentityTokenSource
from agentcore_platform_poc.bench_agent.methods import (
    Case,
    DirectMethod,
    HubSearchMethod,
    Method,
    MirrorMethod,
    digest,
)

GRANT_HEADER = "X-Amzn-Bedrock-AgentCore-Runtime-Custom-Grant"
app = BedrockAgentCoreApp()
_methods: dict[str, Method] = {}
_tokens: IdentityTokenSource | None = None


def _grant(headers: dict[str, str] | None) -> str | None:
    return next((v for k, v in (headers or {}).items() if k.lower() == GRANT_HEADER.lower()), None)


def _build(name: str, hub: ResourceHubClient) -> Method:
    if name == "direct":
        return DirectMethod(hub)
    if name == "hub_search":
        return HubSearchMethod(hub)
    if name == "mirror":
        return MirrorMethod(hub)
    from agentcore_platform_poc.bench_agent.mirage_resource import MirageMethod

    return MirageMethod(hub, fuse=(name == "mirage_fuse"))


async def invoke(payload: dict[str, Any], context: RequestContext) -> dict[str, Any]:
    global _tokens
    grant = _grant(context.request_headers)
    try:
        case = Case.parse(payload.get("case") or {})
    except ValueError as error:
        return {"build_id": build_id(), "ok": False, "error": f"bad_case:{error}"}
    if not grant:
        return {"build_id": build_id(), "ok": False, "error": "missing_grant"}
    if _tokens is None:
        _tokens = IdentityTokenSource(
            os.environ["IDENTITY_PROVIDER"], os.environ["HUB_SCOPE"], os.environ["POC_REGION"]
        )
    cold = case.fresh or case.method not in _methods
    if case.fresh and case.method in _methods:
        await _methods.pop(case.method).close()
    started = time.perf_counter()
    if case.method not in _methods:
        hub = ResourceHubClient(
            os.environ["HUB_URL"],
            _tokens.get,
            grant=grant,
            session_id=context.session_id,
            http=httpx.AsyncClient(timeout=300.0),
        )
        _methods[case.method] = _build(case.method, hub)
    method = _methods[case.method]
    method.hub._grant = grant  # type: ignore[attr-defined]  # the same session may carry a newer grant
    before_req, before_bytes = method.requests(), method.bytes()
    failure: str | None = None
    result: Any = None
    try:
        if case.op == "list":
            result = await method.list(case.target)
        elif case.op == "read":
            result = await method.read(case.target)
        elif case.op == "write":
            await method.write(case.target, b"x" * 10_000)
            result = 10_000
        else:
            folder, glob = case.target.split("|", 1)
            result = await method.search(folder, glob, case.text or "")
    except HubError as hub_error:
        failure = f"hub:{hub_error.status}:{hub_error.code}"
    except Exception as other:  # noqa: BLE001 - reported as data (for example FUSE not available)
        failure = f"{type(other).__name__}: {str(other)[:300]}"
    ms = round((time.perf_counter() - started) * 1000, 1)
    count = len(result) if isinstance(result, list) else (result or 0)
    return {
        "build_id": build_id(),
        "method": case.method,
        "op": case.op,
        "target": case.target,
        "cold": cold,
        "ok": failure is None,
        "ms": ms,
        "bytes": method.bytes() - before_bytes,
        "requests": method.requests() - before_req,
        "result_count": count,
        "result_digest": digest(result) if isinstance(result, list) else str(result),
        "error": failure,
    }


app.entrypoint(invoke)


def main() -> None:
    app.run(host="0.0.0.0", port=8080)  # noqa: S104 - Runtime contract
