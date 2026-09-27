"""Probe agent: Task 0 checks inside Runtime, deployed to the research slot first."""

from __future__ import annotations

import asyncio
import os
from typing import Any

from bedrock_agentcore.runtime import BedrockAgentCoreApp
from bedrock_agentcore.runtime.context import RequestContext

from agentcore_platform_poc import build_id
from agentcore_platform_poc.probe_agent import probes

app = BedrockAgentCoreApp()


async def invoke(payload: dict[str, Any], context: RequestContext) -> dict[str, Any]:
    name = payload.get("probe")
    try:
        if name == "headers":
            detail: dict[str, Any] = probes.header_summary(context.request_headers or {})
        elif name == "identity":
            detail = await probes.identity_probe(
                [os.environ["HUB_SCOPE"], os.environ["GATEWAY_SCOPE"]]
            )
        elif name == "claude_cli":
            from agentcore_platform_poc.agent_platform.tokens import (  # type: ignore[import-untyped]
                IdentityTokenSource,
                write_token_file,
            )

            source = IdentityTokenSource(
                os.environ["IDENTITY_PROVIDER"],
                os.environ["GATEWAY_SCOPE"],
                os.environ["POC_REGION"],
            )
            os.environ["GATEWAY_TOKEN_FILE"] = str(write_token_file(await source.get()))
            detail = await probes.claude_cli_probe()
        elif name == "fuse":
            detail = await asyncio.wait_for(probes.fuse_probe(), timeout=90)
        elif name == "sandbox":
            detail = await asyncio.to_thread(probes.sandbox_probe)
        elif name == "s3_denied":
            detail = await asyncio.to_thread(probes.s3_denied_probe)
        else:
            return {
                "probe": name,
                "build_id": build_id(),
                "ok": False,
                "detail": {"error": "unknown_probe"},
            }
    except Exception as error:  # noqa: BLE001 - probe failures are returned as data
        return {
            "probe": name,
            "build_id": build_id(),
            "ok": False,
            "detail": {"error": type(error).__name__},
        }
    return {"probe": name, "build_id": build_id(), "ok": True, "detail": detail}


app.entrypoint(invoke)


def main() -> None:
    app.run(host="0.0.0.0", port=8080)  # noqa: S104 - Runtime contract
