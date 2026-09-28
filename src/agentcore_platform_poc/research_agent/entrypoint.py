"""Research agent on AgentCore Runtime: grant in, platform tools only, inference via the gateway."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import sys
from pathlib import Path
from typing import Any

import httpx
from bedrock_agentcore.runtime import BedrockAgentCoreApp
from bedrock_agentcore.runtime.context import RequestContext

from agentcore_platform_poc import build_id
from agentcore_platform_poc.agent_platform.hub_client import ResourceHubClient
from agentcore_platform_poc.agent_platform.sandbox import Sandbox
from agentcore_platform_poc.agent_platform.tokens import (
    IdentityTokenSource,
    TokenUnavailable,
    refresh_token_file,
    write_token_file,
)
from agentcore_platform_poc.agent_platform.tools import ToolContext, build_tools
from agentcore_platform_poc.research_agent.claude_adapter import build_options, run_agent
from agentcore_platform_poc.research_agent.config import ResearchConfig

GRANT_HEADER = "X-Amzn-Bedrock-AgentCore-Runtime-Custom-Grant"
USER_TOKEN_HEADER = "X-Amzn-Bedrock-AgentCore-Runtime-Custom-User-Token"  # noqa: S105 - a name
MAX_PROMPT = 4000
CODE_ROOT = Path(__file__).resolve().parents[2]  # the unzipped deployment root
# The CLI runs the helper in its own cwd, so the code root goes on PYTHONPATH explicitly.
HELPER = (
    f"env PYTHONPATH={CODE_ROOT} {sys.executable} "
    "-m agentcore_platform_poc.research_agent.api_key_helper"
)

app = BedrockAgentCoreApp()
logger = logging.getLogger("agentcore_platform_poc")


def _header(headers: dict[str, str] | None, name: str) -> str | None:
    for key, value in (headers or {}).items():
        if key.lower() == name.lower() and value:
            return value
    return None


async def invoke(payload: dict[str, Any], context: RequestContext) -> dict[str, Any]:
    base = {"build_id": build_id(), "session_id": context.session_id}
    grant = _header(context.request_headers, GRANT_HEADER)
    user_token = _header(context.request_headers, USER_TOKEN_HEADER)
    if not grant and not user_token:
        return base | {"error": "missing_grant"}
    prompt = payload.get("prompt")
    if not isinstance(prompt, str) or not prompt or len(prompt) > MAX_PROMPT:
        return base | {"error": "bad_prompt"}
    config = ResearchConfig.from_env(os.environ)
    hub_tokens = IdentityTokenSource(config.provider_name, config.hub_scope, config.region)
    gateway_tokens = IdentityTokenSource(config.provider_name, config.gateway_scope, config.region)
    sandbox = Sandbox(config.region, config.code_interpreter_id)
    refresher: asyncio.Task[None] | None = None
    try:
        write_token_file(await gateway_tokens.get())
        refresher = asyncio.create_task(refresh_token_file(gateway_tokens))
        async with httpx.AsyncClient(timeout=120.0) as http:
            hub = ResourceHubClient(
                config.hub_url,
                hub_tokens.get,
                grant=grant,
                user_token=None if grant else user_token,
                session_id=context.session_id,
                http=http,
            )
            ctx = ToolContext(hub=hub, sandbox=sandbox, http=http)
            run = await run_agent(
                prompt, build_options(config, build_tools(ctx), helper_command=HELPER)
            )
    except TokenUnavailable as error:
        return base | {"error": f"token_unavailable:{error}"}
    except Exception as error:  # noqa: BLE001 - the Runtime result must stay JSON; the type name only
        logger.info("research failed session=%s error=%s", context.session_id, type(error).__name__)
        return base | {"error": f"internal:{type(error).__name__}"}
    finally:
        if refresher is not None:
            refresher.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await refresher
        sandbox.stop()
    logger.info(
        "research done session=%s turns=%s tools=%s error=%s",
        context.session_id,
        run.turns,
        len(run.tool_calls),
        run.error,
    )
    return base | {
        "summary": run.summary,
        "files_written": ctx.files_written,
        "turns": run.turns,
        "input_tokens": run.input_tokens,
        "output_tokens": run.output_tokens,
        "tool_calls": run.tool_calls,
        "error": run.error,
    }


app.entrypoint(invoke)


def main() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    app.run(host="0.0.0.0", port=8080)  # noqa: S104 - Runtime contract
