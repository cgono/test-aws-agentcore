"""Claude Agent SDK adapter: ToolSpecs become an in-process MCP server; built-in tools are off."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultError,
    ResultMessage,
    ToolUseBlock,
    create_sdk_mcp_server,
    query,
    tool,
)

from agentcore_platform_poc.agent_platform.tools import ToolSpec
from agentcore_platform_poc.research_agent.config import ResearchConfig

SERVER_NAME = "platform"
SYSTEM_PROMPT = (
    "You are a research agent working for one user. Their files are in their workspace; use the "
    "ws_* tools for every file. Get data only with fetch_url. Run Python only with run_code: pass "
    "workspace files in 'inputs' and name files to save in 'outputs'. Save results to the "
    "workspace, then reply with a short summary that names the files you wrote. If a tool returns "
    "an error, say which error; do not guess."
)
# The SDK merges options.env over the whole process environment and cannot remove a key, so
# ambient model and AWS credentials are set to "" for the CLI: the apiKeyHelper is its only key.
_BLANKED_ENV = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
)


@dataclass(frozen=True)
class AgentRun:
    summary: str
    turns: int
    input_tokens: int
    output_tokens: int
    tool_calls: list[str]
    error: str | None


def sdk_handler(spec: ToolSpec) -> Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]:
    async def handle(args: dict[str, Any]) -> dict[str, Any]:
        result = await spec.handler(args)
        out: dict[str, Any] = {"content": [{"type": "text", "text": result.text}]}
        if result.is_error:
            out["is_error"] = True
        return out

    return handle


def allowed_tool_names(specs: list[ToolSpec]) -> list[str]:
    return [f"mcp__{SERVER_NAME}__{spec.name}" for spec in specs]


def to_sdk_server(specs: list[ToolSpec]) -> Any:
    tools = [
        tool(spec.name, spec.description, spec.input_schema)(sdk_handler(spec)) for spec in specs
    ]
    return create_sdk_mcp_server(SERVER_NAME, tools=tools)


def build_options(
    config: ResearchConfig,
    specs: list[ToolSpec],
    *,
    helper_command: str,
    helper_ttl_ms: int = 60_000,
    max_turns: int = 30,
) -> ClaudeAgentOptions:
    return ClaudeAgentOptions(
        tools=[],  # removes every built-in tool; allowed_tools alone would only auto-approve
        mcp_servers={SERVER_NAME: to_sdk_server(specs)},
        strict_mcp_config=True,  # no MCP server from .mcp.json or any other config
        allowed_tools=allowed_tool_names(specs),
        setting_sources=[],
        settings=json.dumps({"apiKeyHelper": helper_command}),
        env={
            **dict.fromkeys(_BLANKED_ENV, ""),
            "ANTHROPIC_BASE_URL": config.gateway_url,
            "CLAUDE_CODE_API_KEY_HELPER_TTL_MS": str(helper_ttl_ms),
        },
        system_prompt=SYSTEM_PROMPT,
        model=config.model,
        max_turns=max_turns,
        thinking={"type": "disabled"},
    )


async def run_agent(prompt: str, options: ClaudeAgentOptions) -> AgentRun:
    calls: list[str] = []
    final: ResultMessage | None = None
    failure: str | None = None
    try:
        async for message in query(prompt=prompt, options=options):
            if isinstance(message, AssistantMessage):
                calls.extend(
                    block.name for block in message.content if isinstance(block, ToolUseBlock)
                )
            elif isinstance(message, ResultMessage):
                final = message
    except ResultError as error:
        # The CLI reports a terminal error result, then exits non-zero; keep what the run did.
        # Only the subtype is kept: the message and errors may carry upstream text.
        failure = error.subtype or "result_error"
    if final is None:
        return AgentRun("", 0, 0, 0, calls, failure or "no_result")
    usage = final.usage or {}
    return AgentRun(
        summary=str(final.result or ""),
        turns=int(final.num_turns),
        input_tokens=int(usage.get("input_tokens", 0)),
        output_tokens=int(usage.get("output_tokens", 0)),
        tool_calls=calls,
        error=str(final.subtype) if final.is_error else failure,
    )
