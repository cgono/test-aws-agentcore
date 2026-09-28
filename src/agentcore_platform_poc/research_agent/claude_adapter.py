"""Claude Agent SDK adapter: ToolSpecs become an in-process MCP server; built-in tools are off."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
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
        allowed_tools=allowed_tool_names(specs),
        setting_sources=[],
        settings=json.dumps({"apiKeyHelper": helper_command}),
        env={
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
    async for message in query(prompt=prompt, options=options):
        if isinstance(message, AssistantMessage):
            calls.extend(block.name for block in message.content if isinstance(block, ToolUseBlock))
        elif isinstance(message, ResultMessage):
            final = message
    if final is None:
        return AgentRun("", 0, 0, 0, calls, "no_result")
    usage = final.usage or {}
    return AgentRun(
        summary=str(final.result or ""),
        turns=int(final.num_turns),
        input_tokens=int(usage.get("input_tokens", 0)),
        output_tokens=int(usage.get("output_tokens", 0)),
        tool_calls=calls,
        error=None if not final.is_error else str(final.subtype),
    )
