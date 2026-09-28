from __future__ import annotations

from typing import Any

from agentcore_platform_poc.agent_platform.tools import ToolResult, ToolSpec
from agentcore_platform_poc.research_agent.claude_adapter import (
    allowed_tool_names,
    build_options,
    sdk_handler,
)
from agentcore_platform_poc.research_agent.config import ResearchConfig

CONFIG = ResearchConfig(
    "ap-southeast-1",
    "https://hub.example.test",
    "api://hub/.default",
    "https://gw.example.test/anthropic",
    "api://gw/.default",
    "prov",
    "ci-1",
    "model-a",
)


async def _handler(args: dict[str, Any]) -> ToolResult:
    return ToolResult("ok")


SPECS = [ToolSpec("ws_list", "List.", {"type": "object", "properties": {}}, _handler)]


def test_builtins_disabled_and_only_platform_tools_allowed() -> None:
    options = build_options(CONFIG, SPECS, helper_command="python -m helper")
    assert options.tools == []
    assert options.allowed_tools == ["mcp__platform__ws_list"]
    assert options.setting_sources == []
    assert "platform" in options.mcp_servers
    assert options.max_turns == 30


def test_gateway_and_helper_wiring() -> None:
    options = build_options(CONFIG, SPECS, helper_command="python -m helper", helper_ttl_ms=60000)
    assert options.env["ANTHROPIC_BASE_URL"] == "https://gw.example.test/anthropic"
    assert options.env["CLAUDE_CODE_API_KEY_HELPER_TTL_MS"] == "60000"
    assert '"apiKeyHelper": "python -m helper"' in str(options.settings)
    assert options.model == "model-a"
    assert options.thinking == {"type": "disabled"}


def test_allowed_names() -> None:
    assert allowed_tool_names(SPECS) == ["mcp__platform__ws_list"]


async def test_sdk_handler_maps_results() -> None:
    async def failing(args: dict[str, Any]) -> ToolResult:
        return ToolResult('{"error":"x"}', is_error=True)

    ok = await sdk_handler(SPECS[0])({})
    bad = await sdk_handler(ToolSpec("t", "d", {"type": "object"}, failing))({})
    assert ok == {"content": [{"type": "text", "text": "ok"}]}
    assert bad == {"content": [{"type": "text", "text": '{"error":"x"}'}], "is_error": True}
