"""AgentCore Runtime entry point (HTTP protocol) for the direct-code zip deployment."""

from __future__ import annotations

import functools
import logging
import os
import threading
from typing import Any

import httpx
from bedrock_agentcore.runtime import BedrockAgentCoreApp
from bedrock_agentcore.runtime.context import RequestContext

from agentcore_runtime_poc.runtime_agent.agent import Agent, MsalTokenSource
from agentcore_runtime_poc.runtime_agent.config import AgentConfig
from agentcore_runtime_poc.runtime_agent.secret_store import load_client_secret

app = BedrockAgentCoreApp()
_agent_lock = threading.Lock()


@functools.cache
def _build_agent() -> Agent:
    config = AgentConfig.from_env(os.environ)
    tokens = MsalTokenSource(
        config, functools.partial(load_client_secret, config.region, config.client_secret_arn)
    )
    return Agent(config, tokens, httpx.Client(timeout=30.0))


def get_agent() -> Agent:
    # The SDK runs sync handlers in a thread pool, and functools.cache does not stop concurrent
    # first calls from each building an agent (with its own marker and token cache).
    with _agent_lock:
        return _build_agent()


def invoke(payload: dict[str, Any], context: RequestContext) -> dict[str, Any]:
    return get_agent().handle(payload, context.session_id)


# Registered without decorator syntax: the SDK's decorator is untyped, which mypy --strict rejects.
app.entrypoint(invoke)


def configure_logging() -> None:
    # The SDK configures only its own logger; without this, agent INFO lines never reach CloudWatch.
    logger = logging.getLogger("agentcore_runtime_poc")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def main() -> None:
    configure_logging()
    # The SDK binds 127.0.0.1 unless it detects Docker; the Runtime contract needs 0.0.0.0:8080.
    app.run(host="0.0.0.0", port=8080)  # noqa: S104
