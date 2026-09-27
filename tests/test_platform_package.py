from __future__ import annotations

import importlib

import pytest


@pytest.mark.parametrize(
    "name",
    [
        "agentcore_platform_poc",
        "agentcore_platform_poc.resource_hub",
        "agentcore_platform_poc.agent_platform",
        "agentcore_platform_poc.research_agent",
        "agentcore_platform_poc.bench_agent",
        "agentcore_platform_poc.probe_agent",
        "agentcore_platform_poc.unified_api",
    ],
)
def test_platform_packages_import(name: str) -> None:
    assert importlib.import_module(name) is not None


def test_new_dependencies_are_installed() -> None:
    import claude_agent_sdk
    import mirage

    assert claude_agent_sdk.__name__ == "claude_agent_sdk"
    assert mirage.__name__ == "mirage"
