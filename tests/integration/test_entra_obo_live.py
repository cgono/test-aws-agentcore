from __future__ import annotations

import os
from importlib import import_module
from typing import Protocol

import pytest


class LiveOBOResult(Protocol):
    workload_token_received: bool
    resource_status: int
    subject_alias: str
    consent_prompt_seen: bool


class LiveRuntime(Protocol):
    def run_entra_obo(self, *, user_alias: str) -> LiveOBOResult: ...


@pytest.fixture
def live_runtime() -> LiveRuntime:
    return _load_live_runtime()


def _load_live_runtime() -> LiveRuntime:
    if "AGENTCORE_POC_LIVE" not in os.environ:
        pytest.skip("set AGENTCORE_POC_LIVE=1 and configure live Entra/AWS credentials")
    target = os.environ.get("AGENTCORE_POC_LIVE_RUNTIME")
    if not target or ":" not in target:
        pytest.fail(
            "AGENTCORE_POC_LIVE=1 requires AGENTCORE_POC_LIVE_RUNTIME=module:factory; "
            "the factory must return a configured LiveRuntime"
        )
    module_name, factory_name = target.split(":", maxsplit=1)
    try:
        factory = getattr(import_module(module_name), factory_name)
        runtime = factory()
    except (AttributeError, ImportError, TypeError) as error:
        pytest.fail(f"could not load AGENTCORE_POC_LIVE_RUNTIME: {error}")
    if not callable(getattr(runtime, "run_entra_obo", None)):
        pytest.fail("AGENTCORE_POC_LIVE_RUNTIME factory did not return a LiveRuntime")
    return runtime


def test_live_flag_presence_requires_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTCORE_POC_LIVE", "0")
    monkeypatch.delenv("AGENTCORE_POC_LIVE_RUNTIME", raising=False)

    with pytest.raises(pytest.fail.Exception, match="AGENTCORE_POC_LIVE_RUNTIME"):
        _load_live_runtime()


@pytest.mark.integration
@pytest.mark.parametrize("user_alias", ["user-a", "user-b"])
def test_live_entra_obo_records_h1_h2_h6(live_runtime: LiveRuntime, user_alias: str) -> None:
    result = live_runtime.run_entra_obo(user_alias=user_alias)

    assert result.workload_token_received is True
    assert result.resource_status == 200
    assert result.subject_alias == user_alias
    assert result.consent_prompt_seen is False
