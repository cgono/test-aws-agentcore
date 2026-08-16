from __future__ import annotations

import os
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
    if os.environ.get("AGENTCORE_POC_LIVE") != "1":
        pytest.skip("set AGENTCORE_POC_LIVE=1 and configure live Entra/AWS credentials")
    pytest.skip("provide a live runtime fixture in the operator environment")


@pytest.mark.integration
@pytest.mark.parametrize("user_alias", ["user-a", "user-b"])
def test_live_entra_obo_records_h1_h2_h6(live_runtime: LiveRuntime, user_alias: str) -> None:
    result = live_runtime.run_entra_obo(user_alias=user_alias)

    assert result.workload_token_received is True
    assert result.resource_status == 200
    assert result.subject_alias == user_alias
    assert result.consent_prompt_seen is False
