from __future__ import annotations

import os
from collections.abc import Sequence
from importlib import import_module
from typing import Protocol

import pytest

from agentcore_identity_poc.cli import run_live_user_isolation
from agentcore_identity_poc.experiments import ExperimentConfigurationError, MatrixRow


class LiveIsolationRuntime(Protocol):
    """Operator-owned H4b actions; test code never embeds cloud credentials or tokens."""

    def run_workload_isolation(self) -> Sequence[MatrixRow]: ...


@pytest.fixture
def live_runtime() -> LiveIsolationRuntime:
    return _load_live_runtime()


def _require_live() -> None:
    if "AGENTCORE_POC_LIVE" not in os.environ:
        pytest.skip("set AGENTCORE_POC_LIVE=1 and configure live Entra/AWS/Google credentials")


def _load_live_runtime() -> LiveIsolationRuntime:
    _require_live()
    target = os.environ.get("AGENTCORE_POC_LIVE_RUNTIME")
    if not target or ":" not in target:
        pytest.fail(
            "AGENTCORE_POC_LIVE=1 requires AGENTCORE_POC_LIVE_RUNTIME=module:factory; "
            "the factory must return a configured LiveIsolationRuntime"
        )
    module_name, factory_name = target.split(":", maxsplit=1)
    try:
        factory = getattr(import_module(module_name), factory_name)
        runtime = factory()
    except (AttributeError, ImportError, TypeError) as error:
        pytest.fail(f"could not load AGENTCORE_POC_LIVE_RUNTIME: {error}")
    if not callable(getattr(runtime, "run_workload_isolation", None)):
        pytest.fail("AGENTCORE_POC_LIVE_RUNTIME factory did not return a LiveIsolationRuntime")
    return runtime


def test_live_flag_presence_requires_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTCORE_POC_LIVE", "1")
    monkeypatch.delenv("AGENTCORE_POC_LIVE_RUNTIME", raising=False)

    with pytest.raises(pytest.fail.Exception, match="AGENTCORE_POC_LIVE_RUNTIME"):
        _load_live_runtime()


@pytest.mark.integration
def test_live_user_isolation_records_two_distinct_validated_users() -> None:
    _require_live()
    verified_subject_counts: list[int] = []
    try:
        rows = run_live_user_isolation(on_verified_subject_count=verified_subject_counts.append)
    except ExperimentConfigurationError as error:
        pytest.fail(f"could not configure concrete H4a runner: {error}")

    assert verified_subject_counts == [2]
    assert len(rows) == 2
    assert len({row.user_alias for row in rows}) == 2
    assert all(row.policy_mode == "scoped" for row in rows)
    assert all(row.outcome == "pass" for row in rows)


@pytest.mark.integration
def test_live_workload_isolation_records_broad_and_scoped_same_principal(
    live_runtime: LiveIsolationRuntime,
) -> None:
    rows = live_runtime.run_workload_isolation()

    assert {row.principal_alias for row in rows} and len({row.principal_alias for row in rows}) == 1
    broad_rows = [row for row in rows if row.policy_mode == "broad"]
    scoped_rows = [row for row in rows if row.policy_mode == "scoped"]
    assert len({row.asserted_workload for row in broad_rows}) == 2
    assert all(row.outcome == "pass" for row in broad_rows)
    assert len({row.asserted_workload for row in scoped_rows}) == 2
    assert {row.outcome for row in scoped_rows} == {"pass", "denied"}
