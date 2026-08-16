from __future__ import annotations

import os
from importlib import import_module
from typing import Protocol, cast

import pytest


class LiveLifecycleRuntime(Protocol):
    """Operator-supplied live actions; this test stores no cloud values or credentials."""

    def run_lifecycle_measurements(self) -> dict[str, bool | str]: ...


def _load_live_runtime() -> LiveLifecycleRuntime:
    if "AGENTCORE_POC_LIVE" not in os.environ:
        pytest.skip("set AGENTCORE_POC_LIVE=1 only after enabling the Phase 2 live gate")
    target = os.environ.get("AGENTCORE_POC_LIVE_RUNTIME")
    if not target or ":" not in target:
        pytest.fail(
            "AGENTCORE_POC_LIVE=1 requires AGENTCORE_POC_LIVE_RUNTIME=module:factory; "
            "the factory must return a configured LiveLifecycleRuntime"
        )
    module_name, factory_name = target.split(":", maxsplit=1)
    try:
        factory = getattr(import_module(module_name), factory_name)
        runtime = factory()
    except (AttributeError, ImportError, TypeError) as error:
        pytest.fail(f"could not load AGENTCORE_POC_LIVE_RUNTIME: {error}")
    if not callable(getattr(runtime, "run_lifecycle_measurements", None)):
        pytest.fail("AGENTCORE_POC_LIVE_RUNTIME factory did not return a LiveLifecycleRuntime")
    return cast(LiveLifecycleRuntime, runtime)


def test_live_flag_requires_lifecycle_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTCORE_POC_LIVE", "1")
    monkeypatch.delenv("AGENTCORE_POC_LIVE_RUNTIME", raising=False)

    with pytest.raises(pytest.fail.Exception, match="AGENTCORE_POC_LIVE_RUNTIME"):
        _load_live_runtime()


@pytest.mark.integration
def test_live_lifecycle_has_refresh_and_explicit_offboarding_evidence() -> None:
    result = _load_live_runtime().run_lifecycle_measurements()

    assert result["post_expiry_obo_refresh"] in {True, "unknown"}
    assert result["post_expiry_google_refresh"] in {True, "unknown"}
    assert result["latency_recorded"] is True
    assert result["cloudtrail_recorded"] is True
    assert result["offboarding_h8"] in {"pass", "failed"}
