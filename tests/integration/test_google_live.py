from __future__ import annotations

import os
from importlib import import_module
from typing import Protocol, cast

import pytest


class LiveGoogleRuntime(Protocol):
    """Operator-supplied live actions; no cloud credentials or OAuth values are stored here."""

    def run_google_provider_gate(self) -> dict[str, bool]: ...


def _load_live_runtime() -> LiveGoogleRuntime:
    if "AGENTCORE_POC_LIVE" not in os.environ:
        pytest.skip(
            "set AGENTCORE_POC_LIVE=1 after Google provider setup and callback registration"
        )
    target = os.environ.get("AGENTCORE_POC_LIVE_RUNTIME")
    if not target or ":" not in target:
        pytest.fail(
            "AGENTCORE_POC_LIVE=1 requires AGENTCORE_POC_LIVE_RUNTIME=module:factory; "
            "the factory must return a configured LiveGoogleRuntime"
        )
    module_name, factory_name = target.split(":", maxsplit=1)
    try:
        factory = getattr(import_module(module_name), factory_name)
        runtime = factory()
    except (AttributeError, ImportError, TypeError) as error:
        pytest.fail(f"could not load AGENTCORE_POC_LIVE_RUNTIME: {error}")
    if not callable(getattr(runtime, "run_google_provider_gate", None)):
        pytest.fail("AGENTCORE_POC_LIVE_RUNTIME factory did not return a LiveGoogleRuntime")
    return cast(LiveGoogleRuntime, runtime)


def test_live_flag_presence_requires_google_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTCORE_POC_LIVE", "1")
    monkeypatch.delenv("AGENTCORE_POC_LIVE_RUNTIME", raising=False)

    with pytest.raises(pytest.fail.Exception, match="AGENTCORE_POC_LIVE_RUNTIME"):
        _load_live_runtime()


@pytest.mark.integration
def test_live_google_provider_gate_confirms_callback_binding_and_durable_connection() -> None:
    result = _load_live_runtime().run_google_provider_gate()

    assert result == {
        "callback_bound": True,
        "durable_vault_connection": True,
        "google_consent_completed": True,
    }
