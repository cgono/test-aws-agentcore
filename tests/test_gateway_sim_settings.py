from __future__ import annotations

import pytest

from agentcore_runtime_poc.gateway_sim.settings import GatewaySettings, GatewaySettingsError

ENV = {
    "ENTRA_TENANT_ID": "example-tenant",
    "GATEWAY_APP_CLIENT_ID": "gateway-app-id",
    "GATEWAY_ALLOWED_CALLER_IDS": "caller-a, caller-b",
    "GATEWAY_OPENAI_MODELS": "model-o",
    "GATEWAY_ANTHROPIC_MODELS": "model-a1,model-a2",
    "OPENAI_API_KEY": "test-openai-key",
    "ANTHROPIC_API_KEY": "test-anthropic-key",
}


def test_from_env_parses_lists_and_defaults() -> None:
    settings = GatewaySettings.from_env(ENV)

    assert settings.allowed_caller_ids == frozenset({"caller-a", "caller-b"})
    assert settings.anthropic_models == frozenset({"model-a1", "model-a2"})
    assert settings.max_output_tokens == 256
    assert settings.issuer == "https://login.microsoftonline.com/example-tenant/v2.0"
    assert settings.jwks_url == (
        "https://login.microsoftonline.com/example-tenant/discovery/v2.0/keys"
    )


def test_repr_never_contains_provider_keys() -> None:
    rendered = repr(GatewaySettings.from_env(ENV))

    assert "test-openai-key" not in rendered
    assert "test-anthropic-key" not in rendered


@pytest.mark.parametrize("missing", sorted(ENV))
def test_every_setting_is_required(missing: str) -> None:
    env = {key: value for key, value in ENV.items() if key != missing}

    with pytest.raises(GatewaySettingsError, match=missing):
        GatewaySettings.from_env(env)


@pytest.mark.parametrize("value", ["0", "5000", "many"])
def test_max_output_tokens_is_bounded(value: str) -> None:
    with pytest.raises(GatewaySettingsError, match="GATEWAY_MAX_OUTPUT_TOKENS"):
        GatewaySettings.from_env({**ENV, "GATEWAY_MAX_OUTPUT_TOKENS": value})
