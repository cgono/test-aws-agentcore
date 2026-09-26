"""Gateway simulation settings, read from the environment."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field


class GatewaySettingsError(ValueError):
    """A required gateway setting is missing or invalid."""


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise GatewaySettingsError(f"{name} must be set")
    return value


def _names(env: Mapping[str, str], name: str) -> frozenset[str]:
    items = frozenset(part.strip() for part in _required(env, name).split(",") if part.strip())
    if not items:
        raise GatewaySettingsError(f"{name} must list at least one value")
    return items


def _max_output_tokens(env: Mapping[str, str]) -> int:
    raw = env.get("GATEWAY_MAX_OUTPUT_TOKENS", "256")
    try:
        value = int(raw)
    except ValueError as error:
        raise GatewaySettingsError("GATEWAY_MAX_OUTPUT_TOKENS must be an integer") from error
    if not 1 <= value <= 1024:
        raise GatewaySettingsError("GATEWAY_MAX_OUTPUT_TOKENS must be between 1 and 1024")
    return value


@dataclass(frozen=True)
class GatewaySettings:
    tenant_id: str
    gateway_app_client_id: str
    allowed_caller_ids: frozenset[str]
    openai_models: frozenset[str]
    anthropic_models: frozenset[str]
    openai_api_key: str = field(repr=False)
    anthropic_api_key: str = field(repr=False)
    required_role: str = "Gateway.Invoke"
    max_output_tokens: int = 256
    max_body_bytes: int = 32_768
    max_concurrency: int = 4
    upstream_timeout_seconds: float = 30.0

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> GatewaySettings:
        return cls(
            tenant_id=_required(env, "ENTRA_TENANT_ID"),
            gateway_app_client_id=_required(env, "GATEWAY_APP_CLIENT_ID"),
            allowed_caller_ids=_names(env, "GATEWAY_ALLOWED_CALLER_IDS"),
            openai_models=_names(env, "GATEWAY_OPENAI_MODELS"),
            anthropic_models=_names(env, "GATEWAY_ANTHROPIC_MODELS"),
            openai_api_key=_required(env, "OPENAI_API_KEY"),
            anthropic_api_key=_required(env, "ANTHROPIC_API_KEY"),
            max_output_tokens=_max_output_tokens(env),
        )

    @property
    def issuer(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"

    @property
    def jwks_url(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/discovery/v2.0/keys"
