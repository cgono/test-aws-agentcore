"""Agent configuration from Runtime environment variables (set by Terraform)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


class AgentConfigError(ValueError):
    """A required agent environment variable is missing or invalid."""


_ENV = {
    "region": "POC_REGION",
    "tenant_id": "ENTRA_TENANT_ID",
    "caller_client_id": "GATEWAY_CALLER_CLIENT_ID",
    "client_secret_arn": "GATEWAY_CLIENT_SECRET_ARN",
    "gateway_base_url": "GATEWAY_BASE_URL",
    "gateway_scope": "GATEWAY_SCOPE",
    "openai_model": "AGENT_OPENAI_MODEL",
    "anthropic_model": "AGENT_ANTHROPIC_MODEL",
}


@dataclass(frozen=True)
class AgentConfig:
    region: str
    tenant_id: str
    caller_client_id: str
    client_secret_arn: str
    gateway_base_url: str
    gateway_scope: str
    openai_model: str
    anthropic_model: str

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> AgentConfig:
        values: dict[str, str] = {}
        for field_name, env_name in _ENV.items():
            value = env.get(env_name, "").strip()
            if not value:
                raise AgentConfigError(f"{env_name} must be set")
            values[field_name] = value
        if not values["gateway_base_url"].startswith("https://"):
            raise AgentConfigError("GATEWAY_BASE_URL must use https")
        if not values["gateway_scope"].endswith("/.default"):
            raise AgentConfigError("GATEWAY_SCOPE must end with /.default")
        values["gateway_base_url"] = values["gateway_base_url"].rstrip("/")
        return cls(**values)

    @property
    def authority(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}"
