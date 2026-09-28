"""Research agent configuration from Runtime environment variables (set by Terraform)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

_ENV = {
    "region": "POC_REGION",
    "hub_url": "HUB_URL",
    "hub_scope": "HUB_SCOPE",
    "gateway_url": "GATEWAY_URL",
    "gateway_scope": "GATEWAY_SCOPE",
    "provider_name": "IDENTITY_PROVIDER",
    "code_interpreter_id": "CODE_INTERPRETER_ID",
    "model": "AGENT_MODEL",
}


@dataclass(frozen=True)
class ResearchConfig:
    region: str
    hub_url: str
    hub_scope: str
    gateway_url: str
    gateway_scope: str
    provider_name: str
    code_interpreter_id: str
    model: str

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> ResearchConfig:
        values = {}
        for field, name in _ENV.items():
            value = env.get(name, "").strip()
            if not value:
                raise ValueError(f"{name} must be set")
            values[field] = value
        for url in ("hub_url", "gateway_url"):
            if not values[url].startswith("https://"):
                raise ValueError(f"{_ENV[url]} must use https")
        return cls(**values)
