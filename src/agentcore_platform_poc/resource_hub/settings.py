# src/agentcore_platform_poc/resource_hub/settings.py
"""Resource Hub settings, read from the Lambda environment (set by Terraform)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field


@dataclass(frozen=True)
class HubSettings:
    tenant_id: str
    hub_app_id: str
    allowed_agent_ids: frozenset[str]
    grant_public_key_pem: bytes = field(repr=False)
    workspace_bucket: str
    allow_raw_user_token: bool

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> HubSettings:
        def need(name: str) -> str:
            value = env.get(name, "").strip()
            if not value:
                raise ValueError(f"{name} must be set")
            return value

        agents = frozenset(p.strip() for p in need("ALLOWED_AGENT_IDS").split(",") if p.strip())
        return cls(
            tenant_id=need("TENANT_ID"),
            hub_app_id=need("HUB_APP_ID"),
            allowed_agent_ids=agents,
            grant_public_key_pem=need("GRANT_PUBLIC_KEY_PEM").encode(),
            workspace_bucket=need("WORKSPACE_BUCKET"),
            allow_raw_user_token=env.get("ALLOW_RAW_USER_TOKEN", "false").lower() == "true",
        )
