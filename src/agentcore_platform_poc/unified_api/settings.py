"""Unified API settings: .env values plus platform Terraform outputs."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

# Mirrors max_lifetime_seconds in infra/terraform/platform/runtimes.tf.
RESEARCH_MAX_LIFETIME_S = 10800
BENCH_MAX_LIFETIME_S = 3600


@dataclass(frozen=True)
class UnifiedApiSettings:
    tenant_id: str
    client_id: str
    client_secret: str = field(repr=False)
    cli_client_id: str
    runtime_app_id: str
    region: str
    research_runtime_arn: str
    bench_runtime_arn: str
    research_agent_id: str
    bench_agent_id: str
    kms_key_id: str
    grant_public_key_pem: bytes = field(repr=False)
    max_grant_ttl_s: int = 3600
    expiry_test_mode: bool = False
    signer_role_arn: str = ""

    def __post_init__(self) -> None:
        # A grant must not outlive the Runtime session it is for (runtimes.tf max_lifetime_seconds).
        if not 0 < self.max_grant_ttl_s <= RESEARCH_MAX_LIFETIME_S:
            raise ValueError(f"POC3_MAX_GRANT_TTL_S must be 1..{RESEARCH_MAX_LIFETIME_S}")

    @classmethod
    def from_env(cls, env: Mapping[str, str], outputs: Mapping[str, str]) -> UnifiedApiSettings:
        def need(source: Mapping[str, str], name: str) -> str:
            value = source.get(name, "").strip()
            if not value:
                raise ValueError(f"{name} must be set")
            return value

        return cls(
            tenant_id=need(env, "POC3_TENANT_ID"),
            client_id=need(env, "POC3_UNIFIED_API_CLIENT_ID"),
            client_secret=need(env, "POC3_UNIFIED_API_CLIENT_SECRET"),
            cli_client_id=need(env, "POC3_CLI_CLIENT_ID"),
            runtime_app_id=need(env, "POC3_RUNTIME_APP_ID"),
            region=need(outputs, "aws_region"),
            research_runtime_arn=need(outputs, "research_runtime_arn"),
            bench_runtime_arn=need(outputs, "bench_runtime_arn"),
            research_agent_id=need(env, "POC3_RESEARCH_AGENT_CLIENT_ID"),
            bench_agent_id=need(env, "POC3_BENCH_AGENT_CLIENT_ID"),
            kms_key_id=need(outputs, "grant_kms_key_id"),
            grant_public_key_pem=need(outputs, "grant_public_key_pem").encode(),
            max_grant_ttl_s=int(env.get("POC3_MAX_GRANT_TTL_S", "3600")),
            expiry_test_mode=env.get("POC3_EXPIRY_TEST_MODE", "false").lower() == "true",
            signer_role_arn=need(outputs, "grant_signer_role_arn"),
        )
