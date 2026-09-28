from __future__ import annotations

import dataclasses
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from agentcore_platform_poc.entra import AuthError
from agentcore_platform_poc.grant import LocalSigner, issue_grant, verify_grant
from agentcore_platform_poc.unified_api.app import create_app
from agentcore_platform_poc.unified_api.runtime_client import invocation_url
from agentcore_platform_poc.unified_api.settings import UnifiedApiSettings

A = "00000000-0000-0000-0000-00000000000a"
KEY = ec.generate_private_key(ec.SECP256R1())
PEM = KEY.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
)
USER = {"ver": "2.0", "aud": "api", "oid": A, "scp": "Research.Run", "azp": "cli"}


def _settings(expiry: bool = False) -> UnifiedApiSettings:
    return UnifiedApiSettings(
        "example-tenant",
        "api",
        "not-a-secret",
        "cli",
        "runtime-app",
        "ap-southeast-1",
        "arn:aws:bedrock-agentcore:ap-southeast-1:123456789012:runtime/poc3_research-x",
        "arn:aws:bedrock-agentcore:ap-southeast-1:123456789012:runtime/poc3_bench-x",
        "research-agent",
        "bench-agent",
        "key-1",
        PEM,
        3600,
        expiry,
    )


class FakeVerifier:
    def claims(self, token: str) -> dict[str, Any]:
        if token != "user":
            raise AuthError(401, "token_invalid")
        return dict(USER)


class FakeRuntime:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def invoke(
        self, arn: str, region: str, payload: dict[str, Any], **kwargs: Any
    ) -> tuple[int, dict[str, Any]]:
        self.calls.append({"arn": arn, "payload": payload, **kwargs})
        return 200, {"summary": "done"}


def _client(expiry: bool = False) -> tuple[TestClient, FakeRuntime]:
    runtime = FakeRuntime()
    app = create_app(
        _settings(expiry),
        verifier=FakeVerifier(),
        signer=LocalSigner(KEY),
        runtime=runtime,
        clock=lambda: 1000.0,
    )  # type: ignore[arg-type]
    return TestClient(app), runtime


AUTH = {"Authorization": "Bearer user"}


def test_research_issues_grant_for_caller_and_research_agent() -> None:
    client, runtime = _client()
    response = client.post("/research", json={"prompt": "Follow brief.md"}, headers=AUTH)
    assert response.status_code == 200
    call = runtime.calls[0]
    grant = verify_grant(call["grant"], PEM, now=1001)
    assert (grant.sub, grant.agent, grant.exp - grant.iat) == (A, "research-agent", 3600)
    assert grant.sid == call["session_id"] == response.json()["session_id"]
    assert call["session_id"].startswith("poc3-") and len(call["session_id"]) == 37
    assert call["user_token"] is None and call["arn"].endswith("poc3_research-x")


def test_bench_uses_bench_agent_and_runtime() -> None:
    client, runtime = _client()
    client.post("/bench", json={"case": {"method": "direct"}}, headers=AUTH)
    call = runtime.calls[0]
    assert (
        call["arn"].endswith("poc3_bench-x")
        and verify_grant(call["grant"], PEM, now=1001).agent == "bench-agent"
    )
    assert call["payload"] == {"case": {"method": "direct"}}


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer nope"}])
def test_requires_user_token(headers: dict[str, str]) -> None:
    client, runtime = _client()
    assert client.post("/research", json={"prompt": "x"}, headers=headers).status_code == 401
    assert not runtime.calls


def test_test_mode_inputs_refused_when_off() -> None:
    client, _ = _client(expiry=False)
    for body in (
        {"prompt": "x", "mode": "raw", "user_hub_token": "u"},
        {"prompt": "x", "grant": "g"},
    ):
        assert client.post("/research", json=body, headers=AUTH).status_code == 403
    assert client.post("/grants", json={"ttl_seconds": 60}, headers=AUTH).status_code == 403


def test_expiry_mode_grant_and_raw() -> None:
    client, runtime = _client(expiry=True)
    issued = client.post("/grants", json={"ttl_seconds": 3600}, headers=AUTH).json()
    client.post("/research", json={"prompt": "x", "grant": issued["grant"]}, headers=AUTH)
    assert runtime.calls[-1]["grant"] == issued["grant"]
    client.post(
        "/research", json={"prompt": "x", "mode": "raw", "user_hub_token": "hubtok"}, headers=AUTH
    )
    assert runtime.calls[-1]["user_token"] == "hubtok" and runtime.calls[-1]["grant"] is None


def test_supplied_grant_for_other_user_or_agent_refused() -> None:
    client, _ = _client(expiry=True)
    other_user = issue_grant(
        LocalSigner(KEY),
        sub="00000000-0000-0000-0000-00000000000b",
        agent="research-agent",
        sid="s",
        ttl_seconds=60,
        now=1000,
    )
    other_agent = issue_grant(
        LocalSigner(KEY), sub=A, agent="bench-agent", sid="s", ttl_seconds=60, now=1000
    )
    for grant in (other_user, other_agent, "garbage"):
        assert (
            client.post("/research", json={"prompt": "x", "grant": grant}, headers=AUTH).status_code
            == 403
        )


def test_ttl_cap() -> None:
    client, _ = _client(expiry=True)
    assert client.post("/grants", json={"ttl_seconds": 3601}, headers=AUTH).status_code == 400


@pytest.mark.parametrize("sid", ["short", "x" * 101, "has space" + "x" * 30])
def test_bad_session_id(sid: str) -> None:
    client, _ = _client()
    assert (
        client.post("/research", json={"prompt": "x", "session_id": sid}, headers=AUTH).status_code
        == 400
    )


def test_invocation_url_encodes_arn() -> None:
    url = invocation_url(
        "ap-southeast-1", "arn:aws:bedrock-agentcore:ap-southeast-1:123456789012:runtime/r-1"
    )
    assert url == (
        "https://bedrock-agentcore.ap-southeast-1.amazonaws.com/runtimes/"
        "arn%3Aaws%3Abedrock-agentcore%3Aap-southeast-1%3A123456789012%3Aruntime%2Fr-1/invocations?qualifier=DEFAULT"
    )


def test_grant_never_outlives_the_runtime_session() -> None:
    # Task 8 ruling: each grant is capped at its runtime's max_lifetime (bench 3600 s).
    settings = dataclasses.replace(_settings(expiry=True), max_grant_ttl_s=7200)
    runtime = FakeRuntime()
    app = create_app(
        settings,
        verifier=FakeVerifier(),
        signer=LocalSigner(KEY),
        runtime=runtime,
        clock=lambda: 1000.0,
    )  # type: ignore[arg-type]
    client = TestClient(app)
    client.post("/bench", json={"case": {}}, headers=AUTH)
    bench = verify_grant(runtime.calls[-1]["grant"], PEM, now=1001)
    assert bench.exp - bench.iat == 3600
    assert (
        client.post("/grants", json={"ttl_seconds": 7200}, headers=AUTH).json()["exp"]
        == 1000 + 7200
    )


def test_grant_ttl_setting_above_the_research_runtime_lifetime_is_refused() -> None:
    env = {
        name: "v"
        for name in (
            "POC3_TENANT_ID",
            "POC3_UNIFIED_API_CLIENT_ID",
            "POC3_UNIFIED_API_CLIENT_SECRET",
            "POC3_CLI_CLIENT_ID",
            "POC3_RUNTIME_APP_ID",
            "POC3_RESEARCH_AGENT_CLIENT_ID",
            "POC3_BENCH_AGENT_CLIENT_ID",
        )
    }
    outputs = {
        name: "v"
        for name in (
            "aws_region",
            "research_runtime_arn",
            "bench_runtime_arn",
            "grant_kms_key_id",
            "grant_public_key_pem",
            "grant_signer_role_arn",
        )
    }
    assert UnifiedApiSettings.from_env(env, outputs).max_grant_ttl_s == 3600
    with pytest.raises(ValueError, match="POC3_MAX_GRANT_TTL_S"):
        UnifiedApiSettings.from_env(env | {"POC3_MAX_GRANT_TTL_S": "10801"}, outputs)
