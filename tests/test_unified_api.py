from __future__ import annotations

import dataclasses
import threading
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from agentcore_platform_poc.entra import AuthError
from agentcore_platform_poc.grant import LocalSigner, issue_grant, verify_grant
from agentcore_platform_poc.unified_api import runtime_client
from agentcore_platform_poc.unified_api.app import AssumedRoleKmsSigner, create_app
from agentcore_platform_poc.unified_api.runtime_client import (
    RuntimeClient,
    RuntimeTokenError,
    invocation_url,
    msal_runtime_token,
)
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


@pytest.mark.parametrize("route", ["/research", "/bench", "/grants"])
@pytest.mark.parametrize("raw", [b"not json", b"null", b"[1]"])
def test_body_must_be_a_json_object(route: str, raw: bytes) -> None:
    client, runtime = _client(expiry=True)
    response = client.post(route, content=raw, headers=AUTH | {"content-type": "application/json"})
    assert response.status_code == 400 and response.json() == {"error": "bad_json"}
    assert not runtime.calls


def test_prompt_over_the_runtime_limit_is_refused() -> None:
    client, runtime = _client()
    assert client.post("/research", json={"prompt": "x" * 4001}, headers=AUTH).status_code == 400
    assert client.post("/research", json={"prompt": "x" * 4000}, headers=AUTH).status_code == 200
    assert len(runtime.calls) == 1


@pytest.mark.parametrize(
    "body",
    [
        {"prompt": "x", "mode": "Raw", "user_hub_token": "u"},
        {"prompt": "x", "mode": 5},
        {"prompt": "x", "mode": "raw", "user_hub_token": "u", "grant": "g"},
        {"prompt": "x", "mode": "grant", "user_hub_token": "u"},
    ],
)
def test_unknown_mode_or_conflicting_inputs_are_refused(body: dict[str, Any]) -> None:
    client, runtime = _client(expiry=True)
    assert client.post("/research", json=body, headers=AUTH).status_code == 400
    assert not runtime.calls


def test_supplied_grant_runs_in_its_own_session() -> None:
    client, runtime = _client(expiry=True)
    issued = client.post("/grants", json={"ttl_seconds": 600}, headers=AUTH).json()["grant"]
    sid = verify_grant(issued, PEM, now=1001).sid
    response = client.post("/research", json={"prompt": "x", "grant": issued}, headers=AUTH)
    assert response.json()["session_id"] == runtime.calls[-1]["session_id"] == sid
    other = "poc3-" + "0" * 32
    body = {"prompt": "x", "grant": issued, "session_id": other}
    assert client.post("/research", json=body, headers=AUTH).status_code == 400
    assert len(runtime.calls) == 1


@pytest.mark.parametrize("token", ["a\r\nX-Evil: 1", "a b", "é"])
def test_raw_token_with_unsafe_characters_is_refused(token: str) -> None:
    client, runtime = _client(expiry=True)
    body = {"prompt": "x", "mode": "raw", "user_hub_token": token}
    assert client.post("/research", json=body, headers=AUTH).status_code == 400
    assert not runtime.calls


class FailingRuntime(FakeRuntime):
    def __init__(self, error: Exception) -> None:
        super().__init__()
        self.error = error

    async def invoke(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, Any]]:
        raise self.error


@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (httpx.ConnectTimeout("secret-host"), 504, "runtime_timeout"),
        (httpx.ConnectError("secret-host"), 502, "runtime_unavailable"),
        (RuntimeTokenError("secret tenant"), 502, "runtime_unavailable"),
    ],
)
def test_runtime_failures_are_sanitized(error: Exception, status: int, code: str) -> None:
    app = create_app(
        _settings(),
        verifier=FakeVerifier(),
        signer=LocalSigner(KEY),
        runtime=FailingRuntime(error),  # type: ignore[arg-type]
        clock=lambda: 1000.0,
    )  # type: ignore[arg-type]
    response = TestClient(app).post("/research", json={"prompt": "x"}, headers=AUTH)
    assert (response.status_code, response.json()) == (status, {"error": code})


async def test_runtime_token_is_fetched_off_the_event_loop() -> None:
    loop_thread = threading.get_ident()
    seen: list[int] = []

    def token() -> str:
        seen.append(threading.get_ident())
        return "t"

    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"ok": True}))
    async with httpx.AsyncClient(transport=transport) as http:
        status, body = await RuntimeClient(http, token).invoke(
            "arn:x", "ap-southeast-1", {}, session_id="s", grant="g", user_token=None
        )
    assert (status, body) == (200, {"ok": True}) and seen and seen[0] != loop_thread


def test_msal_failure_is_a_runtime_token_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class Boom:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def acquire_token_for_client(self, scopes: list[str]) -> dict[str, Any]:
            raise OSError("network secret")

    monkeypatch.setattr(runtime_client.msal, "ConfidentialClientApplication", Boom)
    with pytest.raises(RuntimeTokenError) as caught:
        msal_runtime_token(_settings())()
    assert "secret" not in str(caught.value) and caught.value.__cause__ is None


class FakeSts:
    def __init__(self) -> None:
        self.calls = 0

    def assume_role(self, **kwargs: Any) -> dict[str, Any]:
        self.calls += 1
        expires = datetime.fromtimestamp(1000 + 3600, tz=UTC)
        creds = {"AccessKeyId": f"k{self.calls}", "SecretAccessKey": "s", "SessionToken": "t"}
        return {"Credentials": creds | {"Expiration": expires}}


def test_signer_refreshes_assumed_role_credentials_before_they_expire() -> None:
    now = [1000.0]
    made: list[str] = []

    class FakeKms:
        def __init__(self, key: str) -> None:
            self.key = key

        def sign(self, **kwargs: Any) -> dict[str, Any]:
            der = KEY.sign(kwargs["Message"], ec.ECDSA(hashes.SHA256()))
            return {"Signature": der}

    def kms_factory(creds: dict[str, Any]) -> FakeKms:
        made.append(creds["AccessKeyId"])
        return FakeKms(creds["AccessKeyId"])

    sts = FakeSts()
    signer = AssumedRoleKmsSigner(
        sts, "arn:role", "key-1", kms_factory=kms_factory, clock=lambda: now[0]
    )
    signer.sign(b"m")
    now[0] = 1000 + 3000  # still more than 5 minutes left
    signer.sign(b"m")
    assert made == ["k1"]
    now[0] = 1000 + 3400  # inside the refresh margin
    signer.sign(b"m")
    assert made == ["k1", "k2"] and sts.calls == 2
