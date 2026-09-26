from __future__ import annotations

import logging
from typing import Any

import httpx
import pytest
from bedrock_agentcore.runtime.context import RequestContext

from agentcore_runtime_poc.runtime_agent import entrypoint
from agentcore_runtime_poc.runtime_agent.agent import (
    BOOT_ID,
    Agent,
    MsalTokenSource,
    TokenUnavailable,
)
from agentcore_runtime_poc.runtime_agent.config import AgentConfig, AgentConfigError
from agentcore_runtime_poc.runtime_agent.secret_store import SecretUnavailable, load_client_secret

ENV = {
    "POC_REGION": "ap-southeast-1",
    "ENTRA_TENANT_ID": "example-tenant",
    "GATEWAY_CALLER_CLIENT_ID": "caller-a",
    "GATEWAY_CLIENT_SECRET_ARN": (
        "arn:aws:secretsmanager:ap-southeast-1:123456789012:secret:example"
    ),
    "GATEWAY_BASE_URL": "https://gateway.example.test/",
    "GATEWAY_SCOPE": "gateway-app-id/.default",
    "AGENT_OPENAI_MODEL": "model-o",
    "AGENT_ANTHROPIC_MODEL": "model-a",
}
TOKEN_VALUE = "fake-token-" + "value-123"


class FakeTokens:
    def __init__(self, cached: bool = False, fail: bool = False) -> None:
        self.cached = cached
        self.fail = fail
        self.calls = 0

    def acquire(self) -> tuple[str, bool]:
        self.calls += 1
        if self.fail:
            raise TokenUnavailable("invalid_client")
        return TOKEN_VALUE, self.cached


def _agent(handler: Any, tokens: FakeTokens | None = None) -> tuple[Agent, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    ticks = iter([0.0, 0.010, 0.250] * 10)
    agent = Agent(
        AgentConfig.from_env(ENV),
        tokens or FakeTokens(),
        httpx.Client(transport=httpx.MockTransport(record)),
        clock=lambda: next(ticks),
    )
    return agent, seen


def _openai_reply(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": "pong"}}]})


def test_config_strips_trailing_slash_and_builds_authority() -> None:
    config = AgentConfig.from_env(ENV)

    assert config.gateway_base_url == "https://gateway.example.test"
    assert config.authority == "https://login.microsoftonline.com/example-tenant"


@pytest.mark.parametrize(
    ("name", "value"),
    [("GATEWAY_BASE_URL", "http://gateway.example.test"), ("GATEWAY_SCOPE", "gateway-app-id")],
)
def test_config_rejects_insecure_url_and_non_default_scope(name: str, value: str) -> None:
    with pytest.raises(AgentConfigError, match=name):
        AgentConfig.from_env({**ENV, name: value})


def test_config_requires_every_variable() -> None:
    with pytest.raises(AgentConfigError, match="AGENT_ANTHROPIC_MODEL"):
        AgentConfig.from_env({k: v for k, v in ENV.items() if k != "AGENT_ANTHROPIC_MODEL"})


def test_openai_chat_goes_to_gateway_with_bearer_and_reports_timings() -> None:
    agent, seen = _agent(_openai_reply)

    result = agent.handle({"action": "chat", "provider": "openai", "prompt": "ping"}, "s-1")

    [request] = seen
    assert str(request.url) == "https://gateway.example.test/openai/v1/chat/completions"
    assert request.headers["authorization"] == "Bearer " + TOKEN_VALUE
    assert result["gateway_status"] == 200
    assert result["text"] == "pong"
    assert result["timings_ms"] == {"token": 10.0, "gateway": 240.0}
    assert result["boot_id"] == BOOT_ID
    assert result["session_id"] == "s-1"


def test_anthropic_chat_uses_messages_route_and_extracts_text() -> None:
    def reply(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"content": [{"type": "text", "text": "pong"}]})

    agent, seen = _agent(reply)

    result = agent.handle({"action": "chat", "provider": "anthropic", "prompt": "ping"}, "s-1")

    assert str(seen[0].url) == "https://gateway.example.test/anthropic/v1/messages"
    assert result["text"] == "pong"


def test_unauthenticated_chat_sends_no_authorization_header() -> None:
    tokens = FakeTokens()
    agent, seen = _agent(
        lambda request: httpx.Response(401, json={"error": "unauthorized"}), tokens
    )

    result = agent.handle(
        {"action": "chat_unauthenticated", "provider": "openai", "prompt": "ping"}, "s-1"
    )

    assert "authorization" not in seen[0].headers
    assert result["gateway_status"] == 401
    assert "text" not in result
    assert tokens.calls == 0


def test_token_failure_is_reported_without_calling_gateway() -> None:
    agent, seen = _agent(_openai_reply, FakeTokens(fail=True))

    result = agent.handle({"action": "chat", "provider": "openai", "prompt": "ping"}, "s-1")

    assert result["error"] == "token_unavailable:invalid_client"
    assert seen == []


def test_bad_chat_request_and_unknown_action() -> None:
    agent, _ = _agent(_openai_reply)

    assert agent.handle({"action": "chat", "provider": "bedrock", "prompt": "x"}, None)[
        "error"
    ] == ("bad_request")
    assert agent.handle({"action": "dance"}, None)["error"] == "unknown_action"


def test_marker_is_kept_in_process_memory() -> None:
    agent, _ = _agent(_openai_reply)

    assert agent.handle({"action": "get_marker"}, "s-1")["marker"] is None
    agent.handle({"action": "set_marker", "marker": "m-1"}, "s-1")
    assert agent.handle({"action": "get_marker"}, "s-1")["marker"] == "m-1"


def test_probe_egress_reports_healthz_status_and_failures() -> None:
    agent, seen = _agent(lambda request: httpx.Response(200, json={"status": "ok"}))
    assert agent.handle({"action": "probe_egress"}, None)["healthz_status"] == 200
    assert str(seen[0].url) == "https://gateway.example.test/healthz"

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    failing, _ = _agent(refuse)
    assert failing.handle({"action": "probe_egress"}, None)["error"] == "egress_failed:ConnectError"


def test_logs_never_contain_token_or_prompt(caplog: pytest.LogCaptureFixture) -> None:
    agent, _ = _agent(_openai_reply)
    prompt = "prompt-marker-" + "xyz"

    with caplog.at_level(logging.DEBUG):
        agent.handle({"action": "chat", "provider": "openai", "prompt": prompt}, "s-1")

    assert "action=chat session=s-1" in caplog.text
    assert TOKEN_VALUE not in caplog.text
    assert prompt not in caplog.text


class FakeMsalApp:
    def __init__(self, results: list[dict[str, Any]]) -> None:
        self.results = results
        self.scopes: list[list[str]] = []

    def acquire_token_for_client(self, scopes: list[str]) -> dict[str, Any]:
        self.scopes.append(scopes)
        return self.results.pop(0)


def test_msal_token_source_loads_secret_once_and_reports_cache_hits() -> None:
    loads: list[int] = []
    created: dict[str, Any] = {}
    fake_app = FakeMsalApp(
        [
            {"access_token": "t1", "token_source": "identity_provider"},
            {"access_token": "t1", "token_source": "cache"},
        ]
    )

    def factory(**kwargs: Any) -> FakeMsalApp:
        created.update(kwargs)
        return fake_app

    source = MsalTokenSource(
        AgentConfig.from_env(ENV), lambda: loads.append(1) or "secret-value", app_factory=factory
    )

    assert source.acquire() == ("t1", False)
    assert source.acquire() == ("t1", True)
    assert loads == [1]
    assert created["client_id"] == "caller-a"
    assert created["authority"] == "https://login.microsoftonline.com/example-tenant"
    assert fake_app.scopes == [["gateway-app-id/.default"], ["gateway-app-id/.default"]]


def test_msal_token_source_maps_errors() -> None:
    source = MsalTokenSource(
        AgentConfig.from_env(ENV),
        lambda: "secret-value",
        app_factory=lambda **kwargs: FakeMsalApp([{"error": "invalid_client"}]),
    )
    with pytest.raises(TokenUnavailable, match="invalid_client"):
        source.acquire()

    def broken_secret() -> str:
        raise SecretUnavailable("client_secret_missing")

    no_secret = MsalTokenSource(AgentConfig.from_env(ENV), broken_secret)
    with pytest.raises(TokenUnavailable, match="SecretUnavailable"):
        no_secret.acquire()


class FakeSecrets:
    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        self.kwargs: dict[str, Any] = {}

    def get_secret_value(self, **kwargs: Any) -> dict[str, Any]:
        self.kwargs = kwargs
        return self.response


def test_load_client_secret_reads_secret_string() -> None:
    fake = FakeSecrets({"SecretString": "secret-value"})

    value = load_client_secret(
        "ap-southeast-1", "arn:example", client_factory=lambda name, region_name: fake
    )

    assert value == "secret-value"
    assert fake.kwargs == {"SecretId": "arn:example"}


def test_load_client_secret_without_value_raises() -> None:
    fake = FakeSecrets({})

    with pytest.raises(SecretUnavailable):
        load_client_secret(
            "ap-southeast-1", "arn:example", client_factory=lambda n, region_name: fake
        )


def test_entrypoint_delegates_with_session_id(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[dict[str, Any], str | None]] = []

    class Recorder:
        def handle(self, payload: dict[str, Any], session_id: str | None) -> dict[str, Any]:
            calls.append((payload, session_id))
            return {"ok": True}

    monkeypatch.setattr(entrypoint, "get_agent", lambda: Recorder())

    result = entrypoint.invoke({"action": "whoami"}, RequestContext(session_id="s-9"))

    assert result == {"ok": True}
    assert calls == [({"action": "whoami"}, "s-9")]


def test_get_agent_builds_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in ENV.items():
        monkeypatch.setenv(name, value)
    entrypoint._build_agent.cache_clear()

    agent = entrypoint.get_agent()

    assert isinstance(agent, Agent)
    assert entrypoint.get_agent() is agent
    entrypoint._build_agent.cache_clear()


def test_sleep_action_is_bounded() -> None:
    slept: list[float] = []
    agent = Agent(
        AgentConfig.from_env(ENV),
        FakeTokens(),
        httpx.Client(transport=httpx.MockTransport(_openai_reply)),
        sleeper=slept.append,
    )

    assert agent.handle({"action": "sleep", "seconds": 5}, "s-1")["slept_s"] == 5
    assert agent.handle({"action": "sleep", "seconds": 500}, "s-1")["error"] == "bad_request"
    assert slept == [5]


def test_configure_logging_enables_agent_info_logs_once() -> None:
    logger = logging.getLogger("agentcore_runtime_poc")
    logger.handlers.clear()

    entrypoint.configure_logging()
    entrypoint.configure_logging()

    assert logger.level == logging.INFO
    assert len(logger.handlers) == 1
    logger.handlers.clear()
    logger.setLevel(logging.NOTSET)


def test_main_binds_all_interfaces_on_port_8080(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(entrypoint, "configure_logging", lambda: None)
    monkeypatch.setattr(entrypoint.app, "run", lambda **kwargs: calls.append(kwargs))

    entrypoint.main()

    assert calls == [{"host": "0.0.0.0", "port": 8080}]  # noqa: S104


@pytest.mark.parametrize(
    ("factory_error", "result", "expected"),
    [
        (True, {}, "RuntimeError"),
        (False, {"error": "Bearer leaked-value"}, "unknown"),
    ],
    ids=["factory raises", "unsafe error code"],
)
def test_msal_token_source_maps_unexpected_failures_to_safe_codes(
    factory_error: bool, result: dict[str, Any], expected: str
) -> None:
    def factory(**kwargs: Any) -> FakeMsalApp:
        if factory_error:
            raise RuntimeError("authority discovery failed: secret-value")
        return FakeMsalApp([result])

    source = MsalTokenSource(AgentConfig.from_env(ENV), lambda: "secret-value", app_factory=factory)

    with pytest.raises(TokenUnavailable) as caught:
        source.acquire()
    assert str(caught.value) == expected


def test_msal_acquire_exception_is_mapped() -> None:
    class Raising:
        def acquire_token_for_client(self, scopes: list[str]) -> dict[str, Any]:
            raise ConnectionError("network down")

    source = MsalTokenSource(
        AgentConfig.from_env(ENV), lambda: "secret-value", app_factory=lambda **k: Raising()
    )
    with pytest.raises(TokenUnavailable, match="^ConnectionError$"):
        source.acquire()


def test_msal_app_is_built_once_under_concurrent_first_use() -> None:
    import threading
    import time as time_module

    built: list[int] = []

    def factory(**kwargs: Any) -> FakeMsalApp:
        time_module.sleep(0.05)
        built.append(1)
        return FakeMsalApp([{"access_token": "t"} for _ in range(8)])

    source = MsalTokenSource(AgentConfig.from_env(ENV), lambda: "secret-value", app_factory=factory)
    threads = [threading.Thread(target=source.acquire) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert built == [1]


def test_get_agent_is_built_once_under_concurrent_first_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import threading
    import time as time_module

    for name, value in ENV.items():
        monkeypatch.setenv(name, value)
    real_from_env = AgentConfig.from_env

    def slow_from_env(env: Any) -> AgentConfig:
        time_module.sleep(0.05)
        return real_from_env(env)

    monkeypatch.setattr(entrypoint.AgentConfig, "from_env", slow_from_env)
    entrypoint._build_agent.cache_clear()
    agents: list[Agent] = []
    threads = [
        threading.Thread(target=lambda: agents.append(entrypoint.get_agent())) for _ in range(8)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    entrypoint._build_agent.cache_clear()

    assert len({id(agent) for agent in agents}) == 1


def test_unknown_action_is_not_logged_verbatim(caplog: pytest.LogCaptureFixture) -> None:
    agent, _ = _agent(_openai_reply)
    secret_like = "prompt-" + "in-action"

    with caplog.at_level(logging.INFO):
        result = agent.handle({"action": secret_like}, "s-1")

    assert result["error"] == "unknown_action"
    assert secret_like not in caplog.text
    assert "action=unknown session=s-1" in caplog.text


def test_gateway_success_with_invalid_json_is_reported() -> None:
    agent, _ = _agent(lambda request: httpx.Response(200, content=b"not json"))

    result = agent.handle({"action": "chat", "provider": "openai", "prompt": "ping"}, "s-1")

    assert result["gateway_status"] == 200
    assert result["error"] == "gateway_body_invalid"
    assert "text" not in result


@pytest.mark.parametrize("payload", [["chat"], "chat", None])
def test_non_object_payload_is_bad_request(payload: Any) -> None:
    agent, _ = _agent(_openai_reply)

    result = agent.handle(payload, "s-1")

    assert result["error"] == "bad_request"
    assert result["action"] is None
