"""Agent logic: every inference call goes through the gateway with an app-only JWT."""

from __future__ import annotations

import logging
import re
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from typing import Any, Protocol

import httpx
import msal  # type: ignore[import-untyped]

from agentcore_runtime_poc.runtime_agent.config import AgentConfig

BOOT_ID = uuid.uuid4().hex
_BOOTED_AT = time.monotonic()
_MAX_OUTPUT_TOKENS = 64
_ACTIONS = frozenset(
    {"whoami", "set_marker", "get_marker", "probe_egress", "chat", "chat_unauthenticated", "sleep"}
)
_SAFE_ERROR_CODE = re.compile(r"[a-z_]{1,64}")

logger = logging.getLogger(__name__)


class TokenUnavailable(RuntimeError):
    """No gateway token could be obtained. The message is an error code, never a secret."""


class TokenSource(Protocol):
    def acquire(self) -> tuple[str, bool]: ...


class MsalTokenSource:
    def __init__(
        self,
        config: AgentConfig,
        load_secret: Callable[[], str],
        app_factory: Callable[..., Any] = msal.ConfidentialClientApplication,
    ) -> None:
        self._config = config
        self._load_secret = load_secret
        self._app_factory = app_factory
        self._app: Any = None
        self._app_lock = threading.Lock()

    def acquire(self) -> tuple[str, bool]:
        # Exception text from MSAL or boto3 can carry secrets; only the type name leaves here.
        try:
            with self._app_lock:
                if self._app is None:
                    self._app = self._app_factory(
                        client_id=self._config.caller_client_id,
                        client_credential=self._load_secret(),
                        authority=self._config.authority,
                    )
            result = self._app.acquire_token_for_client(scopes=[self._config.gateway_scope])
        except Exception as error:
            raise TokenUnavailable(type(error).__name__) from error
        token = result.get("access_token")
        if not isinstance(token, str):
            code = result.get("error")
            safe = isinstance(code, str) and _SAFE_ERROR_CODE.fullmatch(code)
            raise TokenUnavailable(code if safe else "unknown")
        return token, result.get("token_source") == "cache"


def _extract_text(provider: str, data: Any) -> str:
    try:
        if provider == "openai":
            return str(data["choices"][0]["message"]["content"])
        return "".join(
            str(block.get("text", "")) for block in data["content"] if block.get("type") == "text"
        )
    except (KeyError, IndexError, TypeError, AttributeError):
        return ""


class Agent:
    def __init__(
        self,
        config: AgentConfig,
        tokens: TokenSource,
        http: httpx.Client,
        clock: Callable[[], float] = time.perf_counter,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self._config = config
        self._tokens = tokens
        self._http = http
        self._clock = clock
        self._sleeper = sleeper
        self._marker: str | None = None

    def handle(self, payload: Mapping[str, Any], session_id: str | None) -> dict[str, Any]:
        action = payload.get("action") if isinstance(payload, Mapping) else None
        result: dict[str, Any]
        if not isinstance(payload, Mapping):
            result = {"error": "bad_request"}
        elif action == "whoami":
            result = {}
        elif action == "set_marker":
            self._marker = str(payload.get("marker", ""))
            result = {"marker": self._marker}
        elif action == "get_marker":
            result = {"marker": self._marker}
        elif action == "probe_egress":
            result = self._probe_egress()
        elif action == "chat":
            result = self._chat(payload, authenticated=True)
        elif action == "chat_unauthenticated":
            result = self._chat(payload, authenticated=False)
        elif action == "sleep":
            result = self._sleep(payload)
        else:
            result = {"error": "unknown_action"}
        logger.info(
            "agent action=%s session=%s outcome=%s",
            action if action in _ACTIONS else "unknown",
            session_id,
            result.get("gateway_status", result.get("error", "ok")),
        )
        return {
            "action": action,
            "boot_id": BOOT_ID,
            "session_id": session_id,
            "uptime_s": round(time.monotonic() - _BOOTED_AT, 3),
            **result,
        }

    def _sleep(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        seconds = payload.get("seconds")
        if isinstance(seconds, bool) or not isinstance(seconds, int) or not 1 <= seconds <= 120:
            return {"error": "bad_request"}
        self._sleeper(seconds)
        return {"slept_s": seconds}

    def _probe_egress(self) -> dict[str, Any]:
        try:
            response = self._http.get(f"{self._config.gateway_base_url}/healthz")
        except httpx.HTTPError as error:
            return {"error": f"egress_failed:{type(error).__name__}"}
        return {"healthz_status": response.status_code}

    def _request(self, provider: str, prompt: str) -> tuple[str, dict[str, Any]]:
        messages = [{"role": "user", "content": prompt}]
        base = self._config.gateway_base_url
        if provider == "openai":
            return f"{base}/openai/v1/chat/completions", {
                "model": self._config.openai_model,
                "messages": messages,
                "max_completion_tokens": _MAX_OUTPUT_TOKENS,
            }
        return f"{base}/anthropic/v1/messages", {
            "model": self._config.anthropic_model,
            "max_tokens": _MAX_OUTPUT_TOKENS,
            "messages": messages,
        }

    def _chat(self, payload: Mapping[str, Any], *, authenticated: bool) -> dict[str, Any]:
        provider = payload.get("provider")
        prompt = payload.get("prompt")
        if provider not in ("openai", "anthropic") or not isinstance(prompt, str) or not prompt:
            return {"error": "bad_request"}
        started = self._clock()
        headers: dict[str, str] = {}
        cached = False
        if authenticated:
            try:
                token, cached = self._tokens.acquire()
            except TokenUnavailable as error:
                return {"error": f"token_unavailable:{error}"}
            headers["Authorization"] = f"Bearer {token}"
        token_done = self._clock()
        url, body = self._request(provider, prompt)
        try:
            response = self._http.post(url, json=body, headers=headers)
        except httpx.HTTPError as error:
            return {"error": f"gateway_unreachable:{type(error).__name__}"}
        finished = self._clock()
        result: dict[str, Any] = {
            "provider": provider,
            "gateway_status": response.status_code,
            "token_cached": cached,
            "timings_ms": {
                "token": round((token_done - started) * 1000, 1),
                "gateway": round((finished - token_done) * 1000, 1),
            },
        }
        if response.status_code == 200:
            try:
                result["text"] = _extract_text(provider, response.json())
            except ValueError:
                result["error"] = "gateway_body_invalid"
        return result
