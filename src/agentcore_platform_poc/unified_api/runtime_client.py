"""Invoke AgentCore Runtime over HTTPS with an Entra bearer token (JWT inbound auth, no SigV4)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

import httpx
import msal  # type: ignore[import-untyped]

from agentcore_platform_poc.unified_api.settings import UnifiedApiSettings

GRANT_HEADER = "X-Amzn-Bedrock-AgentCore-Runtime-Custom-Grant"
USER_TOKEN_HEADER = "X-Amzn-Bedrock-AgentCore-Runtime-Custom-User-Token"  # noqa: S105 - a name
SESSION_HEADER = "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id"


def invocation_url(region: str, arn: str) -> str:
    return (
        f"https://bedrock-agentcore.{region}.amazonaws.com/runtimes/"
        f"{quote(arn, safe='')}/invocations?qualifier=DEFAULT"
    )


class RuntimeTokenError(RuntimeError):
    """The unified API could not get its token for the Runtime; the text is a code only."""


def msal_runtime_token(settings: UnifiedApiSettings) -> Callable[[], str]:
    app = msal.ConfidentialClientApplication(
        settings.client_id,
        client_credential=settings.client_secret,
        authority=f"https://login.microsoftonline.com/{settings.tenant_id}",
    )

    def token() -> str:
        try:
            result = app.acquire_token_for_client(
                scopes=[f"api://{settings.runtime_app_id}/.default"]
            )
        except Exception as error:  # noqa: BLE001 - MSAL/requests errors carry URLs and text
            raise RuntimeTokenError(f"runtime token failed: {type(error).__name__}") from None
        if "access_token" not in result:
            raise RuntimeTokenError(f"runtime token failed: {result.get('error', 'unknown')}")
        return str(result["access_token"])

    return token


class RuntimeClient:
    def __init__(self, http: httpx.AsyncClient, token: Callable[[], str]) -> None:
        self._http = http
        self._token = token

    async def invoke(
        self,
        arn: str,
        region: str,
        payload: dict[str, Any],
        *,
        session_id: str,
        grant: str | None,
        user_token: str | None,
    ) -> tuple[int, dict[str, Any]]:
        token = await asyncio.to_thread(self._token)  # MSAL is blocking network I/O
        headers = {
            "authorization": f"Bearer {token}",
            "content-type": "application/json",
            SESSION_HEADER: session_id,
        }
        if grant:
            headers[GRANT_HEADER] = grant
        if user_token:
            headers[USER_TOKEN_HEADER] = user_token
        response = await self._http.post(
            invocation_url(region, arn), json=payload, headers=headers, timeout=900.0
        )
        try:
            body = response.json()
        except ValueError:
            body = {"error": "non_json_body", "content_type": response.headers.get("content-type")}
        return response.status_code, body if isinstance(body, dict) else {"value": body}
