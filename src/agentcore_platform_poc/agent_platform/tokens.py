"""Service tokens from AgentCore Identity (Entra M2M), cached until near expiry."""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import jwt
from bedrock_agentcore.runtime.context import BedrockAgentCoreContext

GATEWAY_TOKEN_FILE = Path("/tmp/poc3-gateway-token")  # noqa: S108 - Runtime microVM, per session


class TokenUnavailable(RuntimeError):
    """No token could be obtained. The message is an error code, never a secret."""


def _exp(token: str) -> float:
    exp = jwt.decode(token, options={"verify_signature": False}).get("exp")
    return float(exp) if isinstance(exp, int | float) else 0.0


class IdentityTokenSource:
    def __init__(
        self,
        provider_name: str,
        scope: str,
        region: str,
        *,
        client: Any | None = None,
        workload_token: Callable[
            [], str | None
        ] = BedrockAgentCoreContext.get_workload_access_token,
        clock: Callable[[], float] = time.time,
        refresh_margin_s: float = 300,
    ) -> None:
        if client is None:
            from bedrock_agentcore.services.identity import IdentityClient

            client = IdentityClient(region)
        self._client = client
        self._provider = provider_name
        self._scope = scope
        self._workload_token = workload_token
        self._clock = clock
        self._margin = refresh_margin_s
        self._token: str | None = None
        self._lock = asyncio.Lock()

    async def get(self) -> str:
        async with self._lock:
            if self._token is not None and _exp(self._token) - self._margin > self._clock():
                return self._token
            workload = self._workload_token()
            if not workload:
                raise TokenUnavailable("no_workload_token")
            try:
                token = await self._client.get_token(
                    provider_name=self._provider,
                    scopes=[self._scope],
                    agent_identity_token=workload,
                    auth_flow="M2M",
                )
            except (
                Exception
            ) as error:  # SDK and botocore text can carry secrets; keep the type only
                raise TokenUnavailable(type(error).__name__) from error
            self._token = str(token)
            return self._token


def write_token_file(token: str, path: Path = GATEWAY_TOKEN_FILE) -> Path:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(token)
    os.replace(tmp, path)
    return path


async def refresh_token_file(
    source: IdentityTokenSource, path: Path = GATEWAY_TOKEN_FILE, interval_s: float = 60
) -> None:
    while True:
        write_token_file(await source.get(), path)
        await asyncio.sleep(interval_s)
