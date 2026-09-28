"""Service tokens from AgentCore Identity (Entra M2M), cached until near expiry."""

from __future__ import annotations

import asyncio
import logging
import os
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import jwt
from bedrock_agentcore.runtime.context import BedrockAgentCoreContext

logger = logging.getLogger(__name__)

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
            except Exception as error:  # SDK and botocore text can carry secrets
                # Keep the type only, and drop the chain so tracebacks cannot log the text.
                raise TokenUnavailable(type(error).__name__) from None
            self._token = str(token)
            return self._token


def write_token_file(token: str, path: Path = GATEWAY_TOKEN_FILE) -> Path:
    # mkstemp creates a new file (O_EXCL, mode 0600), so a planted file or symlink is never used.
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(token)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return path


async def refresh_token_file(
    source: IdentityTokenSource, path: Path = GATEWAY_TOKEN_FILE, interval_s: float = 60
) -> None:
    while True:
        try:
            write_token_file(await source.get(), path)
        except (TokenUnavailable, OSError) as error:
            # Keep trying: the helper refuses the file once its token expires.
            logger.warning("gateway token refresh failed error=%s", type(error).__name__)
        await asyncio.sleep(interval_s)
