"""Minimal Entra device-code authentication boundary."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Protocol, cast

import msal  # type: ignore[import-untyped]


class DeviceFlowClient(Protocol):
    """The narrow MSAL surface required for the device-code flow."""

    def initiate_device_flow(self, *, scopes: list[str]) -> Mapping[str, object]: ...

    def acquire_token_by_device_flow(self, flow: Mapping[str, object]) -> Mapping[str, object]: ...


class EntraAuthError(RuntimeError):
    """An Entra authentication response without any provider payload."""

    def __init__(self, error_code: str) -> None:
        self.error_code = error_code
        super().__init__(
            f"Entra device authentication failed: {error_code}: authentication not completed"
        )


class EntraDeviceAuth:
    """Acquire a device-code token for exactly the configured worker scopes."""

    def __init__(self, client: DeviceFlowClient, scopes: Sequence[str]) -> None:
        self._client = client
        self._scopes = list(scopes)

    @classmethod
    def for_tenant(cls, client_id: str, tenant_id: str, scopes: Sequence[str]) -> EntraDeviceAuth:
        authority = f"https://login.microsoftonline.com/{tenant_id}"
        client = cast(
            DeviceFlowClient,
            msal.PublicClientApplication(client_id, authority=authority),
        )
        return cls(client, scopes)

    def acquire(self, display: Callable[[str], None]) -> str:
        flow = self._client.initiate_device_flow(scopes=self._scopes)
        message = flow.get("message")
        if not isinstance(message, str) or not message:
            raise EntraAuthError(_error_code(flow))
        display(message)

        result = self._client.acquire_token_by_device_flow(flow)
        access_token = result.get("access_token")
        if isinstance(access_token, str) and access_token:
            return access_token
        raise EntraAuthError(_error_code(result))


def _error_code(response: Mapping[str, object]) -> str:
    error = response.get("error")
    return error if isinstance(error, str) and error else "unknown_error"
