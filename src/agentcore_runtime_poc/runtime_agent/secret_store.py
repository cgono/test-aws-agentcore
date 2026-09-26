"""Read the gateway caller secret from Secrets Manager at first use."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import boto3  # type: ignore[import-untyped]


class SecretUnavailable(RuntimeError):
    """The secret has no string value (Terraform creates it empty; the operator fills it)."""


def load_client_secret(
    region: str, secret_arn: str, client_factory: Callable[..., Any] = boto3.client
) -> str:
    client = client_factory("secretsmanager", region_name=region)
    value = client.get_secret_value(SecretId=secret_arn).get("SecretString")
    if not isinstance(value, str) or not value:
        raise SecretUnavailable("client_secret_missing")
    return value
