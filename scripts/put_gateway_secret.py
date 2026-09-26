"""Write the gateway caller secret into the Terraform-created secret. The value comes from env."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import boto3  # type: ignore[import-untyped]
from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]

from scripts.terraform_outputs import load_terraform_outputs


def put_gateway_secret(
    env: Mapping[str, str],
    outputs: Mapping[str, str],
    client_factory: Callable[..., Any] = boto3.client,
) -> str:
    secret = env.get("GATEWAY_CALLER_CLIENT_SECRET", "")
    if not secret:
        raise SystemExit("GATEWAY_CALLER_CLIENT_SECRET must be set in the environment")
    secret_arn = outputs.get("gateway_secret_arn", "")
    if not secret_arn:
        raise SystemExit("gateway_secret_arn is empty: apply with TF_VAR_deploy_runtime=true first")
    client = client_factory("secretsmanager", region_name=outputs["aws_region"])
    try:
        response = client.put_secret_value(SecretId=secret_arn, SecretString=secret)
    except (BotoCoreError, ClientError) as error:
        # Only the error code: service messages and tracebacks could echo the secret value.
        code = (
            error.response["Error"].get("Code", "unknown")
            if isinstance(error, ClientError)
            else type(error).__name__
        )
        raise SystemExit(f"put_secret_value failed: {code}") from None
    return str(response["VersionId"])


def main() -> int:
    version = put_gateway_secret(os.environ, load_terraform_outputs(Path("infra/terraform/poc")))
    print(f"stored secret version {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
