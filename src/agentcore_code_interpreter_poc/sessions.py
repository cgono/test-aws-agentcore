"""Open Code Interpreter sessions with guaranteed cleanup, as an external caller."""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterator, Mapping
from typing import Any

import boto3  # type: ignore[import-untyped]
from bedrock_agentcore.tools.code_interpreter_client import DEFAULT_IDENTIFIER, CodeInterpreter
from botocore.exceptions import ClientError  # type: ignore[import-untyped]

BUILTIN_IDENTIFIER: str = DEFAULT_IDENTIFIER


@contextlib.contextmanager
def open_session(
    region: str,
    *,
    boto_session: Any = None,
    identifier: str = BUILTIN_IDENTIFIER,
    timeout_seconds: int = 900,
    tolerate_stop_errors: bool = False,
) -> Iterator[CodeInterpreter]:
    client = CodeInterpreter(region, session=boto_session)
    client.start(identifier=identifier, session_timeout_seconds=timeout_seconds)
    try:
        yield client
    finally:
        try:
            client.stop()
        except ClientError:
            # Only probes that outlive the session TTL expect this: the session is already gone.
            if not tolerate_stop_errors:
                raise


def assume_role_session(
    role_arn: str,
    region: str,
    *,
    session_policy: Mapping[str, Any] | None = None,
    base_session: Any = None,
) -> Any:
    source = base_session if base_session is not None else boto3.Session(region_name=region)
    sts = source.client("sts", region_name=region)
    request: dict[str, Any] = {"RoleArn": role_arn, "RoleSessionName": "agentcore-ci-poc"}
    if session_policy is not None:
        request["Policy"] = json.dumps(session_policy)
    credentials = sts.assume_role(**request)["Credentials"]
    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region,
    )
