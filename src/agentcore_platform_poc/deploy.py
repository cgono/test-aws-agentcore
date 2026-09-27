"""App CD: upload a component zip and point the runtime (or Lambda) at the new S3 version."""

from __future__ import annotations

import copy
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]

# Every field UpdateAgentRuntime accepts besides the ID and artifact. Copying them from
# GetAgentRuntime keeps Terraform-owned settings unchanged (UpdateAgentRuntime replaces).
UPDATABLE_FIELDS: tuple[str, ...] = (
    "roleArn",
    "networkConfiguration",
    "description",
    "authorizerConfiguration",
    "requestHeaderConfiguration",
    "protocolConfiguration",
    "lifecycleConfiguration",
    "metadataConfiguration",
    "environmentVariables",
    "filesystemConfigurations",
    "capacityProviderConfiguration",
    "platformVersion",
)
_FAILED = frozenset({"CREATE_FAILED", "UPDATE_FAILED", "DELETE_FAILED"})


class DeployError(RuntimeError):
    """The deploy did not reach a good state. The message says what to do next."""


@dataclass(frozen=True)
class DeployResult:
    version_id: str
    runtime_version: str


def update_payload(
    current: Mapping[str, Any], *, bucket: str, key: str, version_id: str
) -> dict[str, Any]:
    payload: dict[str, Any] = {"agentRuntimeId": current["agentRuntimeId"]}
    for field in UPDATABLE_FIELDS:
        if field in current:
            payload[field] = copy.deepcopy(current[field])
    artifact = copy.deepcopy(current["agentRuntimeArtifact"])
    artifact["codeConfiguration"]["code"] = {
        "s3": {"bucket": bucket, "prefix": key, "versionId": version_id}
    }
    payload["agentRuntimeArtifact"] = artifact
    return payload


def wait_until_ready(
    client: Any,
    runtime_id: str,
    *,
    timeout_s: float = 600,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    expected_version: str | None = None,
    expected_s3_version_id: str | None = None,
) -> dict[str, Any]:
    deadline = clock() + timeout_s
    while True:
        current: dict[str, Any] = client.get_agent_runtime(agentRuntimeId=runtime_id)
        status = current.get("status")
        artifact_version = (
            current.get("agentRuntimeArtifact", {})
            .get("codeConfiguration", {})
            .get("code", {})
            .get("s3", {})
            .get("versionId")
        )
        if (
            status == "READY"
            and (expected_version is None or current.get("agentRuntimeVersion") == expected_version)
            and (expected_s3_version_id is None or artifact_version == expected_s3_version_id)
        ):
            return current
        if status in _FAILED and (
            expected_version is None or current.get("agentRuntimeVersion") == expected_version
        ):
            raise DeployError(f"runtime {runtime_id} is {status}")
        if clock() >= deadline:
            raise DeployError(f"timeout waiting for {runtime_id} (last status {status})")
        sleep(5)


def _upload(s3: Any, bucket: str, key: str, zip_path: Path) -> str:
    response = s3.put_object(Bucket=bucket, Key=key, Body=zip_path.read_bytes())
    version = response.get("VersionId")
    if not isinstance(version, str) or not version:
        raise DeployError("code bucket returned no VersionId; is versioning on?")
    return version


def deploy_runtime(
    control: Any,
    s3: Any,
    *,
    runtime_id: str,
    bucket: str,
    key: str,
    zip_path: Path | None = None,
    version_id: str | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> DeployResult:
    current = control.get_agent_runtime(agentRuntimeId=runtime_id)
    if current.get("status") != "READY" and not (
        version_id is not None and current.get("status") == "UPDATE_FAILED"
    ):
        raise DeployError(
            f"runtime {runtime_id} is not READY ({current.get('status')}); not deploying"
        )
    if version_id is None:
        if zip_path is None:
            raise DeployError("need zip_path or version_id")
        version_id = _upload(s3, bucket, key, zip_path)
    try:
        updated = control.update_agent_runtime(
            **update_payload(current, bucket=bucket, key=key, version_id=version_id)
        )
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "AWS error")
        raise DeployError(f"runtime update rejected ({code}); S3 version {version_id}") from None
    except BotoCoreError as error:
        raise DeployError(
            f"runtime update rejected ({type(error).__name__}); S3 version {version_id}"
        ) from None
    expected_version = updated.get("agentRuntimeVersion")
    if not isinstance(expected_version, str) or not expected_version:
        raise DeployError(f"runtime update returned no version; S3 version {version_id}")
    try:
        final = wait_until_ready(
            control,
            runtime_id,
            sleep=sleep,
            expected_version=expected_version,
            expected_s3_version_id=version_id,
        )
    except DeployError as error:
        raise DeployError(f"{error}; S3 version {version_id}") from error
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "AWS error")
        raise DeployError(
            f"runtime status check failed ({code}); S3 version {version_id}"
        ) from None
    except BotoCoreError as error:
        raise DeployError(
            f"runtime status check failed ({type(error).__name__}); S3 version {version_id}"
        ) from None
    return DeployResult(
        version_id=version_id, runtime_version=str(final.get("agentRuntimeVersion"))
    )


def deploy_lambda(
    lambda_client: Any,
    s3: Any,
    *,
    function_name: str,
    bucket: str,
    key: str,
    zip_path: Path | None = None,
    version_id: str | None = None,
    sleep: Callable[[float], None] = time.sleep,
    timeout_s: float = 300,
    clock: Callable[[], float] = time.monotonic,
) -> DeployResult:
    deadline = clock() + timeout_s
    while True:
        before = lambda_client.get_function_configuration(FunctionName=function_name)
        if before.get("LastUpdateStatus") != "InProgress":
            break
        if clock() >= deadline:
            raise DeployError(f"timeout waiting for Lambda {function_name} before update")
        sleep(2)
    if version_id is None:
        if zip_path is None:
            raise DeployError("need zip_path or version_id")
        version_id = _upload(s3, bucket, key, zip_path)
    try:
        updated = lambda_client.update_function_code(
            FunctionName=function_name,
            S3Bucket=bucket,
            S3Key=key,
            S3ObjectVersion=version_id,
            Publish=False,
        )
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "AWS error")
        raise DeployError(f"Lambda update rejected ({code}); S3 version {version_id}") from None
    except BotoCoreError as error:
        raise DeployError(
            f"Lambda update rejected ({type(error).__name__}); S3 version {version_id}"
        ) from None
    expected_hash = updated.get("CodeSha256")
    saw_progress = False
    while True:
        try:
            current = lambda_client.get_function_configuration(FunctionName=function_name)
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code", "AWS error")
            raise DeployError(
                f"Lambda status check failed ({code}); S3 version {version_id}"
            ) from None
        except BotoCoreError as error:
            raise DeployError(
                f"Lambda status check failed ({type(error).__name__}); S3 version {version_id}"
            ) from None
        status = current.get("LastUpdateStatus")
        if status == "InProgress":
            saw_progress = True
        if status == "Successful" and (
            expected_hash is None or current.get("CodeSha256") == expected_hash
        ):
            return DeployResult(version_id=version_id, runtime_version="$LATEST")
        if status == "Failed" and (
            expected_hash is None or current.get("CodeSha256") == expected_hash or saw_progress
        ):
            reason = current.get("LastUpdateStatusReason", "unknown reason")
            raise DeployError(
                f"Lambda {function_name} update failed: {reason}; S3 version {version_id}"
            )
        if clock() >= deadline:
            raise DeployError(
                f"timeout waiting for Lambda {function_name}; S3 version {version_id}"
            )
        sleep(2)
