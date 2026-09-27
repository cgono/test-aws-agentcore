from __future__ import annotations

from typing import Any

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError

from agentcore_platform_poc.deploy import (
    UPDATABLE_FIELDS,
    DeployError,
    deploy_lambda,
    deploy_runtime,
    update_payload,
    wait_until_ready,
)

CURRENT: dict[str, Any] = {
    "agentRuntimeId": "poc3_research-abc",
    "agentRuntimeArn": (
        "arn:aws:bedrock-agentcore:ap-southeast-1:123456789012:runtime/poc3_research-abc"
    ),
    "agentRuntimeName": "poc3_research",
    "agentRuntimeVersion": "3",
    "status": "READY",
    "description": "research",
    "roleArn": "arn:aws:iam::123456789012:role/poc3_research_execution",
    "agentRuntimeArtifact": {
        "codeConfiguration": {
            "code": {"s3": {"bucket": "b", "prefix": "bootstrap/research.zip", "versionId": "v0"}},
            "runtime": "PYTHON_3_13",
            "entryPoint": ["main.py"],
        }
    },
    "networkConfiguration": {"networkMode": "PUBLIC"},
    "protocolConfiguration": {"serverProtocol": "HTTP"},
    "platformVersion": "1.0",
    "lifecycleConfiguration": {"idleRuntimeSessionTimeout": 900, "maxLifetime": 7200},
    "environmentVariables": {"POC_REGION": "ap-southeast-1"},
    "authorizerConfiguration": {
        "customJWTAuthorizer": {
            "discoveryUrl": "https://login.example.test/.well-known/openid-configuration"
        }
    },
    "requestHeaderConfiguration": {
        "requestHeaderAllowlist": ["X-Amzn-Bedrock-AgentCore-Runtime-Custom-Grant"]
    },
    "createdAt": "2026-09-27T00:00:00Z",
    "lastUpdatedAt": "2026-09-27T00:00:00Z",
    "workloadIdentityDetails": {"workloadIdentityArn": "arn:x"},
    "ResponseMetadata": {"HTTPStatusCode": 200},
}


def test_payload_copies_every_updatable_field_and_changes_only_the_artifact_object() -> None:
    payload = update_payload(CURRENT, bucket="b", key="releases/research.zip", version_id="v9")
    assert payload["agentRuntimeId"] == "poc3_research-abc"
    assert payload["agentRuntimeArtifact"]["codeConfiguration"]["code"]["s3"] == {
        "bucket": "b",
        "prefix": "releases/research.zip",
        "versionId": "v9",
    }
    for field in (
        "roleArn",
        "description",
        "networkConfiguration",
        "protocolConfiguration",
        "lifecycleConfiguration",
        "environmentVariables",
        "authorizerConfiguration",
        "requestHeaderConfiguration",
        "platformVersion",
    ):
        assert payload[field] == CURRENT[field]
    assert payload["agentRuntimeArtifact"]["codeConfiguration"]["entryPoint"] == ["main.py"]
    for read_only in (
        "agentRuntimeArn",
        "status",
        "createdAt",
        "workloadIdentityDetails",
        "ResponseMetadata",
        "agentRuntimeVersion",
        "agentRuntimeName",
        "lastUpdatedAt",
    ):
        assert read_only not in payload


def test_payload_does_not_mutate_input() -> None:
    before = repr(CURRENT)
    update_payload(CURRENT, bucket="b", key="k", version_id="v")
    assert repr(CURRENT) == before


def test_updatable_fields_match_installed_agentcore_sdk() -> None:
    from botocore.session import get_session

    model = get_session().get_service_model("bedrock-agentcore-control")
    members = model.operation_model("UpdateAgentRuntime").input_shape.members
    assert set(UPDATABLE_FIELDS) == set(members) - {
        "agentRuntimeId",
        "agentRuntimeArtifact",
        "clientToken",
    }


class FakeControl:
    def __init__(self, statuses: list[str]) -> None:
        self.statuses = statuses
        self.updates: list[dict[str, Any]] = []

    def get_agent_runtime(self, agentRuntimeId: str) -> dict[str, Any]:  # noqa: N803
        status = self.statuses.pop(0) if self.statuses else "READY"
        result = {**CURRENT, "status": status, "agentRuntimeVersion": "4" if self.updates else "3"}
        if self.updates:
            result["agentRuntimeArtifact"] = self.updates[-1]["agentRuntimeArtifact"]
        return result

    def update_agent_runtime(self, **kwargs: Any) -> dict[str, Any]:
        self.updates.append(kwargs)
        return {"status": "UPDATING", "agentRuntimeVersion": "4"}


def test_wait_until_ready_fails_on_update_failed() -> None:
    control = FakeControl(["UPDATING", "UPDATE_FAILED"])
    with pytest.raises(DeployError, match="UPDATE_FAILED"):
        wait_until_ready(control, "poc3_research-abc", sleep=lambda _: None)


def test_wait_until_ready_times_out() -> None:
    control = FakeControl(["UPDATING"] * 100)
    ticks = iter(range(0, 10_000, 100))
    with pytest.raises(DeployError, match="timeout"):
        wait_until_ready(
            control, "x", timeout_s=300, sleep=lambda _: None, clock=lambda: float(next(ticks))
        )


class FakeS3:
    def __init__(self) -> None:
        self.puts: list[tuple[str, str]] = []

    def put_object(self, *, Bucket: str, Key: str, Body: bytes) -> dict[str, str]:  # noqa: N803
        self.puts.append((Bucket, Key))
        return {"VersionId": "v9"}


def test_deploy_runtime_uploads_then_updates(tmp_path: Any) -> None:
    zip_path = tmp_path / "r.zip"
    zip_path.write_bytes(b"zip")
    control, s3 = FakeControl(["READY", "UPDATING", "READY"]), FakeS3()
    result = deploy_runtime(
        control,
        s3,
        runtime_id="poc3_research-abc",
        bucket="b",
        key="releases/research.zip",
        zip_path=zip_path,
        sleep=lambda _: None,
    )
    assert s3.puts == [("b", "releases/research.zip")]
    assert (
        control.updates[0]["agentRuntimeArtifact"]["codeConfiguration"]["code"]["s3"]["versionId"]
        == "v9"
    )
    assert result.version_id == "v9" and result.runtime_version == "4"


def test_deploy_runtime_rollback_skips_upload() -> None:
    control, s3 = FakeControl(["READY", "READY"]), FakeS3()
    deploy_runtime(
        control, s3, runtime_id="x", bucket="b", key="k", version_id="v1", sleep=lambda _: None
    )
    assert s3.puts == []
    assert (
        control.updates[0]["agentRuntimeArtifact"]["codeConfiguration"]["code"]["s3"]["versionId"]
        == "v1"
    )


def test_deploy_runtime_refuses_when_runtime_not_ready() -> None:
    control, s3 = FakeControl(["UPDATING"]), FakeS3()
    with pytest.raises(DeployError, match="not READY"):
        deploy_runtime(
            control, s3, runtime_id="x", bucket="b", key="k", version_id="v1", sleep=lambda _: None
        )


def test_deploy_runtime_ignores_stale_ready_after_update() -> None:
    class StaleReadyControl(FakeControl):
        stale = True

        def get_agent_runtime(self, agentRuntimeId: str) -> dict[str, Any]:  # noqa: N803
            if self.updates and self.stale:
                self.stale = False
                return {**CURRENT, "status": "READY", "agentRuntimeVersion": "3"}
            return super().get_agent_runtime(agentRuntimeId)

    control = StaleReadyControl(["READY", "UPDATING", "READY"])
    result = deploy_runtime(
        control,
        FakeS3(),
        runtime_id="x",
        bucket="b",
        key="k",
        version_id="v1",
        sleep=lambda _: None,
    )
    assert result.runtime_version == "4"
    assert control.stale is False


def test_rollback_from_failed_runtime_update_is_attempted() -> None:
    control = FakeControl(["UPDATE_FAILED", "UPDATING", "READY"])
    result = deploy_runtime(
        control,
        FakeS3(),
        runtime_id="x",
        bucket="b",
        key="k",
        version_id="v1",
        sleep=lambda _: None,
    )
    assert result.version_id == "v1"
    assert len(control.updates) == 1


def test_rollback_ignores_stale_failed_status() -> None:
    class StaleFailedControl(FakeControl):
        stale = True

        def get_agent_runtime(self, agentRuntimeId: str) -> dict[str, Any]:  # noqa: N803
            if self.updates and self.stale:
                self.stale = False
                return {**CURRENT, "status": "UPDATE_FAILED", "agentRuntimeVersion": "3"}
            return super().get_agent_runtime(agentRuntimeId)

    control = StaleFailedControl(["UPDATE_FAILED", "UPDATING", "READY"])
    result = deploy_runtime(
        control,
        FakeS3(),
        runtime_id="x",
        bucket="b",
        key="k",
        version_id="v1",
        sleep=lambda _: None,
    )
    assert result.runtime_version == "4"


def test_runtime_poll_error_keeps_uploaded_version() -> None:
    class PollErrorControl(FakeControl):
        def get_agent_runtime(self, agentRuntimeId: str) -> dict[str, Any]:  # noqa: N803
            if self.updates:
                raise ClientError(
                    {"Error": {"Code": "ExpiredToken", "Message": "expired"}}, "GetAgentRuntime"
                )
            return super().get_agent_runtime(agentRuntimeId)

    with pytest.raises(DeployError, match="S3 version v1"):
        deploy_runtime(
            PollErrorControl(["READY"]),
            FakeS3(),
            runtime_id="x",
            bucket="b",
            key="k",
            version_id="v1",
            sleep=lambda _: None,
        )


def test_runtime_poll_transport_error_keeps_uploaded_version() -> None:
    class PollErrorControl(FakeControl):
        def get_agent_runtime(self, agentRuntimeId: str) -> dict[str, Any]:  # noqa: N803
            if self.updates:
                raise EndpointConnectionError(endpoint_url="https://aws.example.test")
            return super().get_agent_runtime(agentRuntimeId)

    with pytest.raises(DeployError, match="S3 version v1"):
        deploy_runtime(
            PollErrorControl(["READY"]), FakeS3(), runtime_id="x", bucket="b", key="k",
            version_id="v1", sleep=lambda _: None,
        )


def test_update_error_reports_uploaded_version(tmp_path: Any) -> None:
    class FailingControl(FakeControl):
        def update_agent_runtime(self, **kwargs: Any) -> dict[str, Any]:
            raise ClientError(
                {"Error": {"Code": "ConflictException", "Message": "conflict"}},
                "UpdateAgentRuntime",
            )

    zip_path = tmp_path / "r.zip"
    zip_path.write_bytes(b"zip")
    with pytest.raises(DeployError, match="v9"):
        deploy_runtime(
            FailingControl(["READY"]),
            FakeS3(),
            runtime_id="x",
            bucket="b",
            key="k",
            zip_path=zip_path,
            sleep=lambda _: None,
        )


class FakeLambda:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.states = ["InProgress", "Successful"]

    def update_function_code(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return {"Version": "$LATEST"}

    def get_function_configuration(self, FunctionName: str) -> dict[str, Any]:  # noqa: N803
        return {"LastUpdateStatus": self.states.pop(0) if self.states else "Successful"}


def test_deploy_lambda_uses_object_version() -> None:
    lam, s3 = FakeLambda(), FakeS3()
    deploy_lambda(
        lam,
        s3,
        function_name="poc3-resource-hub",
        bucket="b",
        key="releases/resource-hub.zip",
        version_id="v2",
        sleep=lambda _: None,
    )
    assert lam.calls == [
        {
            "FunctionName": "poc3-resource-hub",
            "S3Bucket": "b",
            "S3Key": "releases/resource-hub.zip",
            "S3ObjectVersion": "v2",
            "Publish": False,
        }
    ]


def test_deploy_lambda_waits_for_new_code_hash() -> None:
    class StaleLambda(FakeLambda):
        def __init__(self) -> None:
            super().__init__()
            self.configurations = [
                {"LastUpdateStatus": "Successful", "CodeSha256": "old"},
                {"LastUpdateStatus": "Successful", "CodeSha256": "old"},
                {"LastUpdateStatus": "InProgress", "CodeSha256": "new"},
                {"LastUpdateStatus": "Successful", "CodeSha256": "new"},
            ]

        def update_function_code(self, **kwargs: Any) -> dict[str, Any]:
            self.calls.append(kwargs)
            return {"CodeSha256": "new"}

        def get_function_configuration(self, FunctionName: str) -> dict[str, Any]:  # noqa: N803
            return self.configurations.pop(0)

    lam = StaleLambda()
    deploy_lambda(
        lam,
        FakeS3(),
        function_name="hub",
        bucket="b",
        key="k",
        version_id="v2",
        sleep=lambda _: None,
    )
    assert lam.configurations == []


def test_lambda_ignores_stale_failed_status() -> None:
    class StaleFailedLambda(FakeLambda):
        def __init__(self) -> None:
            super().__init__()
            self.configurations = [
                {"LastUpdateStatus": "Successful", "CodeSha256": "old"},
                {"LastUpdateStatus": "Failed", "CodeSha256": "old"},
                {"LastUpdateStatus": "InProgress", "CodeSha256": "new"},
                {"LastUpdateStatus": "Successful", "CodeSha256": "new"},
            ]

        def update_function_code(self, **kwargs: Any) -> dict[str, Any]:
            return {"CodeSha256": "new"}

        def get_function_configuration(self, FunctionName: str) -> dict[str, Any]:  # noqa: N803
            return self.configurations.pop(0)

    lam = StaleFailedLambda()
    deploy_lambda(
        lam,
        FakeS3(),
        function_name="hub",
        bucket="b",
        key="k",
        version_id="v2",
        sleep=lambda _: None,
    )
    assert lam.configurations == []


def test_lambda_poll_error_keeps_s3_version() -> None:
    class PollErrorLambda(FakeLambda):
        def get_function_configuration(self, FunctionName: str) -> dict[str, Any]:  # noqa: N803
            if self.calls:
                raise ClientError(
                    {"Error": {"Code": "ExpiredToken", "Message": "expired"}},
                    "GetFunctionConfiguration",
                )
            return {"LastUpdateStatus": "Successful"}

    with pytest.raises(DeployError, match="S3 version v2"):
        deploy_lambda(
            PollErrorLambda(),
            FakeS3(),
            function_name="hub",
            bucket="b",
            key="k",
            version_id="v2",
            sleep=lambda _: None,
        )


def test_lambda_timeout_preserves_s3_version_for_retry() -> None:
    class SlowLambda(FakeLambda):
        def __init__(self) -> None:
            super().__init__()
            self.first = True

        def get_function_configuration(self, FunctionName: str) -> dict[str, Any]:  # noqa: N803
            if self.first:
                self.first = False
                return {"LastUpdateStatus": "Successful"}
            return {"LastUpdateStatus": "InProgress"}

    ticks = iter(range(100))
    with pytest.raises(DeployError, match="S3 version v2"):
        deploy_lambda(
            SlowLambda(),
            FakeS3(),
            function_name="hub",
            bucket="b",
            key="k",
            version_id="v2",
            sleep=lambda _: None,
            timeout_s=2,
            clock=lambda: float(next(ticks)),
        )


def test_cli_reports_aws_error_code_without_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from scripts import deploy_agent

    monkeypatch.setattr(
        deploy_agent,
        "load_terraform_outputs",
        lambda root: {
            "aws_region": "ap-southeast-1",
            "code_bucket": "bucket",
            "research_runtime_id": "runtime",
        },
    )
    monkeypatch.setattr(deploy_agent.boto3, "client", lambda *args, **kwargs: object())

    def fail(*args: Any, **kwargs: Any) -> None:
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "request denied"}},
            "GetAgentRuntime",
        )

    monkeypatch.setattr(deploy_agent, "deploy_runtime", fail)
    assert deploy_agent.main(["research", "--version-id", "v1"]) == 1
    assert "AccessDeniedException" in capsys.readouterr().out
