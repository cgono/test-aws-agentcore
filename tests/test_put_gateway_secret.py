from __future__ import annotations

from typing import Any

import pytest

from scripts.put_gateway_secret import put_gateway_secret

OUTPUTS = {"aws_region": "ap-southeast-1", "gateway_secret_arn": "arn:example"}


class FakeSecrets:
    def __init__(self) -> None:
        self.kwargs: dict[str, Any] = {}

    def put_secret_value(self, **kwargs: Any) -> dict[str, Any]:
        self.kwargs = kwargs
        return {"VersionId": "v-2"}


def test_writes_secret_from_environment() -> None:
    fake = FakeSecrets()
    created: dict[str, Any] = {}

    def factory(name: str, region_name: str) -> FakeSecrets:
        created.update(name=name, region=region_name)
        return fake

    version = put_gateway_secret(
        {"GATEWAY_CALLER_CLIENT_SECRET": "secret-value"}, OUTPUTS, client_factory=factory
    )

    assert version == "v-2"
    assert fake.kwargs == {"SecretId": "arn:example", "SecretString": "secret-value"}
    assert created == {"name": "secretsmanager", "region": "ap-southeast-1"}


def test_requires_secret_in_environment() -> None:
    with pytest.raises(SystemExit, match="GATEWAY_CALLER_CLIENT_SECRET"):
        put_gateway_secret({}, OUTPUTS, client_factory=lambda *a, **k: FakeSecrets())


def test_requires_runtime_to_be_deployed() -> None:
    with pytest.raises(SystemExit, match="deploy_runtime"):
        put_gateway_secret(
            {"GATEWAY_CALLER_CLIENT_SECRET": "secret-value"},
            {"aws_region": "ap-southeast-1", "gateway_secret_arn": ""},
            client_factory=lambda *a, **k: FakeSecrets(),
        )


def test_write_failure_never_echoes_the_secret(capsys: pytest.CaptureFixture[str]) -> None:
    from botocore.exceptions import ClientError  # type: ignore[import-untyped]

    canary = "secret-" + "canary-value"

    class Failing:
        def put_secret_value(self, **kwargs: Any) -> dict[str, Any]:
            raise ClientError(
                {"Error": {"Code": "ValidationException", "Message": f"bad {canary}"}},
                "PutSecretValue",
            )

    with pytest.raises(SystemExit) as caught:
        put_gateway_secret(
            {"GATEWAY_CALLER_CLIENT_SECRET": canary},
            OUTPUTS,
            client_factory=lambda *a, **k: Failing(),
        )

    assert str(caught.value) == "put_secret_value failed: ValidationException"
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__ is True
