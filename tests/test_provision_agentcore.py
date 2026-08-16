from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

from agentcore_identity_poc.config import Settings
from scripts.provision_agentcore import (
    BudgetMissingError,
    ProvisioningError,
    apply_resources,
    cleanup_resources,
    main,
    plan_resources,
    render_policy_template,
    verify_budget,
    write_state,
)

SETTINGS = Settings(
    aws_region="us-west-2",
    aws_budget_name="agentcore-identity-poc-monthly",
    entra_tenant_id="tenant-id",
    entra_public_client_id="public-client-id",
    entra_api_client_id="api-client-id",
    entra_downstream_scope="api://resource/access_as_user",
    agentcore_workload_name="approved-workload",
    agentcore_second_workload_name="unapproved-workload",
    agentcore_microsoft_provider="microsoft-provider",
    agentcore_google_provider="google-provider",
    resource_api_audience="api://resource",
    resource_api_url="https://resource.example.test/metadata",
    public_base_url="https://callback.example.test",
)


def test_plan_lists_only_the_two_configured_workloads_and_microsoft_provider() -> None:
    plan = plan_resources(SETTINGS, "123456789012")

    assert plan["account_id"] == "123456789012"
    assert plan["workloads"] == [
        {"name": "approved-workload", "return_urls": []},
        {"name": "unapproved-workload", "return_urls": []},
    ]
    assert plan["provider"] == {"name": "microsoft-provider", "vendor": "MicrosoftOauth2"}


def test_final_scoped_policy_has_no_wildcard_and_denies_user_id_token_operation() -> None:
    policy_path = Path("infra/iam/scoped.json")
    policy = json.loads(policy_path.read_text(encoding="utf-8"))

    rendered = render_policy_template(
        policy,
        {
            "DIRECTORY_ARN": "arn:aws:identitystore::123456789012:identitystore/d-123",
            "WORKLOAD_ARN": "arn:aws:bedrock-agentcore:us-west-2:123456789012:workload-identity/a",
            "SECOND_WORKLOAD_ARN": (
                "arn:aws:bedrock-agentcore:us-west-2:123456789012:workload-identity/b"
            ),
            "VAULT_ARN": "arn:aws:bedrock-agentcore:us-west-2:123456789012:token-vault/default",
            "PROVIDER_ARN": (
                "arn:aws:bedrock-agentcore:us-west-2:123456789012:credential-provider/microsoft"
            ),
        },
    )

    assert "*" not in json.dumps(rendered)
    assert {
        "Effect": "Deny",
        "Action": "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
    }.items() <= rendered["Statement"][-1].items()


class MissingBudgetClient:
    def describe_budget(self, **_: object) -> object:
        raise RuntimeError("not found")


class PresentBudgetClient:
    def describe_budget(self, **_: object) -> dict[str, object]:
        return {"Budget": {"BudgetName": SETTINGS.aws_budget_name}}


class RecordingControlClient:
    def __init__(self) -> None:
        self.workloads: dict[str, dict[str, object]] = {}
        self.providers: dict[str, dict[str, object]] = {}
        self.calls: list[tuple[str, dict[str, object]]] = []

    def get_workload_identity(self, *, name: str) -> dict[str, object]:
        if name not in self.workloads:
            raise ClientError(
                {"Error": {"Code": "ResourceNotFoundException"}}, "GetWorkloadIdentity"
            )
        return self.workloads[name]

    def create_workload_identity(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("create_workload_identity", kwargs))
        name = str(kwargs["name"])
        response = {
            "name": name,
            "workloadIdentityArn": f"arn:workload:{name}",
            "allowedResourceOauth2ReturnUrls": kwargs["allowedResourceOauth2ReturnUrls"],
        }
        self.workloads[name] = response
        return response

    def get_oauth2_credential_provider(self, *, name: str) -> dict[str, object]:
        if name not in self.providers:
            raise ClientError(
                {"Error": {"Code": "ResourceNotFoundException"}},
                "GetOauth2CredentialProvider",
            )
        return self.providers[name]

    def create_oauth2_credential_provider(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("create_oauth2_credential_provider", kwargs))
        name = str(kwargs["name"])
        response = {
            "name": name,
            "credentialProviderArn": f"arn:provider:{name}",
            "callbackUrl": f"https://callback.example.test/{name}",
        }
        self.providers[name] = response
        return response

    def delete_workload_identity(self, *, name: str) -> dict[str, object]:
        self.calls.append(("delete_workload_identity", {"name": name}))
        del self.workloads[name]
        return {}

    def delete_oauth2_credential_provider(self, *, name: str) -> dict[str, object]:
        self.calls.append(("delete_oauth2_credential_provider", {"name": name}))
        del self.providers[name]
        return {}


class RecordingIamClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def put_role_policy(self, **kwargs: object) -> None:
        self.calls.append(kwargs)


def test_budget_preflight_includes_console_and_cli_remediation() -> None:
    with pytest.raises(BudgetMissingError) as raised:
        verify_budget(MissingBudgetClient(), "123456789012", SETTINGS.aws_budget_name)

    assert str(raised.value) == (
        "AWS Budget 'agentcore-identity-poc-monthly' is required before --apply. "
        "Create it in the AWS Billing console or run: aws budgets create-budget "
        "--account-id 123456789012 --budget file://budget.json"
    )


def test_write_state_is_atomic_and_private(tmp_path: Path) -> None:
    state_path = tmp_path / ".poc-state.json"

    write_state(
        state_path,
        {
            "workloads": [{"name": "approved-workload", "arn": "arn:workload"}],
            "provider": {"name": "microsoft-provider", "arn": "arn:provider", "callback_url": "https://x"},
        },
    )

    assert json.loads(state_path.read_text(encoding="utf-8"))["provider"]["arn"] == "arn:provider"
    assert stat.S_IMODE(os.stat(state_path).st_mode) == 0o600
    assert not list(tmp_path.glob(".poc-state.json.*"))


def test_apply_creates_only_absent_named_resources_and_records_returned_values(
    tmp_path: Path,
) -> None:
    control = RecordingControlClient()
    state_path = tmp_path / ".poc-state.json"

    state = apply_resources(
        SETTINGS,
        "123456789012",
        budgets_client=PresentBudgetClient(),
        control_client=control,
        state_path=state_path,
        entra_client_secret="not-logged",
    )
    again = apply_resources(
        SETTINGS,
        "123456789012",
        budgets_client=PresentBudgetClient(),
        control_client=control,
        state_path=state_path,
        entra_client_secret="not-logged",
    )

    assert [call[0] for call in control.calls] == [
        "create_workload_identity",
        "create_workload_identity",
        "create_oauth2_credential_provider",
    ]
    assert all(call[1]["tags"] == {"Project": "agentcore-identity-poc"} for call in control.calls)
    assert state["workloads"] == [
        {"name": "approved-workload", "arn": "arn:workload:approved-workload", "callback_urls": []},
        {
            "name": "unapproved-workload",
            "arn": "arn:workload:unapproved-workload",
            "callback_urls": [],
        },
    ]
    assert state["provider"] == {
        "name": "microsoft-provider",
        "arn": "arn:provider:microsoft-provider",
        "callback_url": "https://callback.example.test/microsoft-provider",
    }
    assert again == state
    assert "not-logged" not in state_path.read_text(encoding="utf-8")


def test_apply_renders_and_installs_scoped_policy_from_recorded_arns(tmp_path: Path) -> None:
    control = RecordingControlClient()
    iam = RecordingIamClient()
    state = apply_resources(
        SETTINGS,
        "123456789012",
        budgets_client=PresentBudgetClient(),
        control_client=control,
        state_path=tmp_path / ".poc-state.json",
        entra_client_secret="not-logged",
        directory_arn="arn:directory:returned",
        vault_arn="arn:vault:returned",
        iam_client=iam,
        iam_role_name="agentcore-poc-role",
    )

    assert state["directory_arn"] == "arn:directory:returned"
    assert state["vault_arn"] == "arn:vault:returned"
    assert iam.calls[0]["RoleName"] == "agentcore-poc-role"
    assert iam.calls[0]["PolicyName"] == "agentcore-identity-poc-scoped"
    policy = json.loads(str(iam.calls[0]["PolicyDocument"]))
    assert "*" not in json.dumps(policy)
    assert "bedrock-agentcore:GetWorkloadAccessTokenForUserId" in json.dumps(policy)


def test_cleanup_deletes_only_recorded_resources_after_exact_confirmation(tmp_path: Path) -> None:
    control = RecordingControlClient()
    state_path = tmp_path / ".poc-state.json"
    apply_resources(
        SETTINGS,
        "123456789012",
        budgets_client=PresentBudgetClient(),
        control_client=control,
        state_path=state_path,
        entra_client_secret="not-logged",
    )
    output: list[str] = []

    cleanup_resources(
        control,
        state_path=state_path,
        apply=True,
        confirm="agentcore-identity-poc",
        output=output.append,
    )

    assert output == [
        "Cleanup targets:",
        "provider: microsoft-provider (arn:provider:microsoft-provider)",
        "workload: approved-workload (arn:workload:approved-workload)",
        "workload: unapproved-workload (arn:workload:unapproved-workload)",
    ]
    assert [call[0] for call in control.calls[-3:]] == [
        "delete_oauth2_credential_provider",
        "delete_workload_identity",
        "delete_workload_identity",
    ]
    assert not state_path.exists()


def test_cleanup_dry_run_loads_state_and_prints_before_creating_aws_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    state_path = tmp_path / ".poc-state.json"
    write_state(
        state_path,
        {
            "version": 1,
            "workloads": [
                {"name": "approved-workload", "arn": "arn:workload:approved"},
                {"name": "unapproved-workload", "arn": "arn:workload:unapproved"},
            ],
            "provider": {
                "name": "microsoft-provider",
                "arn": "arn:provider:microsoft",
                "callback_url": "https://callback.example.test/provider",
            },
        },
    )
    monkeypatch.setattr(
        "scripts.provision_agentcore.boto3.client",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must stay local")),
    )

    assert main(["cleanup", "--state-path", str(state_path)]) == 0
    assert "arn:provider:microsoft" in capsys.readouterr().out


@pytest.mark.parametrize("contents", [None, "not-json", '{"workloads": []}'])
def test_cleanup_refuses_missing_or_malformed_state(tmp_path: Path, contents: str | None) -> None:
    state_path = tmp_path / ".poc-state.json"
    if contents is not None:
        state_path.write_text(contents, encoding="utf-8")

    with pytest.raises(ProvisioningError, match="valid .poc-state.json"):
        cleanup_resources(
            object(), state_path=state_path, apply=True, confirm="agentcore-identity-poc"
        )
