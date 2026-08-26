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
    confirm_google_callback,
    create_google_provider,
    google_phase_two_plan,
    install_scoped_policy,
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
            "SECRET_ARN": (
                "arn:aws:secretsmanager:us-west-2:123456789012:secret:"
                "bedrock-agentcore-identity!default/oauth2/microsoft-abc123"
            ),
        },
    )

    assert "*" not in json.dumps(rendered)
    assert {
        "Effect": "Deny",
        "Action": "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
    }.items() <= rendered["Statement"][-1].items()


def test_install_scoped_policy_grants_the_google_provider_when_it_exists_in_state() -> None:
    """A Google provider created after the initial --apply must not be silently ungranted.

    `.poc-state.json` can record `google_provider` alongside `provider` once Phase 2's
    `google-create --apply` has run. The installed policy must reflect both providers, or
    every scoped-policy call the second provider needs (H4b, google-list, ...) fails with
    an unrelated-looking AccessDenied under the true least-privilege principal, even though
    it works fine under an over-privileged operator profile.
    """
    state: dict[str, object] = {
        "directory_arn": "arn:directory",
        "vault_arn": "arn:vault",
        "workloads": [{"arn": "arn:workload:approved"}, {"arn": "arn:workload:unapproved"}],
        "provider": {"arn": "arn:provider:microsoft", "secret_arn": "arn:secret:microsoft"},
        "google_provider": {"arn": "arn:provider:google", "secret_arn": "arn:secret:google"},
    }
    iam = RecordingIamClient()

    install_scoped_policy(iam, "agentcore-poc-role", state)

    (call,) = iam.calls
    policy = json.loads(call["PolicyDocument"])
    named_resources = next(
        statement["Resource"]
        for statement in policy["Statement"]
        if statement.get("Sid") == "UseOnlyNamedPocResources"
    )
    assert "arn:provider:microsoft" in named_resources
    assert "arn:provider:google" in named_resources
    secret_resources = next(
        statement["Resource"]
        for statement in policy["Statement"]
        if statement.get("Sid") == "AllowOauth2ProviderSecretAccess"
    )
    assert "arn:secret:microsoft" in secret_resources
    assert "arn:secret:google" in secret_resources


def test_install_scoped_policy_omits_the_google_provider_when_absent_from_state() -> None:
    state: dict[str, object] = {
        "directory_arn": "arn:directory",
        "vault_arn": "arn:vault",
        "workloads": [{"arn": "arn:workload:approved"}, {"arn": "arn:workload:unapproved"}],
        "provider": {"arn": "arn:provider:microsoft", "secret_arn": "arn:secret:microsoft"},
    }
    iam = RecordingIamClient()

    install_scoped_policy(iam, "agentcore-poc-role", state)

    (call,) = iam.calls
    assert "arn:provider:google" not in call["PolicyDocument"]
    assert "arn:secret:google" not in call["PolicyDocument"]


class MissingBudgetClient:
    def describe_budget(self, **_: object) -> object:
        raise RuntimeError("not found")


class PresentBudgetClient:
    def describe_budget(self, **_: object) -> dict[str, object]:
        return {"Budget": {"BudgetName": SETTINGS.aws_budget_name}}


class NoBudgetCallsClient:
    def describe_budget(self, **_: object) -> object:
        raise AssertionError("budget API must not be called before local validation")


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
            "clientSecretArn": {"secretArn": f"arn:secret:{name}"},
        }
        self.providers[name] = response
        return response

    def update_workload_identity(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("update_workload_identity", kwargs))
        name = str(kwargs["name"])
        response = self.workloads[name]
        response["allowedResourceOauth2ReturnUrls"] = kwargs["allowedResourceOauth2ReturnUrls"]
        return response

    def delete_workload_identity(self, *, name: str) -> dict[str, object]:
        self.calls.append(("delete_workload_identity", {"name": name}))
        del self.workloads[name]
        return {}

    def delete_oauth2_credential_provider(self, *, name: str) -> dict[str, object]:
        self.calls.append(("delete_oauth2_credential_provider", {"name": name}))
        del self.providers[name]
        return {}


class FailingOnceCleanupControlClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.provider_exists = True
        self.workloads = {"approved-workload", "unapproved-workload"}
        self.fail_first_workload_delete = True

    def delete_oauth2_credential_provider(self, *, name: str) -> dict[str, object]:
        self.calls.append(("delete_oauth2_credential_provider", {"name": name}))
        if not self.provider_exists:
            raise ClientError(
                {"Error": {"Code": "ResourceNotFoundException"}},
                "DeleteOauth2CredentialProvider",
            )
        self.provider_exists = False
        return {}

    def delete_workload_identity(self, *, name: str) -> dict[str, object]:
        self.calls.append(("delete_workload_identity", {"name": name}))
        if self.fail_first_workload_delete:
            self.fail_first_workload_delete = False
            raise RuntimeError("temporary deletion failure")
        if name not in self.workloads:
            raise ClientError(
                {"Error": {"Code": "ResourceNotFoundException"}}, "DeleteWorkloadIdentity"
            )
        self.workloads.remove(name)
        return {}


class NoControlCallsClient:
    def __getattr__(self, name: str) -> object:
        raise AssertionError(f"control-plane method must not be accessed: {name}")


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
    iam = RecordingIamClient()
    state_path = tmp_path / ".poc-state.json"

    state = apply_resources(
        SETTINGS,
        "123456789012",
        budgets_client=PresentBudgetClient(),
        control_client=control,
        state_path=state_path,
        entra_client_secret="not-logged",
        directory_arn="arn:directory:returned",
        vault_arn="arn:vault:returned",
        iam_client=iam,
        iam_role_name="agentcore-poc-role",
    )
    again = apply_resources(
        SETTINGS,
        "123456789012",
        budgets_client=PresentBudgetClient(),
        control_client=control,
        state_path=state_path,
        entra_client_secret="not-logged",
        directory_arn="arn:directory:returned",
        vault_arn="arn:vault:returned",
        iam_client=iam,
        iam_role_name="agentcore-poc-role",
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
        "secret_arn": "arn:secret:microsoft-provider",
    }
    assert again == state
    assert "not-logged" not in state_path.read_text(encoding="utf-8")


def test_google_provider_creation_records_returned_callback_and_blocks_phase_two(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "google-client-id")
    control = RecordingControlClient()
    state_path = tmp_path / ".poc-state.json"
    write_state(state_path, _base_state())

    state = create_google_provider(
        control,
        SETTINGS,
        state_path=state_path,
        client_secret="not-logged",
    )

    assert state["google_provider"] == {
        "name": "google-provider",
        "arn": "arn:provider:google-provider",
        "callback_url": "https://callback.example.test/google-provider",
        "console_status": "google_console_registration_required",
        "secret_arn": "arn:secret:google-provider",
    }
    assert google_phase_two_plan(state)["status"] == "blocked"
    persisted = state_path.read_text(encoding="utf-8")
    assert "not-logged" not in persisted
    assert "https://callback.example.test/google-provider" in persisted


def test_google_callback_confirmation_unblocks_phase_two_and_sets_both_workload_return_urls(
    tmp_path: Path,
) -> None:
    control = RecordingControlClient()
    state_path = tmp_path / ".poc-state.json"
    _seed_workloads(control)
    write_state(
        state_path,
        _base_state(
            google_provider={
                "name": "google-provider",
                "arn": "arn:provider:google-provider",
                "callback_url": "https://callback.example.test/google-provider",
                "console_status": "google_console_registration_required",
            }
        ),
    )

    state = confirm_google_callback(control, SETTINGS, state_path=state_path)

    assert state["google_provider"] == {
        "name": "google-provider",
        "arn": "arn:provider:google-provider",
        "callback_url": "https://callback.example.test/google-provider",
        "console_status": "google_console_registered",
    }
    assert google_phase_two_plan(state)["status"] == "ready"
    assert [call[0] for call in control.calls] == [
        "update_workload_identity",
        "update_workload_identity",
    ]
    assert all(
        call[1]["allowedResourceOauth2ReturnUrls"] == [SETTINGS.google_return_url]
        for call in control.calls
    )


def test_google_callback_confirmation_rejects_missing_return_url_without_promoting_state(
    tmp_path: Path,
) -> None:
    class MissingReturnUrlControlClient(RecordingControlClient):
        def update_workload_identity(self, **kwargs: object) -> dict[str, object]:
            response = super().update_workload_identity(**kwargs)
            response["allowedResourceOauth2ReturnUrls"] = []
            return response

    control = MissingReturnUrlControlClient()
    state_path = tmp_path / ".poc-state.json"
    _seed_workloads(control)
    original_state = _base_state(
        google_provider={
            "name": "google-provider",
            "arn": "arn:provider:google-provider",
            "callback_url": "https://callback.example.test/google-provider",
            "console_status": "google_console_registration_required",
        }
    )
    write_state(state_path, original_state)

    with pytest.raises(ProvisioningError, match="did not retain the POC return URL"):
        confirm_google_callback(control, SETTINGS, state_path=state_path)

    assert json.loads(state_path.read_text(encoding="utf-8")) == original_state


def test_google_callback_confirmation_rejects_a_response_for_a_different_workload(
    tmp_path: Path,
) -> None:
    class MismatchedWorkloadControlClient(RecordingControlClient):
        def update_workload_identity(self, **kwargs: object) -> dict[str, object]:
            response = super().update_workload_identity(**kwargs)
            response["name"] = "different-workload"
            return response

    control = MismatchedWorkloadControlClient()
    state_path = tmp_path / ".poc-state.json"
    _seed_workloads(control)
    original_state = _base_state(
        google_provider={
            "name": "google-provider",
            "arn": "arn:provider:google-provider",
            "callback_url": "https://callback.example.test/google-provider",
            "console_status": "google_console_registration_required",
        }
    )
    write_state(state_path, original_state)

    with pytest.raises(ProvisioningError, match="does not match the requested workload"):
        confirm_google_callback(control, SETTINGS, state_path=state_path)

    assert json.loads(state_path.read_text(encoding="utf-8")) == original_state


def test_google_callback_confirmation_rejects_a_response_with_a_different_workload_arn(
    tmp_path: Path,
) -> None:
    class MismatchedWorkloadArnControlClient(RecordingControlClient):
        def update_workload_identity(self, **kwargs: object) -> dict[str, object]:
            response = super().update_workload_identity(**kwargs)
            response["workloadIdentityArn"] = "arn:workload:different-workload"
            return response

    control = MismatchedWorkloadArnControlClient()
    state_path = tmp_path / ".poc-state.json"
    _seed_workloads(control)
    original_state = _base_state(
        google_provider={
            "name": "google-provider",
            "arn": "arn:provider:google-provider",
            "callback_url": "https://callback.example.test/google-provider",
            "console_status": "google_console_registration_required",
        }
    )
    write_state(state_path, original_state)

    with pytest.raises(ProvisioningError, match="does not match the recorded workload ARN"):
        confirm_google_callback(control, SETTINGS, state_path=state_path)

    assert json.loads(state_path.read_text(encoding="utf-8")) == original_state


def test_google_provider_recreation_requires_a_new_console_update(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "google-client-id")
    control = RecordingControlClient()
    state_path = tmp_path / ".poc-state.json"
    write_state(
        state_path,
        _base_state(
            google_provider={
                "name": "google-provider",
                "arn": "arn:provider:prior-google-provider",
                "callback_url": "https://callback.example.test/prior-google-provider",
                "console_status": "google_console_registered",
            }
        ),
    )

    state = create_google_provider(
        control,
        SETTINGS,
        state_path=state_path,
        client_secret="not-logged",
    )

    assert state["google_provider"] == {
        "name": "google-provider",
        "arn": "arn:provider:google-provider",
        "callback_url": "https://callback.example.test/google-provider",
        "console_status": "google_console_update_required",
        "secret_arn": "arn:secret:google-provider",
    }
    assert google_phase_two_plan(state)["status"] == "blocked"


def test_core_apply_preserves_confirmed_google_provider_state(tmp_path: Path) -> None:
    control = RecordingControlClient()
    iam = RecordingIamClient()
    state_path = tmp_path / ".poc-state.json"
    google_provider = {
        "name": "google-provider",
        "arn": "arn:provider:google-provider",
        "callback_url": "https://callback.example.test/google-provider",
        "console_status": "google_console_registered",
        "secret_arn": "arn:secret:google-provider",
    }
    write_state(state_path, _base_state(google_provider=google_provider))

    state = apply_resources(
        SETTINGS,
        "123456789012",
        budgets_client=PresentBudgetClient(),
        control_client=control,
        state_path=state_path,
        entra_client_secret="not-logged",
        directory_arn="arn:directory:returned",
        vault_arn="arn:vault:returned",
        iam_client=iam,
        iam_role_name="agentcore-poc-role",
    )

    assert state["google_provider"] == google_provider


def test_google_create_requires_a_secret_source_before_constructing_an_aws_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "scripts.provision_agentcore.Settings.from_mapping", lambda _: SETTINGS
    )
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "google-client-id")
    monkeypatch.delenv("GOOGLE_OAUTH_CLIENT_SECRET", raising=False)
    monkeypatch.setattr(
        "scripts.provision_agentcore.boto3.session.Session",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("AWS session must stay local")),
    )

    assert main(["google-create", "--apply"]) == 2


def test_google_create_checks_the_named_budget_before_constructing_a_control_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class GoogleCreateSession:
        def __init__(self) -> None:
            self.services: list[str] = []

        def client(self, service_name: str, **_: object) -> object:
            self.services.append(service_name)
            if service_name == "budgets":
                return MissingBudgetClient()
            raise AssertionError("control-plane client must not be constructed before the budget")

    state_path = tmp_path / ".poc-state.json"
    write_state(state_path, _base_state())
    session = GoogleCreateSession()
    monkeypatch.setattr(
        "scripts.provision_agentcore.Settings.from_mapping", lambda _: SETTINGS
    )
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "google-client-id")
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_SECRET", "not-logged")
    monkeypatch.setattr(
        "scripts.provision_agentcore.boto3.session.Session", lambda **_kwargs: session
    )

    assert main(
        [
            "google-create",
            "--apply",
            "--account-id",
            "123456789012",
            "--state-path",
            str(state_path),
        ]
    ) == 2
    assert session.services == ["budgets"]


def test_google_callback_confirmation_rejects_missing_provider_before_aws_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path = tmp_path / ".poc-state.json"
    write_state(state_path, _base_state())
    monkeypatch.setattr(
        "scripts.provision_agentcore.Settings.from_mapping", lambda _: SETTINGS
    )
    monkeypatch.setattr(
        "scripts.provision_agentcore.boto3.session.Session",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("AWS session must stay local")),
    )

    assert main(["google-confirm-callback", "--apply", "--state-path", str(state_path)]) == 2


def test_plan_blocks_phase_two_before_google_callback_is_acknowledged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "scripts.provision_agentcore.Settings.from_mapping", lambda _: SETTINGS
    )
    write_state(
        tmp_path / ".poc-state.json",
        _base_state(
            google_provider={
                "name": "google-provider",
                "arn": "arn:provider:google-provider",
                "callback_url": "https://callback.example.test/google-provider",
                "console_status": "google_console_registration_required",
            }
        ),
    )

    assert main(["--state-path", str(tmp_path / ".poc-state.json")]) == 0

    plan = json.loads(capsys.readouterr().out)
    assert plan["phase_2"]["status"] == "blocked"


def _base_state(*, google_provider: dict[str, str] | None = None) -> dict[str, object]:
    state: dict[str, object] = {
        "version": 1,
        "account_id": "123456789012",
        "region": "us-west-2",
        "workloads": [
            {
                "name": "approved-workload",
                "arn": "arn:workload:approved-workload",
                "callback_urls": [],
            },
            {
                "name": "unapproved-workload",
                "arn": "arn:workload:unapproved-workload",
                "callback_urls": [],
            },
        ],
        "provider": {
            "name": "microsoft-provider",
            "arn": "arn:provider:microsoft-provider",
            "callback_url": "https://callback.example.test/microsoft-provider",
            "secret_arn": "arn:secret:microsoft-provider",
        },
    }
    if google_provider is not None:
        state["google_provider"] = google_provider
    return state


def _seed_workloads(control: RecordingControlClient) -> None:
    for name in ("approved-workload", "unapproved-workload"):
        control.workloads[name] = {
            "name": name,
            "workloadIdentityArn": f"arn:workload:{name}",
            "allowedResourceOauth2ReturnUrls": [],
        }


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


def test_apply_rejects_missing_scoped_policy_prerequisites_before_creation(tmp_path: Path) -> None:
    control = RecordingControlClient()

    with pytest.raises(ProvisioningError, match="all required for policy install"):
        apply_resources(
            SETTINGS,
            "123456789012",
            budgets_client=PresentBudgetClient(),
            control_client=control,
            state_path=tmp_path / ".poc-state.json",
            entra_client_secret="not-logged",
        )

    assert control.calls == []


def test_apply_rejects_missing_policy_prerequisites_before_budget_api(tmp_path: Path) -> None:
    with pytest.raises(ProvisioningError, match="all required for policy install"):
        apply_resources(
            SETTINGS,
            "123456789012",
            budgets_client=NoBudgetCallsClient(),
            control_client=NoControlCallsClient(),
            state_path=tmp_path / ".poc-state.json",
            entra_client_secret="not-logged",
            vault_arn="arn:vault:returned",
            iam_client=RecordingIamClient(),
            iam_role_name="agentcore-poc-role",
        )


@pytest.mark.parametrize(
    ("environment_name", "environment_value"),
    [
        ("AGENTCORE_DIRECTORY_ARN", " \t "),
        ("AGENTCORE_TOKEN_VAULT_ARN", "\n"),
        ("AGENTCORE_POC_IAM_ROLE_NAME", "  "),
    ],
)
def test_apply_cli_rejects_whitespace_policy_environment_before_aws_session(
    monkeypatch: pytest.MonkeyPatch,
    environment_name: str,
    environment_value: str,
) -> None:
    monkeypatch.setattr(
        "scripts.provision_agentcore.Settings.from_mapping", lambda _: SETTINGS
    )
    monkeypatch.setenv("AGENTCORE_DIRECTORY_ARN", "arn:directory:returned")
    monkeypatch.setenv("AGENTCORE_TOKEN_VAULT_ARN", "arn:vault:returned")
    monkeypatch.setenv("AGENTCORE_POC_IAM_ROLE_NAME", "agentcore-poc-role")
    monkeypatch.setenv(environment_name, environment_value)
    monkeypatch.setattr(
        "scripts.provision_agentcore.boto3.session.Session",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("AWS session must not be created before local validation")
        ),
    )

    assert main(["--apply"]) == 2


@pytest.mark.parametrize(
    ("directory_arn", "vault_arn", "iam_role_name"),
    [
        ("", "arn:vault:returned", "agentcore-poc-role"),
        ("arn:directory:returned", "", "agentcore-poc-role"),
        ("arn:directory:returned", "arn:vault:returned", ""),
        (" \t ", "arn:vault:returned", "agentcore-poc-role"),
        ("arn:directory:returned", "\n", "agentcore-poc-role"),
        ("arn:directory:returned", "arn:vault:returned", "  "),
    ],
)
def test_apply_rejects_blank_or_whitespace_policy_prerequisites_before_aws_calls(
    tmp_path: Path,
    directory_arn: str,
    vault_arn: str,
    iam_role_name: str,
) -> None:
    state_path = tmp_path / ".poc-state.json"

    with pytest.raises(ProvisioningError, match="all required for policy install"):
        apply_resources(
            SETTINGS,
            "123456789012",
            budgets_client=NoBudgetCallsClient(),
            control_client=NoControlCallsClient(),
            state_path=state_path,
            entra_client_secret="not-logged",
            directory_arn=directory_arn,
            vault_arn=vault_arn,
            iam_client=RecordingIamClient(),
            iam_role_name=iam_role_name,
        )

    assert not state_path.exists()


def test_cleanup_deletes_only_recorded_resources_after_exact_confirmation(tmp_path: Path) -> None:
    control = RecordingControlClient()
    iam = RecordingIamClient()
    state_path = tmp_path / ".poc-state.json"
    apply_resources(
        SETTINGS,
        "123456789012",
        budgets_client=PresentBudgetClient(),
        control_client=control,
        state_path=state_path,
        entra_client_secret="not-logged",
        directory_arn="arn:directory:returned",
        vault_arn="arn:vault:returned",
        iam_client=iam,
        iam_role_name="agentcore-poc-role",
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


def test_cleanup_deletes_a_recorded_google_provider_before_workloads(tmp_path: Path) -> None:
    control = RecordingControlClient()
    state_path = tmp_path / ".poc-state.json"
    control.providers["microsoft-provider"] = {
        "name": "microsoft-provider",
        "credentialProviderArn": "arn:provider:microsoft-provider",
        "callbackUrl": "https://callback.example.test/microsoft-provider",
    }
    control.providers["google-provider"] = {
        "name": "google-provider",
        "credentialProviderArn": "arn:provider:google-provider",
        "callbackUrl": "https://callback.example.test/google-provider",
    }
    _seed_workloads(control)
    write_state(
        state_path,
        _base_state(
            google_provider={
                "name": "google-provider",
                "arn": "arn:provider:google-provider",
                "callback_url": "https://callback.example.test/google-provider",
                "console_status": "google_console_registered",
            }
        ),
    )

    cleanup_resources(
        control,
        state_path=state_path,
        apply=True,
        confirm="agentcore-identity-poc",
    )

    assert [call[0] for call in control.calls] == [
        "delete_oauth2_credential_provider",
        "delete_oauth2_credential_provider",
        "delete_workload_identity",
        "delete_workload_identity",
    ]
    assert not state_path.exists()


def test_cleanup_retries_after_partial_failure_when_prior_delete_is_not_found(
    tmp_path: Path,
) -> None:
    control = FailingOnceCleanupControlClient()
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

    with pytest.raises(ProvisioningError, match="could not delete recorded workload identity"):
        cleanup_resources(
            control,
            state_path=state_path,
            apply=True,
            confirm="agentcore-identity-poc",
        )

    assert state_path.exists()
    cleanup_resources(
        control,
        state_path=state_path,
        apply=True,
        confirm="agentcore-identity-poc",
    )

    assert control.calls == [
        ("delete_oauth2_credential_provider", {"name": "microsoft-provider"}),
        ("delete_workload_identity", {"name": "approved-workload"}),
        ("delete_oauth2_credential_provider", {"name": "microsoft-provider"}),
        ("delete_workload_identity", {"name": "approved-workload"}),
        ("delete_workload_identity", {"name": "unapproved-workload"}),
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
