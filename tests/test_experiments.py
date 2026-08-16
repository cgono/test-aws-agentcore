from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentcore_identity_poc.cli import _AwsIamPolicyManager, app
from agentcore_identity_poc.experiments import (
    ExperimentConfigurationError,
    ExperimentTimeout,
    MatrixRow,
    PolicyRestorationError,
    WorkloadAttempt,
    assert_same_aws_principal,
    run_user_isolation,
    run_workload_isolation,
)


def test_matrix_row_is_immutable_and_contains_the_required_evidence_fields() -> None:
    row = MatrixRow(
        principal_alias="development-role",
        asserted_workload="approved-workload",
        user_alias="user-a",
        policy_mode="scoped",
        provider="google-provider",
        outcome="pass",
        aws_error_category=None,
    )

    with pytest.raises(FrozenInstanceError):
        row.outcome = "fail"  # type: ignore[misc]

    assert row.as_details() == {
        "principal_alias": "development-role",
        "asserted_workload": "approved-workload",
        "user_alias": "user-a",
        "policy_mode": "scoped",
        "provider": "google-provider",
        "aws_error_category": None,
    }


def test_final_scoped_policy_explicitly_denies_the_second_workload_jwt_binding() -> None:
    policy = json.loads(Path("infra/iam/scoped.json").read_text(encoding="utf-8"))

    assert {
        "Effect": "Deny",
        "Action": "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
        "Resource": "${SECOND_WORKLOAD_ARN}",
    }.items() <= policy["Statement"][-2].items()


class RecordingIamClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []

    def put_role_policy(self, **kwargs: str) -> None:
        self.calls.append(kwargs)


class FakeStsClient:
    def get_caller_identity(self) -> dict[str, str]:
        return {"Arn": "arn:aws:iam::123456789012:role/agentcore-poc"}


def test_iam_policy_manager_replaces_the_same_inline_policy_for_broad_and_scoped_modes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / ".poc-state.json").write_text(
        json.dumps(
            {
                "directory_arn": "arn:directory",
                "vault_arn": "arn:vault",
                "workloads": [{"arn": "arn:approved"}, {"arn": "arn:unapproved"}],
                "provider": {"arn": "arn:provider"},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    iam = RecordingIamClient()
    manager = _AwsIamPolicyManager(iam, FakeStsClient(), "agentcore-poc-role")

    manager.apply_broad_policy()
    manager.apply_scoped_policy()

    assert [call["PolicyName"] for call in iam.calls] == [
        "agentcore-identity-poc-scoped",
        "agentcore-identity-poc-scoped",
    ]
    assert '"Resource":"*"' in iam.calls[0]["PolicyDocument"]
    assert "DenySecondWorkloadJwtBinding" in iam.calls[1]["PolicyDocument"]


def test_user_isolation_requires_exactly_two_distinct_validated_users() -> None:
    validated: list[str] = []

    with pytest.raises(ExperimentConfigurationError, match="exactly two distinct validated users"):
        run_user_isolation(
            principal_alias="development-role",
            workload_name="approved-workload",
            provider="google-provider",
            users=(
                ("user-a", "inbound-a"),
                ("user-a", "inbound-b"),
            ),
            validate_user=lambda alias, _: validated.append(alias),
            get_workload_token=lambda _, __: "workload-token",
            observe_connection=lambda _, __: WorkloadAttempt("pass"),
        )

    assert validated == []


def test_user_isolation_records_each_distinct_validated_user() -> None:
    validated: list[str] = []
    workload_bindings: list[tuple[str, str]] = []

    rows = run_user_isolation(
        principal_alias="development-role",
        workload_name="approved-workload",
        provider="google-provider",
        users=(("user-a", "inbound-a"), ("user-b", "inbound-b")),
        validate_user=lambda alias, _: validated.append(alias) or f"subject-{alias}",
        get_workload_token=lambda alias, token: workload_bindings.append((alias, token))
        or f"workload-for-{alias}",
        observe_connection=lambda alias, _: WorkloadAttempt(
            "pass", None if alias == "user-a" else ""
        ),
    )

    assert validated == ["user-a", "user-b"]
    assert workload_bindings == [("user-a", "inbound-a"), ("user-b", "inbound-b")]
    assert [(row.user_alias, row.outcome) for row in rows] == [
        ("user-a", "pass"),
        ("user-b", "pass"),
    ]


def test_user_isolation_rejects_different_aliases_with_the_same_verified_subject() -> None:
    validated: list[tuple[str, str]] = []
    workload_bindings: list[tuple[str, str]] = []

    with pytest.raises(
        ExperimentConfigurationError, match="distinct verified Entra subjects"
    ) as error:
        run_user_isolation(
            principal_alias="development-role",
            workload_name="approved-workload",
            provider="google-provider",
            users=(("user-a", "first-jwt"), ("user-b", "refreshed-jwt")),
            validate_user=lambda alias, token: validated.append((alias, token)) or "same-subject",
            get_workload_token=lambda alias, token: workload_bindings.append((alias, token))
            or "workload-token",
            observe_connection=lambda _, __: WorkloadAttempt("pass"),
        )

    assert validated == [("user-a", "first-jwt"), ("user-b", "refreshed-jwt")]
    assert workload_bindings == []
    assert "same-subject" not in str(error.value)


def test_h4b_rejects_rows_collected_under_different_aws_principals() -> None:
    rows = (
        MatrixRow(
            principal_alias="development-role-a",
            asserted_workload="approved-workload",
            user_alias="user-a",
            policy_mode="broad",
            provider="google-provider",
            outcome="pass",
            aws_error_category=None,
        ),
        MatrixRow(
            principal_alias="development-role-b",
            asserted_workload="unapproved-workload",
            user_alias="user-a",
            policy_mode="broad",
            provider="google-provider",
            outcome="pass",
            aws_error_category=None,
        ),
    )

    with pytest.raises(ExperimentConfigurationError, match="same AWS principal"):
        assert_same_aws_principal(rows)


class FakePolicyManager:
    def __init__(self, *, fail_scoped_restore: bool = False) -> None:
        self.policy_mode = "scoped"
        self.actions: list[str] = []
        self.fail_scoped_restore = fail_scoped_restore

    def caller_identity(self) -> str:
        return "development-role"

    def apply_broad_policy(self) -> None:
        self.actions.append("broad")
        self.policy_mode = "broad"

    def apply_scoped_policy(self) -> None:
        self.actions.append("scoped")
        if self.fail_scoped_restore:
            raise RuntimeError("IAM unavailable")
        self.policy_mode = "scoped"


def test_workload_isolation_requires_acknowledgement_before_broad_policy() -> None:
    policy = FakePolicyManager()

    with pytest.raises(ExperimentConfigurationError, match="acknowledge-broad-policy"):
        run_workload_isolation(
            policy_manager=policy,
            workload_names=("approved-workload", "unapproved-workload"),
            user_alias="user-a",
            provider="google-provider",
            acknowledge_broad_policy=False,
            attempt_provider=lambda _: WorkloadAttempt("pass"),
        )

    assert policy.actions == []


def test_workload_isolation_records_broad_and_scoped_rows_under_one_principal() -> None:
    policy = FakePolicyManager()
    recorded: list[MatrixRow] = []

    rows = run_workload_isolation(
        policy_manager=policy,
        workload_names=("approved-workload", "unapproved-workload"),
        user_alias="user-a",
        provider="google-provider",
        acknowledge_broad_policy=True,
        attempt_provider=lambda workload: WorkloadAttempt(
            "pass"
            if policy.policy_mode == "broad" or workload == "approved-workload"
            else "denied",
            (
                None
                if policy.policy_mode == "broad" or workload == "approved-workload"
                else "access_denied"
            ),
        ),
        record_row=recorded.append,
    )

    assert policy.actions == ["broad", "scoped", "scoped"]
    assert [(row.policy_mode, row.asserted_workload, row.outcome) for row in rows] == [
        ("broad", "approved-workload", "pass"),
        ("broad", "unapproved-workload", "pass"),
        ("scoped", "approved-workload", "pass"),
        ("scoped", "unapproved-workload", "denied"),
    ]
    assert {row.principal_alias for row in rows} == {"development-role"}
    assert recorded == list(rows)


def test_workload_isolation_fails_nonzero_when_scoped_restoration_fails() -> None:
    policy = FakePolicyManager(fail_scoped_restore=True)

    with pytest.raises(PolicyRestorationError, match="scripts/provision_agentcore.py --apply"):
        run_workload_isolation(
            policy_manager=policy,
            workload_names=("approved-workload", "unapproved-workload"),
            user_alias="user-a",
            provider="google-provider",
            acknowledge_broad_policy=True,
            attempt_provider=lambda _: WorkloadAttempt("pass"),
        )

    assert policy.actions == ["broad", "scoped", "scoped"]


def test_workload_isolation_records_each_attempt_before_propagation_timeout() -> None:
    policy = FakePolicyManager()
    recorded: list[MatrixRow] = []
    now = [0.0]

    with pytest.raises(ExperimentTimeout, match="within 60 seconds"):
        run_workload_isolation(
            policy_manager=policy,
            workload_names=("approved-workload", "unapproved-workload"),
            user_alias="user-a",
            provider="google-provider",
            acknowledge_broad_policy=True,
            attempt_provider=lambda _: WorkloadAttempt("denied", "access_denied"),
            clock=lambda: now[0],
            sleep=lambda seconds: now.__setitem__(0, now[0] + seconds),
            propagation_timeout_seconds=1,
            record_row=recorded.append,
        )

    assert [(row.policy_mode, row.outcome) for row in recorded] == [
        ("broad", "denied"),
        ("broad", "denied"),
        ("broad", "denied"),
        ("broad", "denied"),
    ]
    assert policy.actions == ["broad", "scoped"]


def test_workload_isolation_cli_requires_acknowledgement_before_loading_configuration() -> None:
    result = CliRunner().invoke(app, ["workload-isolation"])

    assert result.exit_code == 2
    assert result.stdout == (
        '{"status":"blocked","category":"configuration",'
        '"detail":"acknowledge_broad_policy_required"}\n'
    )
