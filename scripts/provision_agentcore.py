"""Plan, apply, and clean up the narrowly scoped AgentCore Identity POC resources."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Protocol, cast

import boto3  # type: ignore[import-untyped]
from botocore.exceptions import ClientError  # type: ignore[import-untyped]

from agentcore_identity_poc.config import Settings, SettingsError

_PROJECT_TAG = {"Project": "agentcore-identity-poc"}
_STATE_PATH = Path(".poc-state.json")
_POLICY_PLACEHOLDERS = frozenset(
    {"DIRECTORY_ARN", "WORKLOAD_ARN", "SECOND_WORKLOAD_ARN", "VAULT_ARN", "PROVIDER_ARN"}
)


class ProvisioningError(RuntimeError):
    """Raised when an operator action is unsafe or cannot be completed."""


class BudgetMissingError(ProvisioningError):
    """Raised before writes when the required monthly budget is absent."""


class BudgetsClient(Protocol):
    def describe_budget(self, **kwargs: str) -> Mapping[str, object]: ...


class ControlPlaneClient(Protocol):
    def get_workload_identity(self, *, name: str) -> Mapping[str, object]: ...

    def create_workload_identity(self, **kwargs: object) -> Mapping[str, object]: ...

    def get_oauth2_credential_provider(self, *, name: str) -> Mapping[str, object]: ...

    def create_oauth2_credential_provider(self, **kwargs: object) -> Mapping[str, object]: ...

    def delete_workload_identity(self, *, name: str) -> Mapping[str, object]: ...

    def delete_oauth2_credential_provider(self, *, name: str) -> Mapping[str, object]: ...


class IamPolicyClient(Protocol):
    def put_role_policy(self, **kwargs: object) -> None: ...


def plan_resources(settings: Settings, account_id: str) -> dict[str, object]:
    """Return the exact named resources that an apply operation may create."""
    return {
        "account_id": account_id,
        "region": settings.aws_region,
        "workloads": [
            {"name": settings.agentcore_workload_name, "return_urls": []},
            {"name": settings.agentcore_second_workload_name, "return_urls": []},
        ],
        "provider": {"name": settings.agentcore_microsoft_provider, "vendor": "MicrosoftOauth2"},
        "tags": _PROJECT_TAG,
    }


def verify_budget(client: BudgetsClient, account_id: str, budget_name: str) -> None:
    """Ensure an intentionally named AWS Budget is in place before creating resources."""
    try:
        client.describe_budget(AccountId=account_id, BudgetName=budget_name)
    except Exception as error:
        message = (
            f"AWS Budget '{budget_name}' is required before --apply. "
            "Create it in the AWS Billing console or run: aws budgets create-budget "
            f"--account-id {account_id} --budget file://budget.json"
        )
        raise BudgetMissingError(message) from error


def render_policy_template(template: object, replacements: Mapping[str, str]) -> object:
    """Replace exact JSON placeholder values without using shell interpolation."""
    missing = _POLICY_PLACEHOLDERS - replacements.keys()
    if missing:
        raise ProvisioningError(f"policy replacements missing: {', '.join(sorted(missing))}")
    return _replace_policy_value(template, replacements)


def _replace_policy_value(value: object, replacements: Mapping[str, str]) -> object:
    if isinstance(value, list):
        return [_replace_policy_value(item, replacements) for item in value]
    if isinstance(value, Mapping):
        return {key: _replace_policy_value(item, replacements) for key, item in value.items()}
    if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
        name = value[2:-1]
        if name not in _POLICY_PLACEHOLDERS:
            raise ProvisioningError(f"unsupported policy placeholder: {name}")
        return replacements[name]
    return value


def load_policy_template(path: Path, replacements: Mapping[str, str]) -> dict[str, object]:
    """Parse and render a checked-in IAM JSON template."""
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProvisioningError(f"could not parse policy template: {path}") from error
    rendered = render_policy_template(parsed, replacements)
    if not isinstance(rendered, dict):
        raise ProvisioningError(f"policy template must be an object: {path}")
    return cast(dict[str, object], rendered)


def apply_resources(
    settings: Settings,
    account_id: str,
    *,
    budgets_client: BudgetsClient,
    control_client: ControlPlaneClient,
    state_path: Path = _STATE_PATH,
    entra_client_secret: str | None = None,
    directory_arn: str | None = None,
    vault_arn: str | None = None,
    iam_client: IamPolicyClient | None = None,
    iam_role_name: str | None = None,
) -> dict[str, object]:
    """Create absent POC resources and persist only their returned identifiers."""
    verify_budget(budgets_client, account_id, settings.aws_budget_name)

    policy_inputs = (directory_arn, vault_arn, iam_client, iam_role_name)
    if not all(item is not None for item in policy_inputs):
        raise ProvisioningError(
            "directory ARN, vault ARN, IAM client, and IAM role name are all required "
            "for policy install"
        )

    provider = _find_provider(control_client, settings.agentcore_microsoft_provider)
    secret = entra_client_secret if entra_client_secret is not None else os.environ.get(
        "ENTRA_API_CLIENT_SECRET"
    )
    if provider is None and not secret:
        raise ProvisioningError(
            "ENTRA_API_CLIENT_SECRET must be set before creating the Microsoft credential provider"
        )

    workloads = [
        _ensure_workload(control_client, settings.agentcore_workload_name),
        _ensure_workload(control_client, settings.agentcore_second_workload_name),
    ]
    if provider is None:
        provider = _create_microsoft_provider(control_client, settings, cast(str, secret))

    state: dict[str, object] = {
        "version": 1,
        "account_id": account_id,
        "region": settings.aws_region,
        "workloads": workloads,
        "provider": provider,
        "directory_arn": cast(str, directory_arn),
        "vault_arn": cast(str, vault_arn),
    }
    install_scoped_policy(cast(IamPolicyClient, iam_client), cast(str, iam_role_name), state)
    write_state(state_path, state)
    return state


def install_scoped_policy(
    client: IamPolicyClient, role_name: str, state: Mapping[str, object]
) -> None:
    """Render the checked-in final policy with recorded ARNs and install it on one IAM role."""
    workloads = cast(list[Mapping[str, str]], state.get("workloads", []))
    provider = cast(Mapping[str, str], state.get("provider", {}))
    if len(workloads) != 2:
        raise ProvisioningError(
            "state must record exactly two workload ARNs for scoped policy install"
        )
    replacements = {
        "DIRECTORY_ARN": _state_string(state, "directory_arn"),
        "WORKLOAD_ARN": _state_string(workloads[0], "arn"),
        "SECOND_WORKLOAD_ARN": _state_string(workloads[1], "arn"),
        "VAULT_ARN": _state_string(state, "vault_arn"),
        "PROVIDER_ARN": _state_string(provider, "arn"),
    }
    policy_path = Path(__file__).resolve().parents[1] / "infra" / "iam" / "scoped.json"
    policy = load_policy_template(policy_path, replacements)
    serialized = json.dumps(policy, separators=(",", ":"), sort_keys=True)
    if "*" in serialized or "bedrock-agentcore:GetWorkloadAccessTokenForUserId" not in serialized:
        raise ProvisioningError("rendered scoped policy is not safely constrained")
    client.put_role_policy(
        RoleName=role_name,
        PolicyName="agentcore-identity-poc-scoped",
        PolicyDocument=serialized,
    )


def _state_string(state: Mapping[str, object], field: str) -> str:
    value = state.get(field)
    if not isinstance(value, str) or not value:
        raise ProvisioningError(f"state omitted required ARN: {field}")
    return value


def _ensure_workload(client: ControlPlaneClient, name: str) -> dict[str, object]:
    existing = _find_workload(client, name)
    response = existing or client.create_workload_identity(
        name=name,
        allowedResourceOauth2ReturnUrls=[],
        tags=_PROJECT_TAG,
    )
    arn = _required_string(response, "workloadIdentityArn")
    return {
        "name": _required_string(response, "name"),
        "arn": arn,
        "callback_urls": _string_list(response.get("allowedResourceOauth2ReturnUrls")),
    }


def _create_microsoft_provider(
    client: ControlPlaneClient, settings: Settings, client_secret: str
) -> dict[str, object]:
    response = client.create_oauth2_credential_provider(
        name=settings.agentcore_microsoft_provider,
        credentialProviderVendor="MicrosoftOauth2",
        oauth2ProviderConfigInput={
            "microsoftOauth2ProviderConfig": {
                "clientId": settings.entra_api_client_id,
                "tenantId": settings.entra_tenant_id,
                "clientSecret": client_secret,
            }
        },
        tags=_PROJECT_TAG,
    )
    return _provider_state(response)


def _provider_state(response: Mapping[str, object]) -> dict[str, object]:
    return {
        "name": _required_string(response, "name"),
        "arn": _required_string(response, "credentialProviderArn"),
        "callback_url": _required_string(response, "callbackUrl"),
    }


def _find_workload(client: ControlPlaneClient, name: str) -> Mapping[str, object] | None:
    try:
        return client.get_workload_identity(name=name)
    except Exception as error:
        if _is_not_found(error):
            return None
        raise ProvisioningError(f"could not read workload identity '{name}'") from error


def _find_provider(client: ControlPlaneClient, name: str) -> Mapping[str, object] | None:
    try:
        response = client.get_oauth2_credential_provider(name=name)
    except Exception as error:
        if _is_not_found(error):
            return None
        raise ProvisioningError(f"could not read credential provider '{name}'") from error
    return _provider_state(response)


def _is_not_found(error: Exception) -> bool:
    if not isinstance(error, ClientError):
        return False
    details = error.response.get("Error", {})
    return isinstance(details, Mapping) and details.get("Code") in {
        "ResourceNotFoundException",
        "NotFoundException",
    }


def _required_string(value: Mapping[str, object], field: str) -> str:
    result = value.get(field)
    if not isinstance(result, str) or not result:
        raise ProvisioningError(f"AWS response omitted required field: {field}")
    return result


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return []
    return value


def write_state(path: Path, state: Mapping[str, object]) -> None:
    """Atomically write a private local resource inventory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(state, indent=2, sort_keys=True) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f"{path.name}.", dir=path.parent, text=True
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as state_file:
            state_file.write(encoded)
        os.replace(temporary_path, path)
        os.chmod(path, 0o600)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def cleanup_resources(
    client: object,
    *,
    state_path: Path = _STATE_PATH,
    apply: bool,
    confirm: str | None,
    output: Callable[[str], None] = print,
) -> None:
    """Print, then optionally delete, exactly the resource identifiers in valid local state."""
    state = preview_cleanup(state_path, output)

    if not apply:
        return
    if confirm != "agentcore-identity-poc":
        raise ProvisioningError("cleanup requires --apply --confirm agentcore-identity-poc")
    if not all(
        callable(getattr(client, method, None))
        for method in ("delete_oauth2_credential_provider", "delete_workload_identity")
    ):
        raise ProvisioningError("cleanup requires an AgentCore control-plane client")
    control_client = cast(ControlPlaneClient, client)

    provider = cast(dict[str, str], state["provider"])
    control_client.delete_oauth2_credential_provider(name=provider["name"])
    for workload in cast(list[dict[str, str]], state["workloads"]):
        control_client.delete_workload_identity(name=workload["name"])
    state_path.unlink()


def preview_cleanup(path: Path, output: Callable[[str], None] = print) -> dict[str, object]:
    """Load and print local cleanup targets without constructing an AWS client."""
    state = _load_state(path)
    output("Cleanup targets:")
    for identifier in _cleanup_identifiers(state):
        output(identifier)
    return state


def _load_state(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProvisioningError("valid .poc-state.json is required for cleanup") from error
    if not _valid_state(value):
        raise ProvisioningError("valid .poc-state.json is required for cleanup")
    return cast(dict[str, object], value)


def _valid_state(value: object) -> bool:
    if not isinstance(value, dict) or value.get("version") != 1:
        return False
    workloads = value.get("workloads")
    provider = value.get("provider")
    if not isinstance(workloads, list) or len(workloads) != 2 or not isinstance(provider, dict):
        return False
    workload_fields_valid = all(
        isinstance(workload, dict)
        and isinstance(workload.get("name"), str)
        and isinstance(workload.get("arn"), str)
        for workload in workloads
    )
    return workload_fields_valid and all(
        isinstance(provider.get(field), str) and provider[field]
        for field in ("name", "arn", "callback_url")
    )


def _cleanup_identifiers(state: Mapping[str, object]) -> list[str]:
    provider = cast(Mapping[str, str], state["provider"])
    workloads = cast(list[Mapping[str, str]], state["workloads"])
    return [
        f"provider: {provider['name']} ({provider['arn']})",
        *[f"workload: {workload['name']} ({workload['arn']})" for workload in workloads],
    ]


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply", action="store_true", help="create resources after budget verification"
    )
    parser.add_argument("--state-path", type=Path, default=_STATE_PATH)
    parser.add_argument("--account-id", help="AWS account ID for dry-run output")
    parser.add_argument("--confirm", help="required confirmation text for cleanup")
    parser.add_argument("command", choices=("plan", "cleanup"), nargs="?", default="plan")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.command == "cleanup":
        try:
            state = preview_cleanup(args.state_path)
            if not args.apply:
                return 0
            if args.confirm != "agentcore-identity-poc":
                raise ProvisioningError("cleanup requires --apply --confirm agentcore-identity-poc")
            client = boto3.client("bedrock-agentcore-control")
            _delete_recorded_resources(cast(ControlPlaneClient, client), state, args.state_path)
        except ProvisioningError as error:
            print(str(error))
            return 2
        return 0

    try:
        settings = Settings.from_mapping(os.environ)
    except SettingsError as error:
        print(json.dumps({"status": "blocked", "detail": str(error)}, separators=(",", ":")))
        return 2

    account_id = args.account_id or os.environ.get("AWS_ACCOUNT_ID") or "unresolved"
    if not args.apply:
        print(
            json.dumps(plan_resources(settings, account_id), separators=(",", ":"), sort_keys=True)
        )
        return 0

    session = boto3.session.Session(region_name=settings.aws_region)
    account_id = args.account_id or session.client("sts").get_caller_identity()["Account"]
    try:
        state = apply_resources(
            settings,
            account_id,
            budgets_client=cast(BudgetsClient, session.client("budgets", region_name="us-east-1")),
            control_client=cast(
                ControlPlaneClient,
                session.client("bedrock-agentcore-control", region_name=settings.aws_region),
            ),
            state_path=args.state_path,
            directory_arn=os.environ.get("AGENTCORE_DIRECTORY_ARN"),
            vault_arn=os.environ.get("AGENTCORE_TOKEN_VAULT_ARN"),
            iam_client=cast(IamPolicyClient, session.client("iam"))
            if os.environ.get("AGENTCORE_POC_IAM_ROLE_NAME")
            else None,
            iam_role_name=os.environ.get("AGENTCORE_POC_IAM_ROLE_NAME"),
        )
    except ProvisioningError as error:
        print(str(error))
        return 2
    print(json.dumps(state, separators=(",", ":"), sort_keys=True))
    return 0


def _delete_recorded_resources(
    client: ControlPlaneClient, state: Mapping[str, object], state_path: Path
) -> None:
    provider = cast(Mapping[str, str], state["provider"])
    client.delete_oauth2_credential_provider(name=provider["name"])
    for workload in cast(list[Mapping[str, str]], state["workloads"]):
        client.delete_workload_identity(name=workload["name"])
    state_path.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
