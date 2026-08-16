"""Plan, apply, and clean up the narrowly scoped AgentCore Identity POC resources."""

from __future__ import annotations

import argparse
import json
import os
import sys
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

    def update_workload_identity(self, **kwargs: object) -> Mapping[str, object]: ...

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
    validate_policy_prerequisites(directory_arn, vault_arn, iam_role_name)
    if iam_client is None:
        raise ProvisioningError(
            "directory ARN, vault ARN, IAM client, and IAM role name are all required "
            "for policy install"
        )
    existing_google_provider: object | None = None
    if state_path.exists():
        existing_google_provider = _load_state(state_path).get("google_provider")
    verify_budget(budgets_client, account_id, settings.aws_budget_name)

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
    if isinstance(existing_google_provider, Mapping):
        state["google_provider"] = dict(existing_google_provider)
    install_scoped_policy(iam_client, cast(str, iam_role_name), state)
    write_state(state_path, state)
    return state


def create_google_provider(
    control_client: ControlPlaneClient,
    settings: Settings,
    *,
    state_path: Path = _STATE_PATH,
    client_secret: str,
) -> dict[str, object]:
    """Create the Google provider and retain its returned callback for operator registration."""
    client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID", "").strip()
    if not client_id:
        raise ProvisioningError("GOOGLE_OAUTH_CLIENT_ID must be set before google-create --apply")
    if not client_secret.strip():
        raise ProvisioningError(
            "a Google OAuth client secret is required from the environment or stdin"
        )
    state = _load_state(state_path)
    prior_google = state.get("google_provider")
    provider = _find_provider(control_client, settings.agentcore_google_provider)
    if provider is None:
        try:
            response = control_client.create_oauth2_credential_provider(
                name=settings.agentcore_google_provider,
                credentialProviderVendor="GoogleOauth2",
                oauth2ProviderConfigInput={
                    "googleOauth2ProviderConfig": {
                        "clientId": client_id,
                        "clientSecret": client_secret,
                    }
                },
                tags=_PROJECT_TAG,
            )
        except Exception as error:
            raise ProvisioningError("could not create Google credential provider") from error
        provider = _provider_state(response)

    google_state = _google_provider_state(prior_google, provider)
    updated = dict(state)
    updated["google_provider"] = google_state
    write_state(state_path, updated)
    return updated


def _google_provider_state(
    prior: object, provider: Mapping[str, object]
) -> dict[str, str]:
    callback_url = _state_string(provider, "callback_url")
    if not isinstance(prior, Mapping):
        status = "google_console_registration_required"
    elif prior.get("callback_url") != callback_url or prior.get("arn") != provider.get("arn"):
        status = "google_console_update_required"
    else:
        previous_status = prior.get("console_status")
        status = (
            previous_status
            if previous_status in {
                "google_console_registration_required",
                "google_console_update_required",
                "google_console_registered",
            }
            else "google_console_registration_required"
        )
    return {
        "name": _state_string(provider, "name"),
        "arn": _state_string(provider, "arn"),
        "callback_url": callback_url,
        "console_status": status,
    }


def google_phase_two_plan(state: Mapping[str, object]) -> dict[str, str]:
    """Describe whether the operator has acknowledged the generated Google callback."""
    provider = state.get("google_provider")
    if not isinstance(provider, Mapping):
        return {
            "status": "blocked",
            "detail": "google_provider_missing; run google-create --apply",
        }
    callback_url = provider.get("callback_url")
    status = provider.get("console_status")
    if not isinstance(callback_url, str) or not callback_url:
        return {"status": "blocked", "detail": "google_callback_missing"}
    if status != "google_console_registered":
        return {
            "status": "blocked",
            "detail": (
                "register the recorded callback in Google then run "
                "google-confirm-callback --apply"
            ),
        }
    return {"status": "ready", "detail": "google_callback_registered"}


def confirm_google_callback(
    control_client: ControlPlaneClient, settings: Settings, *, state_path: Path = _STATE_PATH
) -> dict[str, object]:
    """Acknowledge Google registration and register the POC return URL on both workloads."""
    state = _load_state(state_path)
    provider = state.get("google_provider")
    if not isinstance(provider, Mapping):
        raise ProvisioningError("google-create --apply must finish before callback confirmation")
    if provider.get("console_status") not in {
        "google_console_registration_required",
        "google_console_update_required",
    }:
        if provider.get("console_status") == "google_console_registered":
            return state
        raise ProvisioningError("Google callback state is invalid")

    workloads = cast(list[Mapping[str, object]], state["workloads"])
    updated_workloads: list[dict[str, object]] = []
    for workload in workloads:
        name = _state_string(workload, "name")
        existing_return_urls = _string_list(workload.get("callback_urls"))
        return_urls = list(dict.fromkeys([*existing_return_urls, settings.google_return_url]))
        try:
            response = control_client.update_workload_identity(
                name=name,
                allowedResourceOauth2ReturnUrls=return_urls,
            )
        except Exception as error:
            raise ProvisioningError(
                "could not register the POC return URL on a workload identity"
            ) from error
        updated_workloads.append(
            {
                "name": _required_string(response, "name"),
                "arn": _required_string(response, "workloadIdentityArn"),
                "callback_urls": _string_list(response.get("allowedResourceOauth2ReturnUrls")),
            }
        )

    updated_provider = dict(provider)
    updated_provider["console_status"] = "google_console_registered"
    updated = dict(state)
    updated["workloads"] = updated_workloads
    updated["google_provider"] = updated_provider
    write_state(state_path, updated)
    return updated


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


def _is_nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def validate_policy_prerequisites(
    directory_arn: str | None, vault_arn: str | None, iam_role_name: str | None
) -> None:
    """Reject incomplete local provisioning inputs before any AWS API is contacted."""
    if not (
        _is_nonempty_string(directory_arn)
        and _is_nonempty_string(vault_arn)
        and _is_nonempty_string(iam_role_name)
    ):
        raise ProvisioningError(
            "directory ARN, vault ARN, IAM client, and IAM role name are all required "
            "for policy install"
        )


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

    _delete_recorded_resources(control_client, state, state_path)


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
    standard_provider_valid = all(
        isinstance(provider.get(field), str) and provider[field]
        for field in ("name", "arn", "callback_url")
    )
    google_provider = value.get("google_provider")
    google_provider_valid = google_provider is None or (
        isinstance(google_provider, dict)
        and all(
            isinstance(google_provider.get(field), str) and google_provider[field]
            for field in ("name", "arn", "callback_url")
        )
        and google_provider.get("console_status")
        in {
            "google_console_registration_required",
            "google_console_update_required",
            "google_console_registered",
        }
    )
    return workload_fields_valid and standard_provider_valid and google_provider_valid


def _cleanup_identifiers(state: Mapping[str, object]) -> list[str]:
    provider = cast(Mapping[str, str], state["provider"])
    workloads = cast(list[Mapping[str, str]], state["workloads"])
    google_provider = state.get("google_provider")
    google_identifier = (
        [f"google provider: {google_provider['name']} ({google_provider['arn']})"]
        if isinstance(google_provider, Mapping)
        else []
    )
    return [
        f"provider: {provider['name']} ({provider['arn']})",
        *google_identifier,
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
    parser.add_argument(
        "--google-secret-stdin",
        action="store_true",
        help="read the Google OAuth client secret from standard input for google-create",
    )
    parser.add_argument(
        "command",
        choices=(
            "plan",
            "cleanup",
            "google-create",
            "google-show-callback",
            "google-confirm-callback",
        ),
        nargs="?",
        default="plan",
    )
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

    if args.command == "google-show-callback":
        try:
            state = _load_state(args.state_path)
            provider = state.get("google_provider")
            if not isinstance(provider, Mapping):
                raise ProvisioningError(
                    "google-create --apply must finish before google-show-callback"
                )
            print(
                json.dumps(
                    {
                        "callback_url": _state_string(provider, "callback_url"),
                        "console_status": _state_string(provider, "console_status"),
                        "phase_2": google_phase_two_plan(state),
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
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
    if args.command == "plan" and not args.apply:
        plan = plan_resources(settings, account_id)
        try:
            plan["phase_2"] = google_phase_two_plan(_load_state(args.state_path))
        except ProvisioningError:
            plan["phase_2"] = {
                "status": "blocked",
                "detail": "google_provider_missing; run google-create --apply",
            }
        print(
            json.dumps(plan, separators=(",", ":"), sort_keys=True)
        )
        return 0

    if args.command == "google-create":
        if not args.apply:
            print("google-create requires --apply")
            return 2
        try:
            secret = _read_google_client_secret(from_stdin=args.google_secret_stdin)
            session = boto3.session.Session(region_name=settings.aws_region)
            state = create_google_provider(
                cast(
                    ControlPlaneClient,
                    session.client("bedrock-agentcore-control", region_name=settings.aws_region),
                ),
                settings,
                state_path=args.state_path,
                client_secret=secret,
            )
        except ProvisioningError as error:
            print(str(error))
            return 2
        print(json.dumps({"google_provider": state["google_provider"]}, separators=(",", ":")))
        return 0

    if args.command == "google-confirm-callback":
        if not args.apply:
            print("google-confirm-callback requires --apply")
            return 2
        try:
            state = _load_state(args.state_path)
            provider = state.get("google_provider")
            if not isinstance(provider, Mapping):
                raise ProvisioningError(
                    "google-create --apply must finish before callback confirmation"
                )
            callback_status = provider.get("console_status")
            if callback_status == "google_console_registered":
                print(json.dumps({"phase_2": google_phase_two_plan(state)}, separators=(",", ":")))
                return 0
            if callback_status not in {
                "google_console_registration_required",
                "google_console_update_required",
            }:
                raise ProvisioningError("Google callback state is invalid")
            session = boto3.session.Session(region_name=settings.aws_region)
            state = confirm_google_callback(
                cast(
                    ControlPlaneClient,
                    session.client("bedrock-agentcore-control", region_name=settings.aws_region),
                ),
                settings,
                state_path=args.state_path,
            )
        except ProvisioningError as error:
            print(str(error))
            return 2
        print(json.dumps({"phase_2": google_phase_two_plan(state)}, separators=(",", ":")))
        return 0

    directory_arn = os.environ.get("AGENTCORE_DIRECTORY_ARN")
    vault_arn = os.environ.get("AGENTCORE_TOKEN_VAULT_ARN")
    iam_role_name = os.environ.get("AGENTCORE_POC_IAM_ROLE_NAME")
    try:
        validate_policy_prerequisites(directory_arn, vault_arn, iam_role_name)
    except ProvisioningError as error:
        print(str(error))
        return 2

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
            directory_arn=directory_arn,
            vault_arn=vault_arn,
            iam_client=cast(IamPolicyClient, session.client("iam")),
            iam_role_name=iam_role_name,
        )
    except ProvisioningError as error:
        print(str(error))
        return 2
    print(json.dumps(state, separators=(",", ":"), sort_keys=True))
    return 0


def _read_google_client_secret(*, from_stdin: bool) -> str:
    environment_secret = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
    if from_stdin and environment_secret:
        raise ProvisioningError(
            "set only one Google client-secret source: GOOGLE_OAUTH_CLIENT_SECRET or "
            "--google-secret-stdin"
        )
    secret = sys.stdin.readline().rstrip("\r\n") if from_stdin else environment_secret
    if not isinstance(secret, str) or not secret.strip():
        raise ProvisioningError(
            "set GOOGLE_OAUTH_CLIENT_SECRET or pass --google-secret-stdin for google-create --apply"
        )
    return secret


def _delete_recorded_resources(
    client: ControlPlaneClient, state: Mapping[str, object], state_path: Path
) -> None:
    provider = cast(Mapping[str, str], state["provider"])
    google_provider = state.get("google_provider")
    if isinstance(google_provider, Mapping):
        _delete_provider_if_present(client, _state_string(google_provider, "name"))
    _delete_provider_if_present(client, provider["name"])
    for workload in cast(list[Mapping[str, str]], state["workloads"]):
        _delete_workload_if_present(client, workload["name"])
    state_path.unlink()


def _delete_provider_if_present(client: ControlPlaneClient, name: str) -> None:
    try:
        client.delete_oauth2_credential_provider(name=name)
    except Exception as error:
        if _is_not_found(error):
            return
        raise ProvisioningError(
            f"could not delete recorded credential provider '{name}'"
        ) from error


def _delete_workload_if_present(client: ControlPlaneClient, name: str) -> None:
    try:
        client.delete_workload_identity(name=name)
    except Exception as error:
        if _is_not_found(error):
            return
        raise ProvisioningError(f"could not delete recorded workload identity '{name}'") from error


if __name__ == "__main__":
    raise SystemExit(main())
