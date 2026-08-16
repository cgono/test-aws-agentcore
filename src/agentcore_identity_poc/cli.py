"""Command-line entry point for the AgentCore Identity POC."""

from __future__ import annotations

import json
import os
import secrets
import sys
import time
import webbrowser
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, NoReturn, Protocol, cast

import boto3  # type: ignore[import-untyped]
import typer

from agentcore_identity_poc.agentcore import (
    AgentCoreDataPlane,
    AgentCoreError,
    AgentCoreIdentity,
    AgentCoreInternalError,
    AuthorizationRequired,
    OAuthToken,
)
from agentcore_identity_poc.config import Settings, SettingsError
from agentcore_identity_poc.downstream import (
    DownstreamError,
    DownstreamUnauthorized,
    DriveMetadata,
    GoogleDriveClient,
    SyntheticMetadata,
    SyntheticResourceClient,
)
from agentcore_identity_poc.entra import EntraAuthError, EntraDeviceAuth
from agentcore_identity_poc.evidence import EvidenceWriter
from agentcore_identity_poc.jwt_validation import JwtPolicy, TokenRejected, make_http_jwks_loader
from agentcore_identity_poc.models import JsonValue, Observation

_CONFIGURATION_EXIT = 2
_AUTHENTICATION_EXIT = 3
_AGENTCORE_EXIT = 4
_DOWNSTREAM_EXIT = 5
_DEFAULT_EVIDENCE_PATH = Path("evidence/phase-1.jsonl")
_DEFAULT_GOOGLE_EVIDENCE_PATH = Path("evidence/phase-2.jsonl")
_GOOGLE_DRIVE_METADATA_SCOPE = "https://www.googleapis.com/auth/drive.metadata.readonly"


class IdentityClient(Protocol):
    """The token operations used by the Entra and Google commands."""

    def workload_token(self, workload_name: str, user_token: str) -> str: ...

    def obo_token(self, workload_token: str, provider: str, scopes: list[str]) -> str: ...

    def google_token(
        self,
        workload_token: str,
        provider: str,
        scopes: list[str],
        return_url: str,
        state: str,
        *,
        force_authentication: bool = False,
    ) -> OAuthToken | AuthorizationRequired: ...


class ResourceClient(Protocol):
    """The narrow synthetic-resource boundary used by this command."""

    def list(self, access_token: str) -> SyntheticMetadata: ...


class GoogleDriveResourceClient(Protocol):
    """The aggregate-only Google Drive surface used by Google commands."""

    def list(self, access_token: str) -> DriveMetadata: ...


class ObservationSink(Protocol):
    """An append-only destination for sanitized observations."""

    def append(self, observation: Observation) -> None: ...


@dataclass(frozen=True)
class Runtime:
    """Replaceable collaborators for command tests and local execution."""

    load_settings: Callable[[], Settings]
    check_reachability: Callable[[Settings], None]
    acquire_token: Callable[[Settings, Callable[[str], None]], str]
    validate_token: Callable[[Settings, str], None]
    agentcore: Callable[[Settings], IdentityClient]
    downstream: Callable[[Settings], ResourceClient]
    clock: Callable[[], float]
    evidence_writer: Callable[[Path], ObservationSink]
    stdin_isatty: Callable[[], bool]
    read_stdin_line: Callable[[], str] = lambda: sys.stdin.readline()
    google_drive: Callable[[Settings], GoogleDriveResourceClient] = lambda _: GoogleDriveClient()
    open_browser: Callable[[str], bool] = webbrowser.open
    random_urlsafe: Callable[[], str] = lambda: secrets.token_urlsafe(32)


app = typer.Typer(add_completion=False, no_args_is_help=True)


@app.callback()
def main() -> None:
    """Run AgentCore Identity POC commands."""


@app.command("preflight")
def preflight(json_output: Annotated[bool, typer.Option("--json")] = False) -> None:
    """Check local configuration before any provider reachability work."""
    runtime = runtime_factory()
    try:
        settings = runtime.load_settings()
    except SettingsError as error:
        _emit_configuration_failure(error, json_output=json_output)

    try:
        runtime.check_reachability(settings)
    except AgentCoreError:
        _emit_blocked("identity_broker", _AGENTCORE_EXIT, "agentcore_unreachable")

    if json_output:
        typer.echo(_json_line({"status": "ready", "category": "configuration"}))
    else:
        typer.echo("Local configuration is valid")


@app.command("entra-obo")
def entra_obo(
    token_stdin: Annotated[bool, typer.Option("--token-stdin")] = False,
    evidence_path: Annotated[Path, typer.Option()] = _DEFAULT_EVIDENCE_PATH,
) -> None:
    """Validate an Entra user and call the synthetic resource through AgentCore OBO."""
    runtime = runtime_factory()
    try:
        settings = runtime.load_settings()
    except SettingsError as error:
        _emit_configuration_failure(error, json_output=True)

    writer = runtime.evidence_writer(evidence_path)
    try:
        inbound_token = _get_inbound_token(runtime, settings, token_stdin=token_stdin)
    except _InteractiveStdinError:
        _emit_blocked(
            "configuration",
            _CONFIGURATION_EXIT,
            "token_stdin_requires_noninteractive_input",
        )
    except (EntraAuthError, TokenRejected):
        _append(writer, "H1", "acquire_inbound_token", "fail", {"category": "authentication"})
        _emit_blocked("authentication", _AUTHENTICATION_EXIT, "inbound_token_unavailable")

    started_at = runtime.clock()
    try:
        runtime.validate_token(settings, inbound_token)
    except (EntraAuthError, TokenRejected):
        _append(writer, "H1", "validate_inbound_token", "fail", {"category": "authentication"})
        _emit_blocked("authentication", _AUTHENTICATION_EXIT, "inbound_token_rejected")

    try:
        identity = runtime.agentcore(settings)
        workload_token = identity.workload_token(
            settings.agentcore_workload_name, inbound_token
        )
    except AgentCoreError:
        _append(writer, "H1", "workload_token", "fail", {"category": "identity_broker"})
        _emit_blocked("identity_broker", _AGENTCORE_EXIT, "workload_token_unavailable")

    _append(
        writer,
        "H1",
        "workload_token",
        "pass",
        {
            "workload_name": settings.agentcore_workload_name,
            "latency_ms": _elapsed_milliseconds(runtime, started_at),
        },
    )

    try:
        downstream_token = identity.obo_token(
            workload_token,
            settings.agentcore_microsoft_provider,
            [settings.entra_downstream_scope],
        )
    except AgentCoreError:
        _append(writer, "H2", "obo_token", "fail", {"category": "identity_broker"})
        _emit_blocked("identity_broker", _AGENTCORE_EXIT, "obo_token_unavailable")

    _append(
        writer,
        "H2",
        "obo_token",
        "pass",
        {
            "provider": settings.agentcore_microsoft_provider,
            "scope": settings.entra_downstream_scope,
            "latency_ms": _elapsed_milliseconds(runtime, started_at),
        },
    )

    resource_client = runtime.downstream(settings)
    try:
        metadata = resource_client.list(downstream_token)
    except DownstreamError:
        _append(writer, "H6", "synthetic_resource", "fail", {"category": "denied"})
        _emit_blocked("downstream_denied", _DOWNSTREAM_EXIT, "synthetic_resource_denied")
    finally:
        _close_resource_client(resource_client)

    _append(
        writer,
        "H6",
        "synthetic_resource",
        "pass",
        {"status": 200, "item_count": len(metadata.items)},
    )
    typer.echo(_json_line({"status": "pass", "operation": "entra-obo", "resource_status": 200}))


@app.command("google-connect")
def google_connect(
    open_browser: Annotated[bool, typer.Option("--open-browser/--print-url")] = True,
) -> None:
    """Open or print the same-origin browser session-binding entry point."""
    runtime = runtime_factory()
    try:
        settings = runtime.load_settings()
    except SettingsError as error:
        _emit_configuration_failure(error, json_output=True)

    connect_url = f"{settings.public_base_url}/connect"
    if open_browser:
        runtime.open_browser(connect_url)
        typer.echo(_json_line({"status": "authorization_started"}))
        return
    typer.echo(_json_line({"status": "authorization_started", "url": connect_url}))


@app.command("google-list")
def google_list(
    evidence_path: Annotated[Path, typer.Option()] = _DEFAULT_GOOGLE_EVIDENCE_PATH,
) -> None:
    """Retrieve a vaulted Google token and list aggregate Drive metadata."""
    runtime = runtime_factory()
    try:
        settings = runtime.load_settings()
    except SettingsError as error:
        _emit_configuration_failure(error, json_output=True)

    writer = runtime.evidence_writer(evidence_path)
    _, identity, workload_token = _validated_google_identity(runtime, settings, writer)
    authorization = _request_google_token(runtime, settings, identity, workload_token, writer)
    if isinstance(authorization, AuthorizationRequired):
        _emit_authorization_required()

    try:
        metadata = _list_google_metadata(runtime, settings, authorization.access_token, writer)
    except DownstreamUnauthorized:
        _emit_blocked("downstream_denied", _DOWNSTREAM_EXIT, "google_drive_unauthorized")
    type_counts: dict[str, JsonValue] = {
        mime_type: count for mime_type, count in metadata.type_counts.items()
    }
    _append(
        writer,
        "H6",
        "google_drive_metadata",
        "pass",
        {"item_count": metadata.item_count, "type_counts": type_counts},
    )
    typer.echo(
        _json_line(
            {
                "status": "pass",
                "operation": "google-list",
                "item_count": metadata.item_count,
                "type_counts": type_counts,
            }
        )
    )


@app.command("google-revoke-check")
def google_revoke_check(
    evidence_path: Annotated[Path, typer.Option()] = _DEFAULT_GOOGLE_EVIDENCE_PATH,
) -> None:
    """Detect a revoked Google token and request one new browser authorization."""
    runtime = runtime_factory()
    try:
        settings = runtime.load_settings()
    except SettingsError as error:
        _emit_configuration_failure(error, json_output=True)

    writer = runtime.evidence_writer(evidence_path)
    _, identity, workload_token = _validated_google_identity(runtime, settings, writer)
    authorization = _request_google_token(runtime, settings, identity, workload_token, writer)
    if isinstance(authorization, AuthorizationRequired):
        _emit_authorization_required()

    try:
        _list_google_metadata(runtime, settings, authorization.access_token, writer)
    except DownstreamUnauthorized:
        _request_google_token(
            runtime,
            settings,
            identity,
            workload_token,
            writer,
            force_authentication=True,
        )
        _emit_authorization_required()

    typer.echo(_json_line({"status": "pass", "operation": "google-revoke-check"}))


class _InteractiveStdinError(ValueError):
    """Raised when a token could be exposed by terminal input."""


def _validated_google_identity(
    runtime: Runtime,
    settings: Settings,
    writer: ObservationSink,
) -> tuple[str, IdentityClient, str]:
    try:
        token = runtime.acquire_token(settings, typer.echo)
        runtime.validate_token(settings, token)
    except (EntraAuthError, TokenRejected):
        _append(writer, "H1", "validate_inbound_token", "fail", {"category": "authentication"})
        _emit_blocked("authentication", _AUTHENTICATION_EXIT, "inbound_token_rejected")

    try:
        identity = runtime.agentcore(settings)
        workload_token = identity.workload_token(settings.agentcore_workload_name, token)
    except AgentCoreError:
        _append(writer, "H1", "workload_token", "fail", {"category": "identity_broker"})
        _emit_blocked("identity_broker", _AGENTCORE_EXIT, "workload_token_unavailable")

    _append(
        writer,
        "H1",
        "workload_token",
        "pass",
        {"workload_name": settings.agentcore_workload_name},
    )
    return token, identity, workload_token


def _request_google_token(
    runtime: Runtime,
    settings: Settings,
    identity: IdentityClient,
    workload_token: str,
    writer: ObservationSink,
    *,
    force_authentication: bool = False,
) -> OAuthToken | AuthorizationRequired:
    try:
        authorization = identity.google_token(
            workload_token,
            settings.agentcore_google_provider,
            [_GOOGLE_DRIVE_METADATA_SCOPE],
            settings.google_return_url,
            runtime.random_urlsafe(),
            force_authentication=force_authentication,
        )
    except AgentCoreError:
        _append(writer, "H3", "google_vault_token", "fail", {"category": "identity_broker"})
        _emit_blocked("identity_broker", _AGENTCORE_EXIT, "google_token_unavailable")

    if isinstance(authorization, AuthorizationRequired):
        _append(
            writer,
            "H3",
            "google_vault_token",
            "authorization_required",
            {"provider": settings.agentcore_google_provider},
        )
    else:
        _append(
            writer,
            "H3",
            "google_vault_token",
            "pass",
            {"provider": settings.agentcore_google_provider},
        )
    return authorization


def _list_google_metadata(
    runtime: Runtime,
    settings: Settings,
    access_token: str,
    writer: ObservationSink,
) -> DriveMetadata:
    drive = runtime.google_drive(settings)
    try:
        return drive.list(access_token)
    except DownstreamUnauthorized:
        _append(writer, "H6", "google_drive_metadata", "fail", {"category": "unauthorized"})
        raise
    except DownstreamError:
        _append(writer, "H6", "google_drive_metadata", "fail", {"category": "denied"})
        _emit_blocked("downstream_denied", _DOWNSTREAM_EXIT, "google_drive_denied")
    finally:
        _close_resource_client(drive)


def _get_inbound_token(runtime: Runtime, settings: Settings, *, token_stdin: bool) -> str:
    if not token_stdin:
        return runtime.acquire_token(settings, typer.echo)
    if runtime.stdin_isatty():
        raise _InteractiveStdinError()

    token = runtime.read_stdin_line().rstrip("\r\n")
    if not token:
        raise EntraAuthError("missing_token")
    return token


def _append(
    writer: ObservationSink,
    hypothesis: str,
    operation: str,
    outcome: str,
    details: Mapping[str, JsonValue],
) -> None:
    writer.append(Observation(hypothesis, operation, outcome, details))


def _elapsed_milliseconds(runtime: Runtime, started_at: float) -> int:
    return max(0, round((runtime.clock() - started_at) * 1_000))


def _close_resource_client(resource_client: object) -> None:
    close = getattr(resource_client, "close", None)
    if callable(close):
        close()


def _emit_configuration_failure(error: SettingsError, *, json_output: bool) -> None:
    if json_output:
        typer.echo(
            _json_line(
                {"status": "blocked", "category": "configuration", "detail": str(error)}
            )
        )
    else:
        typer.echo(f"Configuration blocked: {error}")
    raise typer.Exit(code=_CONFIGURATION_EXIT)


def _emit_blocked(category: str, exit_code: int, detail: str) -> NoReturn:
    typer.echo(_json_line({"status": "blocked", "category": category, "detail": detail}))
    raise typer.Exit(code=exit_code)


def _emit_authorization_required() -> NoReturn:
    typer.echo(
        _json_line(
            {
                "status": "authorization_required",
                "category": "authentication",
                "detail": "google_authorization_required",
            }
        )
    )
    raise typer.Exit(code=_AUTHENTICATION_EXIT)


def _json_line(value: Mapping[str, JsonValue]) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=False)


def _default_runtime() -> Runtime:
    return Runtime(
        load_settings=lambda: Settings.from_mapping(os.environ),
        check_reachability=_check_agentcore_reachability,
        acquire_token=_acquire_device_code_token,
        validate_token=_validate_inbound_token,
        agentcore=_agentcore_identity,
        downstream=lambda settings: SyntheticResourceClient(settings.resource_api_url),
        clock=time.monotonic,
        evidence_writer=EvidenceWriter,
        stdin_isatty=lambda: sys.stdin.isatty(),
    )


def _acquire_device_code_token(settings: Settings, display: Callable[[str], None]) -> str:
    worker_scope = f"api://{settings.entra_api_client_id}/access_as_user"
    return EntraDeviceAuth.for_tenant(
        settings.entra_public_client_id,
        settings.entra_tenant_id,
        [worker_scope],
    ).acquire(display)


def _validate_inbound_token(settings: Settings, token: str) -> None:
    jwks_url = f"https://login.microsoftonline.com/{settings.entra_tenant_id}/discovery/v2.0/keys"
    JwtPolicy(
        issuer=settings.entra_issuer,
        audience=f"api://{settings.entra_api_client_id}",
        jwks_loader=make_http_jwks_loader(jwks_url),
    ).validate(token)


def _agentcore_identity(settings: Settings) -> AgentCoreIdentity:
    client = boto3.client("bedrock-agentcore", region_name=settings.aws_region)
    return AgentCoreIdentity(cast(AgentCoreDataPlane, client))


def _check_agentcore_reachability(settings: Settings) -> None:
    """Verify access to the configured workload using one read-only control-plane call."""
    try:
        client = boto3.client("bedrock-agentcore-control", region_name=settings.aws_region)
        client.get_workload_identity(name=settings.agentcore_workload_name)
    except Exception as error:
        raise AgentCoreInternalError() from error


runtime_factory: Callable[[], Runtime] = _default_runtime
