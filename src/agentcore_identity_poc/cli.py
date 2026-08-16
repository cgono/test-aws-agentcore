"""Command-line entry point for the AgentCore Identity POC."""

from __future__ import annotations

import json
import os
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Protocol, cast

import boto3  # type: ignore[import-untyped]
import typer

from agentcore_identity_poc.agentcore import AgentCoreDataPlane, AgentCoreError, AgentCoreIdentity
from agentcore_identity_poc.config import Settings, SettingsError
from agentcore_identity_poc.downstream import (
    DownstreamError,
    SyntheticMetadata,
    SyntheticResourceClient,
)
from agentcore_identity_poc.entra import EntraAuthError, EntraDeviceAuth
from agentcore_identity_poc.evidence import EvidenceWriter
from agentcore_identity_poc.jwt_validation import JwtPolicy, TokenRejected, make_http_jwks_loader
from agentcore_identity_poc.models import Observation

_CONFIGURATION_EXIT = 2
_AUTHENTICATION_EXIT = 3
_AGENTCORE_EXIT = 4
_DOWNSTREAM_EXIT = 5
_DEFAULT_EVIDENCE_PATH = Path("evidence/phase-1.jsonl")


class IdentityClient(Protocol):
    """Only the token operations required by the Entra OBO command."""

    def workload_token(self, workload_name: str, user_token: str) -> str: ...

    def obo_token(self, workload_token: str, provider: str, scopes: list[str]) -> str: ...


class ResourceClient(Protocol):
    """The narrow synthetic-resource boundary used by this command."""

    def list(self, access_token: str) -> SyntheticMetadata: ...


class ObservationSink(Protocol):
    """An append-only destination for sanitized observations."""

    def append(self, observation: Observation) -> None: ...


@dataclass(frozen=True)
class Runtime:
    """Replaceable collaborators for command tests and local execution."""

    load_settings: Callable[[], Settings]
    acquire_token: Callable[[Settings, Callable[[str], None]], str]
    validate_token: Callable[[Settings, str], None]
    agentcore: Callable[[Settings], IdentityClient]
    downstream: Callable[[Settings], ResourceClient]
    clock: Callable[[], float]
    evidence_writer: Callable[[Path], ObservationSink]
    stdin_isatty: Callable[[], bool]
    read_stdin_line: Callable[[], str] = lambda: sys.stdin.readline()


app = typer.Typer(add_completion=False, no_args_is_help=True)


@app.callback()
def main() -> None:
    """Run AgentCore Identity POC commands."""


@app.command("preflight")
def preflight(json_output: Annotated[bool, typer.Option("--json")] = False) -> None:
    """Check local configuration before any provider reachability work."""
    runtime = runtime_factory()
    try:
        runtime.load_settings()
    except SettingsError as error:
        _emit_configuration_failure(error, json_output=json_output)

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


class _InteractiveStdinError(ValueError):
    """Raised when a token could be exposed by terminal input."""


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
    details: dict[str, bool | int | str],
) -> None:
    writer.append(Observation(hypothesis, operation, outcome, details))


def _elapsed_milliseconds(runtime: Runtime, started_at: float) -> int:
    return max(0, round((runtime.clock() - started_at) * 1_000))


def _close_resource_client(resource_client: ResourceClient) -> None:
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


def _emit_blocked(category: str, exit_code: int, detail: str) -> None:
    typer.echo(_json_line({"status": "blocked", "category": category, "detail": detail}))
    raise typer.Exit(code=exit_code)


def _json_line(value: dict[str, bool | int | str]) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=False)


def _default_runtime() -> Runtime:
    return Runtime(
        load_settings=lambda: Settings.from_mapping(os.environ),
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


runtime_factory: Callable[[], Runtime] = _default_runtime
