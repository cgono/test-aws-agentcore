"""Command-line entry point for the AgentCore Identity POC."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sys
import time
import webbrowser
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Lock
from typing import Annotated, NoReturn, Protocol, cast

import boto3  # type: ignore[import-untyped]
import typer

from agentcore_identity_poc.agentcore import (
    AgentCoreDataPlane,
    AgentCoreError,
    AgentCoreIdentity,
    AgentCoreInternalError,
    AgentCoreThrottled,
    AuthorizationRequired,
    OAuthToken,
)
from agentcore_identity_poc.assessment import (
    AssessmentError,
    decide,
    load_terminal_results,
    render_markdown,
)
from agentcore_identity_poc.config import Settings, SettingsError
from agentcore_identity_poc.downstream import (
    DownstreamError,
    DownstreamThrottled,
    DownstreamUnauthorized,
    DriveMetadata,
    GoogleDriveClient,
    SyntheticMetadata,
    SyntheticResourceClient,
    drive_metadata_marker,
)
from agentcore_identity_poc.entra import EntraAuthError, EntraDeviceAuth
from agentcore_identity_poc.evidence import EvidenceWriter
from agentcore_identity_poc.experiments import (
    CloudTrailAttribution,
    ExperimentConfigurationError,
    ExperimentTimeout,
    ExpiryComparison,
    ExpiryObservation,
    MatrixRow,
    MeasurementConfigurationError,
    PolicyRestorationError,
    RetryableMeasurementError,
    SourceExpiryExperiment,
    StoredExpiryObservation,
    WorkloadAttempt,
    WorkloadPolicyManager,
    cold_warm_latency_report,
    compare_expiry_observations,
    load_expiry_resume_state,
    measure_bounded_concurrency,
    measure_latency,
    record_expiry_state,
    retry_with_backoff,
    run_user_isolation,
    run_workload_isolation,
    token_fingerprint,
)
from agentcore_identity_poc.jwt_validation import JwtPolicy, TokenRejected, make_http_jwks_loader
from agentcore_identity_poc.models import JsonValue, Observation

_CONFIGURATION_EXIT = 2
_AUTHENTICATION_EXIT = 3
_AGENTCORE_EXIT = 4
_DOWNSTREAM_EXIT = 5
_DEFAULT_EVIDENCE_PATH = Path("evidence/phase-1.jsonl")
_DEFAULT_GOOGLE_EVIDENCE_PATH = Path("evidence/phase-2.jsonl")
_GOOGLE_DRIVE_METADATA_SCOPE = "https://www.googleapis.com/auth/drive.metadata.readonly"
_POLICY_NAME = "agentcore-identity-poc-scoped"
_STATE_PATH = Path(".poc-state.json")
_DEFAULT_EXPIRY_STATE_PATH = Path(".poc-expiry-state.json")
_SAFE_ALIAS_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")


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
    validate_token: Callable[[Settings, str], Mapping[str, object]]
    agentcore: Callable[[Settings], IdentityClient]
    downstream: Callable[[Settings], ResourceClient]
    clock: Callable[[], float]
    evidence_writer: Callable[[Path], ObservationSink]
    stdin_isatty: Callable[[], bool]
    read_stdin_line: Callable[[], str] = lambda: sys.stdin.readline()
    google_drive: Callable[[Settings], GoogleDriveResourceClient] = lambda _: GoogleDriveClient()
    open_browser: Callable[[str], bool] = webbrowser.open
    random_urlsafe: Callable[[], str] = lambda: secrets.token_urlsafe(32)
    wall_clock: Callable[[], float] = time.time
    sleep: Callable[[float], None] = time.sleep
    random_unit: Callable[[], float] = secrets.SystemRandom().random
    cloudtrail_events: Callable[[Settings, int], CloudTrailAttribution] = (
        lambda settings, lookback: _cloudtrail_attribution(settings, lookback)
    )
    source_expiry_runner: Callable[
        [Settings, IdentityClient, str, float, Callable[[], float]], SourceExpiryExperiment
    ] | None = None


class _RetryCounters:
    """Thread-safe aggregate retry evidence for one measurement command."""

    def __init__(self) -> None:
        self.throttle_count = 0
        self.retry_attempts = 0
        self.backoff_ms = 0
        self._lock = Lock()

    def record_throttle(self) -> None:
        with self._lock:
            self.throttle_count += 1

    def record_retry(self, delay: float) -> None:
        with self._lock:
            self.retry_attempts += 1
            self.backoff_ms += max(0, round(delay * 1_000))


@dataclass(frozen=True)
class _GoogleDriveMeasurement:
    workload_fingerprint: str
    google_fingerprint: str
    drive_marker: str
    cold: bool
    workload_latency_ms: int
    google_latency_ms: int
    drive_latency_ms: int


app = typer.Typer(add_completion=False, no_args_is_help=True)
measure_app = typer.Typer(no_args_is_help=True)
offboard_app = typer.Typer(no_args_is_help=True)
app.add_typer(measure_app, name="measure")
app.add_typer(offboard_app, name="offboard")


@app.callback()
def main() -> None:
    """Run AgentCore Identity POC commands."""


@app.command("report")
def report(
    evidence: Annotated[Path, typer.Option("--evidence")],
    output: Annotated[Path, typer.Option("--output")],
    iam_acceptable: Annotated[bool, typer.Option("--iam-acceptable/--iam-unacceptable")] = False,
    audit_acceptable: Annotated[
        bool, typer.Option("--audit-acceptable/--audit-unacceptable")
    ] = False,
    latency_acceptable: Annotated[
        bool, typer.Option("--latency-acceptable/--latency-unacceptable")
    ] = False,
    quota_acceptable: Annotated[
        bool, typer.Option("--quota-acceptable/--quota-unacceptable")
    ] = False,
    custom_provider_plausible: Annotated[
        bool, typer.Option("--custom-provider-plausible/--custom-provider-incompatible")
    ] = True,
) -> None:
    """Create a status-only suitability assessment from explicit terminal evidence."""
    try:
        results = load_terminal_results(evidence)
        custom_provider_path_plausible = custom_provider_plausible and results["H5"] == "pass"
        decision = decide(
            results,
            iam_acceptable=iam_acceptable,
            custom_provider_plausible=custom_provider_path_plausible,
            audit_acceptable=audit_acceptable,
            latency_acceptable=latency_acceptable,
            quota_acceptable=quota_acceptable,
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            render_markdown(
                results,
                decision,
                custom_provider_plausible=custom_provider_path_plausible,
            ),
            encoding="utf-8",
        )
    except AssessmentError:
        typer.echo(_json_line({"status": "blocked", "category": "assessment_incomplete"}))
        raise typer.Exit(code=_CONFIGURATION_EXIT) from None
    typer.echo(_json_line({"status": "pass", "operation": "report", "decision": decision}))


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
        typer.echo(
            _json_line(
                {
                    "status": "ready",
                    "category": "configuration",
                    "agentcore_authorized_domain": (
                        f"bedrock-agentcore.{settings.aws_region}.amazonaws.com"
                    ),
                }
            )
        )
    else:
        typer.echo("Local configuration is valid")


@measure_app.command("latency")
def measure_latency_command(
    samples: Annotated[int, typer.Option("--samples")] = 10,
    evidence_path: Annotated[Path, typer.Option()] = _DEFAULT_GOOGLE_EVIDENCE_PATH,
) -> None:
    """Measure cold and warm workload-to-Google-Drive latency without retaining tokens."""
    runtime = runtime_factory()
    try:
        settings = runtime.load_settings()
        writer = runtime.evidence_writer(evidence_path)
        inbound_token, identity = _measurement_identity(runtime, settings, writer)
        measurements: list[_GoogleDriveMeasurement] = []
        fingerprint_salt = runtime.random_urlsafe()
        report = measure_latency(
            samples=samples,
            operation=lambda cold: measurements.append(
                _google_drive_measurement(
                    runtime,
                    settings,
                    identity,
                    inbound_token,
                    cold=cold,
                    fingerprint_salt=fingerprint_salt,
                )
            ),
            clock=runtime.clock,
        )
    except SettingsError as error:
        _emit_configuration_failure(error, json_output=True)
    except MeasurementConfigurationError as error:
        _emit_blocked("configuration", _CONFIGURATION_EXIT, str(error))
    except AgentCoreError:
        _emit_blocked("identity_broker", _AGENTCORE_EXIT, "workload_token_unavailable")
    except RetryableMeasurementError:
        _append(writer, "H7", "measure_latency", "fail", {"category": "throttled"})
        _emit_blocked("identity_broker", _AGENTCORE_EXIT, "measurement_throttled")
    except DownstreamUnauthorized:
        _append(writer, "H6", "measure_latency", "fail", {"category": "unauthorized"})
        _emit_blocked("downstream_denied", _DOWNSTREAM_EXIT, "google_drive_unauthorized")
    except DownstreamError:
        _append(writer, "H6", "measure_latency", "fail", {"category": "denied"})
        _emit_blocked("downstream_denied", _DOWNSTREAM_EXIT, "google_drive_denied")
    workload_cache_equivalent = len({item.workload_fingerprint for item in measurements}) == 1
    google_cache_equivalent = len({item.google_fingerprint for item in measurements}) == 1
    drive_result_equivalent = len({item.drive_marker for item in measurements}) == 1
    stage_latency_ms = _stage_latency_details(measurements)
    _append(
        writer,
        "H7",
        "measure_latency",
        "pass",
        {
            "sample_count": len(report.samples),
            "cold_sample_count": sum(sample.cold for sample in report.samples),
            "warm_sample_count": sum(not sample.cold for sample in report.samples),
            "p50_ms": report.p50_ms,
            "p95_ms": report.p95_ms,
            "workload_cache_equivalent": workload_cache_equivalent,
            "google_cache_equivalent": google_cache_equivalent,
            "drive_result_equivalent": drive_result_equivalent,
            "stage_latency_ms": stage_latency_ms,
        },
    )
    typer.echo(
        _json_line(
            {
                "status": "pass",
                "operation": "measure_latency",
                "samples": len(report.samples),
                "cold_samples": sum(sample.cold for sample in report.samples),
                "warm_samples": sum(not sample.cold for sample in report.samples),
                "p50_ms": report.p50_ms,
                "p95_ms": report.p95_ms,
                "workload_cache_equivalent": workload_cache_equivalent,
                "google_cache_equivalent": google_cache_equivalent,
                "drive_result_equivalent": drive_result_equivalent,
                "stage_latency_ms": stage_latency_ms,
            }
        )
    )


@measure_app.command("concurrency")
def measure_concurrency_command(
    workers: Annotated[int, typer.Option("--workers")] = 5,
    requests: Annotated[int, typer.Option("--requests")] = 20,
    documented_quota: Annotated[int | None, typer.Option("--documented-quota")] = None,
    temporal_target: Annotated[int | None, typer.Option("--temporal-target")] = None,
    evidence_path: Annotated[Path, typer.Option()] = _DEFAULT_GOOGLE_EVIDENCE_PATH,
) -> None:
    """Measure end-to-end throttling while bounding concurrent Google Drive requests."""
    runtime = runtime_factory()
    try:
        settings = runtime.load_settings()
        writer = runtime.evidence_writer(evidence_path)
        inbound_token, identity = _measurement_identity(runtime, settings, writer)
        measurements: list[_GoogleDriveMeasurement] = []
        marker_lock = Lock()
        counters = _RetryCounters()
        fingerprint_salt = runtime.random_urlsafe()

        def request(index: int) -> None:
            measurement = _google_drive_measurement(
                runtime,
                settings,
                identity,
                inbound_token,
                counters=counters,
                cold=index == 0,
                fingerprint_salt=fingerprint_salt,
            )
            with marker_lock:
                measurements.append(measurement)

        report = measure_bounded_concurrency(
            workers=workers,
            requests=requests,
            request=request,
        )
    except SettingsError as error:
        _emit_configuration_failure(error, json_output=True)
    except MeasurementConfigurationError as error:
        _emit_blocked("configuration", _CONFIGURATION_EXIT, str(error))
    except AgentCoreError:
        _emit_blocked("identity_broker", _AGENTCORE_EXIT, "workload_token_unavailable")
    except RetryableMeasurementError:
        _append(writer, "H7", "measure_concurrency", "fail", {"category": "throttled"})
        _emit_blocked("identity_broker", _AGENTCORE_EXIT, "measurement_throttled")
    except DownstreamUnauthorized:
        _append(writer, "H6", "measure_concurrency", "fail", {"category": "unauthorized"})
        _emit_blocked("downstream_denied", _DOWNSTREAM_EXIT, "google_drive_unauthorized")
    except DownstreamError:
        _append(writer, "H6", "measure_concurrency", "fail", {"category": "denied"})
        _emit_blocked("downstream_denied", _DOWNSTREAM_EXIT, "google_drive_denied")
    workload_cache_equivalent = len({item.workload_fingerprint for item in measurements}) == 1
    google_cache_equivalent = len({item.google_fingerprint for item in measurements}) == 1
    drive_result_equivalent = len({item.drive_marker for item in measurements}) == 1
    stage_latency_ms = _stage_latency_details(measurements)
    readiness_details = _concurrency_readiness(
        actual_probe_concurrency=report.maximum_workers,
        documented_quota=documented_quota,
        temporal_target=temporal_target,
    )
    _append(
        writer,
        "H7",
        "measure_concurrency",
        "pass",
        {
            "workers": report.maximum_workers,
            "requests": report.completed,
            "workload_cache_equivalent": workload_cache_equivalent,
            "google_cache_equivalent": google_cache_equivalent,
            "drive_result_equivalent": drive_result_equivalent,
            "throttle_count": counters.throttle_count,
            "retry_attempts": counters.retry_attempts,
            "backoff_ms": counters.backoff_ms,
            "stage_latency_ms": stage_latency_ms,
            **readiness_details,
        },
    )
    typer.echo(
        _json_line(
            {
                "status": "pass",
                "operation": "measure_concurrency",
                "workers": report.maximum_workers,
                "requests": report.completed,
                "workload_cache_equivalent": workload_cache_equivalent,
                "google_cache_equivalent": google_cache_equivalent,
                "drive_result_equivalent": drive_result_equivalent,
                "throttle_count": counters.throttle_count,
                "retry_attempts": counters.retry_attempts,
                "backoff_ms": counters.backoff_ms,
                "stage_latency_ms": stage_latency_ms,
                **readiness_details,
            }
        )
    )


@measure_app.command("expiry")
def measure_expiry_command(
    resume_state: Annotated[Path, typer.Option("--resume-state")] = _DEFAULT_EXPIRY_STATE_PATH,
    evidence_path: Annotated[Path, typer.Option()] = _DEFAULT_GOOGLE_EVIDENCE_PATH,
) -> None:
    """Issue distinct token types, save opaque lifecycle state, and exit for later resume."""
    runtime = runtime_factory()
    try:
        settings = runtime.load_settings()
        writer = runtime.evidence_writer(evidence_path)
        project_id = _measurement_project_id(settings)
        resumed = resume_state.exists()
        prior_entries: tuple[StoredExpiryObservation, ...] = ()
        resume_at: float | None = None
        if resumed:
            prior_entries = load_expiry_resume_state(resume_state, project_id=project_id)
            now = runtime.wall_clock()
            pending = [
                entry.expires_at
                for entry in prior_entries
                if entry.kind != "google_token"
                and entry.expires_at is not None
                and entry.expires_at > now
            ]
            if pending:
                resume_at = min(pending)
                typer.echo(
                    _json_line(
                        {
                            "status": "resume_required",
                            "operation": "measure_expiry",
                            "resume_at": resume_at,
                            "pending_token_kinds": [
                                entry.kind
                                for entry in prior_entries
                                if entry.expires_at is not None
                                and entry.expires_at > now
                            ],
                        }
                    )
                )
                return
        entries = _issue_expiry_observations(runtime, settings, writer)
        now = runtime.wall_clock()
        source_expiry_result: SourceExpiryExperiment | None = None
        if not prior_entries and runtime.source_expiry_runner is not None:
            workload_token = next(
                entry.token for entry in entries if entry.kind == "workload_token"
            )
            inbound_expiry = next(
                entry.expires_at for entry in entries if entry.kind == "inbound_jwt"
            )
            if inbound_expiry is not None:
                source_expiry_result = runtime.source_expiry_runner(
                    settings,
                    runtime.agentcore(settings),
                    workload_token,
                    inbound_expiry,
                    runtime.wall_clock,
                )
        run_salt = _expiry_run_salt(project_id, min(entry.issued_at for entry in entries))
        comparisons: tuple[ExpiryComparison, ...] = ()
        if prior_entries:
            prior_run_salt = _expiry_run_salt(
                project_id,
                min(entry.issued_at for entry in prior_entries),
            )
            comparisons = compare_expiry_observations(
                prior_entries,
                entries,
                prior_run_salt=prior_run_salt,
            )
        resume_at = record_expiry_state(
            resume_state,
            project_id=project_id,
            entries=entries,
            run_salt=run_salt,
        )
    except SettingsError as error:
        _emit_configuration_failure(error, json_output=True)
    except MeasurementConfigurationError as error:
        _emit_blocked("configuration", _CONFIGURATION_EXIT, str(error))
    except AgentCoreError:
        _emit_blocked("identity_broker", _AGENTCORE_EXIT, "expiry_token_unavailable")
    comparisons_by_kind = {comparison.kind: comparison for comparison in comparisons}
    for entry in entries:
        hypothesis = "H3" if entry.kind == "google_token" else "H7"
        comparison = comparisons_by_kind.get(entry.kind)
        details: dict[str, JsonValue]
        if entry.kind == "google_token":
            outcome = "fail"
            operation = "provider_expiry_unavailable"
            details = {
                "token_kind": "google_token",
                "detail": "agentcore_response_lacks_provider_expiry_raw_token_not_retained",
            }
        elif comparison is None:
            outcome = "resume_required"
            operation = "expiry_issue"
            details = {
                "token_kind": entry.kind,
                "issued_at": entry.issued_at,
                "expires_at": entry.expires_at,
                "expiry_known": entry.expiry_known,
                "fingerprint": token_fingerprint(entry.token, run_salt=run_salt),
            }
        else:
            outcome = "unproven"
            operation = "fresh_token_comparison"
            details = {
                "token_kind": entry.kind,
                "prior_expiry_known": comparison.prior_expiry_known,
                "prior_expires_at": comparison.prior_expires_at,
                "previous_fingerprint": comparison.previous_fingerprint,
                "new_fingerprint": comparison.new_fingerprint,
                "fingerprint_changed": comparison.fingerprint_changed,
                "drive_metadata_observed": entry.drive_metadata_observed,
            }
        _append(
            writer,
            hypothesis,
            operation,
            outcome,
            details,
        )
    if source_expiry_result is None:
        _append(
            writer,
            "H7",
            "obo_after_inbound_expiry",
            "unproven",
            {"detail": "continuous_runner_not_configured"},
        )
    else:
        _append(
            writer,
            "H7",
            "obo_after_inbound_expiry",
            source_expiry_result.outcome,
            {
                "source_expired": source_expiry_result.source_expired,
                "obo_succeeded": source_expiry_result.obo_succeeded,
            },
        )
    typer.echo(
        _json_line(
            {
                "status": _expiry_command_status(comparisons_by_kind, entries, now),
                "operation": "measure_expiry",
                "resume_at": resume_at,
                "token_kinds": [entry.kind for entry in entries],
            }
        )
    )


@measure_app.command("cloudtrail")
def measure_cloudtrail_command(
    lookback_minutes: Annotated[int, typer.Option("--lookback-minutes")] = 30,
    evidence_path: Annotated[Path, typer.Option()] = _DEFAULT_GOOGLE_EVIDENCE_PATH,
) -> None:
    """Record presence-only AgentCore CloudTrail attribution without retaining event payloads."""
    if lookback_minutes < 1 or lookback_minutes > 1_440:
        _emit_blocked("configuration", _CONFIGURATION_EXIT, "lookback_minutes_must_be_1_to_1440")
    runtime = runtime_factory()
    try:
        settings = runtime.load_settings()
        writer = runtime.evidence_writer(evidence_path)
        attribution = runtime.cloudtrail_events(settings, lookback_minutes)
    except SettingsError as error:
        _emit_configuration_failure(error, json_output=True)
    except Exception:
        _emit_blocked("identity_broker", _AGENTCORE_EXIT, "cloudtrail_lookup_unavailable")
    _append(
        writer,
        "H7",
        "audit_attribution",
        attribution.outcome,
        {
            "lookback_minutes": lookback_minutes,
            "eligible_event_count": attribution.eligible_event_count,
            "aws_principal_present": attribution.aws_principal_present,
            "workload_identity_present": attribution.workload_identity_present,
            "user_correlation_present": attribution.user_correlation_present,
        },
    )
    typer.echo(
        _json_line(
            {
                "status": attribution.outcome,
                "operation": "measure_cloudtrail",
                "lookback_minutes": lookback_minutes,
                "eligible_event_count": attribution.eligible_event_count,
                "aws_principal_present": attribution.aws_principal_present,
                "workload_identity_present": attribution.workload_identity_present,
                "user_correlation_present": attribution.user_correlation_present,
            }
        )
    )


@offboard_app.command("google")
def offboard_google(
    user_alias: Annotated[str, typer.Option("--user-alias")],
    apply: Annotated[bool, typer.Option("--apply")] = False,
    evidence_path: Annotated[Path, typer.Option()] = _DEFAULT_GOOGLE_EVIDENCE_PATH,
) -> None:
    """Test revocation and reauthentication; never delete a shared credential provider."""
    if not apply:
        _emit_blocked("configuration", _CONFIGURATION_EXIT, "offboard_google_requires_apply")
    if not _SAFE_ALIAS_PATTERN.fullmatch(user_alias):
        _emit_blocked("configuration", _CONFIGURATION_EXIT, "invalid_user_alias")
    runtime = runtime_factory()
    try:
        settings = runtime.load_settings()
        writer = runtime.evidence_writer(evidence_path)
        inbound_token, identity = _measurement_identity(runtime, settings, writer)
        workload_token = _retry_agentcore(
            lambda: identity.workload_token(settings.agentcore_workload_name, inbound_token),
            runtime,
        )
        authorization = _retry_agentcore(
            lambda: identity.google_token(
                workload_token,
                settings.agentcore_google_provider,
                [_GOOGLE_DRIVE_METADATA_SCOPE],
                settings.google_return_url,
                runtime.random_urlsafe(),
                force_authentication=False,
            ),
            runtime,
        )
        if isinstance(authorization, AuthorizationRequired):
            _emit_authorization_required()
        drive = runtime.google_drive(settings)
        revocation_observed = False
        try:
            drive.list(authorization.access_token)
        except DownstreamUnauthorized:
            revocation_observed = True
        else:
            _append(
                writer,
                "H8",
                "google_revocation_probe",
                "fail",
                {"user_alias": user_alias, "detail": "drive_revocation_not_observed"},
            )
        finally:
            _close_resource_client(drive)
        if revocation_observed:
            reauthentication = _retry_agentcore(
                lambda: identity.google_token(
                    workload_token,
                    settings.agentcore_google_provider,
                    [_GOOGLE_DRIVE_METADATA_SCOPE],
                    settings.google_return_url,
                    runtime.random_urlsafe(),
                    force_authentication=True,
                ),
                runtime,
            )
            _append(
                writer,
                "H8",
                "google_revocation_probe",
                "pass",
                {
                    "user_alias": user_alias,
                    "detail": "drive_revoked_401_force_authentication_requested",
                    "reauthentication": (
                        "authorization_required"
                        if isinstance(reauthentication, AuthorizationRequired)
                        else "token_reissued"
                    ),
                },
            )
    except SettingsError as error:
        _emit_configuration_failure(error, json_output=True)
    except AgentCoreError:
        _emit_blocked("identity_broker", _AGENTCORE_EXIT, "google_revocation_check_unavailable")

    purge = getattr(identity, "purge_google_user_connection", None)
    if callable(purge):
        try:
            purge(user_alias)
        except Exception:
            _append(
                writer,
                "H8",
                "offboard_google",
                "fail",
                {"user_alias": user_alias, "detail": "per_user_purge_failed"},
            )
            typer.echo(
                _json_line(
                    {
                        "status": "failed",
                        "operation": "offboard_google",
                        "hypothesis": "H8",
                        "detail": "per_user_purge_failed",
                    }
                )
            )
            return
        purge_outcome = "pass" if revocation_observed else "fail"
        detail = (
            "per_user_purge_completed"
            if revocation_observed
            else "drive_revocation_not_observed"
        )
        _append(
            writer,
            "H8",
            "offboard_google",
            purge_outcome,
            {"user_alias": user_alias, "detail": detail},
        )
        typer.echo(
            _json_line(
                {
                "status": "pass" if revocation_observed else "failed",
                "operation": "offboard_google",
                "hypothesis": "H8",
                "detail": detail,
                }
            )
        )
        return

    detail = (
        "per_user_purge_unavailable"
        if revocation_observed
        else "drive_revocation_not_observed"
    )
    _append(
        writer,
        "H8",
        "offboard_google",
        "fail",
        {"user_alias": user_alias, "detail": detail},
    )
    typer.echo(
        _json_line(
            {
                "status": "failed",
                "operation": "offboard_google",
                "hypothesis": "H8",
                "detail": detail,
            }
        )
    )


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
        try:
            browser_opened = runtime.open_browser(connect_url)
        except webbrowser.Error:
            browser_opened = False
        if browser_opened:
            typer.echo(_json_line({"status": "authorization_started"}))
            return
        typer.echo(
            _json_line(
                {
                    "status": "authorization_started",
                    "mode": "print_url",
                    "url": connect_url,
                }
            )
        )
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
        {
            "item_count": metadata.item_count,
            "type_counts": type_counts,
            "connection_marker": drive_metadata_marker(metadata),
        },
    )
    typer.echo(
        _json_line(
            {
                "status": "pass",
                "operation": "google-list",
                "item_count": metadata.item_count,
                "type_counts": type_counts,
                "connection_marker": drive_metadata_marker(metadata),
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


@app.command("user-isolation")
def user_isolation(
    user_a_alias: Annotated[str, typer.Option("--user-a-alias")],
    user_b_alias: Annotated[str, typer.Option("--user-b-alias")],
    user_a_drive_marker: Annotated[str, typer.Option("--user-a-drive-marker")],
    user_b_drive_marker: Annotated[str, typer.Option("--user-b-drive-marker")],
    tokens_stdin: Annotated[bool, typer.Option("--tokens-stdin")] = False,
    evidence_path: Annotated[Path, typer.Option()] = _DEFAULT_GOOGLE_EVIDENCE_PATH,
) -> None:
    """Prove distinct users have independent vaulted Google connections."""
    runtime = runtime_factory()
    try:
        settings = runtime.load_settings()
        expected_connection_markers = _expected_connection_markers(
            user_a_alias,
            user_a_drive_marker,
            user_b_alias,
            user_b_drive_marker,
        )
        users = _get_isolation_users(
            runtime,
            settings,
            user_a_alias=user_a_alias,
            user_b_alias=user_b_alias,
            tokens_stdin=tokens_stdin,
        )
    except SettingsError as error:
        _emit_configuration_failure(error, json_output=True)
    except _InteractiveStdinError:
        _emit_blocked(
            "configuration",
            _CONFIGURATION_EXIT,
            "tokens_stdin_requires_noninteractive_input",
        )
    except (EntraAuthError, TokenRejected):
        _emit_blocked("authentication", _AUTHENTICATION_EXIT, "inbound_token_unavailable")
    except ExperimentConfigurationError as error:
        _emit_blocked("configuration", _CONFIGURATION_EXIT, str(error))

    writer = runtime.evidence_writer(evidence_path)
    try:
        rows = _run_user_isolation(
            runtime,
            settings,
            users,
            writer,
            expected_connection_markers=expected_connection_markers,
        )
    except (EntraAuthError, TokenRejected):
        _emit_blocked("authentication", _AUTHENTICATION_EXIT, "inbound_token_rejected")
    except ExperimentConfigurationError:
        _emit_blocked(
            "authentication", _AUTHENTICATION_EXIT, "distinct_verified_subjects_required"
        )
    except AgentCoreError:
        _emit_blocked("identity_broker", _AGENTCORE_EXIT, "google_token_unavailable")

    for row in rows:
        _append(writer, "H4a", "user_isolation", row.outcome, row.as_details())

    if any(row.outcome == "authorization_required" for row in rows):
        _emit_authorization_required()
    if any(row.outcome != "pass" for row in rows):
        if any(
            row.connection_marker is not None and row.outcome == "fail" for row in rows
        ):
            _emit_blocked(
                "downstream_denied", _DOWNSTREAM_EXIT, "google_connection_state_mismatch"
            )
        _emit_blocked("downstream_denied", _DOWNSTREAM_EXIT, "google_connection_unavailable")
    typer.echo(
        _json_line({"status": "pass", "operation": "user-isolation", "user_count": len(rows)})
    )


@app.command("workload-isolation")
def workload_isolation(
    acknowledge_broad_policy: Annotated[
        bool, typer.Option("--acknowledge-broad-policy")
    ] = False,
    evidence_path: Annotated[Path, typer.Option()] = _DEFAULT_GOOGLE_EVIDENCE_PATH,
) -> None:
    """Run the same-principal broad-versus-scoped IAM workload matrix."""
    if not acknowledge_broad_policy:
        _emit_blocked(
            "configuration", _CONFIGURATION_EXIT, "acknowledge_broad_policy_required"
        )

    runtime = runtime_factory()
    writer = runtime.evidence_writer(evidence_path)
    try:
        settings = runtime.load_settings()
        rows = _run_workload_isolation(
            runtime,
            settings,
            record_row=lambda row: _append(
                writer, "H4b", "workload_isolation", row.outcome, row.as_details()
            ),
        )
    except SettingsError as error:
        _emit_configuration_failure(error, json_output=True)
    except ExperimentConfigurationError as error:
        _emit_blocked("configuration", _CONFIGURATION_EXIT, str(error))
    except PolicyRestorationError as error:
        _emit_blocked("identity_broker", _AGENTCORE_EXIT, str(error))
    except ExperimentTimeout as error:
        _emit_blocked("identity_broker", _AGENTCORE_EXIT, str(error))
    typer.echo(
        _json_line(
            {
                "status": "pass",
                "operation": "workload-isolation",
                "attempt_count": len(rows),
            }
        )
    )


class _AwsIamPolicyManager(WorkloadPolicyManager):
    """Apply only the checked-in temporary and final inline IAM policies."""

    def __init__(self, iam_client: object, sts_client: object, role_name: str) -> None:
        self._iam_client = iam_client
        self._sts_client = sts_client
        self._role_name = role_name

    def caller_identity(self) -> str:
        response = cast(Mapping[str, object], self._sts_client.get_caller_identity())  # type: ignore[attr-defined]
        arn = response.get("Arn")
        if not isinstance(arn, str) or not arn:
            raise ExperimentConfigurationError("AWS caller identity response omitted an ARN")
        return f"aws-principal-{hashlib.sha256(arn.encode()).hexdigest()[:12]}"

    def apply_broad_policy(self) -> None:
        self._put_policy(_POLICY_NAME, _load_json_policy("broad-observation.json"))

    def apply_scoped_policy(self) -> None:
        state = _load_poc_state(_STATE_PATH)
        self._put_policy(_POLICY_NAME, _render_scoped_policy(state))

    def _put_policy(self, policy_name: str, policy: Mapping[str, object]) -> None:
        self._iam_client.put_role_policy(  # type: ignore[attr-defined]
            RoleName=self._role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy, separators=(",", ":"), sort_keys=True),
        )


def _run_workload_isolation(
    runtime: Runtime,
    settings: Settings,
    *,
    record_row: Callable[[MatrixRow], None] | None = None,
) -> tuple[MatrixRow, ...]:
    role_name = os.environ.get("AGENTCORE_POC_IAM_ROLE_NAME", "").strip()
    user_alias = os.environ.get("AGENTCORE_POC_USER_ALIAS", "").strip()
    if not role_name or not user_alias:
        raise ExperimentConfigurationError(
            "AGENTCORE_POC_IAM_ROLE_NAME and AGENTCORE_POC_USER_ALIAS must be set"
        )

    try:
        inbound_token = runtime.acquire_token(settings, typer.echo)
        runtime.validate_token(settings, inbound_token)
    except (EntraAuthError, TokenRejected) as error:
        raise ExperimentConfigurationError("could not validate the H4b Entra user") from error

    identity = runtime.agentcore(settings)
    policy_manager = _AwsIamPolicyManager(
        boto3.client("iam", region_name=settings.aws_region),
        boto3.client("sts", region_name=settings.aws_region),
        role_name,
    )

    def attempt_provider(workload_name: str) -> WorkloadAttempt:
        try:
            workload_token = identity.workload_token(workload_name, inbound_token)
            authorization = identity.google_token(
                workload_token,
                settings.agentcore_google_provider,
                [_GOOGLE_DRIVE_METADATA_SCOPE],
                settings.google_return_url,
                runtime.random_urlsafe(),
            )
        except AgentCoreError as error:
            return WorkloadAttempt(
                "denied" if _is_access_denied(error) else "fail",
                _aws_error_category(error),
            )
        if isinstance(authorization, AuthorizationRequired):
            return WorkloadAttempt("authorization_required")
        return WorkloadAttempt("pass")

    return run_workload_isolation(
        policy_manager=policy_manager,
        workload_names=(settings.agentcore_workload_name, settings.agentcore_second_workload_name),
        user_alias=user_alias,
        provider=settings.agentcore_google_provider,
        acknowledge_broad_policy=True,
        attempt_provider=attempt_provider,
        clock=runtime.clock,
        record_row=record_row,
    )


def _get_isolation_users(
    runtime: Runtime,
    settings: Settings,
    *,
    user_a_alias: str,
    user_b_alias: str,
    tokens_stdin: bool,
) -> tuple[tuple[str, str], tuple[str, str]]:
    aliases = (user_a_alias, user_b_alias)
    if len(set(aliases)) != 2 or not all(_SAFE_ALIAS_PATTERN.fullmatch(alias) for alias in aliases):
        raise ExperimentConfigurationError(
            "user aliases must be two distinct opaque values using letters, digits, "
            "hyphens, or underscores"
        )
    if tokens_stdin:
        return (
            (user_a_alias, _get_inbound_token(runtime, settings, token_stdin=True)),
            (user_b_alias, _get_inbound_token(runtime, settings, token_stdin=True)),
        )
    return (
        (user_a_alias, runtime.acquire_token(settings, typer.echo)),
        (user_b_alias, runtime.acquire_token(settings, typer.echo)),
    )


def _run_user_isolation(
    runtime: Runtime,
    settings: Settings,
    users: tuple[tuple[str, str], tuple[str, str]],
    writer: ObservationSink,
    *,
    expected_connection_markers: Mapping[str, str],
    on_verified_subject_count: Callable[[int], None] | None = None,
) -> tuple[MatrixRow, ...]:
    identity = runtime.agentcore(settings)

    def observe_connection(user_alias: str, workload_token: str) -> WorkloadAttempt:
        try:
            authorization = identity.google_token(
                workload_token,
                settings.agentcore_google_provider,
                [_GOOGLE_DRIVE_METADATA_SCOPE],
                settings.google_return_url,
                runtime.random_urlsafe(),
            )
        except AgentCoreError as error:
            return WorkloadAttempt(
                "denied" if _is_access_denied(error) else "fail",
                _aws_error_category(error),
            )
        if isinstance(authorization, AuthorizationRequired):
            return WorkloadAttempt("authorization_required")

        drive = runtime.google_drive(settings)
        try:
            metadata = drive.list(authorization.access_token)
        except DownstreamUnauthorized:
            _append(
                writer,
                "H6",
                "google_drive_metadata",
                "fail",
                {"user_alias": user_alias, "category": "unauthorized"},
            )
            return WorkloadAttempt("denied", "unauthorized")
        except DownstreamError:
            _append(
                writer,
                "H6",
                "google_drive_metadata",
                "fail",
                {"user_alias": user_alias, "category": "denied"},
            )
            return WorkloadAttempt("denied", "access_denied")
        finally:
            _close_resource_client(drive)

        _append(
            writer,
            "H6",
            "google_drive_metadata",
            "pass",
            {
                "user_alias": user_alias,
                "item_count": metadata.item_count,
                "type_counts": dict(metadata.type_counts),
                "connection_marker": drive_metadata_marker(metadata),
            },
        )
        return WorkloadAttempt("pass", connection_marker=drive_metadata_marker(metadata))

    return run_user_isolation(
        principal_alias="local-poc-worker",
        workload_name=settings.agentcore_workload_name,
        provider=settings.agentcore_google_provider,
        users=users,
        expected_connection_markers=expected_connection_markers,
        validate_user=lambda _, token: _validated_subject(runtime.validate_token(settings, token)),
        get_workload_token=lambda _, token: identity.workload_token(
            settings.agentcore_workload_name, token
        ),
        observe_connection=observe_connection,
        on_verified_subject_count=on_verified_subject_count,
    )


def run_live_user_isolation(
    *, on_verified_subject_count: Callable[[int], None] | None = None
) -> tuple[MatrixRow, ...]:
    """Run the opt-in H4a live path with two device-code authenticated users."""
    runtime = _default_runtime()
    settings = runtime.load_settings()
    user_a_alias = os.environ.get("AGENTCORE_POC_USER_A_ALIAS", "").strip()
    user_b_alias = os.environ.get("AGENTCORE_POC_USER_B_ALIAS", "").strip()
    expected_connection_markers = _expected_connection_markers(
        user_a_alias,
        os.environ.get("AGENTCORE_POC_USER_A_DRIVE_MARKER", "").strip(),
        user_b_alias,
        os.environ.get("AGENTCORE_POC_USER_B_DRIVE_MARKER", "").strip(),
    )
    users = _get_isolation_users(
        runtime,
        settings,
        user_a_alias=user_a_alias,
        user_b_alias=user_b_alias,
        tokens_stdin=False,
    )
    writer = runtime.evidence_writer(_DEFAULT_GOOGLE_EVIDENCE_PATH)
    rows = _run_user_isolation(
        runtime,
        settings,
        users,
        writer,
        expected_connection_markers=expected_connection_markers,
        on_verified_subject_count=on_verified_subject_count,
    )
    for row in rows:
        _append(writer, "H4a", "user_isolation", row.outcome, row.as_details())
    return rows


def _expected_connection_markers(
    user_a_alias: str,
    user_a_marker: str,
    user_b_alias: str,
    user_b_marker: str,
) -> dict[str, str]:
    markers = {user_a_alias: user_a_marker, user_b_alias: user_b_marker}
    if len(markers) != 2 or len(set(markers.values())) != 2 or not all(
        re.fullmatch(r"[0-9a-f]{64}", marker) for marker in markers.values()
    ):
        raise ExperimentConfigurationError(
            "H4a requires one sanitized expected Drive marker for each user alias"
        )
    return markers


def _load_json_policy(filename: str) -> Mapping[str, object]:
    policy_path = Path(__file__).resolve().parents[2] / "infra" / "iam" / filename
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ExperimentConfigurationError(
            f"could not load IAM policy template: {filename}"
        ) from error
    if not isinstance(policy, Mapping):
        raise ExperimentConfigurationError(f"IAM policy template must be an object: {filename}")
    return cast(Mapping[str, object], policy)


def _load_poc_state(path: Path) -> Mapping[str, object]:
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ExperimentConfigurationError(
            "could not read .poc-state.json for scoped policy recovery"
        ) from error
    if not isinstance(state, Mapping):
        raise ExperimentConfigurationError(".poc-state.json must contain an object")
    return cast(Mapping[str, object], state)


def _render_scoped_policy(state: Mapping[str, object]) -> Mapping[str, object]:
    workloads = state.get("workloads")
    provider = state.get("provider")
    if (
        not isinstance(workloads, list)
        or len(workloads) != 2
        or not all(isinstance(item, Mapping) for item in workloads)
        or not isinstance(provider, Mapping)
    ):
        raise ExperimentConfigurationError(
            ".poc-state.json does not contain the recorded scoped resources"
        )
    replacements = {
        "DIRECTORY_ARN": _required_state_arn(state, "directory_arn"),
        "WORKLOAD_ARN": _required_state_arn(cast(Mapping[str, object], workloads[0]), "arn"),
        "SECOND_WORKLOAD_ARN": _required_state_arn(cast(Mapping[str, object], workloads[1]), "arn"),
        "VAULT_ARN": _required_state_arn(state, "vault_arn"),
        "PROVIDER_ARN": _required_state_arn(cast(Mapping[str, object], provider), "arn"),
    }
    rendered = json.loads(json.dumps(_load_json_policy("scoped.json")))
    if not isinstance(rendered, dict):
        raise ExperimentConfigurationError("scoped IAM policy must be an object")
    _replace_policy_values(rendered, replacements)
    serialized = json.dumps(rendered, separators=(",", ":"), sort_keys=True)
    if "*" in serialized:
        raise ExperimentConfigurationError("rendered scoped IAM policy is not safely constrained")
    return cast(Mapping[str, object], rendered)


def _required_state_arn(state: Mapping[str, object], field_name: str) -> str:
    value = state.get(field_name)
    if not isinstance(value, str) or not value:
        raise ExperimentConfigurationError(f".poc-state.json omitted required ARN: {field_name}")
    return value


def _replace_policy_values(value: object, replacements: Mapping[str, str]) -> object:
    if isinstance(value, dict):
        for key, nested in value.items():
            value[key] = _replace_policy_values(nested, replacements)
        return value
    if isinstance(value, list):
        for index, nested in enumerate(value):
            value[index] = _replace_policy_values(nested, replacements)
        return value
    if isinstance(value, str):
        for name, replacement in replacements.items():
            value = value.replace(f"${{{name}}}", replacement)
    return value


def _is_access_denied(error: AgentCoreError) -> bool:
    return error.__class__.__name__ == "AgentCoreAccessDenied"


def _aws_error_category(error: AgentCoreError) -> str:
    return {
        "AgentCoreAccessDenied": "access_denied",
        "AgentCoreThrottled": "throttled",
        "AgentCoreValidationError": "validation",
    }.get(error.__class__.__name__, "internal")


def _measurement_identity(
    runtime: Runtime, settings: Settings, writer: ObservationSink
) -> tuple[str, IdentityClient]:
    try:
        inbound_token = runtime.acquire_token(settings, typer.echo)
        runtime.validate_token(settings, inbound_token)
    except (EntraAuthError, TokenRejected):
        _append(writer, "H1", "validate_inbound_token", "fail", {"category": "authentication"})
        _emit_blocked("authentication", _AUTHENTICATION_EXIT, "inbound_token_rejected")
    return inbound_token, runtime.agentcore(settings)


def _retry_agentcore[R](
    operation: Callable[[], R], runtime: Runtime, *, counters: _RetryCounters | None = None
) -> R:
    def retryable_operation() -> R:
        try:
            return operation()
        except AgentCoreThrottled as error:
            if counters is not None:
                counters.record_throttle()
            raise RetryableMeasurementError("agentcore_throttled") from error

    return retry_with_backoff(
        retryable_operation,
        sleep=runtime.sleep,
        random_unit=runtime.random_unit,
        on_retry=counters.record_retry if counters is not None else None,
    )


def _google_drive_measurement(
    runtime: Runtime,
    settings: Settings,
    identity: IdentityClient,
    inbound_token: str,
    *,
    counters: _RetryCounters | None = None,
    cold: bool,
    fingerprint_salt: str,
) -> _GoogleDriveMeasurement:
    """Run the workload, Google provider, and aggregate Drive operation as one measurement."""

    def operation() -> _GoogleDriveMeasurement:
        workload_started_at = runtime.clock()
        workload_token = _retry_agentcore(
            lambda: identity.workload_token(settings.agentcore_workload_name, inbound_token),
            runtime,
            counters=counters,
        )
        workload_latency_ms = _elapsed_milliseconds(runtime, workload_started_at)
        google_started_at = runtime.clock()
        authorization = _retry_agentcore(
            lambda: identity.google_token(
                workload_token,
                settings.agentcore_google_provider,
                [_GOOGLE_DRIVE_METADATA_SCOPE],
                settings.google_return_url,
                runtime.random_urlsafe(),
            ),
            runtime,
            counters=counters,
        )
        google_latency_ms = _elapsed_milliseconds(runtime, google_started_at)
        if isinstance(authorization, AuthorizationRequired):
            _emit_authorization_required()
        drive = runtime.google_drive(settings)
        try:
            drive_started_at = runtime.clock()
            metadata = drive.list(authorization.access_token)
            return _GoogleDriveMeasurement(
                workload_fingerprint=token_fingerprint(workload_token, run_salt=fingerprint_salt),
                google_fingerprint=token_fingerprint(
                    authorization.access_token,
                    run_salt=fingerprint_salt,
                ),
                drive_marker=drive_metadata_marker(metadata),
                cold=cold,
                workload_latency_ms=workload_latency_ms,
                google_latency_ms=google_latency_ms,
                drive_latency_ms=_elapsed_milliseconds(runtime, drive_started_at),
            )
        except DownstreamThrottled as error:
            if counters is not None:
                counters.record_throttle()
            raise RetryableMeasurementError("drive_throttled") from error
        finally:
            _close_resource_client(drive)

    return retry_with_backoff(
        operation,
        sleep=runtime.sleep,
        random_unit=runtime.random_unit,
        on_retry=counters.record_retry if counters is not None else None,
    )


def _stage_latency_details(
    measurements: list[_GoogleDriveMeasurement],
) -> dict[str, JsonValue]:
    """Summarize each end-to-end stage without retaining tokens or response content."""
    stages = {
        "workload": [(item.cold, item.workload_latency_ms) for item in measurements],
        "google": [(item.cold, item.google_latency_ms) for item in measurements],
        "drive": [(item.cold, item.drive_latency_ms) for item in measurements],
    }
    details: dict[str, JsonValue] = {}
    for name, samples in stages.items():
        summary = cold_warm_latency_report(samples)
        details[name] = {
            "cold_p50_ms": summary.cold_p50_ms,
            "cold_p95_ms": summary.cold_p95_ms,
            "warm_p50_ms": summary.warm_p50_ms,
            "warm_p95_ms": summary.warm_p95_ms,
        }
    return details


def _concurrency_readiness(
    *,
    actual_probe_concurrency: int,
    documented_quota: int | None,
    temporal_target: int | None,
) -> dict[str, JsonValue]:
    """Compare operator-declared limits without inferring unverified AWS service quotas."""
    probe_quota_status = (
        "unknown"
        if documented_quota is None
        else "probe_within_quota"
        if actual_probe_concurrency <= documented_quota
        else "probe_exceeds_quota"
    )
    target_quota_status = (
        "unknown"
        if temporal_target is None or documented_quota is None
        else "target_within_quota"
        if temporal_target <= documented_quota
        else "target_exceeds_quota"
    )
    probe_target_status = (
        "unknown"
        if temporal_target is None
        else "probe_exercises_target"
        if actual_probe_concurrency >= temporal_target
        else "probe_below_target"
    )
    readiness = (
        "unknown"
        if "unknown" in {probe_quota_status, target_quota_status, probe_target_status}
        else "ready"
        if probe_quota_status == "probe_within_quota"
        and target_quota_status == "target_within_quota"
        and probe_target_status == "probe_exercises_target"
        else "unknown"
        if probe_quota_status == "probe_within_quota"
        and target_quota_status == "target_within_quota"
        and probe_target_status == "probe_below_target"
        else "not_ready"
    )
    return {
        "documented_quota": documented_quota,
        "temporal_target": temporal_target,
        "probe_quota_status": probe_quota_status,
        "target_quota_status": target_quota_status,
        "probe_target_status": probe_target_status,
        "readiness": readiness,
    }


def _issue_expiry_observations(
    runtime: Runtime,
    settings: Settings,
    writer: ObservationSink,
) -> tuple[ExpiryObservation, ...]:
    inbound_token, identity = _measurement_identity(runtime, settings, writer)
    now = runtime.wall_clock()
    try:
        claims = runtime.validate_token(settings, inbound_token)
    except (EntraAuthError, TokenRejected):
        _emit_blocked("authentication", _AUTHENTICATION_EXIT, "inbound_token_rejected")
    inbound_expiry = claims.get("exp")
    if not isinstance(inbound_expiry, int | float) or inbound_expiry < now:
        raise MeasurementConfigurationError("inbound token must contain a future expiry timestamp")
    workload_token = _retry_agentcore(
        lambda: identity.workload_token(settings.agentcore_workload_name, inbound_token), runtime
    )
    obo_token = _retry_agentcore(
        lambda: identity.obo_token(
            workload_token,
            settings.agentcore_microsoft_provider,
            [settings.entra_downstream_scope],
        ),
        runtime,
    )
    google = _retry_agentcore(
        lambda: identity.google_token(
            workload_token,
            settings.agentcore_google_provider,
            [_GOOGLE_DRIVE_METADATA_SCOPE],
            settings.google_return_url,
            runtime.random_urlsafe(),
        ),
        runtime,
    )
    if isinstance(google, AuthorizationRequired):
        _emit_authorization_required()
    google_expiry = None
    return (
        ExpiryObservation("inbound_jwt", inbound_token, now, float(inbound_expiry)),
        ExpiryObservation(
            "workload_token", workload_token, now, _supported_token_expiry(workload_token)
        ),
        ExpiryObservation("obo_token", obo_token, now, _supported_token_expiry(obo_token)),
        ExpiryObservation(
            "google_token",
            google.access_token,
            now,
            google_expiry,
            False,
        ),
    )


def _measurement_project_id(settings: Settings) -> str:
    identity = ":".join(
        (settings.aws_region, settings.agentcore_workload_name, settings.agentcore_google_provider)
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _expiry_command_status(
    comparisons: Mapping[str, ExpiryComparison],
    entries: tuple[ExpiryObservation, ...],
    now: float,
) -> str:
    del comparisons, entries, now
    return "unproven"


def _expiry_run_salt(project_id: str, issued_at: float) -> str:
    """Derive an opaque lifecycle-run salt from persisted, non-token timing metadata."""
    return hashlib.sha256(f"{project_id}:{issued_at:.6f}".encode()).hexdigest()


def _supported_token_expiry(token: str) -> float | None:
    """Read an ``exp`` claim only from a well-formed JWT; opaque tokens remain unknown."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        import base64

        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return None
    expiry = claims.get("exp") if isinstance(claims, Mapping) else None
    return float(expiry) if isinstance(expiry, int | float) else None


def _cloudtrail_attribution(settings: Settings, lookback_minutes: int) -> CloudTrailAttribution:
    """Inspect event structures in memory and retain only attribution-category presence."""
    client = boto3.client("cloudtrail", region_name=settings.aws_region)
    start_time = datetime.now(UTC) - timedelta(minutes=lookback_minutes)
    paginator = client.get_paginator("lookup_events")
    events: list[Mapping[str, object]] = []
    for page in paginator.paginate(
        LookupAttributes=[
            {
                "AttributeKey": "EventSource",
                "AttributeValue": "bedrock-agentcore.amazonaws.com",
            }
        ],
        StartTime=start_time,
    ):
        page_events = page.get("Events", [])
        if isinstance(page_events, list):
            events.extend(event for event in page_events if isinstance(event, Mapping))
    return _cloudtrail_attribution_from_events(events)


def _cloudtrail_attribution_from_events(
    events: list[Mapping[str, object]],
) -> CloudTrailAttribution:
    """Derive only required field-presence booleans from raw event payloads in memory."""
    parsed_events = [_decode_cloudtrail_event(event) for event in events]
    eligible_events = [event for event in parsed_events if _is_provider_token_event(event)]
    category_presence = [
        (
            _mapping_has_any_key(event, {"arn", "principalid", "accountid"}, under="useridentity"),
            _mapping_has_any_key(
                event,
                {"workloadname", "workloadidentity", "workloadidentitytoken"},
            ),
            _mapping_has_any_key(
                event,
                {"useridentifier", "userid", "usertoken", "customstate"},
            ),
        )
        for event in eligible_events
    ]
    return CloudTrailAttribution(
        eligible_event_count=len(eligible_events),
        aws_principal_present=any(principal for principal, _, _ in category_presence),
        workload_identity_present=any(workload for _, workload, _ in category_presence),
        user_correlation_present=any(user for _, _, user in category_presence),
        attribution_complete=any(all(categories) for categories in category_presence),
    )


def _decode_cloudtrail_event(event: Mapping[str, object]) -> Mapping[str, object]:
    payload = event.get("CloudTrailEvent")
    if not isinstance(payload, str):
        return event
    try:
        decoded = json.loads(payload)
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, Mapping) else {}


def _is_provider_token_event(event: Mapping[str, object]) -> bool:
    """Keep only the documented AgentCore provider-token retrieval operation."""
    event_name = next(
        (value for key, value in event.items() if key.casefold() == "eventname"),
        None,
    )
    return isinstance(event_name, str) and event_name.casefold() == "getresourceoauth2token"


def _mapping_has_any_key(
    value: Mapping[str, object], keys: set[str], *, under: str | None = None
) -> bool:
    """Search key names only; values never leave this in-memory parser."""
    for key, nested in value.items():
        normalized = key.lower()
        if under is None and normalized in keys:
            return True
        if under is not None and normalized == under and isinstance(nested, Mapping):
            return any(child.lower() in keys for child in nested)
        if isinstance(nested, Mapping) and _mapping_has_any_key(nested, keys, under=under):
            return True
        if isinstance(nested, list) and any(
            _mapping_has_any_key(item, keys, under=under)
            for item in nested
            if isinstance(item, Mapping)
        ):
            return True
    return False


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


def _validated_subject(claims: Mapping[str, object]) -> str:
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise TokenRejected("Token rejected")
    return subject


def _validate_inbound_token(settings: Settings, token: str) -> Mapping[str, object]:
    jwks_url = f"https://login.microsoftonline.com/{settings.entra_tenant_id}/discovery/v2.0/keys"
    return JwtPolicy(
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
