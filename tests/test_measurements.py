from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentcore_identity_poc.agentcore import AuthorizationRequired, OAuthToken
from agentcore_identity_poc.cli import Runtime, app
from agentcore_identity_poc.config import Settings
from agentcore_identity_poc.experiments import (
    ExpiryObservation,
    MeasurementConfigurationError,
    RetryableMeasurementError,
    load_expiry_resume_state,
    measure_bounded_concurrency,
    measure_latency,
    record_expiry_state,
    retry_with_backoff,
    token_fingerprint,
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


class RecordingEvidence:
    def __init__(self) -> None:
        self.observations: list[object] = []

    def append(self, observation: object) -> None:
        self.observations.append(observation)


class MeasurementIdentity:
    def __init__(self) -> None:
        self.workload_calls = 0
        self.force_authentication: list[bool] = []

    def workload_token(self, workload_name: str, user_token: str) -> str:
        assert workload_name == SETTINGS.agentcore_workload_name
        assert user_token == "inbound-secret"
        self.workload_calls += 1
        return "workload-secret"

    def obo_token(self, workload_token: str, provider: str, scopes: list[str]) -> str:
        assert workload_token == "workload-secret"
        return "obo-secret"

    def google_token(
        self,
        workload_token: str,
        provider: str,
        scopes: list[str],
        return_url: str,
        state: str,
        *,
        force_authentication: bool = False,
    ) -> OAuthToken | AuthorizationRequired:
        self.force_authentication.append(force_authentication)
        return OAuthToken("google-secret")


def _measurement_runtime(
    identity: MeasurementIdentity,
    evidence: RecordingEvidence,
    *,
    clock: object = lambda: 0.0,
) -> Runtime:
    return Runtime(
        load_settings=lambda: SETTINGS,
        check_reachability=lambda _: None,
        acquire_token=lambda _, __: "inbound-secret",
        validate_token=lambda _, __: {"sub": "subject", "exp": 100.0},
        agentcore=lambda _: identity,
        downstream=lambda _: None,  # type: ignore[arg-type]
        clock=clock,  # type: ignore[arg-type]
        evidence_writer=lambda _: evidence,
        stdin_isatty=lambda: False,
        random_urlsafe=lambda: "opaque-state",
    )


def test_latency_reports_distinct_cold_and_warm_samples_with_percentiles() -> None:
    now = iter((0.0, 0.100, 0.100, 0.120, 0.120, 0.150))

    report = measure_latency(
        samples=3,
        operation=lambda cold: "cold" if cold else "warm",
        clock=lambda: next(now),
    )

    assert [sample.cold for sample in report.samples] == [True, False, False]
    assert [sample.latency_ms for sample in report.samples] == [100, 20, 30]
    assert report.p50_ms == 30
    assert report.p95_ms == 100


def test_token_fingerprints_are_salted_per_run_and_do_not_include_token() -> None:
    token = "header.payload.signature"

    first = token_fingerprint(token, run_salt="run-one")
    second = token_fingerprint(token, run_salt="run-two")

    assert first != second
    assert len(first) == 64
    assert token not in first


def test_bounded_concurrency_never_exceeds_requested_workers() -> None:
    active = 0
    maximum_active = 0

    def request(index: int) -> int:
        nonlocal active, maximum_active
        active += 1
        maximum_active = max(maximum_active, active)
        active -= 1
        return index

    result = measure_bounded_concurrency(workers=2, requests=5, request=request)

    assert result.completed == 5
    assert result.maximum_workers == 2
    assert maximum_active <= 2


def test_retry_uses_jittered_exponential_backoff_for_retryable_failures() -> None:
    attempts = 0
    delays: list[float] = []

    def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise RetryableMeasurementError("throttled")
        return "ok"

    assert (
        retry_with_backoff(
            operation,
            sleep=delays.append,
            random_unit=lambda: 0.5,
            max_attempts=3,
        )
        == "ok"
    )
    assert delays == [0.125, 0.25]


def test_retry_does_not_retry_non_retryable_4xx() -> None:
    attempts = 0

    def operation() -> str:
        nonlocal attempts
        attempts += 1
        raise MeasurementConfigurationError("invalid request")

    with pytest.raises(MeasurementConfigurationError):
        retry_with_backoff(operation, sleep=lambda _: None, random_unit=lambda: 0.5)

    assert attempts == 1


def test_expiry_state_records_distinct_token_kinds_without_tokens(tmp_path: Path) -> None:
    path = tmp_path / "resume.json"
    entries = (
        ExpiryObservation("inbound_jwt", "inbound.token.value", 10.0, 20.0),
        ExpiryObservation("workload_token", "workload.token.value", 11.0, 21.0),
        ExpiryObservation("obo_token", "obo.token.value", 12.0, 22.0),
        ExpiryObservation("google_token", "google.token.value", 13.0, 23.0),
    )

    resume_at = record_expiry_state(
        path,
        project_id="project-a",
        entries=entries,
        run_salt="deterministic-salt",
    )

    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert set(item["kind"] for item in stored["entries"]) == {
        "inbound_jwt",
        "workload_token",
        "obo_token",
        "google_token",
    }
    assert "inbound.token.value" not in path.read_text(encoding="utf-8")
    assert stored["entries"][0]["fingerprint"] != "inbound.token.value"
    assert resume_at == 20.0


def test_resume_state_requires_private_mode_matching_project_and_no_jwt_values(
    tmp_path: Path,
) -> None:
    path = tmp_path / "resume.json"
    path.write_text(
        json.dumps(
            {
                "project_id": "project-a",
                "entries": [
                    {
                        "kind": "inbound_jwt",
                        "issued_at": 1.0,
                        "expires_at": 2.0,
                        "fingerprint": "a" * 64,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    os.chmod(path, 0o644)

    with pytest.raises(MeasurementConfigurationError, match="mode 0600"):
        load_expiry_resume_state(path, project_id="project-a")

    os.chmod(path, 0o600)
    with pytest.raises(MeasurementConfigurationError, match="current project"):
        load_expiry_resume_state(path, project_id="other-project")

    record_expiry_state(
        path,
        project_id="project-a",
        run_salt="salt",
        entries=(
            ExpiryObservation("inbound_jwt", "inbound", 1, 2),
            ExpiryObservation("workload_token", "workload", 1, 2),
            ExpiryObservation("obo_token", "obo", 1, 2),
            ExpiryObservation("google_token", "google", 1, 2),
        ),
    )
    # Inject an actual JWT-shaped value rather than relying on a token-like test fixture.
    state = json.loads(path.read_text(encoding="utf-8"))
    state["entries"][0]["fingerprint"] = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.signature"
    path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(MeasurementConfigurationError, match="JWT-shaped"):
        load_expiry_resume_state(path, project_id="project-a")


def test_measure_latency_reports_cold_warm_percentiles_and_no_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = MeasurementIdentity()
    evidence = RecordingEvidence()
    clock = iter((0.0, 0.100, 0.100, 0.120, 0.120, 0.150))
    runtime = _measurement_runtime(identity, evidence, clock=lambda: next(clock))
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)

    result = CliRunner().invoke(app, ["measure", "latency", "--samples", "3"])

    assert result.exit_code == 0
    assert result.stdout == (
        '{"status":"pass","operation":"measure_latency","samples":3,'
        '"cold_samples":1,"warm_samples":2,"p50_ms":30,"p95_ms":100}\n'
    )
    assert identity.workload_calls == 3
    assert "inbound-secret" not in result.output
    assert "workload-secret" not in result.output


def test_measure_expiry_writes_private_resume_state_and_exits_immediately(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    identity = MeasurementIdentity()
    evidence = RecordingEvidence()
    runtime = _measurement_runtime(identity, evidence, clock=lambda: 10.0)
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)
    state_path = tmp_path / "expiry-state.json"

    result = CliRunner().invoke(app, ["measure", "expiry", "--resume-state", str(state_path)])

    assert result.exit_code == 0
    rendered = json.loads(result.stdout)
    assert rendered["status"] == "resume_required"
    assert rendered["resume_at"] == 100.0
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600
    assert "inbound-secret" not in state_path.read_text(encoding="utf-8")
    assert "workload-secret" not in state_path.read_text(encoding="utf-8")
    assert "obo-secret" not in state_path.read_text(encoding="utf-8")
    assert "google-secret" not in state_path.read_text(encoding="utf-8")


def test_measure_expiry_does_not_call_identity_again_before_resume_time(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    state_path = tmp_path / "expiry-state.json"
    first_identity = MeasurementIdentity()
    first_runtime = _measurement_runtime(first_identity, RecordingEvidence(), clock=lambda: 10.0)
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: first_runtime)
    assert (
        CliRunner().invoke(app, ["measure", "expiry", "--resume-state", str(state_path)]).exit_code
        == 0
    )

    resumed_identity = MeasurementIdentity()
    resumed_runtime = _measurement_runtime(
        resumed_identity, RecordingEvidence(), clock=lambda: 10.0
    )
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: resumed_runtime)
    result = CliRunner().invoke(app, ["measure", "expiry", "--resume-state", str(state_path)])

    assert result.exit_code == 0
    assert json.loads(result.stdout) == {
        "status": "resume_required",
        "operation": "measure_expiry",
        "resume_at": 100.0,
    }
    assert resumed_identity.workload_calls == 0


def test_offboard_google_forces_authentication_but_never_deletes_shared_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = MeasurementIdentity()
    evidence = RecordingEvidence()
    runtime = _measurement_runtime(identity, evidence)
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)

    result = CliRunner().invoke(app, ["offboard", "google", "--user-alias", "user-a", "--apply"])

    assert result.exit_code == 0
    assert identity.force_authentication == [False, True]
    rendered = json.loads(result.stdout)
    assert rendered == {
        "status": "failed",
        "operation": "offboard_google",
        "hypothesis": "H8",
        "detail": "per_user_purge_unavailable",
    }
    observations = [item.as_dict() for item in evidence.observations]
    assert observations[-1]["outcome"] == "fail"
    assert "inbound-secret" not in repr(observations)
