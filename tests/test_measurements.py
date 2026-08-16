from __future__ import annotations

import json
import os
import stat
from base64 import urlsafe_b64encode
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentcore_identity_poc.agentcore import AgentCoreThrottled, AuthorizationRequired, OAuthToken
from agentcore_identity_poc.cli import Runtime, _expiry_run_salt, app
from agentcore_identity_poc.config import Settings
from agentcore_identity_poc.downstream import DownstreamUnauthorized, DriveMetadata
from agentcore_identity_poc.experiments import (
    ExpiryObservation,
    MeasurementConfigurationError,
    RetryableMeasurementError,
    compare_expiry_observations,
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
_INBOUND_TOKEN = "inbound-secret"


class RecordingEvidence:
    def __init__(self) -> None:
        self.observations: list[object] = []

    def append(self, observation: object) -> None:
        self.observations.append(observation)


class MeasurementIdentity:
    def __init__(self, *, inbound_token: str = _INBOUND_TOKEN, token_suffix: str = "") -> None:
        self.inbound_token = inbound_token
        self.token_suffix = token_suffix
        self.workload_calls = 0
        self.force_authentication: list[bool] = []

    def workload_token(self, workload_name: str, user_token: str) -> str:
        assert workload_name == SETTINGS.agentcore_workload_name
        assert user_token == self.inbound_token
        self.workload_calls += 1
        return f"workload-secret{self.token_suffix}"

    def obo_token(self, workload_token: str, provider: str, scopes: list[str]) -> str:
        assert workload_token == f"workload-secret{self.token_suffix}"
        return f"obo-secret{self.token_suffix}"

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
        return OAuthToken(f"google-secret{self.token_suffix}")


class MeasurementDrive:
    def __init__(self, results: list[DriveMetadata | Exception] | None = None) -> None:
        self.results = results or [DriveMetadata(1, {"text/plain": 1})]
        self.access_tokens: list[str] = []

    def list(self, access_token: str) -> DriveMetadata:
        self.access_tokens.append(access_token)
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    def close(self) -> None:
        return None


class ExpiringGoogleIdentity(MeasurementIdentity):
    def __init__(self, expiry: int, suffix: str = "token") -> None:
        super().__init__()
        self.google_token_value = _jwt_with_expiry(expiry, suffix)

    def google_token(
        self,
        workload_token: str,
        provider: str,
        scopes: list[str],
        return_url: str,
        state: str,
        *,
        force_authentication: bool = False,
    ) -> OAuthToken:
        return OAuthToken(self.google_token_value)


def _jwt_with_expiry(expiry: int, signature: str) -> str:
    payload = urlsafe_b64encode(json.dumps({"exp": expiry}).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJub25lIn0.{payload}.{signature}"


def _measurement_runtime(
    identity: MeasurementIdentity,
    evidence: RecordingEvidence,
    *,
    clock: object = lambda: 0.0,
    drive: MeasurementDrive | None = None,
    inbound_expiry: float = 100.0,
) -> Runtime:
    measurement_drive = drive or MeasurementDrive()
    return Runtime(
        load_settings=lambda: SETTINGS,
        check_reachability=lambda _: None,
        acquire_token=lambda _, __: identity.inbound_token,
        validate_token=lambda _, __: {"sub": "subject", "exp": inbound_expiry},
        agentcore=lambda _: identity,
        downstream=lambda _: None,  # type: ignore[arg-type]
        google_drive=lambda _: measurement_drive,
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


def test_resume_state_rejects_jwt_shaped_values_anywhere_in_decoded_json(tmp_path: Path) -> None:
    path = tmp_path / "resume.json"
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
    state = json.loads(path.read_text(encoding="utf-8"))
    state["unrelated"] = {"nested": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.signature"}
    path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(MeasurementConfigurationError, match="JWT-shaped"):
        load_expiry_resume_state(path, project_id="project-a")

    state = json.loads(path.read_text(encoding="utf-8"))
    state = {"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.signature": state}
    path.write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(MeasurementConfigurationError, match="JWT-shaped"):
        load_expiry_resume_state(path, project_id="project-a")


def test_measure_latency_reports_cold_warm_percentiles_and_no_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = MeasurementIdentity()
    evidence = RecordingEvidence()
    drive = MeasurementDrive([DriveMetadata(1, {"text/plain": 1}) for _ in range(3)])
    clock = iter((0.0, 0.100, 0.100, 0.120, 0.120, 0.150))
    runtime = _measurement_runtime(identity, evidence, clock=lambda: next(clock), drive=drive)
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)

    result = CliRunner().invoke(app, ["measure", "latency", "--samples", "3"])

    assert result.exit_code == 0
    assert result.stdout == (
        '{"status":"pass","operation":"measure_latency","samples":3,'
        '"cold_samples":1,"warm_samples":2,"p50_ms":30,"p95_ms":100,'
        '"workload_cache_equivalent":true,"google_cache_equivalent":true,'
        '"drive_result_equivalent":true}\n'
    )
    assert identity.workload_calls == 3
    assert drive.access_tokens == ["google-secret"] * 3
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
    assert rendered["status"] == "unknown"
    assert rendered["resume_at"] == 100.0
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600
    assert "inbound-secret" not in state_path.read_text(encoding="utf-8")
    assert "workload-secret" not in state_path.read_text(encoding="utf-8")
    assert "obo-secret" not in state_path.read_text(encoding="utf-8")
    assert "google-secret" not in state_path.read_text(encoding="utf-8")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert [entry["expiry_known"] for entry in state["entries"]] == [True, False, False, False]
    assert [entry["expires_at"] for entry in state["entries"]] == [100.0, None, None, None]


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
        "status": "unknown",
        "operation": "measure_expiry",
        "detail": "google_expiry_unknown",
        "resume_at": None,
    }
    assert resumed_identity.workload_calls == 0


def test_measure_expiry_compares_old_and_new_fingerprints_after_known_expiry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    state_path = tmp_path / "expiry-state.json"
    first_evidence = RecordingEvidence()
    first_runtime = _measurement_runtime(MeasurementIdentity(), first_evidence, clock=lambda: 10.0)
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: first_runtime)
    assert (
        CliRunner().invoke(app, ["measure", "expiry", "--resume-state", str(state_path)]).exit_code
        == 0
    )

    resumed_evidence = RecordingEvidence()
    resumed_runtime = _measurement_runtime(
        MeasurementIdentity(), resumed_evidence, clock=lambda: 101.0
    )
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: resumed_runtime)
    result = CliRunner().invoke(app, ["measure", "expiry", "--resume-state", str(state_path)])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["status"] == "unknown"
    assert resumed_evidence.observations == []


def test_measure_expiry_uses_persisted_issue_timestamp_for_resume_salt(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "expiry-state.json"
    original = (
        ExpiryObservation("inbound_jwt", "same-inbound", 10.0, 100.0),
        ExpiryObservation("workload_token", "same-workload", 10.0, None),
        ExpiryObservation("obo_token", "same-obo", 10.0, None),
        ExpiryObservation("google_token", "same-google", 10.0, 100.0),
    )
    record_expiry_state(
        state_path,
        project_id="project-a",
        entries=original,
        run_salt=_expiry_run_salt("project-a", 10.0),
    )
    comparisons = compare_expiry_observations(
        load_expiry_resume_state(state_path, project_id="project-a"),
        (
            ExpiryObservation("inbound_jwt", "same-inbound", 11.0, 200.0),
            ExpiryObservation("workload_token", "same-workload", 11.0, None),
            ExpiryObservation("obo_token", "same-obo", 11.0, None),
            ExpiryObservation("google_token", "same-google", 11.0, 200.0),
        ),
        prior_run_salt=_expiry_run_salt("project-a", 10.0),
    )
    assert all(not comparison.fingerprint_changed for comparison in comparisons)


def test_measure_expiry_keeps_opaque_google_state_unknown_and_preserves_resume_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    state_path = tmp_path / "expiry-state.json"
    first_runtime = _measurement_runtime(
        MeasurementIdentity(), RecordingEvidence(), clock=lambda: 10.0
    )
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: first_runtime)
    assert (
        CliRunner().invoke(app, ["measure", "expiry", "--resume-state", str(state_path)]).exit_code
        == 0
    )
    original_state = state_path.read_text(encoding="utf-8")

    resumed_identity = MeasurementIdentity()
    resumed_runtime = _measurement_runtime(
        resumed_identity,
        RecordingEvidence(),
        clock=lambda: 101.0,
        inbound_expiry=200.0,
    )
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: resumed_runtime)
    result = CliRunner().invoke(app, ["measure", "expiry", "--resume-state", str(state_path)])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["status"] == "unknown"
    assert resumed_identity.workload_calls == 0
    assert state_path.read_text(encoding="utf-8") == original_state


def test_measure_expiry_rejects_operator_supplied_google_boundary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    state_path = tmp_path / "expiry-state.json"
    first_runtime = _measurement_runtime(
        MeasurementIdentity(), RecordingEvidence(), clock=lambda: 10.0
    )
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: first_runtime)
    result = CliRunner().invoke(
        app,
        [
            "measure",
            "expiry",
            "--resume-state",
            str(state_path),
            "--google-resume-at",
            "100",
        ],
    )

    assert result.exit_code == 2
    assert "No such option" in result.stderr


def test_measure_expiry_uses_provider_derived_google_expiry_and_drive_success_for_h3(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    state_path = tmp_path / "expiry-state.json"
    first_runtime = _measurement_runtime(
        ExpiringGoogleIdentity(100, "first"), RecordingEvidence(), clock=lambda: 10.0
    )
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: first_runtime)
    assert (
        CliRunner().invoke(app, ["measure", "expiry", "--resume-state", str(state_path)]).exit_code
        == 0
    )

    evidence = RecordingEvidence()
    runtime = _measurement_runtime(
        ExpiringGoogleIdentity(200, "second"),
        evidence,
        clock=lambda: 101.0,
        inbound_expiry=200.0,
        drive=MeasurementDrive([DriveMetadata(1, {"text/plain": 1})]),
    )
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)
    result = CliRunner().invoke(app, ["measure", "expiry", "--resume-state", str(state_path)])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["status"] == "pass"
    google = next(
        item.as_dict()
        for item in evidence.observations
        if item.as_dict()["hypothesis"] == "H3"
    )
    assert (google["operation"], google["outcome"]) == ("post_expiry_refresh", "pass")
    assert google["details"]["drive_metadata_observed"] is True


def test_offboard_google_detects_drive_revocation_before_forcing_authentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = MeasurementIdentity()
    evidence = RecordingEvidence()
    drive = MeasurementDrive([DownstreamUnauthorized()])
    runtime = _measurement_runtime(identity, evidence, drive=drive)
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)

    result = CliRunner().invoke(app, ["offboard", "google", "--user-alias", "user-a", "--apply"])

    assert result.exit_code == 0
    assert identity.force_authentication == [False, True]
    assert drive.access_tokens == ["google-secret"]
    rendered = json.loads(result.stdout)
    assert rendered == {
        "status": "failed",
        "operation": "offboard_google",
        "hypothesis": "H8",
        "detail": "per_user_purge_unavailable",
    }
    observations = [item.as_dict() for item in evidence.observations]
    assert observations[-2] == {
        "hypothesis": "H8",
        "operation": "google_revocation_probe",
        "outcome": "pass",
        "details": {
            "user_alias": "user-a",
            "detail": "drive_revoked_401_force_authentication_requested",
            "reauthentication": "token_reissued",
        },
    }
    assert observations[-1]["outcome"] == "fail"
    assert "inbound-secret" not in repr(observations)


def test_offboard_google_does_not_force_authentication_without_drive_revocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = MeasurementIdentity()
    evidence = RecordingEvidence()
    runtime = _measurement_runtime(identity, evidence)
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)

    result = CliRunner().invoke(app, ["offboard", "google", "--user-alias", "user-a", "--apply"])

    assert result.exit_code == 0
    assert identity.force_authentication == [False]
    assert json.loads(result.stdout)["detail"] == "drive_revocation_not_observed"
    observations = [item.as_dict() for item in evidence.observations]
    assert [item["operation"] for item in observations] == [
        "google_revocation_probe",
        "offboard_google",
    ]
    assert observations[-1]["outcome"] == "fail"


def test_offboard_google_attempts_narrow_purge_after_nonrevoked_probe_but_keeps_h8_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class PurgableIdentity(MeasurementIdentity):
        def __init__(self) -> None:
            super().__init__()
            self.purged_aliases: list[str] = []

        def purge_google_user_connection(self, user_alias: str) -> None:
            self.purged_aliases.append(user_alias)

    identity = PurgableIdentity()
    runtime = _measurement_runtime(identity, RecordingEvidence())
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)

    result = CliRunner().invoke(app, ["offboard", "google", "--user-alias", "user-a", "--apply"])

    assert result.exit_code == 0
    assert identity.purged_aliases == ["user-a"]
    assert json.loads(result.stdout) == {
        "status": "failed",
        "operation": "offboard_google",
        "hypothesis": "H8",
        "detail": "drive_revocation_not_observed",
    }


def test_measure_concurrency_records_end_to_end_throttle_and_retry_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = MeasurementIdentity()
    evidence = RecordingEvidence()
    drive = MeasurementDrive([DriveMetadata(1, {"text/plain": 1}) for _ in range(3)])
    runtime = _measurement_runtime(identity, evidence, drive=drive)
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)

    result = CliRunner().invoke(
        app,
        ["measure", "concurrency", "--workers", "1", "--requests", "3"],
    )

    assert result.exit_code == 0
    rendered = json.loads(result.stdout)
    assert rendered["operation"] == "measure_concurrency"
    assert rendered["throttle_count"] == 0
    assert rendered["retry_attempts"] == 0
    assert rendered["workload_cache_equivalent"] is True
    assert rendered["google_cache_equivalent"] is True
    assert rendered["drive_result_equivalent"] is True
    assert drive.access_tokens == ["google-secret"] * 3


def test_measure_concurrency_records_throttled_retry_backoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ThrottledIdentity(MeasurementIdentity):
        def workload_token(self, workload_name: str, user_token: str) -> str:
            if self.workload_calls == 0:
                self.workload_calls += 1
                raise AgentCoreThrottled()
            return super().workload_token(workload_name, user_token)

    identity = ThrottledIdentity()
    runtime = replace(
        _measurement_runtime(identity, RecordingEvidence()),
        sleep=lambda _: None,
        random_unit=lambda: 0.0,
    )
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)

    result = CliRunner().invoke(
        app,
        ["measure", "concurrency", "--workers", "1", "--requests", "1"],
    )

    assert result.exit_code == 0
    rendered = json.loads(result.stdout)
    assert rendered["throttle_count"] == 1
    assert rendered["retry_attempts"] == 1
    assert rendered["backoff_ms"] == 100


def test_measure_latency_does_not_infer_token_cache_from_matching_drive_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RotatingIdentity(MeasurementIdentity):
        def workload_token(self, workload_name: str, user_token: str) -> str:
            self.workload_calls += 1
            return f"workload-{self.workload_calls}"

        def google_token(
            self,
            workload_token: str,
            provider: str,
            scopes: list[str],
            return_url: str,
            state: str,
            *,
            force_authentication: bool = False,
        ) -> OAuthToken:
            return OAuthToken(f"google-for-{workload_token}")

    runtime = _measurement_runtime(
        RotatingIdentity(),
        RecordingEvidence(),
        clock=iter((0.0, 0.1, 0.1, 0.2)).__next__,
        drive=MeasurementDrive([DriveMetadata(1, {"text/plain": 1}) for _ in range(2)]),
    )
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)

    result = CliRunner().invoke(app, ["measure", "latency", "--samples", "2"])

    assert result.exit_code == 0
    rendered = json.loads(result.stdout)
    assert rendered["workload_cache_equivalent"] is False
    assert rendered["google_cache_equivalent"] is False
    assert rendered["drive_result_equivalent"] is True
