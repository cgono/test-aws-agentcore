from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from typer.testing import CliRunner

from agentcore_identity_poc.agentcore import AgentCoreAccessDenied
from agentcore_identity_poc.cli import Runtime, app
from agentcore_identity_poc.config import Settings, SettingsError
from agentcore_identity_poc.downstream import DownstreamAccessDenied, SyntheticMetadata
from agentcore_identity_poc.entra import EntraAuthError
from agentcore_identity_poc.models import Observation

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


@dataclass
class RecordingEvidence:
    observations: list[Observation] = field(default_factory=list)

    def append(self, observation: Observation) -> None:
        self.observations.append(observation)


@dataclass
class FakeIdentity:
    events: list[str]
    workload_error: Exception | None = None
    obo_error: Exception | None = None

    def workload_token(self, workload_name: str, user_token: str) -> str:
        self.events.append(f"workload:{workload_name}:{user_token}")
        if self.workload_error is not None:
            raise self.workload_error
        return "workload-secret"

    def obo_token(self, workload_token: str, provider: str, scopes: list[str]) -> str:
        self.events.append(f"obo:{provider}:{','.join(scopes)}")
        if self.obo_error is not None:
            raise self.obo_error
        assert workload_token == "workload-secret"
        return "downstream-secret"


@dataclass
class FakeResource:
    events: list[str]
    error: Exception | None = None

    def list(self, access_token: str) -> SyntheticMetadata:
        self.events.append(f"resource:{access_token}")
        if self.error is not None:
            raise self.error
        return SyntheticMetadata(subject_alias="run-alias", items=("one", "two"))


def _runtime(
    *,
    settings: Callable[[], Settings] = lambda: SETTINGS,
    acquire_token: Callable[[Settings, Callable[[str], None]], str] | None = None,
    validate_token: Callable[[Settings, str], None] | None = None,
    identity: FakeIdentity | None = None,
    resource: FakeResource | None = None,
    evidence: RecordingEvidence | None = None,
    stdin_isatty: Callable[[], bool] = lambda: False,
) -> tuple[Runtime, list[str], RecordingEvidence]:
    events: list[str] = []
    evidence_writer = evidence or RecordingEvidence()
    fake_identity = identity or FakeIdentity(events)
    fake_resource = resource or FakeResource(events)

    def default_acquire(_: Settings, __: Callable[[str], None]) -> str:
        events.append("acquire")
        return "inbound-secret"

    def default_validate(_: Settings, token: str) -> None:
        events.append(f"validate:{token}")

    return (
        Runtime(
            load_settings=settings,
            acquire_token=acquire_token or default_acquire,
            validate_token=validate_token or default_validate,
            agentcore=lambda _: fake_identity,
            downstream=lambda _: fake_resource,
            clock=lambda: 1.0,
            evidence_writer=lambda _: evidence_writer,
            stdin_isatty=stdin_isatty,
        ),
        events,
        evidence_writer,
    )


def test_preflight_reports_machine_readable_configuration_failure(
    monkeypatch: object,
) -> None:
    runtime, _, _ = _runtime(
        settings=lambda: (_ for _ in ()).throw(SettingsError("AWS_REGION must be set"))
    )
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)  # type: ignore[attr-defined]

    result = CliRunner().invoke(app, ["preflight", "--json"])

    assert result.exit_code == 2
    assert result.stdout == (
        '{"status":"blocked","category":"configuration","detail":"AWS_REGION must be set"}\n'
    )


def test_entra_obo_records_h1_h2_h6_and_never_discloses_tokens(monkeypatch: object) -> None:
    runtime, events, evidence = _runtime()
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)  # type: ignore[attr-defined]

    result = CliRunner().invoke(app, ["entra-obo"])

    assert result.exit_code == 0
    assert result.stdout == '{"status":"pass","operation":"entra-obo","resource_status":200}\n'
    assert events == [
        "acquire",
        "validate:inbound-secret",
        "workload:approved-workload:inbound-secret",
        "obo:microsoft-provider:api://resource/access_as_user",
        "resource:downstream-secret",
    ]
    assert [(item.hypothesis, item.outcome) for item in evidence.observations] == [
        ("H1", "pass"),
        ("H2", "pass"),
        ("H6", "pass"),
    ]
    rendered_evidence = [item.as_dict() for item in evidence.observations]
    assert "inbound-secret" not in result.output
    assert "workload-secret" not in result.output
    assert "downstream-secret" not in result.output
    assert "inbound-secret" not in repr(rendered_evidence)
    assert "workload-secret" not in repr(rendered_evidence)
    assert "downstream-secret" not in repr(rendered_evidence)


def test_entra_obo_token_stdin_reads_one_noninteractive_line(monkeypatch: object) -> None:
    runtime, events, _ = _runtime()
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)  # type: ignore[attr-defined]

    result = CliRunner().invoke(
        app,
        ["entra-obo", "--token-stdin"],
        input="provided-token\nthis-line-must-not-be-read\n",
    )

    assert result.exit_code == 0
    assert events[0] == "validate:provided-token"
    assert "acquire" not in events
    assert "this-line-must-not-be-read" not in result.output


def test_entra_obo_rejects_interactive_token_stdin(monkeypatch: object) -> None:
    runtime, events, _ = _runtime(stdin_isatty=lambda: True)
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)  # type: ignore[attr-defined]

    result = CliRunner().invoke(app, ["entra-obo", "--token-stdin"], input="provided-token\n")

    assert result.exit_code == 2
    assert "interactive" in result.stdout
    assert events == []


def test_entra_obo_validates_before_agentcore_and_maps_auth_failure(monkeypatch: object) -> None:
    def reject(_: Settings, __: str) -> None:
        raise EntraAuthError("invalid_token")

    runtime, events, evidence = _runtime(validate_token=reject)
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)  # type: ignore[attr-defined]

    result = CliRunner().invoke(app, ["entra-obo"])

    assert result.exit_code == 3
    assert events == ["acquire"]
    assert [(item.hypothesis, item.outcome) for item in evidence.observations] == [
        ("H1", "fail"),
    ]


def test_entra_obo_maps_agentcore_failure(monkeypatch: object) -> None:
    events: list[str] = []
    runtime, _, evidence = _runtime(
        identity=FakeIdentity(events, workload_error=AgentCoreAccessDenied())
    )
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)  # type: ignore[attr-defined]

    result = CliRunner().invoke(app, ["entra-obo"])

    assert result.exit_code == 4
    assert [(item.hypothesis, item.outcome) for item in evidence.observations] == [
        ("H1", "fail"),
    ]


def test_entra_obo_maps_downstream_denial(monkeypatch: object) -> None:
    events: list[str] = []
    runtime, _, evidence = _runtime(resource=FakeResource(events, error=DownstreamAccessDenied()))
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)  # type: ignore[attr-defined]

    result = CliRunner().invoke(app, ["entra-obo"])

    assert result.exit_code == 5
    assert [(item.hypothesis, item.outcome) for item in evidence.observations] == [
        ("H1", "pass"),
        ("H2", "pass"),
        ("H6", "fail"),
    ]
