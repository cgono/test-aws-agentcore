from __future__ import annotations

import webbrowser
from dataclasses import dataclass, field, replace

from typer.testing import CliRunner

from agentcore_identity_poc.agentcore import AuthorizationRequired, OAuthToken
from agentcore_identity_poc.cli import Runtime, app
from agentcore_identity_poc.config import Settings
from agentcore_identity_poc.downstream import DownstreamUnauthorized, DriveMetadata
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
    google_results: list[OAuthToken | AuthorizationRequired]
    google_force_authentication: list[bool] = field(default_factory=list)
    workload_tokens: list[str] = field(default_factory=list)

    def workload_token(self, workload_name: str, user_token: str) -> str:
        assert workload_name == SETTINGS.agentcore_workload_name
        self.workload_tokens.append(user_token)
        return "workload-secret"

    def obo_token(self, workload_token: str, provider: str, scopes: list[str]) -> str:
        raise AssertionError("not used by Google commands")

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
        assert workload_token == "workload-secret"
        assert provider == SETTINGS.agentcore_google_provider
        assert scopes == ["https://www.googleapis.com/auth/drive.metadata.readonly"]
        assert return_url == SETTINGS.google_return_url
        assert state
        self.google_force_authentication.append(force_authentication)
        return self.google_results.pop(0)


@dataclass
class FakeDrive:
    results: list[DriveMetadata | Exception]
    access_tokens: list[str] = field(default_factory=list)

    def list(self, access_token: str) -> DriveMetadata:
        self.access_tokens.append(access_token)
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    def close(self) -> None:
        return None


def _runtime(
    *,
    identity: FakeIdentity | None = None,
    drive: FakeDrive | None = None,
    evidence: RecordingEvidence | None = None,
    opened_urls: list[str] | None = None,
) -> tuple[Runtime, RecordingEvidence]:
    fake_identity = identity or FakeIdentity([OAuthToken("google-access-token")])
    fake_drive = drive or FakeDrive([DriveMetadata(0, {})])
    recording_evidence = evidence or RecordingEvidence()
    opened = opened_urls if opened_urls is not None else []
    return (
        Runtime(
            load_settings=lambda: SETTINGS,
            check_reachability=lambda _: None,
            acquire_token=lambda _, __: "inbound-secret",
            validate_token=lambda _, __: None,
            agentcore=lambda _: fake_identity,
            downstream=lambda _: fake_drive,
            google_drive=lambda _: fake_drive,
            clock=lambda: 1.0,
            evidence_writer=lambda _: recording_evidence,
            stdin_isatty=lambda: False,
            open_browser=lambda url: opened.append(url) or True,
            random_urlsafe=lambda: "opaque-state",
        ),
        recording_evidence,
    )


def test_google_connect_prints_the_same_origin_callback_url(monkeypatch: object) -> None:
    runtime, _ = _runtime()
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)  # type: ignore[attr-defined]

    result = CliRunner().invoke(app, ["google-connect", "--print-url"])

    assert result.exit_code == 0
    assert result.stdout == (
        '{"status":"authorization_started","url":"https://callback.example.test/connect"}\n'
    )


def test_google_connect_opens_the_same_origin_callback_url(monkeypatch: object) -> None:
    opened_urls: list[str] = []
    runtime, _ = _runtime(opened_urls=opened_urls)
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)  # type: ignore[attr-defined]

    result = CliRunner().invoke(app, ["google-connect", "--open-browser"])

    assert result.exit_code == 0
    assert result.stdout == '{"status":"authorization_started"}\n'
    assert opened_urls == ["https://callback.example.test/connect"]


def test_google_connect_prints_the_url_when_browser_launch_returns_false(
    monkeypatch: object,
) -> None:
    runtime, _ = _runtime()
    runtime = replace(runtime, open_browser=lambda _: False)
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)  # type: ignore[attr-defined]

    result = CliRunner().invoke(app, ["google-connect", "--open-browser"])

    assert result.exit_code == 0
    assert result.stdout == (
        '{"status":"authorization_started","mode":"print_url",'
        '"url":"https://callback.example.test/connect"}\n'
    )


def test_google_connect_prints_the_url_when_browser_launch_raises(
    monkeypatch: object,
) -> None:
    def browser_unavailable(_: str) -> bool:
        raise webbrowser.Error("no browser")

    runtime, _ = _runtime()
    runtime = replace(runtime, open_browser=browser_unavailable)
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)  # type: ignore[attr-defined]

    result = CliRunner().invoke(app, ["google-connect", "--open-browser"])

    assert result.exit_code == 0
    assert result.stdout == (
        '{"status":"authorization_started","mode":"print_url",'
        '"url":"https://callback.example.test/connect"}\n'
    )


def test_google_list_outputs_only_aggregate_metadata_and_redacts_tokens(
    monkeypatch: object,
) -> None:
    identity = FakeIdentity([OAuthToken("google-access-token")])
    drive = FakeDrive([DriveMetadata(3, {"application/pdf": 1, "text/plain": 2})])
    runtime, evidence = _runtime(identity=identity, drive=drive)
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)  # type: ignore[attr-defined]

    result = CliRunner().invoke(app, ["google-list"])

    assert result.exit_code == 0
    assert result.stdout == (
        '{"status":"pass","operation":"google-list","item_count":3,'
        '"type_counts":{"application/pdf":1,"text/plain":2}}\n'
    )
    assert identity.google_force_authentication == [False]
    assert drive.access_tokens == ["google-access-token"]
    rendered_evidence = [observation.as_dict() for observation in evidence.observations]
    assert "inbound-secret" not in result.output
    assert "workload-secret" not in result.output
    assert "google-access-token" not in result.output
    assert "inbound-secret" not in repr(rendered_evidence)
    assert "workload-secret" not in repr(rendered_evidence)
    assert "google-access-token" not in repr(rendered_evidence)


def test_google_revoke_check_forces_one_new_authorization_after_drive_401(
    monkeypatch: object,
) -> None:
    identity = FakeIdentity(
        [
            OAuthToken("google-access-token"),
            AuthorizationRequired(
                authorization_url="https://accounts.example.test/authorize?code=secret",
                session_uri="session-secret",
            ),
        ]
    )
    drive = FakeDrive([DownstreamUnauthorized()])
    runtime, evidence = _runtime(identity=identity, drive=drive)
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)  # type: ignore[attr-defined]

    result = CliRunner().invoke(app, ["google-revoke-check"])

    assert result.exit_code == 3
    assert result.stdout == (
        '{"status":"authorization_required","category":"authentication",'
        '"detail":"google_authorization_required"}\n'
    )
    assert identity.google_force_authentication == [False, True]
    assert drive.access_tokens == ["google-access-token"]
    rendered_evidence = [observation.as_dict() for observation in evidence.observations]
    assert "google-access-token" not in result.output
    assert "secret" not in result.output
    assert "google-access-token" not in repr(rendered_evidence)
    assert "secret" not in repr(rendered_evidence)


def test_google_list_maps_a_revoked_drive_token_without_exposing_it(
    monkeypatch: object,
) -> None:
    runtime, evidence = _runtime(
        drive=FakeDrive([DownstreamUnauthorized()]),
    )
    monkeypatch.setattr("agentcore_identity_poc.cli.runtime_factory", lambda: runtime)  # type: ignore[attr-defined]

    result = CliRunner().invoke(app, ["google-list"])

    assert result.exit_code == 5
    assert result.stdout == (
        '{"status":"blocked","category":"downstream_denied",'
        '"detail":"google_drive_unauthorized"}\n'
    )
    assert "google-access-token" not in result.output
    assert "google-access-token" not in repr(
        [observation.as_dict() for observation in evidence.observations]
    )
