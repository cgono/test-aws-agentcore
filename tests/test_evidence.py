import json
from pathlib import Path

import pytest

from agentcore_identity_poc.evidence import EvidenceWriter
from agentcore_identity_poc.models import Observation
from agentcore_identity_poc.redaction import UnsafeEvidenceError

JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.c2lnbmF0dXJl"


def observation(details: dict[str, object]) -> Observation:
    return Observation("H1", "workload", "pass", details)


def test_writer_rejects_token_shaped_values(tmp_path: Path) -> None:
    writer = EvidenceWriter(tmp_path / "evidence.jsonl")

    with pytest.raises(UnsafeEvidenceError):
        writer.append(observation({"token": JWT}))


def test_writer_persists_only_sanitized_fields(tmp_path: Path) -> None:
    path = tmp_path / "evidence.jsonl"
    EvidenceWriter(path).append(
        Observation("H1", "workload", "pass", {"issuer": "https://issuer", "latency_ms": 12})
    )

    assert path.read_text() == (
        '{"hypothesis":"H1","operation":"workload","outcome":"pass",'
        '"details":{"issuer":"https://issuer","latency_ms":12}}\n'
    )
    assert json.loads(path.read_text()) == {
        "hypothesis": "H1",
        "operation": "workload",
        "outcome": "pass",
        "details": {"issuer": "https://issuer", "latency_ms": 12},
    }


@pytest.mark.parametrize(
    "details",
    [
        {"header": "Bearer redacted-value"},
        {"authorization_url": "https://auth.example.test/authorize?code=redacted"},
        {"callback_url": "https://auth.example.test/return?session_id=redacted"},
        {"redirect_url": "https://auth.example.test/return?state=redacted"},
        {"href": "https://auth.example.test/authorize?access_token=redacted"},
        {"href": "https://auth.example.test/authorize?refresh_token=redacted"},
        {"href": "https://auth.example.test/authorize?id_token=redacted"},
        {"href": "https://auth.example.test/authorize?token=redacted"},
        {"cookie": "redacted-value"},
        {"client_secret": "redacted-value"},
        {"nested": [{"refresh_token": "redacted-value"}]},
        {"accessToken": "redacted-value"},
        {"clientSecret": "redacted-value"},
        {"refreshToken": "redacted-value"},
        {"nested": [{"sessionId": "redacted-value"}]},
        {"authorizationHeader": "Basic redacted-value"},
        {"cookieValue": "sid=redacted-value"},
        {"user": "member" + "@" + "example.invalid"},
        {"drive": {"filename": "redacted-document.txt"}},
        {"drive": {"name": "Confidential-Finance.xlsx"}},
        {"files": [{"name": "Quarterly Plan.xlsx"}]},
        {"workload_access_token": "opaque"},
        {"headers": {"X-Authorization": "Basic redacted-value"}},
        {"response_cookie": "opaque"},
        {"clientSecretValue": "opaque"},
        {"apiKeyValue": "opaque"},
        {"passwordValue": "opaque"},
        {"sessionIdValue": "opaque"},
        {"stateValue": "opaque"},
        {"codeValue": "opaque"},
    ],
)
def test_writer_rejects_unsafe_values_recursively(
    tmp_path: Path, details: dict[str, object]
) -> None:
    writer = EvidenceWriter(tmp_path / "evidence.jsonl")

    with pytest.raises(UnsafeEvidenceError):
        writer.append(observation(details))


def test_writer_does_not_create_or_partially_append_on_rejection(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "evidence.jsonl"
    writer = EvidenceWriter(path)

    with pytest.raises(UnsafeEvidenceError):
        writer.append(observation({"nested": {"token": JWT}}))

    assert not path.exists()

    writer.append(observation({"result": "allowed"}))
    original_contents = path.read_text()

    with pytest.raises(UnsafeEvidenceError):
        writer.append(observation({"access_token": "redacted-value"}))

    assert path.read_text() == original_contents


def test_observation_details_are_immutable_and_defensively_copied(tmp_path: Path) -> None:
    details = {"nested": [{"status": "initial"}]}
    item = Observation("H1", "workload", "pass", details)
    details["nested"][0]["status"] = "changed"

    with pytest.raises(TypeError):
        item.details["result"] = "changed"  # type: ignore[index]

    path = tmp_path / "evidence.jsonl"
    EvidenceWriter(path).append(item)

    assert json.loads(path.read_text())["details"] == {"nested": [{"status": "initial"}]}
