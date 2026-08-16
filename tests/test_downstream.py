from __future__ import annotations

import httpx
import pytest
import respx

from agentcore_identity_poc.downstream import (
    DownstreamAccessDenied,
    DownstreamFailure,
    DownstreamThrottled,
    GoogleDriveClient,
    SyntheticResourceClient,
)


@respx.mock
def test_resource_client_returns_normalized_synthetic_metadata() -> None:
    route = respx.get("https://resource.example.test/metadata").mock(
        return_value=httpx.Response(200, json={"subject_alias": "user-a", "items": []})
    )

    result = SyntheticResourceClient("https://resource.example.test/metadata").list("token")

    assert result.subject_alias == "user-a"
    assert result.items == ()
    assert route.calls[0].request.headers["Authorization"] == "Bearer token"


@pytest.mark.parametrize(
    ("status_code", "exception_type"),
    [
        (401, DownstreamAccessDenied),
        (403, DownstreamAccessDenied),
        (429, DownstreamThrottled),
        (500, DownstreamFailure),
    ],
)
@respx.mock
def test_resource_client_maps_http_errors_without_exposing_body(
    status_code: int, exception_type: type[Exception]
) -> None:
    secret = "https://example.test/?access_token=secret"
    respx.get("https://resource.example.test/metadata").mock(
        return_value=httpx.Response(status_code, text=secret)
    )

    with pytest.raises(exception_type) as raised:
        SyntheticResourceClient("https://resource.example.test/metadata").list("token")

    assert secret not in str(raised.value)
    assert "token" not in str(raised.value)


def test_resource_client_maps_timeouts_without_exposing_request_headers() -> None:
    def raise_timeout(_: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("token", request=httpx.Request("GET", "https://resource.example.test"))

    client = httpx.Client(transport=httpx.MockTransport(raise_timeout))

    with pytest.raises(DownstreamFailure) as raised:
        resource_client = SyntheticResourceClient(
            "https://resource.example.test/metadata", client=client
        )
        resource_client.list("token")

    assert "token" not in str(raised.value)


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"subject_alias": "user-a"},
        {"subject_alias": "user-a", "items": "not-a-list"},
        {"subject_alias": 1, "items": []},
    ],
)
@respx.mock
def test_resource_client_rejects_invalid_metadata_schema(body: object) -> None:
    respx.get("https://resource.example.test/metadata").mock(
        return_value=httpx.Response(200, json=body)
    )

    with pytest.raises(DownstreamFailure):
        SyntheticResourceClient("https://resource.example.test/metadata").list("token")


@respx.mock
def test_google_drive_client_discards_file_identifiers_and_names() -> None:
    route = respx.get("https://www.googleapis.com/drive/v3/files").mock(
        return_value=httpx.Response(
            200,
            json={
                "files": [
                    {"id": "secret-id", "name": "private-name", "mimeType": "text/plain"},
                    {"id": "other-id", "name": "private-sheet", "mimeType": "text/plain"},
                    {"id": "third-id", "name": "private-pdf", "mimeType": "application/pdf"},
                ]
            },
        )
    )

    result = GoogleDriveClient().list("token")

    assert result.item_count == 3
    assert result.type_counts == {"application/pdf": 1, "text/plain": 2}
    assert route.calls[0].request.headers["Authorization"] == "Bearer token"


@respx.mock
def test_google_drive_client_rejects_invalid_schema() -> None:
    respx.get("https://www.googleapis.com/drive/v3/files").mock(
        return_value=httpx.Response(200, json={"files": [{"mimeType": 1}]})
    )

    with pytest.raises(DownstreamFailure):
        GoogleDriveClient().list("token")


def test_downstream_clients_share_injected_client_without_closing_it() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url == httpx.URL("https://resource.example.test/metadata"):
            return httpx.Response(200, json={"subject_alias": "user-a", "items": []})
        if request.url == httpx.URL("https://www.googleapis.com/drive/v3/files"):
            return httpx.Response(200, json={"files": [{"mimeType": "text/plain"}]})
        return httpx.Response(404)

    shared_client = httpx.Client(transport=httpx.MockTransport(handler))
    resource_client = SyntheticResourceClient(
        "https://resource.example.test/metadata", client=shared_client
    )
    drive_client = GoogleDriveClient(client=shared_client)

    assert resource_client.list("resource-token").subject_alias == "user-a"
    assert drive_client.list("drive-token").type_counts == {"text/plain": 1}

    resource_client.close()
    drive_client.close()

    assert not shared_client.is_closed
    shared_client.close()


def test_owned_downstream_client_closes_at_context_exit() -> None:
    with SyntheticResourceClient("https://resource.example.test/metadata") as resource_client:
        assert not resource_client.is_closed

    assert resource_client.is_closed
