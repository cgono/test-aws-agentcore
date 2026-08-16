"""Token-safe HTTP clients for the synthetic API and Google Drive metadata."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

import httpx

_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
_GOOGLE_FILES_URL = "https://www.googleapis.com/drive/v3/files"


class DownstreamError(RuntimeError):
    """Base error that deliberately omits downstream responses and headers."""

    message = "Downstream request failed"

    def __init__(self) -> None:
        super().__init__(self.message)


class DownstreamAccessDenied(DownstreamError):
    message = "Downstream request was denied"


class DownstreamThrottled(DownstreamError):
    message = "Downstream request was throttled"


class DownstreamFailure(DownstreamError):
    message = "Downstream request could not be completed"


@dataclass(frozen=True)
class SyntheticMetadata:
    subject_alias: str
    items: tuple[object, ...]


@dataclass(frozen=True)
class DriveMetadata:
    item_count: int
    type_counts: dict[str, int]


class SyntheticResourceClient:
    """Read normalized metadata from the synthetic downstream API."""

    def __init__(self, metadata_url: str, *, client: httpx.Client | None = None) -> None:
        self._metadata_url = metadata_url
        self._client = client or httpx.Client(timeout=_TIMEOUT)

    def list(self, access_token: str) -> SyntheticMetadata:
        payload = _get_json(self._client, self._metadata_url, access_token)
        subject_alias = payload.get("subject_alias")
        items = payload.get("items")
        if not isinstance(subject_alias, str) or not subject_alias or not isinstance(items, list):
            raise DownstreamFailure() from ValueError("Synthetic metadata schema was invalid")
        return SyntheticMetadata(subject_alias=subject_alias, items=tuple(items))


class GoogleDriveClient:
    """List only aggregate Google Drive metadata, discarding user content identifiers."""

    def __init__(self, *, client: httpx.Client | None = None) -> None:
        self._client = client or httpx.Client(timeout=_TIMEOUT)

    def list(self, access_token: str) -> DriveMetadata:
        payload = _get_json(self._client, _GOOGLE_FILES_URL, access_token)
        files = payload.get("files")
        if not isinstance(files, list):
            raise DownstreamFailure() from ValueError("Google Drive response schema was invalid")

        type_counts: dict[str, int] = {}
        for item in files:
            if not isinstance(item, Mapping) or not isinstance(item.get("mimeType"), str):
                error = ValueError("Google Drive response schema was invalid")
                raise DownstreamFailure() from error
            mime_type = item["mimeType"]
            type_counts[mime_type] = type_counts.get(mime_type, 0) + 1
        return DriveMetadata(item_count=len(files), type_counts=dict(sorted(type_counts.items())))


def _get_json(client: httpx.Client, url: str, access_token: str) -> Mapping[str, object]:
    try:
        response = client.get(url, headers={"Authorization": f"Bearer {access_token}"})
        _raise_for_downstream_status(response)
        payload = response.json()
        if not isinstance(payload, Mapping):
            raise ValueError("Response JSON was not an object")
        return payload
    except DownstreamError:
        raise
    except (httpx.HTTPError, ValueError) as error:
        raise DownstreamFailure() from error


def _raise_for_downstream_status(response: httpx.Response) -> None:
    if response.status_code in {401, 403}:
        raise DownstreamAccessDenied()
    if response.status_code == 429:
        raise DownstreamThrottled()
    if response.is_error:
        raise DownstreamFailure()
