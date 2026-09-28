# src/agentcore_platform_poc/resource_hub/handler.py
"""Lambda function URL handler for the Resource Hub. Every request is authenticated here."""

from __future__ import annotations

import base64
import functools
import json
import os
import re
import time
from collections.abc import Callable
from typing import Any

import boto3  # type: ignore[import-untyped]
from botocore.config import Config  # type: ignore[import-untyped]

from agentcore_platform_poc.entra import AuthError, build_verifier
from agentcore_platform_poc.resource_hub.auth import Caller, authenticate
from agentcore_platform_poc.resource_hub.paths import (
    PathRejected,
    canonical_path,
    check_glob,
    object_key,
)
from agentcore_platform_poc.resource_hub.settings import HubSettings
from agentcore_platform_poc.resource_hub.store import MAX_CHUNK, NotFound, TooLarge, WorkspaceStore

_RANGE = re.compile(r"bytes=(\d+)-(\d*)")
Authenticate = Callable[..., Caller]


@functools.cache
def _components() -> tuple[WorkspaceStore, Authenticate]:
    settings = HubSettings.from_env(os.environ)
    verifier = build_verifier(settings.tenant_id, settings.hub_app_id)
    # Short socket timeouts bound a stalled S3 read, so a search returns before the Lambda timeout.
    s3_config = Config(connect_timeout=5, read_timeout=15, retries={"max_attempts": 2})
    store = WorkspaceStore(boto3.client("s3", config=s3_config), settings.workspace_bucket)

    def auth(headers: dict[str, str], **_: Any) -> Caller:
        return authenticate(headers, verifier=verifier, settings=settings, now=int(time.time()))

    return store, auth


def _json(status: int, body: Any, headers: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json", **(headers or {})},
        "body": json.dumps(body),
    }


def _bytes(status: int, data: bytes, headers: dict[str, str]) -> dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {"content-type": "application/octet-stream", **headers},
        "body": base64.b64encode(data).decode(),
        "isBase64Encoded": True,
    }


def _body(event: dict[str, Any]) -> bytes:
    raw = event.get("body") or ""
    return base64.b64decode(raw) if event.get("isBase64Encoded") else raw.encode()


def _log(caller: Caller | None, op: str, path: str, status: int, started: float) -> None:
    print(
        json.dumps(
            {  # one JSON line per request; never tokens or contents
                "op": op,
                "path": path,
                "status": status,
                "ms": round((time.perf_counter() - started) * 1000, 1),
                "mode": caller.mode if caller else None,
                "oid": caller.oid if caller else None,
                "azp": caller.azp if caller else None,
                "sid": caller.sid if caller else None,
            }
        )
    )


def _route(
    event: dict[str, Any], store: WorkspaceStore, caller: Caller
) -> tuple[str, str, dict[str, Any]]:
    method = event["requestContext"]["http"]["method"]
    raw_path: str = event.get("rawPath", "")
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    if method == "GET" and raw_path.startswith("/v1/list/"):
        path = canonical_path(raw_path.removeprefix("/v1/list/"), decode=True, allow_empty=True)
        entries = [e.__dict__ for e in store.list(caller.oid, path)]
        return "list", path, _json(200, {"entries": entries})
    if method == "GET" and raw_path.startswith("/v1/stat/"):
        path = canonical_path(raw_path.removeprefix("/v1/stat/"), decode=True)
        return (
            "stat",
            path,
            _json(200, {"path": path, "size": store.size(object_key(caller.oid, path))}),
        )
    if raw_path.startswith("/v1/files/") and method in {"GET", "PUT"}:
        path = canonical_path(raw_path.removeprefix("/v1/files/"), decode=True)
        key = object_key(caller.oid, path)
        if method == "PUT":
            data = _body(event)
            store.put(key, data)
            return "write", path, _json(200, {"path": path, "size": len(data)})
        match = _RANGE.fullmatch(headers.get("range", ""))
        if headers.get("range") and not match:
            return "read", path, _json(416, {"error": "bad_range"})
        if match is None:
            size = store.size(key)
            if size > MAX_CHUNK:
                return "read", path, _json(413, {"error": "too_large", "size": size})
            data, total = store.read_range(key, 0, None)
            return "read", path, _bytes(200, data, {"x-total-size": str(total)})
        start, end = int(match.group(1)), int(match.group(2)) if match.group(2) else None
        try:
            data, total = store.read_range(key, start, end)
        except ValueError:
            return "read", path, _json(416, {"error": "bad_range"})
        if not data:  # only an empty file gets here; no byte range can be satisfied
            return "read", path, _json(416, {"error": "bad_range"})
        last = start + len(data) - 1
        return (
            "read",
            path,
            _bytes(
                206,
                data,
                {"content-range": f"bytes {start}-{last}/{total}", "x-total-size": str(total)},
            ),
        )
    if method == "POST" and raw_path == "/v1/search":
        try:
            request = json.loads(_body(event))
        except ValueError:
            return "search", "", _json(400, {"error": "bad_json"})
        if not isinstance(request, dict):
            return "search", "", _json(400, {"error": "bad_search_request"})
        text, glob, ignore = (
            request.get("text"),
            request.get("glob"),
            request.get("ignore_case", False),
        )
        if (
            not isinstance(text, str)
            or not text
            or not isinstance(ignore, bool)
            or (glob is not None and not isinstance(glob, str))
        ):
            return "search", "", _json(400, {"error": "bad_search_request"})
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:  # a lone surrogate from a JSON "\ud800" escape
            return "search", "", _json(400, {"error": "bad_search_request"})
        checked_glob = check_glob(glob) if glob is not None else None
        result = store.search(caller.oid, text, glob=checked_glob, ignore_case=ignore)
        return (
            "search",
            glob or "",
            _json(
                200,
                {
                    "matches": [m.__dict__ for m in result.matches],
                    "truncated": result.truncated,
                    "bytes_scanned": result.bytes_scanned,
                    "objects_scanned": result.objects_scanned,
                },
            ),
        )
    return "unknown", raw_path[:100], _json(404, {"error": "no_route"})


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    started = time.perf_counter()
    store, auth = _components()
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    caller: Caller | None = None
    op, path = "auth", ""
    try:
        caller = auth(headers)
        op, path, response = _route(event, store, caller)
    except AuthError as error:
        response = _json(error.status, {"error": error.code})
    except PathRejected:
        response = _json(400, {"error": "bad_path"})
    except NotFound:
        response = _json(404, {"error": "not_found"})
    except TooLarge:
        response = _json(413, {"error": "too_large"})
    except Exception:  # never return exception text to the caller
        response = _json(500, {"error": "internal"})
    _log(caller, op, path, response["statusCode"], started)
    return response
