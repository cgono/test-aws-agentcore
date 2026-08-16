"""Same-origin browser callback routes for the Google federation proof of concept."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from importlib.resources import files
from threading import Lock
from typing import Protocol, cast

import boto3  # type: ignore[import-untyped]
import msal  # type: ignore[import-untyped]
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from agentcore_identity_poc.agentcore import (
    AgentCoreDataPlane,
    AgentCoreIdentity,
    AuthorizationRequired,
    OAuthToken,
)
from agentcore_identity_poc.config import Settings
from agentcore_identity_poc.jwt_validation import JwtPolicy, make_http_jwks_loader

_COOKIE_MAX_AGE_SECONDS = 600
_MAX_CONSUMED_NONCES = 2_048
_ENTRA_FLOW_COOKIE = "agentcore_entra_flow"
_GOOGLE_STATE_COOKIE = "agentcore_google_state"
_SESSION_STORAGE_KEY = "agentcore_entra_access_token"
_GOOGLE_SCOPE = "https://www.googleapis.com/auth/drive.metadata.readonly"


class AuthorizationCodeClient(Protocol):
    """The small MSAL authorization-code surface used by the callback routes."""

    def initiate_auth_code_flow(
        self, *, scopes: list[str], redirect_uri: str
    ) -> Mapping[str, object]: ...

    def acquire_token_by_auth_code_flow(
        self, flow: Mapping[str, object], auth_response: Mapping[str, str]
    ) -> Mapping[str, object]: ...


class GoogleIdentityClient(Protocol):
    """The AgentCore calls needed to begin and complete Google federation."""

    def workload_token(self, workload_name: str, user_token: str) -> str: ...

    def google_token(
        self,
        workload_token: str,
        provider: str,
        scopes: list[str],
        return_url: str,
        state: str,
    ) -> OAuthToken | AuthorizationRequired: ...

    def complete_google(self, session_uri: str, user_token: str) -> None: ...


@dataclass(frozen=True)
class WebRuntime:
    """Injectable dependencies for local route tests and the production host."""

    settings: Settings
    msal: Callable[[Settings], AuthorizationCodeClient]
    validate_token: Callable[[str], Mapping[str, object]]
    identity: Callable[[Settings], GoogleIdentityClient]
    clock: Callable[[], float] = time.time
    random_urlsafe: Callable[[], str] = lambda: secrets.token_urlsafe(32)


@dataclass
class _SessionCookies:
    """Signed, short-lived local cookies with process-local replay tracking."""

    clock: Callable[[], float]
    signing_key: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    consumed_nonces: dict[str, float] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def encode(self, payload: Mapping[str, object]) -> str:
        body = _encode_json(dict(payload))
        signature = hmac.new(self.signing_key, body, hashlib.sha256).digest()
        return f"{_urlsafe(body)}.{_urlsafe(signature)}"

    def decode(self, value: str | None) -> dict[str, object] | None:
        with self._lock:
            self._prune_consumed_nonces()
            if not value or "." not in value:
                return None
            body_part, signature_part = value.split(".", 1)
            try:
                body = _urlsafe_decode(body_part)
                actual_signature = _urlsafe_decode(signature_part)
            except ValueError:
                return None
            expected_signature = hmac.new(self.signing_key, body, hashlib.sha256).digest()
            if not hmac.compare_digest(actual_signature, expected_signature):
                return None
            try:
                payload = json.loads(body)
            except (UnicodeDecodeError, json.JSONDecodeError):
                return None
            if not isinstance(payload, dict):
                return None
            expires_at = payload.get("expires_at")
            nonce = payload.get("nonce")
            if (
                not isinstance(expires_at, int | float)
                or isinstance(expires_at, bool)
                or expires_at <= self.clock()
                or not isinstance(nonce, str)
                or not nonce
                or nonce in self.consumed_nonces
            ):
                return None
            return payload

    def consume(self, payload: Mapping[str, object]) -> bool:
        with self._lock:
            self._prune_consumed_nonces()
            nonce = payload.get("nonce")
            expires_at = payload.get("expires_at")
            if (
                not isinstance(nonce, str)
                or not nonce
                or nonce in self.consumed_nonces
                or len(self.consumed_nonces) >= _MAX_CONSUMED_NONCES
                or not isinstance(expires_at, int | float)
                or isinstance(expires_at, bool)
            ):
                return False
            self.consumed_nonces[nonce] = min(
                float(expires_at), self.clock() + _COOKIE_MAX_AGE_SECONDS
            )
            return True

    def _prune_consumed_nonces(self) -> None:
        now = self.clock()
        self.consumed_nonces = {
            nonce: expires_at
            for nonce, expires_at in self.consumed_nonces.items()
            if expires_at > now
        }


def create_app(runtime: WebRuntime) -> FastAPI:
    """Create a callback app with no persistent token cache or remote session store."""
    app = FastAPI()
    app.state.runtime = runtime
    cookies = _SessionCookies(clock=runtime.clock)

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @app.get("/connect")
    def connect() -> Response:
        try:
            flow = runtime.msal(runtime.settings).initiate_auth_code_flow(
                scopes=[f"api://{runtime.settings.entra_api_client_id}/access_as_user"],
                redirect_uri=f"{runtime.settings.public_base_url}/auth/entra/callback",
            )
            auth_uri = flow.get("auth_uri")
            if not isinstance(auth_uri, str) or not auth_uri:
                raise ValueError("missing authorization URI")
            flow_payload = _flow_payload(flow, runtime.clock(), runtime.random_urlsafe())
        except Exception:
            return _error_response("authentication_failed", 400, _ENTRA_FLOW_COOKIE)

        response = RedirectResponse(auth_uri, status_code=307)
        _set_security_headers(response)
        _set_cookie(response, _ENTRA_FLOW_COOKIE, cookies.encode(flow_payload))
        return response

    @app.get("/auth/entra/callback")
    def entra_callback(request: Request) -> Response:
        payload = cookies.decode(request.cookies.get(_ENTRA_FLOW_COOKIE))
        if payload is None or not cookies.consume(payload):
            return _error_response("authentication_failed", 400, _ENTRA_FLOW_COOKIE)

        flow = payload.get("flow")
        if not isinstance(flow, Mapping):
            return _error_response("authentication_failed", 400, _ENTRA_FLOW_COOKIE)
        try:
            result = runtime.msal(runtime.settings).acquire_token_by_auth_code_flow(
                flow, dict(request.query_params)
            )
            access_token = result.get("access_token")
            if not isinstance(access_token, str) or not access_token:
                raise ValueError("missing access token")
        except Exception:
            return _error_response("authentication_failed", 400, _ENTRA_FLOW_COOKIE)

        response = HTMLResponse(_entra_complete_page(access_token))
        _set_security_headers(response, csp_nonce=_page_nonce(response.body))
        _delete_cookie(response, _ENTRA_FLOW_COOKIE)
        return response

    @app.post("/oauth/google/start")
    def google_start(request: Request) -> Response:
        token = _bearer_token(request)
        if token is None:
            return _error_response("authentication_failed", 401)
        try:
            claims = _validated_claims(runtime.validate_token(token), runtime.settings)
            subject = claims["sub"]
            state = runtime.random_urlsafe()
            identity = runtime.identity(runtime.settings)
            workload_token = identity.workload_token(
                runtime.settings.agentcore_workload_name, token
            )
            authorization = identity.google_token(
                workload_token,
                runtime.settings.agentcore_google_provider,
                [_GOOGLE_SCOPE],
                runtime.settings.google_return_url,
                state,
            )
        except Exception:
            return _error_response("authentication_failed", 401)

        if isinstance(authorization, OAuthToken):
            response = JSONResponse({"status": "connected"})
            _set_security_headers(response)
            return response

        state_payload = {
            "expires_at": runtime.clock() + _COOKIE_MAX_AGE_SECONDS,
            "nonce": runtime.random_urlsafe(),
            "session_uri": authorization.session_uri,
            "state": state,
            "sub": subject,
        }
        response = JSONResponse({"authorization_url": authorization.authorization_url})
        _set_security_headers(response)
        _set_cookie(response, _GOOGLE_STATE_COOKIE, cookies.encode(state_payload))
        return response

    @app.get("/oauth/google/return")
    def google_return() -> HTMLResponse:
        response = HTMLResponse(_google_return_page())
        _set_security_headers(response, csp_nonce=_page_nonce(response.body))
        return response

    @app.post("/oauth/google/complete")
    async def google_complete(request: Request) -> Response:
        payload = cookies.decode(request.cookies.get(_GOOGLE_STATE_COOKIE))
        if payload is None or not cookies.consume(payload):
            return _error_response("completion_failed", 400, _GOOGLE_STATE_COOKIE)

        try:
            body = await request.json()
            if not isinstance(body, Mapping):
                raise ValueError("invalid body")
            state = body.get("state")
            session_uri = body.get("session_uri")
            token = _bearer_token(request)
            if not isinstance(state, str) or not isinstance(session_uri, str) or token is None:
                raise PermissionError("missing browser binding")
            if state != payload.get("state") or session_uri != payload.get("session_uri"):
                raise ValueError("state mismatch")
            claims = _validated_claims(runtime.validate_token(token), runtime.settings)
            if claims["sub"] != payload.get("sub"):
                raise ValueError("user mismatch")
            runtime.identity(runtime.settings).complete_google(session_uri, token)
        except PermissionError:
            return _error_response("completion_failed", 401, _GOOGLE_STATE_COOKIE)
        except Exception:
            return _error_response("completion_failed", 400, _GOOGLE_STATE_COOKIE)

        response = Response(status_code=204)
        _set_security_headers(response)
        _delete_cookie(response, _GOOGLE_STATE_COOKIE)
        return response

    return app


def create_production_app() -> FastAPI:
    """Create the Uvicorn callback app from POC environment configuration."""
    settings = Settings.from_mapping(os.environ)
    jwks_url = f"https://login.microsoftonline.com/{settings.entra_tenant_id}/discovery/v2.0/keys"
    policy = JwtPolicy(
        issuer=settings.entra_issuer,
        audience=f"api://{settings.entra_api_client_id}",
        jwks_loader=make_http_jwks_loader(jwks_url),
    )
    return create_app(
        WebRuntime(
            settings=settings,
            msal=_authorization_code_client,
            validate_token=policy.validate,
            identity=_agentcore_identity,
        )
    )


def _authorization_code_client(settings: Settings) -> AuthorizationCodeClient:
    return cast(
        AuthorizationCodeClient,
        msal.PublicClientApplication(
            settings.entra_public_client_id,
            authority=f"https://login.microsoftonline.com/{settings.entra_tenant_id}",
        ),
    )


def _agentcore_identity(settings: Settings) -> GoogleIdentityClient:
    client = boto3.client("bedrock-agentcore", region_name=settings.aws_region)
    return AgentCoreIdentity(cast(AgentCoreDataPlane, client))


def _flow_payload(flow: Mapping[str, object], clock: float, nonce: str) -> dict[str, object]:
    return {"expires_at": clock + _COOKIE_MAX_AGE_SECONDS, "flow": dict(flow), "nonce": nonce}


def _validated_claims(claims: Mapping[str, object], settings: Settings) -> dict[str, str]:
    issuer = claims.get("iss")
    audience = claims.get("aud")
    subject = claims.get("sub")
    expected_audience = f"api://{settings.entra_api_client_id}"
    audience_matches = audience == expected_audience or (
        isinstance(audience, list) and expected_audience in audience
    )
    if (
        issuer != settings.entra_issuer
        or not audience_matches
        or not isinstance(subject, str)
        or not subject
    ):
        raise ValueError("token claims rejected")
    return {"sub": subject}


def _bearer_token(request: Request) -> str | None:
    authorization = request.headers.get("authorization")
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.removeprefix("Bearer ")
    return token if token else None


def _urlsafe(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _urlsafe_decode(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, UnicodeEncodeError) as error:
        raise ValueError("invalid signed cookie") from error


def _encode_json(value: Mapping[str, object]) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _set_cookie(response: Response, key: str, value: str) -> None:
    response.set_cookie(
        key,
        value,
        max_age=_COOKIE_MAX_AGE_SECONDS,
        httponly=True,
        secure=True,
        samesite="lax",
    )


def _delete_cookie(response: Response, key: str) -> None:
    response.delete_cookie(key, httponly=True, secure=True, samesite="lax")


def _set_security_headers(response: Response, *, csp_nonce: str | None = None) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    if csp_nonce is not None:
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; base-uri 'none'; connect-src 'self'; form-action 'self'; "
            f"script-src 'nonce-{csp_nonce}'"
        )


def _error_response(error: str, status_code: int, cookie_name: str | None = None) -> JSONResponse:
    response = JSONResponse({"error": error}, status_code=status_code)
    _set_security_headers(response)
    if cookie_name is not None:
        _delete_cookie(response, cookie_name)
    return response


def _page_nonce(body: bytes | memoryview) -> str:
    """Extract the nonce already embedded into a rendered page without exposing a token."""
    body = bytes(body)
    marker = b'nonce="'
    start = body.find(marker) + len(marker)
    end = body.find(b'"', start)
    return body[start:end].decode("ascii")


def _entra_complete_page(access_token: str) -> str:
    nonce = secrets.token_urlsafe(16)
    token = _safe_json_for_script(access_token)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Connecting</title></head>
<body><script nonce="{nonce}">
(() => {{
  const accessToken = {token};
  window.sessionStorage.setItem("{_SESSION_STORAGE_KEY}", accessToken);
  window.history.replaceState({{}}, document.title, "/auth/entra/callback");
  window.fetch("/oauth/google/start", {{
    method: "POST", credentials: "same-origin",
    headers: {{Authorization: `Bearer ${{accessToken}}`}}
  }}).then((response) => response.ok ? response.json() : Promise.reject()).then((result) => {{
    if (typeof result.authorization_url === "string") {{
      window.location.assign(result.authorization_url);
    }} else {{
      window.sessionStorage.removeItem("{_SESSION_STORAGE_KEY}");
    }}
  }}).catch(() => window.sessionStorage.removeItem("{_SESSION_STORAGE_KEY}"));
}})();
</script></body></html>"""


def _google_return_page() -> str:
    nonce = secrets.token_urlsafe(16)
    template = files("agentcore_identity_poc").joinpath("static/complete.html").read_text("utf-8")
    return template.replace("__CSP_NONCE__", nonce)


def _safe_json_for_script(value: str) -> str:
    return (
        json.dumps(value)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
