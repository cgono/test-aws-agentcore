"""Inbound Entra JWT validation with a small, bounded JWKS cache."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx
import jwt

_JWKS_CACHE_SECONDS = 300.0
_PRIVATE_JWK_PARAMETERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})

type Jwks = Mapping[str, object]
type JwksLoader = Callable[[], Jwks]


class TokenRejected(ValueError):
    """A bearer token could not be accepted under the configured policy."""


def make_http_jwks_loader(jwks_url: str, client: httpx.Client | None = None) -> JwksLoader:
    """Return a loader that obtains only public RSA signing JWKs over HTTPS."""
    _require_absolute_https_url(jwks_url)

    def load() -> Jwks:
        if client is None:
            with httpx.Client(timeout=5.0) as temporary_client:
                return _fetch_public_jwks(temporary_client, jwks_url)
        return _fetch_public_jwks(client, jwks_url)

    return load


def _require_absolute_https_url(jwks_url: str) -> None:
    try:
        parsed_url = urlparse(jwks_url)
        has_host = parsed_url.hostname is not None
    except ValueError as error:
        raise ValueError("JWKS URL must be an absolute HTTPS URL") from error
    if parsed_url.scheme != "https" or not has_host:
        raise ValueError("JWKS URL must be an absolute HTTPS URL")


def _fetch_public_jwks(client: httpx.Client, jwks_url: str) -> Jwks:
    response = client.get(jwks_url, timeout=5.0)
    response.raise_for_status()
    body = response.json()
    if not isinstance(body, Mapping):
        raise ValueError("JWKS response must be an object")

    keys = body.get("keys")
    if not isinstance(keys, list):
        raise ValueError("JWKS response must contain a keys list")

    return {"keys": [key for key in keys if _is_public_rsa_jwk(key)]}


def _is_public_rsa_jwk(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    if value.get("kty") != "RSA":
        return False
    return not any(parameter in value for parameter in _PRIVATE_JWK_PARAMETERS)


@dataclass(frozen=True)
class JwtPolicy:
    """Validate bearer JWTs against exactly one Entra issuer and audience."""

    issuer: str
    audience: str
    jwks_loader: JwksLoader
    clock: Callable[[], float] = time.monotonic
    _cached_jwks: Jwks | None = field(default=None, init=False, compare=False, repr=False)
    _cache_expires_at: float = field(default=0.0, init=False, compare=False, repr=False)

    def validate(self, token: str) -> dict[str, Any]:
        """Return verified claims, or raise a token-free ``TokenRejected`` error."""
        try:
            header = jwt.get_unverified_header(token)
            key_id = header.get("kid")
            if not isinstance(key_id, str) or not key_id:
                raise TokenRejected("Token rejected")

            jwk = self._find_jwk(key_id, refresh=False)
            if jwk is None:
                jwk = self._find_jwk(key_id, refresh=True)
            if jwk is None:
                raise TokenRejected("Token rejected")

            public_key = jwt.PyJWK.from_dict(jwk).key
            return jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["iss", "aud", "sub", "exp"]},
            )
        except TokenRejected:
            raise
        except (httpx.HTTPError, jwt.PyJWTError, TypeError, ValueError, KeyError) as error:
            raise TokenRejected("Token rejected") from error

    def _find_jwk(self, key_id: str, *, refresh: bool) -> dict[str, Any] | None:
        jwks = self._load_jwks(refresh=refresh)
        keys = jwks.get("keys")
        if not isinstance(keys, list):
            raise ValueError("JWKS response must contain a keys list")
        for key in keys:
            if isinstance(key, Mapping) and key.get("kid") == key_id:
                return dict(key)
        return None

    def _load_jwks(self, *, refresh: bool) -> Jwks:
        now = self.clock()
        if not refresh and self._cached_jwks is not None and now < self._cache_expires_at:
            return self._cached_jwks

        jwks = self.jwks_loader()
        object.__setattr__(self, "_cached_jwks", jwks)
        object.__setattr__(self, "_cache_expires_at", now + _JWKS_CACHE_SECONDS)
        return jwks
