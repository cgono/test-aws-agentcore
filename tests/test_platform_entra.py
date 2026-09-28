# tests/test_platform_entra.py
from __future__ import annotations

from typing import Any

import jwt
import pytest

from agentcore_identity_poc.jwt_validation import TokenRejected
from agentcore_platform_poc.entra import AuthError, EntraVerifier, require_app, require_user

USER = {
    "ver": "2.0",
    "aud": "hub",
    "oid": "00000000-0000-0000-0000-00000000000a",
    "scp": "Workspace.ReadWrite other",
    "azp": "cli",
    "exp": 2000,
}
APP = {
    "ver": "2.0",
    "aud": "hub",
    "roles": ["Workspace.Agent"],
    "azp": "research",
    "idtyp": "app",
    "exp": 2000,
}


class FakePolicy:
    def __init__(self, claims: dict[str, Any] | None, cause: Exception | None = None) -> None:
        self._claims = claims
        self._cause = cause
        self.audience = "hub"

    def validate(self, token: str) -> dict[str, Any]:
        if self._claims is None:
            raise TokenRejected("Token rejected") from self._cause
        return dict(self._claims)


def _unsigned(exp: int) -> str:
    return jwt.encode({"exp": exp}, "k" * 32, algorithm="HS256")


def test_valid_claims_pass_through() -> None:
    verifier = EntraVerifier(FakePolicy(USER))  # type: ignore[arg-type]
    assert verifier.claims("t")["oid"] == USER["oid"]


def test_expired_token_is_token_expired() -> None:
    # PyJWT raises ExpiredSignatureError only after the signature check passed.
    policy = FakePolicy(None, cause=jwt.ExpiredSignatureError("Signature has expired"))
    verifier = EntraVerifier(policy)  # type: ignore[arg-type]
    with pytest.raises(AuthError) as caught:
        verifier.claims("t")
    assert (caught.value.status, caught.value.code) == (401, "token_expired")


def test_forged_token_with_past_exp_is_token_invalid() -> None:
    verifier = EntraVerifier(FakePolicy(None))  # type: ignore[arg-type]
    with pytest.raises(AuthError) as caught:
        verifier.claims(_unsigned(exp=1))
    assert caught.value.code == "token_invalid"


def test_bad_token_is_token_invalid() -> None:
    verifier = EntraVerifier(FakePolicy(None))  # type: ignore[arg-type]
    for token in (_unsigned(exp=4000), "garbage"):
        with pytest.raises(AuthError) as caught:
            verifier.claims(token)
        assert caught.value.code == "token_invalid"


@pytest.mark.parametrize("change", [{"ver": "1.0"}, {"aud": ["hub", "x"]}])
def test_v1_or_list_aud_rejected(change: dict[str, Any]) -> None:
    verifier = EntraVerifier(FakePolicy({**USER, **change}))  # type: ignore[arg-type]
    with pytest.raises(AuthError, match="token_invalid"):
        verifier.claims("t")


def test_require_user() -> None:
    assert require_user(USER, scope="Workspace.ReadWrite") == USER["oid"]
    assert (
        require_user(USER, scope="Workspace.ReadWrite", allowed_azp=frozenset({"cli"}))
        == USER["oid"]
    )


@pytest.mark.parametrize(
    ("claims", "code"),
    [
        ({**USER, "idtyp": "app"}, "not_user_token"),
        ({k: v for k, v in USER.items() if k != "scp"}, "missing_scope"),
        ({**USER, "scp": "Workspace.ReadWriteX"}, "missing_scope"),
        ({k: v for k, v in USER.items() if k != "oid"}, "not_user_token"),
        (APP, "not_user_token"),
    ],
)
def test_require_user_rejections(claims: dict[str, Any], code: str) -> None:
    with pytest.raises(AuthError) as caught:
        require_user(claims, scope="Workspace.ReadWrite")
    assert (caught.value.status, caught.value.code) == (403, code)


def test_require_user_azp() -> None:
    with pytest.raises(AuthError, match="client_not_allowed"):
        require_user(USER, scope="Workspace.ReadWrite", allowed_azp=frozenset({"other"}))


def test_require_app() -> None:
    assert (
        require_app(APP, role="Workspace.Agent", allowed_azp=frozenset({"research"})) == "research"
    )


@pytest.mark.parametrize(
    ("claims", "code"),
    [
        (USER, "not_app_token"),
        # Task 0 adds the optional idtyp claim; a roles-only token without it is not trusted.
        ({k: v for k, v in APP.items() if k != "idtyp"}, "not_app_token"),
        ({**APP, "idtyp": "user"}, "not_app_token"),
        ({**APP, "roles": ["Other"]}, "missing_role"),
        ({**APP, "roles": "Workspace.Agent"}, "missing_role"),
        ({**APP, "azp": "bench"}, "client_not_allowed"),
    ],
)
def test_require_app_rejections(claims: dict[str, Any], code: str) -> None:
    with pytest.raises(AuthError) as caught:
        require_app(claims, role="Workspace.Agent", allowed_azp=frozenset({"research"}))
    assert caught.value.code == code
