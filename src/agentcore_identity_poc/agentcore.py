"""A narrow, token-safe boundary around AgentCore Identity data-plane calls."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import NoReturn, Protocol

from botocore.exceptions import ClientError  # type: ignore[import-untyped]

type AgentCoreResponse = Mapping[str, object]


class AgentCoreDataPlane(Protocol):
    """Only the AgentCore operations exercised by this proof of concept."""

    def get_workload_access_token_for_jwt(
        self, *, workloadName: str, userToken: str
    ) -> AgentCoreResponse: ...

    def get_resource_oauth2_token(
        self,
        *,
        workloadIdentityToken: str,
        resourceCredentialProviderName: str,
        scopes: list[str],
        oauth2Flow: str,
        resourceOauth2ReturnUrl: str | None = None,
        forceAuthentication: bool | None = None,
        customParameters: Mapping[str, str] | None = None,
        customState: str | None = None,
    ) -> AgentCoreResponse: ...

    def complete_resource_token_auth(
        self, *, userIdentifier: Mapping[str, str], sessionUri: str
    ) -> AgentCoreResponse: ...


@dataclass(frozen=True)
class OAuthToken:
    """An immediately usable downstream OAuth access token."""

    access_token: str


@dataclass(frozen=True)
class AuthorizationRequired:
    """The browser authorization details for an AgentCore-managed OAuth session."""

    authorization_url: str
    session_uri: str


class AgentCoreError(RuntimeError):
    """Base error for expected AgentCore failures without AWS response details."""

    message = "AgentCore Identity request failed"

    def __init__(self) -> None:
        super().__init__(self.message)


class AgentCoreAccessDenied(AgentCoreError):
    """The configured AWS principal cannot perform the requested operation."""

    message = "AgentCore Identity request was denied"


class AgentCoreThrottled(AgentCoreError):
    """AgentCore rejected the operation due to throttling."""

    message = "AgentCore Identity request was throttled"


class AgentCoreValidationError(AgentCoreError):
    """AgentCore rejected the request shape or configured values."""

    message = "AgentCore Identity request was invalid"


class AgentCoreInternalError(AgentCoreError):
    """AgentCore or its transport could not complete the operation."""

    message = "AgentCore Identity request could not be completed"


_ACCESS_DENIED_CODES = frozenset(
    {"AccessDenied", "AccessDeniedException", "Unauthorized", "UnauthorizedException"}
)
_THROTTLING_CODES = frozenset(
    {"LimitExceededException", "Throttling", "ThrottlingException", "TooManyRequestsException"}
)
_VALIDATION_CODES = frozenset(
    {
        "InvalidParameterException",
        "InvalidRequestException",
        "ResourceNotFoundException",
        "ValidationException",
    }
)
_INTERNAL_CODES = frozenset(
    {
        "InternalError",
        "InternalServerException",
        "ServiceFailureException",
        "ServiceUnavailableException",
    }
)


class AgentCoreIdentity:
    """Issue AgentCore workload and resource tokens using approved request shapes."""

    def __init__(self, client: AgentCoreDataPlane) -> None:
        self._client = client

    def workload_token(self, workload_name: str, user_token: str) -> str:
        response = self._request(
            lambda: self._client.get_workload_access_token_for_jwt(
                workloadName=workload_name,
                userToken=user_token,
            )
        )
        return _required_string(response, "workloadAccessToken")

    def obo_token(self, workload_token: str, provider: str, scopes: list[str]) -> str:
        response = self._request(
            lambda: self._client.get_resource_oauth2_token(
                workloadIdentityToken=workload_token,
                resourceCredentialProviderName=provider,
                scopes=scopes,
                oauth2Flow="ON_BEHALF_OF_TOKEN_EXCHANGE",
            )
        )
        return _required_string(response, "accessToken")

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
        if force_authentication:
            # forceAuthentication=True forces AgentCore to run a fresh
            # authorization dance instead of reusing a cached one. Note:
            # customParameters is passed straight through to AgentCore's
            # provider-specific token exchange, and it only tolerates the keys
            # it recognizes for that provider ("access_type" for Google) --
            # adding an unrecognized key (e.g. "prompt") does not error, but
            # silently breaks the exchange: AgentCore still reports completion
            # (CompleteResourceTokenAuth 200s, the browser sees success) while
            # nothing is actually vaulted, and every later retrieval reports
            # "authorization required" with no token, forever. Confirmed via a
            # controlled manual test: identical calls differing only by the
            # presence of "prompt" vault a retrievable token without it and
            # nothing with it. Keep this branch's customParameters minimal and
            # identical to the non-forced branch below.
            response = self._request(
                lambda: self._client.get_resource_oauth2_token(
                    workloadIdentityToken=workload_token,
                    resourceCredentialProviderName=provider,
                    scopes=scopes,
                    oauth2Flow="USER_FEDERATION",
                    resourceOauth2ReturnUrl=return_url,
                    forceAuthentication=True,
                    customParameters={"access_type": "offline"},
                    customState=state,
                )
            )
        else:
            response = self._request(
                lambda: self._client.get_resource_oauth2_token(
                    workloadIdentityToken=workload_token,
                    resourceCredentialProviderName=provider,
                    scopes=scopes,
                    oauth2Flow="USER_FEDERATION",
                    resourceOauth2ReturnUrl=return_url,
                    customParameters={"access_type": "offline"},
                    customState=state,
                )
            )
        token = response.get("accessToken")
        if isinstance(token, str) and token:
            return OAuthToken(token)
        return AuthorizationRequired(
            authorization_url=_required_string(response, "authorizationUrl"),
            session_uri=_required_string(response, "sessionUri"),
        )

    def complete_google(self, session_uri: str, user_token: str) -> None:
        self._request(
            lambda: self._client.complete_resource_token_auth(
                userIdentifier={"userToken": user_token},
                sessionUri=session_uri,
            )
        )

    @staticmethod
    def _request(request: Callable[[], AgentCoreResponse]) -> AgentCoreResponse:
        try:
            return request()
        except Exception as error:
            _raise_mapped_error(error)


def _required_string(response: AgentCoreResponse, field_name: str) -> str:
    value = response.get(field_name)
    if isinstance(value, str) and value:
        return value
    error = ValueError("AgentCore response did not contain a required field")
    raise AgentCoreInternalError() from error


def _raise_mapped_error(error: Exception) -> NoReturn:
    if isinstance(error, ClientError):
        code = _client_error_code(error)
        if code in _ACCESS_DENIED_CODES:
            raise AgentCoreAccessDenied() from error
        if code in _THROTTLING_CODES:
            raise AgentCoreThrottled() from error
        if code in _VALIDATION_CODES:
            raise AgentCoreValidationError() from error
        if code in _INTERNAL_CODES:
            raise AgentCoreInternalError() from error
    raise AgentCoreInternalError() from error


def _client_error_code(error: ClientError) -> str | None:
    details = error.response.get("Error")
    if not isinstance(details, Mapping):
        return None
    code = details.get("Code")
    return code if isinstance(code, str) else None
