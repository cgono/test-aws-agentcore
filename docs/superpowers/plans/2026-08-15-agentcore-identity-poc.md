# AgentCore Identity Auth Broker POC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python-only feasibility POC that tests AgentCore Identity workload binding, Microsoft OBO, Google credential vaulting/session binding, IAM isolation, token lifetime behavior, offboarding, and operational suitability.

**Architecture:** A Typer CLI owns orchestration and sanitized evidence collection. Focused adapters wrap Entra, AgentCore, and downstream HTTP APIs; a small FastAPI process serves the synthetic Entra-protected resource and the Google session-binding callback. Cloud integrations are behind protocols so local tests use deterministic fakes, and each cloud phase has a stop gate before later work begins.

**Tech Stack:** Python 3.12+, `boto3` 1.42.49, `bedrock-agentcore` 1.18.1, `msal` 1.37.0, `PyJWT[crypto]` 2.13.0, FastAPI 0.139.2, Uvicorn 0.51.0, HTTPX, Typer 0.27.0, pytest, pytest-cov, Ruff, and mypy.

---

## Delivery order

1. Tasks 1-8 produce the local foundation and Entra OBO slice. Run the Phase 1 gate before continuing.
2. Tasks 9-12 add Google session binding, vault access, and isolation. Run the Phase 2 gate before continuing.
3. Tasks 13-15 add lifecycle/operational evidence and the final suitability report.

Cloud tests are marked `integration` and never run as part of the default unit suite. Commands that create or delete cloud resources require an explicit `--apply`; cleanup reads exact resource IDs from ignored local state.

## File map

| Path | Responsibility |
| --- | --- |
| `pyproject.toml` | Package metadata, pinned dependencies, pytest/Ruff/mypy configuration, CLI entry point |
| `.env.example` | Names and non-secret examples for required configuration |
| `.gitignore` | Virtual environment, secret inputs, local state, and raw evidence exclusions |
| `src/agentcore_identity_poc/config.py` | Strict environment configuration and preflight validation |
| `src/agentcore_identity_poc/models.py` | Shared enums and immutable result/evidence models |
| `src/agentcore_identity_poc/redaction.py` | Secret detection, per-run user aliasing, and safe structured logging |
| `src/agentcore_identity_poc/evidence.py` | Append-only sanitized JSONL observations and report aggregation |
| `src/agentcore_identity_poc/jwt_validation.py` | JWKS-backed issuer/audience/signature/expiry validation |
| `src/agentcore_identity_poc/entra.py` | MSAL device-code and authorization-code flows |
| `src/agentcore_identity_poc/agentcore.py` | Boto3 data/control-plane boundary and stable error mapping |
| `src/agentcore_identity_poc/downstream.py` | Synthetic resource and Google Drive HTTP clients |
| `src/agentcore_identity_poc/resource_api.py` | FastAPI synthetic Entra-protected resource used by Phase 1 |
| `src/agentcore_identity_poc/web.py` | FastAPI OAuth session-binding callback routes used by Phase 2 |
| `src/agentcore_identity_poc/cli.py` | User-facing preflight, OBO, Google, test, measurement, and report commands |
| `src/agentcore_identity_poc/static/complete.html` | Same-origin browser session completion page; no application UI |
| `infra/iam/*.json` | Broad observation policy, final scoped policy, and JWT-only deny guardrail |
| `scripts/provision_agentcore.py` | Repeatable create/read/update operations and ignored resource state |
| `tests/` | Unit, web-route, contract, and opt-in cloud integration tests |
| `docs/runbook.md` | Exact setup, manual provider steps, stage gates, and cleanup |
| `docs/assessment-template.md` | Hypothesis results, operational measurements, comparison, and decision rule |

### Task 1: Establish the Python project and quality gates

**Files:**
- Create: `pyproject.toml`
- Create: `.gitignore`
- Create: `.env.example`
- Create: `src/agentcore_identity_poc/__init__.py`
- Create: `tests/test_package.py`
- Modify: `README.md`

- [ ] **Step 1: Write the failing package smoke test**

```python
# tests/test_package.py
from importlib.metadata import version


def test_package_metadata_is_installed() -> None:
    assert version("agentcore-identity-poc") == "0.1.0"
```

- [ ] **Step 2: Run the test before package metadata exists**

Run: `python3 -m venv .venv && .venv/bin/python -m pip install --upgrade pip && .venv/bin/python -m pytest tests/test_package.py -v`

Expected: FAIL because `pytest` or the package is not installed.

- [ ] **Step 3: Add package metadata and pinned tools**

```toml
# pyproject.toml
[build-system]
requires = ["setuptools==80.9.0"]
build-backend = "setuptools.build_meta"

[project]
name = "agentcore-identity-poc"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
  "bedrock-agentcore==1.18.1",
  "boto3==1.42.49",
  "fastapi==0.139.2",
  "httpx==0.28.1",
  "msal==1.37.0",
  "PyJWT[crypto]==2.13.0",
  "typer==0.27.0",
  "uvicorn==0.51.0",
]

[project.optional-dependencies]
dev = [
  "mypy==1.18.2",
  "pytest==8.4.2",
  "pytest-asyncio==1.1.0",
  "pytest-cov==6.2.1",
  "respx==0.22.0",
  "ruff==0.12.10",
]

[project.scripts]
agentcore-identity-poc = "agentcore_identity_poc.cli:app"

[tool.setuptools.packages.find]
where = ["src"]

[tool.setuptools.package-data]
agentcore_identity_poc = ["static/*.html"]

[tool.pytest.ini_options]
addopts = "-ra --strict-markers"
testpaths = ["tests"]
markers = ["integration: requires live cloud/provider credentials"]

[tool.ruff]
line-length = 100
target-version = "py312"

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP", "S"]

[tool.ruff.lint.per-file-ignores]
"tests/**/*.py" = ["S101", "S105", "S106"]

[tool.mypy]
python_version = "3.12"
strict = true
packages = ["agentcore_identity_poc"]
```

Add `.env`, `.venv/`, `.poc-state.json`, `evidence/raw/`, `evidence/*.jsonl`, and Python cache files to `.gitignore`. Document `.venv/bin/python -m pip install -e '.[dev]'` and the three validation commands in `README.md`.

- [ ] **Step 4: Install and verify the baseline**

Run: `.venv/bin/python -m pip install -e '.[dev]' && .venv/bin/python -m pytest tests/test_package.py -v && .venv/bin/ruff check . && .venv/bin/mypy src`

Expected: one passing test, Ruff exit 0, mypy exit 0.

- [ ] **Step 5: Commit the project skeleton**

```bash
git add pyproject.toml .gitignore .env.example README.md src tests/test_package.py
git commit -m "build: initialize AgentCore Identity POC package"
```

### Task 2: Define strict configuration and preflight output

**Files:**
- Create: `src/agentcore_identity_poc/config.py`
- Create: `tests/test_config.py`
- Modify: `.env.example`

- [ ] **Step 1: Write failing configuration tests**

```python
# tests/test_config.py
import pytest

from agentcore_identity_poc.config import Settings, SettingsError


BASE = {
    "AWS_REGION": "us-west-2",
    "AWS_BUDGET_NAME": "agentcore-identity-poc-monthly",
    "ENTRA_TENANT_ID": "11111111-1111-1111-1111-111111111111",
    "ENTRA_PUBLIC_CLIENT_ID": "22222222-2222-2222-2222-222222222222",
    "ENTRA_API_CLIENT_ID": "33333333-3333-3333-3333-333333333333",
    "ENTRA_DOWNSTREAM_SCOPE": "api://44444444-4444-4444-4444-444444444444/access_as_user",
    "AGENTCORE_WORKLOAD_NAME": "iig-poc-approved",
    "AGENTCORE_SECOND_WORKLOAD_NAME": "iig-poc-unapproved",
    "AGENTCORE_MICROSOFT_PROVIDER": "iig-poc-microsoft",
    "AGENTCORE_GOOGLE_PROVIDER": "iig-poc-google",
    "RESOURCE_API_AUDIENCE": "api://44444444-4444-4444-4444-444444444444",
    "RESOURCE_API_URL": "https://poc-resource.example.test/metadata",
    "PUBLIC_BASE_URL": "https://poc-callback.example.test",
}


def test_settings_require_exact_https_public_url() -> None:
    values = BASE | {"PUBLIC_BASE_URL": "http://localhost:8000"}
    with pytest.raises(SettingsError, match="PUBLIC_BASE_URL must use https"):
        Settings.from_mapping(values)


def test_settings_derive_pinned_issuer_and_callback() -> None:
    settings = Settings.from_mapping(BASE)
    assert settings.entra_issuer == (
        "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0"
    )
    assert settings.google_return_url == "https://poc-callback.example.test/oauth/google/return"
```

- [ ] **Step 2: Verify the tests fail for the missing module**

Run: `.venv/bin/python -m pytest tests/test_config.py -v`

Expected: collection error for `agentcore_identity_poc.config`.

- [ ] **Step 3: Implement immutable settings**

```python
# src/agentcore_identity_poc/config.py
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlparse


class SettingsError(ValueError):
    """Raised when required POC configuration is absent or unsafe."""


@dataclass(frozen=True)
class Settings:
    aws_region: str
    aws_budget_name: str
    entra_tenant_id: str
    entra_public_client_id: str
    entra_api_client_id: str
    entra_downstream_scope: str
    agentcore_workload_name: str
    agentcore_second_workload_name: str
    agentcore_microsoft_provider: str
    agentcore_google_provider: str
    resource_api_audience: str
    resource_api_url: str
    public_base_url: str

    @classmethod
    def from_mapping(cls, values: Mapping[str, str]) -> "Settings":
        required = MappingProxyType({field: field.upper() for field in cls.__annotations__})
        missing = [env for env in required.values() if not values.get(env)]
        if missing:
            raise SettingsError(f"missing configuration: {', '.join(sorted(missing))}")
        kwargs = {field: values[env].rstrip("/") for field, env in required.items()}
        if urlparse(kwargs["public_base_url"]).scheme != "https":
            raise SettingsError("PUBLIC_BASE_URL must use https")
        return cls(**kwargs)

    @property
    def entra_issuer(self) -> str:
        return f"https://login.microsoftonline.com/{self.entra_tenant_id}/v2.0"

    @property
    def google_return_url(self) -> str:
        return f"{self.public_base_url}/oauth/google/return"
```

- [ ] **Step 4: Run configuration tests**

Run: `.venv/bin/python -m pytest tests/test_config.py -v`

Expected: two passing tests.

- [ ] **Step 5: Commit configuration**

```bash
git add .env.example src/agentcore_identity_poc/config.py tests/test_config.py
git commit -m "feat: add strict POC configuration"
```

### Task 3: Build sanitized evidence recording

**Files:**
- Create: `src/agentcore_identity_poc/models.py`
- Create: `src/agentcore_identity_poc/redaction.py`
- Create: `src/agentcore_identity_poc/evidence.py`
- Create: `tests/test_evidence.py`

- [ ] **Step 1: Write failing redaction and evidence tests**

```python
# tests/test_evidence.py
import json

import pytest

from agentcore_identity_poc.evidence import EvidenceWriter
from agentcore_identity_poc.models import Observation
from agentcore_identity_poc.redaction import UnsafeEvidenceError


JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.c2lnbmF0dXJl"


def test_writer_rejects_token_shaped_values(tmp_path) -> None:
    writer = EvidenceWriter(tmp_path / "evidence.jsonl")
    with pytest.raises(UnsafeEvidenceError):
        writer.append(Observation("H1", "workload", "pass", {"token": JWT}))


def test_writer_persists_only_sanitized_fields(tmp_path) -> None:
    path = tmp_path / "evidence.jsonl"
    EvidenceWriter(path).append(
        Observation("H1", "workload", "pass", {"issuer": "https://issuer", "latency_ms": 12})
    )
    row = json.loads(path.read_text().strip())
    assert row["hypothesis"] == "H1"
    assert row["details"] == {"issuer": "https://issuer", "latency_ms": 12}
```

- [ ] **Step 2: Verify the tests fail for missing evidence types**

Run: `.venv/bin/python -m pytest tests/test_evidence.py -v`

Expected: collection error for the missing modules.

- [ ] **Step 3: Implement immutable observations and recursive safety checks**

```python
# src/agentcore_identity_poc/models.py
from dataclasses import asdict, dataclass


type JsonValue = None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]


@dataclass(frozen=True)
class Observation:
    hypothesis: str
    operation: str
    outcome: str
    details: dict[str, JsonValue]

    def as_dict(self) -> dict[str, object]:
        return asdict(self)
```

`redaction.py` must reject JWT-shaped strings, Bearer headers, authorization URLs containing `code`, `session_id`, or `state`, cookie values, known secret field names, email addresses, and Drive filenames. `EvidenceWriter.append()` must validate first, create its parent directory, and append one compact JSON object followed by `\n`.

- [ ] **Step 4: Run evidence tests and quality checks**

Run: `.venv/bin/python -m pytest tests/test_evidence.py -v && .venv/bin/ruff check src tests && .venv/bin/mypy src`

Expected: two passing tests and both static checks exit 0.

- [ ] **Step 5: Commit evidence safety**

```bash
git add src/agentcore_identity_poc/models.py src/agentcore_identity_poc/redaction.py src/agentcore_identity_poc/evidence.py tests/test_evidence.py
git commit -m "feat: add sanitized evidence recording"
```

### Task 4: Validate inbound JWTs against pinned Entra policy

**Files:**
- Create: `src/agentcore_identity_poc/jwt_validation.py`
- Create: `tests/test_jwt_validation.py`

- [ ] **Step 1: Write failing issuer, audience, expiry, and signature tests**

```python
# tests/test_jwt_validation.py
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from agentcore_identity_poc.jwt_validation import JwtPolicy, TokenRejected


def test_rejects_foreign_issuer(rsa_key_pair) -> None:
    private_key, jwk = rsa_key_pair
    token = jwt.encode(
        {
            "iss": "https://foreign.example.test",
            "aud": "api-client",
            "sub": "user-a",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        },
        private_key,
        algorithm="RS256",
        headers={"kid": jwk["kid"]},
    )
    policy = JwtPolicy("https://tenant.example.test", "api-client", lambda: {"keys": [jwk]})
    with pytest.raises(TokenRejected, match="issuer"):
        policy.validate(token)
```

Add separate tests for the intended claims, wrong audience, expired token, missing `sub`, unknown `kid`, and invalid signature. Generate RSA keys inside a session-scoped fixture; never check in a live token.

- [ ] **Step 2: Verify the JWT tests fail**

Run: `.venv/bin/python -m pytest tests/test_jwt_validation.py -v`

Expected: collection error for `jwt_validation`.

- [ ] **Step 3: Implement explicit policy validation**

```python
# src/agentcore_identity_poc/jwt_validation.py
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import jwt


class TokenRejected(ValueError):
    """Raised when an inbound token does not satisfy the pinned policy."""


@dataclass(frozen=True)
class JwtPolicy:
    issuer: str
    audience: str
    jwks_loader: Callable[[], dict[str, Any]]

    def validate(self, token: str) -> dict[str, Any]:
        try:
            kid = jwt.get_unverified_header(token)["kid"]
            key_data = next(key for key in self.jwks_loader()["keys"] if key["kid"] == kid)
            key = jwt.PyJWK.from_dict(key_data).key
            return jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["iss", "aud", "sub", "exp"]},
            )
        except (jwt.PyJWTError, KeyError, StopIteration) as error:
            raise TokenRejected(f"token rejected: {error}") from error
```

The production JWKS loader uses HTTPX with a five-second timeout and caches only the public JWKS document for five minutes. A missing `kid` triggers one immediate JWKS refresh before rejection so key rotation is testable.

- [ ] **Step 4: Run JWT tests**

Run: `.venv/bin/python -m pytest tests/test_jwt_validation.py -v`

Expected: all JWT policy tests pass.

- [ ] **Step 5: Commit JWT validation**

```bash
git add src/agentcore_identity_poc/jwt_validation.py tests/test_jwt_validation.py
git commit -m "feat: validate inbound Entra JWTs"
```

### Task 5: Wrap AgentCore data-plane operations

**Files:**
- Create: `src/agentcore_identity_poc/agentcore.py`
- Create: `tests/test_agentcore.py`

- [ ] **Step 1: Write failing request-shape tests with a recording fake**

```python
# tests/test_agentcore.py
from agentcore_identity_poc.agentcore import AgentCoreIdentity


class RecordingClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def get_workload_access_token_for_jwt(self, **kwargs):
        self.calls.append(("workload", kwargs))
        return {"workloadAccessToken": "wat-value"}

    def get_resource_oauth2_token(self, **kwargs):
        self.calls.append(("resource", kwargs))
        return {"accessToken": "downstream-value"}


def test_obo_uses_jwt_workload_binding_and_declared_scope() -> None:
    client = RecordingClient()
    identity = AgentCoreIdentity(client)
    wat = identity.workload_token("approved-workload", "user-jwt")
    token = identity.obo_token(wat, "microsoft-provider", ["api://resource/access"])
    assert token == "downstream-value"
    assert client.calls == [
        ("workload", {"workloadName": "approved-workload", "userToken": "user-jwt"}),
        (
            "resource",
            {
                "workloadIdentityToken": "wat-value",
                "resourceCredentialProviderName": "microsoft-provider",
                "scopes": ["api://resource/access"],
                "oauth2Flow": "ON_BEHALF_OF_TOKEN_EXCHANGE",
            },
        ),
    ]
```

Add tests for `USER_FEDERATION` with `customParameters={"access_type": "offline"}`, authorization-required responses, `complete_resource_token_auth(userIdentifier={"userToken": "signed-user-jwt"})`, throttling, access denial, and never calling `get_workload_access_token_for_user_id`.

- [ ] **Step 2: Verify the adapter tests fail**

Run: `.venv/bin/python -m pytest tests/test_agentcore.py -v`

Expected: collection error for `agentcore`.

- [ ] **Step 3: Implement a narrow Boto3 adapter**

Define `AgentCoreDataPlane` as a `Protocol`, immutable `OAuthToken` and `AuthorizationRequired` result types, and these complete `AgentCoreIdentity` methods:

```python
def workload_token(self, workload_name: str, user_token: str) -> str:
    response = self._client.get_workload_access_token_for_jwt(
        workloadName=workload_name,
        userToken=user_token,
    )
    return str(response["workloadAccessToken"])

def obo_token(self, workload_token: str, provider: str, scopes: list[str]) -> str:
    response = self._client.get_resource_oauth2_token(
        workloadIdentityToken=workload_token,
        resourceCredentialProviderName=provider,
        scopes=scopes,
        oauth2Flow="ON_BEHALF_OF_TOKEN_EXCHANGE",
    )
    return str(response["accessToken"])

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
    response = self._client.get_resource_oauth2_token(
        workloadIdentityToken=workload_token,
        resourceCredentialProviderName=provider,
        scopes=scopes,
        oauth2Flow="USER_FEDERATION",
        resourceOauth2ReturnUrl=return_url,
        forceAuthentication=force_authentication,
        customParameters={"access_type": "offline"},
        customState=state,
    )
    if token := response.get("accessToken"):
        return OAuthToken(str(token))
    return AuthorizationRequired(
        authorization_url=str(response["authorizationUrl"]),
        session_uri=str(response["sessionUri"]),
    )

def complete_google(self, session_uri: str, user_token: str) -> None:
    self._client.complete_resource_token_auth(
        userIdentifier={"userToken": user_token},
        sessionUri=session_uri,
    )
```

Map AWS access errors, validation errors, throttling, and internal errors to stable POC exceptions. Preserve the original exception as `__cause__`, but expose no serialized AWS response because it may contain an authorization URL.

- [ ] **Step 4: Run adapter tests**

Run: `.venv/bin/python -m pytest tests/test_agentcore.py -v`

Expected: all AgentCore adapter tests pass.

- [ ] **Step 5: Commit the AgentCore boundary**

```bash
git add src/agentcore_identity_poc/agentcore.py tests/test_agentcore.py
git commit -m "feat: wrap AgentCore Identity data plane"
```

### Task 6: Acquire Entra tokens and call the synthetic resource

**Files:**
- Create: `src/agentcore_identity_poc/entra.py`
- Create: `src/agentcore_identity_poc/downstream.py`
- Create: `src/agentcore_identity_poc/resource_api.py`
- Create: `tests/test_entra.py`
- Create: `tests/test_downstream.py`
- Create: `tests/test_resource_api.py`

- [ ] **Step 1: Write failing MSAL and downstream tests**

```python
def test_device_code_requests_only_worker_api_scope(fake_msal) -> None:
    auth = EntraDeviceAuth(fake_msal, ["api://worker/access_as_user"])
    token = auth.acquire(lambda message: None)
    assert token == "entra-user-token"
    assert fake_msal.requested_scopes == ["api://worker/access_as_user"]


def test_resource_client_returns_synthetic_subject(respx_mock) -> None:
    respx_mock.get("https://resource.example.test/metadata").mock(
        return_value=httpx.Response(200, json={"subject_alias": "user-a", "items": []})
    )
    result = SyntheticResourceClient("https://resource.example.test/metadata").list("token")
    assert result.subject_alias == "user-a"
```

Also test MSAL error responses, HTTP 401/403/429/500 mapping, authorization header construction, timeouts, and response schema rejection.

In `tests/test_resource_api.py`, create signed JWTs with the RSA fixture from Task 4. Assert `GET /metadata` returns synthetic data for the expected downstream audience and delegated scope, and rejects wrong issuer, audience, expiry, missing scope, and missing Bearer authentication.

- [ ] **Step 2: Verify the tests fail**

Run: `.venv/bin/python -m pytest tests/test_entra.py tests/test_downstream.py tests/test_resource_api.py -v`

Expected: collection errors for the new modules.

- [ ] **Step 3: Implement MSAL and HTTP adapters**

`EntraDeviceAuth` must use `msal.PublicClientApplication`, call `initiate_device_flow(scopes=self._scopes)`, display only `message`, and call `acquire_token_by_device_flow`. It returns only `access_token` or raises `EntraAuthError` with the OAuth error code and sanitized description.

`SyntheticResourceClient` and `GoogleDriveClient` use a shared HTTPX client configured with five-second connect and ten-second total timeouts. They send Bearer tokens, return normalized metadata, and never log request headers or raw bodies.

`create_resource_app(jwt_policy)` exposes only `GET /healthz` and `GET /metadata`. The metadata route validates the downstream token independently, requires the configured delegated scope, and returns a per-run subject alias plus an empty synthetic item list. It never returns the token subject, claims, or provider response. Add an app factory entry point so Uvicorn starts it from environment-backed settings.

- [ ] **Step 4: Run adapter tests**

Run: `.venv/bin/python -m pytest tests/test_entra.py tests/test_downstream.py tests/test_resource_api.py -v`

Expected: all Entra and downstream tests pass.

- [ ] **Step 5: Commit provider adapters**

```bash
git add src/agentcore_identity_poc/entra.py src/agentcore_identity_poc/downstream.py src/agentcore_identity_poc/resource_api.py tests/test_entra.py tests/test_downstream.py tests/test_resource_api.py
git commit -m "feat: add Entra and downstream adapters"
```

### Task 7: Expose preflight and Entra OBO CLI commands

**Files:**
- Create: `src/agentcore_identity_poc/cli.py`
- Create: `tests/test_cli_obo.py`

- [ ] **Step 1: Write failing CLI tests**

```python
from typer.testing import CliRunner

from agentcore_identity_poc.cli import app


def test_preflight_reports_machine_readable_failures(monkeypatch) -> None:
    monkeypatch.delenv("AWS_REGION", raising=False)
    result = CliRunner().invoke(app, ["preflight", "--json"])
    assert result.exit_code == 2
    assert '"status":"blocked"' in result.stdout
    assert "AWS_REGION" in result.stdout
```

Add tests showing `entra-obo` validates before AWS, records H1/H2/H6 observations, prints no access token, and exits with documented codes: `0` pass, `2` local configuration, `3` authentication, `4` AgentCore, `5` downstream denial.

- [ ] **Step 2: Verify CLI tests fail**

Run: `.venv/bin/python -m pytest tests/test_cli_obo.py -v`

Expected: collection error for `cli`.

- [ ] **Step 3: Implement dependency-injected Typer commands**

```python
app = typer.Typer(no_args_is_help=True)


@app.command("preflight")
def preflight(json_output: bool = typer.Option(False, "--json")) -> None:
    """Check local configuration and read-only provider reachability."""


@app.command("entra-obo")
def entra_obo(
    token_stdin: bool = typer.Option(False, "--token-stdin"),
    evidence_path: Path = typer.Option(Path("evidence/phase-1.jsonl")),
) -> None:
    """Validate an Entra user and call the synthetic resource through AgentCore OBO."""
```

Use a `Runtime` factory so tests replace settings, token acquisition, AgentCore, downstream clients, clock, and evidence writer without monkeypatching Boto internals. `--token-stdin` must reject interactive terminals and read exactly one line so tokens never appear in shell history or process arguments.

- [ ] **Step 4: Run the Phase 1 local suite**

Run: `.venv/bin/python -m pytest -m 'not integration' -v && .venv/bin/ruff check . && .venv/bin/mypy src`

Expected: all local tests pass and static checks exit 0.

- [ ] **Step 5: Commit the Entra CLI slice**

```bash
git add src/agentcore_identity_poc/cli.py tests/test_cli_obo.py
git commit -m "feat: add preflight and Entra OBO commands"
```

### Task 8: Add repeatable AgentCore provisioning and the Phase 1 gate

**Files:**
- Create: `scripts/provision_agentcore.py`
- Create: `scripts/__init__.py`
- Create: `infra/iam/broad-observation.json`
- Create: `infra/iam/scoped.json`
- Create: `infra/iam/deny-user-id.json`
- Create: `tests/test_provision_agentcore.py`
- Create: `tests/integration/test_entra_obo_live.py`
- Create: `docs/runbook.md`

- [ ] **Step 1: Write failing dry-run provisioning tests**

Test that `plan_resources(settings, account_id)` produces exactly two named workload identities, the Microsoft provider, no wildcard in the final scoped policy, and an explicit deny for `bedrock-agentcore:GetWorkloadAccessTokenForUserId`. Test that preflight blocks when the configured AWS budget does not exist and that cleanup refuses missing or malformed `.poc-state.json`.

- [ ] **Step 2: Verify provisioning tests fail**

Run: `.venv/bin/python -m pytest tests/test_provision_agentcore.py -v`

Expected: collection error because the script is absent.

- [ ] **Step 3: Implement plan/apply/cleanup commands**

The script must default to a JSON plan. Before any create operation, it verifies the named monthly AWS budget exists and exits with the exact console/CLI remediation when absent. `--apply` creates only absent named resources, tags them `Project=agentcore-identity-poc`, and atomically writes returned names/ARNs/callback URLs to `.poc-state.json` with mode `0600`. `cleanup --apply` deletes only resources recorded in that state after printing their exact identifiers and requiring `--confirm agentcore-identity-poc`.

IAM JSON files use `${DIRECTORY_ARN}`, `${WORKLOAD_ARN}`, `${SECOND_WORKLOAD_ARN}`, `${VAULT_ARN}`, and `${PROVIDER_ARN}` as values replaced by the provisioning script's JSON parser, never shell interpolation. Use ARNs returned by AWS and recorded in state; do not synthesize provider ARN formats. The final policy includes directory, named workload, vault, and named provider ARNs plus the explicit user-ID deny and contains no wildcard.

- [ ] **Step 4: Add the opt-in live OBO test and runbook gate**

```python
@pytest.mark.integration
@pytest.mark.parametrize("user_alias", ["user-a", "user-b"])
def test_live_entra_obo_records_h1_h2_h6(live_runtime, user_alias: str) -> None:
    result = live_runtime.run_entra_obo(user_alias=user_alias)
    assert result.workload_token_received is True
    assert result.resource_status == 200
    assert result.subject_alias == user_alias
    assert result.consent_prompt_seen is False
```

The runbook documents Entra's three registrations/roles: public CLI client, confidential middle-tier API app, and downstream resource API. It requires confirming that the inbound `aud` equals the middle-tier client ID and that the public client is pre-authorized before running the live test. It also gives the exact Uvicorn app-factory command and tunnel URL for the synthetic resource API.

- [ ] **Step 5: Run the Phase 1 gate**

Run local: `.venv/bin/python -m pytest -m 'not integration' -v`

Run live after preflight passes: `.venv/bin/python -m pytest tests/integration/test_entra_obo_live.py -m integration -v -s`

Expected: H1, H2, and H6 evidence is recorded. Stop here and write a failure note if the live test does not pass; do not begin Google work.

- [ ] **Step 6: Commit provisioning and Phase 1 gate**

```bash
git add scripts infra tests/test_provision_agentcore.py tests/integration/test_entra_obo_live.py docs/runbook.md
git commit -m "feat: provision and verify Entra OBO slice"
```

### Task 9: Implement the browser-bound callback session

**Files:**
- Create: `src/agentcore_identity_poc/web.py`
- Create: `src/agentcore_identity_poc/static/complete.html`
- Create: `tests/test_web_session.py`

- [ ] **Step 1: Write failing route tests**

Test these behaviors with FastAPI `TestClient` and fake MSAL/AgentCore dependencies:

```python
def test_google_return_does_not_complete_without_live_browser_token(client, fake_identity) -> None:
    response = client.get("/oauth/google/return?session_id=urn:test&state=valid")
    assert response.status_code == 200
    assert "sessionStorage" in response.text
    assert fake_identity.complete_calls == []


def test_complete_rejects_state_mismatch(client, fake_identity) -> None:
    response = client.post(
        "/oauth/google/complete",
        json={"session_uri": "urn:test", "state": "wrong"},
        headers={"Authorization": "Bearer user-token"},
    )
    assert response.status_code == 400
    assert fake_identity.complete_calls == []
```

Add tests for missing/expired state cookie, ten-minute expiry, token user mismatch, replay, successful completion, secure cookie flags, and redacted error bodies.

- [ ] **Step 2: Verify route tests fail**

Run: `.venv/bin/python -m pytest tests/test_web_session.py -v`

Expected: collection error for `web`.

- [ ] **Step 3: Implement minimal same-origin routes**

`create_app(runtime)` generates a random process-local cookie-signing key at startup and exposes:

- `GET /healthz`
- `GET /connect` to begin MSAL authorization code flow with PKCE and store only the short-lived MSAL flow metadata in a signed, `HttpOnly`, `Secure`, `SameSite=Lax` cookie
- `GET /auth/entra/callback` to complete MSAL and return a CSP-nonced page that writes only the Entra access token to `sessionStorage`, removes OAuth query parameters from browser history, and POSTs `/oauth/google/start`
- `POST /oauth/google/start` to validate the Bearer token, request AgentCore Google authorization with an opaque state, set a signed one-time state cookie, and return the provider authorization URL
- `GET /oauth/google/return` to serve `complete.html` without calling AgentCore
- `POST /oauth/google/complete` to verify cookie, state, session URI, live Bearer token, issuer/audience, and `sub`; call `CompleteResourceTokenAuth`; then clear cookie and browser storage

The page uses no third-party JavaScript. MSAL Python performs the authorization-code exchange; the page only moves the returned access token into and out of same-origin `sessionStorage`. Serialize the token into the response with JSON encoding that escapes `<`, `>`, `&`, U+2028, and U+2029, and authorize the inline script with a per-response CSP nonce. Add `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, and `X-Content-Type-Options: nosniff` to every auth response. Clear the MSAL-flow cookie after the Entra callback and the Google-state cookie after success or terminal failure.

- [ ] **Step 4: Run callback tests**

Run: `.venv/bin/python -m pytest tests/test_web_session.py -v`

Expected: all callback/session tests pass.

- [ ] **Step 5: Commit callback binding**

```bash
git add src/agentcore_identity_poc/web.py src/agentcore_identity_poc/static/complete.html tests/test_web_session.py
git commit -m "feat: add OAuth session-binding callback"
```

### Task 10: Add Google retrieval, refresh, and revocation commands

**Files:**
- Modify: `src/agentcore_identity_poc/cli.py`
- Modify: `src/agentcore_identity_poc/downstream.py`
- Create: `tests/test_cli_google.py`

- [ ] **Step 1: Write failing Google command tests**

Test `google-connect`, `google-list`, and `google-revoke-check`. Assert initial requests include `access_type=offline`; later retrieval omits `forceAuthentication`; a Drive 401 causes exactly one `forceAuthentication=true` request and returns `authorization_required`; no refresh or access token reaches output/evidence.

- [ ] **Step 2: Verify Google tests fail**

Run: `.venv/bin/python -m pytest tests/test_cli_google.py -v`

Expected: failures because the commands are absent.

- [ ] **Step 3: Implement Google commands**

```python
@app.command("google-connect")
def google_connect(open_browser: bool = typer.Option(True, "--open-browser/--print-url")) -> None:
    """Start the live-browser session-binding flow."""


@app.command("google-list")
def google_list(evidence_path: Path = Path("evidence/phase-2.jsonl")) -> None:
    """Retrieve a vaulted Google token and list sanitized Drive metadata."""


@app.command("google-revoke-check")
def google_revoke_check() -> None:
    """Detect provider revocation and force a new authorization session once."""
```

`google-list` outputs only item count and type counts. The Drive adapter must discard IDs, names, owners, links, and timestamps before returning to the CLI.

- [ ] **Step 4: Run Google command tests and full local suite**

Run: `.venv/bin/python -m pytest -m 'not integration' -v`

Expected: all local tests pass.

- [ ] **Step 5: Commit Google CLI behavior**

```bash
git add src/agentcore_identity_poc/cli.py src/agentcore_identity_poc/downstream.py tests/test_cli_google.py
git commit -m "feat: add Google vault lifecycle commands"
```

### Task 11: Implement IAM and user-isolation matrices

**Files:**
- Modify: `src/agentcore_identity_poc/cli.py`
- Create: `src/agentcore_identity_poc/experiments.py`
- Create: `tests/test_experiments.py`
- Create: `tests/integration/test_isolation_live.py`

- [ ] **Step 1: Write failing matrix tests**

Define immutable matrix rows containing principal alias, asserted workload, user alias, policy mode, provider, outcome, and AWS error category. Test that H4a requires two distinct validated users and that H4b rejects results collected under different AWS principals.

- [ ] **Step 2: Verify matrix tests fail**

Run: `.venv/bin/python -m pytest tests/test_experiments.py -v`

Expected: collection error for `experiments`.

- [ ] **Step 3: Implement explicit experiment runners**

`run_user_isolation()` obtains two JWT-backed workload tokens under the approved workload and proves each sees only its own Google connection state. `run_workload_isolation()` records the same AWS caller identity, applies the broad observation policy, attempts both workload names, applies the final scoped policy, and repeats. It waits for IAM propagation with a bounded 60-second deadline and records every attempt.

The CLI requires `--acknowledge-broad-policy` before applying the broad policy and restores the final scoped policy in a `finally` block. A failed restoration exits nonzero and prints the exact recovery command from the runbook.

- [ ] **Step 4: Run local and live isolation tests**

Run local: `.venv/bin/python -m pytest tests/test_experiments.py -v`

Run live: `.venv/bin/python -m pytest tests/integration/test_isolation_live.py -m integration -v -s`

Expected: H4a and both broad/scoped H4b rows are present in sanitized evidence.

- [ ] **Step 5: Commit isolation experiments**

```bash
git add src/agentcore_identity_poc/cli.py src/agentcore_identity_poc/experiments.py tests/test_experiments.py tests/integration/test_isolation_live.py
git commit -m "feat: measure user and workload isolation"
```

### Task 12: Add the Google provider runbook and Phase 2 gate

**Files:**
- Modify: `scripts/provision_agentcore.py`
- Modify: `docs/runbook.md`
- Create: `tests/integration/test_google_live.py`

- [ ] **Step 1: Test two-stage Google provider state**

Add unit tests proving provider creation saves the returned unique `callbackUrl`, plan output blocks until that URL is acknowledged as registered in Google, and provider recreation changes state to `google_console_update_required`.

- [ ] **Step 2: Implement the two-stage provider workflow**

Add `google-create --apply`, `google-show-callback`, and `google-confirm-callback --apply`. Never accept a Google client secret in a command argument; read it from stdin or an environment variable, pass it directly to Boto3, and exclude it from state and exceptions.

- [ ] **Step 3: Document the exact manual steps**

The runbook must require:

1. Add the exact regional AgentCore domain printed by preflight to Google authorized domains.
2. Create the OAuth client and leave redirect URIs empty until AgentCore returns its callback.
3. Register the exact AgentCore callback in Google.
4. Register the POC return URL on both workload identities.
5. Start the FastAPI process, expose it through the chosen HTTPS tunnel, and verify `/healthz` before consent.
6. Complete Google consent within ten minutes.
7. Wait for natural access-token expiry before the refresh observation.

- [ ] **Step 4: Run the Phase 2 gate**

Run: `.venv/bin/python -m pytest tests/integration/test_google_live.py tests/integration/test_isolation_live.py -m integration -v -s`

Expected: Google session binding, durable vault connection, H4a, and H4b evidence is present. H3 remains pending until post-expiry refresh is observed in Task 13; H7 and H8 also remain pending. Stop if callback binding or durable vaulting fails.

- [ ] **Step 5: Commit Google provisioning and runbook**

```bash
git add scripts/provision_agentcore.py docs/runbook.md tests/integration/test_google_live.py
git commit -m "docs: add Google provider and callback runbook"
```

### Task 13: Measure expiry, revocation, offboarding, latency, caching, and throttling

**Files:**
- Modify: `src/agentcore_identity_poc/experiments.py`
- Modify: `src/agentcore_identity_poc/cli.py`
- Create: `tests/test_measurements.py`
- Create: `tests/integration/test_lifecycle_live.py`

- [ ] **Step 1: Write failing deterministic measurement tests**

Use a fake monotonic clock and scripted clients. Verify p50/p95 calculation, distinct cold/warm samples, SHA-256 token fingerprints salted per run, bounded concurrency, exponential backoff with jitter, no retry after a non-retryable 4xx, and expiry rows that distinguish inbound JWT, workload token, OBO token, and Google retrieval.

- [ ] **Step 2: Verify measurement tests fail**

Run: `.venv/bin/python -m pytest tests/test_measurements.py -v`

Expected: failures because measurement runners are absent.

- [ ] **Step 3: Implement bounded measurement commands**

Add:

- `measure latency --samples 10`
- `measure concurrency --workers 5 --requests 20`
- `measure expiry --resume-state .poc-expiry-state.json`
- `measure cloudtrail --lookback-minutes 30`
- `offboard google --user-alias user-a --apply`

The expiry command writes only issue/expiry timestamps and opaque salted fingerprints, then exits with a resume timestamp rather than sleeping for an hour. On resume it validates that the stored state is mode `0600`, belongs to the current project ID, and contains no JWT-shaped values.

The offboarding command first tests provider revocation and `forceAuthentication`. It then discovers the narrowest documented AgentCore operation; if the installed SDK exposes no per-user purge, it records H8 as failed and does not delete the shared provider as a substitute.

- [ ] **Step 4: Run lifecycle tests**

Run local: `.venv/bin/python -m pytest tests/test_measurements.py -v`

Run live: `.venv/bin/python -m pytest tests/integration/test_lifecycle_live.py -m integration -v -s`

Expected: H3 has post-expiry refresh evidence, H7 has separate OBO and Google results, H8 is explicitly pass or fail, and latency, caching, throttling, and CloudTrail fields are recorded without raw tokens.

- [ ] **Step 5: Commit lifecycle measurements**

```bash
git add src/agentcore_identity_poc/experiments.py src/agentcore_identity_poc/cli.py tests/test_measurements.py tests/integration/test_lifecycle_live.py
git commit -m "feat: measure identity lifecycle and operations"
```

### Task 14: Produce compatibility, baseline, and decision reports

**Files:**
- Create: `src/agentcore_identity_poc/assessment.py`
- Create: `tests/test_assessment.py`
- Create: `docs/assessment-template.md`
- Create after live evidence: `docs/assessment.md`
- Create: `docs/provider-compatibility.md`
- Create: `docs/direct-baseline.md`

- [ ] **Step 1: Write failing decision-rule tests**

```python
def test_rejects_when_mandatory_hypothesis_fails() -> None:
    results = passing_results() | {"H7": "fail"}
    assert decide(results, iam_acceptable=True, custom_provider_plausible=True) == "reject_or_defer"


def test_adopts_with_caveats_for_accepted_iam_dependency() -> None:
    assert decide(passing_results(), iam_acceptable=True, custom_provider_plausible=True) == (
        "adopt_with_caveats"
    )
```

Add tests for missing evidence, unacceptable H4b IAM dependency, custom-provider incompatibility affecting only that path, absent audit attribution, and unacceptable latency/quota measurements.

- [ ] **Step 2: Verify assessment tests fail**

Run: `.venv/bin/python -m pytest tests/test_assessment.py -v`

Expected: collection error for `assessment`.

- [ ] **Step 3: Implement deterministic report generation**

`assessment.py` loads sanitized JSONL, requires one terminal result for H1-H8, validates measurement units, applies the design's decision rule, and renders Markdown without copying raw provider responses. It exits nonzero when required evidence is absent rather than guessing.

`provider-compatibility.md` has one row each for discovery, grant, client authentication, actor token, actor scopes, audience/resource, custom parameters, and outbound web identity federation for PingOne and AD FS. Every cell contains a source link, supported/unsupported/unknown, and consequence.

`direct-baseline.md` compares AgentCore with MSAL OBO plus KMS-encrypted refresh storage across secret custody, refresh orchestration, revocation, deletion, callback binding, IAM, regional dependency, latency, quotas, audit, migration, cost, and operational ownership.

- [ ] **Step 4: Run report tests and generate the draft**

Run: `.venv/bin/python -m pytest tests/test_assessment.py -v`

Run after live evidence exists: `.venv/bin/agentcore-identity-poc report --evidence evidence/sanitized.jsonl --output docs/assessment.md`

Expected: report command exits 0 only when all mandatory evidence is present.

- [ ] **Step 5: Commit assessment generation**

```bash
git add src/agentcore_identity_poc/assessment.py tests/test_assessment.py docs/assessment-template.md docs/provider-compatibility.md docs/direct-baseline.md
git commit -m "feat: generate AgentCore suitability assessment"
```

### Task 15: Final verification, secret scan, cleanup rehearsal, and handoff

**Files:**
- Modify: `README.md`
- Modify: `docs/runbook.md`
- Modify: `docs/assessment.md`
- Create: `tests/test_repository_safety.py`

- [ ] **Step 1: Add repository safety tests**

Test that tracked text files contain no JWTs, authorization headers, OAuth callback query values, private-key blocks, email addresses, non-example UUID tenant IDs, or evidence rows with forbidden keys. Exclude `.git`, `.venv`, and the explicitly ignored raw-evidence directory.

- [ ] **Step 2: Run the full local verification suite**

Run: `.venv/bin/python -m pytest -m 'not integration' --cov=agentcore_identity_poc --cov-report=term-missing --cov-fail-under=90`

Run: `.venv/bin/ruff check . && .venv/bin/mypy src`

Expected: all tests pass, coverage is at least 90%, Ruff and mypy exit 0.

- [ ] **Step 3: Rehearse dry-run cleanup and verify tracked files**

Run: `.venv/bin/python scripts/provision_agentcore.py cleanup`

Expected: prints the exact tagged resources from `.poc-state.json` and performs no mutation without `--apply` and the matching confirmation value.

Run: `git status --short && git diff --check`

Expected: only intentional documentation/evidence changes appear; no whitespace errors or secret files are tracked.

- [ ] **Step 4: Complete the runbook and README**

Document the four execution stages, exact commands, expected exit codes, evidence locations, manual Google step, IAM restoration procedure, expiry resume flow, cloud cleanup, known limitations, and the rule that optional OneDrive evidence cannot substitute for the synthetic resource result.

- [ ] **Step 5: Run live gates in order and clean up**

Run Phase 1, Phase 2, then lifecycle integration tests. Generate `docs/assessment.md`, review its redaction test, revoke Google/Entra grants, run confirmed cleanup, and verify the tagged AgentCore resources and POC Secrets Manager entries are absent.

- [ ] **Step 6: Commit the verified handoff**

```bash
git add README.md docs/runbook.md docs/assessment.md tests/test_repository_safety.py
git commit -m "docs: finalize AgentCore Identity POC runbook"
```

## Design coverage

| Design requirement | Plan coverage |
| --- | --- |
| H1 workload plus validated Entra JWT | Tasks 4, 5, 7, and 8 |
| H2 Microsoft OBO without normal-use prompt | Tasks 6, 7, and the two-user Phase 1 gate in Task 8 |
| H3 Google vault and post-expiry refresh | Tasks 9, 10, 12, and 13 |
| H4a per-user vault isolation | Task 11 |
| H4b same-principal broad/scoped IAM evidence | Tasks 8 and 11 |
| H5 PingOne and AD FS custom-provider fit | Task 14 |
| H6 downstream authorization remains authoritative | Tasks 4, 6, 7, and 8 |
| H7 inbound-token and workload-token expiry | Task 13 |
| H8 revocation and per-user offboarding | Tasks 10 and 13 |
| Session binding, state, ten-minute expiry, no remote cache | Task 9 and the Phase 2 gate in Task 12 |
| Google two-stage provider creation | Tasks 8 and 12 |
| Secret custody, redaction, and JWT-only IAM guardrail | Tasks 3, 5, 8, 9, and 15 |
| Latency, caching, throttling, quotas, and CloudTrail | Task 13 |
| Direct implementation baseline and decision rule | Task 14 |
| Resource-ID cleanup and cost guardrail | Tasks 2, 8, 12, and 15 |

## Completion criteria

- The default local suite is deterministic and uses no live credentials.
- Phase 1 records H1, H2, and H6 before Google work starts.
- Phase 2 proves the application-owned `CompleteResourceTokenAuth` callback, Google refresh, H4a, and the broad/scoped H4b IAM matrix.
- Lifecycle evidence gives explicit H7 and H8 outcomes rather than assumptions.
- Operational evidence records latency, caching behavior, throttling, quota comparison, and CloudTrail attribution.
- The PingOne/AD FS matrix and direct baseline are complete enough to apply the decision rule.
- No OAuth client secret, refresh token, access token, authorization URL, cookie, filename, email address, or stable personal identifier is present in tracked files or sanitized evidence.
- Cleanup is resource-ID-based, confirmed, and demonstrated.
