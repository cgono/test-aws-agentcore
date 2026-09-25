# Runtime + LLM Gateway POC (Phase 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deploy a zip-packaged agent to AgentCore Runtime with Terraform. All inference goes through a simulated, JWT-protected central LLM gateway. Then answer Q2.1–Q2.6 and TF.3–TF.5 with live, recorded observations.

**Architecture:**
- A local FastAPI **gateway simulation** (`agentcore_runtime_poc.gateway_sim`), exposed through a `cloudflared` tunnel. It accepts only Entra **app-only** tokens that carry the `Gateway.Invoke` app role, and it forwards to fixed OpenAI/Anthropic URLs under strict limits.
- An **agent** (`agentcore_runtime_poc.runtime_agent`) built on `BedrockAgentCoreApp`. It gets a client-credentials token with MSAL (the client secret comes from Secrets Manager) and calls only the gateway.
- A packaging script builds a deterministic Linux-ARM64 zip.
- A reusable Terraform module (`agentcore_agent_runtime`) deploys the zip from a versioned S3 bucket. The POC root adds the bucket, the secret shell, and the runtime behind `deploy_runtime`.
- A local invoker and an opt-in live gate exercise the runtime.

**Tech Stack:** Python 3.13; `bedrock-agentcore==1.18.1`, `boto3==1.43.31`, `httpx==0.28.1`, `msal==1.37.0`, `fastapi==0.139.2`, `PyJWT[crypto]==2.13.0`; `uv` for ARM64 wheels; Terraform 1.14.x with `hashicorp/aws` `6.66.0`; `cloudflared`.

**Spec:** `docs/superpowers/specs/2026-09-25-code-interpreter-runtime-poc-design.md`
**Depends on:** `docs/superpowers/plans/2026-09-25-code-interpreter-poc.md` (Phase 1). It must be complete first: this plan extends its Terraform root, its `scripts/terraform_outputs.py`, its `observations` module, and its Phase 0 gate.

## Global Constraints

- **Tasks marked OPERATOR-RUN need a human at an interactive terminal:** Entra portal steps, `aws sso login`, `terraform apply`/`destroy`, the gateway and tunnel, and the live pytest gates. A subagent must stop at these tasks and hand over.
- **No ECR, no CodeBuild, no container images, no AgentCore CLI, no starter toolkit.** Runtime deploys only through Terraform `agent_runtime_artifact.code_configuration` (S3 zip).
- **No Bedrock model access.** The runtime execution role must not have `bedrock:InvokeModel*`. Inference goes only through the gateway.
- Terraform: root `required_version = "~> 1.14.0"`, provider `hashicorp/aws` `= 6.66.0`. Modules use `>= 1.9.0` and `>= 6.66.0`. Build IAM JSON with `jsonencode()`. Runtime names match `^[a-zA-Z][a-zA-Z0-9_]{0,47}$`.
- Secret values never go into Terraform state, argv, logs, observations, or tracked files. The gateway caller secret is written from the environment by `scripts/put_gateway_secret.py`. The OpenAI and Anthropic keys live only in `.env` and in the gateway process.
- The gateway returns no upstream headers and follows no redirects. It relays only an error *type* and status for upstream errors.
- The agent and gateway log only action, provider, status, caller client ID, and timings. They never log tokens, secrets, prompts, or completions.
- No new Python dependencies in `pyproject.toml`. The agent zip's own pins live in `src/agentcore_runtime_poc/runtime_agent/requirements.txt` and match `pyproject.toml`.
- Untyped imports follow repo style: `import boto3  # type: ignore[import-untyped]`, `import msal  # type: ignore[import-untyped]`.
- Tracked files must pass `tests/test_repository_safety.py`. In tests, build any credential-shaped fixture by string concatenation. Use `example-tenant`, `123456789012`, and `*.example.test`.
- The Phase 0 gate (Phase 1's, extended in Task 9) must pass before every commit. The coverage floor is 90% of the combined total.
- Run repo scripts as modules from the repo root: `.venv/bin/python -m scripts.<name>`. Plain `python scripts/<name>.py` cannot import `scripts.terraform_outputs`.
- Probe statuses: `pass`/`fail` only when the probe's own control steps succeeded; `blocked` when a control failed or a response lacked the fields being compared.
- Signed commits: use a plain `git commit`. If 1Password signing fails, stop and ask the user.

---

### Task 0: Operator prerequisites (OPERATOR-RUN, hard gate)

**Files:**
- Modify: `.env` (untracked)

- [ ] **Step 1: Register the gateway resource app (Entra portal)**

In the same tenant as the Identity POC, create an app registration named `agentcore-poc-llm-gateway`:
1. **Expose an API**: set the Application ID URI (the default `api://<app-id>` is fine).
2. **App roles**: create a role with display name `Gateway Invoke`, value `Gateway.Invoke`, and allowed member types **Applications**.
3. **Manifest**: set `api.requestedAccessTokenVersion` to `2`. The gateway accepts only the v2 issuer.
4. Optional, recommended: **Token configuration**, then **Add optional claim**, then **Access**, then `idtyp`.

- [ ] **Step 2: Register the caller app (Entra portal)**

Create `agentcore-poc-runtime-caller`:
1. **Certificates & secrets**: create a client secret and copy its value once.
2. **API permissions**: **Add**, then **My APIs**, then `agentcore-poc-llm-gateway`, then **Application permissions**, then `Gateway.Invoke`. Then **Grant admin consent**.

- [ ] **Step 3: Add the Phase 2 entries to `.env`**

```
GATEWAY_APP_CLIENT_ID=<gateway app (client) id>
GATEWAY_CALLER_CLIENT_ID=<caller app (client) id>
GATEWAY_ALLOWED_CALLER_IDS=<caller app (client) id>
GATEWAY_CALLER_CLIENT_SECRET=<caller secret value>
OPENAI_API_KEY=<dev key>
ANTHROPIC_API_KEY=<dev key>
GATEWAY_OPENAI_MODELS=<one small chat-completions model your key can use>
GATEWAY_ANTHROPIC_MODELS=claude-haiku-4-5-20251001
AGENT_OPENAI_MODEL=<same as GATEWAY_OPENAI_MODELS>
AGENT_ANTHROPIC_MODEL=claude-haiku-4-5-20251001
GATEWAY_MAX_OUTPUT_TOKENS=256
ENTRA_TENANT_ID=<tenant id, the same tenant as the Identity POC>
```

The main checkout's `.env` does not contain `ENTRA_TENANT_ID`, so add it here.

- [ ] **Step 4: Check the token shape before any AWS work**

```bash
set -a; source .env; set +a
.venv/bin/python - <<'EOF'
import os, jwt, msal
app = msal.ConfidentialClientApplication(
    os.environ["GATEWAY_CALLER_CLIENT_ID"],
    client_credential=os.environ["GATEWAY_CALLER_CLIENT_SECRET"],
    authority=f"https://login.microsoftonline.com/{os.environ['ENTRA_TENANT_ID']}",
)
result = app.acquire_token_for_client(scopes=[f"{os.environ['GATEWAY_APP_CLIENT_ID']}/.default"])
claims = jwt.decode(result["access_token"], options={"verify_signature": False})
print({"ver": claims.get("ver"), "roles": claims.get("roles"), "has_scp": "scp" in claims,
       "idtyp": claims.get("idtyp"), "aud_is_gateway": claims.get("aud") == os.environ["GATEWAY_APP_CLIENT_ID"]})
EOF
```

Expected: `{'ver': '2.0', 'roles': ['Gateway.Invoke'], 'has_scp': False, 'idtyp': 'app' (or None), 'aud_is_gateway': True}`.
**If `ver` is `1.0`, fix Step 1.3. If `roles` is missing, fix Step 2.2 (admin consent). Do not continue until this passes.** The script prints only claim names and values, never the token.

- [ ] **Step 5: Confirm `aws sso login` and the Phase 1 state**

Run: `aws sts get-caller-identity` and `terraform -chdir=infra/terraform/poc output`
Expected: the account prints, and the Phase 1 outputs exist (or Phase 1 was destroyed on purpose; `apply` recreates it).

---

### Task 1: Repo-safety check for LLM API keys

**Files:**
- Modify: `tests/test_repository_safety.py`

**Interfaces:**
- Produces: a new finding category `llm_api_key`, used by `_scan_string_values`.

- [ ] **Step 1: Add the failing parametrized case**

In `test_sensitive_values_are_reported`'s `@pytest.mark.parametrize` list, add:

```python
        ("llm_api_key", lambda: "OPENAI_API_KEY=" + "sk-" + "proj-" + "a1B2" * 8),
        ("llm_api_key", lambda: "key = '" + "sk-" + "ant-api03-" + "Z9y8" * 8 + "'"),
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `.venv/bin/python -m pytest tests/test_repository_safety.py -k sensitive_values_are_reported -v`
Expected: the two new cases FAIL (`[] != ['fixture.txt: llm_api_key']`).

- [ ] **Step 3: Implement**

Next to the other patterns near the top of the file, add:

```python
_LLM_API_KEY_PATTERN = re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{20,}")
```

In `_scan_string_values`, before `return findings`, add:

```python
    if _LLM_API_KEY_PATTERN.search(content):
        findings.append(f"{rendered_path}: llm_api_key")
```

- [ ] **Step 4: Run the whole safety suite**

Run: `.venv/bin/python -m pytest tests/test_repository_safety.py -q`
Expected: all pass. The repository scan still reports no findings.

- [ ] **Step 5: Commit**

```bash
git add tests/test_repository_safety.py
git commit -m "test: flag OpenAI/Anthropic-shaped API keys in tracked files"
```

---

### Task 2: Gateway settings and app-role authorization

**Files:**
- Create: `src/agentcore_runtime_poc/__init__.py`
- Create: `src/agentcore_runtime_poc/gateway_sim/__init__.py`
- Create: `src/agentcore_runtime_poc/gateway_sim/settings.py`
- Create: `src/agentcore_runtime_poc/gateway_sim/auth.py`
- Test: `tests/test_gateway_sim_settings.py`
- Test: `tests/test_gateway_sim_auth.py`

**Interfaces:**
- Consumes: `agentcore_identity_poc.jwt_validation.JwtPolicy`, `TokenRejected`, `audience_variants`, `make_http_jwks_loader` (existing).
- Produces:
  - `GatewaySettings` (frozen dataclass) with fields `tenant_id`, `gateway_app_client_id`, `allowed_caller_ids: frozenset[str]`, `openai_models: frozenset[str]`, `anthropic_models: frozenset[str]`, `openai_api_key`, `anthropic_api_key` (both `repr=False`), `required_role="Gateway.Invoke"`, `max_output_tokens=256`, `max_body_bytes=32768`, `max_concurrency=4`, and `upstream_timeout_seconds=30.0`. It has `from_env(env: Mapping[str, str])` and the properties `issuer` and `jwks_url`.
  - `GatewaySettingsError(ValueError)`.
  - `CallerRejected(Exception)`.
  - `Authorizer` (Protocol): `authorize(header: str | None) -> str`.
  - `AppRoleAuthorizer(policy, required_role, allowed_caller_ids)`: its `authorize` returns the caller's `azp`. It requires `ver == "2.0"`, rejects `scp` and non-`app` `idtyp`, and requires the role and an allowed `azp`.
  - `build_authorizer` accepts exactly the bare gateway app ID as audience (v2 tokens never carry `api://`). It does not use `audience_variants()`.
  - `build_authorizer(settings: GatewaySettings) -> AppRoleAuthorizer`.

- [ ] **Step 1: Write the failing settings tests**

`tests/test_gateway_sim_settings.py`:

```python
from __future__ import annotations

import pytest

from agentcore_runtime_poc.gateway_sim.settings import GatewaySettings, GatewaySettingsError

ENV = {
    "ENTRA_TENANT_ID": "example-tenant",
    "GATEWAY_APP_CLIENT_ID": "gateway-app-id",
    "GATEWAY_ALLOWED_CALLER_IDS": "caller-a, caller-b",
    "GATEWAY_OPENAI_MODELS": "model-o",
    "GATEWAY_ANTHROPIC_MODELS": "model-a1,model-a2",
    "OPENAI_API_KEY": "test-openai-key",
    "ANTHROPIC_API_KEY": "test-anthropic-key",
}


def test_from_env_parses_lists_and_defaults() -> None:
    settings = GatewaySettings.from_env(ENV)

    assert settings.allowed_caller_ids == frozenset({"caller-a", "caller-b"})
    assert settings.anthropic_models == frozenset({"model-a1", "model-a2"})
    assert settings.max_output_tokens == 256
    assert settings.issuer == "https://login.microsoftonline.com/example-tenant/v2.0"
    assert settings.jwks_url == (
        "https://login.microsoftonline.com/example-tenant/discovery/v2.0/keys"
    )


def test_repr_never_contains_provider_keys() -> None:
    rendered = repr(GatewaySettings.from_env(ENV))

    assert "test-openai-key" not in rendered
    assert "test-anthropic-key" not in rendered


@pytest.mark.parametrize("missing", sorted(ENV))
def test_every_setting_is_required(missing: str) -> None:
    env = {key: value for key, value in ENV.items() if key != missing}

    with pytest.raises(GatewaySettingsError, match=missing):
        GatewaySettings.from_env(env)


@pytest.mark.parametrize("value", ["0", "5000", "many"])
def test_max_output_tokens_is_bounded(value: str) -> None:
    with pytest.raises(GatewaySettingsError, match="GATEWAY_MAX_OUTPUT_TOKENS"):
        GatewaySettings.from_env({**ENV, "GATEWAY_MAX_OUTPUT_TOKENS": value})
```

- [ ] **Step 2: Write the failing authorization tests**

`tests/test_gateway_sim_auth.py`:

```python
from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from agentcore_identity_poc.jwt_validation import JwtPolicy
from agentcore_runtime_poc.gateway_sim.auth import AppRoleAuthorizer, CallerRejected

ISSUER = "https://login.microsoftonline.com/example-tenant/v2.0"
AUDIENCE = "gateway-app-id"


@pytest.fixture(scope="module")
def signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def authorizer(signing_key: rsa.RSAPrivateKey) -> AppRoleAuthorizer:
    public_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(signing_key.public_key(), as_dict=True)
    jwk = {**public_jwk, "kid": "k1", "use": "sig", "alg": "RS256"}
    policy = JwtPolicy(issuer=ISSUER, audience=AUDIENCE, jwks_loader=lambda: {"keys": [jwk]})
    return AppRoleAuthorizer(
        policy=policy, required_role="Gateway.Invoke", allowed_caller_ids=frozenset({"caller-a"})
    )


@pytest.fixture
def token(signing_key: rsa.RSAPrivateKey) -> Callable[..., str]:
    def make(drop: tuple[str, ...] = (), **overrides: Any) -> str:
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "service-principal-object-id",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "azp": "caller-a",
            "roles": ["Gateway.Invoke"],
            "idtyp": "app",
            "ver": "2.0",
        }
        claims.update(overrides)
        for name in drop:
            claims.pop(name)
        return jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "k1"})

    return make


def _header(value: str) -> str:
    return "Bearer " + value


def test_app_token_with_role_from_allowed_caller_is_accepted(
    authorizer: AppRoleAuthorizer, token: Callable[..., str]
) -> None:
    assert authorizer.authorize(_header(token())) == "caller-a"


def test_token_without_idtyp_is_accepted_when_otherwise_valid(
    authorizer: AppRoleAuthorizer, token: Callable[..., str]
) -> None:
    assert authorizer.authorize(_header(token(drop=("idtyp",)))) == "caller-a"


@pytest.mark.parametrize(
    ("description", "kwargs"),
    [
        ("missing roles", {"drop": ("roles",)}),
        ("wrong role", {"roles": ["Other.Role"]}),
        ("delegated token", {"scp": "access_as_user"}),
        ("user token type", {"idtyp": "user"}),
        ("caller not allowed", {"azp": "caller-z"}),
        ("missing azp", {"drop": ("azp",)}),
        ("v1 issuer", {"iss": "https://sts.windows.net/example-tenant/"}),
        ("wrong audience", {"aud": "other-app"}),
        ("expired", {"exp": datetime.now(UTC) - timedelta(minutes=5)}),
        ("v1 token version", {"ver": "1.0"}),
        ("missing version", {"drop": ("ver",)}),
        ("api uri audience", {"aud": "api://gateway-app-id"}),
    ],
)
def test_rejections(
    authorizer: AppRoleAuthorizer,
    token: Callable[..., str],
    description: str,
    kwargs: dict[str, Any],
) -> None:
    with pytest.raises(CallerRejected):
        authorizer.authorize(_header(token(**kwargs)))


@pytest.mark.parametrize("header", [None, "", "Basic abc", "Bearer "])
def test_missing_or_malformed_header_is_rejected(
    authorizer: AppRoleAuthorizer, header: str | None
) -> None:
    with pytest.raises(CallerRejected):
        authorizer.authorize(header)


def test_rejection_message_never_contains_the_token(
    authorizer: AppRoleAuthorizer, token: Callable[..., str]
) -> None:
    value = token(roles=[])
    with pytest.raises(CallerRejected) as caught:
        authorizer.authorize(_header(value))

    assert value not in str(caught.value)
```

- [ ] **Step 3: Run the tests and confirm they fail**

Run: `.venv/bin/python -m pytest tests/test_gateway_sim_settings.py tests/test_gateway_sim_auth.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'agentcore_runtime_poc'`.

- [ ] **Step 4: Implement**

`src/agentcore_runtime_poc/__init__.py`:

```python
"""Phase 2 POC: AgentCore Runtime with inference routed through a central LLM gateway."""
```

`src/agentcore_runtime_poc/gateway_sim/__init__.py`:

```python
"""Local stand-in for the employer's central LLM gateway. Never shipped in the agent zip."""
```

`src/agentcore_runtime_poc/gateway_sim/settings.py`:

```python
"""Gateway simulation settings, read from the environment."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field


class GatewaySettingsError(ValueError):
    """A required gateway setting is missing or invalid."""


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise GatewaySettingsError(f"{name} must be set")
    return value


def _names(env: Mapping[str, str], name: str) -> frozenset[str]:
    items = frozenset(part.strip() for part in _required(env, name).split(",") if part.strip())
    if not items:
        raise GatewaySettingsError(f"{name} must list at least one value")
    return items


def _max_output_tokens(env: Mapping[str, str]) -> int:
    raw = env.get("GATEWAY_MAX_OUTPUT_TOKENS", "256")
    try:
        value = int(raw)
    except ValueError as error:
        raise GatewaySettingsError("GATEWAY_MAX_OUTPUT_TOKENS must be an integer") from error
    if not 1 <= value <= 1024:
        raise GatewaySettingsError("GATEWAY_MAX_OUTPUT_TOKENS must be between 1 and 1024")
    return value


@dataclass(frozen=True)
class GatewaySettings:
    tenant_id: str
    gateway_app_client_id: str
    allowed_caller_ids: frozenset[str]
    openai_models: frozenset[str]
    anthropic_models: frozenset[str]
    openai_api_key: str = field(repr=False)
    anthropic_api_key: str = field(repr=False)
    required_role: str = "Gateway.Invoke"
    max_output_tokens: int = 256
    max_body_bytes: int = 32_768
    max_concurrency: int = 4
    upstream_timeout_seconds: float = 30.0

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> GatewaySettings:
        return cls(
            tenant_id=_required(env, "ENTRA_TENANT_ID"),
            gateway_app_client_id=_required(env, "GATEWAY_APP_CLIENT_ID"),
            allowed_caller_ids=_names(env, "GATEWAY_ALLOWED_CALLER_IDS"),
            openai_models=_names(env, "GATEWAY_OPENAI_MODELS"),
            anthropic_models=_names(env, "GATEWAY_ANTHROPIC_MODELS"),
            openai_api_key=_required(env, "OPENAI_API_KEY"),
            anthropic_api_key=_required(env, "ANTHROPIC_API_KEY"),
            max_output_tokens=_max_output_tokens(env),
        )

    @property
    def issuer(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"

    @property
    def jwks_url(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/discovery/v2.0/keys"
```

`src/agentcore_runtime_poc/gateway_sim/auth.py`:

```python
"""App-only (client-credentials) authorization for the gateway simulation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from agentcore_identity_poc.jwt_validation import (
    JwtPolicy,
    TokenRejected,
    make_http_jwks_loader,
)
from agentcore_runtime_poc.gateway_sim.settings import GatewaySettings


class CallerRejected(Exception):
    """The request is not from an authorized app-only caller. Messages never include tokens."""


class Authorizer(Protocol):
    def authorize(self, header: str | None) -> str: ...


@dataclass(frozen=True)
class AppRoleAuthorizer:
    policy: JwtPolicy
    required_role: str
    allowed_caller_ids: frozenset[str]

    def authorize(self, header: str | None) -> str:
        if not header or not header.startswith("Bearer "):
            raise CallerRejected("missing bearer token")
        token = header.removeprefix("Bearer ").strip()
        if not token:
            raise CallerRejected("missing bearer token")
        try:
            claims = self.policy.validate(token)
        except TokenRejected as error:
            raise CallerRejected("token rejected") from error
        if claims.get("ver") != "2.0":
            raise CallerRejected("not a v2.0 token")
        if "scp" in claims:
            raise CallerRejected("delegated token")
        if claims.get("idtyp", "app") != "app":
            raise CallerRejected("not an app-only token")
        roles = claims.get("roles")
        if not isinstance(roles, list) or self.required_role not in roles:
            raise CallerRejected("missing app role")
        caller = claims.get("azp")
        if not isinstance(caller, str) or caller not in self.allowed_caller_ids:
            raise CallerRejected("caller not allowed")
        return caller


def build_authorizer(settings: GatewaySettings) -> AppRoleAuthorizer:
    policy = JwtPolicy(
        issuer=settings.issuer,
        audience=settings.gateway_app_client_id,
        jwks_loader=make_http_jwks_loader(settings.jwks_url),
    )
    return AppRoleAuthorizer(
        policy=policy,
        required_role=settings.required_role,
        allowed_caller_ids=settings.allowed_caller_ids,
    )
```

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `.venv/bin/python -m pytest tests/test_gateway_sim_settings.py tests/test_gateway_sim_auth.py -v`
Expected: all pass.

- [ ] **Step 6: Lint, type-check, commit**

```bash
.venv/bin/ruff check src/agentcore_runtime_poc tests/test_gateway_sim_*.py
.venv/bin/mypy src
git add src/agentcore_runtime_poc tests/test_gateway_sim_settings.py tests/test_gateway_sim_auth.py
git commit -m "feat: add gateway simulation settings and app-role authorization"
```

---

### Task 3: Gateway proxy app with strict limits

**Files:**
- Create: `src/agentcore_runtime_poc/gateway_sim/app.py`
- Test: `tests/test_gateway_sim_app.py`

**Interfaces:**
- Consumes: `GatewaySettings`, `Authorizer`, `CallerRejected`, `build_authorizer` (Task 2).
- Produces:
  - `create_app(settings: GatewaySettings, *, authorizer: Authorizer | None = None, upstream: httpx.AsyncClient | None = None) -> FastAPI`
  - `create_production_app() -> FastAPI`, the uvicorn factory
  - Constants `OPENAI_URL`, `ANTHROPIC_URL`, `ANTHROPIC_VERSION`
  - Routes: `GET /healthz` (unauthenticated and returns no data; the spec's "every request" auth rule applies to the proxy routes), `POST /openai/v1/chat/completions`, `POST /anthropic/v1/messages`
  - Limits are applied in this order: auth, then the concurrency slot, then a bounded streaming body read (declared `content-length` checked first), then JSON and body rules. OpenAI's `n` must be absent or 1, so output tokens can't be multiplied.

- [ ] **Step 1: Write the failing tests**

`tests/test_gateway_sim_app.py`:

```python
from __future__ import annotations

import json
from collections.abc import Callable, Iterator

import httpx
import pytest
from fastapi.testclient import TestClient

from agentcore_runtime_poc.gateway_sim.app import (
    ANTHROPIC_URL,
    ANTHROPIC_VERSION,
    OPENAI_URL,
    create_app,
)
from agentcore_runtime_poc.gateway_sim.auth import CallerRejected
from agentcore_runtime_poc.gateway_sim.settings import GatewaySettings

OPENAI_KEY = "test-openai-key"
ANTHROPIC_KEY = "test-anthropic-key"
GOOD = {"Authorization": "Bearer good"}


class FakeAuthorizer:
    def authorize(self, header: str | None) -> str:
        if header != "Bearer good":
            raise CallerRejected("bad")
        return "caller-a"


def _settings(**overrides: object) -> GatewaySettings:
    values: dict[str, object] = {
        "tenant_id": "example-tenant",
        "gateway_app_client_id": "gateway-app-id",
        "allowed_caller_ids": frozenset({"caller-a"}),
        "openai_models": frozenset({"model-o"}),
        "anthropic_models": frozenset({"model-a"}),
        "openai_api_key": OPENAI_KEY,
        "anthropic_api_key": ANTHROPIC_KEY,
        "max_output_tokens": 64,
        "max_body_bytes": 2048,
    }
    values.update(overrides)
    return GatewaySettings(**values)  # type: ignore[arg-type]


Handler = Callable[[httpx.Request], httpx.Response]


def _client(handler: Handler, **overrides: object) -> tuple[TestClient, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    upstream = httpx.AsyncClient(transport=httpx.MockTransport(record))
    app = create_app(_settings(**overrides), authorizer=FakeAuthorizer(), upstream=upstream)
    return TestClient(app), seen


def _ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"id": "x", "ok": True}, headers={"x-upstream-detail": "hide"})


def test_healthz_needs_no_auth() -> None:
    client, _ = _client(_ok)

    assert client.get("/healthz").json() == {"status": "ok"}


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer bad"}])
def test_unauthorized_requests_never_reach_upstream(headers: dict[str, str]) -> None:
    client, seen = _client(_ok)

    response = client.post(
        "/openai/v1/chat/completions", json={"model": "model-o"}, headers=headers
    )

    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized"}
    assert seen == []


def test_openai_forward_uses_fixed_url_server_key_and_default_token_cap() -> None:
    client, seen = _client(_ok)

    response = client.post(
        "/openai/v1/chat/completions",
        json={"model": "model-o", "messages": [{"role": "user", "content": "hi"}]},
        headers=GOOD,
    )

    assert response.status_code == 200
    assert response.json() == {"id": "x", "ok": True}
    assert "x-upstream-detail" not in response.headers
    [request] = seen
    assert str(request.url) == OPENAI_URL
    assert request.headers["authorization"] == "Bearer " + OPENAI_KEY
    assert json.loads(request.content)["max_completion_tokens"] == 64


def test_anthropic_forward_uses_fixed_url_and_provider_headers() -> None:
    client, seen = _client(_ok)

    response = client.post(
        "/anthropic/v1/messages",
        json={"model": "model-a", "max_tokens": 32, "messages": []},
        headers=GOOD,
    )

    assert response.status_code == 200
    [request] = seen
    assert str(request.url) == ANTHROPIC_URL
    assert request.headers["x-api-key"] == ANTHROPIC_KEY
    assert request.headers["anthropic-version"] == ANTHROPIC_VERSION
    assert "authorization" not in request.headers
    assert json.loads(request.content)["max_tokens"] == 32


@pytest.mark.parametrize(
    ("path", "body", "error"),
    [
        ("/openai/v1/chat/completions", {"model": "model-x"}, "model_not_allowed"),
        (
            "/openai/v1/chat/completions",
            {"model": "model-o", "stream": True},
            "streaming_not_supported",
        ),
        (
            "/openai/v1/chat/completions",
            {"model": "model-o", "max_tokens": 10},
            "use_max_completion_tokens",
        ),
        (
            "/openai/v1/chat/completions",
            {"model": "model-o", "max_completion_tokens": 65},
            "max_tokens_out_of_range",
        ),
        (
            "/anthropic/v1/messages",
            {"model": "model-a", "max_tokens": 0},
            "max_tokens_out_of_range",
        ),
        (
            "/anthropic/v1/messages",
            {"model": "model-a", "max_tokens": True},
            "max_tokens_out_of_range",
        ),
        ("/anthropic/v1/messages", ["not", "an", "object"], "invalid_json"),
        ("/openai/v1/chat/completions", {"model": "model-o", "n": 3}, "n_must_be_1"),
    ],
)
def test_request_limits(path: str, body: object, error: str) -> None:
    client, seen = _client(_ok)

    response = client.post(path, json=body, headers=GOOD)

    assert response.status_code == 400
    assert response.json() == {"error": error}
    assert seen == []


def test_oversized_body_is_rejected() -> None:
    client, seen = _client(_ok)

    response = client.post(
        "/openai/v1/chat/completions",
        content=b"{" + b" " * 4096 + b"}",
        headers={**GOOD, "content-type": "application/json"},
    )

    assert response.status_code == 413
    assert seen == []


def test_upstream_error_relays_only_status_and_type() -> None:
    def leaky(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={"error": {"type": "authentication_error", "message": "bad key " + OPENAI_KEY}},
        )

    client, _ = _client(leaky)

    response = client.post("/openai/v1/chat/completions", json={"model": "model-o"}, headers=GOOD)

    assert response.status_code == 401
    assert response.json() == {"error": {"upstream_status": 401, "type": "authentication_error"}}
    assert OPENAI_KEY not in response.text


def test_upstream_redirect_is_not_followed() -> None:
    def redirect(request: httpx.Request) -> httpx.Response:
        return httpx.Response(307, headers={"location": "https://elsewhere.example.test/"})

    client, seen = _client(redirect)

    response = client.post("/openai/v1/chat/completions", json={"model": "model-o"}, headers=GOOD)

    assert response.status_code == 502
    assert response.json() == {"error": "upstream_redirect"}
    assert len(seen) == 1


def test_upstream_timeout_maps_to_504() -> None:
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    client, _ = _client(slow)

    response = client.post("/anthropic/v1/messages", json={"model": "model-a"}, headers=GOOD)

    assert response.status_code == 504
    assert response.json() == {"error": "upstream_timeout"}


def test_saturated_gateway_returns_429() -> None:
    client, seen = _client(_ok, max_concurrency=0)

    response = client.post("/openai/v1/chat/completions", json={"model": "model-o"}, headers=GOOD)

    assert response.status_code == 429
    assert seen == []


def test_oversized_body_without_content_length_is_rejected_while_streaming() -> None:
    client, seen = _client(_ok)

    def chunks() -> Iterator[bytes]:
        for _ in range(8):
            yield b" " * 512

    response = client.post("/openai/v1/chat/completions", content=chunks(), headers=GOOD)

    assert response.status_code == 413
    assert seen == []
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `.venv/bin/python -m pytest tests/test_gateway_sim_app.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'agentcore_runtime_poc.gateway_sim.app'`.

- [ ] **Step 3: Implement**

`src/agentcore_runtime_poc/gateway_sim/app.py`:

```python
"""Mock central LLM gateway: app-role JWT auth, fixed upstreams, strict limits."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Literal

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from agentcore_runtime_poc.gateway_sim.auth import Authorizer, CallerRejected, build_authorizer
from agentcore_runtime_poc.gateway_sim.settings import GatewaySettings

Provider = Literal["openai", "anthropic"]

OPENAI_URL = "https://api.openai.com/v1/chat/completions"
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
_TOKEN_FIELD: dict[Provider, str] = {"openai": "max_completion_tokens", "anthropic": "max_tokens"}

logger = logging.getLogger(__name__)


def _error(status: int, code: str) -> JSONResponse:
    return JSONResponse({"error": code}, status_code=status)


def _normalize_body(
    provider: Provider, body: dict[str, Any], settings: GatewaySettings
) -> str | None:
    if body.get("stream"):
        return "streaming_not_supported"
    allowed = settings.openai_models if provider == "openai" else settings.anthropic_models
    if body.get("model") not in allowed:
        return "model_not_allowed"
    if provider == "openai" and "max_tokens" in body:
        return "use_max_completion_tokens"
    if provider == "openai" and body.get("n", 1) != 1:
        return "n_must_be_1"
    field = _TOKEN_FIELD[provider]
    value = body.get(field)
    if value is None:
        body[field] = settings.max_output_tokens
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        return "max_tokens_out_of_range"
    if not 1 <= value <= settings.max_output_tokens:
        return "max_tokens_out_of_range"
    return None


def _upstream_request(provider: Provider, settings: GatewaySettings) -> tuple[str, dict[str, str]]:
    if provider == "openai":
        return OPENAI_URL, {
            "Authorization": f"Bearer {settings.openai_api_key}",
            "Content-Type": "application/json",
        }
    return ANTHROPIC_URL, {
        "x-api-key": settings.anthropic_api_key,
        "anthropic-version": ANTHROPIC_VERSION,
        "Content-Type": "application/json",
    }


async def _forward(
    client: httpx.AsyncClient, provider: Provider, body: dict[str, Any], settings: GatewaySettings
) -> tuple[int, dict[str, Any]]:
    url, headers = _upstream_request(provider, settings)
    try:
        response = await client.post(
            url,
            json=body,
            headers=headers,
            timeout=settings.upstream_timeout_seconds,
            follow_redirects=False,
        )
    except httpx.TimeoutException:
        return 504, {"error": "upstream_timeout"}
    except httpx.HTTPError:
        return 502, {"error": "upstream_unreachable"}
    if 300 <= response.status_code < 400:
        return 502, {"error": "upstream_redirect"}
    try:
        data: Any = response.json()
    except ValueError:
        data = None
    if response.status_code >= 400:
        error = data.get("error") if isinstance(data, dict) else None
        kind = error.get("type") if isinstance(error, dict) else None
        return response.status_code, {
            "error": {
                "upstream_status": response.status_code,
                "type": kind if isinstance(kind, str) else "unknown",
            }
        }
    if not isinstance(data, dict):
        return 502, {"error": "upstream_invalid_json"}
    return 200, data


async def _read_limited(request: Request, limit: int) -> bytes | None:
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        return None
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def create_app(
    settings: GatewaySettings,
    *,
    authorizer: Authorizer | None = None,
    upstream: httpx.AsyncClient | None = None,
) -> FastAPI:
    auth = authorizer if authorizer is not None else build_authorizer(settings)
    client = upstream if upstream is not None else httpx.AsyncClient(follow_redirects=False)
    semaphore = asyncio.Semaphore(settings.max_concurrency)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        if upstream is None:
            await client.aclose()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    async def proxy(request: Request, provider: Provider) -> JSONResponse:
        try:
            caller = auth.authorize(request.headers.get("authorization"))
        except CallerRejected as rejection:
            logger.info("gateway reject provider=%s reason=%s", provider, rejection)
            return _error(401, "unauthorized")
        if semaphore.locked():
            return _error(429, "too_many_requests")
        async with semaphore:
            raw = await _read_limited(request, settings.max_body_bytes)
            if raw is None:
                return _error(413, "body_too_large")
            try:
                body = json.loads(raw)
            except ValueError:
                return _error(400, "invalid_json")
            if not isinstance(body, dict):
                return _error(400, "invalid_json")
            problem = _normalize_body(provider, body, settings)
            if problem is not None:
                return _error(400, problem)
            started = time.perf_counter()
            status, payload = await _forward(client, provider, body, settings)
        logger.info(
            "gateway forward provider=%s caller=%s status=%s ms=%.0f",
            provider,
            caller,
            status,
            (time.perf_counter() - started) * 1000,
        )
        return JSONResponse(payload, status_code=status)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/openai/v1/chat/completions")
    async def openai_route(request: Request) -> JSONResponse:
        return await proxy(request, "openai")

    @app.post("/anthropic/v1/messages")
    async def anthropic_route(request: Request) -> JSONResponse:
        return await proxy(request, "anthropic")

    return app


def create_production_app() -> FastAPI:
    return create_app(GatewaySettings.from_env(os.environ))
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `.venv/bin/python -m pytest tests/test_gateway_sim_app.py -v`
Expected: all pass.

- [ ] **Step 5: Lint, type-check, commit**

```bash
.venv/bin/ruff check src/agentcore_runtime_poc tests/test_gateway_sim_app.py
.venv/bin/mypy src
git add src/agentcore_runtime_poc/gateway_sim/app.py tests/test_gateway_sim_app.py
git commit -m "feat: add gateway simulation proxy with fixed upstreams and strict limits"
```

---

### Task 4: Runtime agent (config, secret, token source, handler, entry point)

**Files:**
- Create: `src/agentcore_runtime_poc/runtime_agent/__init__.py`
- Create: `src/agentcore_runtime_poc/runtime_agent/config.py`
- Create: `src/agentcore_runtime_poc/runtime_agent/secret_store.py`
- Create: `src/agentcore_runtime_poc/runtime_agent/agent.py`
- Create: `src/agentcore_runtime_poc/runtime_agent/entrypoint.py`
- Create: `src/agentcore_runtime_poc/runtime_agent/requirements.txt`
- Test: `tests/test_runtime_agent.py`

**Interfaces:**
- Produces:
  - `AgentConfig` (frozen), read by `from_env(env)` from these variables:
    - `POC_REGION`
    - `ENTRA_TENANT_ID`
    - `GATEWAY_CALLER_CLIENT_ID`
    - `GATEWAY_CLIENT_SECRET_ARN`
    - `GATEWAY_BASE_URL` (https, trailing `/` stripped)
    - `GATEWAY_SCOPE` (must end in `/.default`)
    - `AGENT_OPENAI_MODEL`
    - `AGENT_ANTHROPIC_MODEL`

    It has an `authority` property. Invalid input raises `AgentConfigError(ValueError)`.
  - `load_client_secret(region, secret_arn, client_factory=boto3.client) -> str`, which raises `SecretUnavailable`.
  - `TokenSource` (Protocol) `acquire() -> tuple[str, bool]` (token, from_cache); `MsalTokenSource(config, load_secret, app_factory=msal.ConfidentialClientApplication)`; `TokenUnavailable(RuntimeError)`.
  - `Agent(config, tokens, http: httpx.Client, clock=time.perf_counter)`, whose `handle(payload, session_id) -> dict[str, Any]` supports these actions:
    - `whoami`
    - `set_marker`
    - `get_marker`
    - `probe_egress`
    - `chat`
    - `chat_unauthenticated`
    - `sleep` (`seconds` 1–120; used in Task 10 to hold an invocation open during a deploy)
  - `BOOT_ID: str`.
  - The response keys that Task 9 relies on:
    - `action`, `boot_id`, `session_id`, `uptime_s`
    - `marker`
    - `healthz_status`
    - `provider`, `gateway_status`, `token_cached`
    - `timings_ms.token`, `timings_ms.gateway`
    - `text`
    - `error`
  - `entrypoint.app` (`BedrockAgentCoreApp`), `entrypoint.get_agent()` (cached), `entrypoint.invoke(payload, context)`, `entrypoint.configure_logging()`, and `entrypoint.main()` (calls `configure_logging()` then `app.run()`).
  - Every handled request logs one line: `agent action=<action> session=<session_id> outcome=<status or error>`. The Q2.5 live check keys on this line.

- [ ] **Step 1: Write the failing tests**

`tests/test_runtime_agent.py`:

```python
from __future__ import annotations

import logging
from typing import Any

import httpx
import pytest
from bedrock_agentcore.runtime.context import RequestContext

from agentcore_runtime_poc.runtime_agent import entrypoint
from agentcore_runtime_poc.runtime_agent.agent import (
    BOOT_ID,
    Agent,
    MsalTokenSource,
    TokenUnavailable,
)
from agentcore_runtime_poc.runtime_agent.config import AgentConfig, AgentConfigError
from agentcore_runtime_poc.runtime_agent.secret_store import SecretUnavailable, load_client_secret

ENV = {
    "POC_REGION": "ap-southeast-1",
    "ENTRA_TENANT_ID": "example-tenant",
    "GATEWAY_CALLER_CLIENT_ID": "caller-a",
    "GATEWAY_CLIENT_SECRET_ARN": (
        "arn:aws:secretsmanager:ap-southeast-1:123456789012:secret:example"
    ),
    "GATEWAY_BASE_URL": "https://gateway.example.test/",
    "GATEWAY_SCOPE": "gateway-app-id/.default",
    "AGENT_OPENAI_MODEL": "model-o",
    "AGENT_ANTHROPIC_MODEL": "model-a",
}
TOKEN_VALUE = "fake-token-" + "value-123"


class FakeTokens:
    def __init__(self, cached: bool = False, fail: bool = False) -> None:
        self.cached = cached
        self.fail = fail
        self.calls = 0

    def acquire(self) -> tuple[str, bool]:
        self.calls += 1
        if self.fail:
            raise TokenUnavailable("invalid_client")
        return TOKEN_VALUE, self.cached


def _agent(handler: Any, tokens: FakeTokens | None = None) -> tuple[Agent, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    ticks = iter([0.0, 0.010, 0.250] * 10)
    agent = Agent(
        AgentConfig.from_env(ENV),
        tokens or FakeTokens(),
        httpx.Client(transport=httpx.MockTransport(record)),
        clock=lambda: next(ticks),
    )
    return agent, seen


def _openai_reply(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": "pong"}}]})


def test_config_strips_trailing_slash_and_builds_authority() -> None:
    config = AgentConfig.from_env(ENV)

    assert config.gateway_base_url == "https://gateway.example.test"
    assert config.authority == "https://login.microsoftonline.com/example-tenant"


@pytest.mark.parametrize(
    ("name", "value"),
    [("GATEWAY_BASE_URL", "http://gateway.example.test"), ("GATEWAY_SCOPE", "gateway-app-id")],
)
def test_config_rejects_insecure_url_and_non_default_scope(name: str, value: str) -> None:
    with pytest.raises(AgentConfigError, match=name):
        AgentConfig.from_env({**ENV, name: value})


def test_config_requires_every_variable() -> None:
    with pytest.raises(AgentConfigError, match="AGENT_ANTHROPIC_MODEL"):
        AgentConfig.from_env({k: v for k, v in ENV.items() if k != "AGENT_ANTHROPIC_MODEL"})


def test_openai_chat_goes_to_gateway_with_bearer_and_reports_timings() -> None:
    agent, seen = _agent(_openai_reply)

    result = agent.handle({"action": "chat", "provider": "openai", "prompt": "ping"}, "s-1")

    [request] = seen
    assert str(request.url) == "https://gateway.example.test/openai/v1/chat/completions"
    assert request.headers["authorization"] == "Bearer " + TOKEN_VALUE
    assert result["gateway_status"] == 200
    assert result["text"] == "pong"
    assert result["timings_ms"] == {"token": 10.0, "gateway": 240.0}
    assert result["boot_id"] == BOOT_ID
    assert result["session_id"] == "s-1"


def test_anthropic_chat_uses_messages_route_and_extracts_text() -> None:
    def reply(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"content": [{"type": "text", "text": "pong"}]})

    agent, seen = _agent(reply)

    result = agent.handle({"action": "chat", "provider": "anthropic", "prompt": "ping"}, "s-1")

    assert str(seen[0].url) == "https://gateway.example.test/anthropic/v1/messages"
    assert result["text"] == "pong"


def test_unauthenticated_chat_sends_no_authorization_header() -> None:
    tokens = FakeTokens()
    agent, seen = _agent(
        lambda request: httpx.Response(401, json={"error": "unauthorized"}), tokens
    )

    result = agent.handle(
        {"action": "chat_unauthenticated", "provider": "openai", "prompt": "ping"}, "s-1"
    )

    assert "authorization" not in seen[0].headers
    assert result["gateway_status"] == 401
    assert "text" not in result
    assert tokens.calls == 0


def test_token_failure_is_reported_without_calling_gateway() -> None:
    agent, seen = _agent(_openai_reply, FakeTokens(fail=True))

    result = agent.handle({"action": "chat", "provider": "openai", "prompt": "ping"}, "s-1")

    assert result["error"] == "token_unavailable:invalid_client"
    assert seen == []


def test_bad_chat_request_and_unknown_action() -> None:
    agent, _ = _agent(_openai_reply)

    assert agent.handle({"action": "chat", "provider": "bedrock", "prompt": "x"}, None)[
        "error"
    ] == ("bad_request")
    assert agent.handle({"action": "dance"}, None)["error"] == "unknown_action"


def test_marker_is_kept_in_process_memory() -> None:
    agent, _ = _agent(_openai_reply)

    assert agent.handle({"action": "get_marker"}, "s-1")["marker"] is None
    agent.handle({"action": "set_marker", "marker": "m-1"}, "s-1")
    assert agent.handle({"action": "get_marker"}, "s-1")["marker"] == "m-1"


def test_probe_egress_reports_healthz_status_and_failures() -> None:
    agent, seen = _agent(lambda request: httpx.Response(200, json={"status": "ok"}))
    assert agent.handle({"action": "probe_egress"}, None)["healthz_status"] == 200
    assert str(seen[0].url) == "https://gateway.example.test/healthz"

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    failing, _ = _agent(refuse)
    assert failing.handle({"action": "probe_egress"}, None)["error"] == "egress_failed:ConnectError"


def test_logs_never_contain_token_or_prompt(caplog: pytest.LogCaptureFixture) -> None:
    agent, _ = _agent(_openai_reply)
    prompt = "prompt-marker-" + "xyz"

    with caplog.at_level(logging.DEBUG):
        agent.handle({"action": "chat", "provider": "openai", "prompt": prompt}, "s-1")

    assert "action=chat session=s-1" in caplog.text
    assert TOKEN_VALUE not in caplog.text
    assert prompt not in caplog.text


class FakeMsalApp:
    def __init__(self, results: list[dict[str, Any]]) -> None:
        self.results = results
        self.scopes: list[list[str]] = []

    def acquire_token_for_client(self, scopes: list[str]) -> dict[str, Any]:
        self.scopes.append(scopes)
        return self.results.pop(0)


def test_msal_token_source_loads_secret_once_and_reports_cache_hits() -> None:
    loads: list[int] = []
    created: dict[str, Any] = {}
    fake_app = FakeMsalApp(
        [
            {"access_token": "t1", "token_source": "identity_provider"},
            {"access_token": "t1", "token_source": "cache"},
        ]
    )

    def factory(**kwargs: Any) -> FakeMsalApp:
        created.update(kwargs)
        return fake_app

    source = MsalTokenSource(
        AgentConfig.from_env(ENV), lambda: loads.append(1) or "secret-value", app_factory=factory
    )

    assert source.acquire() == ("t1", False)
    assert source.acquire() == ("t1", True)
    assert loads == [1]
    assert created["client_id"] == "caller-a"
    assert created["authority"] == "https://login.microsoftonline.com/example-tenant"
    assert fake_app.scopes == [["gateway-app-id/.default"], ["gateway-app-id/.default"]]


def test_msal_token_source_maps_errors() -> None:
    source = MsalTokenSource(
        AgentConfig.from_env(ENV),
        lambda: "secret-value",
        app_factory=lambda **kwargs: FakeMsalApp([{"error": "invalid_client"}]),
    )
    with pytest.raises(TokenUnavailable, match="invalid_client"):
        source.acquire()

    def broken_secret() -> str:
        raise SecretUnavailable("client_secret_missing")

    no_secret = MsalTokenSource(AgentConfig.from_env(ENV), broken_secret)
    with pytest.raises(TokenUnavailable, match="SecretUnavailable"):
        no_secret.acquire()


class FakeSecrets:
    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        self.kwargs: dict[str, Any] = {}

    def get_secret_value(self, **kwargs: Any) -> dict[str, Any]:
        self.kwargs = kwargs
        return self.response


def test_load_client_secret_reads_secret_string() -> None:
    fake = FakeSecrets({"SecretString": "secret-value"})

    value = load_client_secret(
        "ap-southeast-1", "arn:example", client_factory=lambda name, region_name: fake
    )

    assert value == "secret-value"
    assert fake.kwargs == {"SecretId": "arn:example"}


def test_load_client_secret_without_value_raises() -> None:
    fake = FakeSecrets({})

    with pytest.raises(SecretUnavailable):
        load_client_secret(
            "ap-southeast-1", "arn:example", client_factory=lambda n, region_name: fake
        )


def test_entrypoint_delegates_with_session_id(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[dict[str, Any], str | None]] = []

    class Recorder:
        def handle(self, payload: dict[str, Any], session_id: str | None) -> dict[str, Any]:
            calls.append((payload, session_id))
            return {"ok": True}

    monkeypatch.setattr(entrypoint, "get_agent", lambda: Recorder())

    result = entrypoint.invoke({"action": "whoami"}, RequestContext(session_id="s-9"))

    assert result == {"ok": True}
    assert calls == [({"action": "whoami"}, "s-9")]


def test_get_agent_builds_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in ENV.items():
        monkeypatch.setenv(name, value)
    entrypoint.get_agent.cache_clear()

    agent = entrypoint.get_agent()

    assert isinstance(agent, Agent)
    assert entrypoint.get_agent() is agent
    entrypoint.get_agent.cache_clear()


def test_sleep_action_is_bounded() -> None:
    slept: list[float] = []
    agent = Agent(
        AgentConfig.from_env(ENV),
        FakeTokens(),
        httpx.Client(transport=httpx.MockTransport(_openai_reply)),
        sleeper=slept.append,
    )

    assert agent.handle({"action": "sleep", "seconds": 5}, "s-1")["slept_s"] == 5
    assert agent.handle({"action": "sleep", "seconds": 500}, "s-1")["error"] == "bad_request"
    assert slept == [5]


def test_configure_logging_enables_agent_info_logs_once() -> None:
    logger = logging.getLogger("agentcore_runtime_poc")
    logger.handlers.clear()

    entrypoint.configure_logging()
    entrypoint.configure_logging()

    assert logger.level == logging.INFO
    assert len(logger.handlers) == 1
    logger.handlers.clear()
    logger.setLevel(logging.NOTSET)
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `.venv/bin/python -m pytest tests/test_runtime_agent.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'agentcore_runtime_poc.runtime_agent'`.

- [ ] **Step 3: Implement**

`src/agentcore_runtime_poc/runtime_agent/__init__.py`:

```python
"""Agent code shipped in the Runtime zip. Imports nothing from gateway_sim."""
```

`src/agentcore_runtime_poc/runtime_agent/requirements.txt`:

```
bedrock-agentcore==1.18.1
boto3==1.43.31
httpx==0.28.1
msal==1.37.0
```

`src/agentcore_runtime_poc/runtime_agent/config.py`:

```python
"""Agent configuration from Runtime environment variables (set by Terraform)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


class AgentConfigError(ValueError):
    """A required agent environment variable is missing or invalid."""


_ENV = {
    "region": "POC_REGION",
    "tenant_id": "ENTRA_TENANT_ID",
    "caller_client_id": "GATEWAY_CALLER_CLIENT_ID",
    "client_secret_arn": "GATEWAY_CLIENT_SECRET_ARN",
    "gateway_base_url": "GATEWAY_BASE_URL",
    "gateway_scope": "GATEWAY_SCOPE",
    "openai_model": "AGENT_OPENAI_MODEL",
    "anthropic_model": "AGENT_ANTHROPIC_MODEL",
}


@dataclass(frozen=True)
class AgentConfig:
    region: str
    tenant_id: str
    caller_client_id: str
    client_secret_arn: str
    gateway_base_url: str
    gateway_scope: str
    openai_model: str
    anthropic_model: str

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> AgentConfig:
        values: dict[str, str] = {}
        for field_name, env_name in _ENV.items():
            value = env.get(env_name, "").strip()
            if not value:
                raise AgentConfigError(f"{env_name} must be set")
            values[field_name] = value
        if not values["gateway_base_url"].startswith("https://"):
            raise AgentConfigError("GATEWAY_BASE_URL must use https")
        if not values["gateway_scope"].endswith("/.default"):
            raise AgentConfigError("GATEWAY_SCOPE must end with /.default")
        values["gateway_base_url"] = values["gateway_base_url"].rstrip("/")
        return cls(**values)

    @property
    def authority(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}"
```

`src/agentcore_runtime_poc/runtime_agent/secret_store.py`:

```python
"""Read the gateway caller secret from Secrets Manager at first use."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import boto3  # type: ignore[import-untyped]


class SecretUnavailable(RuntimeError):
    """The secret has no string value (Terraform creates it empty; the operator fills it)."""


def load_client_secret(
    region: str, secret_arn: str, client_factory: Callable[..., Any] = boto3.client
) -> str:
    client = client_factory("secretsmanager", region_name=region)
    value = client.get_secret_value(SecretId=secret_arn).get("SecretString")
    if not isinstance(value, str) or not value:
        raise SecretUnavailable("client_secret_missing")
    return value
```

`src/agentcore_runtime_poc/runtime_agent/agent.py`:

```python
"""Agent logic: every inference call goes through the gateway with an app-only JWT."""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Callable, Mapping
from typing import Any, Protocol

import httpx
import msal  # type: ignore[import-untyped]

from agentcore_runtime_poc.runtime_agent.config import AgentConfig

BOOT_ID = uuid.uuid4().hex
_BOOTED_AT = time.monotonic()
_MAX_OUTPUT_TOKENS = 64

logger = logging.getLogger(__name__)


class TokenUnavailable(RuntimeError):
    """No gateway token could be obtained. The message is an error code, never a secret."""


class TokenSource(Protocol):
    def acquire(self) -> tuple[str, bool]: ...


class MsalTokenSource:
    def __init__(
        self,
        config: AgentConfig,
        load_secret: Callable[[], str],
        app_factory: Callable[..., Any] = msal.ConfidentialClientApplication,
    ) -> None:
        self._config = config
        self._load_secret = load_secret
        self._app_factory = app_factory
        self._app: Any = None

    def acquire(self) -> tuple[str, bool]:
        if self._app is None:
            try:
                secret = self._load_secret()
            except Exception as error:
                raise TokenUnavailable(type(error).__name__) from error
            self._app = self._app_factory(
                client_id=self._config.caller_client_id,
                client_credential=secret,
                authority=self._config.authority,
            )
        result = self._app.acquire_token_for_client(scopes=[self._config.gateway_scope])
        token = result.get("access_token")
        if not isinstance(token, str):
            raise TokenUnavailable(str(result.get("error", "unknown")))
        return token, result.get("token_source") == "cache"


def _extract_text(provider: str, data: Any) -> str:
    try:
        if provider == "openai":
            return str(data["choices"][0]["message"]["content"])
        return "".join(
            str(block.get("text", "")) for block in data["content"] if block.get("type") == "text"
        )
    except (KeyError, IndexError, TypeError, AttributeError):
        return ""


class Agent:
    def __init__(
        self,
        config: AgentConfig,
        tokens: TokenSource,
        http: httpx.Client,
        clock: Callable[[], float] = time.perf_counter,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self._config = config
        self._tokens = tokens
        self._http = http
        self._clock = clock
        self._sleeper = sleeper
        self._marker: str | None = None

    def handle(self, payload: Mapping[str, Any], session_id: str | None) -> dict[str, Any]:
        action = payload.get("action")
        result: dict[str, Any]
        if action == "whoami":
            result = {}
        elif action == "set_marker":
            self._marker = str(payload.get("marker", ""))
            result = {"marker": self._marker}
        elif action == "get_marker":
            result = {"marker": self._marker}
        elif action == "probe_egress":
            result = self._probe_egress()
        elif action == "chat":
            result = self._chat(payload, authenticated=True)
        elif action == "chat_unauthenticated":
            result = self._chat(payload, authenticated=False)
        elif action == "sleep":
            result = self._sleep(payload)
        else:
            result = {"error": "unknown_action"}
        logger.info(
            "agent action=%s session=%s outcome=%s",
            action,
            session_id,
            result.get("gateway_status", result.get("error", "ok")),
        )
        return {
            "action": action,
            "boot_id": BOOT_ID,
            "session_id": session_id,
            "uptime_s": round(time.monotonic() - _BOOTED_AT, 3),
            **result,
        }

    def _sleep(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        seconds = payload.get("seconds")
        if isinstance(seconds, bool) or not isinstance(seconds, int) or not 1 <= seconds <= 120:
            return {"error": "bad_request"}
        self._sleeper(seconds)
        return {"slept_s": seconds}

    def _probe_egress(self) -> dict[str, Any]:
        try:
            response = self._http.get(f"{self._config.gateway_base_url}/healthz")
        except httpx.HTTPError as error:
            return {"error": f"egress_failed:{type(error).__name__}"}
        return {"healthz_status": response.status_code}

    def _request(self, provider: str, prompt: str) -> tuple[str, dict[str, Any]]:
        messages = [{"role": "user", "content": prompt}]
        base = self._config.gateway_base_url
        if provider == "openai":
            return f"{base}/openai/v1/chat/completions", {
                "model": self._config.openai_model,
                "messages": messages,
                "max_completion_tokens": _MAX_OUTPUT_TOKENS,
            }
        return f"{base}/anthropic/v1/messages", {
            "model": self._config.anthropic_model,
            "max_tokens": _MAX_OUTPUT_TOKENS,
            "messages": messages,
        }

    def _chat(self, payload: Mapping[str, Any], *, authenticated: bool) -> dict[str, Any]:
        provider = payload.get("provider")
        prompt = payload.get("prompt")
        if provider not in ("openai", "anthropic") or not isinstance(prompt, str) or not prompt:
            return {"error": "bad_request"}
        started = self._clock()
        headers: dict[str, str] = {}
        cached = False
        if authenticated:
            try:
                token, cached = self._tokens.acquire()
            except TokenUnavailable as error:
                return {"error": f"token_unavailable:{error}"}
            headers["Authorization"] = f"Bearer {token}"
        token_done = self._clock()
        url, body = self._request(provider, prompt)
        try:
            response = self._http.post(url, json=body, headers=headers)
        except httpx.HTTPError as error:
            return {"error": f"gateway_unreachable:{type(error).__name__}"}
        finished = self._clock()
        result: dict[str, Any] = {
            "provider": provider,
            "gateway_status": response.status_code,
            "token_cached": cached,
            "timings_ms": {
                "token": round((token_done - started) * 1000, 1),
                "gateway": round((finished - token_done) * 1000, 1),
            },
        }
        if response.status_code == 200:
            result["text"] = _extract_text(provider, response.json())
        return result
```

`src/agentcore_runtime_poc/runtime_agent/entrypoint.py`:

```python
"""AgentCore Runtime entry point (HTTP protocol) for the direct-code zip deployment."""

from __future__ import annotations

import functools
import logging
import os
from typing import Any

import httpx
from bedrock_agentcore.runtime import BedrockAgentCoreApp
from bedrock_agentcore.runtime.context import RequestContext

from agentcore_runtime_poc.runtime_agent.agent import Agent, MsalTokenSource
from agentcore_runtime_poc.runtime_agent.config import AgentConfig
from agentcore_runtime_poc.runtime_agent.secret_store import load_client_secret

app = BedrockAgentCoreApp()


@functools.cache
def get_agent() -> Agent:
    config = AgentConfig.from_env(os.environ)
    tokens = MsalTokenSource(
        config, functools.partial(load_client_secret, config.region, config.client_secret_arn)
    )
    return Agent(config, tokens, httpx.Client(timeout=30.0))


def invoke(payload: dict[str, Any], context: RequestContext) -> dict[str, Any]:
    return get_agent().handle(payload, context.session_id)


# Registered without decorator syntax: the SDK's decorator is untyped, which mypy --strict rejects.
app.entrypoint(invoke)


def configure_logging() -> None:
    # The SDK configures only its own logger; without this, agent INFO lines never reach CloudWatch.
    logger = logging.getLogger("agentcore_runtime_poc")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def main() -> None:
    configure_logging()
    app.run()
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `.venv/bin/python -m pytest tests/test_runtime_agent.py -v`
Expected: all pass.

- [ ] **Step 5: Lint, type-check, commit**

```bash
.venv/bin/ruff check src/agentcore_runtime_poc tests/test_runtime_agent.py
.venv/bin/mypy src
git add src/agentcore_runtime_poc/runtime_agent tests/test_runtime_agent.py
git commit -m "feat: add Runtime agent that routes all inference through the gateway"
```

---

### Task 5: Deterministic agent zip builder

**Files:**
- Create: `src/agentcore_runtime_poc/packaging.py`
- Create: `scripts/build_agent_zip.py`
- Test: `tests/test_agent_packaging.py`

**Interfaces:**
- Consumes: the agent sources (Task 4) and `runtime_agent/requirements.txt`.
- Produces:
  - `build_agent_zip(output: Path, *, source_root: Path, index_url: str, installer: Installer, workdir: Path) -> Path`
  - `verify_agent_zip(path: Path, *, max_bytes: int = MAX_ZIP_BYTES) -> None`
  - `uv_installer(requirements: Path = AGENT_REQUIREMENTS, run=subprocess.run) -> Installer`. It passes the index URL to `uv` in the `UV_DEFAULT_INDEX` environment variable, never in argv, because at work the URL can carry Artifactory credentials.
  - `agent_source_files(source_root: Path) -> list[Path]`
  - `PackagingError`
  - `Installer = Callable[[Path, str], None]`
  - Script default output: `build/agent/agent.zip`, which is already gitignored through `build/`.

- [ ] **Step 1: Write the failing tests**

`tests/test_agent_packaging.py`:

```python
from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path
from typing import Any

import pytest

from agentcore_runtime_poc import packaging


def _source_tree(root: Path) -> Path:
    package = root / "src" / "agentcore_runtime_poc"
    (package / "runtime_agent").mkdir(parents=True)
    (package / "gateway_sim").mkdir()
    (package / "__init__.py").write_text('"""pkg"""\n')
    (package / "runtime_agent" / "__init__.py").write_text("")
    (package / "runtime_agent" / "entrypoint.py").write_text("def main() -> None: ...\n")
    (package / "runtime_agent" / "requirements.txt").write_text("httpx==0.28.1\n")
    (package / "gateway_sim" / "app.py").write_text("SECRET_ROUTE = 1\n")
    (root / "src" / ".env").write_text("OPENAI_API_KEY=never\n")
    return root / "src"


def _fake_installer(target: Path, index_url: str) -> None:
    (target / "httpx").mkdir(parents=True)
    (target / "httpx" / "__init__.py").write_text("VERSION = 1\n")
    (target / "httpx" / "__pycache__").mkdir()
    (target / "httpx" / "__pycache__" / "x.cpython-313.pyc").write_bytes(b"\x00")
    tool = target / "bin" / "tool"
    tool.parent.mkdir()
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)


def _build(tmp_path: Path) -> Path:
    return packaging.build_agent_zip(
        tmp_path / "out" / "agent.zip",
        source_root=_source_tree(tmp_path),
        index_url="https://pypi.org/simple",
        installer=_fake_installer,
        workdir=tmp_path / "work",
    )


def test_zip_has_deps_agent_sources_and_main_at_root(tmp_path: Path) -> None:
    with zipfile.ZipFile(_build(tmp_path)) as archive:
        names = set(archive.namelist())
        main = archive.read("main.py").decode()

    assert {
        "main.py",
        "httpx/__init__.py",
        "bin/tool",
        "agentcore_runtime_poc/__init__.py",
        "agentcore_runtime_poc/runtime_agent/__init__.py",
        "agentcore_runtime_poc/runtime_agent/entrypoint.py",
    } <= names
    assert "from agentcore_runtime_poc.runtime_agent.entrypoint import main" in main


def test_zip_excludes_gateway_sim_env_and_bytecode(tmp_path: Path) -> None:
    with zipfile.ZipFile(_build(tmp_path)) as archive:
        names = archive.namelist()

    assert not [n for n in names if "gateway_sim" in n or n.endswith(".pyc") or ".env" in n]
    assert not [n for n in names if n.endswith("requirements.txt")]


def test_zip_permissions_are_644_or_755(tmp_path: Path) -> None:
    with zipfile.ZipFile(_build(tmp_path)) as archive:
        modes = {info.filename: (info.external_attr >> 16) & 0o777 for info in archive.infolist()}

    assert modes["bin/tool"] == 0o755
    assert modes["main.py"] == 0o644
    assert set(modes.values()) <= {0o644, 0o755}


def test_zip_is_deterministic(tmp_path: Path) -> None:
    first = _build(tmp_path / "a").read_bytes()
    second = _build(tmp_path / "b").read_bytes()

    assert first == second


def _zip_with(path: Path, names: list[str]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name in names:
            archive.writestr(name, "x")
    return path


@pytest.mark.parametrize(
    "extra",
    [
        ".env",
        "nested/.poc-state.json",
        "agentcore_runtime_poc/gateway_sim/app.py",
        "a/__pycache__/b.pyc",
    ],
)
def test_verify_rejects_forbidden_members(tmp_path: Path, extra: str) -> None:
    path = _zip_with(
        tmp_path / "bad.zip",
        ["main.py", "agentcore_runtime_poc/runtime_agent/entrypoint.py", extra],
    )

    with pytest.raises(packaging.PackagingError, match="must not contain"):
        packaging.verify_agent_zip(path)


def test_verify_requires_main_and_entrypoint(tmp_path: Path) -> None:
    with pytest.raises(packaging.PackagingError, match="missing"):
        packaging.verify_agent_zip(_zip_with(tmp_path / "bad.zip", ["main.py"]))


def test_verify_enforces_size_limit(tmp_path: Path) -> None:
    path = _zip_with(
        tmp_path / "big.zip", ["main.py", "agentcore_runtime_poc/runtime_agent/entrypoint.py"]
    )

    with pytest.raises(packaging.PackagingError, match="limit"):
        packaging.verify_agent_zip(path, max_bytes=10)


def test_uv_installer_targets_linux_arm64_wheels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def fake_run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["args"] = args
        seen["kwargs"] = kwargs
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(packaging.shutil, "which", lambda name: "/usr/local/bin/uv")
    install = packaging.uv_installer(tmp_path / "requirements.txt", run=fake_run)

    install(tmp_path / "deps", "https://mirror.example.test/simple")

    args = seen["args"]
    assert args[:3] == ["/usr/local/bin/uv", "pip", "install"]
    assert args[args.index("--python-platform") + 1] == "aarch64-manylinux2014"
    assert args[args.index("--python-version") + 1] == "3.13"
    assert "https://mirror.example.test/simple" not in args
    assert seen["kwargs"]["env"]["UV_DEFAULT_INDEX"] == "https://mirror.example.test/simple"
    assert "--only-binary=:all:" in args
    assert seen["kwargs"]["check"] is True


def test_uv_installer_requires_uv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(packaging.shutil, "which", lambda name: None)

    with pytest.raises(packaging.PackagingError, match="uv"):
        packaging.uv_installer(tmp_path / "r.txt")(tmp_path, "https://pypi.org/simple")


def test_real_source_tree_ships_only_runtime_agent() -> None:
    files = packaging.agent_source_files(Path("src"))

    assert Path("agentcore_runtime_poc/runtime_agent/entrypoint.py") in files
    assert all("gateway_sim" not in path.parts for path in files)
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `.venv/bin/python -m pytest tests/test_agent_packaging.py -v`
Expected: FAIL with `ImportError: cannot import name 'packaging'`.

- [ ] **Step 3: Implement**

`src/agentcore_runtime_poc/packaging.py`:

```python
"""Build the Runtime direct-code-deployment zip: Linux ARM64 wheels, agent sources, main.py."""

from __future__ import annotations

import os
import shutil
import subprocess
import zipfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath

AGENT_REQUIREMENTS = Path(__file__).resolve().parent / "runtime_agent" / "requirements.txt"
PLATFORM = "aarch64-manylinux2014"
PYTHON_VERSION = "3.13"
MAX_ZIP_BYTES = 250 * 1024 * 1024
ENTRY_SCRIPT = (
    "from agentcore_runtime_poc.runtime_agent.entrypoint import main\n"
    "\n"
    'if __name__ == "__main__":\n'
    "    main()\n"
)
REQUIRED_MEMBERS = frozenset({"main.py", "agentcore_runtime_poc/runtime_agent/entrypoint.py"})
FORBIDDEN_BASENAMES = frozenset(
    {".env", ".poc-state.json", ".poc-expiry-state.json", "terraform.tfstate", "terraform.tfvars"}
)
# Fixed timestamps keep the zip byte-identical across builds, so Terraform only redeploys on change.
_FIXED_TIME = (1980, 1, 1, 0, 0, 0)

Installer = Callable[[Path, str], None]


class PackagingError(RuntimeError):
    """The agent zip could not be built or failed verification."""


def uv_installer(
    requirements: Path = AGENT_REQUIREMENTS,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> Installer:
    def install(target: Path, index_url: str) -> None:
        uv = shutil.which("uv")
        if uv is None:
            raise PackagingError("uv is required to fetch Linux ARM64 wheels")
        run(  # noqa: S603 - uv is resolved from PATH; arguments are fixed.
            [
                uv,
                "pip",
                "install",
                "--python-platform",
                PLATFORM,
                "--python-version",
                PYTHON_VERSION,
                "--target",
                str(target),
                "--only-binary=:all:",
                "-r",
                str(requirements),
            ],
            check=True,
            # Via env, not argv: at work the index URL can carry Artifactory credentials.
            env={**os.environ, "UV_DEFAULT_INDEX": index_url},
        )

    return install


def agent_source_files(source_root: Path) -> list[Path]:
    package = source_root / "agentcore_runtime_poc"
    files = [package / "__init__.py", *sorted((package / "runtime_agent").glob("*.py"))]
    return [path.relative_to(source_root) for path in files]


def _is_packable(relative: Path) -> bool:
    return "__pycache__" not in relative.parts and relative.suffix != ".pyc"


def _write(archive: zipfile.ZipFile, name: str, data: bytes, *, executable: bool) -> None:
    info = zipfile.ZipInfo(name, date_time=_FIXED_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (0o100755 if executable else 0o100644) << 16
    archive.writestr(info, data)


def build_agent_zip(
    output: Path, *, source_root: Path, index_url: str, installer: Installer, workdir: Path
) -> Path:
    deps = workdir / "deps"
    deps.mkdir(parents=True, exist_ok=True)
    installer(deps, index_url)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(deps.rglob("*")):
            relative = path.relative_to(deps)
            if path.is_file() and _is_packable(relative):
                _write(
                    archive,
                    relative.as_posix(),
                    path.read_bytes(),
                    executable=os.access(path, os.X_OK),
                )
        for relative in agent_source_files(source_root):
            _write(
                archive,
                relative.as_posix(),
                (source_root / relative).read_bytes(),
                executable=False,
            )
        _write(archive, "main.py", ENTRY_SCRIPT.encode(), executable=False)
    verify_agent_zip(output)
    return output


def verify_agent_zip(path: Path, *, max_bytes: int = MAX_ZIP_BYTES) -> None:
    size = path.stat().st_size
    if size > max_bytes:
        raise PackagingError(f"zip is {size} bytes; limit is {max_bytes}")
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
    missing = REQUIRED_MEMBERS - set(names)
    if missing:
        raise PackagingError(f"zip is missing {sorted(missing)}")
    for name in names:
        parts = PurePosixPath(name).parts
        if (
            parts[-1] in FORBIDDEN_BASENAMES
            or "__pycache__" in parts
            or name.endswith(".pyc")
            or "gateway_sim" in parts
        ):
            raise PackagingError(f"zip must not contain {name}")
```

`scripts/build_agent_zip.py`:

```python
"""Build build/agent/agent.zip for the AgentCore Runtime direct code deployment."""

from __future__ import annotations

import argparse
import hashlib
import os
import tempfile
from pathlib import Path

from agentcore_runtime_poc.packaging import build_agent_zip, uv_installer

DEFAULT_OUTPUT = Path("build/agent/agent.zip")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    # Taken from the environment only: at work this URL may embed Artifactory credentials.
    index_url = os.environ.get("AGENT_PACKAGE_INDEX_URL", "https://pypi.org/simple")
    with tempfile.TemporaryDirectory() as workdir:
        path = build_agent_zip(
            args.output,
            source_root=Path("src"),
            index_url=index_url,
            installer=uv_installer(),
            workdir=Path(workdir),
        )
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    print(f"{path} {path.stat().st_size} bytes sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `.venv/bin/python -m pytest tests/test_agent_packaging.py -v`
Expected: all pass.

- [ ] **Step 5: Build the real zip once (needs network, no AWS)**

Run: `.venv/bin/python -m scripts.build_agent_zip`
Expected: `build/agent/agent.zip <N> bytes sha256=<hex>`, with N well under 250 MB (roughly 20–40 MB). Run it again; the sha256 must be identical. If `uv` fails because a wheel has no `aarch64-manylinux2014` build, record the package name. That is a finding about the agent's dependency set.

- [ ] **Step 6: Lint, type-check, commit**

```bash
.venv/bin/ruff check src/agentcore_runtime_poc scripts/build_agent_zip.py tests/test_agent_packaging.py
.venv/bin/mypy src
git add src/agentcore_runtime_poc/packaging.py scripts/build_agent_zip.py tests/test_agent_packaging.py
git commit -m "feat: build a deterministic Linux ARM64 zip for Runtime direct code deployment"
```

---

### Task 6: Terraform module `agentcore_agent_runtime` with tests

**Files:**
- Create: `infra/terraform/modules/agentcore_agent_runtime/versions.tf`
- Create: `infra/terraform/modules/agentcore_agent_runtime/variables.tf`
- Create: `infra/terraform/modules/agentcore_agent_runtime/main.tf`
- Create: `infra/terraform/modules/agentcore_agent_runtime/outputs.tf`
- Test: `infra/terraform/modules/agentcore_agent_runtime/tests/module.tftest.hcl`

**Interfaces:**
- Produces: module inputs:
  - `name`
  - `description` (null)
  - `code_bucket_name`
  - `code_object_key`
  - `code_object_version_id` (null)
  - `python_runtime` (`"PYTHON_3_13"`)
  - `entry_point` (`["main.py"]`)
  - `environment_variables` (`{}`)
  - `secret_arns` (`[]`)
  - `network_mode` (`"PUBLIC"`)
  - `vpc_subnet_ids`, `vpc_security_group_ids` (`[]`)
  - `idle_session_timeout_seconds` (900)
  - `max_lifetime_seconds` (28800)
  - `tags` (`{}`)

  Outputs: `agent_runtime_arn`, `agent_runtime_id`, `agent_runtime_version`, `execution_role_arn`.

- [ ] **Step 1: Write the failing module tests**

`infra/terraform/modules/agentcore_agent_runtime/tests/module.tftest.hcl`:

```hcl
mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }

  mock_data "aws_region" {
    defaults = {
      region = "ap-southeast-1"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/mock-execution-role"
    }
  }
}

variables {
  name                   = "poc_agent_test"
  code_bucket_name       = "example-bucket"
  code_object_key        = "agent/agent.zip"
  code_object_version_id = "example-version-1"
}

run "zip_artifact_passes_through" {
  command = plan

  assert {
    condition     = aws_bedrockagentcore_agent_runtime.this.agent_runtime_artifact[0].code_configuration[0].runtime == "PYTHON_3_13"
    error_message = "default runtime must be PYTHON_3_13"
  }

  assert {
    condition     = aws_bedrockagentcore_agent_runtime.this.agent_runtime_artifact[0].code_configuration[0].entry_point == tolist(["main.py"])
    error_message = "default entry point must be main.py"
  }

  assert {
    condition     = aws_bedrockagentcore_agent_runtime.this.agent_runtime_artifact[0].code_configuration[0].code[0].s3[0].version_id == "example-version-1"
    error_message = "the zip object version must pass through so new zips redeploy"
  }

  assert {
    condition     = length(aws_bedrockagentcore_agent_runtime.this.agent_runtime_artifact[0].container_configuration) == 0
    error_message = "the module must never render a container configuration"
  }

  assert {
    condition     = aws_bedrockagentcore_agent_runtime.this.network_configuration[0].network_mode == "PUBLIC"
    error_message = "default network mode must be PUBLIC"
  }
}

run "lifecycle_passes_through" {
  command = plan

  variables {
    idle_session_timeout_seconds = 120
    max_lifetime_seconds         = 900
  }

  assert {
    condition     = aws_bedrockagentcore_agent_runtime.this.lifecycle_configuration[0].idle_runtime_session_timeout == 120
    error_message = "idle timeout must pass through"
  }

  assert {
    condition     = aws_bedrockagentcore_agent_runtime.this.lifecycle_configuration[0].max_lifetime == 900
    error_message = "max lifetime must pass through"
  }
}

run "execution_policy_has_no_ecr_or_bedrock_model_access" {
  command = apply

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_role_policy.execution.policy).Statement :
      alltrue([for action in flatten([statement.Action]) : !startswith(action, "ecr:") && !startswith(action, "bedrock:")])
    ])
    error_message = "execution role must not grant ECR or Bedrock model actions"
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_iam_role_policy.execution.policy).Statement :
      contains(flatten([statement.Resource]), "arn:aws:s3:::example-bucket/agent/agent.zip")
    ])
    error_message = "execution role must be able to read exactly the zip object"
  }

  assert {
    condition     = length(jsondecode(aws_iam_role_policy.execution.policy).Statement) == 7
    error_message = "no secret statement without secret_arns"
  }
}

run "secret_statement_scoped_to_given_arns" {
  command = apply

  variables {
    secret_arns = ["arn:aws:secretsmanager:ap-southeast-1:123456789012:secret:example"]
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_iam_role_policy.execution.policy).Statement :
      statement.Sid == "ReadNamedSecrets" && statement.Resource == ["arn:aws:secretsmanager:ap-southeast-1:123456789012:secret:example"]
    ])
    error_message = "secret access must be limited to the given ARNs"
  }
}

run "trust_policy_is_scoped_to_account_and_region" {
  command = apply

  assert {
    condition     = jsondecode(aws_iam_role.execution.assume_role_policy).Statement[0].Condition.StringEquals["aws:SourceAccount"] == "123456789012"
    error_message = "trust must be limited to this account"
  }

  assert {
    condition     = jsondecode(aws_iam_role.execution.assume_role_policy).Statement[0].Condition.ArnLike["aws:SourceArn"] == "arn:aws:bedrock-agentcore:ap-southeast-1:123456789012:*"
    error_message = "trust must be limited to AgentCore in this region"
  }
}

run "rejects_unsupported_python" {
  command = plan

  variables {
    python_runtime = "PYTHON_3_9"
  }

  expect_failures = [var.python_runtime]
}

run "rejects_three_part_entry_point" {
  command = plan

  variables {
    entry_point = ["a", "b", "c"]
  }

  expect_failures = [var.entry_point]
}

run "rejects_idle_timeout_below_60" {
  command = plan

  variables {
    idle_session_timeout_seconds = 30
  }

  expect_failures = [var.idle_session_timeout_seconds]
}

run "rejects_max_lifetime_below_idle_timeout" {
  command = plan

  variables {
    idle_session_timeout_seconds = 900
    max_lifetime_seconds         = 600
  }

  expect_failures = [var.max_lifetime_seconds]
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

```bash
mkdir -p infra/terraform/modules/agentcore_agent_runtime && cd infra/terraform/modules/agentcore_agent_runtime
printf 'terraform {\n  required_providers {\n    aws = {\n      source  = "hashicorp/aws"\n      version = ">= 6.66.0"\n    }\n  }\n}\n' > versions.tf
terraform init -backend=false -input=false
terraform test
```

Expected: FAIL, with undeclared resources and variables.

- [ ] **Step 3: Write the module**

`versions.tf` (replaces the stub):

```hcl
terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.66.0"
    }
  }
}
```

`variables.tf`:

```hcl
variable "name" {
  type        = string
  description = "Runtime name: a letter, then letters, digits, or underscores (max 48)."

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9_]{0,47}$", var.name))
    error_message = "name must match ^[a-zA-Z][a-zA-Z0-9_]{0,47}$ (no hyphens)."
  }
}

variable "description" {
  type    = string
  default = null
}

variable "code_bucket_name" {
  type = string
}

variable "code_object_key" {
  type = string
}

variable "code_object_version_id" {
  type        = string
  default     = null
  description = "S3 object version of the zip. Pass it so that a new zip changes the runtime and redeploys it."
}

variable "python_runtime" {
  type    = string
  default = "PYTHON_3_13"

  validation {
    condition     = contains(["PYTHON_3_10", "PYTHON_3_11", "PYTHON_3_12", "PYTHON_3_13"], var.python_runtime)
    error_message = "python_runtime must be PYTHON_3_10 through PYTHON_3_13."
  }
}

variable "entry_point" {
  type    = list(string)
  default = ["main.py"]

  validation {
    condition     = length(var.entry_point) >= 1 && length(var.entry_point) <= 2
    error_message = "entry_point must have 1 or 2 elements."
  }
}

variable "environment_variables" {
  type    = map(string)
  default = {}
}

variable "secret_arns" {
  type    = list(string)
  default = []
}

variable "network_mode" {
  type    = string
  default = "PUBLIC"

  validation {
    condition     = contains(["PUBLIC", "VPC"], var.network_mode)
    error_message = "network_mode must be PUBLIC or VPC."
  }
}

variable "vpc_subnet_ids" {
  type    = list(string)
  default = []

  validation {
    condition     = var.network_mode != "VPC" || length(var.vpc_subnet_ids) > 0
    error_message = "vpc_subnet_ids is required when network_mode is VPC."
  }
}

variable "vpc_security_group_ids" {
  type    = list(string)
  default = []

  validation {
    condition     = var.network_mode != "VPC" || length(var.vpc_security_group_ids) > 0
    error_message = "vpc_security_group_ids is required when network_mode is VPC."
  }
}

variable "idle_session_timeout_seconds" {
  type    = number
  default = 900

  validation {
    condition     = var.idle_session_timeout_seconds >= 60 && var.idle_session_timeout_seconds <= 28800
    error_message = "idle_session_timeout_seconds must be between 60 and 28800."
  }
}

variable "max_lifetime_seconds" {
  type    = number
  default = 28800

  validation {
    condition     = var.max_lifetime_seconds >= var.idle_session_timeout_seconds && var.max_lifetime_seconds <= 28800
    error_message = "max_lifetime_seconds must be at least idle_session_timeout_seconds and at most 28800."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}
```

`main.tf`:

```hcl
data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  account_id    = data.aws_caller_identity.current.account_id
  region        = data.aws_region.current.region
  log_group_arn = "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/bedrock-agentcore/runtimes"

  base_statements = [
    {
      Sid      = "RuntimeLogGroups"
      Effect   = "Allow"
      Action   = ["logs:CreateLogGroup", "logs:DescribeLogStreams"]
      Resource = ["${local.log_group_arn}/*"]
    },
    {
      Sid      = "RuntimeLogResourcePolicy"
      Effect   = "Allow"
      Action   = ["logs:PutResourcePolicy"]
      Resource = ["${local.log_group_arn}/${var.name}-*"]
    },
    {
      Sid      = "DescribeLogGroups"
      Effect   = "Allow"
      Action   = ["logs:DescribeLogGroups"]
      Resource = ["arn:aws:logs:${local.region}:${local.account_id}:log-group:*"]
    },
    {
      Sid      = "RuntimeLogStreams"
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = ["${local.log_group_arn}/*:log-stream:*"]
    },
    {
      Sid      = "Tracing"
      Effect   = "Allow"
      Action   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets"]
      Resource = ["*"]
    },
    {
      Sid       = "Metrics"
      Effect    = "Allow"
      Action    = ["cloudwatch:PutMetricData"]
      Resource  = ["*"]
      Condition = { StringEquals = { "cloudwatch:namespace" = "bedrock-agentcore" } }
    },
    {
      Sid      = "ReadCodePackage"
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:GetObjectVersion"]
      Resource = ["arn:aws:s3:::${var.code_bucket_name}/${var.code_object_key}"]
    },
  ]

  secret_statements = [
    for _ in range(length(var.secret_arns) > 0 ? 1 : 0) : {
      Sid      = "ReadNamedSecrets"
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = var.secret_arns
    }
  ]
}

resource "aws_iam_role" "execution" {
  name = "${var.name}_execution"
  tags = var.tags
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AgentCoreRuntimeAssume"
      Effect    = "Allow"
      Principal = { Service = "bedrock-agentcore.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:aws:bedrock-agentcore:${local.region}:${local.account_id}:*" }
      }
    }]
  })
}

resource "aws_iam_role_policy" "execution" {
  name = "agent-runtime-execution"
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = concat(local.base_statements, local.secret_statements)
  })
}

resource "aws_bedrockagentcore_agent_runtime" "this" {
  agent_runtime_name    = var.name
  description           = var.description
  role_arn              = aws_iam_role.execution.arn
  environment_variables = var.environment_variables
  tags                  = var.tags

  lifecycle_configuration = [{
    idle_runtime_session_timeout = var.idle_session_timeout_seconds
    max_lifetime                 = var.max_lifetime_seconds
  }]

  agent_runtime_artifact {
    code_configuration {
      entry_point = var.entry_point
      runtime     = var.python_runtime

      code {
        s3 {
          bucket     = var.code_bucket_name
          prefix     = var.code_object_key
          version_id = var.code_object_version_id
        }
      }
    }
  }

  network_configuration {
    network_mode = var.network_mode

    dynamic "network_mode_config" {
      for_each = var.network_mode == "VPC" ? [1] : []

      content {
        security_groups = var.vpc_security_group_ids
        subnets         = var.vpc_subnet_ids
      }
    }
  }

  protocol_configuration {
    server_protocol = "HTTP"
  }

  depends_on = [aws_iam_role_policy.execution]
}
```

`outputs.tf`:

```hcl
output "agent_runtime_arn" {
  value = aws_bedrockagentcore_agent_runtime.this.agent_runtime_arn
}

output "agent_runtime_id" {
  value = aws_bedrockagentcore_agent_runtime.this.agent_runtime_id
}

output "agent_runtime_version" {
  value = aws_bedrockagentcore_agent_runtime.this.agent_runtime_version
}

output "execution_role_arn" {
  value = aws_iam_role.execution.arn
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

```bash
terraform fmt -check -recursive
terraform validate
terraform test
```

Expected: `validate` prints `Success!` and `terraform test` reports `9 passed, 0 failed`.

- [ ] **Step 5: Commit**

```bash
cd ../../../..
git add infra/terraform/modules/agentcore_agent_runtime
git commit -m "feat: add zip-only agentcore_agent_runtime Terraform module with tests"
```

---

### Task 7: POC root wiring, and writing the secret value outside Terraform

**Files:**
- Modify: `infra/terraform/poc/variables.tf` (append)
- Create: `infra/terraform/poc/runtime.tf`
- Modify: `infra/terraform/poc/outputs.tf` (append)
- Create: `infra/terraform/poc/tests/fixtures/fake-agent.zip` (text fixture)
- Test: `infra/terraform/poc/tests/runtime.tftest.hcl`
- Create: `scripts/put_gateway_secret.py`
- Test: `tests/test_put_gateway_secret.py`

**Interfaces:**
- Consumes: module `agentcore_agent_runtime` (Task 6), `local.account_id` (Phase 1 `main.tf`), and `scripts.terraform_outputs.load_terraform_outputs` (Phase 1).
- Produces:
  - Root variables:
    - `deploy_runtime` (bool, false)
    - `entra_tenant_id`
    - `gateway_app_client_id`
    - `gateway_caller_client_id`
    - `gateway_base_url`
    - `agent_openai_model`
    - `agent_anthropic_model`
    - `agent_zip_path` (`"../../../build/agent/agent.zip"`)
    - `runtime_idle_session_timeout_seconds` (120)
    - `runtime_max_lifetime_seconds` (900)
  - Root outputs (strings):
    - `agent_runtime_arn`, `agent_runtime_id`, `agent_runtime_version`
    - `gateway_secret_arn`
    - `agent_code_bucket`
    - `name_prefix`
    - `runtime_idle_session_timeout_seconds`
  - Root output (map): `agent_environment`.
  - `scripts.put_gateway_secret.put_gateway_secret(env: Mapping[str, str], outputs: Mapping[str, str], client_factory=boto3.client) -> str` (returns the new secret version ID).

- [ ] **Step 1: Write the failing root test and fixture**

Create the fixture file: `printf 'fixture only, not a real zip\n' > infra/terraform/poc/tests/fixtures/fake-agent.zip`

`infra/terraform/poc/tests/runtime.tftest.hcl`:

```hcl
mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }

  mock_data "aws_region" {
    defaults = {
      region = "ap-southeast-1"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/mock-execution-role"
    }
  }
}

variables {
  aws_region      = "ap-southeast-1"
  aws_budget_name = "example-budget"
}

run "runtime_is_off_by_default" {
  command = plan

  assert {
    condition     = length(module.agent_runtime) == 0 && length(aws_s3_bucket.agent_code) == 0
    error_message = "Phase 1 applies must not create runtime resources"
  }

  assert {
    condition     = output.agent_runtime_arn == ""
    error_message = "runtime ARN output must be empty when not deployed"
  }
}

run "runtime_on_wires_bucket_zip_secret_and_environment" {
  command = apply

  variables {
    deploy_runtime           = true
    entra_tenant_id          = "example-tenant"
    gateway_app_client_id    = "gateway-app-id"
    gateway_caller_client_id = "caller-a"
    gateway_base_url         = "https://gateway.example.test/"
    agent_openai_model       = "model-o"
    agent_anthropic_model    = "model-a"
    agent_zip_path           = "tests/fixtures/fake-agent.zip"
  }

  assert {
    condition     = aws_s3_bucket.agent_code[0].bucket == "ci-rt-poc-agent-code-123456789012"
    error_message = "bucket name must be derived from the prefix and account"
  }

  assert {
    condition     = aws_s3_bucket_versioning.agent_code[0].versioning_configuration[0].status == "Enabled"
    error_message = "versioning must be on so new zips get new version ids"
  }

  assert {
    condition     = aws_s3_object.agent_zip[0].source_hash == filemd5("tests/fixtures/fake-agent.zip")
    error_message = "zip object must track the local file's hash"
  }

  assert {
    condition     = aws_secretsmanager_secret.gateway_caller[0].recovery_window_in_days == 0
    error_message = "POC secret must delete immediately on destroy"
  }

  assert {
    condition     = output.agent_environment["GATEWAY_SCOPE"] == "gateway-app-id/.default"
    error_message = "scope must be the gateway app's .default scope"
  }

  assert {
    condition     = output.agent_environment["GATEWAY_BASE_URL"] == "https://gateway.example.test"
    error_message = "trailing slash must be trimmed"
  }

  assert {
    condition     = output.agent_environment["GATEWAY_CLIENT_SECRET_ARN"] == aws_secretsmanager_secret.gateway_caller[0].arn
    error_message = "agent must be told the secret ARN, not the secret"
  }
}

run "runtime_on_requires_https_gateway_url" {
  command = plan

  variables {
    deploy_runtime           = true
    entra_tenant_id          = "example-tenant"
    gateway_app_client_id    = "gateway-app-id"
    gateway_caller_client_id = "caller-a"
    gateway_base_url         = "http://gateway.example.test"
    agent_openai_model       = "model-o"
    agent_anthropic_model    = "model-a"
    agent_zip_path           = "tests/fixtures/fake-agent.zip"
  }

  expect_failures = [var.gateway_base_url]
}

run "runtime_on_requires_tenant" {
  command = plan

  variables {
    deploy_runtime           = true
    gateway_app_client_id    = "gateway-app-id"
    gateway_caller_client_id = "caller-a"
    gateway_base_url         = "https://gateway.example.test"
    agent_openai_model       = "model-o"
    agent_anthropic_model    = "model-a"
    agent_zip_path           = "tests/fixtures/fake-agent.zip"
  }

  expect_failures = [var.entra_tenant_id]
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `cd infra/terraform/poc && terraform init -backend=false -input=false && terraform test`
Expected: FAIL for `runtime.tftest.hcl`, with undeclared variables, resources, and module. Phase 1's `code_interpreter.tftest.hcl` still passes.

- [ ] **Step 3: Implement**

Append to `infra/terraform/poc/variables.tf`:

```hcl
variable "deploy_runtime" {
  type    = bool
  default = false
}

variable "entra_tenant_id" {
  type    = string
  default = ""

  validation {
    condition     = !var.deploy_runtime || length(var.entra_tenant_id) > 0
    error_message = "entra_tenant_id is required when deploy_runtime is true."
  }
}

variable "gateway_app_client_id" {
  type    = string
  default = ""

  validation {
    condition     = !var.deploy_runtime || length(var.gateway_app_client_id) > 0
    error_message = "gateway_app_client_id is required when deploy_runtime is true."
  }
}

variable "gateway_caller_client_id" {
  type    = string
  default = ""

  validation {
    condition     = !var.deploy_runtime || length(var.gateway_caller_client_id) > 0
    error_message = "gateway_caller_client_id is required when deploy_runtime is true."
  }
}

variable "gateway_base_url" {
  type    = string
  default = ""

  validation {
    condition     = !var.deploy_runtime || startswith(var.gateway_base_url, "https://")
    error_message = "gateway_base_url must be an https URL when deploy_runtime is true."
  }
}

variable "agent_openai_model" {
  type    = string
  default = ""

  validation {
    condition     = !var.deploy_runtime || length(var.agent_openai_model) > 0
    error_message = "agent_openai_model is required when deploy_runtime is true."
  }
}

variable "agent_anthropic_model" {
  type    = string
  default = ""

  validation {
    condition     = !var.deploy_runtime || length(var.agent_anthropic_model) > 0
    error_message = "agent_anthropic_model is required when deploy_runtime is true."
  }
}

variable "agent_zip_path" {
  type    = string
  default = "../../../build/agent/agent.zip"
}

variable "runtime_idle_session_timeout_seconds" {
  type    = number
  default = 120
}

variable "runtime_max_lifetime_seconds" {
  type    = number
  default = 900
}
```

`infra/terraform/poc/runtime.tf`:

```hcl
locals {
  runtime_count = var.deploy_runtime ? 1 : 0
  code_bucket   = "${replace(var.name_prefix, "_", "-")}-agent-code-${local.account_id}"
  agent_zip_key = "agent/agent.zip"
}

resource "aws_s3_bucket" "agent_code" {
  count         = local.runtime_count
  bucket        = local.code_bucket
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "agent_code" {
  count                   = local.runtime_count
  bucket                  = aws_s3_bucket.agent_code[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "agent_code" {
  count  = local.runtime_count
  bucket = aws_s3_bucket.agent_code[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "agent_code" {
  count  = local.runtime_count
  bucket = aws_s3_bucket.agent_code[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_object" "agent_zip" {
  count       = local.runtime_count
  bucket      = aws_s3_bucket.agent_code[0].id
  key         = local.agent_zip_key
  source      = var.agent_zip_path
  source_hash = filemd5(var.agent_zip_path)

  depends_on = [aws_s3_bucket_versioning.agent_code]
}

# Terraform creates only the empty secret; scripts/put_gateway_secret.py writes the value,
# so the value never enters Terraform state or plan output.
resource "aws_secretsmanager_secret" "gateway_caller" {
  count                   = local.runtime_count
  name                    = "${var.name_prefix}/gateway-caller-client-secret"
  recovery_window_in_days = 0
}

locals {
  agent_environment = var.deploy_runtime ? {
    POC_REGION                = var.aws_region
    ENTRA_TENANT_ID           = var.entra_tenant_id
    GATEWAY_CALLER_CLIENT_ID  = var.gateway_caller_client_id
    GATEWAY_CLIENT_SECRET_ARN = aws_secretsmanager_secret.gateway_caller[0].arn
    GATEWAY_BASE_URL          = trimsuffix(var.gateway_base_url, "/")
    GATEWAY_SCOPE             = "${var.gateway_app_client_id}/.default"
    AGENT_OPENAI_MODEL        = var.agent_openai_model
    AGENT_ANTHROPIC_MODEL     = var.agent_anthropic_model
  } : {}
}

module "agent_runtime" {
  count  = local.runtime_count
  source = "../modules/agentcore_agent_runtime"

  name                         = "${var.name_prefix}_agent"
  description                  = "POC agent: inference only through the central LLM gateway"
  code_bucket_name             = aws_s3_bucket.agent_code[0].id
  code_object_key              = aws_s3_object.agent_zip[0].key
  code_object_version_id       = aws_s3_object.agent_zip[0].version_id
  secret_arns                  = [aws_secretsmanager_secret.gateway_caller[0].arn]
  environment_variables        = local.agent_environment
  idle_session_timeout_seconds = var.runtime_idle_session_timeout_seconds
  max_lifetime_seconds         = var.runtime_max_lifetime_seconds
}
```

Append to `infra/terraform/poc/outputs.tf`:

```hcl
output "name_prefix" {
  value = var.name_prefix
}

output "agent_runtime_arn" {
  value = try(module.agent_runtime[0].agent_runtime_arn, "")
}

output "agent_runtime_id" {
  value = try(module.agent_runtime[0].agent_runtime_id, "")
}

output "agent_runtime_version" {
  value = try(tostring(module.agent_runtime[0].agent_runtime_version), "")
}

output "gateway_secret_arn" {
  value = try(aws_secretsmanager_secret.gateway_caller[0].arn, "")
}

output "agent_code_bucket" {
  value = try(aws_s3_bucket.agent_code[0].id, "")
}

output "runtime_idle_session_timeout_seconds" {
  value = tostring(var.runtime_idle_session_timeout_seconds)
}

output "agent_environment" {
  value = local.agent_environment
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

```bash
terraform fmt -check -recursive
terraform validate
terraform test
```

Expected: `validate` prints `Success!` and `terraform test` reports `6 passed, 0 failed` (2 from Phase 1 plus 4 new). `runtime_is_off_by_default` passing also proves that `filemd5` is not evaluated when `deploy_runtime` is false, so Phase 1 applies work without a built zip.

- [ ] **Step 5: Write the failing secret-writer test**

`tests/test_put_gateway_secret.py`:

```python
from __future__ import annotations

from typing import Any

import pytest

from scripts.put_gateway_secret import put_gateway_secret

OUTPUTS = {"aws_region": "ap-southeast-1", "gateway_secret_arn": "arn:example"}


class FakeSecrets:
    def __init__(self) -> None:
        self.kwargs: dict[str, Any] = {}

    def put_secret_value(self, **kwargs: Any) -> dict[str, Any]:
        self.kwargs = kwargs
        return {"VersionId": "v-2"}


def test_writes_secret_from_environment() -> None:
    fake = FakeSecrets()
    created: dict[str, Any] = {}

    def factory(name: str, region_name: str) -> FakeSecrets:
        created.update(name=name, region=region_name)
        return fake

    version = put_gateway_secret(
        {"GATEWAY_CALLER_CLIENT_SECRET": "secret-value"}, OUTPUTS, client_factory=factory
    )

    assert version == "v-2"
    assert fake.kwargs == {"SecretId": "arn:example", "SecretString": "secret-value"}
    assert created == {"name": "secretsmanager", "region": "ap-southeast-1"}


def test_requires_secret_in_environment() -> None:
    with pytest.raises(SystemExit, match="GATEWAY_CALLER_CLIENT_SECRET"):
        put_gateway_secret({}, OUTPUTS, client_factory=lambda *a, **k: FakeSecrets())


def test_requires_runtime_to_be_deployed() -> None:
    with pytest.raises(SystemExit, match="deploy_runtime"):
        put_gateway_secret(
            {"GATEWAY_CALLER_CLIENT_SECRET": "secret-value"},
            {"aws_region": "ap-southeast-1", "gateway_secret_arn": ""},
            client_factory=lambda *a, **k: FakeSecrets(),
        )
```

- [ ] **Step 6: Implement the secret writer**

`scripts/put_gateway_secret.py`:

```python
"""Write the gateway caller secret into the Terraform-created secret. The value comes from env."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import boto3  # type: ignore[import-untyped]

from scripts.terraform_outputs import load_terraform_outputs


def put_gateway_secret(
    env: Mapping[str, str],
    outputs: Mapping[str, str],
    client_factory: Callable[..., Any] = boto3.client,
) -> str:
    secret = env.get("GATEWAY_CALLER_CLIENT_SECRET", "")
    if not secret:
        raise SystemExit("GATEWAY_CALLER_CLIENT_SECRET must be set in the environment")
    secret_arn = outputs.get("gateway_secret_arn", "")
    if not secret_arn:
        raise SystemExit("gateway_secret_arn is empty: apply with TF_VAR_deploy_runtime=true first")
    client = client_factory("secretsmanager", region_name=outputs["aws_region"])
    response = client.put_secret_value(SecretId=secret_arn, SecretString=secret)
    return str(response["VersionId"])


def main() -> int:
    version = put_gateway_secret(os.environ, load_terraform_outputs(Path("infra/terraform/poc")))
    print(f"stored secret version {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 7: Run the tests and commit**

Run: `.venv/bin/python -m pytest tests/test_put_gateway_secret.py -v` and expect 3 passed. Then:

```bash
cd infra/terraform/poc && terraform test && cd ../../..
.venv/bin/ruff check scripts/put_gateway_secret.py tests/test_put_gateway_secret.py
git add infra/terraform/poc scripts/put_gateway_secret.py tests/test_put_gateway_secret.py
git commit -m "feat: wire zip bucket, secret shell, and runtime into the POC Terraform root"
```

---

### Task 8: Runtime invoker and CLI

**Files:**
- Create: `src/agentcore_runtime_poc/invoke.py`
- Create: `scripts/invoke_runtime_agent.py`
- Test: `tests/test_runtime_invoke.py`

**Interfaces:**
- Produces:
  - `new_session_id() -> str` (36 characters, above the API minimum of 33)
  - `InvokeResult(status_code: int, body: dict[str, Any], elapsed_ms: float, session_id: str)`
  - `RuntimeInvoker(client, agent_runtime_arn, clock=time.perf_counter)` with `.invoke(payload, session_id) -> InvokeResult` and `.stop(session_id) -> None`

- [ ] **Step 1: Write the failing tests**

`tests/test_runtime_invoke.py`:

```python
from __future__ import annotations

import io
import json
from typing import Any

from agentcore_runtime_poc.invoke import RuntimeInvoker, new_session_id

ARN = "arn:aws:bedrock-agentcore:ap-southeast-1:123456789012:runtime/ci_rt_poc_agent-abc"


class FakeClient:
    def __init__(self, raw: bytes, status: int = 200) -> None:
        self.raw = raw
        self.status = status
        self.invoke_kwargs: dict[str, Any] = {}
        self.stop_kwargs: dict[str, Any] = {}

    def invoke_agent_runtime(self, **kwargs: Any) -> dict[str, Any]:
        self.invoke_kwargs = kwargs
        return {"response": io.BytesIO(self.raw), "statusCode": self.status}

    def stop_runtime_session(self, **kwargs: Any) -> dict[str, Any]:
        self.stop_kwargs = kwargs
        return {}


def test_session_ids_are_long_enough_and_unique() -> None:
    first, second = new_session_id(), new_session_id()

    assert len(first) >= 33
    assert first != second


def test_invoke_sends_json_payload_and_parses_body() -> None:
    client = FakeClient(b'{"boot_id": "b1"}')
    ticks = iter([1.0, 1.25])
    invoker = RuntimeInvoker(client, ARN, clock=lambda: next(ticks))

    result = invoker.invoke({"action": "whoami"}, "s" * 36)

    assert result.body == {"boot_id": "b1"}
    assert result.status_code == 200
    assert result.elapsed_ms == 250.0
    assert client.invoke_kwargs["agentRuntimeArn"] == ARN
    assert client.invoke_kwargs["runtimeSessionId"] == "s" * 36
    assert client.invoke_kwargs["qualifier"] == "DEFAULT"
    assert client.invoke_kwargs["contentType"] == "application/json"
    assert json.loads(client.invoke_kwargs["payload"]) == {"action": "whoami"}


def test_empty_and_non_object_bodies() -> None:
    assert RuntimeInvoker(FakeClient(b""), ARN).invoke({}, "s" * 36).body == {}
    assert RuntimeInvoker(FakeClient(b"[1]"), ARN).invoke({}, "s" * 36).body == {"value": [1]}


def test_stop_targets_the_session() -> None:
    client = FakeClient(b"{}")

    RuntimeInvoker(client, ARN).stop("s" * 36)

    assert client.stop_kwargs == {
        "agentRuntimeArn": ARN,
        "runtimeSessionId": "s" * 36,
        "qualifier": "DEFAULT",
    }
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `.venv/bin/python -m pytest tests/test_runtime_invoke.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'agentcore_runtime_poc.invoke'`.

- [ ] **Step 3: Implement**

`src/agentcore_runtime_poc/invoke.py`:

```python
"""Invoke the deployed Runtime agent with the caller's own AWS credentials (SigV4)."""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any


def new_session_id() -> str:
    return f"poc-{uuid.uuid4().hex}"


@dataclass(frozen=True)
class InvokeResult:
    status_code: int
    body: dict[str, Any]
    elapsed_ms: float
    session_id: str


class RuntimeInvoker:
    def __init__(
        self,
        client: Any,
        agent_runtime_arn: str,
        clock: Callable[[], float] = time.perf_counter,
    ) -> None:
        self._client = client
        self._arn = agent_runtime_arn
        self._clock = clock

    def invoke(self, payload: Mapping[str, Any], session_id: str) -> InvokeResult:
        started = self._clock()
        response = self._client.invoke_agent_runtime(
            agentRuntimeArn=self._arn,
            runtimeSessionId=session_id,
            qualifier="DEFAULT",
            contentType="application/json",
            accept="application/json",
            payload=json.dumps(dict(payload)).encode("utf-8"),
        )
        raw = response["response"].read()
        elapsed_ms = round((self._clock() - started) * 1000, 1)
        parsed: Any = json.loads(raw) if raw else {}
        body = parsed if isinstance(parsed, dict) else {"value": parsed}
        return InvokeResult(int(response.get("statusCode", 200)), body, elapsed_ms, session_id)

    def stop(self, session_id: str) -> None:
        self._client.stop_runtime_session(
            agentRuntimeArn=self._arn, runtimeSessionId=session_id, qualifier="DEFAULT"
        )
```

`scripts/invoke_runtime_agent.py`:

```python
"""Invoke the POC Runtime agent once and print the JSON result."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import boto3  # type: ignore[import-untyped]

from agentcore_runtime_poc.invoke import RuntimeInvoker, new_session_id
from scripts.terraform_outputs import load_terraform_outputs

ACTIONS = (
    "whoami",
    "set_marker",
    "get_marker",
    "probe_egress",
    "chat",
    "chat_unauthenticated",
    "sleep",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=ACTIONS, required=True)
    parser.add_argument("--provider", choices=("openai", "anthropic"))
    parser.add_argument("--prompt")
    parser.add_argument("--marker")
    parser.add_argument("--seconds", type=int)
    parser.add_argument("--session-id")
    parser.add_argument("--stop", action="store_true", help="stop the session afterwards")
    args = parser.parse_args(argv)

    outputs = load_terraform_outputs(Path("infra/terraform/poc"))
    client = boto3.client("bedrock-agentcore", region_name=outputs["aws_region"])
    invoker = RuntimeInvoker(client, outputs["agent_runtime_arn"])
    session_id = args.session_id or new_session_id()
    payload = {
        key: value
        for key, value in {
            "action": args.action,
            "provider": args.provider,
            "prompt": args.prompt,
            "marker": args.marker,
            "seconds": args.seconds,
        }.items()
        if value is not None
    }
    result = invoker.invoke(payload, session_id)
    print(
        json.dumps(
            {
                "session_id": session_id,
                "status_code": result.status_code,
                "elapsed_ms": result.elapsed_ms,
                "body": result.body,
            },
            indent=2,
        )
    )
    if args.stop:
        invoker.stop(session_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run the tests and confirm they pass, then commit**

Run: `.venv/bin/python -m pytest tests/test_runtime_invoke.py -v` and expect 4 passed.

```bash
.venv/bin/ruff check src/agentcore_runtime_poc scripts/invoke_runtime_agent.py tests/test_runtime_invoke.py
.venv/bin/mypy src
git add src/agentcore_runtime_poc/invoke.py scripts/invoke_runtime_agent.py tests/test_runtime_invoke.py
git commit -m "feat: add SigV4 Runtime invoker and CLI"
```

---

### Task 9: Phase 2 live gate, gate updates, and runbook

**Files:**
- Create: `src/agentcore_runtime_poc/inventory.py`
- Create: `scripts/container_inventory.py`
- Test: `tests/test_container_inventory.py`
- Create: `tests/integration/test_runtime_live.py`
- Modify: `pyproject.toml` (`[tool.mypy] packages`)
- Modify: `README.md` and `docs/runbook.md` (Phase 0 commands; a Phase 2 section)

**Interfaces:**
- Consumes:
  - Root outputs (Task 7): `aws_region`, `agent_runtime_arn`, `agent_runtime_id`, `agent_runtime_version`, `name_prefix`, `runtime_idle_session_timeout_seconds`
  - `RuntimeInvoker`, `new_session_id` (Task 8)
  - `Observation`, `append_observations` (Phase 1)
  - The agent response keys (Task 4)
- Produces:
  - `inventory.container_inventory(ecr, codebuild) -> dict[str, list[str]]` (paginated), `inventory.new_resources(before, after) -> dict[str, list[str]]`, `inventory.save_inventory(path, inventory)`, and `inventory.load_inventory(path)`
  - `scripts.container_inventory.BEFORE_PATH` (`evidence/raw/container-inventory-before.json`), written by `python -m scripts.container_inventory` before the first apply

- [ ] **Step 1: Write the failing inventory tests**

`tests/test_container_inventory.py`:

```python
from __future__ import annotations

from pathlib import Path
from typing import Any

from agentcore_runtime_poc.inventory import (
    container_inventory,
    load_inventory,
    new_resources,
    save_inventory,
)


class FakePaginated:
    def __init__(self, operation: str, pages: list[dict[str, Any]]) -> None:
        self.operation = operation
        self.pages = pages

    def get_paginator(self, name: str) -> FakePaginated:
        assert name == self.operation
        return self

    def paginate(self) -> list[dict[str, Any]]:
        return self.pages


def test_inventory_reads_every_page() -> None:
    ecr = FakePaginated(
        "describe_repositories",
        [
            {"repositories": [{"repositoryName": "b"}]},
            {"repositories": [{"repositoryName": "a"}]},
        ],
    )
    codebuild = FakePaginated("list_projects", [{"projects": ["p1"]}, {"projects": ["p2"]}])

    assert container_inventory(ecr, codebuild) == {
        "ecr_repositories": ["a", "b"],
        "codebuild_projects": ["p1", "p2"],
    }


def test_new_resources_ignores_pre_existing_ones() -> None:
    before = {"ecr_repositories": ["team-repo"], "codebuild_projects": []}
    after = {"ecr_repositories": ["team-repo", "bedrock-agentcore-x"], "codebuild_projects": ["p"]}

    assert new_resources(before, after) == {
        "ecr_repositories": ["bedrock-agentcore-x"],
        "codebuild_projects": ["p"],
    }


def test_inventory_round_trips_through_a_file(tmp_path: Path) -> None:
    path = tmp_path / "raw" / "before.json"
    inventory = {"ecr_repositories": ["a"], "codebuild_projects": []}

    save_inventory(path, inventory)

    assert load_inventory(path) == inventory
```

- [ ] **Step 2: Run them and confirm they fail**

Run: `.venv/bin/python -m pytest tests/test_container_inventory.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'agentcore_runtime_poc.inventory'`.

- [ ] **Step 3: Implement the inventory module and snapshot script**

`src/agentcore_runtime_poc/inventory.py`:

```python
"""Paginated inventory of container-build resources, compared before and after a deploy."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

KEYS = ("ecr_repositories", "codebuild_projects")


def container_inventory(ecr: Any, codebuild: Any) -> dict[str, list[str]]:
    repositories = [
        repo["repositoryName"]
        for page in ecr.get_paginator("describe_repositories").paginate()
        for repo in page.get("repositories", [])
    ]
    projects = [
        name
        for page in codebuild.get_paginator("list_projects").paginate()
        for name in page.get("projects", [])
    ]
    return {"ecr_repositories": sorted(repositories), "codebuild_projects": sorted(projects)}


def new_resources(
    before: Mapping[str, list[str]], after: Mapping[str, list[str]]
) -> dict[str, list[str]]:
    return {key: sorted(set(after.get(key, [])) - set(before.get(key, []))) for key in KEYS}


def save_inventory(path: Path, inventory: Mapping[str, list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(inventory), indent=2, sort_keys=True), encoding="utf-8")


def load_inventory(path: Path) -> dict[str, list[str]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {key: [str(name) for name in raw.get(key, [])] for key in KEYS}
```

`scripts/container_inventory.py`:

```python
"""Snapshot ECR repositories and CodeBuild projects before a deploy (for Q2.6)."""

from __future__ import annotations

import os
from pathlib import Path

import boto3  # type: ignore[import-untyped]

from agentcore_runtime_poc.inventory import container_inventory, save_inventory

BEFORE_PATH = Path("evidence/raw/container-inventory-before.json")


def main() -> int:
    region = os.environ["AWS_REGION"]
    inventory = container_inventory(
        boto3.client("ecr", region_name=region), boto3.client("codebuild", region_name=region)
    )
    save_inventory(BEFORE_PATH, inventory)
    print(f"{BEFORE_PATH}: {', '.join(f'{k}={len(v)}' for k, v in inventory.items())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Run: `.venv/bin/python -m pytest tests/test_container_inventory.py -v`
Expected: 3 passed.

- [ ] **Step 4: Write the live gate**

`tests/integration/test_runtime_live.py`:

```python
"""Opt-in Phase 2 live gate. OPERATOR-RUN after apply, secret write, and gateway + tunnel start."""

from __future__ import annotations

import contextlib
import os
import re
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import boto3
import httpx
import pytest

from agentcore_code_interpreter_poc.observations import Observation, Status, append_observations
from agentcore_runtime_poc.inventory import container_inventory, load_inventory, new_resources
from agentcore_runtime_poc.invoke import InvokeResult, RuntimeInvoker, new_session_id
from scripts.container_inventory import BEFORE_PATH
from scripts.terraform_outputs import load_terraform_outputs

pytestmark = pytest.mark.integration

OBSERVATIONS = Path("evidence/raw/runtime-observations.jsonl")
_JWT_SHAPE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.")


def _status(ok: bool) -> Status:
    return "pass" if ok else "fail"


def _valid(result: InvokeResult, action: str, *required: str) -> bool:
    body = result.body
    return (
        result.status_code == 200
        and body.get("action") == action
        and "error" not in body
        and bool(body.get("boot_id"))
        and all(key in body for key in required)
    )


@pytest.fixture(scope="module")
def outputs() -> dict[str, str]:
    if "AGENTCORE_POC_LIVE" not in os.environ:
        pytest.skip("set AGENTCORE_POC_LIVE=1 after apply, secret write, gateway and tunnel start")
    values = load_terraform_outputs(Path("infra/terraform/poc"))
    if not values.get("agent_runtime_arn"):
        pytest.fail("agent_runtime_arn is empty: apply with TF_VAR_deploy_runtime=true first")
    return values


@pytest.fixture(scope="module")
def invoker(outputs: dict[str, str]) -> RuntimeInvoker:
    client = boto3.client("bedrock-agentcore", region_name=outputs["aws_region"])
    return RuntimeInvoker(client, outputs["agent_runtime_arn"])


@pytest.fixture
def opened(invoker: RuntimeInvoker) -> Iterator[list[str]]:
    sessions: list[str] = []
    yield sessions
    for session_id in sessions:
        with contextlib.suppress(Exception):
            invoker.stop(session_id)


def _session(opened: list[str]) -> str:
    session_id = new_session_id()
    opened.append(session_id)
    return session_id


def _config(outputs: dict[str, str]) -> dict[str, str]:
    return {
        "region": outputs["aws_region"],
        "runtime_id": outputs["agent_runtime_id"],
        "runtime_version": outputs.get("agent_runtime_version", ""),
    }


def _record(observations: list[Observation]) -> None:
    append_observations(OBSERVATIONS, observations)
    for observation in observations:
        print(observation.as_dict())
    failed = [o.as_dict() for o in observations if o.status != "pass"]
    assert not failed, failed


def _pick(body: dict[str, Any], *keys: str) -> str:
    return str({key: body.get(key) for key in keys})


def test_q2_1_runtime_reaches_external_gateway(
    invoker: RuntimeInvoker, opened: list[str], outputs: dict[str, str]
) -> None:
    result = invoker.invoke({"action": "probe_egress"}, _session(opened))
    status: Status = (
        _status(result.body.get("healthz_status") == 200)
        if _valid(result, "probe_egress", "healthz_status")
        else "blocked"
    )
    _record(
        [
            Observation(
                "Q2.1",
                "egress_to_external_https",
                status,
                "the tunnel URL's /healthz returns 200 from inside Runtime (PUBLIC network mode)",
                _pick(result.body, "healthz_status", "error"),
                _config(outputs),
            )
        ]
    )


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_q2_2_round_trip_through_gateway(
    provider: str, invoker: RuntimeInvoker, opened: list[str], outputs: dict[str, str]
) -> None:
    result = invoker.invoke(
        {"action": "chat", "provider": provider, "prompt": "Reply with the single word: pong"},
        _session(opened),
    )
    body = result.body
    text = str(body.get("text") or "")
    _record(
        [
            Observation(
                "Q2.2",
                f"{provider}_round_trip",
                _status(_valid(result, "chat", "text") and body.get("gateway_status") == 200),
                "Runtime -> Entra token -> gateway -> provider -> back to caller",
                f"gateway_status={body.get('gateway_status')} text_chars={len(text)} "
                f"timings_ms={body.get('timings_ms')} client_ms={result.elapsed_ms} "
                f"error={body.get('error')}",
                _config(outputs),
            )
        ]
    )


def test_q2_2_gateway_rejects_unauthenticated_call_from_runtime(
    invoker: RuntimeInvoker, opened: list[str], outputs: dict[str, str]
) -> None:
    result = invoker.invoke(
        {"action": "chat_unauthenticated", "provider": "openai", "prompt": "ping"},
        _session(opened),
    )
    status: Status = (
        _status(result.body.get("gateway_status") == 401)
        if _valid(result, "chat_unauthenticated", "gateway_status")
        else "blocked"
    )
    _record(
        [
            Observation(
                "Q2.2",
                "unauthenticated_call_rejected",
                status,
                "a gateway call without a JWT is rejected with 401",
                _pick(result.body, "gateway_status", "error"),
                _config(outputs),
            )
        ]
    )


def test_q2_2_gateway_rejects_bad_tokens_directly(outputs: dict[str, str]) -> None:
    url = os.environ["GATEWAY_BASE_URL"].rstrip("/") + "/openai/v1/chat/completions"
    body = {"model": "any", "messages": []}
    no_token = httpx.post(url, json=body, timeout=15).status_code
    garbage = httpx.post(
        url, json=body, headers={"Authorization": "Bearer not-a-real-token"}, timeout=15
    ).status_code
    _record(
        [
            Observation(
                "Q2.2",
                "direct_bad_tokens_rejected",
                _status(no_token == 401 and garbage == 401),
                "missing and malformed tokens get 401 at the public gateway URL",
                f"no_token={no_token} garbage={garbage}",
                _config(outputs),
            )
        ]
    )


def test_q2_3_isolation_is_per_session(
    invoker: RuntimeInvoker, opened: list[str], outputs: dict[str, str]
) -> None:
    first, second = _session(opened), _session(opened)
    marker = uuid.uuid4().hex
    set_result = invoker.invoke({"action": "set_marker", "marker": marker}, first)
    same = invoker.invoke({"action": "get_marker"}, first)
    other = invoker.invoke({"action": "get_marker"}, second)
    controls_ok = (
        _valid(set_result, "set_marker", "marker")
        and set_result.body["marker"] == marker
        and _valid(same, "get_marker", "marker")
        and _valid(other, "get_marker", "marker")
    )
    same_ok = same.body.get("marker") == marker and (
        same.body.get("boot_id") == set_result.body.get("boot_id")
    )
    other_ok = other.body.get("marker") is None and (
        other.body.get("boot_id") != same.body.get("boot_id")
    )
    _record(
        [
            Observation(
                "Q2.3",
                "state_persists_within_session",
                _status(same_ok) if controls_ok else "blocked",
                "same runtimeSessionId reaches the same process and sees the marker",
                f"controls_ok={controls_ok} same_boot="
                f"{same.body.get('boot_id') == set_result.body.get('boot_id')} "
                f"marker_seen={same.body.get('marker') == marker}",
                _config(outputs),
            ),
            Observation(
                "Q2.3",
                "state_isolated_across_sessions",
                _status(other_ok) if controls_ok else "blocked",
                "a different runtimeSessionId gets a different environment and no marker",
                f"controls_ok={controls_ok} different_boot="
                f"{other.body.get('boot_id') != same.body.get('boot_id')} "
                f"marker={other.body.get('marker')!r}",
                _config(outputs),
            ),
        ]
    )


def test_q2_4_cold_warm_and_token_cache(
    invoker: RuntimeInvoker, opened: list[str], outputs: dict[str, str]
) -> None:
    session_id = _session(opened)
    cold = invoker.invoke({"action": "whoami"}, session_id)
    warm = invoker.invoke({"action": "whoami"}, session_id)
    chat = {"action": "chat", "provider": "anthropic", "prompt": "Reply ok"}
    first_chat = invoker.invoke(chat, session_id)
    second_chat = invoker.invoke(chat, session_id)
    whoami_ok = _valid(cold, "whoami") and _valid(warm, "whoami")
    chats_ok = _valid(first_chat, "chat", "token_cached") and _valid(
        second_chat, "chat", "token_cached"
    )
    first_timings = first_chat.body.get("timings_ms") or {}
    second_timings = second_chat.body.get("timings_ms") or {}
    _record(
        [
            Observation(
                "Q2.4",
                "cold_vs_warm_latency",
                _status(cold.body["boot_id"] == warm.body["boot_id"]) if whoami_ok else "blocked",
                "record cold (first call in a new session) vs warm client latency",
                f"cold_ms={cold.elapsed_ms} warm_ms={warm.elapsed_ms} "
                f"uptime_at_first_call_s={cold.body.get('uptime_s')}",
                _config(outputs),
            ),
            Observation(
                "Q2.4",
                "token_cached_across_invocations",
                _status(second_chat.body["token_cached"] is True) if chats_ok else "blocked",
                "the second call in a warm session reuses the MSAL-cached token",
                f"first_token_ms={first_timings.get('token')} "
                f"second_token_ms={second_timings.get('token')} "
                f"gateway_ms={second_timings.get('gateway')}",
                _config(outputs),
            ),
        ]
    )


def test_q2_4_idle_timeout_reclaims_session(
    invoker: RuntimeInvoker, opened: list[str], outputs: dict[str, str]
) -> None:
    if "AGENTCORE_POC_SLOW" not in os.environ:
        pytest.skip("set AGENTCORE_POC_SLOW=1 to run the idle-timeout probe (~3 minutes)")
    idle = int(outputs["runtime_idle_session_timeout_seconds"])
    session_id = _session(opened)
    before = invoker.invoke({"action": "set_marker", "marker": "idle-check"}, session_id)
    time.sleep(idle + 45)
    after = invoker.invoke({"action": "get_marker"}, session_id)
    controls_ok = (
        _valid(before, "set_marker", "marker")
        and before.body["marker"] == "idle-check"
        and _valid(after, "get_marker", "marker")
    )
    reclaimed = after.body.get("boot_id") != before.body.get("boot_id") and (
        after.body.get("marker") is None
    )
    _record(
        [
            Observation(
                "Q2.4",
                "idle_session_reclaimed",
                _status(reclaimed) if controls_ok else "blocked",
                f"after {idle + 45}s idle (configured timeout {idle}s) the same session id "
                "gets a fresh environment",
                f"controls_ok={controls_ok} "
                f"same_boot={after.body.get('boot_id') == before.body.get('boot_id')} "
                f"marker={after.body.get('marker')!r}",
                _config(outputs),
            )
        ]
    )


def _log_messages(logs: Any, prefix: str, start_ms: int) -> tuple[list[str], list[str]]:
    groups = [
        group["logGroupName"]
        for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=prefix)
        for group in page.get("logGroups", [])
    ]
    messages = [
        event["message"]
        for group in groups
        for page in logs.get_paginator("filter_log_events").paginate(
            logGroupName=group, startTime=start_ms
        )
        for event in page.get("events", [])
    ]
    return groups, messages


def test_q2_5_logs_hold_no_tokens_secrets_or_prompts(
    invoker: RuntimeInvoker, opened: list[str], outputs: dict[str, str]
) -> None:
    marker = f"prompt-marker-{uuid.uuid4().hex}"
    session_id = _session(opened)
    start_ms = int(time.time() * 1000) - 60_000
    chat = invoker.invoke(
        {"action": "chat", "provider": "anthropic", "prompt": f"Ignore {marker}. Reply ok."},
        session_id,
    )
    denied = invoker.invoke(
        {"action": "chat_unauthenticated", "provider": "openai", "prompt": marker}, session_id
    )
    logs = boto3.client("logs", region_name=outputs["aws_region"])
    prefix = f"/aws/bedrock-agentcore/runtimes/{outputs['agent_runtime_id']}"
    groups: list[str] = []
    messages: list[str] = []
    correlated: list[str] = []
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        groups, messages = _log_messages(logs, prefix, start_ms)
        correlated = [m for m in messages if f"session={session_id}" in m]
        if any("action=chat " in m for m in correlated) and any(
            "action=chat_unauthenticated" in m for m in correlated
        ):
            break
        time.sleep(15)
    secret = os.environ.get("GATEWAY_CALLER_CLIENT_SECRET", "")
    completion = str(chat.body.get("text") or "")
    checks = {
        "jwt": any(_JWT_SHAPE.search(message) for message in messages),
        "prompt": any(marker in message for message in messages),
        "client_secret": bool(secret) and any(secret in message for message in messages),
        "completion": len(completion) >= 12 and any(completion in m for m in messages),
    }
    leaks = [name for name, hit in checks.items() if hit]
    evidence_ok = (
        _valid(chat, "chat")
        and _valid(denied, "chat_unauthenticated")
        and any("action=chat " in m for m in correlated)
        and any("action=chat_unauthenticated" in m for m in correlated)
    )
    _record(
        [
            Observation(
                "Q2.5",
                "runtime_logs_redacted",
                _status(not leaks) if evidence_ok else "blocked",
                "agent log lines for this session reach CloudWatch (success and failure paths) "
                "and no log holds a JWT, the client secret, the prompt, or the completion",
                f"log_groups={groups} events={len(messages)} correlated={len(correlated)} "
                f"leaks={leaks}",
                _config(outputs),
            )
        ]
    )


def test_q2_6_no_container_resources_created(outputs: dict[str, str]) -> None:
    if not BEFORE_PATH.exists():
        pytest.fail(
            f"{BEFORE_PATH} missing: run python -m scripts.container_inventory before apply"
        )
    region = outputs["aws_region"]
    after = container_inventory(
        boto3.client("ecr", region_name=region), boto3.client("codebuild", region_name=region)
    )
    created = new_resources(load_inventory(BEFORE_PATH), after)
    _record(
        [
            Observation(
                "Q2.6",
                "no_ecr_or_codebuild_created",
                _status(not any(created.values())),
                "no ECR repository or CodeBuild project appeared between the pre-apply snapshot "
                "and now",
                f"created={created} totals={ {key: len(value) for key, value in after.items()} }",
                _config(outputs),
            )
        ]
    )
```

- [ ] **Step 5: Confirm that it skips cleanly without the flag**

Run: `.venv/bin/python -m pytest tests/integration/test_runtime_live.py -v`
Expected: 10 skipped (2 of them are the parametrized round-trip cases).

- [ ] **Step 6: Update the gates**

In `pyproject.toml`: `packages = ["agentcore_identity_poc", "agentcore_code_interpreter_poc", "agentcore_runtime_poc"]`.

In `README.md` "1. Local Verification" and `docs/runbook.md` "Phase 0", change the pytest line to measure all three packages:

```bash
.venv/bin/python -m pytest -m 'not integration' \
  --cov=agentcore_identity_poc --cov=agentcore_code_interpreter_poc --cov=agentcore_runtime_poc \
  --cov-report=term-missing --cov-fail-under=90
```

and add, after the Phase 1 Terraform lines:

```bash
(cd infra/terraform/modules/agentcore_agent_runtime && terraform init -backend=false -input=false >/dev/null && terraform test)
```

- [ ] **Step 7: Add the Phase 2 runbook section**

Append to `docs/runbook.md`:

````markdown
## Runtime + Gateway POC (Phase 2)

Operator-run, interactive terminal, fresh `aws sso login`. Three terminals.

Terminal A, the gateway simulation (keep it running):

```bash
set -a; source .env; set +a
.venv/bin/uvicorn agentcore_runtime_poc.gateway_sim.app:create_production_app --factory \
  --host 127.0.0.1 --port 8002
```

Terminal B, the tunnel (keep it running; copy the `https://....trycloudflare.com` URL):

```bash
cloudflared tunnel --url http://127.0.0.1:8002
```

Terminal C, build, deploy, secret, and live gate:

```bash
set -a; source .env; set +a
export GATEWAY_BASE_URL=<tunnel URL from terminal B>
curl -s "$GATEWAY_BASE_URL/healthz"                       # expect {"status":"ok"}
.venv/bin/python -m scripts.build_agent_zip
.venv/bin/python -m scripts.container_inventory             # Q2.6 baseline, before any apply
export TF_VAR_aws_region="$AWS_REGION" TF_VAR_aws_budget_name="$AWS_BUDGET_NAME" \
  TF_VAR_deploy_runtime=true TF_VAR_entra_tenant_id="$ENTRA_TENANT_ID" \
  TF_VAR_gateway_app_client_id="$GATEWAY_APP_CLIENT_ID" \
  TF_VAR_gateway_caller_client_id="$GATEWAY_CALLER_CLIENT_ID" \
  TF_VAR_gateway_base_url="$GATEWAY_BASE_URL" \
  TF_VAR_agent_openai_model="$AGENT_OPENAI_MODEL" TF_VAR_agent_anthropic_model="$AGENT_ANTHROPIC_MODEL"
terraform -chdir=infra/terraform/poc plan -out=phase2.tfplan   # TF.1: no ECR/CodeBuild
terraform -chdir=infra/terraform/poc apply phase2.tfplan
terraform -chdir=infra/terraform/poc plan -detailed-exitcode   # TF.2: exit 0
.venv/bin/python -m scripts.put_gateway_secret
.venv/bin/python -m scripts.invoke_runtime_agent --action chat --provider anthropic --prompt "Reply ok" --stop
AGENTCORE_POC_LIVE=1 .venv/bin/python -m pytest tests/integration/test_runtime_live.py -m integration -v -s
AGENTCORE_POC_LIVE=1 AGENTCORE_POC_SLOW=1 .venv/bin/python -m pytest \
  tests/integration/test_runtime_live.py -m integration -k idle -v -s
```

The live gate configures a 120 s idle timeout to keep the probe short. The service default
(15 minutes, per AWS docs) is not measured; record the configured value in the findings.

A quick tunnel gets a new URL each time it restarts. After a restart, export the new
`GATEWAY_BASE_URL` and `TF_VAR_gateway_base_url` and apply again (an environment-variable
change is an in-place runtime update). If `apply` fails on the runtime with an IAM "cannot
assume role" error right after the role was created, wait 30 s and apply again. Record this
as an IAM-propagation finding for the work module.

Observations go to `evidence/raw/runtime-observations.jsonl` (ignored).
````

- [ ] **Step 8: Run the full Phase 0 gate and commit**

Expected: every gate command exits 0 and total coverage is at least 90%.

```bash
git add src/agentcore_runtime_poc/inventory.py scripts/container_inventory.py \
  tests/test_container_inventory.py tests/integration/test_runtime_live.py \
  pyproject.toml README.md docs/runbook.md
git commit -m "feat: add Phase 2 live gate and extend the local gate to the runtime package"
```

---

### Task 10: Deploy, verify, and exercise Terraform lifecycle (OPERATOR-RUN)

**Files:** none are tracked. Local only: Terraform state and `evidence/raw/runtime-observations.jsonl`.

- [ ] **Step 1: Deploy and run the live gate**

Follow the Phase 2 runbook section in full. Record the resource list from the plan (TF.1) and the exit code of the second plan (TF.2).

- [ ] **Step 2: TF.3, a new zip means an in-place update**

```bash
terraform -chdir=infra/terraform/poc output -raw agent_runtime_version
# Make a visible, harmless code change, e.g. set _MAX_OUTPUT_TOKENS = 48 in runtime_agent/agent.py
.venv/bin/python -m scripts.build_agent_zip
# Terminal D: hold an invocation open across the deploy (prints session_id and boot_id when done)
.venv/bin/python -m scripts.invoke_runtime_agent --action sleep --seconds 110 --session-id "poc-inflight-$(uuidgen | tr -d -)"
# Terminal C, within a few seconds of starting terminal D:
time terraform -chdir=infra/terraform/poc apply
terraform -chdir=infra/terraform/poc output -raw agent_runtime_version
.venv/bin/python -m scripts.invoke_runtime_agent --action whoami --session-id <same session id as terminal D>
```

Expected: the plan shows `aws_s3_object.agent_zip[0]` updated and `module.agent_runtime[0].aws_bedrockagentcore_agent_runtime.this` **updated in place** (`~`), not replaced (`-/+`). The version number increases. Record:
- the wall-clock time of the apply (Q2.6);
- whether terminal D's in-flight invocation completed or failed during the deploy;
- whether the follow-up `whoami` on the same session returns the same `boot_id` (old environment kept) or a new one.

Afterwards, revert the code change and build and apply again.

- [ ] **Step 3: TF.4, attributes that force replacement (plan only; do not apply)**

```bash
terraform -chdir=infra/terraform/poc plan -var name_prefix=ci_rt_poc2 | grep -E 'must be replaced|forces replacement' | sort -u
terraform -chdir=infra/terraform/poc plan -var runtime_idle_session_timeout_seconds=300 | grep -E '~|must be replaced'
```

Record which resources and attributes force replacement and which update in place.

- [ ] **Step 4: TF.5, destroy, including from a partial state**

```bash
terraform -chdir=infra/terraform/poc destroy
terraform -chdir=infra/terraform/poc apply -target='aws_s3_object.agent_zip[0]'   # partial: bucket + zip only
terraform -chdir=infra/terraform/poc destroy
aws s3api head-bucket --bucket "ci-rt-poc-agent-code-$(aws sts get-caller-identity --query Account --output text)" \
  || echo "bucket gone"
aws bedrock-agentcore-control list-agent-runtimes --region "$AWS_REGION"
```

Expected: both destroys finish, the bucket is gone, and no `ci_rt_poc_agent` runtime is listed.

The service creates the runtime's CloudWatch log groups itself, so they are not in Terraform state and `destroy` leaves them. Delete and verify them:

```bash
PREFIX=/aws/bedrock-agentcore/runtimes/ci_rt_poc_agent-
for group in $(aws logs describe-log-groups --region "$AWS_REGION" --log-group-name-prefix "$PREFIX" \
    --query 'logGroups[].logGroupName' --output text); do
  aws logs delete-log-group --region "$AWS_REGION" --log-group-name "$group"
done
aws logs describe-log-groups --region "$AWS_REGION" --log-group-name-prefix "$PREFIX" --query 'length(logGroups)'
```

Expected: `0`. Record this as a TF finding: the work module must decide how to own these log groups (for example, pre-create them with retention, or clean them up outside Terraform).

Then remove the non-Terraform pieces:
- Stop terminals A and B.
- Delete the two Entra app registrations (or remove the caller secret) in the portal.
- Remove the `GATEWAY_*`, `OPENAI_API_KEY`, and `ANTHROPIC_API_KEY` lines from `.env`.

---

### Task 11: Findings write-up

**Files:**
- Create: `docs/runtime-findings.md`

- [ ] **Step 1: Write the findings doc**

Use this structure. Fill every row from `evidence/raw/runtime-observations.jsonl` and from Task 10's notes. Use error codes and numbers only; never raw payloads.

```markdown
# Runtime + Gateway Findings (Phase 2)

**Date:** <run date> · **Region:** <region> · **Deploy:** Terraform <version>, hashicorp/aws 6.66.0,
direct code (S3 zip), PYTHON_3_13, PUBLIC network mode · **SDK:** bedrock-agentcore 1.18.1

## Summary

<3–5 sentences: can Runtime host an agent whose only inference path is a JWT-protected external
gateway; what it costs in latency; what the work Terraform module must include.>

## Results

| Q | Check | Procedure | Expected | Observed | Config | Status |
|---|---|---|---|---|---|---|
| Q2.1 | egress_to_external_https | ... | ... | ... | ... | ... |
| ... one row per observation, then TF.1–TF.5 and the Q2.6 update time ... |

## Latency breakdown

| Segment | First call | Warm call |
|---|---|---|
| Client → Runtime (cold vs warm `whoami`) | | |
| Entra token (MSAL) | | |
| Gateway + provider | | |

## Implications for the work Terraform modules

- <e.g. no ECR or Bedrock permissions needed; version_id wiring for redeploys; replacement-forcing
  attributes from TF.4; IAM propagation retry; idle/max lifetime values; secret-shell pattern>

## Limits of these results

- The gateway is a simulation on a public tunnel. This proves Runtime can reach and authenticate
  to an external JWT-protected gateway in PUBLIC mode. It does not prove compatibility with the
  real gateway's schema, network placement (a private gateway would need VPC mode), or auth
  details.
- The caller was a local SigV4 script, not the unified API service. User-context propagation
  (future Phase 3) is untested. Note for Phase 3: `aws_bedrockagentcore_agent_runtime` has
  `authorizer_configuration.custom_jwt_authorizer` for inbound JWT auth; it was not used here.
```

- [ ] **Step 2: Safety check and commit**

```bash
.venv/bin/python -m pytest tests/test_repository_safety.py -q
git add docs/runtime-findings.md
git commit -m "docs: record Runtime + gateway Phase 2 findings"
```
