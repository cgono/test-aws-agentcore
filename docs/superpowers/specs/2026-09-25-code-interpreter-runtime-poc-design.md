# AgentCore Code Interpreter + Runtime POC — Design

**Date:** 2026-09-25
**Status:** draft, pending Codex review and human approval
**Relationship to existing work:** independent of the AgentCore Identity POC
(`src/agentcore_identity_poc/`). Shares this repo, its conventions, and its
AWS account/region and Entra tenant. Integration with Identity's OBO flow is
explicitly deferred — see "Out of scope" below.

## Goal

Verify and understand how two more AWS Bedrock AgentCore capabilities work,
through live testing against real AWS (and, for Phase 2, real Entra and real
LLM providers behind a simulated gateway):

1. **Code Interpreter** — AWS's managed code-execution sandbox.
2. **Runtime** — AWS's managed hosting for agent code, with the constraint
   that inference must be routed through the user's employer's centralized
   LLM gateway (which proxies OpenAI and Anthropic behind AD-issued JWT
   auth), not through Bedrock or the Anthropic/OpenAI APIs directly.

This is an understanding-focused POC, not an adoption decision. Unlike the
Identity POC, it does not use numbered hypotheses, sanitized JSONL evidence,
or a final `assessment.md` go/no-go. Each phase instead has a short list of
numbered verification questions and ends in a findings write-up.

## Non-goals / out of scope

- **Identity integration.** Phase 2's Runtime agent does not fetch a
  per-user Entra/Google credential via the Identity POC's OBO flow. It uses
  its own client-credentials JWT to call the gateway simulation. Integrating
  Runtime with Identity's OBO flow is valuable future work, not this POC.
- **Production caller topology.** The user's real target architecture is:
  UI → (JWT auth) → a unified API service → that service invokes AgentCore
  Runtime, passing enough context for Runtime to act with the correct user
  identity. This POC does **not** build or test that unified API service or
  the "Runtime receives user context from its caller" problem. Phase 2
  invokes the Runtime agent directly from a local script — the simplest
  possible caller — to first prove the Runtime-hosting and
  gateway-routing mechanics work at all.
  - **Future Phase 3 (not part of this POC):** once Phase 1 and Phase 2
    are proven, a follow-up phase should test a minimal stand-in for the
    unified API service invoking AgentCore Runtime with propagated user
    identity/credentials, so Runtime actions carry real user context. This
    is recorded here so it isn't lost, not designed yet.
- **Code Interpreter invoked from Runtime.** The user's real integration
  targets for Code Interpreter are agents running in Temporal (now) and
  Databricks (later) — both external orchestrators outside any AWS-hosted
  agent runtime. Phase 1 therefore verifies Code Interpreter standalone,
  invoked via plain boto3/SDK from outside an AWS execution context (i.e.
  from this repo's local scripts/tests) — which already matches the
  Temporal/Databricks calling pattern better than testing it as a Runtime
  tool would.
- **PingOne/AD FS or other non-Entra identity providers** — not available,
  same limitation as the Identity POC's H5.

## Repo layout

New packages, siblings to the existing `agentcore_identity_poc`:

```
src/
  agentcore_identity_poc/        (existing, untouched)
  agentcore_code_interpreter_poc/
  agentcore_runtime_poc/
    gateway_sim/                 # mock centralized LLM gateway
    runtime_agent/                # BedrockAgentCoreApp entrypoint
docs/
  code-interpreter-findings.md   # Phase 1 output
  runtime-findings.md            # Phase 2 output
  superpowers/plans/2026-09-25-code-interpreter-runtime-poc.md  # (next step)
```

Work happens on a new branch, `feature/agentcore-code-interpreter-runtime-poc`,
following the existing project's worktree convention
(`.worktrees/agentcore-code-interpreter-runtime-poc`).

Shared conventions reused as-is: `.env`-based secrets (never committed),
`tests/test_repository_safety.py` (extended — see Safety below), the
Phase 0 local gate (`pytest -m 'not integration'` with coverage, `ruff`,
`mypy`, repo-safety, `git diff --check`), and `pytest -m integration` live
gates run manually by an operator with a fresh `aws sso login`.

## Phase 1: Code Interpreter

**Package:** `src/agentcore_code_interpreter_poc/`

Built on `bedrock_agentcore.tools.code_interpreter_client` (`CodeInterpreter`
class and `code_session` context manager), already available via the
existing `bedrock-agentcore==1.18.1` dependency — no new dependency needed
for this phase.

**Verification questions** (Q1.1, Q1.2, ... — numbered for traceability in
the findings doc, not formal hypotheses):

- Q1.1 Session lifecycle: does a session persist state (variables, files)
  across multiple `execute_code`-style calls? How long does an idle session
  live before AWS reclaims it?
- Q1.2 Language support: confirm Python; check what else is exposed
  (JavaScript/TypeScript, shell) and whether switching languages mid-session
  is possible or requires a new session.
- Q1.3 File I/O: write a file in one call, read it back in a later call in
  the same session; confirm behavior across session boundaries (should not
  persist).
- Q1.4 Network egress from inside the sandbox: can executed code reach the
  public internet by default, or is it network-isolated? This determines
  whether Code Interpreter could ever be used to call an LLM/gateway
  directly from inside executed code, versus only ever being driven as a
  tool by an external caller.
- Q1.5 Failure modes: timeout behavior for long-running code, error
  surfacing for exceptions/syntax errors, any resource limits observed
  (memory, CPU, output size).
- Q1.6 IAM: minimal execution role/permissions actually required to create
  a session and execute code, invoked as an external caller (not from
  inside an AWS-hosted agent) — this is the shape a Temporal worker's AWS
  credentials would need.

**Mechanics:**
- Local (non-integration) tests mock the boto3 `bedrock-agentcore-data`
  client — no live calls, run in the Phase 0 gate.
- A `pytest -m integration` live gate (new file,
  `tests/integration/test_code_interpreter_live.py`) exercises Q1.1–Q1.6
  against real AWS, run manually behind an env flag
  (`AGENTCORE_POC_LIVE=1`, matching the existing convention). No
  `evidence/*.jsonl` — the live test prints/logs observations that get
  written up in the findings doc by the operator.
- **Output:** `docs/code-interpreter-findings.md` — one short section per
  verification question with the observed answer.

## Phase 2: Runtime + centralized LLM gateway simulation

**Package:** `src/agentcore_runtime_poc/`

### Component 1: gateway simulation (`gateway_sim/`)

A FastAPI app, same operational pattern as the Identity POC's
`resource_api`/`web.py` (run locally with `uvicorn`, exposed via a
`cloudflared` tunnel for a real public HTTPS URL). It exists to give
Runtime something realistic to call — its own correctness is not what's
under test.

- Requires `Authorization: Bearer <JWT>` on every request.
- Validates the JWT against a **new** Entra client-credentials app
  registration in the existing tenant, with a dedicated scope (e.g.
  `gateway.invoke`). Reuses this repo's existing JWT validation code
  (`jwt_validation.py` / `audience_variants()` helper) where the claim
  shapes line up; client-credentials tokens differ from the Identity POC's
  delegated user tokens, so validation logic will need review, not a
  blind copy.
- Exposes two proxy routes approximating the real gateway's shape (exact
  schema unknown — see Open Items): `/openai/v1/chat/completions` and
  `/anthropic/v1/messages`, each forwarding the request body to the real
  OpenAI/Anthropic APIs using dev keys from `.env`, and returning the real
  response unmodified.

### Component 2: Runtime-hosted agent (`runtime_agent/`)

Built on `bedrock_agentcore.runtime.app.BedrockAgentCoreApp`. A minimal
entrypoint that, per invocation:
1. Acquires a client-credentials JWT via MSAL (same tenant/app as gateway
   simulation expects).
2. Calls the gateway simulation's proxy route with that JWT instead of
   calling any Bedrock/Anthropic/OpenAI SDK directly.
3. Returns the LLM response back through Runtime's response contract.

**Deployment:** AWS's official `bedrock-agentcore-starter-toolkit`
(`agentcore configure` / `agentcore launch`) — the AWS-intended path,
handles the Docker build and ECR push, and gets a working baseline faster
than hand-rolling boto3 control-plane calls. The findings doc records what
the toolkit does under the hood (IAM role it creates, ECR repo, control-plane
API calls) so the "understand how it works" goal is still met even though
we're not hand-rolling it.

**Invocation for this POC:** a local script (`scripts/invoke_runtime_agent.py`
or similar) calls the deployed Runtime agent directly via its invoke API —
the simplest possible caller, deliberately not simulating the real unified
API service (see "Out of scope" / Future Phase 3).

**Verification questions:**
- Q2.1 Can Runtime reach an arbitrary external HTTPS endpoint at all, i.e.
  is egress locked to AWS/Bedrock or genuinely open to the internet?
- Q2.2 Does the full round trip work: invoke Runtime → Runtime fetches a
  JWT → calls gateway simulation → gateway calls the real LLM → response
  flows back to the caller?
- Q2.3 Session isolation between concurrent invocations (two overlapping
  calls don't see each other's state).
- Q2.4 Cold-start latency, and whether/how Runtime scales to zero between
  invocations.
- Q2.5 How logs and errors surface (CloudWatch? Runtime-specific
  observability?) — relevant for debugging a real deployment later.

**Output:** `docs/runtime-findings.md`.

## Safety and secrets

- New `.env` entries: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` (dev keys,
  gateway-sim only, never committed), plus a new Entra client ID/secret for
  the gateway simulation's app registration.
- Extend `tests/test_repository_safety.py`'s credential-shaped-value
  patterns to also catch OpenAI (`sk-...`) and Anthropic API key shapes, so
  an accidental paste into a tracked file is caught the same way existing
  secrets are.
- No raw LLM prompts/completions or JWTs get written to any tracked file or
  findings doc — findings describe *behavior observed*, not raw
  request/response payloads.

## Cost and cleanup

- Cost is small: a handful of real LLM calls during verification, plus
  standard AgentCore Runtime/Code Interpreter usage charges. No resources
  are left running idle by design — Runtime scales to zero between
  invocations, and Code Interpreter sessions are short-lived, unlike the
  Identity POC's long-running tunnels.
- Cleanup: extend `scripts/provision_agentcore.py` (or add a sibling
  script) to delete the Runtime resource, its ECR repository/image, and its
  IAM execution role, following the existing preview →
  `--apply --confirm <name>` pattern.

## Dependencies

Add to `pyproject.toml`: `bedrock-agentcore-starter-toolkit`, `openai`,
`anthropic`. Reuse existing `msal`, `PyJWT[crypto]`, `fastapi`, `uvicorn`,
`boto3`, `typer`.

## Open items

- **Regional availability.** Confirm AgentCore Runtime and Code Interpreter
  are available in `ap-southeast-1` for this account before writing more
  code than a smoke-test call — first task of implementation, not assumed
  here.
- **Local Docker availability**, required by the starter toolkit's image
  build step.
- **Real gateway schema is unknown** beyond "OpenAI + Anthropic proxy,
  AD-issued JWT auth." The gateway simulation's routes
  (`/openai/v1/chat/completions`, `/anthropic/v1/messages`) are a
  best-effort approximation of a typical internal gateway shape, not a
  confirmed spec — called out explicitly in `runtime-findings.md` as an
  assumption, not a validated fact.
- **Client-credentials JWT validation** reuses only what applies from the
  existing `jwt_validation.py`; the claim shapes for an app-only
  (client-credentials) token differ from a delegated user token, so this
  needs its own review during implementation, not a copy-paste.
