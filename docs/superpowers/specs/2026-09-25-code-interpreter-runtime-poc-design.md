# AgentCore Code Interpreter + Runtime POC — Design

**Date:** 2026-09-25
**Status:** draft, incorporates Codex review, pending human approval
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
- Q1.3 File I/O: two parts. (a) Internal persistence — write a file in one
  call, read it back in a later call in the same session; confirm it does
  not survive into a new session. (b) Caller data path — upload a file
  from the external caller into a session and download a file the session
  produced back to the caller. (b) is the one that actually matters for
  Temporal/Databricks, which will need to move data in and out, not just
  rely on in-sandbox persistence.
- Q1.4 Network egress from inside the sandbox: can executed code reach the
  public internet? Explicitly test both the **built-in/default**
  interpreter and, if time allows, a **custom** interpreter with a
  different network mode — AWS supports more than one network
  configuration here, so a single negative result only describes the
  configuration tested, not Code Interpreter categorically. State which
  configuration produced which result.
- Q1.5 Failure modes: timeout behavior for long-running code, error
  surfacing for exceptions/syntax errors, any resource limits observed
  (memory, CPU, output size). Distinguish **session TTL**
  (`sessionTimeoutSeconds`, a fixed lifetime regardless of activity) from
  **per-execution timeout** (how long a single `execute_code`-style call
  is allowed to run) — these are different limits and should be measured
  separately.
- Q1.6 IAM: create a **scoped-down IAM policy** for the external caller
  (the identity that starts sessions and executes code — the shape a
  Temporal worker would assume) and confirm the minimal action set it
  needs, separately from whatever execution role AWS attaches to the
  sandbox itself. Testing with broad SSO/admin credentials cannot answer
  this question — the whole point is finding the minimal caller policy.

**Mechanics:**
- Local (non-integration) tests mock the boto3 `bedrock-agentcore` client
  (data-plane operations like `start_code_interpreter_session`,
  `invoke_code_interpreter`, `stop_code_interpreter_session`) — no live
  calls, run in the Phase 0 gate.
- A `pytest -m integration` live gate (new file,
  `tests/integration/test_code_interpreter_live.py`) exercises Q1.1–Q1.6
  against real AWS, run manually behind an env flag
  (`AGENTCORE_POC_LIVE=1`, matching the existing convention). Every test
  stops its session in a `finally`/context-manager block — no session is
  left running past the test that created it. No `evidence/*.jsonl` — the
  live test prints/logs observations that get written up in the findings
  doc by the operator.
- **Output:** `docs/code-interpreter-findings.md` — for each verification
  question: the procedure run, the expected behavior, the observed
  result, the exact configuration/interpreter-identifier/SDK version used,
  and a status (pass / fail / blocked).

## Phase 2: Runtime + centralized LLM gateway simulation

**Package:** `src/agentcore_runtime_poc/`

### Component 1: gateway simulation (`gateway_sim/`)

A FastAPI app, same operational pattern as the Identity POC's
`resource_api`/`web.py` (run locally with `uvicorn`, exposed via a
`cloudflared` tunnel for a real public HTTPS URL). It exists to give
Runtime something realistic to call — its own correctness is not what's
under test.

- Requires `Authorization: Bearer <JWT>` on every request. Authorization is
  **application (client-credentials), not delegated**: define a
  gateway-resource app registration with an **app role** (e.g.
  `Gateway.Invoke`), assign that role to a separate caller app registration
  with admin consent, and have the caller request a token for
  `<gateway-resource-app-id>/.default` — not a delegated scope. The gateway
  validates issuer, the gateway-resource's own audience, token version, and
  that `roles` contains `Gateway.Invoke`; it explicitly rejects tokens with
  no `roles` claim and tokens that look delegated (carry a `scp` claim
  instead of `roles`, or — if checked — `idtyp` other than `app`). This is
  a distinct authorization model from the Identity POC's delegated
  user-OBO tokens, so it's new logic, not a reuse of `jwt_validation.py`'s
  `audience_variants()` path as-is — only the low-level "verify a JWT
  signature against Entra's JWKS" plumbing is shared.
- **The mock's own correctness is part of the security boundary**, since
  it holds real provider API keys and is reachable from the public
  internet via the tunnel. It must: forward only to fixed, hardcoded
  upstream URLs (no caller-controlled destination); never leak the
  upstream API key back to the caller in any response, header, redirect,
  or error message; enforce a small model allowlist and a max
  output-token cap per request; enforce request size and concurrency
  limits; use bounded timeouts with no unbounded retry; and start
  non-streaming-only (streaming is a later extension, not this POC).
  Upstream error responses are relayed with their status code and a
  sanitized body (no upstream headers that might carry key material
  echoed back).
- Exposes two proxy routes approximating the real gateway's shape (exact
  schema unknown — see Open Items): `/openai/v1/chat/completions` and
  `/anthropic/v1/messages`, each forwarding the request body to the real
  OpenAI/Anthropic APIs using dev keys from `.env`, and returning the real
  response unmodified (subject to the sanitization above). Both routes get
  exercised in Phase 2 verification — not just one provider.

### Component 2: Runtime-hosted agent (`runtime_agent/`)

Built on `bedrock_agentcore.runtime.app.BedrockAgentCoreApp`. A minimal
entrypoint that, per invocation:
1. Acquires a client-credentials JWT via MSAL (same tenant/app as gateway
   simulation expects).
2. Calls the gateway simulation's proxy route with that JWT instead of
   calling any Bedrock/Anthropic/OpenAI SDK directly.
3. Returns the LLM response back through Runtime's response contract.

**Secret delivery to the deployed container:** the Entra client secret
(and any other secret the deployed agent needs) is stored in AWS Secrets
Manager, not baked into the container image or read from a local `.env` —
a local `.env` only makes sense for code running on the operator's
machine, not code running inside Runtime. The Runtime execution role gets
a narrowly-scoped `secretsmanager:GetSecretValue` grant on that one
secret. The container build/upload context explicitly excludes `.env`,
`.poc-state.json`, and any Identity-POC state files (e.g. via
`.dockerignore`), and redaction requirements from the existing repo-safety
test extend to whatever this agent logs — CloudWatch log lines,
exceptions, and traces must not contain the JWT, the client secret, or raw
LLM request/response bodies.

**Deployment:** AWS currently labels the standalone Python
`bedrock-agentcore-starter-toolkit` as legacy in favor of the AgentCore
CLI; the toolkit's own default launch path already builds via CodeBuild
rather than requiring a local Docker daemon. Concretely deciding which
tool and which build mode (CodeBuild-backed vs. local Docker) to use is an
early implementation task, not assumed here — whichever is chosen, the
findings doc records what it does under the hood (IAM role(s) it creates,
ECR repo, any CodeBuild/S3 resources, control-plane API calls) so the
"understand how it works" goal is met regardless of which path is picked.

**Invocation for this POC:** a local script (`scripts/invoke_runtime_agent.py`
or similar) calls the deployed Runtime agent directly via its invoke API,
authenticating with the caller's own AWS credentials (IAM/SigV4) —
**this inbound AWS-level authorization is separate from the agent's own
outbound Entra client-credentials call to the gateway**; the two must not
be conflated in the findings doc. This is the simplest possible caller,
deliberately not simulating the real unified API service (see "Out of
scope" / Future Phase 3). The invocation payload/response format (what
JSON shape the script sends and what Runtime's contract requires back) is
documented as part of Q2.2's findings.

**Verification questions:**
- Q2.1 Can Runtime reach an arbitrary external HTTPS endpoint at all, i.e.
  is egress locked to AWS/Bedrock or genuinely open to the internet, under
  the network configuration this POC actually deploys (default vs. a VPC
  configuration)? A positive result proves *this configuration* can reach
  an external HTTPS gateway — it does not by itself prove compatibility
  with the real employer gateway's network placement (e.g. if that
  gateway is only reachable from a private network), and the findings doc
  states that limit explicitly.
- Q2.2 Does the full round trip work: invoke Runtime → Runtime fetches a
  JWT → calls gateway simulation → gateway calls the real LLM → response
  flows back to the caller? Exercise **both** the OpenAI and Anthropic
  proxy routes, and include at least one **negative-auth** case (missing
  or invalid JWT correctly rejected by the gateway simulation, not
  silently passed through).
- Q2.3 Isolation is **per session**, not per invocation: AgentCore Runtime
  sessions are addressed by a `runtimeSessionId`, and invocations sharing
  one session share an execution environment while invocations in
  different sessions do not. Test both: state set in one session is
  visible to a later invocation in the *same* session, and is *not*
  visible from a *different* session, using explicit state markers (not
  inference from timing).
- Q2.4 Lifecycle: Runtime does not necessarily tear down between
  invocations — sessions have an idle-timeout setting (verify the default,
  commonly on the order of minutes, not immediate scale-to-zero) before
  AWS reclaims them. Measure cold-start latency (first invocation of a
  fresh session) separately from warm-invocation latency, and separately
  again from the Entra-token-fetch + gateway + LLM latency inside the
  round trip — these should be reported as distinct numbers, not one
  blended "Runtime latency."
- Q2.5 How logs and errors surface (CloudWatch? Runtime-specific
  observability?) — relevant for debugging a real deployment later, and
  where the redaction requirement above needs to be enforced in practice.

**Output:** `docs/runtime-findings.md`, in the same structured format as
Phase 1: procedure, expected behavior, observed result,
configuration/version, status.

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

- Reuse the existing named-AWS-Budget preflight check from the Identity
  POC before provisioning anything in this POC — don't skip that guard
  just because it's a new package.
- Cost is small: a handful of real LLM calls during verification, plus
  standard AgentCore Runtime/Code Interpreter usage charges, plus whatever
  build-time resources the chosen deployment path uses (e.g. CodeBuild
  minutes). Code Interpreter sessions are short-lived; Runtime sessions
  persist for their idle-timeout window (see Q2.4), not indefinitely, but
  are not instant scale-to-zero either — cleanup must not assume no
  billable resource is ever left running between sessions.
- Cleanup inventory, tracked explicitly (not just "Runtime/ECR/one role"):
  the Runtime resource itself, its ECR repository/image, its IAM execution
  role, any CodeBuild project/artifacts or S3 buckets the chosen
  deployment path created, the Secrets Manager secret holding the Entra
  client secret, CloudWatch log groups, and any custom Code Interpreter
  resource created for Q1.4's custom-network test. Also revoke/delete the
  new Entra app registrations and roles, and stop the local gateway
  simulation + `cloudflared` tunnel.
- Cleanup must work even after a **partial** deployment failure (e.g. the
  build succeeded but `agentcore launch` didn't finish) — extend
  `scripts/provision_agentcore.py` (or add a sibling script) with the
  existing preview → `--apply --confirm <name>` pattern, but don't assume
  every resource in the inventory above will always exist.

## Dependencies

Add to `pyproject.toml`, pinned to exact versions at implementation time
(matching this repo's existing exact-pin convention): a deployment
dependency for whichever path Runtime's "Deployment" section above settles
on, plus `openai` and `anthropic`. Reuse existing `msal`, `PyJWT[crypto]`,
`fastapi`, `uvicorn`, `boto3`, `typer`. Extend `pyproject.toml`'s coverage
target and mypy `packages` list to include the two new packages, not just
`agentcore_identity_poc`.

## Open items

- **Regional availability.** Confirm AgentCore Runtime and Code Interpreter
  are available in `ap-southeast-1` for this account before writing more
  code than a smoke-test call — first task of implementation, not assumed
  here.
- **Deployment tool/build-mode choice** for Runtime (AgentCore CLI vs. the
  legacy starter toolkit; CodeBuild-backed vs. local-Docker build) — decide
  this early, since it determines whether local Docker is even needed and
  what the cleanup inventory looks like.
- **Real gateway schema is unknown** beyond "OpenAI + Anthropic proxy,
  AD-issued JWT auth." The gateway simulation's routes
  (`/openai/v1/chat/completions`, `/anthropic/v1/messages`) are a
  best-effort approximation of a typical internal gateway shape, not a
  confirmed spec — called out explicitly in `runtime-findings.md` as an
  assumption, not a validated fact. A successful Phase 2 run proves
  Runtime *can* host an agent that authenticates to and routes through an
  external JWT-protected gateway; it does not by itself prove
  compatibility with the real employer gateway's actual schema, network
  placement, or auth details.
- **Client-credentials JWT validation and app-role authorization** for the
  gateway simulation build on, but are not a copy-paste of, the existing
  `jwt_validation.py` — only low-level signature/JWKS verification is
  shared; the app-role/`.default`/audience checks described under
  "Component 1" above are new logic specific to this POC.
- **Scoped IAM policy for Code Interpreter's external caller (Q1.6)** and
  **Runtime's execution role** are not fully enumerated here; deriving the
  minimal action sets is implementation work, informed by AWS's own
  documented permission requirements for each API used.
