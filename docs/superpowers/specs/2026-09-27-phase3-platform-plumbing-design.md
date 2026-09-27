# Phase 3a: Platform Plumbing POC (Claude Agent SDK) — Design

**Date:** 2026-09-27
**Status:** draft, approved section by section in chat, Codex adversarial review applied
(see "Review changes" at the end), pending human review
**Builds on:** Phase 1 (`docs/code-interpreter-findings.md`), Phase 2 (`docs/runtime-findings.md`),
and the earlier Identity POC (`docs/assessment.md`). All Phase 2 AWS resources and Entra apps were
destroyed, so Phase 3a sets up everything again.

## Goal

Build a small copy of the work platform so the user can understand how its parts connect:

> caller → **unified API** → agent in **AgentCore Runtime** → agent writes code → **AgentCore Code
> Interpreter** runs it. Inference goes only through the **central LLM gateway**. User files live in
> an S3 bucket behind a **Resource Hub** that allows each user only their own files.

The demo is a small "deep research" task. It also runs a benchmark that answers a real work question:
**how fast is file access through the Resource Hub, and is Mirage fast enough?**

This is an understanding POC, not an adoption decision. It ends in a findings write-up
(`docs/phase3-findings.md`) that answers the verification questions below.

## What the user said

- Phase 3 is a miniature of the work plumbing.
- The unified API invokes agents. At work these can be in Temporal, Databricks, or AgentCore Runtime.
- Agents generate code and run it in a sandbox, ideally AgentCore Code Interpreter.
- All inference goes through the corporate LLM gateway. It supports the Anthropic Messages API with
  SSE streaming and `tools`.
- Each user has a file workspace: a segregated prefix in one S3 bucket. The **Resource Hub** calls S3
  with boto3. Its only value is authn/authz, so users see only their own files. Users upload files
  freely and then ask questions about them, so agents may `grep`/`rg` across many files. File size at
  work can be several GB.
- Work is discussing **Mirage** (<https://github.com/strukto-ai/mirage>) to mount the Resource Hub as a
  file system. The user is concerned about its performance.
- At work the agent authenticates to the Resource Hub with a **service token plus the user's token**.
  The purpose of the user token is to make it hard for an agent to read another user's files.
- The solution must be neutral across agent frameworks. Priority: **Claude Agent SDK**, then
  **LangChain Deep Agents**, then **DeepSeek Harness** (<https://github.com/deepseek-ai/deepseek-harness>).
- Deploys should need only "upload zip to S3" plus "update agent". No `terraform apply` per release.
- At work the application code and the infra (Terraform) code are in different repos. The infra repo
  can only call Terraform modules owned by the Cloud Team, and has its own plan/apply pipelines.

## Decisions made in brainstorming

| # | Decision |
|---|---|
| D1 | Split Phase 3: **3a** = all plumbing + Claude Agent SDK (this spec). **3b** = Deep Agents on the same plumbing. **3c** = check DeepSeek Harness fit, then build. |
| D2 | Replace the raw user token with a **session grant** signed by the unified API (KMS). Keep one **raw-token expiry test** to show the failure the grant avoids. |
| D3 | Use **AgentCore Identity**: Runtime inbound JWT authorizer; OAuth2 credential provider (Entra client credentials, `M2M`) for the agent's service token; workload identity. |
| D4 | Research data = **World Bank API + seed files** in the user workspace. User A: Southeast Asia. User B: Central America. |
| D5 | Neutral layer = **approach A**: one framework-neutral Python platform library with one tool contract, plus a thin adapter per framework. A central MCP server (for example behind AgentCore Gateway) is later work. |
| D6 | Run a **full file-access benchmark** of five methods, including Mirage SDK, Mirage FUSE, and a Resource Hub search endpoint. File sizes go up to **5 GB**. |
| D7 | Resource Hub runs on **Lambda + function URL**. Unified API and LLM gateway sim run locally (gateway behind a cloudflared tunnel, as in Phase 2). |
| D8 | Resource Hub serves large files with **HTTP Range reads** (chunks of 4 MB or less), not streaming or presigned URLs. |

## Assumptions (not confirmed by the user)

- A1. In 3a the unified API calls only AgentCore Runtime. Temporal and Databricks callers are out of scope.
- A2. "Done" = one live run for each of two test users that produces a chart in that user's own
  workspace, the isolation tests pass, and the benchmark table exists.
- A3. Real work gateway behavior that the simulator copies: Anthropic Messages passthrough with SSE and
  tools, app-role JWT auth. Anything more is not simulated.

## Non-goals

- Temporal and Databricks callers.
- Deep Agents and DeepSeek Harness agents (3b, 3c).
- A central MCP tool server or AgentCore Gateway (the MCP product).
- Mirage with its native S3 resource and scoped S3 credentials (a presigned/credential-vending
  Resource Hub). The Resource Hub passes bytes through, as at work.
- Code Interpreter file-system mounts. The agent copies files in and out.
- **Large uploads through the Resource Hub.** A buffered Lambda function URL accepts at most 6 MB per
  request, so 3a user uploads through the Resource Hub are limited to 4 MB per file. Large benchmark
  files are seeded straight to S3. The findings must state that a byte-passthrough Resource Hub on
  Lambda cannot take multi-GB uploads without chunked multipart through the Hub, response/request
  streaming, or presigned upload URLs, and that 3a does not test any of these.
- Streaming the agent's answer to the caller. The Runtime returns one JSON result.
- A web UI. A CLI acts as the UI.
- Production hardening beyond what the tests need (WAF, rate limits, multi-region).

## Architecture

```
 caller CLI ("UI")                                   local
   │  user's Entra token (User A or User B)
   ▼
 Unified API (FastAPI)                               local
   │  checks user JWT → signs session grant (KMS ES256)
   │  invokes Runtime over HTTPS
   │     Authorization: Bearer <unified API service token>
   │     X-Amzn-Bedrock-AgentCore-Runtime-Custom-Grant: <grant>
   │     X-Amzn-Bedrock-AgentCore-Runtime-Session-Id: <sid>
   ▼
 AgentCore Runtime "poc3_research" (zip, PYTHON_3_13)   AWS
   │  inbound JWT authorizer (AgentCore Identity)
   │  service token from Identity (Entra client credentials, M2M)
   ├──► LLM gateway sim (local, via tunnel): Anthropic SSE + tools
   ├──► Resource Hub (Lambda function URL) ──► S3 workspace bucket, users/<oid>/...
   ├──► World Bank API (public internet, allow-listed host)
   └──► AgentCore Code Interpreter (custom, SANDBOX network)

 AgentCore Runtime "poc3_bench" (zip) ──► Resource Hub   (benchmark only, no LLM)
```

### Components

| Component | Runs | Responsibility |
|---|---|---|
| Caller CLI | local | Signs in User A or User B (Phase 1 Entra test users). Uploads seed files in user mode. Calls the unified API. Prints the result. |
| Unified API | local, FastAPI | Checks the user token. Creates the session ID. Signs the grant. Gets its own service token. Invokes the Runtime. Routes `/research` → `poc3_research` and `/bench` → `poc3_bench`. |
| Research agent | Runtime `poc3_research` | Claude Agent SDK. Uses only the platform tools, served as an in-process SDK MCP server. |
| Platform library `agent_platform` | inside each agent zip | Framework-neutral tool contract and clients (Resource Hub, Code Interpreter, token provider). |
| Resource Hub | Lambda + function URL (auth type `NONE`, JWT checked in code) | Authn/authz and S3 access for `users/<oid>/`. List, read (with Range), write, search. |
| LLM gateway sim | local + cloudflared tunnel | Phase 2 simulator, extended to pass Anthropic SSE streaming and `tools` through. |
| Code Interpreter | AgentCore, custom, `SANDBOX` network | Runs the chart code. No internet. `SANDBOX` mode still allows S3 calls that the execution role permits, so its role has **no S3 permissions at all**; a live negative test runs `boto3` S3 calls from inside the sandbox and expects them to fail. matplotlib is preinstalled. |
| Benchmark agent | Runtime `poc3_bench` | Runs the five file-access methods from inside Runtime. |
| Admin/seed script | local | Seeds benchmark workspaces straight to S3 (test fixtures). |

### Repository layout (one repo, two roles)

- `infra/terraform/` plays the **infra repo**. It owns: code bucket, workspace bucket, KMS key,
  Resource Hub Lambda (with a placeholder zip), both runtimes, execution roles, the Identity OAuth2
  credential provider, the Code Interpreter, and the log groups (with retention).
- `scripts/deploy_agent.py` plays the **app CD pipeline**. It deploys agent code and the Resource Hub
  Lambda code. It never changes Terraform-owned attributes.
- New Python package `src/agentcore_platform_poc/` with sub-packages `agent_platform/`,
  `resource_hub/`, `unified_api/`, `research_agent/`, `bench_agent/`. The Phase 2 gateway sim in
  `src/agentcore_runtime_poc/gateway_sim/` is extended in place.

## Deploy model (no Terraform per release)

**Runtime module change:** the runtime resource gets
`lifecycle { ignore_changes = [agent_runtime_artifact] }`. Terraform creates the runtime once from a
placeholder zip. After that, the CD script owns the artifact. Terraform still owns role, network,
environment variables, authorizer, header allow-list, and lifecycle settings.

**S3 key ownership (no shared keys):**

| Key | Owner |
|---|---|
| `bootstrap/<component>.zip` | Terraform (the placeholder zip, written once) |
| `releases/<component>.zip` (versioned) | CD script only. Terraform never declares an object at this key. |

The execution roles may read both keys. `terraform destroy` needs `force_destroy` on the code bucket
because CD-owned versions exist; the findings record that.

**`scripts/deploy_agent.py <research|bench|resource-hub>`:**

1. Build the zip (same packaging as Phase 2; linux/arm64 wheels).
2. `s3 put-object` to `releases/<component>.zip` in the code bucket. Record the new `VersionId`.
3. For a runtime: `get-agent-runtime` → copy every field that `update-agent-runtime` accepts → change
   only `agentRuntimeArtifact.codeConfiguration.code.s3.versionId` → `update-agent-runtime`. Poll
   `get-agent-runtime` until `READY` (fail on `*_FAILED` or a timeout). For the Lambda:
   `update-function-code` with the S3 object version, then wait for `LastUpdateStatus = Successful`.
4. Print the new runtime version and the rollback command (the same script with the previous
   `VersionId`).

**Rule proven by the live gate:** after any CD deploy, `terraform plan` shows no changes.

**Which code runs:** Phase 2 showed that an open session keeps its old code after an update. So every
deploy, redeploy, and rollback check uses a **new** session ID. Each agent returns a `build_id`
(baked into the zip at build time) in its result, and the check compares it with the deployed build.

**Code Interpreter "definitions":** a Code Interpreter has no code to deploy. Its configuration
(network mode, execution role) is infrastructure, and agents select it by ID from an environment
variable. The code the agent sends at run time is the "template". Nothing is deployed per release.

## Identity and tokens

### Entra app registrations (new; deleted at cleanup)

| App | Purpose |
|---|---|
| `poc3-cli` | Public client used by the caller CLI to sign in User A or User B (delegated scopes `Research.Run` and `Workspace.ReadWrite`). |
| `poc3-unified-api` | Exposes delegated scope `Research.Run`. Confidential client: uses client credentials to call the Runtime and holds no signing key (KMS signs). |
| `poc3-agent-runtime` | Audience for Runtime invocation. App role `Runtime.Invoke`, assigned to `poc3-unified-api`. |
| `poc3-research-agent` | Service identity of the research agent. Its client secret is stored only in an AgentCore Identity credential provider. App roles assigned: `Workspace.Agent` on the Resource Hub and the gateway caller role. |
| `poc3-bench-agent` | Service identity of the benchmark agent (separate, so a research grant cannot be used by the bench runtime and the reverse). Role: `Workspace.Agent` only; no gateway role. |
| `poc3-resource-hub` | Delegated scope `Workspace.ReadWrite` (users) and app role `Workspace.Agent` (agents). |
| `poc3-llm-gateway` | As in Phase 2 (app role for callers). |

**Token version.** A v2 token endpoint does not by itself give v2 access tokens: the *resource* app's
manifest must set `requestedAccessTokenVersion = 2` (the default gives v1 tokens, which carry `appid`
instead of `azp`). Every resource app above (`poc3-unified-api`, `poc3-agent-runtime`,
`poc3-resource-hub`, `poc3-llm-gateway`) sets it to 2. Task 0 gets one real token for each audience
and asserts `ver == "2.0"`, `iss`, `aud`, `azp`, and `roles`/`scp` before anything else is built.

All tokens are validated against the tenant JWKS (`iss`, `aud`, `exp`, `nbf`, signature, `ver`).

**What each receiver accepts:**

| Receiver | Token type | Required claims |
|---|---|---|
| Unified API (from CLI) | delegated user token | `aud` = unified API, `scp` contains `Research.Run`, `tid` = our tenant, `azp` = the CLI's client ID, has `oid` and no `roles`-only app token (`idtyp` != `app`) |
| Runtime authorizer | app token | `aud` = agent runtime, `azp` = unified API, `roles` contains `Runtime.Invoke` |
| Resource Hub (user mode) | delegated user token | `aud` = resource hub, `scp` contains `Workspace.ReadWrite`, `idtyp` != `app` |
| Resource Hub (agent modes) | app token | `aud` = resource hub, `roles` contains `Workspace.Agent`, `azp` in the allowed agent list |
| LLM gateway sim | app token | as in Phase 2 |

Each rejection above has a unit test.

### Session grant

Signed by the unified API with a KMS asymmetric key (`ECC_NIST_P256`, `ECDSA_SHA_256`, JWS `ES256`).
KMS returns a DER-encoded ECDSA signature; JWS `ES256` needs the 64-byte `R || S` form, so the signer
converts DER → raw before base64url encoding. The Resource Hub verifies it with the public key, which
is given to the Lambda as configuration and not fetched per request. A live probe signs with KMS and
verifies in the deployed Lambda, because local-key tests cannot catch a DER/raw mistake.

| Claim | Value |
|---|---|
| `iss` | `poc3-unified-api` |
| `aud` | `poc3-resource-hub` |
| `sub` | the user's Entra `oid` |
| `agent` | client ID of the agent the grant is for (`poc3-research-agent` or `poc3-bench-agent`) |
| `sid` | the Runtime session ID |
| `jti`, `iat` | unique ID, issue time |
| `exp` | `iat` + grant TTL. Default TTL = **1 hour**, and never longer than the Runtime `max_lifetime`. Only the expiry test issues a longer control grant. |

The unified API issues a grant only after it has validated a user token (see "What each receiver
accepts"). The grant carries no scopes: it means "this agent may act on this user's workspace until
`exp`".

**Replay and binding: what 3a does and does not stop.**

- A grant alone is useless: the Resource Hub also needs a service token whose `azp` equals
  `grant.agent`. The research and bench agents have different identities.
- `sid` is **not** enforced. The Resource Hub cannot see the caller's real Runtime session; only the
  agent could report it, and the agent is the party we would be checking. So `sid` is audit only.
- `jti` is not consumed, because one run makes many Resource Hub calls with the same grant. There is
  no revocation list in 3a.
- **Residual risk:** someone who steals both a grant and that agent's service token can act for that
  user until the grant's `exp` (1 hour by default). The findings record this and name the options
  for work: shorter TTL with refresh through the unified API, or a revocation list keyed on `jti`.

### Token flow for one run

1. CLI → unified API: user token.
2. Unified API validates it, creates `sid`, and signs the grant.
3. Unified API → Runtime: `Bearer` = unified API service token (`aud` = `poc3-agent-runtime`), plus
   grant and session headers. The Runtime JWT authorizer checks the discovery URL, the audience, and a
   **custom claim match**: `azp` = unified API client ID and `roles` contains `Runtime.Invoke`.
   (`allowedClients` is not used because Entra v2 tokens have no `client_id` claim. Task 0 verifies
   this.) The Runtime's request header allow-list includes the grant header.
4. Agent → Resource Hub: agent service token (`aud` = `poc3-resource-hub`) in `Authorization`, grant
   in `X-Resource-Grant`, `sid` in `X-Session-Id` (audit only).
5. Agent → LLM gateway: agent service token (`aud` = `poc3-llm-gateway`). The Claude Code CLI reads it
   through `apiKeyHelper`. The helper prints the contents of a token file. The agent process refreshes
   that file from Identity before the token expires. The CLI caches helper output (5 minutes by
   default), so `CLAUDE_CODE_API_KEY_HELPER_TTL_MS` is set well below the token lifetime.
   `ANTHROPIC_BASE_URL` = `<tunnel>/anthropic`, because the simulator serves `/anthropic/v1/messages`
   and the CLI appends `/v1/messages`.

**Outbound M2M tokens (AgentCore Identity).** Entra client credentials give one audience per request
(`{resource}/.default`), so each agent calls `GetResourceOauth2Token` (via `@requires_access_token`,
`auth_flow="M2M"`) **once per audience**:

| Agent | Scope requested | Expected token |
|---|---|---|
| research | `api://poc3-resource-hub/.default` | `aud` = resource hub, `roles` ∋ `Workspace.Agent` |
| research | `api://poc3-llm-gateway/.default` | `aud` = gateway, `roles` ∋ gateway caller role |
| bench | `api://poc3-resource-hub/.default` | `aud` = resource hub, `roles` ∋ `Workspace.Agent` |

Task 0 asserts each row with a real token.

### Resource Hub access rules

| Caller mode | Requires | User comes from |
|---|---|---|
| **user** | user token, scope `Workspace.ReadWrite` | token `oid` |
| **agent + grant** | service token with role `Workspace.Agent` **and** a valid grant where `grant.agent == token.azp` and `grant.aud == poc3-resource-hub` | `grant.sub` |
| **agent + raw user token** (expiry test only; off unless a Lambda flag enables it) | service token with role `Workspace.Agent` **and** a user token in `X-User-Token` | user token `oid` |

- The API has **no user-ID parameter**. The prefix is always `users/<oid>/`.
- **One path routine** is used by every operation (list, read, write, search, and search `glob`):
  URL-decode exactly once; then reject (`400`) empty segments, `.`, `..`, a leading `/`, backslashes,
  encoded separators left after decoding (`%2F`, `%5C`, `%2E`), control characters, and paths longer
  than 1,024 bytes; then join to `users/<oid>/` and assert the key still starts with that prefix. A
  `glob` may use `*` and `?` inside segments only; it is matched against keys already inside the
  prefix, never used to build a key.
- Failures: missing or invalid token → `401`; `token_expired` is a distinct error code; wrong role or
  agent mismatch → `403`; object not in the user's prefix → `404` (never reveal other users' keys).
- The Resource Hub logs `sid`, caller mode, `azp`, `oid`, operation, and path. It never logs tokens.

### Raw-token expiry test

1. The CLI gets a user token and records its `exp`.
2. At the same time, the unified API issues a control grant with a TTL longer than the wait (for
   example 2 h; the Runtime `max_lifetime` for this test is set to allow it).
3. After the user token's `exp` has passed (60–90 min, while other tests run), invoke the agent twice:
   once in raw-token mode with the expired token, once with the control grant.
4. Expected: raw-token mode → the Resource Hub returns `401 token_expired` and the agent reports it;
   grant mode → success.

## Platform library `agent_platform`

It imports no agent framework. The tool contract is a list of
`ToolSpec(name, description, input_schema, handler)`.

| Tool | Behavior |
|---|---|
| `ws_list(prefix="")` | List entries under a workspace path: name, size, modified time. |
| `ws_read(path, offset=0, length=None)` | Read text. Large files are read with Range requests. The tool returns at most a fixed number of bytes to the model and says when output is truncated. |
| `ws_write(path, content)` | Write text. |
| `ws_search(text, glob=None, ignore_case=False)` | Call the Resource Hub search endpoint. **Fixed-string search only** (no regex), so the work per byte is bounded. Returns path, line number, line. Capped result count. |
| `fetch_url(url)` | HTTPS GET. Host allow-list: `api.worldbank.org`. **Redirects are not followed.** Response size cap. |
| `run_code(code, inputs=[], outputs=[])` | Start the Code Interpreter session on first use. Copy each workspace `inputs` path into the sandbox. Run the Python code. Copy each sandbox `outputs` file back to the workspace. Return stdout, stderr, and the output paths. |

Supporting classes: `ResourceHubClient` (the only code that talks to the Resource Hub),
`Sandbox` (wraps `bedrock_agentcore.tools.code_interpreter_client.CodeInterpreter`; always stopped in
`finally` at the end of the invocation), `TokenProvider` (Identity M2M tokens and the `apiKeyHelper`
token file).

Tools return structured errors (`forbidden`, `not_found`, `token_expired`, `too_large`,
`sandbox_error`, `upstream_error`) as tool results. They do not raise, so the model can report the
error.

Binary outputs such as `chart.png` are written to the workspace as bytes (`ws_write` for the model is
text-only; `run_code` handles binary copy-out internally).

## Research agent (Claude Agent SDK)

- Entry point: `BedrockAgentCoreApp`. It reads the grant header and session ID from the request
  context. A missing grant → error JSON, no model call.
- Tools: `ToolSpec` list → `@tool` functions → `create_sdk_mcp_server("platform")`.
- **All built-in tools are disabled** with `ClaudeAgentOptions(tools=[])`. (`allowed_tools` only
  auto-approves tools; it does not remove them.) `allowed_tools` lists the `mcp__platform__*` tools so
  they run without a permission prompt. Settings sources are isolated (no user/project settings
  files are loaded). `max_turns` is capped.
- A live negative test asks the agent to use `Bash`, `Read`, `WebFetch`, and `WebSearch`, and checks
  from the SDK message stream that no built-in tool call happened.
- Model: an Anthropic model on the gateway sim's allow-list. `ANTHROPIC_BASE_URL` = gateway tunnel URL.
- Result JSON: `{summary, files_written, turns, input_tokens, output_tokens, error}`.

### Research flow

1. CLI uploads `brief.md` to the user's workspace (user mode).
   - User A: Southeast Asia, 11 countries (BRN, KHM, IDN, LAO, MYS, MMR, PHL, SGP, THA, TLS, VNM).
   - User B: Central America, 7 countries (BLZ, CRI, SLV, GTM, HND, NIC, PAN).
   - **Year rule:** for each country, the most recent non-empty value (`mrnev=1`), so the year may
     differ per country. `data.csv` has columns `iso3, country, year, value`, and the chart labels
     each bar with its year. A country with no value is listed in the report as missing and is left
     out of the chart.
2. CLI → unified API `/research` → Runtime, prompt "Follow the instructions in brief.md."
3. Agent: `ws_read brief.md` → `fetch_url` (World Bank indicator `NY.GDP.PCAP.PP.CD`, one
   multi-country call with `mrnev=1&per_page=100&format=json`) → `ws_write data.csv` → `run_code`
   (matplotlib bar chart, `inputs=[data.csv]`, `outputs=[chart.png]`) → `ws_write report.md`.
4. **Check (in code, not by eye):** the live gate makes the same World Bank call itself and asserts
   that `data.csv` has exactly the expected ISO3 set (11 or 7, less any country the API returns as
   empty), with the same years and values (within rounding).
5. Result JSON back through the unified API to the CLI.

## Gateway simulator changes

- Allow the Anthropic fields and headers that the Claude Code CLI sends. The exact set is captured in
  Task 0 (for example `tools`, `tool_choice`, `metadata`, `thinking`, `anthropic-beta`).
- Pass SSE streams through unchanged, and still enforce the model allow-list and the output-token cap.
- OpenAI path unchanged.

## File-access benchmark

**Where:** Runtime `poc3_bench`, same zip deploy, same platform library and Identity service token.
It uses a grant for User A, minted by the unified API `/bench` route, and a separate prefix
`users/<A-oid>/bench/`. No LLM calls.

**Workspaces (seeded straight to S3 by the admin script; test fixtures):**

| Workspace | Contents |
|---|---|
| small | 20 text files × about 10 KB |
| large | 950 × 10 KB, 45 × 1 MB, 5 × 5 MB, 3 × 50 MB, 2 × 200 MB, 1 × 1 GB, 1 × 5 GB |

Content is generated from a fixed random seed. Large objects are built inside S3 from a 100 MB block
with multipart `UploadPartCopy`, so nothing large is uploaded from the laptop. Search needles are
planted at known file/line positions, and the expected match set is saved with the fixture.

**Target workloads and "fast enough" thresholds.** These are proposals for the user to confirm at
spec review. The findings judge each method against them.

| Workload | Threshold (warm, p50 / p95) |
|---|---|
| list a workspace of 1,000 files | ≤ 1 s / ≤ 2 s |
| read a 10 KB file | ≤ 200 ms / ≤ 500 ms |
| write a 10 KB file | ≤ 300 ms / ≤ 750 ms |
| search 1,000 × 10 KB files (interactive "ask about my files") | ≤ 5 s / ≤ 10 s |
| read a whole 1 GB file | ≥ 50 MB/s |
| search a 5 GB file | recorded only (no threshold; shows the size where search stops being interactive) |

**Operations and repetitions:**

- list the whole workspace; read 1 small file; write 1 small file: **30 repetitions**;
- search across the small workspace and across the 1,000 × 10 KB files: **30 repetitions**;
- read whole 50 MB / 1 GB / 5 GB files, and search across the large files: **5 repetitions**
  (report median and max; no p95 claim at this count).

**Cold and warm.** "Cold" = first operation in a new Runtime session with a new client, a new Mirage
instance, a new mount, or an empty mirror. It includes setup time (mount, SDK init, mirror sync) for
**every** method. "Warm" = later repetitions in the same session. Each method reports both.

**Fair order.** Method order is randomized per round. Caches are reported, not hidden: for each
method the findings say what it caches (Mirage cache, page cache, mirror).

**Recorded per operation:** end-to-end time, bytes transferred, Resource Hub requests made, and an
estimated cost (Lambda GB-seconds + S3 requests).

**One case per request.** A synchronous Runtime invocation has a 15-minute limit, so the unified API
`/bench` route invokes **one (method, operation, size) case per request**. The caller writes each
result row to `evidence/bench/*.jsonl` immediately, and a rerun skips rows already present. The cold
case of each method uses a new session ID.

**Methods:**

| # | Method | Notes |
|---|---|---|
| 1 | Direct API | List, parallel GETs (concurrency 16), Range reads for large files, streaming regex. |
| 2 | Resource Hub search endpoint | Lambda lists and streams S3 objects in parallel and returns only matches. Fixed-string search. Hard limits per request: bytes scanned (default 6 GB), objects (default 2,000), concurrency (16), and wall time (default 5 min; the response says `truncated` with the reason when a limit is hit). Record duration and max memory. |
| 3 | Mirage SDK | A small custom Mirage resource for the Resource Hub API (Mirage's S3 resource would skip the Resource Hub), following Mirage's custom-resource guide. It must support list, ranged read, write, and search; Task 0 proves each. |
| 4 | Mirage FUSE mount | The same custom resource, mounted at `/mnt/ws`; real `rg -F` (static arm64 binary in the zip). If FUSE is not available on Runtime, record "not feasible on Runtime" with the exact error. That result says nothing about FUSE speed, so the findings then report Mirage SDK and FUSE conclusions separately. |
| 5 | Copy-in mirror | Parallel download to `/tmp`, then `rg`. Report sync, search, and write-back time separately. If `/tmp` cannot hold a tier, record the limit. |

No method loads a whole large file into memory.

**Correctness guard:** a method's timings count only if its list and search results equal the expected
set.

**Operational limits recorded as findings:** Lambda function URL buffered response limit (6 MB, the
reason for Range reads), Lambda 15-minute limit for search over large files, Runtime `/tmp` size,
Runtime session limits.

**Output:** `evidence/bench/*.jsonl` (raw rows) and a table plus recommendation in
`docs/phase3-findings.md`.

## Verification questions

| # | Question |
|---|---|
| Q1 | Does the CD-only deploy (upload + `update-agent-runtime`) work, and does `terraform plan` stay clean after it? Does rollback by S3 version work? |
| Q2 | Does the Runtime inbound JWT authorizer accept the unified API's Entra service token (custom claim match) and reject others? Does the custom grant header reach the agent? |
| Q3 | Does the Identity OAuth2 credential provider (Entra client credentials) give the agent working service tokens for the gateway and the Resource Hub? |
| Q4 | Does the Claude Agent SDK run on Runtime from a zip, with inference only through the gateway sim (streaming + tools)? |
| Q5 | Does the research run work for both users, with checks computed in code (data matches World Bank, valid PNG, report present, writes only in own prefix)? |
| Q6 | Do all isolation tests pass (path escape, forged or changed grant, agent mismatch, expired grant, LLM asked to read the other user's files, built-in tools unavailable, no direct workspace-bucket access from Runtime or Code Interpreter)? |
| Q7 | Does the raw user token fail after expiry while the grant keeps working? |
| Q8 | Benchmark: latency, throughput, requests, and cost of the five methods at each size, judged against the target thresholds. Is the Mirage SDK fast enough? Is a Mirage FUSE mount feasible on Runtime, and if so, fast enough? Should search be a Resource Hub tool? |

## Task 0 probes (live, before the main build)

1. Claude Agent SDK in a linux/arm64 zip on Runtime: the bundled Claude Code CLI starts, the zip fits
   the direct-code size limit, `tools=[]` leaves only MCP tools, and `apiKeyHelper` (with the TTL
   setting) is called again after the TTL. Capture the request fields and headers it sends to
   `ANTHROPIC_BASE_URL`.
2. Entra tokens: one real token per audience in "What each receiver accepts" and each M2M row, with
   `ver`, `aud`, `azp`, `roles`/`scp` asserted.
3. Runtime inbound JWT authorizer with custom claims, and the custom grant header reaching the agent.
   The hashicorp/aws 6.66 `aws_bedrockagentcore_agent_runtime` docs list custom claims and a request
   header allow-list, so this probe checks behavior, not provider support. Also check provider support
   for the Identity OAuth2 credential provider; if it is missing, use a small script and record the
   gap for the work modules.
4. KMS `Sign` → DER-to-raw ES256 grant → verification inside the deployed Resource Hub Lambda.
5. Whether `/dev/fuse` exists and a FUSE mount is allowed on Runtime; the size of `/tmp`.
6. Mirage: the custom Resource Hub resource does list, ranged read, write, and search from inside
   Runtime (SDK), and mounts if probe 5 allows it.
7. Code Interpreter: binary file write/read (PNG), and S3 calls from inside the sandbox fail.

If probe 1, 2, 3, or 4 fails, stop and report. The research demo depends on them. If probe 5 or 6
fails, continue and record it; only benchmark methods 3–4 are affected.

## Testing

**Local (pytest, no AWS):**

- grant sign/verify (local key in place of KMS), including DER → raw conversion with a known vector;
- every token rule in "What each receiver accepts" (wrong `aud`, `ver`, `scp`, `roles`, `azp`, app
  token where a user token is required);
- every Resource Hub access rule: three caller modes, wrong key, changed `sub`, agent mismatch
  (including a research grant with the bench identity), expired grant, expired user token, raw-token
  flag off;
- path routine: `..`, `%2e%2e`, `%2F`, double-encoding, backslash, leading `/`, control characters,
  over-long paths, and hostile `glob` values;
- `fetch_url`: non-allow-listed host, redirect to another host, oversized response;
- Range handling; search limits (bytes, objects, time) and result capping;
- `ToolSpec` → Claude SDK adapter generation; `tools=[]` set in the options;
- `run_code` copy-in/out with a fake sandbox;
- gateway sim SSE and `tools` passthrough, model allow-list still enforced;
- deploy script: the update payload equals the fetched configuration except `versionId`.

**Live gate:** Task 0 probes; deploy + no-drift + redeploy + rollback, each checked with a new
session and `build_id` (Q1); both research runs (Q5); isolation tests, built-in tool negative test,
and Code Interpreter/Runtime S3 negative tests (Q6); raw-token expiry test (Q7); benchmark (Q8). Evidence goes to `evidence/`, results
to `docs/phase3-findings.md`.

## Error handling

- Platform tools return structured errors to the model and do not raise.
- Runtime entry point returns error JSON for a missing grant or an internal failure; it never returns
  a stack trace or token.
- The sandbox always stops in `finally`.
- The deploy script fails fast if the runtime does not reach `READY` and prints the rollback command.
- Resource Hub error codes are listed under access rules.

## Security notes

- The user's Entra token never reaches the agent, except in the raw-token test.
- The agent's client secret exists only in the Identity credential provider.
- The grant signing key never leaves KMS. Only the unified API role has `kms:Sign`.
- The CD role needs only: `s3:PutObject` on the code keys, `bedrock-agentcore:GetAgentRuntime` and
  `UpdateAgentRuntime` on the two runtimes, `lambda:UpdateFunctionCode` and `GetFunction` on the
  Resource Hub, and `iam:PassRole` on the two execution roles. For the POC the operator's SSO role
  runs it, and the findings document lists this minimum set.
- The Code Interpreter has no network access, and its role has no S3 permissions (proven by a
  negative test).
- The Runtime execution roles can read only the code objects. They have **no** access to the workspace
  bucket, so an agent cannot skip the Resource Hub. A negative test calls the workspace bucket with
  the Runtime role and expects `AccessDenied`. Only the Resource Hub Lambda role can reach the
  workspace bucket.
- The Resource Hub function URL is public (auth `NONE`). Every request is authenticated in code, and
  search has hard work limits. There is no WAF or rate limit in 3a; the findings record that.

## Cleanup

`terraform destroy`; delete the Runtime log groups; empty and delete both buckets; schedule the KMS key
for deletion (7 days); delete the Entra app registrations; remove `.env` values for Phase 3.

## Later phases (not in this spec)

- **3b:** a Deep Agents agent on the same platform library and live gate (LangChain tools from the same
  `ToolSpec` list, or a Resource Hub `BackendProtocol` plus `AgentCoreSandbox`).
- **3c:** check DeepSeek Harness (tools, MCP, custom model endpoint), then build.
- Possible: serve the platform library behind a central MCP server for Temporal and Databricks agents.

## Review changes (Codex adversarial review, 2026-09-27)

Accepted and applied: grant replay limits made explicit and separate bench identity (was: `sid`
implied binding); `tools=[]` to remove built-in tools (was: `allowed_tools`, which only
auto-approves); Code Interpreter and Runtime roles get no workspace-bucket access, with negative
tests (`SANDBOX` mode alone does not block S3); Entra resource apps set
`requestedAccessTokenVersion = 2`; one M2M token request per audience; per-receiver token rules;
KMS DER → raw ES256 conversion and a live probe; large uploads declared out of scope with a required
finding; fixed-string search with hard work limits; one benchmark case per Runtime request; benchmark
thresholds, repetitions, cold/warm definition, and randomized order; Mirage custom-resource probe in
Task 0; one canonical path routine and no redirects in `fetch_url`; deterministic World Bank year
rule; separate bootstrap and release S3 keys; new session IDs and `build_id` for deploy checks;
`ANTHROPIC_BASE_URL` includes `/anthropic` and the `apiKeyHelper` TTL is set.

Checked against sources before accepting: Claude Agent SDK `tools` vs `allowed_tools` (SDK types and
README); gateway route `/anthropic/v1/messages` (`gateway_sim/app.py`); Terraform owning
`agent/agent.zip` (`infra/terraform/poc/runtime.tf`).
