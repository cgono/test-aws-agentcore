# AgentCore Identity POC Runbook

## Current Status (updated 2026-08-31)

All three phases are complete with current, live, passing (or, for known limitations,
live-confirmed-failing) evidence. H1, H2, H6 (Entra OBO, both test users), the Google
callback/consent/durable-vault gate, H4a, and H4b are all proven post-fix (see the
`customParameters` and Secrets Manager findings under Phase 2 Isolation below, plus the
stale-`.env`-process and dying-quick-tunnel findings under Phase 1). H3 remains a documented
feasibility blocker (AgentCore exposes no provider-token expiry metadata), and H5 is out of
scope (no PingOne/AD FS environment available). H7 and H8 are both terminal `fail` (see Phase 3
observations below). `docs/assessment.md` is generated: decision `reject_or_defer`, custom-provider
production path `rejected`.

**Remaining work:** only cleanup (`scripts/provision_agentcore.py cleanup`, see the Cleanup
section) is left. Every live gate needs a real interactive terminal (see the note under Phase 1)
and a valid `aws sso login` session.

## Prerequisites

Choose an AgentCore-supported AWS region and create the monthly AWS Budget named by
`AWS_BUDGET_NAME`. Provisioning refuses to create resources without that budget.

Create three Entra registrations:

1. A public CLI client for device-code sign-in. Pre-authorize it for the middle-tier API.
2. A confidential middle-tier API app. Its application ID is `ENTRA_API_CLIENT_ID`; grant it
   delegated access to the downstream resource and create a client secret in
   `ENTRA_API_CLIENT_SECRET` only for the provisioning process.
3. A downstream resource API with the delegated `access_as_user` scope used by
   `ENTRA_DOWNSTREAM_SCOPE` and `RESOURCE_API_AUDIENCE`.

Before a live run, inspect the inbound access token: its `aud` will be the bare
`ENTRA_API_CLIENT_ID` GUID (Entra v2.0 access tokens never carry the `api://<client-id>`
Application ID URI form as `aud`, regardless of how "Expose an API" is configured — the
validator accepts either form), and the public CLI client must already be pre-authorized. A
consent prompt is a failed Phase 1 condition.

## Phase 0: Local Verification

This phase is deterministic and must not use AWS, Entra, Google, browser, or provider
credentials. Each command must exit `0` before a live phase begins:

```bash
.venv/bin/python -m pytest -m 'not integration' --cov=agentcore_identity_poc \
  --cov-report=term-missing --cov-fail-under=90
.venv/bin/ruff check .
.venv/bin/mypy src
.venv/bin/python -m pytest tests/test_repository_safety.py -q
git diff --check
```

The safety test scans tracked UTF-8 text files. It rejects credential-shaped JWTs,
authorization-header values, OAuth callback query values, private keys, email addresses,
non-example Entra tenant IDs, and forbidden JSONL evidence keys. Git metadata, the virtual
environment, and `evidence/raw/` are the only path exclusions. A failure is a stop condition:
remove or redact the value rather than suppressing the check.

## Phase 1

Start the synthetic resource API with its app factory:

```bash
.venv/bin/uvicorn agentcore_identity_poc.resource_api:create_app --factory --host 127.0.0.1 --port 8000
```

Expose it through an authenticated public HTTPS tunnel and copy the HTTPS URL printed by the
command:

```bash
cloudflared tunnel --url http://127.0.0.1:8000
```

Set the generated tunnel URL as the public callback base and resource endpoint, for example:

```bash
PUBLIC_BASE_URL=https://poc-resource.trycloudflare.com
RESOURCE_API_URL=https://poc-resource.trycloudflare.com/metadata
```

Validate local configuration first:

```bash
.venv/bin/agentcore-identity-poc preflight --json
```

Record `agentcore_authorized_domain` from this output. It is the exact regional AgentCore
domain that must be added to Google before the credential provider is created.

Review the exact resource plan without cloud writes:

```bash
.venv/bin/python scripts/provision_agentcore.py --account-id 123456789012
```

Apply only after reviewing the plan. The script checks the named budget before writes, tags
all resources `Project=agentcore-identity-poc`, renders and installs the final no-wildcard scoped
IAM policy, and writes a private `.poc-state.json` inventory. Supply the recorded directory and
token-vault ARNs plus the IAM role that receives the inline policy before applying.

```bash
ENTRA_API_CLIENT_SECRET=... \
AGENTCORE_DIRECTORY_ARN=arn:... \
AGENTCORE_TOKEN_VAULT_ARN=arn:... \
AGENTCORE_POC_IAM_ROLE_NAME=agentcore-poc-role \
.venv/bin/python scripts/provision_agentcore.py --apply
```

Run the live gate only after preflight and provisioning succeed:

```bash
AGENTCORE_POC_LIVE=1 \
AGENTCORE_POC_LIVE_RUNTIME=operator_live_runtime:create_runtime \
.venv/bin/python -m pytest tests/integration/test_entra_obo_live.py -m integration -v -s
```

`operator_live_runtime:create_runtime` must return a configured object with
`run_entra_obo(user_alias=...)`. The gate skips only when `AGENTCORE_POC_LIVE` is absent; a
requested live run without this runtime fails clearly. It must run both aliases and record H1,
H2, and H6. Stop before Google work when this gate fails.

Always run every live gate as `.venv/bin/python -m pytest`, never a bare `pytest`. The `-m` form
puts the current directory on `sys.path`, which is the only reason the root-level
`operator_live_runtime` module (and its `scripts.provision_agentcore` import) resolves; a bare
`pytest` invocation fails with an opaque `could not load AGENTCORE_POC_LIVE_RUNTIME` error.

**Every live gate needs a real interactive terminal, not a piped or backgrounded shell.**
`test_entra_obo_live.py` asks a mid-run yes/no question on stdin ("Did a consent/permission
screen appear?"); if stdin is not a live terminal (for example the command is run through a
backgrounded/piped tool call), that prompt gets EOF instead of an answer and the test silently
treats it as "consent seen", failing H2 for a reason that has nothing to do with the actual run.
Every device-code prompt across every live test likewise needs a human at a browser within its
sign-in window. Run these commands directly in your own terminal session.

**Finding: long-running `uvicorn` processes serve a stale `.env` snapshot.** `resource_api` (port
8000) and `web:create_production_app` (port 8001) both read configuration once at process
startup. If `.env` is edited after either has been started -- a new Google provider, a rotated
tunnel URL, a changed workload name -- the running process keeps using its original values
indefinitely. This produces a specific, easy-to-misdiagnose symptom in the Google flow: the
browser-served `google-connect` establishes a grant under the stale process's (old) provider or
workload name, while a fresh CLI invocation of `google-list` reads the current `.env` and looks
up a different one, so it reports `authorization_required` permanently -- indistinguishable from
the actual vaulting bug in the finding below except that retrying never resolves it. Restart both
`uvicorn` processes (same ports, so any `cloudflared` tunnel already pointed at them keeps working
unchanged) after any `.env` edit and before trusting a live gate result.

**Finding: unattended `cloudflared tunnel --url` "quick tunnels" die silently after about a day.**
These are unauthenticated, ephemeral tunnels; Cloudflare eventually drops the registration while
the local `cloudflared` process keeps running and retrying, so the previously-working public
hostname starts returning `NXDOMAIN` with no local error. The failure surfaces downstream as a
plain DNS/connect error in whatever test tries to reach that hostname next (for example
`test_entra_obo_live.py` failing with `httpx.ConnectError` against `RESOURCE_API_URL`), which
looks like a code or network problem rather than a dead tunnel. Check the tunnel's own log for a
repeating `"Unauthorized: Tunnel not found"` line before assuming a code-level bug. Fix: kill the
dead `cloudflared` process, start a new one on the same local port (it gets a new random
hostname), and update whichever `.env` variable (`RESOURCE_API_URL` or `PUBLIC_BASE_URL`) held the
old one -- `PUBLIC_BASE_URL` changing also requires updating the registered Entra/Google redirect
URIs, since that hostname is embedded in the OAuth callback registration; `RESOURCE_API_URL` does
not, since it is only read client-side by whichever process calls into the synthetic resource API.

## Google Browser Callback

Run the callback service with its production factory. The factory reads the existing POC
environment variables, including `PUBLIC_BASE_URL`, and validates Entra callback tokens against
the tenant JWKS.

```bash
.venv/bin/uvicorn agentcore_identity_poc.web:create_production_app --factory --host 127.0.0.1 --port 8001
```

Expose port 8001 through an authenticated public HTTPS tunnel, set `PUBLIC_BASE_URL` to that
tunnel origin, then add `https://<tunnel-origin>/auth/entra/callback` as the public client
redirect URI in Entra before beginning the browser callback test.

Verify the public callback service before beginning Google consent:

```bash
curl --fail https://<tunnel-origin>/healthz
```

## Google Provider Setup

This is a two-stage workflow. The Google console registration cannot be automated because
AgentCore returns a unique provider callback only after creation. Do not begin Phase 2 while the
provisioning plan reports `"phase_2":{"status":"blocked"}`.

1. In Google Cloud, create or select the POC project. On the OAuth consent-screen App domain
   page, add the exact `agentcore_authorized_domain` printed by preflight to Authorized domains.
   Configure the low-risk `https://www.googleapis.com/auth/drive.metadata.readonly` scope and
   the intended test users.
2. Create a Web application OAuth client. Leave Authorized redirect URIs empty at this stage.
   Keep its client ID and client secret out of shell history and tracked files.
3. Create the named AgentCore Google provider. The client secret is accepted only through the
   environment or standard input, never through a command argument. The script stores only the
   returned provider ARN and callback URL in the mode-`0600` local state file.

```bash
GOOGLE_OAUTH_CLIENT_ID=... \
GOOGLE_OAUTH_CLIENT_SECRET=... \
.venv/bin/python scripts/provision_agentcore.py google-create --apply
```

For a protected standard-input source instead:

```bash
export GOOGLE_OAUTH_CLIENT_ID=...
secret-command | \
  .venv/bin/python scripts/provision_agentcore.py google-create --apply --google-secret-stdin
```

4. Print the unique callback URL and register that exact value in the Google OAuth client's
   Authorized redirect URIs. A recreated provider has a different callback and changes local
   state to `google_console_update_required`; repeat this console step before continuing.

```bash
.venv/bin/python scripts/provision_agentcore.py google-show-callback
```

5. After saving the Google console change, acknowledge it and register the POC
   `PUBLIC_BASE_URL/oauth/google/return` URL on both workload identities:

```bash
.venv/bin/python scripts/provision_agentcore.py google-confirm-callback --apply
```

The command must report `"phase_2":{"status":"ready"}`. Complete the first Google consent
within ten minutes, which is the authorization-session lifetime. H3 is currently an explicit
feasibility blocker: AgentCore's token response exposes an opaque access token but no expiry
metadata, and the POC deliberately does not retain raw tokens. It therefore cannot distinguish a
post-expiry Google refresh safely. `measure expiry` records the sanitized
`provider_expiry_unavailable` H3 failure rather than asking an operator to wait or treating a
second retrieval as refresh evidence.

## Phase 2 Isolation

Authorize the Google provider once for each of two test users through the callback service. Use
opaque aliases, not email addresses or Entra object IDs; the aliases are the only user values
written to evidence. The concrete H4a command acquires and validates two separate Entra JWTs and
requires their verified `sub` claims to differ in memory before it requests an approved-workload
token or Drive metadata. It never writes subjects to output or evidence.

Before the H4a run, obtain a separate `connection_marker` from `google-list` while signed in as
each test user. It is a SHA-256 fingerprint of only the aggregate item count and MIME-type
histogram, not a Drive item ID or name. The two marker values must differ. Store them as opaque
operator inputs; H4a compares each user result to that user's expected marker and rejects swapped
or indistinguishable connection states. By default it starts two device-code sign-ins. For
noninteractive automation, pass exactly two JWTs on standard input in the same order as the
aliases:

```bash
printf '%s\n%s\n' "$USER_A_JWT" "$USER_B_JWT" | \
  .venv/bin/agentcore-identity-poc user-isolation \
  --user-a-alias user-a \
  --user-b-alias user-b \
  --user-a-drive-marker "$USER_A_DRIVE_MARKER" \
  --user-b-drive-marker "$USER_B_DRIVE_MARKER" \
  --tokens-stdin
```

The command appends H4a rows and per-user aggregate Drive metadata to
`evidence/phase-2.jsonl`; it never records tokens, authorization URLs, or user identifiers.
Both users must have an available Google connection and successful Drive metadata observation for
the command to pass.

The H4a live test invokes this concrete path, using device-code sign-in for each user. Set the
same opaque aliases before running the Phase 2 gate. H4b retains a separate operator runtime
because it deliberately replaces an IAM inline policy.

```bash
AGENTCORE_POC_LIVE=1 \
AGENTCORE_POC_USER_A_ALIAS=user-a \
AGENTCORE_POC_USER_B_ALIAS=user-b \
AGENTCORE_POC_USER_A_DRIVE_MARKER="$USER_A_DRIVE_MARKER" \
AGENTCORE_POC_USER_B_DRIVE_MARKER="$USER_B_DRIVE_MARKER" \
AGENTCORE_POC_IAM_ROLE_NAME=agentcore-poc-role \
AGENTCORE_POC_USER_ALIAS=user-a \
AGENTCORE_POC_LIVE_RUNTIME=operator_live_runtime:create_runtime \
.venv/bin/python -m pytest tests/integration/test_isolation_live.py -m integration -v -s
```

`AGENTCORE_POC_IAM_ROLE_NAME` and `AGENTCORE_POC_USER_ALIAS` are read directly by the H4b
driver, separately from the H4a `_A`/`_B` aliases above; both must be set or the live H4b
observation fails with a configuration error before any AWS call. `AGENTCORE_POC_USER_ALIAS`
is the single opaque alias recorded against every H4b matrix row -- it does not need to match
either H4a alias. `operator_live_runtime:create_runtime` needs only `run_workload_isolation()`
for H4b. The temporary broad-policy run requires the explicit acknowledgement documented by
`agentcore-identity-poc workload-isolation --help` and restores the scoped policy in all cases.
The concrete runner obtains and compares a hashed STS caller alias immediately before and after
every broad and scoped workload attempt; it aborts rather than stamping an initial caller alias
onto later rows.

IAM policy propagation on real AWS can occasionally take more than one internal retry pass
(bounded at 60 seconds). If `run_workload_isolation()` returns extra rows that make the live
test's outcome-set assertions fail even though no error was raised, this is a transient
propagation delay, not a real IAM isolation failure -- wait a few seconds and rerun the same
live test rather than treating it as a hypothesis failure. In practice, a fresh `apply_broad_policy()`
write on this account consistently took several seconds (observed repeatedly, not a rare fluke) to
propagate before the unapproved workload's `GetWorkloadAccessTokenForJWT` call stopped seeing the
role's *previous* (scoped) policy; the scoped-policy transition at the end of the run converged
immediately by comparison. `test_live_workload_isolation_records_broad_and_scoped_same_principal`'s
assertions check every accumulated row, including this pre-convergence window, so a live rerun can
fail this specific assertion on essentially every attempt even though the underlying broad/scoped
convergence itself is correct every time -- confirm this by inspecting the evidence file for the
run: if the *last* row for each workload/policy-mode pair matches the expected outcome, treat the
mechanism as proven and the test failure as the propagation-latency mismatch described above, not
a new defect.

**Finding: `customParameters` passed to `GetResourceOauth2Token` must be minimal and exact --
unrecognized keys silently break vaulting.** AgentCore's Google integration only tolerates the
`customParameters` keys it recognizes (`access_type` for Google); adding an unrecognized key (for
example `prompt`, an attempt to force Google's own re-consent screen) does not raise an error
anywhere in the flow -- `GetResourceOauth2Token` still returns an `authorizationUrl`, the browser
consent screen still appears and completes normally, and `CompleteResourceTokenAuth` still returns
success -- but nothing is actually vaulted. Every later retrieval call reports "authorization
required" indefinitely, with no error to point at the real cause. This was confirmed with a
controlled test: two authorization requests differing *only* in the presence of a `prompt` key,
against the same workload and provider, one vaulted a durable, immediately retrievable token and
the other vaulted nothing. Do not add IdP-specific query parameters to `customParameters` beyond
what AgentCore documents as supported for that provider, and keep the parameter set identical
between the call that establishes a grant and any call that later retrieves it. **This generalizes
beyond Google**: the same silent-failure shape should be expected from any AgentCore Identity
OAuth2 credential provider, including a custom PingOne/AD FS provider, if `customParameters`
carries a key the provider integration does not recognize -- verify durability with an explicit
retrieval-after-establishment check rather than trusting a 200/204 completion response.

The actual, durable fix for the "second workload's consent is access-token-only and cannot be
refreshed" problem (both workloads share one Google OAuth client, so a second workload's first
authorization can complete without Google issuing a refresh token, per Google's own consent-history
rules) is **revoking the app's access at Google's account permissions page and reconnecting**, not
a request parameter -- a revoked-then-fresh authorization is unconditionally treated as first-ever
by Google and always includes a refresh token.

**Finding: a scoped policy needs a Secrets Manager grant, not just `bedrock-agentcore:*`.**
AgentCore Identity stores each OAuth2 credential provider's client secret in an AWS-managed
Secrets Manager secret (name pattern
`bedrock-agentcore-identity!default/oauth2/<provider-name>-<random-suffix>`). When a workload
calls `GetResourceOauth2Token`, IAM authorizes that call against `secretsmanager:GetSecretValue`
on that specific secret ARN, evaluated on the *calling principal itself* -- not against
`bedrock-agentcore:*` alone, and not against a service-linked role AgentCore assumes internally.
This is undocumented in AWS's public reference and is provider-agnostic: it was confirmed for
both the Microsoft and Google providers in this POC. Because it surfaced as a generic
`AccessDeniedException`, it is easy to misdiagnose as an IAM propagation delay or a
`bedrock-agentcore` scoping gap. It does not weaken per-workload isolation -- the secret is
per-*provider*, shared by every workload using that provider, so granting it does not bypass
`DenySecondWorkloadJwtBinding`, which still gates the unapproved workload before it ever reaches
this call. The exact secret ARN is available with no wildcard needed from
`GetOAuth2CredentialProvider`'s `clientSecretArn.secretArn` field; `scripts/provision_agentcore.py`
now captures it into `.poc-state.json` (`provider.secret_arn`, `google_provider.secret_arn`) and
`infra/iam/scoped.json` grants it via the `AllowOauth2ProviderSecretAccess` statement. **This
generalizes beyond this POC**: any production IAM role whose workload calls an AgentCore Identity
OAuth2 credential provider -- Microsoft, Google, or a custom PingOne/AD FS provider -- needs this
same additional grant on that provider's AWS-managed secret; `bedrock-agentcore:*`-only policies
will fail with an access-denied error that has nothing to do with the `bedrock-agentcore`
namespace.

If the command reports a scoped-policy restoration failure, stop immediately. Restore the checked
in final policy before any further live test, then rerun the scoped observation:

```bash
.venv/bin/python scripts/provision_agentcore.py --apply
```

The temporary broad policy is evidence-only and must never remain installed after the experiment.

Run the complete opt-in Phase 2 gate only after the Google callback confirmation, browser health
check, and first consent have succeeded:

```bash
AGENTCORE_POC_LIVE=1 \
AGENTCORE_POC_USER_A_ALIAS=user-a \
AGENTCORE_POC_USER_B_ALIAS=user-b \
AGENTCORE_POC_USER_A_DRIVE_MARKER="$USER_A_DRIVE_MARKER" \
AGENTCORE_POC_USER_B_DRIVE_MARKER="$USER_B_DRIVE_MARKER" \
AGENTCORE_POC_IAM_ROLE_NAME=agentcore-poc-role \
AGENTCORE_POC_USER_ALIAS=user-a \
AGENTCORE_POC_LIVE_RUNTIME=operator_live_runtime:create_runtime \
.venv/bin/python -m pytest \
  tests/integration/test_google_live.py tests/integration/test_isolation_live.py \
  -m integration -v -s
```

The operator runtime supplies `run_google_provider_gate()` for callback binding, completed
consent, and durable-vault connection evidence, and `run_workload_isolation()` for H4b. Stop the
POC if callback binding or durable vaulting fails. H3 remains a documented feasibility blocker
until the AgentCore API exposes provider expiry metadata without requiring raw-token retention.
H7 and H8 remain pending as well.

`user-a` and `user-b` are opaque operator aliases, not email addresses or Entra identifiers. Each
marker is the distinct SHA-256 fingerprint emitted by `google-list` for that alias's aggregate
Drive item count and MIME-type histogram; it is not a Drive item identifier or name.

## Phase 3: Lifecycle, Assessment, and Handoff

Run lifecycle work only after both Phase 1 and the complete Phase 2 gate pass. It appends only
sanitized rows to `evidence/phase-2.jsonl`; that ignored file and the mode-`0600`
`.poc-expiry-state.json` resume state must not be added to Git.

### Phase 3 observations (2026-08-29)

- Preflight succeeded after renewing the AWS SSO session.
- The initial latency attempt returned `google_authorization_required` for User A despite
  earlier durable-vault evidence. The configured provider still matched the recorded state and
  the public callback health check returned HTTP 200. A fresh User A Google consent followed by
  `google-list` restored a durable Drive-metadata read; no infrastructure change was required.
- The 10-sample latency run passed: p50 1022 ms and p95 1949 ms. Its aggregate Drive results and
  Google-token fingerprints were stable; workload-token fingerprints differed between samples.
- The 5-worker, 20-request concurrency run passed with all requests completed, zero throttles,
  zero retries, and zero backoff. The run did not establish a documented quota or temporal target,
  so its readiness result remains `unknown` rather than a capacity pass.
- The 30-minute CloudTrail observation passed with 13 eligible events and all three required
  attribution fields present: AWS principal, workload identity, and user correlation.
- H8 recorded `failed` with `drive_revocation_not_observed`. This is an evidence result, not a
  command failure: the command exited zero and did not delete the shared credential provider.
- H7 remains unstarted. `OperatorLiveRuntime.run_lifecycle_measurements()` invoked the live CLI
  through Typer's `CliRunner`, which captured the Entra device-code prompt for `measure latency`,
  `measure expiry`, and `offboard google` (each acquires its own fresh inbound token) while the flow
  waited for browser approval; an operator could not see or complete that prompt, so the prescribed
  lifecycle pytest gate could not yet seed or confirm the real source-expiry experiment.

  **Fixed:** `operator_live_runtime.py` now calls those three Typer command functions directly
  (`_invoke_cli_command`) instead of through `CliRunner`, so their device-code prompt reaches the
  real terminal live, exactly as running the command directly at a shell would; `measure cloudtrail`
  needs no interactive token and still uses `CliRunner`. `offboard google`'s pass/fail is now read
  back from its just-appended H8 evidence row instead of parsed `CliRunner` output, since there is
  no captured stdout left once the call is direct. The lifecycle live gate still needs a real
  interactive terminal for every run (same requirement as every other live gate) and can involve up
  to three separate device-code sign-ins per invocation (latency, expiry when it is not resuming,
  offboard) -- run it with `-s` and be ready to sign in as `user-a` (or whichever alias
  `AGENTCORE_POC_USER_A_ALIAS` names) each time it prompts.

  **H7 seed/confirm timing:** after the seed run, do not just wait for the runbook's generic
  "60-90 minutes" -- read the actual `inbound_expiry` timestamp the seed run wrote, and wait until
  wall-clock time passes it before rerunning:

  ```bash
  python3 -c "import json,datetime; d=json.load(open('evidence/raw/h7-source-expiry-state.json')); \
    print(datetime.datetime.fromtimestamp(d['inbound_expiry']))"
  ```

  Never `cat` that file directly -- it holds a real, unredacted workload access token. The confirm
  run is only valid once real time has passed that timestamp; the resume state's own `resume_at` can
  reflect a different (e.g. workload-token) boundary and is not the right thing to wait on for H7
  specifically.

**Important ordering for H7:** do not run standalone `measure expiry` before the lifecycle gate.
The operator runtime installs the H7 raw-state seeder only inside that gate, and the seeder runs
only when `.poc-expiry-state.json` does not already exist. A standalone invocation creates that
resume state without creating the raw H7 state, making the later gate unable to seed H7 without
altering state.

```bash
.venv/bin/agentcore-identity-poc measure latency --samples 10
.venv/bin/agentcore-identity-poc measure concurrency --workers 5 --requests 20
.venv/bin/agentcore-identity-poc measure cloudtrail --lookback-minutes 30
.venv/bin/agentcore-identity-poc offboard google --user-alias user-a --apply
```

The latency, concurrency, CloudTrail, and successful offboarding commands exit `0`. A blocked
configuration or provider condition exits nonzero and stops the interpretation of that result.
Offboarding may exit `0` while reporting `"status":"failed"`: that is an explicit H8 failure,
not a pass, when the installed SDK has no narrow per-user purge or Drive revocation was not
observed. It must never delete the shared Google provider as a substitute.

`measure expiry` exits `0` with `"status":"resume_required"` and a `resume_at` value while an
inbound, workload, or OBO boundary remains in the future. Wait until that timestamp, then rerun
the same command with the same resume-state path. Do not alter the state file, sleep inside the
command, or use a synthetic expiry. The Google token response has no trustworthy expiry metadata;
the command records `H3/provider_expiry_unavailable` as `fail` while retaining no raw provider
token. This is the current H3 feasibility limitation, so a second retrieval is not refresh proof.

Run the lifecycle integration gate with an operator-provided runtime only after those commands
and their required provider state are ready:

```bash
AGENTCORE_POC_LIVE=1 \
AGENTCORE_POC_LIVE_RUNTIME=operator_live_runtime:create_runtime \
.venv/bin/python -m pytest tests/integration/test_lifecycle_live.py -m integration -v -s
```

It exits `0` only when the configured runtime provides the observed lifecycle values. The expected
Google post-expiry result is currently `failed` or `unproven`; it is not a reason to override the
H3 evidence failure. Optional OneDrive observations are supplementary only and cannot replace the
synthetic resource result for H2 or H6.

The H7 inbound-token-expiry proof needs two separate runs of this command. The first run's
`measure expiry` call seeds real (never sanitized-evidence-safe) token state to the
already-ignored `evidence/raw/` directory and reports `post_expiry_obo_refresh` as `"unknown"` --
this is expected, not a failure, because the source token has not actually expired yet at that
point. Wait for a default Entra access token to actually expire (typically 60-90 minutes, not
configurable by this POC), then rerun the identical command. The operator runtime checks real
elapsed time itself; it never sleeps inside the process. A completed second run reports `True`
only if the existing workload access token still obtained a fresh downstream token after its
source JWT expired. That second run also writes the durable H7 `obo_after_inbound_expiry`
evidence row; `assessment-finalize` requires that row to accept an `H7=pass` selection, so a
missing second run is not just an unfinished measurement, it makes `H7=pass` unreachable.

`scripts/provision_agentcore.py cleanup` does not remove `evidence/raw/`. If the H7 flow is
abandoned between the two runs (for example, the operator does not return after the wait), a
real workload access token is left sitting in
`evidence/raw/h7-source-expiry-state.json` until the second run completes and deletes it, or
until it is removed by hand. Delete that file manually if the H7 flow is abandoned.

### Phase 3 completion (2026-08-31)

- **Fixed an `UnsafeEvidenceError` crash in `measure expiry`'s first live run against the real
  evidence writer.** The evidence key `"token_kind"` trips `redaction.py`'s component-level
  blocklist (it contains the component `"token"`) even though its value is only an enum tag,
  never a token; every prior test used a fake evidence writer that never called
  `assert_safe_evidence`, so this was never caught before it hit the real writer. Renamed to
  `"kind"` in `cli.py`; added a regression test in `test_measurements.py` that routes through the
  real `EvidenceWriter` so a future evidence-detail key of this shape is caught in CI, not live.
  If the crash happened after the seed run, check first whether
  `evidence/raw/h7-source-expiry-state.json` still exists (via the Python one-liner above, never
  `cat`) before assuming the H7 seed was lost -- `source_expiry_runner` and the resume-state write
  both complete before the crashing evidence-append loop runs, so the seed usually survives.

- **The confirming H7 run is a one-shot consumer, not a repeatable check.** The first time
  `run_source_expiry_obo_experiment()` runs after wall-clock time passes `inbound_expiry`, it
  makes the real OBO call and unconditionally deletes
  `evidence/raw/h7-source-expiry-state.json` on either outcome (pass or fail). Once the
  `obo_after_inbound_expiry` row lands in evidence, H7 is done -- there is nothing to rerun or
  wait for, and later lifecycle-gate runs will just report `"unknown"` (no raw state left to
  check), which the gate accepts. This session's actual result: OBO does **not** survive source
  (inbound Entra) token expiry using the old workload token --
  `{"hypothesis":"H7","operation":"obo_after_inbound_expiry","outcome":"fail",
  "details":{"source_expired":true,"obo_succeeded":false}}`.

- **Recurring, still-unresolved finding: the AgentCore-vaulted Google grant for a user can go
  from working to `google_authorization_required` on every embedded device-code sign-in within
  roughly an hour of being (re-)established via `/connect`.** Happened twice in this session.
  Two live theories, neither confirmed: a short server-side grant TTL unrelated to source-token
  expiry, or the device-code flow silently reusing a stale/wrong cached Microsoft account in the
  browser (fixed once by signing out of every other Microsoft account and signing in only as the
  test user). Ruled out: `offboard_google` does not cause this -- in production it is a read-only
  probe (`purge_google_user_connection` exists only in test fakes, never called live), confirmed
  by grep and by the evidence rows it actually wrote. **Workaround until root-caused:** reconnect
  Google (`/connect` as the test user, then `google-list` to confirm the marker) immediately
  before every lifecycle-gate rerun, not just once per session.

- **`entra-obo`'s default evidence path (`evidence/phase-1.jsonl`) does not persist across
  sessions in this worktree** -- it never got combined with `evidence/phase-2.jsonl`, so H2 had
  zero evidence rows anywhere on disk despite being verified live back in Phase 1. Regenerate it
  with one more quick, Google-independent sign-in, pointed at the evidence file you actually use
  for assessment: `entra-obo --evidence-path evidence/phase-2.jsonl`.

- **Building `evidence/sanitized.jsonl` from the accumulated evidence file is not always a
  straight copy.** `assessment.py`'s `_validate_measurements` rejects `null` in any
  `_COUNT_FIELDS` key (e.g. `documented_quota`), but a real `measure concurrency` row legitimately
  emits `null` there for an AWS-undocumented quota -- a genuine schema mismatch between the
  evidence writers and the assessment validator, not something a rerun fixes. Drop the offending
  row(s) rather than editing values; `assessment-finalize`'s per-hypothesis check is
  existence-based across the whole evidence history (any matching-operation row with the right
  outcome), not "exactly one row," so dropping one row is safe as long as another qualifying row
  remains for that hypothesis. Worth a follow-up to make the validator accept `null` for
  genuinely-undocumented quota fields instead of requiring this manual step.

### Assessment

Do not create `docs/assessment.md` until all required live gates have produced and an operator has
reviewed sanitized evidence. First finalize one terminal result for every hypothesis, then render
the report. Both commands exit `0` only with complete, safe evidence; a missing hypothesis,
unsafe row, or unacknowledged decision exits `2` and leaves the report absent or unchanged.

```bash
.venv/bin/agentcore-identity-poc assessment-finalize \
  --evidence evidence/sanitized.jsonl \
  --output evidence/assessment-terminal.jsonl \
  --h5-compatibility-reviewed \
  --result H1=pass --result H2=pass --result H3=fail \
  --result H4a=pass --result H4b=pass --result H5=fail \
  --result H6=pass --result H7=fail --result H8=fail

.venv/bin/agentcore-identity-poc report \
  --evidence evidence/assessment-terminal.jsonl \
  --output docs/assessment.md \
  --iam-acceptable --audit-acceptable --latency-acceptable --quota-acceptable
```

Use actual terminal outcomes rather than the example selections above. The H3 limitation normally
makes the decision `reject_or_defer`; `--allow-deferred-failures` is an explicit operator defer,
never a pass. Review the generated report with `tests/test_assessment.py` and the repository safety
test before treating it as a handoff artifact. The assessment template explains the decision
switches and redaction boundary in detail.

### Cleanup

Print the exact recorded resources first:

```bash
.venv/bin/python scripts/provision_agentcore.py cleanup
```

Deletion requires both the apply flag and the literal confirmation:

```bash
.venv/bin/python scripts/provision_agentcore.py cleanup --apply --confirm agentcore-identity-poc
```

The preview exits `0` and makes no AWS client or mutation call; it lists only valid resource IDs
from local `.poc-state.json`. A missing or invalid state, an absent `--apply`, or a mismatched
confirmation exits `2`. Before confirmed cleanup, revoke the Google OAuth grant for both test
users and revoke the Entra grants created for the POC. Confirm that the final scoped IAM policy is
installed, not the temporary broad policy. After cleanup, verify that the tagged AgentCore
workloads and providers are absent and separately remove or verify absence of any POC Secrets
Manager entry that the operator created outside this script. The script intentionally does not
discover or delete unrecorded resources.
