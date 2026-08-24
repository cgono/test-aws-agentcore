# AgentCore Identity POC Runbook

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
live test rather than treating it as a hypothesis failure.

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

```bash
.venv/bin/agentcore-identity-poc measure latency --samples 10
.venv/bin/agentcore-identity-poc measure concurrency --workers 5 --requests 20
.venv/bin/agentcore-identity-poc measure expiry --resume-state .poc-expiry-state.json
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
