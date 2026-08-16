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

Before a live run, inspect the inbound access token: its `aud` must equal
`api://<ENTRA_API_CLIENT_ID>`, and the public CLI client must already be pre-authorized. A
consent prompt is a failed Phase 1 condition.

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
within ten minutes, which is the authorization-session lifetime. For the H3 refresh observation,
wait for natural Google access-token expiry; do not treat a second immediate retrieval as refresh
evidence.

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
AGENTCORE_POC_LIVE_RUNTIME=operator_live_runtime:create_runtime \
.venv/bin/python -m pytest tests/integration/test_isolation_live.py -m integration -v -s
```

`operator_live_runtime:create_runtime` needs only `run_workload_isolation()` for H4b. The
temporary broad-policy run requires the explicit acknowledgement documented by
`agentcore-identity-poc workload-isolation --help` and restores the scoped policy in all cases.
The concrete runner obtains and compares a hashed STS caller alias immediately before and after
every broad and scoped workload attempt; it aborts rather than stamping an initial caller alias
onto later rows.

Run the complete opt-in Phase 2 gate only after the Google callback confirmation, browser health
check, and first consent have succeeded:

```bash
AGENTCORE_POC_LIVE=1 \
AGENTCORE_POC_USER_A_ALIAS=user-a \
AGENTCORE_POC_USER_B_ALIAS=user-b \
AGENTCORE_POC_USER_A_DRIVE_MARKER="$USER_A_DRIVE_MARKER" \
AGENTCORE_POC_USER_B_DRIVE_MARKER="$USER_B_DRIVE_MARKER" \
AGENTCORE_POC_LIVE_RUNTIME=operator_live_runtime:create_runtime \
.venv/bin/python -m pytest \
  tests/integration/test_google_live.py tests/integration/test_isolation_live.py \
  -m integration -v -s
```

The operator runtime supplies `run_google_provider_gate()` for callback binding, completed
consent, and durable-vault connection evidence, and `run_workload_isolation()` for H4b. Stop the
POC if callback binding or durable vaulting fails. H3 remains pending until Task 13 records a
post-expiry retrieval; H7 and H8 remain pending as well.

`user-a` and `user-b` are opaque operator aliases, not email addresses or Entra identifiers. Each
marker is the distinct SHA-256 fingerprint emitted by `google-list` for that alias's aggregate
Drive item count and MIME-type histogram; it is not a Drive item identifier or name.

## Cleanup

Print the exact recorded resources first:

```bash
.venv/bin/python scripts/provision_agentcore.py cleanup
```

Deletion requires both the apply flag and the literal confirmation:

```bash
.venv/bin/python scripts/provision_agentcore.py cleanup --apply --confirm agentcore-identity-poc
```
