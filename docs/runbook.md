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

## Cleanup

Print the exact recorded resources first:

```bash
.venv/bin/python scripts/provision_agentcore.py cleanup
```

Deletion requires both the apply flag and the literal confirmation:

```bash
.venv/bin/python scripts/provision_agentcore.py cleanup --apply --confirm agentcore-identity-poc
```
