# AgentCore Identity POC

This repository is a command-line feasibility POC for AWS AgentCore Identity. It does not create
cloud resources, open a browser, or call a provider during its default test suite. The POC keeps
raw credentials, JWTs, OAuth callbacks, and evidence outside version control; the detailed
operator procedure is in [the runbook](docs/runbook.md).

## Setup

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
```

Copy values into an untracked environment file or export them in the terminal. Never put secrets
in command arguments, evidence, or tracked files. `.poc-state.json`, `evidence/*.jsonl`, and
`evidence/raw/` are intentionally ignored.

## Four Stages

### 1. Local Verification

Run this before any cloud action. Every command exits `0` on success and uses no live credentials.

```bash
.venv/bin/python -m pytest -m 'not integration' --cov=agentcore_identity_poc \
  --cov-report=term-missing --cov-fail-under=90
.venv/bin/ruff check .
.venv/bin/mypy src
.venv/bin/python -m pytest tests/test_repository_safety.py -q
git diff --check
```

The repository safety test scans tracked UTF-8 text files for credential-shaped values, identity
data, and unsafe JSONL evidence keys. It ignores only Git metadata, the virtual environment, and
the explicitly ignored `evidence/raw/` directory; it permits documented non-secret examples.

### 2. Phase 1: Entra OBO and Synthetic Resource

Validate configuration, review the no-write plan, provision only after a named AWS Budget is
present, then run the opt-in integration gate. Successful commands exit `0`; a configuration or
provider block exits nonzero and stops the phase.

```bash
.venv/bin/agentcore-identity-poc preflight --json
.venv/bin/python scripts/provision_agentcore.py --account-id 123456789012
AGENTCORE_POC_LIVE=1 \
AGENTCORE_POC_LIVE_RUNTIME=operator_live_runtime:create_runtime \
  .venv/bin/python -m pytest tests/integration/test_entra_obo_live.py -m integration -v -s
```

Phase 1 writes only sanitized observations to `evidence/phase-1.jsonl`: H1 workload issuance, H2
OBO, and H6 synthetic-resource authorization. The optional OneDrive path is not evidence for H2
or H6; only the synthetic resource API proves downstream authorization remains authoritative.

### 3. Phase 2: Google Callback and Isolation

Google setup is a two-stage manual registration process. Create the provider using a secret from
the environment or standard input, print its returned callback URL, register that exact URL in
Google, then confirm it. Do not pass the secret as an argument.

```bash
GOOGLE_OAUTH_CLIENT_ID=... GOOGLE_OAUTH_CLIENT_SECRET=... \
  .venv/bin/python scripts/provision_agentcore.py google-create --apply
.venv/bin/python scripts/provision_agentcore.py google-show-callback
.venv/bin/python scripts/provision_agentcore.py google-confirm-callback --apply
```

After the callback service's HTTPS `/healthz` response and first consent, run the Phase 2 gate in
the runbook. It records sanitized `evidence/phase-2.jsonl` observations for callback binding,
durable vault connection, H4a two-user Drive isolation, and H4b broad/scoped IAM behavior. An IAM
policy restoration failure, callback failure, or missing durable connection is a stop condition.

### 4. Lifecycle, Decision, and Cleanup

Run latency, concurrency, expiry, CloudTrail, and per-user offboarding only after Phase 2. The
expiry command writes a mode-`0600` ignored resume state and returns `0` with
`"status":"resume_required"` while a known boundary is still pending. Resume it after that
timestamp; it must not sleep or retain raw tokens.

```bash
.venv/bin/agentcore-identity-poc measure latency --samples 10
.venv/bin/agentcore-identity-poc measure concurrency --workers 5 --requests 20
.venv/bin/agentcore-identity-poc measure expiry --resume-state .poc-expiry-state.json
.venv/bin/agentcore-identity-poc measure cloudtrail --lookback-minutes 30
.venv/bin/agentcore-identity-poc offboard google --user-alias user-a --apply
```

H3 is currently expected to record a sanitized `provider_expiry_unavailable` failure: the
AgentCore response does not expose provider-token expiry metadata and the POC intentionally does
not retain the raw Google token. Do not infer refresh from a second retrieval or wait manually for
an undocumented boundary. H7 and H8 must be finalized from their actual observations.

Only after every required live gate and compatibility decision is complete may an operator run
`assessment-finalize` and then `report` to create local `docs/assessment.md` from sanitized
evidence. The command sequence and explicit decision acknowledgements are in
[`docs/assessment-template.md`](docs/assessment-template.md); no assessment is committed without
finalized live evidence.

Cleanup is also operator-only. First preview the recorded IDs; deletion requires both `--apply`
and the literal confirmation. Revoke Google and Entra grants, confirm the scoped IAM policy has
been restored, then verify the recorded AgentCore resources and POC Secrets Manager entries are
absent after cleanup.

```bash
.venv/bin/python scripts/provision_agentcore.py cleanup
.venv/bin/python scripts/provision_agentcore.py cleanup --apply --confirm agentcore-identity-poc
```
