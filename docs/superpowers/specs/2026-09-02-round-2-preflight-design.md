# Round 2 Engineering and Security Preflight Design

**Status:** Approved for implementation planning

**Date:** 2026-09-02

**Audience:** POC engineering, architecture, security, and identity reviewers

**Related record:** docs/round-2-hypotheses-and-tests.md. This design does not amend Round 1 evidence, docs/assessment.md, or the adoption recommendation.

## 1. Purpose and decision boundary

Round 2 must not run a live gate until its missing engineering controls are built and verified and the outstanding architecture decisions are explicitly recorded. This design covers the local engineering controls and the evidence needed for hosted preflight. It does not authorize an AWS, Entra, Google, browser, tunnel, or other live Round 2 action.

The POC will implement Candidate B, the asynchronous GetWorkloadAccessTokenForUserId path. It will use a local SQLite authorization store for the bounded POC and expose a persistence interface that permits a later DynamoDB implementation. Candidate A, fresh workforce-JWT reacquisition, remains not tested: the POC has no approved noninteractive workforce identity issuer. Keycloak is an optional follow-on evaluation of Candidate A, not a Round 2 build dependency.

This design does not represent Candidate B as equivalent to Candidate A. Candidate B binds a user through a trusted, bounded job-authorization record and IAM controls; Candidate A would bind a user through a newly signed JWT. Any successful Candidate B result remains subject to explicit architecture and security approval of that authorization model.

## 2. Scope constraints

### In scope

- A durable, token-free POC job-authorization model and SQLite storage adapter.
- A worker-side authorization service that enforces record bindings and local offboarding state.
- Explicit AgentCore request methods for Microsoft USER_FEDERATION and UserId workload tokens.
- A dedicated, static POC worker IAM policy and structural policy verification.
- Separate Round 2 sanitized evidence and terminal-assessment paths.
- A safe Google tokeninfo expiry diagnostic, an H9 repeating-probe command, and a local preflight command.
- Unit and static verification for the above.
- A decision record for all unresolved section 11 approvals, Candidate B, and Keycloak follow-on status.

### Out of scope

- Running a Round 2 integration test, minting a real workload or provider token, browser authorization, provider creation, AWS IAM mutation, Entra administration, or tunnel creation.
- Persisting an inbound JWT, workload token, Graph token, OAuth token, refresh token, provider response, authorization URL, secret, email address, or direct account identifier.
- Adding MSAL caching or another long-lived workforce credential to the POC.
- Implementing Keycloak or treating it as evidence for Round 2 Candidate A.
- Replacing the Round 1 assessment rules, generating a replacement Round 1 report, or combining Round 1 and Round 2 evidence files.

## 3. Architecture

The worker receives an opaque job reference and intended operation. It does not receive a user string that is passed through to AgentCore. It loads the job record, verifies that it is active and unexpired, compares the request to the record's immutable bindings, and checks the current local offboarding decision. Only then does it request a UserId-backed workload token. It repeats record and offboarding checks before every downstream call, keeps returned tokens in memory only, and discards them at command completion.

### 3.1 Job authorization domain

JobAuthorization is an immutable value object containing:

| Field | Rule |
| --- | --- |
| job_correlation | Opaque, unique job reference; not an identity value. |
| user_alias | Canonical namespaced POC user value derived before job creation. |
| identity_mapping_alias | Exact, precommitted value expected to address the JWT-established AgentCore connection. |
| provider_alias | Exactly one configured Microsoft user-federation provider. |
| scope_set | Nonempty, canonicalized least-privilege scope tuple; includes offline_access only for the Microsoft provider flow. |
| workload_alias | Exact dedicated asynchronous workload. |
| operation_class | Exact approved operation, initially graph_me. |
| approved_at and expires_at | UTC timestamps; expiry is later than approval. |
| approved_by | Opaque approver alias, not an email or account ID. |
| job_status_category | active, completed, expired, or revoked. |
| offboarding_category and checked_at | Latest local allow or deny decision and its observation time. |

Records are created only through a deliberate administrative command requiring an explicit apply acknowledgement. A caller cannot change user, provider, scope, workload, operation, or approval timestamps after creation. An active record may become completed, expired, or revoked; no terminal state can return to active.

JobAuthorizationStore defines create, get, transition, and set_offboarding operations. The SQLite adapter is the only POC implementation. It creates the parent directory with mode 0700 and the database file with mode 0600, verifies owner-only permissions before use, and refuses an insecure path. A DynamoDbJobAuthorizationStore can later implement this interface without changing the worker's authorization logic.

### 3.2 Worker authorization service

AsyncAuthorizationWorker accepts a trusted job reference plus requested provider, scopes, workload, and operation. It follows this exact sequence:

1. Load the record; reject a missing, inactive, expired, completed, or revoked record.
2. Compare every requested binding with the stored binding; reject any difference.
3. Check local offboarding state and freshness; reject deny or stale state.
4. Read user_alias only from the stored record and use it as the UserId request value.
5. Obtain a UserId workload token from AgentCore.
6. Reload and recheck the record and offboarding state.
7. Retrieve the existing Microsoft credential and validate that the Graph subject correlation is the precommitted user correlation.
8. Reload and recheck authorization immediately before the Graph call.
9. Record a sanitized observation and, for a terminal one-shot job, transition it to completed.

The service fails closed. It never starts browser authorization, creates a connection, or substitutes a caller-provided user value when authorization is absent. It emits category-only errors suitable for evidence, never tokens or provider responses.

### 3.3 AgentCore boundary

Extend AgentCoreDataPlane and AgentCoreIdentity with a UserId operation and an explicit Microsoft user-federation operation.

The UserId method calls GetWorkloadAccessTokenForUserId with exactly the workload name and stored user value. The Microsoft method sends oauth2Flow USER_FEDERATION, accepts either a direct access token or structured authorization-required result, and uses the exact Graph scopes including offline_access. It sends no customParameters and specifically never reuses Google's access_type=offline parameter.

Return URL and state are accepted only for an explicit connection-establishment command. An H7-R1 or H7-R2 no-interaction observation records authorization-required and stops; it does not follow the URL.

### 3.4 IAM policy and static verification

Add infra/iam/async-worker.json. It permits only the dedicated worker role to call GetWorkloadAccessTokenForUserId for the exact configured workload identity and Microsoft provider, with StringEquals on bedrock-agentcore:userid for the single namespaced POC user. No other statement grants that action. The interactive policy retains its explicit UserId deny.

The local preflight validates this checked-in policy shape: the positive Allow contains the exact condition key and POC value; a direct request with a different user cannot match; no action or resource is wildcarded; and the interactive policy retains its deny. Structural checks are not proof of AWS evaluation.

Hosted preflight must make direct calls under the dedicated worker role: the exact approved user must succeed and a different value must raise AccessDeniedException. Any other result leaves the control unproven and blocks Candidate B.

### 3.5 Evidence and assessment

Every Round 2 observation is written to evidence/round-2.jsonl, ignored by Git. Standard detail names are run_correlation, resource_fingerprint, workload_fingerprint, source_fingerprint, aws_correlation, job_correlation, user_alias, identity_mapping_alias, browser_prompt_returned, binding_completed, job_status_category, and offboarding_category.

Every writer uses the real EvidenceWriter. Tests prove each new row passes assert_safe_evidence at write time and reject unsafe natural names such as token_kind. No fixture contains a live-looking credential.

Create a Round 2 assessment namespace separate from assessment.py. It accepts only H3-R, H7-R1, H7-R2, H8-R, and H9 and produces separate terminal evidence and a separate Round 2 assessment document. Its terminal outcomes are pass, fail, inconclusive, and not_tested, with source-evidence rules. not_tested is permitted only for Candidate A and the unavailable production workforce-only branch; it cannot mask an incomplete or failed Candidate B result. It never reads or writes Round 1 evidence or changes Round 1 required-hypothesis logic.

### 3.6 Google diagnostic and H9

The Google expiry diagnostic sends the in-memory access token only to Google's tokeninfo endpoint. It uses an isolated HTTP client with request and event logging disabled, never prints a request URL, and returns only a calculated UTC expiry or a category saying authoritative expiry was unavailable. It writes no token, response body, or query string. Hosted preflight proves this on a throwaway grant before H3-R.

The H9 command uses a configurable five-minute default interval and an operator-selected duration of at least 150 minutes. It records UTC and monotonic elapsed time, fingerprints, known expiry diagnostics, controlled sign-in timestamps, identity correlation, AWS and CloudTrail correlation, authorization-URL presence, and Drive outcome. On the first authorization_required it makes one controlled repeat using unchanged parameters and stops. It never follows an authorization URL, reconnects the provider, or sleeps inside an integration test.

### 3.7 Local and hosted preflight separation

round-2-preflight --local is deterministic. It validates SQLite permissions and schema, evidence-key safety, policy structure, expected configuration aliases, Round 2 assessment isolation, and that raw resume paths such as .poc-expiry-state.json are ignored. It neither initializes cloud clients nor reads provider credentials.

round-2-preflight --hosted is an operator procedure, not an automatic command. After local preflight passes and decisions are approved, the operator captures provider and IAM configuration fingerprints, verifies synchronized UTC time, validates a healthy public callback tunnel, proves tokeninfo on a throwaway grant, and performs direct AWS UserId positive and negative controls. Each hosted observation is sanitized and recorded separately. A missing or failed hosted check blocks live gates.

## 4. Security controls and failure behavior

| Threat or failure | Required response |
| --- | --- |
| Caller substitutes user, provider, scope, workload, or operation | Reject before an AgentCore call; record category only. |
| Job is expired, completed, revoked, missing, or locally denied | Reject before an AgentCore call; no browser fallback. |
| Authorization changes after token acquisition | Recheck and reject before Graph; discard in-memory material. |
| IAM condition is absent or allows a different user | Mark control unproven and stop Candidate B. |
| JWT/UserId vault mapping cannot be proven | Mark Candidate B inconclusive; do not start the aging test. |
| AgentCore returns an authorization URL during no-interaction observation | Record presence and stop without opening it. |
| Sensitive material reaches logs or evidence | Fail closed and invalidate the affected run. |
| Clock, expiry, user mapping, or Graph subject cannot be proven | Mark the affected test inconclusive; do not infer success. |
| SQLite permission or owner validation fails | Refuse to use the store. |

## 5. Decisions required before hosted preflight

The decision record must identify an owner and date for each item.

| Decision | Current POC position |
| --- | --- |
| Durable job record as UserId authority | Approved for bounded POC, subject to this design's controls. |
| Candidate B worker role | Approved for bounded POC, subject to direct AWS positive and negative proof. |
| Candidate A | not_tested; no approved noninteractive same-user JWT issuance exists. |
| Keycloak | Optional Candidate A follow-on; requires separate review of issuance authority, credential custody, and revocation. |
| Job maximum lifetime and offboarding freshness | Must be set before hosted preflight. |
| Bounded post-offboarding Graph-token lifetime | Must be explicitly accepted or rejected. |
| Residual AgentCore vault storage | Must be explicitly accepted or rejected after H8-R Branch E. |
| forceAuthentication behavior | Evaluate as targeted refresh-credential invalidation only, never assumed deletion. |
| H9 no-recurrence closure standard | Must be approved before H9. |
| Entra-coupled offboarding evidence | Must be accepted or deemed insufficient because PingOne B1 is unavailable. |

## 6. Verification strategy

Implementation is test-first. At minimum, tests cover SQLite creation and restrictive permissions; migration and transactional state changes; every invalid binding and record state; pre- and post-acquisition offboarding checks; AgentCore UserId and Microsoft request shapes; IAM policy structure; real EvidenceWriter validation; assessment separation; diagnostic log suppression; H9 repeat/stop behavior; and local preflight's no-cloud-client invariant.

Then run:

    .venv/bin/python -m pytest -m 'not integration' --cov=agentcore_identity_poc --cov-report=term-missing --cov-fail-under=90
    .venv/bin/ruff check .
    .venv/bin/mypy src
    .venv/bin/python -m pytest tests/test_repository_safety.py -q
    git diff --check

Only after these pass, the hosted-preflight decision record is complete, and the required reviewers approve the stated decisions may an operator begin hosted preflight. The first live gate thereafter is H9, followed by the remaining section 9 order.

## 7. Keycloak follow-on boundary

Keycloak is not a fallback for Candidate B. A later Candidate A proposal may use it only if it establishes an approved, auditable basis for a worker to obtain a fresh same-user workforce JWT. Before it may be added to a live plan, it must define the source of issuance authority; the storage, encryption, and access controls for any long-lived credential or session; per-user revocation and offboarding propagation; issuer, audience, subject mapping, signing-key rotation, and expiry validation; and why the mechanism cannot turn a caller-supplied user string into impersonation authority.

Until then, Keycloak remains a documented not_tested Candidate A follow-on and cannot be used to claim a Round 2 pass.

