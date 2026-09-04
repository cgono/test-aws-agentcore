# Round 2 Engineering and Security Preflight Design

**Status:** Revised after technical review; pending final review

**Date:** 2026-09-02

**Last revised:** 2026-09-04

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
- Local build work that adds `.poc-expiry-state.json`, `.poc-round-2-jobs.sqlite3`, and the SQLite
  journal/WAL sidecars to `.gitignore` before any Round 2 state is created.

### Out of scope

- Executing any hosted prerequisite or Round 2 gate during the engineering build: minting a real workload or provider token, browser authorization, applying provider creation, AWS IAM mutation, Entra administration, or tunnel creation. Building and testing the dry-run/provider-provisioning path and documenting the later hosted sequence remain in scope.
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
| user_alias | Canonical internal POC user label: arbitrary and namespaced, never derived from a UPN, email address, Entra `oid`, or other direct account identifier. |
| identity_mapping_alias | Exact, precommitted AWS UserId value expected to address the JWT-established AgentCore connection; also arbitrary and namespaced. |
| subject_correlation | One-way correlation for the established Graph subject, used only to prove that resumed work stayed bound to the expected user. |
| provider_alias | Exactly one configured Microsoft user-federation provider. |
| requested_scopes | Nonempty, canonicalized least-privilege scope tuple; includes offline_access only for the Microsoft provider flow. |
| workload_alias | Exact dedicated asynchronous workload. |
| operation_class | Exact approved operation, initially graph_me. |
| approved_at and expires_at | UTC timestamps; expiry is later than approval. |
| approved_by | Opaque approver alias, not an email or account ID. |
| job_status_category | active, completed, expired, or revoked. |
| offboarding_category and checked_at | Latest local allow or deny decision and its observation time. |

Records are created only through a deliberate administrative command requiring an explicit apply acknowledgement. A caller cannot change user, provider, scope, workload, operation, or approval timestamps after creation. An active record may become completed, expired, or revoked; no terminal state can return to active.

JobAuthorizationStore defines create, get, transition, and set_offboarding operations. The SQLite adapter is the only POC implementation and uses `.poc-round-2-jobs.sqlite3`. It creates the parent directory with mode 0700 where the parent is POC-owned, creates the database file with mode 0600, verifies owner-only permissions before use, and refuses an insecure path. The database and its journal/WAL sidecars are ignored by Git. A DynamoDbJobAuthorizationStore can later implement this interface without changing the worker's authorization logic.

### 3.2 Worker authorization service

AsyncAuthorizationWorker accepts a trusted job reference plus requested provider, scopes, workload, and operation. It follows this exact sequence:

1. Load the record; reject a missing, inactive, expired, completed, or revoked record.
2. Compare every requested binding with the stored binding; reject any difference.
3. Check local offboarding state and freshness; reject deny or stale state. The engineering default is 60 seconds, is configurable only to a positive value no greater than the job lifetime, and is replaced by the architecture-approved maximum before hosted preflight.
4. Read identity_mapping_alias only from the stored record and use it as the UserId request value. Never derive it from request input at resume time.
5. Obtain a UserId workload token from AgentCore.
6. Reload and recheck the record and offboarding state.
7. Retrieve the existing Microsoft credential and validate that the Graph subject correlation equals the record's immutable subject_correlation.
8. Reload and recheck authorization immediately before the Graph call.
9. Record a sanitized observation and, for a terminal one-shot job, transition it to completed.

The service fails closed. It never starts browser authorization, creates a connection, or substitutes a caller-provided user value when authorization is absent. It emits category-only errors suitable for evidence, never tokens or provider responses.

### 3.3 AgentCore boundary

Extend AgentCoreDataPlane and AgentCoreIdentity with a UserId operation and an explicit Microsoft user-federation operation.

The UserId method calls GetWorkloadAccessTokenForUserId with exactly the workload name and stored identity_mapping_alias. The Microsoft method sends oauth2Flow USER_FEDERATION, accepts either a direct access token or structured authorization-required result, and uses the exact Graph scopes including offline_access. It sends no customParameters and specifically never reuses Google's access_type=offline parameter.

Return URL and state are accepted only for an explicit connection-establishment command. An H7-R1 or H7-R2 no-interaction observation records authorization-required and stops; it does not follow the URL.

### 3.4 IAM policy and static verification

Add infra/iam/async-worker.json. Its UserId statement permits only GetWorkloadAccessTokenForUserId on the exact asynchronous workload, with StringEquals on bedrock-agentcore:userid for the precommitted identity_mapping_alias. A separate statement permits GetResourceOauth2Token only on the exact directory, asynchronous workload, token vault, and Microsoft user-federation provider resources required by the tested AWS evaluation. A third statement permits Secrets Manager GetSecretValue only for that provider's recorded AWS-managed secret. No other statement grants the UserId operation, and the interactive policy retains its explicit UserId deny.

The local preflight validates this checked-in policy shape: the positive Allow contains the exact condition key and POC value; a direct request with a different user cannot match; no action or resource is wildcarded; and the interactive policy retains its deny. Structural checks are not proof of AWS evaluation.

Hosted preflight must make direct calls under the dedicated worker role: the exact approved user must succeed and a different value must raise AccessDeniedException. Any other result leaves the control unproven and blocks Candidate B.

Round 1 H4b already demonstrated that, under its temporary broad IAM policy, two distinct workload identities acting for the same user could retrieve the existing Google connection: the live gate required both broad-policy outcomes to pass, and H4b is terminal pass evidence. That result removes workload identity as the observed vault-partition boundary for the tested provider. The dedicated asynchronous workload is therefore an operational and IAM-scoping handle, not a security boundary by itself. Candidate B's user controls are the trusted immutable record, its repeated offboarding checks, the dedicated role, and the IAM UserId condition once the hosted positive and negative calls prove it.

### 3.5 Evidence and assessment

Every Round 2 observation is written to evidence/round-2.jsonl, ignored by Git. The minimum approved detail-name vocabulary is run_correlation, resource_fingerprint, workload_fingerprint, source_fingerprint, aws_correlation, cloudtrail_correlation, job_correlation, user_alias, identity_mapping_alias, subject_correlation, provider_alias, workload_alias, requested_scopes, oauth_flow, iam_role_alias, browser_prompt_returned, binding_completed, job_status_category, offboarding_category, expiry_diagnostic_source, sign_in_at, and causal_attribution. This is an extensible allowlist: every added name must first pass the real redaction validator and a real EvidenceWriter test. Record fields that are not explicitly approved evidence names remain record-only.

Every writer uses the real EvidenceWriter. Tests prove each new row passes assert_safe_evidence at write time and reject unsafe natural names such as token_kind. No fixture contains a live-looking credential.

Create a Round 2 assessment namespace separate from the Round 1 rules in assessment.py. First extract a shared safety-and-shape validator that performs raw-response rejection, assert_safe_evidence, raw-secret-text rejection, Observation shape checks, and measurement-unit checks without applying any terminal marker or terminal-outcome rule. The existing Round 1 loader wraps that shared validator with its unchanged assessment_terminal marker and pass/fail set. The Round 2 loader wraps it with a distinct round_2_assessment_terminal marker and Round 2 rules. It must not call the current monolithic private _validate_row as though that function were already generic.

The Round 2 loader accepts the five hypothesis labels H3-R, H7-R1, H7-R2, H8-R, and H9 plus the supporting, nonterminal R2-PREFLIGHT label. It rejects unknown labels to catch misspellings. R2-PREFLIGHT rows may prove prerequisites but can never receive the Round 2 terminal marker or substitute for hypothesis evidence.

The Round 2 outcome vocabulary includes pass, fail, inconclusive, not_tested, not_approved, and incomplete, but the finalizer applies narrower per-result rules. Candidate A and the unavailable PingOne workforce-only branch use nonterminal component conclusions of not_tested. H7-R2 may terminate as not_approved only when source evidence shows that the mechanism worked technically and the decision record shows architecture or security rejection. H8-R may terminate as incomplete only when Branch E or the combined scenario was not completed; it must not infer a pass from isolated branches. Candidate B cannot use not_tested to mask a failed or unfinished run.

H3-R has two required conclusions. Its top-level terminal outcome is the functional result: pass, fail, or inconclusive. When the functional result is fail, the terminal details must also contain causal_attribution with exactly refresh_specific, shared_with_h9, or unresolved, backed by H9 evidence where applicable. A pass uses not_applicable; an inconclusive result records unresolved. H9 terminates pass only when its terminal causal_attribution records one of controlled_recurrence, session_explanation_ruled_out, or test_session_explanation; otherwise H9 is inconclusive. Thus later H9 evidence can refine H3-R causality without changing H3-R's functional result.

Round 2 produces separate terminal evidence and a separate Round 2 assessment document. It never reads or writes Round 1 evidence or changes Round 1 required-hypothesis logic.

### 3.6 Google diagnostic and H9

The Google expiry diagnostic sends the in-memory access token only to Google's tokeninfo endpoint. It obtains the token within the process rather than accepting it as a command-line argument, environment variable, or shell-expanded value. It uses an isolated HTTP client with request and event logging disabled and environment proxy discovery disabled. Before the diagnostic, preflight requires HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, and their lowercase forms to be unset; it never prints a request URL. The diagnostic returns only a calculated UTC expiry or a category saying authoritative expiry was unavailable and writes no token, response body, query string, or shell-history entry. Hosted preflight proves this on a throwaway grant before H3-R.

The H9 command uses a configurable five-minute default interval and an operator-selected duration of at least 150 minutes. It records UTC and monotonic elapsed time, fingerprints, known expiry diagnostics, controlled sign-in timestamps, identity correlation, AWS and CloudTrail correlation, authorization-URL presence, and Drive outcome. On the first authorization_required it makes one controlled repeat using unchanged parameters and stops. It never follows an authorization URL, reconnects the provider, or sleeps inside an integration test.

### 3.7 Local and hosted preflight separation

round-2-preflight --local is a new, deterministic command implemented in a separate Round 2 preflight module. It shares no runtime or reachability path with the existing preflight command at cli.py:282, which intentionally calls check_reachability. The new command validates SQLite permissions and schema, evidence-key safety, policy structure, expected configuration aliases, Round 2 assessment isolation, and that .poc-expiry-state.json, .poc-round-2-jobs.sqlite3, and the SQLite sidecars are ignored. It neither calls runtime_factory nor initializes cloud clients, network clients, or provider credentials; an invariant test fails if any such factory is invoked.

round-2-preflight --hosted is an operator procedure, not an automatic command. After local preflight passes and the pre-run decisions are approved, it runs in this order:

1. Create the separate Entra resource application with its web redirect URI empty and with only the approved Graph permission.
2. Create the separate AgentCore Microsoft USER_FEDERATION provider, capture its returned callbackUrl and AWS-managed secret ARN in the mode-0600 ignored POC state, then register that exact callbackUrl as the Entra web redirect URI. This apply operation is a hosted prerequisite; its dry-run and unit-tested provisioning path are engineering preflight work.
3. Capture provider and IAM configuration fingerprints, verify synchronized UTC time, and validate the public callback tunnel required for connection establishment.
4. Prove tokeninfo on a throwaway grant with proxy variables absent and diagnostic logging disabled.
5. Perform direct AWS UserId positive and wrong-user negative controls under the dedicated worker role.
6. Complete the identity-mapping gate before any aging test. The identity architecture owner obtains an authoritative AWS statement or current product documentation, records its source and date, and approves one exact mapping rule or one bounded test value. The provisioning operator uses an explicit precommit command to write the resulting opaque value to the ignored POC state as identity_mapping_alias. New jobs copy that value immutably; the worker never accepts it from a job payload.
7. Using a JWT-established Microsoft connection, make one non-aging UserId interoperability probe with that precommitted value. Success proves interoperability only for that value. Failure of an authoritative documented mapping records identity_interoperability_not_demonstrated; lack of an authoritative mapping and lack of a successful precommitted value records inconclusive. Either result blocks Candidate B's aging test. Do not search arbitrary strings or establish a replacement UserId-backed connection.

Each hosted prerequisite writes a sanitized R2-PREFLIGHT row. A missing or failed prerequisite blocks live gates.

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

## 5. Architecture decision record

The implementation creates docs/round-2-architecture-decisions.md. The committed record contains sanitized statuses, rationale, owner aliases, and decision dates; it contains no direct account identifiers or provider material. The ignored POC state contains the exact provisioned aliases and configuration fingerprints. Before hosted preflight, each row must contain either a final decision or an explicit, binding acceptance rule for a conclusion that depends on later observation. The observed final decision is added after the corresponding test without changing that precommitted rule.

| Decision | Current POC position |
| --- | --- |
| Durable job record as UserId authority | Approved for bounded POC, subject to this design's controls. |
| Candidate B worker role | Approved for bounded POC, subject to direct AWS positive and negative proof. |
| JWT/UserId identity mapping | Identity architecture owns the authoritative-source check and mapping-rule approval; the provisioning operator precommits the exact opaque identity_mapping_alias; security reviews the trusted derivation and live interoperability result. No aging test runs until the gate passes. |
| Candidate A | not_tested; no approved noninteractive same-user JWT issuance exists. |
| Keycloak | Optional Candidate A follow-on; requires separate review of issuance authority, credential custody, and revocation. |
| Job maximum lifetime and offboarding freshness | Engineering uses a 60-second conservative freshness default for tests; architecture must fix both values before hosted preflight. |
| Bounded post-offboarding Graph-token lifetime | Architecture fixes the maximum acceptable exposure before hosted preflight, then compares the observation with that limit. |
| Residual AgentCore vault storage | Architecture precommits the conditions under which residual storage could be accepted; after H8-R Branch E it records accept or reject against the observed state and restoration behavior. |
| forceAuthentication behavior | Architecture decides before the probe whether proven targeted refresh-credential invalidation is sufficient when record deletion remains unproven; no result may be described as deletion without AWS evidence. |
| H9 no-recurrence closure standard | Architecture fixes the observation duration and corroborating evidence before H9; the duration cannot be less than 150 minutes or end before the initial inbound/workload expiries. |
| Entra-coupled offboarding evidence | Architecture decides before H8-R whether coupled evidence can close the POC or whether unavailable PingOne B1 keeps it open. |

## 6. Verification strategy

Implementation is test-first. At minimum, tests cover SQLite creation and restrictive permissions; exact ignore rules for the resume and SQLite files; migration and transactional state changes; every invalid binding and record state; the 60-second default and configured offboarding freshness; mapping precommit provenance and rejection of resume-time user input; pre- and post-acquisition offboarding checks; AgentCore UserId and Microsoft request shapes; all worker IAM statements; Microsoft provider dry-run ordering and callback capture; real EvidenceWriter validation including every listed key; Round 1 and Round 2 assessment separation and outcome matrices; diagnostic proxy/log/shell-input suppression; H9 dual-conclusion and repeat/stop behavior; and the new local preflight's no-runtime/no-cloud/no-network invariant.

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
