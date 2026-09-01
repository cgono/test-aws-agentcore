# AgentCore Identity POC — Round 2 Hypotheses and Test Design

**Date:** 2026-09-01

**Status:** Proposed for architecture and security review

**Audience:** Architecture, security, identity, and POC operators

**Round 1 record:** `docs/executive-summary.md`, `docs/assessment.md`, and
`docs/runbook.md`

## 1. Purpose and relationship to Round 1

Round 1 remains an immutable record of what the POC demonstrated at the time:

- H3 failed because AgentCore did not expose provider-token expiry metadata, so the run could not
  distinguish a refreshed Google token from a still-valid cached token safely.
- H7 failed because the Microsoft OBO path could not obtain a new downstream token after the
  original inbound Entra JWT expired.
- H8 failed because the POC found no acceptable narrow per-user purge operation and did not observe
  downstream revocation.
- A roughly hourly recurrence of `google_authorization_required` remained unexplained.

Round 2 does not overwrite those outcomes. It tests narrower follow-up hypotheses that may show
whether AgentCore is usable through a different Microsoft flow, whether Google refresh works
despite missing metadata, and whether compensating controls can make residual vault storage
acceptable.

## 2. Proposed hypothesis set

| ID | Question | Terminal pass criterion |
| --- | --- | --- |
| H3-R | Does AgentCore behaviorally refresh a naturally expired Google access token even when it omits expiry metadata? | After independently confirmed natural expiry plus clock-skew allowance, AgentCore returns a token with a different one-way fingerprint and Drive succeeds without renewed authorization. |
| H7-R1 | Can Microsoft `USER_FEDERATION` make AgentCore the refresh-token vault for delegated Graph access? | After the original inbound Entra JWT and workload token expire, a newly acquired, correctly user-bound workload token retrieves the existing Microsoft connection and Graph succeeds without renewed Microsoft interaction. A weaker result that requires workforce interaction but no resource-app authorization is recorded separately and does not satisfy this strict criterion. |
| H7-R2 | Can a long-running background agent resume securely? | Under at least one architecture-approved asynchronous authorization model, a dedicated worker obtains a new, correctly user-bound workload token and retrieves the existing Microsoft connection; all negative authorization controls deny access. |
| H8-R | Can layered identity, application, and downstream controls compensate for absent or inadequate per-user purge? | Local denial and downstream revocation prevent approved application retrieval and downstream use after existing access tokens expire. Residual vault state and its behavior after local restoration are separately recorded and explicitly accepted or rejected by architecture review. |
| H9 | Is the roughly hourly `authorization_required` lapse a product behavior or a test-account/browser-session artifact? | The test classifies the observation by reproducing it under a clean identity, otherwise ruling out the account/session explanation, or positively demonstrating that account/session contamination causes it. |

`R` means a Round 2 refinement. It does not imply that the corresponding Round 1 result has changed.

## 3. Design principles

### 3.1 Separate identity paths

Round 2 uses separate roles and workload identities for the two workload-token paths:

- **Interactive/JWT path:** continues to use `GetWorkloadAccessTokenForJWT`. Its IAM policy retains
  the explicit deny on `GetWorkloadAccessTokenForUserId`.
- **Asynchronous/UserId path:** uses a dedicated worker role and workload identity. It may call
  `GetWorkloadAccessTokenForUserId` only after validating a durable job-authorization record and
  the current offboarding state.

AWS recommends the JWT path when a JWT is available because AgentCore validates its signature,
issuer, and expiry. AWS treats the UserId value as an opaque, caller-asserted string; its security
therefore depends on trusted upstream resolution, IAM scoping, and audit controls. The Round 2
design treats the UserId path as an exceptional enterprise pattern, not an equivalent substitute
for cryptographic user proof. See the AWS guidance for
[`GetWorkloadAccessTokenForUserId`](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/get-workload-access-token.html).

For the bounded POC, the asynchronous role must also restrict the
`bedrock-agentcore:userid` condition to the exact namespaced test-user value and scope access to the
named workload identity and credential provider. This makes the wrong-user negative control an IAM
denial as well as an application denial. A production role that serves an open-ended user
population cannot claim the same static condition as its complete user-binding control; that
requires a separate architecture decision.

**Verify the condition key before you rely on it.** Current AWS documentation says
`bedrock-agentcore:userid` applies to `GetWorkloadAccessTokenForUserId` and
`CompleteResourceTokenAuth`, but the POC must prove the live behavior before treating it as a
control. Give the dedicated test role an `Allow` for `GetWorkloadAccessTokenForUserId` on the exact
workload resource with `StringEquals` on the approved namespaced user value, and ensure no other
statement grants that action. Preflight must then make two direct AWS calls without application
logic intercepting them:

1. **Positive control:** the worker calls `GetWorkloadAccessTokenForUserId` with the exact approved
   user value, and the call succeeds.
2. **Negative control:** the same worker calls it with a different user value, and AWS returns
   `AccessDeniedException`.

If the positive call fails or the negative call succeeds, record the IAM condition control as
unproven or unavailable and stop Candidate B. Do not fall back to application logic alone for the
wrong-user control. A future policy using a `Deny` must specify and test its exact condition
operator separately because missing-key behavior differs between ordinary, negated, and
`IfExists` operators.

### 3.2 Separate Microsoft providers

Create a new Microsoft credential provider and Entra application registration for
`USER_FEDERATION`; do not reuse the Round 1 OBO provider. Use the minimum delegated Graph permission
needed for the probe. `User.Read` and `GET /me` are sufficient unless the review specifically
requires a file operation. Include `offline_access` so Microsoft can issue a refresh token, as
described by the current
[AgentCore refresh-token guidance](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity-authentication.html).

The provider setup must follow the current
[AgentCore Microsoft provider procedure](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity-idp-microsoft.html),
including registering AgentCore's provider-specific callback URL in Entra.

AgentCore issues that callback URL only in the `CreateOauth2CredentialProvider` response, so the
order matters. Create the Entra application registration first and leave its redirect URI empty.
Then create the AgentCore credential provider. Then register the returned `callbackUrl` in Entra as
a web platform redirect URI.

**Do not send `access_type` to Microsoft.** AWS configures refresh tokens per provider. Google needs
`customParameters={"access_type": "offline"}`. Microsoft needs `offline_access` in `scopes` and no
equivalent custom parameter. `agentcore.py`'s `google_token()` hardcodes the Google custom
parameter, so a Microsoft call must not reuse that method. Round 1 recorded that an unrecognized
custom parameter does not raise an error: AgentCore reports a completed authorization, vaults
nothing, and every later retrieval reports authorization required.

### 3.3 Durable job authorization

The asynchronous path requires a durable authorization record containing no provider token:

| Field | Required meaning |
| --- | --- |
| `job_id` | Immutable identifier for the background job. |
| `user_key` | Canonical, namespaced workforce identity derived by a trusted identity-resolution layer; never accepted from job payload input. |
| `agentcore_identity_key` | The exact, precommitted mapping expected to reach the connection created for that user. |
| `provider` and `scopes` | One named Microsoft provider and an exact least-privilege scope set. |
| `workload` and `operation_class` | The dedicated worker identity and approved class of work. |
| `approved_at`, `expires_at`, and `approved_by` | Authorization provenance and a finite maximum lifetime. |
| `status` | `active`, `completed`, `expired`, or `revoked`. |
| `offboarding_status` and `checked_at` | Current local deny/offboarding decision and freshness of that decision. |

The worker checks the record immediately before acquiring a workload token and again before every
downstream call. A provider access token already in memory does not override a newly applied deny.

These field names describe the job record itself, which is never committed evidence. Map them to the
approved evidence key names in section 3.4 before any evidence row is written.

### 3.4 Evidence and token handling

All test hosts must use a synchronized UTC clock. Each event records both UTC and monotonic elapsed
time. A default five-minute allowance is applied after a confirmed token expiry unless the
provider documents a larger allowance.

Committed evidence may contain only:

- test-run and hypothesis correlation, step, and result category;
- opaque user alias and one-way subject correlation, never an email address or display name;
- workload/provider aliases and IAM role alias;
- OAuth flow, requested scopes, and acquisition path;
- one-way SHA-256 fingerprints, timestamps, and expiry diagnostic source;
- whether AgentCore returned an authorization URL and whether `CompleteResourceTokenAuth` occurred;
- downstream status category, AWS correlation values, and relevant CloudTrail correlation;
- local deny, workforce-account, job-authorization, and downstream-revocation states.

**Use approved evidence key names.** `redaction.py` rejects any evidence key that contains the
components `access`, `api`, `authorization`, `bearer`, `client`, `code`, `cookie`, `id`, `key`,
`password`, `refresh`, `secret`, `session`, `set`, `state`, or `token`. `correlation_id` is the only
exemption. Many natural names for Round 2 data therefore raise `UnsafeEvidenceError` in the live
evidence writer. Round 1 hit this failure live with the key `token_kind`. Use these standardized
names instead:

| Data | Natural/source name | Evidence key | Validator result for source name |
| --- | --- | --- | --- |
| Test run | `run_id` | `run_correlation` | Rejected. |
| Provider access-token fingerprint | `token_fingerprint` | `resource_fingerprint` | Rejected. |
| Workload-token fingerprint | `workload_token_fingerprint` | `workload_fingerprint` | Rejected. |
| Inbound JWT fingerprint | `source_token_fingerprint` | `source_fingerprint` | Rejected. |
| AWS request identifier | `request_id` | `aws_correlation` | Rejected. |
| Job-authorization record | `job_id` | `job_correlation` | Rejected. |
| Canonical user | `user_key` | `user_alias` | Rejected. |
| Expected AgentCore mapping | `agentcore_identity_key` | `identity_mapping_alias` | Rejected. |
| Authorization URL returned | `authorization_url_returned` | `browser_prompt_returned` | Rejected. |
| Session binding completed | `session_binding_completed` | `binding_completed` | Rejected. |
| Job state | `status` | `job_status_category` | Accepted but too generic. |
| Deny or offboarding state | `offboarding_status` | `offboarding_category` | Accepted; standardized for consistency. |

Two rules are easy to forget. `correlation_id` is the only allowed name that ends in `_id`; every
other `*_id` name is rejected. `state` is a blocked component, so `job_state_category` is rejected
while `job_status_category` is accepted.

Check every new key before you use it live:

```bash
python3 -c "import sys; sys.path.insert(0,'src')
from agentcore_identity_poc.redaction import assert_safe_evidence, UnsafeEvidenceError
for name in sys.argv[1:]:
    try:
        assert_safe_evidence({name: 'x'}); print('accepted', name)
    except UnsafeEvidenceError:
        print('rejected', name)" resource_fingerprint job_correlation
```

The placeholder name itself must comply. `your_new_key` is rejected, because `key` is a blocked
component.

Add a unit test that routes every new Round 2 evidence row through the real `EvidenceWriter`, not a
fake one. Both `EvidenceWriter` and the assessment loader call `assert_safe_evidence`, but the fake
writers used by most CLI tests do not; that is why Round 1 found the `token_kind` failure live
instead of at append time in CI.

**Write Round 2 evidence to a separate file.** Use `evidence/round-2.jsonl`. Do not append Round 2
rows to the Round 1 evidence file. `assessment.py` fixes `REQUIRED_HYPOTHESES` at `H1` to `H8`, so
`load_terminal_results` silently ignores every row named `H3-R`, `H7-R1`, `H7-R2`, `H8-R`, or `H9`.
`assessment-finalize` therefore cannot process Round 2 without a code change. If a Round 2 row
instead reuses a plain `H3`, `H7`, or `H8` identifier in the Round 1 file, it adds a second terminal
row and finalize fails with "expected exactly one terminal result". That breaks the Round 1 record
this document promises to keep. Building the Round 2 finalize path is preflight work; see
section 9.

Raw provider tokens, workload tokens, refresh tokens, authorization URLs, cookies, client secrets,
and provider responses are not committed or logged. H3-R never persists the Google access token.
Where another test must retain a previously issued workload token across a real expiry boundary, it
uses the Round 1 raw-state pattern documented in `docs/runbook.md`. The raw token goes to the
git-ignored `evidence/raw/` directory in a mode-`0600` file. The separate
`.poc-expiry-state.json` resume file is also written with mode `0600`, but the current `.gitignore`
does not list it; add that path to `.gitignore` before live testing and never stage it. Delete raw
token state on success, failure, or abandonment.

An automatic consent flow is forbidden during an observation. Returning an authorization URL is
recorded as an outcome and the test stops. Following the URL would destroy the evidence being
measured.

### 3.5 Engineering work Round 2 needs

Round 2 is not a configuration change. The POC code does not contain these parts yet. Build and
unit-test each one before the live gates run:

| Need | Current state |
| --- | --- |
| Microsoft `USER_FEDERATION` retrieval | `agentcore.py` has `obo_token()` for OBO and `google_token()` for Google. `google_token()` sends Google-only custom parameters. A Microsoft user-federation method does not exist. |
| `GetWorkloadAccessTokenForUserId` | The `AgentCoreDataPlane` protocol does not declare this operation, and no code calls it. |
| Dedicated worker role and workload identity | `infra/iam/` holds only the Round 1 scoped policy and the user-ID deny policy. |
| Durable job-authorization record | No store, schema, or offboarding check exists. |
| Repeating H9 probe | No command runs a repeated retrieval and Drive probe on a timer. |
| Round 2 evidence and assessment path | See section 3.4. |

## 4. H3-R — Controlled Google natural-expiry refresh

### Hypothesis

AgentCore can refresh a user-federated Google credential after access-token expiry even though the
`GetResourceOauth2Token` response does not expose expiry metadata.

Google documents that access tokens have limited lifetimes and that a refresh token can obtain new
access tokens without renewed consent. AgentCore currently documents automatic use of a stored
refresh token when an access token expires. Round 2 tests that behavior rather than inferring it
from the documented claim. See the
[Google OAuth 2.0 guidance](https://developers.google.com/identity/protocols/oauth2) and
[AgentCore automatic-refresh guidance](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity-authentication.html).

### Preconditions and controls

- Use the existing Google provider with exactly the known-good Drive metadata scope and
  `access_type=offline`. Do not add `prompt` or any unverified custom parameter.
- Use a clean browser identity and verify the expected AgentCore user mapping before connection.
- Establish a fresh Google grant and prove a baseline Drive metadata call.
- Use Google's `tokeninfo` endpoint as the approved expiry diagnostic. It returns `expires_in` for
  the presented access token, and it sends that token only to the provider that issued it, which is
  acceptable. Prove the diagnostic works during preflight, on a throwaway grant. The token stays in
  process memory, and only the returned absolute expiry is recorded. Disable HTTP client debug
  logging and ensure the request URL cannot enter application, proxy, shell-history, or evidence
  logs because the diagnostic carries the access token as a query parameter. If preflight shows
  that `tokeninfo` gives no authoritative expiry, the test is `inconclusive`; elapsed time alone is
  not confirmed expiry.
- Do not apply the runbook's "reconnect Google before every rerun" workaround during this test. A
  reconnect creates a new grant and destroys the evidence H3-R measures.

### Procedure

1. Record the test-run ID, user alias, provider configuration fingerprint, scopes, and UTC clock
   status.
2. Establish a new Google connection through the existing session-binding callback.
3. Retrieve one access token, calculate its one-way fingerprint in memory, and call Drive.
4. Query the approved expiry diagnostic while the token is still only in memory. Persist the
   fingerprint, absolute expiry, diagnostic source, and baseline Drive result; discard the token.
5. Wait outside the test process until the recorded expiry plus five minutes.
6. Recheck clock synchronization and verify that no provider, scope, user mapping, or local deny
   state changed.
7. Request the credential again with identical parameters. Do not use `forceAuthentication`.
8. Record the new one-way fingerprint and call the same Drive operation.
9. Confirm from callback/application evidence that no authorization URL was followed and no new
   `CompleteResourceTokenAuth` occurred.

### Interpretation

- **Pass:** expiry was independently confirmed, the fingerprint changed, and Drive succeeded
  without renewed authorization.
- **Fail — refresh:** after confirmed expiry, AgentCore requires authorization or returns a token
  that Drive rejects.
- **Fail — identity continuity:** evidence shows the same intended user was presented but AgentCore
  looked up a different or absent connection. Record separately from refresh failure.
- **Inconclusive:** expiry was not authoritative, the test ran early, the browser/user mapping is
  uncertain, parameters changed, or the diagnostic itself affected the grant.

**H9 informs cause, not the H3-R functional result.** A refresh failure and the unexplained hourly
lapse can produce the same observation: `authorization_required` about one hour after the
connection was established. The Google access-token lifetime and the lapse horizon overlap almost
exactly. Record two separate conclusions:

- **Functional result:** after confirmed expiry, changed fingerprint plus a successful Drive call
  is `pass`; `authorization_required` or a Drive-rejected credential is
  `fail — post-expiry reacquisition`.
- **Causal attribution:** classify a failure as `refresh-specific`, `shared with H9`, or
  `unresolved`. H9 may change this attribution, but it cannot turn a failed end-to-end behavior
  into `inconclusive`.

An H3-R run is still `inconclusive` when expiry, identity continuity, configuration stability, or
the diagnostic itself cannot be proven, as defined above.

A pass refines the Round 1 conclusion to: behavioral refresh works, but expiry observability
remains absent. It does not retroactively turn H3 into a pass because Round 1's operational
metadata requirement remains unmet.

## 5. H7-R1 — Microsoft `USER_FEDERATION` refresh-token vault

### Hypothesis

After one Microsoft user-federation interaction, AgentCore can hold the long-lived Microsoft
credential and later vend a fresh delegated Graph access token without another Microsoft
interaction, even when the tokens used to establish the connection have expired.

### Preconditions and controls

- Use the separate Microsoft provider described in section 3.2.
- Call it with a new Microsoft user-federation method. Do not reuse `google_token()`; see
  section 3.2.
- In this POC the workforce IdP and the Microsoft resource IdP are the same Entra tenant. Use a
  separate application registration for the resource provider, so consent and sign-in events can be
  told apart in the Entra logs.
- Fix one Graph operation and its minimum delegated permission before consent.
- Record the expected Entra tenant, subject correlation, workforce issuer, workload identity, and
  exact scopes.
- Define how expiry of both the original inbound JWT and workload token will be confirmed. For an
  opaque token without expiry metadata, rejection of that original token is the negative proof.
- Preserve Entra sign-in/audit evidence outside the repository so interactive activity can be
  distinguished from refresh-token redemption.

### Establishment and baseline

1. Acquire a valid inbound JWT and mint a JWT-backed workload token.
2. Call `GetResourceOauth2Token` with `oauth2Flow=USER_FEDERATION`, the exact scopes including
   `offline_access`, and the approved return URL.
3. Complete session binding once as the same active user.
4. Retrieve the Microsoft resource token and call the fixed Graph operation.
5. Record sanitized source/workload/resource fingerprints, known expiries, Graph subject
   correlation, AWS correlation values, and authorization-event timestamps.
6. Allow both the original inbound JWT and original workload token to expire. Confirm the expiry
   boundary rather than relying on a nominal 60-minute wait.

### Candidate A — fresh workforce JWT

1. Obtain a fresh JWT from the configured workforce IdP for the same canonical user.
2. Validate issuer, signature, audience, expiry, and required claims locally.
3. Confirm that its subject maps to the same AgentCore connection identity used during
   establishment.
4. Mint a new workload token, retrieve the Microsoft resource token, and call Graph.
5. Verify that AgentCore returned no authorization URL and that no new `CompleteResourceTokenAuth`
   event occurred.
6. Record workforce interaction and resource-app interaction separately. `entra.py` supports only
   the device-code flow, so step 1 is itself an interactive Microsoft workforce sign-in in the
   current POC. Entra sign-in and consent logs must still prove that the separate resource
   application registration had no new authorization or consent event.

Candidate A is supplementary in the current Entra-only POC: it can prove that AgentCore reused the
resource connection after a new workforce sign-in, but it cannot satisfy H7-R1's strict
"no renewed Microsoft interaction" criterion. It becomes eligible for the strict criterion only
if a separately approved workforce IdP can issue the fresh same-user JWT without Microsoft
interaction.

### Candidate B — `GetWorkloadAccessTokenForUserId`

1. Start with an active durable job-authorization record for the same user and operation.
2. Resolve the namespaced `user_key` from the trusted record, never from caller input.
3. Assume the dedicated worker role and confirm the current offboarding decision is allow.
4. Call `GetWorkloadAccessTokenForUserId`, retrieve the existing Microsoft credential, and call
   Graph.
5. Verify Graph's user context matches the established user's sanitized subject correlation.
6. Verify that no authorization URL appeared and that Entra logs show no new workforce sign-in,
   resource-app authorization, or consent event.

This branch must not assume that a caller-supplied UserId and a JWT's `iss`/`sub` address the same
vault partition. Whether the UserId path can retrieve a connection established through the JWT
path is itself part of the test. Establishing a second Microsoft connection through the UserId
path does not satisfy the pass criterion.

Candidate B has an identity-mapping gate before the live aging test. Obtain an authoritative AWS
statement or current product documentation that defines whether and how a UserId-backed workload
token addresses a connection established through the JWT-backed path. AWS's
`provider_id+user_id` example is namespace/collision guidance for the UserId path; it is not proof
that the literal string maps to AgentCore's internal JWT `iss`/`sub` partition. AgentCore does not
expose an exact JWT-partition composite string for the POC to reproduce.

- If AWS documents a mapping, precommit that exact mapping and test it once with the approved user.
- If a UserId value successfully retrieves the JWT-established connection, interoperability is
  proven for that value and Candidate B may continue.
- If documented candidates fail, record `identity interoperability not demonstrated`; do not claim
  that arbitrary additional strings would also fail.
- If AWS supplies no authoritative mapping and no value succeeds, Candidate B is `inconclusive`
  and must not proceed to the long-running pass test.

Establishing a separate connection through a UserId-backed workload token may be tested as a
different architecture, but it cannot satisfy this candidate's requirement to retrieve the
existing JWT-established Microsoft connection.

### Interpretation

Report Candidate A and Candidate B independently:

- **Pass:** the new workload token is correctly user-bound, the existing connection is retrieved,
  Graph succeeds as that user, and no renewed Microsoft interaction occurs. Candidate A's weaker
  Entra-only result is reported as supplementary, not as this pass.
- **Fail — vault refresh:** the same connection is found but AgentCore cannot produce a usable
  post-expiry Graph token.
- **Fail — identity partition:** AWS documents the expected cross-path mapping, the POC presents it
  correctly, and AgentCore maps the enterprise user to a different vault identity. Failed guesses
  without an authoritative mapping are inconclusive instead.
- **Fail — user binding:** a token or Graph result is bound to any other user. This is a stop-work
  security failure.
- **Inconclusive:** source/workload expiry, user continuity, or the absence of renewed Microsoft
  interaction cannot be demonstrated.

## 6. H7-R2 — Long-running secure reacquisition

### Hypothesis

A suspended background job can resume after its original identity tokens expire without turning a
caller-supplied user string into an impersonation primitive.

### Procedure

Run the same job twice from a known-good Microsoft user-federation baseline, once per candidate
path:

1. Create an active job-authorization record with a finite expiry and exact user, provider, scope,
   workload, and operation bindings.
2. Start the worker, prove one Graph call, checkpoint the job, and discard in-memory provider
   credentials.
3. Wait until the original inbound and workload tokens expire.
4. Resume through Candidate A or Candidate B from section 5.
5. Recheck job authorization and offboarding immediately before workload-token acquisition.
6. Retrieve the existing Microsoft credential, recheck authorization, and call Graph.
7. Mark the job completed so its authorization cannot be replayed.

Candidate A is eligible only if the workforce IdP has an architecture-approved way to issue a new
same-user JWT to the worker without misrepresenting an application identity as a user. Candidate B
is eligible only after architecture and security approve the durable-record model and dedicated
role.

**Candidate A is `not tested` with the current POC implementation.** A background job resumes when
no user is present, while `entra.py` acquires a JWT only through the interactive device-code flow.
Adding an MSAL token cache would put a long-lived Microsoft workforce refresh token in our
platform, contradicting the POC premise, so that is not an implicit fallback. A future workforce
IdP might offer another architecture-approved asynchronous issuance model; evaluate that model on
its own terms rather than claiming MSAL caching is the only possible architecture. Until such a
mechanism is supplied and approved, Candidate B is the only H7-R2 path this POC can run.

### Required negative controls

Each candidate must deny safely when applicable:

- the job record is expired, completed, or revoked;
- the user is locally denied or offboarded;
- the requested provider, scope, operation, or workload differs from the record;
- a different IAM role attempts the call;
- a different user key is substituted;
- the authorization changes between token acquisition and the Graph call.

No negative control may fall back to browser authorization or create a new connection.

### Interpretation

- **Pass:** at least one architecture-approved candidate resumes as the correct Graph user, and all
  its required negative controls deny.
- **Fail:** an approved candidate cannot resume, crosses users, ignores revocation, or permits an
  unbound role/operation.
- **Not approved:** the mechanism works technically but architecture or security rejects its
  authorization model. This does not count as a pass.
- **Not tested:** a candidate lacks the required workforce-IdP capability or review approval.

H7-R2 does not change Round 1 H7. OBO still fails after its subject assertion expires; Round 2 is
testing an alternative user-federation architecture.

## 7. H8-R — Offboarding compensation matrix

### Hypothesis

Even if AgentCore has no reliable general-purpose per-user delete operation, independent local,
workforce, and downstream controls can prevent future approved use of the user's Microsoft
connection after the bounded lifetime of already-issued access tokens.

Microsoft documents that `revokeSignInSessions` invalidates refresh tokens and browser session
cookies, may take several minutes, and does not immediately make every already-issued access token
disappear. See the Microsoft Graph
[`revokeSignInSessions` reference](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0)
and the Microsoft
[refresh-token lifecycle](https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens).

### Isolation rule

Test each control from an independently restored known-good baseline. Do not stack controls until
the final combined scenario. Otherwise, a local deny could mask a failed workforce disablement or
a still-usable downstream grant.

**The production workforce-only control is unavailable in this POC.** The intended production
mapping disables a PingOne account, but no PingOne or AD FS environment exists. This is the same
missing prerequisite recorded by Round 1 H5; H5 itself is not the cause of the block. The only
workforce IdP available is Entra, which is also the Microsoft resource IdP.

Keep the controls distinct in the record:

- Record the production-representative PingOne workforce-only control as
  `not tested — no separate workforce IdP environment`.
- Run an Entra account-disablement surrogate from its own known-good baseline. It can prove that no
  new workforce JWT or JWT-backed workload token is available for a disabled user, but its
  workforce and downstream effects are coupled and cannot be attributed independently.
- Run Branch C separately from another known-good baseline. Revoking Entra sessions or the grant
  without disabling the account remains a distinct, independently testable action.

Do not claim that the Entra surrogate proves the production separation. Architecture review must
decide whether the coupled evidence is sufficient or whether the missing PingOne test keeps H8-R
open.

### Matrix

| Branch | Action | Immediate probe | Post-expiry probe | Required attribution |
| --- | --- | --- | --- | --- |
| A — local deny | Add the user to the application deny record. | New gateway/worker activity is rejected, including activity presented with a previously issued workload token. | Denial remains effective. | Application policy decision and absence of AgentCore retrieval. |
| B1 — production workforce disable | Disable the PingOne workforce account without changing the Entra resource identity. | No new PingOne JWT or JWT-backed workload token can be established. | Retry remains denied after propagation allowance. | `Not tested` in this POC unless a separate workforce IdP environment is supplied. |
| B2 — Entra surrogate | Disable the Entra test account from a known-good baseline. | No new Entra workforce JWT or JWT-backed workload token can be established. | Retry remains denied after propagation allowance. | Entra account-state event plus local token-validation outcome; downstream effects are coupled. |
| C — Entra revoke | Use an Entra-team-approved administrative or delegated token to revoke the user's sessions or grant. | Record whether the existing Graph access token still works during its residual lifetime. | Refresh-token redemption fails and Graph cannot be called with an expired access token. | Entra revocation event, AgentCore retrieval result, and Graph result. |
| D — old workload token | Attempt AgentCore retrieval with the exact workload token issued before each control. | Record whether AgentCore returns a cached or new Microsoft access token. | Returned material, if any, must not create a usable downstream path. | Token fingerprints, expiry boundary, and Graph result. |
| E — local restore | In the isolated POC only, restore local allow after downstream revocation. | Attempt retrieval without completing any new authorization. | Determine whether residual AgentCore state becomes usable. | Authorization URL flag, callback count, Graph result, and Entra logs. |

An already-issued Graph token may remain usable before its expiry. That residual exposure is not a
test failure if it matches the recorded lifetime and local application controls prevent the
approved agent from using it. It is a risk interval that the architecture review must accept or
reject.

### `forceAuthentication` targeted-purge probe

Current AWS documentation states that `forceAuthentication=true` clears stored refresh tokens and
forces a complete federation flow. Round 2 must verify the scope and effect of that claim rather
than treating it as a documented per-user deletion API:

1. Start with working Microsoft connections for User A and User B on the same provider.
2. As User A's correctly bound workload identity, call `GetResourceOauth2Token` with
   `forceAuthentication=true` and the exact normal scopes.
3. Do not follow the returned authorization URL and do not complete session binding.
4. After User A's existing Graph access token expires, attempt ordinary retrieval and Graph use.
5. Confirm User B's connection remains retrievable and usable.
6. Record whether the service exposes any evidence of deleted storage, cleared refresh capability,
   or only a forced-authentication state.

This subtest passes as a targeted refresh-credential invalidation only if User A cannot resume
without new authorization and User B is unaffected. It is not called storage deletion unless AWS
provides evidence that the stored per-user record itself is gone.

### Combined scenario and interpretation

After the isolated branches, apply local deny, the available workforce-disablement control, and
Entra revocation in the approved operational order. Then repeat the old-workload-token and Graph
probes before and after both the known Graph access-token expiry and the original workload-token
expiry. In the current environment, label this the **Entra-coupled combined scenario**. It does not
become production-representative unless B1 is later run with a separate workforce IdP.

- **Technical pass:** the approved application cannot retrieve or use the connection after local
  deny; after revocation propagation and expiry of the previously issued Graph and workload
  tokens, the old workload token cannot retrieve, no new workforce/workload token can be
  established, and Graph access cannot be reacquired.
- **Fail:** any approved application path survives local denial, a fresh user-bound workload token
  can be established for the disabled user, or Graph remains usable through refresh after the
  downstream revocation propagation and access-token expiry boundaries.
- **Inconclusive:** token lifetimes, propagation, residual token provenance, or user mapping cannot
  be proven.

If architecture requires independently attributable workforce disablement, the unavailable B1
result keeps H8-R open even when the Entra-coupled combined scenario technically passes.

Technical pass is necessary but not sufficient. Architecture review must separately record:

```text
Residual AgentCore vault storage: accept | reject
Observed state:
Restoration behavior:
Maximum access-token exposure window:
Compensating controls and owners:
AWS clarification or roadmap dependency:
Decision owner and date:
```

If residual storage is rejected, H8-R cannot support adoption even when the technical matrix
passes.

## 8. H9 — Hourly `authorization_required` lapse classification

### Hypothesis

The prior roughly hourly Google lapse can be attributed either to a repeatable AgentCore/provider
boundary or to browser/test-account identity contamination.

### Controlled setup

- Use a new dedicated browser profile with no cached Microsoft or Google accounts.
- Sign in to exactly one Microsoft identity and one intended Google identity.
- Record the expected sanitized `iss`/`sub` correlation before Google authorization and at every
  subsequent JWT acquisition.
- Establish a fresh Google connection with the known-good scopes and custom parameters.
- Prove a baseline Drive call and record its connection marker and token fingerprint.
- Make no provider, IAM, callback, scope, custom-parameter, or application-policy changes during
  the observation.
- Verify the public callback tunnel during connection establishment. Monitor its health afterward
  because Round 1 recorded quick tunnels that died, but do not automatically invalidate an H9
  retrieval observation merely because the callback later becomes unreachable: H9 forbids
  following a new authorization URL, so the callback is not on the successful retrieval path.
  Invalidate only an observation that actually depended on the failed tunnel or another failed
  public endpoint.

### Observation procedure

1. Run a credential-retrieval and Drive probe every five minutes for at least 150 minutes, and
   beyond the known expiry of the initial inbound and workload tokens. A probe needs no user
   interaction while the current workload token stays valid.
2. Obtain fresh JWT-backed workload tokens only through the controlled single-identity session. Plan
   for the interruption: `entra.py` supports only the device-code flow, so every new inbound JWT
   needs an interactive sign-in. The observation window therefore contains one or more operator
   sign-ins, and that sign-in is itself the suspected contamination source. Record every sign-in
   with its UTC timestamp, and record the resolved subject correlation immediately after it.
3. For every probe record UTC and monotonic time, source/workload/resource fingerprints and known
   expiries, sanitized subject correlation, the AgentCore correlation value, CloudTrail event
   correlation, authorization-URL presence, and Drive result.
4. If `authorization_required` occurs, stop normal retries. Record the first failing timestamp and
   make one controlled repeat with the same identity and parameters; do not reconnect.
5. Correlate the transition with source-token expiry, workload-token expiry, Google access-token
   expiry, AgentCore observability, browser sign-in events, and any change in the resolved user.

### Interpretation

- **Classified — controlled recurrence:** the lapse occurs while identity and configuration remain
  stable, with correlated evidence locating or narrowing the failing boundary. This rules out the
  known multi-account browser explanation, but it is labeled an AgentCore/provider defect
  candidate until AWS or provider evidence identifies ownership.
- **Classified — session explanation ruled out by other evidence:** the clean run does not itself
  reproduce the lapse, but correlated identity and provider evidence independently excludes the
  proposed account/session mechanism and narrows the failure to a product/provider boundary.
- **Classified — test-session explanation:** a subject/account mismatch is observed in the old
  scenario, or the clean single-identity run remains healthy for the full window while a deliberate
  contaminated-session control reproduces the earlier behavior.
- **Inconclusive:** the lapse does not recur and the test cannot reproduce the session explanation,
  timestamps are incomplete, or the identity/configuration changes during observation.

The absence of recurrence in one clean run alone does not prove the product is defect-free. It
only rules out a defect finding for this POC if the session explanation is positively supported.

## 9. Execution order and stop gates

Run the tests in this order:

1. **Preflight:** capture provider/IAM configuration fingerprints, confirm time synchronization,
   validate evidence redaction, and obtain architecture approval for candidate asynchronous paths.
   Also finish this build and verification work before any live gate:
   - the approved evidence key names, plus a unit test through the real `EvidenceWriter`
     (section 3.4);
   - the separate Round 2 evidence file and its finalize path (section 3.4);
   - the Microsoft user-federation method and the `GetWorkloadAccessTokenForUserId` call
     (section 3.5);
   - the `bedrock-agentcore:userid` positive and negative controls (section 3.1);
   - the Google `tokeninfo` expiry diagnostic, proven on a throwaway grant (section 4);
   - a healthy public callback tunnel for connection establishment, with separate health evidence
     if any observed step actually depends on it (section 8).
2. **H9:** characterize the unexplained lapse before other destructive or forced-authentication
   actions can contaminate it.
3. **H3-R:** create a separate fresh Google grant and run the controlled expiry test. H9 evidence
   may not substitute unless it independently meets every H3-R precondition.
4. **H7-R1:** establish and age the separate Microsoft user-federation connection.
5. **H7-R2:** run every approved and currently testable reacquisition candidate and its negative
   controls. Record Candidate A as `not tested` under the current implementation.
6. **H8-R:** run isolated offboarding branches, the targeted `forceAuthentication` probe, and the
   combined matrix last because they intentionally alter identity and grant state.
7. **Closeout:** sanitize evidence, delete raw token state, record the architecture decisions, and
   only then authorize AWS resource teardown.

### Timebox and scope cuts

Round 2 is long, and most of it is waiting. Each aging step needs a real token to expire, and most
steps need an operator at a terminal for a device-code sign-in. Do not present calendar estimates
as commitments before the engineering preflight is scoped. Use the actual token expiries and these
minimum live windows:

| Step | Minimum live window | Operator checkpoints |
| --- | --- | --- |
| Preflight and build | Set an explicit engineering timebox after decomposing section 3.5. | Provider setup, IAM controls, evidence schema, and local test gates. |
| H9 | At least 150 minutes and beyond the initial inbound/workload-token expiries. | Initial connection plus every required device-code sign-in. |
| H3-R | Until the diagnosed Google expiry plus five minutes. | Fresh connection, baseline, and post-expiry probe. |
| H7-R1 | Until both the original inbound and workload tokens have confirmed expiry. | Establishment, Candidate A supplementary run, and Candidate B mapping gate. |
| H7-R2 | Candidate B's real expiry wait plus every negative control. | Job authorization, resume, denial probes, and completion. |
| H8-R | Each isolated branch and combined scenario must cross the relevant propagation and token-expiry boundaries from a restored baseline. | Every reset, revocation, restoration, and before/after-expiry probe. |

This work competes with the decision to tear the AWS resources down. Agree the scope before the
first run so that a partial Round 2 still answers a question. The only pre-authorized scope cut is:

1. H7-R2 Candidate A, which section 6 already expects to record as `not tested` with the current
   implementation.

Do not cut H8-R Branch E: restoration behavior is required for the residual-storage decision. Do
not cut the H8-R combined scenario: it is the stated compensating-control pass criterion. If the
timebox expires before either completes, report H8-R as incomplete rather than inferring it from
the isolated branches.

Do not cut H9. It supplies causal attribution for H3-R and independently resolves the unexplained
Round 1 observation, although it does not change H3-R's functional pass/fail rule.

### Stop gates

Stop and invalidate the affected run if:

- a token, authorization URL, cookie, secret, or direct account identifier enters logs or committed
  evidence;
- the expected user mapping cannot be proven;
- a resource-provider authorization URL is followed during a no-interaction observation. A planned
  workforce device-code sign-in is not a stop gate, but you must record it;
- scopes, custom parameters, provider configuration, IAM policy, or local deny state changes
  without being the explicit independent variable;
- clock synchronization or token-expiry evidence is inadequate;
- a cross-user result or incorrectly bound Graph identity is observed.

## 10. Decision impact

Round 2 can change the adoption recommendation only through explicit architecture review:

- **Google:** H3-R pass supports behavioral refresh but leaves the Round 1 expiry-metadata gap as
  an operational caveat requiring an owner and failure-handling design.
- **Microsoft long-running work:** H7-R1 and at least one H7-R2 candidate must pass. The candidate's
  authorization model must also be approved; technical success through an unapproved UserId path
  is not sufficient.
- **Offboarding:** H8-R must technically pass and residual vault storage must be explicitly
  accepted. A rejection of residual storage keeps the overall recommendation at reject/defer.
- **Hourly lapse:** H9 must classify the prior observation. A controlled recurrence without an
  accepted root cause or mitigation keeps the recommendation at reject/defer.

The original H3, H7, and H8 terminal results remain in `docs/assessment.md`. If Round 2 changes the
recommendation, publish a separate Round 2 assessment and then revise the executive summary with a
dated addendum; do not edit the Round 1 evidence into a different outcome.

## 11. Review decisions required before execution

Architecture and security must decide:

1. Whether the durable job-authorization record is an acceptable source of authority for
   `GetWorkloadAccessTokenForUserId`.
2. Which candidate JWT-reacquisition mechanism, if any, is approved for an asynchronous worker.
3. The maximum job-authorization lifetime and freshness requirement for offboarding checks.
4. Whether the bounded lifetime of already-issued Graph access tokens is acceptable after
   offboarding.
5. Whether residual AgentCore vault storage is acceptable if retrieval and refresh are denied.
6. Whether AWS's documented `forceAuthentication` behavior is sufficient if the POC proves
   targeted refresh-credential invalidation but cannot prove record deletion.
7. The observation window and evidence needed to close H9 if no recurrence occurs.
8. Whether the Entra-coupled offboarding evidence is acceptable despite the missing
   production-representative PingOne workforce-only control.
9. Whether to commission a separate workforce-IdP mechanism for Candidate A. An MSAL
   workforce-refresh-token cache is out of scope unless architecture explicitly changes the POC
   premise and accepts long-lived Microsoft credential storage in our platform.

No asynchronous candidate or residual-storage outcome is considered approved merely because it
works in the POC.

## 12. Primary references

- [AgentCore `GetResourceOauth2Token` API](https://docs.aws.amazon.com/bedrock-agentcore/latest/APIReference/API_GetResourceOauth2Token.html)
- [AgentCore workload access tokens and UserId security controls](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/get-workload-access-token.html)
- [AgentCore automatic refresh-token storage and usage](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity-authentication.html)
- [AgentCore Microsoft credential-provider setup](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity-idp-microsoft.html)
- [AgentCore identity observability fields](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/observability-identity-metrics.html)
- [Microsoft refresh-token lifecycle and revocation](https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens)
- [Microsoft Graph `revokeSignInSessions`](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0)
- [Microsoft Graph permission best practices](https://learn.microsoft.com/en-us/graph/best-practices-graph-permission)
- [Google OAuth 2.0 access and refresh behavior](https://developers.google.com/identity/protocols/oauth2)
