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
| H7-R1 | Can Microsoft `USER_FEDERATION` make AgentCore the refresh-token vault for delegated Graph access? | After the original inbound Entra JWT and workload token expire, a newly acquired, correctly user-bound workload token retrieves the existing Microsoft connection and Graph succeeds without new Microsoft interaction. |
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

### 3.4 Evidence and token handling

All test hosts must use a synchronized UTC clock. Each event records both UTC and monotonic elapsed
time. A default five-minute allowance is applied after a confirmed token expiry unless the
provider documents a larger allowance.

Committed evidence may contain only:

- test-run ID, hypothesis ID, step, result category, and correlation ID;
- opaque user alias and one-way subject correlation, never an email address or display name;
- workload/provider aliases and IAM role alias;
- OAuth flow, requested scopes, and acquisition path;
- one-way SHA-256 token fingerprints, timestamps, and expiry diagnostic source;
- whether an authorization URL was returned and whether `CompleteResourceTokenAuth` occurred;
- downstream status category, AgentCore/AWS request IDs, and relevant CloudTrail correlation;
- local deny, workforce-account, job-authorization, and downstream-revocation states.

Raw provider tokens, workload tokens, refresh tokens, authorization URLs, cookies, client secrets,
and provider responses are not committed or logged. H3-R never persists the Google access token.
Where another test must retain a previously issued workload token across a real expiry boundary,
it uses the existing ignored, mode-`0600` raw-state pattern documented in `docs/runbook.md`; the
file is deleted on success, failure, or abandonment.

An automatic consent flow is forbidden during an observation. Returning an authorization URL is
recorded as an outcome and the test stops. Following the URL would destroy the evidence being
measured.

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
- Select one provider-supported diagnostic before the run. It may inspect the access token only in
  process memory and must return an authoritative expiry or remaining lifetime. If no approved
  diagnostic exists, the test is `inconclusive`; elapsed time alone is not confirmed expiry.

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
   correlation, AWS request IDs, and authorization-event timestamps.
6. Allow both the original inbound JWT and original workload token to expire. Confirm the expiry
   boundary rather than relying on a nominal 60-minute wait.

### Candidate A — fresh workforce JWT

1. Obtain a fresh JWT from the configured workforce IdP for the same canonical user.
2. Validate issuer, signature, audience, expiry, and required claims locally.
3. Confirm that its subject maps to the same AgentCore connection identity used during
   establishment.
4. Mint a new workload token, retrieve the Microsoft resource token, and call Graph.
5. Verify that AgentCore returned no authorization URL and that no new Microsoft authorization or
   `CompleteResourceTokenAuth` event occurred.

### Candidate B — `GetWorkloadAccessTokenForUserId`

1. Start with an active durable job-authorization record for the same user and operation.
2. Resolve the namespaced `user_key` from the trusted record, never from caller input.
3. Assume the dedicated worker role and confirm the current offboarding decision is allow.
4. Call `GetWorkloadAccessTokenForUserId`, retrieve the existing Microsoft credential, and call
   Graph.
5. Verify Graph's user context matches the established user's sanitized subject correlation.
6. Verify that no authorization URL or new Microsoft interaction occurred.

This branch must not assume that a caller-supplied UserId and a JWT's `iss`/`sub` address the same
vault partition. Whether the UserId path can retrieve a connection established through the JWT
path is itself part of the test. Establishing a second Microsoft connection through the UserId
path does not satisfy the pass criterion.

### Interpretation

Report Candidate A and Candidate B independently:

- **Pass:** the new workload token is correctly user-bound, the existing connection is retrieved,
  Graph succeeds as that user, and no new Microsoft interaction occurs.
- **Fail — vault refresh:** the same connection is found but AgentCore cannot produce a usable
  post-expiry Graph token.
- **Fail — identity partition:** the acquisition path maps the correct enterprise user to a
  different AgentCore vault identity and reports authorization required.
- **Fail — user binding:** a token or Graph result is bound to any other user. This is a stop-work
  security failure.
- **Inconclusive:** source/workload expiry, user continuity, or absence of Microsoft interaction
  cannot be demonstrated.

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

### Matrix

| Branch | Action | Immediate probe | Post-expiry probe | Required attribution |
| --- | --- | --- | --- | --- |
| A — local deny | Add the user to the application deny record. | New gateway/worker activity is rejected, including activity presented with a previously issued workload token. | Denial remains effective. | Application policy decision and absence of AgentCore retrieval. |
| B — workforce disable | Disable the configured workforce account. For the intended production mapping this is PingOne. | No new workforce JWT or JWT-backed workload token can be established. | Retry remains denied after propagation allowance. | Workforce IdP event plus local token-validation outcome. |
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

After the isolated branches, apply local deny, workforce disablement, and Entra revocation in the
approved operational order. Then repeat the old-workload-token and Graph probes before and after
both the known Graph access-token expiry and the original workload-token expiry.

- **Technical pass:** the approved application cannot retrieve or use the connection after local
  deny; after revocation propagation and expiry of the previously issued Graph and workload
  tokens, the old workload token cannot retrieve, no new workforce/workload token can be
  established, and Graph access cannot be reacquired.
- **Fail:** any approved application path survives local denial, a fresh user-bound workload token
  can be established for the disabled user, or Graph remains usable through refresh after the
  downstream revocation propagation and access-token expiry boundaries.
- **Inconclusive:** token lifetimes, propagation, residual token provenance, or user mapping cannot
  be proven.

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

### Observation procedure

1. Run a non-interactive credential-retrieval and Drive probe every five minutes for at least 150
   minutes and beyond the known expiry of the initial inbound and workload tokens.
2. Obtain fresh JWT-backed workload tokens only through the controlled single-identity session.
3. For every probe record UTC and monotonic time, source/workload/resource fingerprints and known
   expiries, sanitized subject correlation, AgentCore request ID, CloudTrail event correlation,
   authorization-URL presence, and Drive result.
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
2. **H9:** characterize the unexplained lapse before other destructive or forced-authentication
   actions can contaminate it.
3. **H3-R:** create a separate fresh Google grant and run the controlled expiry test. H9 evidence
   may not substitute unless it independently meets every H3-R precondition.
4. **H7-R1:** establish and age the separate Microsoft user-federation connection.
5. **H7-R2:** run both approved reacquisition candidates and their negative controls.
6. **H8-R:** run isolated offboarding branches, the targeted `forceAuthentication` probe, and the
   combined matrix last because they intentionally alter identity and grant state.
7. **Closeout:** sanitize evidence, delete raw token state, record the architecture decisions, and
   only then authorize AWS resource teardown.

Stop and invalidate the affected run if:

- a token, authorization URL, cookie, secret, or direct account identifier enters logs or committed
  evidence;
- the expected user mapping cannot be proven;
- a browser authorization flow is followed during a no-interaction observation;
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
