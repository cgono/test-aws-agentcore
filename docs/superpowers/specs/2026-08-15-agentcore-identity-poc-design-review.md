# Review: AgentCore Identity Auth Broker POC Design

**Reviewing:** `2026-08-15-agentcore-identity-poc-design.md`
**Date:** 2026-08-15
**Method:** Design critique plus verification of the AgentCore Identity API claims against current AWS documentation.

## Summary

The design is unusually disciplined for a POC: per-hypothesis pass criteria, an explicit refusal to treat AgentCore as a policy decision point, and a production-mapping table that admits what the POC does not prove. Section 7's framing — "the worker does not own durable user credentials or OAuth client secrets," not "the worker sees no credentials" — is the right claim and most designs get it wrong.

The API assumptions check out. `GetWorkloadAccessTokenForJWT` exists and validates signature, issuer presence, and expiry using `iss`+`sub` as the user key. `GetResourceOauth2Token` with `oauth2Flow=ON_BEHALF_OF_TOKEN_EXCHANGE` is real, and `MicrosoftOauth2` is a first-class provider using `JWT_AUTHORIZATION_GRANT` (RFC 7523 §2.1) with `requested_token_use=on_behalf_of` added automatically. Custom providers do support RFC 8693 `TOKEN_EXCHANGE`. Nothing in the design depends on an API that does not exist.

The holes are in the parts the docs make sound simpler than they are, and in what the POC declines to measure.

---

## Blocking — fix before implementation

### B1. §6.2 omits OAuth session binding entirely

This is the largest gap. The Google flow as written goes: AgentCore returns an authorization URL → frontend redirects → "Google obtains the user's consent and returns the authorization response to AgentCore's provider-specific callback" → "AgentCore stores the Google refresh token in its vault."

The actual flow has a step in the middle that the spec never mentions. Per [OAuth 2.0 authorization URL session binding](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/oauth2-authorization-url-session-binding.html), after the provider callback AgentCore redirects the browser to **an HTTPS endpoint you host**, which must:

1. be registered on the workload identity as an `AllowedResourceOauth2ReturnUrl` (via `CreateWorkloadIdentity`/`UpdateWorkloadIdentity`);
2. verify that the currently logged-in user matches the user who initiated the authorization; and
3. call `CompleteResourceTokenAuth` with the session URI **and** the original inbound IdP token or user_id.

Until `CompleteResourceTokenAuth` succeeds, no credential is vaulted. The design's §6.2 steps 5–7 cannot happen as written.

Consequences the spec needs to absorb:

- **§12 prerequisites** gain a hard requirement: a publicly reachable HTTPS callback. On a laptop that means a tunnel (ngrok/Cloudflare) or using `agentcore dev`, which hosts the callback and calls `CompleteResourceTokenAuth` for you. Decide which, because the tunnel version changes the container/CORS/allowlist setup and the `agentcore dev` version means you are not actually exercising the callback you would have to build for EKS.
- **Authorization URLs and their session IDs expire in 10 minutes.** That belongs in §9's failure table, and it is a genuine production constraint (see B4).
- **§10 has an internal conflict.** AWS is explicit that the user identifier presented to `CompleteResourceTokenAuth` must come from the live browser session (cookie or browser storage) and "should NOT be pulled from any remote session cache." §10 says browser tokens "are not persisted in local storage unless testing proves a compelling need." Those two constraints meet at the callback endpoint. Resolve it deliberately rather than discovering it at implementation time.
- AWS also recommends passing an opaque `state` to `GetResourceOauth2Token` for CSRF protection on your callback. §10's "exact allowlists" bullet should say this.

### B2. The Google callback URL does not exist until after the provider is created

Per the [Google provider doc](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity-idp-google.html), AgentCore issues a **unique callback URL per credential provider**, of the form `https://bedrock-agentcore.<region>.amazonaws.com/identities/oauth2/callback/<uuid>`, and you cannot know it before calling `CreateOauth2CredentialProvider`. The documented sequence is: create the Google OAuth client → create the AgentCore provider (placeholder secret is fine) → read `callbackUrl` from the response → register it in the Google console → `UpdateOauth2CredentialProvider` with the real client ID/secret.

Also: Google's OAuth consent screen requires `bedrock-agentcore.<region>.amazonaws.com` in **Authorized domains**.

This breaks §14's "infrastructure-as-code or repeatable CLI configuration" if you assume a single-shot apply. There is a mandatory manual console step in the middle of provider creation. Say so, and design the runbook as two IaC phases with a documented console step between them. Recreating the provider invalidates the callback URL and requires re-registration in Google — worth noting for the cleanup instructions in §10, which currently imply teardown/rebuild is cheap.

### B3. H4 bundles a service-enforced claim with one that is not enforced at all

H4 reads: "User A cannot retrieve User B's credential, and an unapproved workload cannot retrieve either user's credential."

The first half is service-enforced — credentials are scoped to the user identity in the workload access token, and that is a real pass/fail.

The second half is not. From [Scope down access to credential providers by workload identity](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/scope-credential-provider-access.html):

> The IAM role you assign to an agent controls which credential providers the agent can call. **The service does not enforce additional binding between workload identities and credential providers in the same account.**

A workload identity is a name string. Any principal holding `bedrock-agentcore:GetResourceOauth2Token` on a broadly-scoped resource can assert any workload name in the account. The isolation is entirely a property of how you write the `Resource` block.

**This is the most important finding for the work decision**, and the spec should promote it out of a hypothesis and into §8's authorization model. It means AgentCore does not give you workload isolation for free: on EKS you get it from per-pod IAM roles scoped to specific workload-identity and credential-provider ARNs — which is infrastructure you would have to build and govern anyway. That reframes the value proposition from "AgentCore isolates agents" to "AgentCore vaults credentials; you still isolate agents with IAM."

Split into:

- **H4a** (service-enforced): with one workload identity and one IAM principal, a workload access token minted for User A cannot retrieve User B's vaulted Google credential.
- **H4b** (IAM-enforced): specify the principal. The interesting test is **same IAM principal, different workload name** — and you should expect it to *succeed* under a policy that names the workload-identity-directory ARN broadly, then show it failing once the policy is scoped to a named workload identity ARN. Recording both results is the evidence that matters. A test that only uses a second, differently-permissioned principal proves nothing except that IAM works.

### B4. Inbound token lifetime versus long-running work is untested, and it is the production shape

Microsoft OBO requires a live subject token. The worker holds the user's inbound Entra access token (~60–90 min) and holds no refresh token for it — correctly, by design. So a Temporal activity running longer than the inbound token's lifetime cannot obtain a new downstream token, and cannot self-heal.

§9's row — "Token expires during downstream call → worker obtains one fresh token from AgentCore and retries once" — quietly assumes AgentCore can always mint a fresh Graph token. It cannot if the *inbound subject* token has expired. The vaulted Google path survives this (AgentCore holds a refresh token); the OBO path does not.

Combine with B1's 10-minute authorization URL and the production shape breaks concretely: a Temporal workflow that pauses for human Google consent, or that runs longer than an Entra token lifetime, hits both walls.

Add a hypothesis and test it — it is minutes of work and the answer is production-blocking:

> **H7** — Behavior under inbound-token expiry is understood and survivable. With a valid workload access token but an expired inbound Entra JWT, record what `GetResourceOauth2Token ON_BEHALF_OF_TOKEN_EXCHANGE` returns; separately record whether a workload access token outlives the JWT it was minted from, and for how long. Vaulted-credential (Google) and OBO (Microsoft) paths are recorded separately because they are expected to differ.

The POC as specified — a synchronous request/response worker — will never surface this, even though §13 says the destination is a Temporal worker.

### B5. Verify two Entra prerequisites before building anything

Both threaten H2, the highest-value hypothesis. Treat as checks, not assumptions:

- **App-registration identity.** Microsoft's OBO flow requires the assertion's `aud` to be the middle-tier app performing the exchange. So the app registration whose client ID/secret you store in the AgentCore `MicrosoftOauth2` provider must be **the same app registration that exposes the worker-API scope** the SPA requests. §5 and §6.1 describe both ends but never state they are one app. Get this wrong and OBO fails with an audience error that reads like a scope problem.
- **Consent is two grants, not one.** Tenant admin consent covers the delegated Graph `Files.Read` permission on the API app. It does not automatically cover the SPA's consent to the *worker API's own* scope. Unless the SPA client is pre-authorized on the API app (`knownClientApplications` / pre-authorized applications), the user still sees a prompt — and H2's pass criterion is "no consent prompt during normal use." Add pre-authorization to §5 and to the H2 evidence steps.

---

## Worth fixing

### W1. H1's fail-closed evidence is misattributed

H1 claims AgentCore fails closed on "wrong issuer." `CreateWorkloadIdentity` accepts only `name`, `allowedResourceOauth2ReturnUrls`, and `tags` — there is no discovery URL, trusted-issuer, or allowed-audience field. (Those exist on AgentCore *Runtime* inbound auth config, which this design deliberately does not use.) AgentCore validates that the JWT is well-signed and unexpired and keys the identity on `iss`+`sub`; it is not your issuer allowlist.

The accurate claim is narrower but still worth testing: **the worker's own token validation is the only thing keeping foreign issuers out.** A validly-signed JWT from an unrelated IdP would mint a workload access token keyed to *that* `iss`+`sub` — it reaches credentials stored under that identity, not another user's, so this is not cross-user escalation. But it does mean §5's "validates the inbound Entra access token before accepting a request" is load-bearing security, not hygiene, and H1's evidence column should attribute issuer/audience rejection to the worker.

Related and worth a line in §8: because the vault keys on `iss`+`sub`, two IdPs that produce colliding `sub` values collide in the vault. AWS documents `provider_id+user_id` partitioning as guidance for the `GetWorkloadAccessTokenForUserId` path; on the JWT path you get whatever the issuers give you. Relevant if IIG ever fronts more than one IdP.

Also worth an explicit control: if the worker always has a JWT, add an IAM `Deny` on `bedrock-agentcore:GetWorkloadAccessTokenForUserId` so the unverified-string path cannot be used. AWS recommends exactly this, and it belongs in §10.

### W2. Credential migration and offboarding are unaddressed

Two gaps that an enterprise review will find:

- **Migration.** §13 maps "Entra inbound token → PingOne token." Since the vault keys on `iss`+`sub`, that swap orphans every vaulted Google credential — every user re-consents. Not a POC blocker, but it belongs in §13 as a stated migration cost, and it is exactly the kind of thing that is cheap to note now and expensive to discover later.
- **Offboarding.** §11 tests revoking a grant at Google. It does not test the enterprise requirement: a user leaves, and you must purge their vaulted credentials from AgentCore. Establish whether a per-user credential deletion path exists (as opposed to deleting the whole provider) and record the answer. If the only lever is provider-level deletion, that is a finding your security team needs.

### W3. No decision rule

§3 gives per-hypothesis pass criteria and correctly refuses a blanket pass. But nothing says which results mean **adopt**, **adopt with caveats**, or **reject**. Which hypotheses are must-pass? If H2 passes and H5 fails, what happens? If H4b shows isolation is purely IAM-shaped, does that change the answer?

Without this, a suitability POC ends in "it mostly worked," and the decision gets made on whoever writes the summary. Write the rule before you run the tests, while you have no results to rationalize around.

### W4. No baseline comparison

The POC tests only AgentCore. "It works" does not answer "is it worth adopting," because the alternative is not nothing — it is ~200 lines of MSAL OBO plus a KMS-encrypted refresh-token table, or PingOne's own token exchange used directly. Add a short deliverable in §14: a one-page comparison of what AgentCore actually removes (client-secret custody, refresh orchestration, vault encryption/KMS, per-provider protocol quirks) versus what it adds (a new AWS dependency in the auth path, a service that is not the policy decision point, region constraints, the two-phase provider-creation dance from B2). This is the section your architecture review will actually argue about.

### W5. Nothing measures operational characteristics

No hypothesis covers latency added per downstream call (you are inserting two AWS API round-trips before every Graph call), service quotas and throttling on `GetWorkloadAccessTokenForJWT` / `GetResourceOauth2Token` at Temporal-worker concurrency, whether AgentCore caches and returns the same access token across calls, or CloudTrail coverage. That last one is concrete and cheap: can you answer "which user's Google credential did which workload retrieve, and when" from CloudTrail alone? §8 asserts an authorization model but §11 never tests whether the audit trail supports it. Add these as recorded measurements rather than pass/fail hypotheses.

### W6. Reframe phase 2, or cut it

The stated goal of the Keycloak phase is to learn whether AgentCore's custom provider can fit PingOne and AD FS. But the real question — *does the custom provider config surface enough knobs?* — is largely answerable by reading the `CreateOauth2CredentialProvider` API shape, which is now visible: `grantType` (`TOKEN_EXCHANGE` | `JWT_AUTHORIZATION_GRANT`), `clientAuthenticationMethod`, `actorTokenContent` (`M2M` | `AWS_IAM_ID_TOKEN_JWT` | `NONE`), `actorTokenScopes`, `customParameters`, and a `discoveryUrl` requirement.

That last item is the one to check first: the custom provider config takes a `discoveryUrl` pointing at `.well-known/openid-configuration`. Confirm AD FS exposes one in a form AgentCore accepts — if it does not, phase 2 against Keycloak proves nothing about the AD FS path regardless of outcome.

Two cheaper substitutes for a weekend, in order:

1. Map PingOne's and AD FS's documented token-exchange support onto that config surface on paper. An afternoon, no infrastructure, and it answers the production question more directly than Keycloak does.
2. If you still want a live test, point a custom provider at a mock authorization server you control rather than Keycloak. You get to inject failure modes — wrong audience, unauthorized client, malformed response — which is where the interesting behavior is, and you skip standing up Keycloak.

Also note `AWS_IAM_ID_TOKEN_JWT` as actor-token content requires the account to be enabled for outbound web identity federation (`iam:EnableOutboundWebIdentityFederation`). If that mode is interesting for the internal-resource case, check account eligibility early — it may need the Cloud Team you were trying to avoid.

### W7. Make the custom Entra-protected test API the primary H2 target

§12's fallback is right but should be promoted to the default. A custom Entra-protected test API as the OBO target exercises the full OBO mechanic — same app registration, same admin consent, same `JWT_AUTHORIZATION_GRANT` exchange, same audience validation — with **zero licensing dependency**. OneDrive then becomes an optional confirmation that adds realism, not a prerequisite that can stall the whole phase.

This matters because the OneDrive prerequisite is the most likely thing to block you on day one. Entra Free gives you app registration but not a licensed OneDrive workload, and the usual workaround — the Microsoft 365 Developer Program E5 sandbox — has had eligibility restrictions tied to paid subscriptions. **Verify current eligibility before you build anything else**, and do not let H2 depend on the answer.

---

## Nits

- **§7 table.** The "May be visible to worker" / "Must never reach frontend" columns both read `Yes` for several rows, which is ambiguous — "Yes" in the second column means "yes, must never reach it." Rename to "Worker may hold" / "Frontend must never hold," or invert to a single "Frontend access" column.
- **§9.** Missing rows for authorization-URL expiry (10 min) and for `CompleteResourceTokenAuth` session-mismatch, both of which follow from B1.
- **§12.** Add the region constraint explicitly — AgentCore Identity is not in every region, and picking one before creating the Entra and Google apps avoids rework, since the Google authorized-domain entry is region-specific.
- **§12.** No cost note. Small for a POC, but "personal AWS account" implies you should state the expected order of magnitude and set a budget alarm.
- **§11.** "Force access-token expiry" for the Google refresh test is not really forceable — plan on waiting out the ~1 hour, and note how you will observe that a refresh actually occurred rather than a cached token being returned.
- **§14.** The deliverable list (README, architecture doc, assessment, runbook, production-mapping doc, IaC, containerized SPA + worker, test suite) is enterprise-report scaffolding around a feasibility test.

## On scope

You called this a weekend project. As specified it is not one: two IdP tenants, a licensed M365 account, a Google project, a containerized SPA and worker, a public HTTPS tunnel, Keycloak, a mock API, IaC, and a test suite.

The suggestion, which you should feel free to reject if the polished artifact is itself the point:

- **Session 1 — one Python script, no frontend, no containers.** Entra device-code or a pasted JWT → `GetWorkloadAccessTokenForJWT` → `GetResourceOauth2Token ON_BEHALF_OF_TOKEN_EXCHANGE` → call your custom Entra-protected test API. That answers H1, most of H2, and B5's two prerequisite checks. If B5 is wrong, you find out in an hour instead of on day two.
- **Session 2 — Google 3LO** using `agentcore dev` to host the callback, then once more with a real tunnel to prove you can build the callback yourself. Answers H3 and surfaces B1 honestly. Add the H4a/H4b IAM matrix and H7 here; both are minutes once the script exists.
- **Then decide** whether the frontend, containers, and phase 2 are still worth it. If H1–H4 and H7 hold, the remaining work is packaging and a paper exercise (W6), not risk reduction.

The frontend earns its place only if you specifically want to prove the session-binding callback end to end — which, given B1, is a legitimate reason to build it. Just build it for that reason rather than for the demo.

## References

- [Get workload access token](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/get-workload-access-token.html)
- [On-behalf-of token exchange](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/on-behalf-of-token-exchange.html)
- [OAuth 2.0 authorization URL session binding](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/oauth2-authorization-url-session-binding.html)
- [Scope down access to credential providers by workload identity](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/scope-credential-provider-access.html)
- [Google credential provider](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity-idp-google.html)
- [CreateWorkloadIdentity API reference](https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateWorkloadIdentity.html)
- [Microsoft identity platform OAuth 2.0 On-Behalf-Of flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow)
</content>
</invoke>
