# AgentCore Identity POC — Executive Summary

**Date:** 2026-09-01
**Audience:** Engineering leadership (no prior context assumed)
**Full technical record:** `docs/assessment.md` (terminal evidence), `docs/runbook.md` (how the POC was run)

## Bottom line

We built and ran a real, live proof-of-concept of **Amazon Bedrock AgentCore Identity** as the
credential broker for our agents — the component that would let an agent act on a user's behalf
against Microsoft and Google without our platform ever holding that user's passwords, OAuth
client secrets, or refresh tokens.

**Recommendation: reject or defer adoption in its current form.** Five of nine hypotheses
passed cleanly, including the core "does the plumbing work" questions. But three of the
remaining four failures land on requirements we called out up front as non-negotiable:
surviving a long-running agent task, revoking a user's access on offboarding, and refreshing a
third-party credential without visibility into when it expires. Those are not edge cases for an
agent platform — they're the everyday operating conditions.

This is a genuine, evidence-backed "not yet," not a dead end. See **Options going forward**
below before we tear the environment down.

## What we tested, and why

An agent platform that acts on behalf of users needs an answer to: *how does the agent get a
short-lived, revocable, per-user credential for Microsoft/Google/other systems, without our
platform having to store and protect long-lived secrets itself?* AgentCore Identity is AWS's
managed answer to that question — it sits between our agent and the identity providers, brokering
tokens and holding the durable credentials in AWS's vault instead of ours.

We defined nine testable hypotheses (H1–H8, with H4 split into two parts) covering the whole
lifecycle: authenticating the agent and the user, exchanging tokens without extra consent
prompts, isolating one user's credentials from another's, enforcing access with IAM, surviving
token expiry, and revoking access on offboarding. Each was tested against live AWS, Microsoft
Entra, and Google accounts — not mocked — and the result for each is a permanent, redacted
evidence record, not a subjective judgment call.

## Results at a glance

| # | Question | Result | What it means |
|---|---|---|---|
| H1 | Can the agent prove its own identity *and* the end user's identity together? | ✅ Pass | The foundation works: AWS-authorized agent + a validated real user token together produce a usable credential. |
| H2 | Can it get a Microsoft token for the user without an extra sign-in prompt? | ✅ Pass | Confirmed for two separate test users — no surprise consent screens. |
| H3 | Can it own and refresh a Google credential without ever seeing the user's long-lived secret? | ❌ Fail | It can hold and use the credential, but AWS gives us **no way to know when it's about to expire** — see below. |
| H4a | Is one user's vaulted credential provably walled off from another user's? | ✅ Pass | Confirmed: a token minted for User A cannot retrieve User B's credential. |
| H4b | Can we enforce "this agent only" access using our own AWS permissions (IAM), not just trust AWS's word for it? | ✅ Pass | Yes — and importantly, this isolation has to be *set up by us* via IAM policy; it is not automatic. |
| H5 | Would this same approach work with our actual production identity providers (PingOne / AD FS)? | ❌ Fail (untested) | Not a real failure — we had no live PingOne/AD FS environment to test against. This only blocks that specific future path; it doesn't affect the Microsoft/Google results above. |
| H6 | Does the downstream system still enforce its own authorization, or does AgentCore silently bypass it? | ✅ Pass | Downstream authorization stayed authoritative — AgentCore did not weaken it. |
| H7 | If the user's session (token) expires mid-task, can the agent keep working? | ❌ Fail | No. Once the user's underlying sign-in expires, the agent **cannot** get a fresh Microsoft token on its own — it needs the user to sign in again. |
| H8 | Can we cleanly cut off a user's access when they leave or are offboarded? | ❌ Fail | No reliable, narrow "revoke this one user" operation exists today; a downstream check after "offboarding" still succeeded. |

## What worked well

The parts of AgentCore Identity that are its actual job — proving identity, brokering tokens
without exposing secrets, and keeping user credentials isolated from each other — all held up
under real, live testing:

- **Isolation is real, not advertised.** We deliberately tried to have one user's identity reach
  another user's Google credential, and it failed as it should (H4a). We also proved that if we
  *don't* configure IAM carefully, isolation between two different agent workloads is not
  automatic — AgentCore expects us to enforce that boundary ourselves, and once we did, it held
  (H4b).
- **No secret sprawl.** At no point did our code or logs ever hold a client secret or a user's
  long-lived refresh token — that is the entire value proposition, and it worked as designed.
- **Auditability is achievable.** Every credential exchange showed up in AWS CloudTrail with the
  three things we'd need to investigate an incident: which AWS principal acted, which agent
  workload it was, and which end user it was acting for.
- **Latency is workable.** A full round trip (agent identity → user token → downstream data
  read) measured roughly **1.0–1.8 seconds** end to end in our environment, which is acceptable
  for the kind of assistant-style, human-in-the-loop workflows we're building toward — though not
  validated at production scale or concurrency.

## What didn't work, and why it matters

- **No visibility into third-party token expiry (H3).** Once we're storing a Google credential
  on a user's behalf, we need to know when to refresh it before it silently fails mid-task. AWS's
  API simply doesn't return that information for this kind of credential. This is a hard platform
  limitation, not something more engineering effort on our side fixes.
- **Long-running agent work can't outlive the user's sign-in (H7).** We proved directly that once
  the user's Microsoft sign-in expires (typically 60–90 minutes), an agent that's still working
  cannot silently get a new downstream token — it stalls until the user re-authenticates. Any
  workflow we expect to run longer than a user's active session (which describes a lot of our
  planned agent use cases) would need a redesign around this constraint, not just a config change.
- **Offboarding a single user isn't clean (H8).** We tried to revoke one user's Google access and
  confirm it downstream. AgentCore has no narrow, per-user "delete this credential" operation we
  could find, and the downstream system kept honoring the old credential after our attempt. For a
  platform that will hold real employee/user credentials, "we can't reliably cut someone off" is
  a compliance and security gap, not a minor rough edge.
- **Compatibility with our actual identity providers is unproven (H5).** Everything above was
  tested against Microsoft Entra and Google, because that's what we had live access to. We have
  not proven this works with PingOne or AD FS, which is what production would likely need. This
  is a gap in testing, not a demonstrated failure of the product.

## Key risk to flag separately

Independent of the nine hypotheses, we hit a **recurring, unexplained credential lapse**: a
user's vaulted Google access unexpectedly stopped working roughly once an hour during testing,
requiring a fresh sign-in to restore it, with no error or warning beforehand. We have not
root-caused whether this is an AWS-side session limit or an artifact of our test environment. If
it's the former, it compounds the H7/H8 findings above; if it's the latter, it's noise. Either
way, it's unresolved and worth AWS's attention before we'd rely on this in production.

## Options going forward

Before tearing down the test environment (which would require re-provisioning to re-test), we see
three reasonable paths:

1. **Wind down now.** The three mandatory failures (H3, H7, H8) are enough on their own to reject
   the current form of AgentCore Identity for our use case. If we're confident these are AWS
   platform limitations rather than configuration issues, further testing here has low expected
   value, and the environment can be torn down.
2. **Escalate to AWS and re-test.** H3, H7, and H8 all look like genuine product gaps rather than
   something we're doing wrong. We could raise these directly with AWS/Bedrock product and support,
   ask whether a roadmap fix or an undocumented API exists, and re-run the specific failing tests
   if they point us at one — cheap to do while the environment is still live.
3. **Expand the experiment.** Get short-term access to a PingOne or AD FS test tenant to close the
   H5 gap for real, and/or design and test an engineering workaround for H7 (e.g., proactively
   refreshing well before a token's *known* typical lifetime, accepting some risk instead of a
   guarantee) to see whether "adopt with caveats" becomes reachable instead of outright rejection.

We'd like your input on which of these — or what combination — is worth the additional time
before we decommission the AWS resources.
