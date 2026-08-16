# AgentCore Identity Suitability Assessment Template

## Evidence Input

Generate a draft only from sanitized JSONL. Each hypothesis needs exactly one explicit terminal
observation with `operation` set to `assessment_terminal` and `details.terminal` set to `true`.
The report generator rejects missing or duplicate terminal observations and invalid measurements;
it never guesses a result from intermediate evidence.

```sh
.venv/bin/agentcore-identity-poc report \
  --evidence evidence/sanitized.jsonl \
  --output docs/assessment.md \
  --iam-acceptable \
  --audit-acceptable \
  --latency-acceptable \
  --quota-acceptable
```

`assessment.md` is deliberately not committed before a live run. The command emits status-only
Markdown and excludes provider responses, credentials, tokens, authorization URLs, and evidence
details. The four acceptance switches are explicit platform/security decisions after reviewing
sanitized IAM, audit, latency, and quota observations.

## Hypothesis Results

| Hypothesis | Terminal result | Evidence reference | Interpretation |
| --- | --- | --- | --- |
| H1 | pending | Sanitized workload observation | Validated Entra subject plus AWS workload token. |
| H2 | pending | Sanitized OBO observation | Delegated Entra token without normal-use consent prompt. |
| H3 | pending | Sanitized post-expiry Google observation | Current API limitation: the provider response does not expose provider-token expiry, and raw provider tokens must not be retained. Record the observed post-expiry Drive result, or fail/defer this hypothesis. |
| H4a | pending | Sanitized two-user isolation observation | Distinct validated subjects and expected Drive aggregates remain isolated. |
| H4b | pending | Sanitized broad/scoped IAM matrix | Same AWS principal observation; assess its IAM dependency separately. |
| H5 | pending | [Provider compatibility assessment](provider-compatibility.md) | Plausible is not proven; incompatibility rejects only the intended custom-provider production path. |
| H6 | pending | Sanitized resource API observation | Downstream authorization remains authoritative. |
| H7 | pending | Sanitized expiry observation | Inbound, workload, OBO, and Google lifecycles are separately recorded. |
| H8 | pending | Sanitized revocation/offboarding observation | Per-user purge is required; deleting a shared provider is not an acceptable substitute. |

## Operational Measurements

| Dimension | Observed value | Acceptance decision | Evidence reference |
| --- | --- | --- | --- |
| Latency | pending milliseconds | acceptable / unacceptable | Sanitized latency observations (`p50_ms`, `p95_ms`) |
| Quota and retry behavior | pending bounded request count | acceptable / unacceptable | Sanitized concurrency observations |
| Audit attribution | pending presence-only result | acceptable / unacceptable | Sanitized CloudTrail observation |
| IAM dependency | pending broad/scoped matrix | acceptable / unacceptable | Sanitized H4b observations |

## Decision Rule

- Reject or defer when any mandatory hypothesis H1, H2, H3, H4a, H6, H7, or H8 is not `pass`.
- Reject or defer when H4b is not `pass`, its IAM model is unacceptable, or audit, latency, or quota
  observations are unacceptable.
- When mandatory results and H4b pass and operational dependencies are accepted, record
  `adopt_with_caveats`. The caveat is the demonstrated IAM dependency, not a claim that isolation
  is intrinsic to the vault.
- H5 is a separate production-path decision. A PingOne or AD FS incompatibility rejects that
  custom-provider path while preserving the general AgentCore decision for other providers.

## Comparison and Ownership

Complete the operational comparison in [direct-baseline.md](direct-baseline.md). State whether
AgentCore removes enough credential-management work and risk to justify its AWS dependency; a
happy-path token exchange alone is insufficient.
