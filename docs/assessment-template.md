# AgentCore Identity Suitability Assessment Template

## Evidence Input

Generate a draft only from sanitized JSONL. First finalize actual emitted nonterminal observations
into one minimal terminal artifact. The finalizer validates the JSONL, requires one canonical
`pass` or `fail` selection for every H1-H8, requires same-hypothesis source evidence, and requires
the explicit H5 compatibility-review acknowledgement because H5 is a documented paper decision.
It writes exactly one `assessment_terminal` row with `details.terminal=true` for each hypothesis;
it does not copy observation details or provider responses.

```sh
.venv/bin/agentcore-identity-poc assessment-finalize \
  --evidence evidence/sanitized.jsonl \
  --output evidence/assessment-terminal.jsonl \
  --h5-compatibility-reviewed \
  --result H1=pass \
  --result H2=pass \
  --result H3=fail \
  --result H4a=pass \
  --result H4b=pass \
  --result H5=fail \
  --result H6=pass \
  --result H7=fail \
  --result H8=fail

.venv/bin/agentcore-identity-poc report \
  --evidence evidence/assessment-terminal.jsonl \
  --output docs/assessment.md \
  --iam-acceptable \
  --audit-acceptable \
  --latency-acceptable \
  --quota-acceptable
```

Select results only after reviewing their associated sanitized observations. The example records
the current H3 API limitation and unresolved production-path/lifecycle items as failures; it is not
a substitute for live evidence. `assessment.md` is deliberately not committed before a live run.
The command emits status-only Markdown and excludes provider responses, credentials, tokens,
authorization URLs, and evidence details. The four acceptance switches are explicit
platform/security decisions after reviewing sanitized IAM, audit, latency, and quota observations.

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
