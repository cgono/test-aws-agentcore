# Direct Implementation Baseline

The baseline is a direct implementation using MSAL OBO plus a KMS-encrypted per-user refresh-token table. It is not a recommendation to store raw provider responses or to relax downstream authorization.

| Dimension | AgentCore Identity | Direct MSAL OBO plus KMS-encrypted refresh storage | Decision implication |
| --- | --- | --- | --- |
| Client-secret custody and rotation | AgentCore stores OAuth client configuration and can reference Secrets Manager. | The application owns secret storage, KMS policy, rotation integration, and deployment rollout. | Prefer AgentCore only when its custody model meets security ownership requirements. |
| Refresh-token storage | Token vault owns retained provider credentials. | Application owns schema, KMS encryption context, access controls, backup exposure, and lifecycle jobs. | This is the largest potential reduction in credential-management work. |
| Refresh orchestration | AgentCore requests a fresh provider token when a valid refresh credential exists. | Worker implements refresh scheduling, single-flight locking, retries, and refresh-token replacement. | Compare observed H3 behavior, not a documented happy path. |
| Revocation and per-user deletion | Feasible only with a documented narrow per-user operation. | Application deletes one encrypted row and invalidates local caches, then verifies provider revocation. | Reject/defer either path without an acceptable offboarding result. |
| Provider-specific protocol handling | Custom-provider fields and token-endpoint parameters still require mapping. | Application implements each grant, parameter, and vendor exception itself. | H5 can reject only the production provider path. |
| Callback and session binding | Application still owns browser session binding and callback completion. | Application owns OAuth state, PKCE, callback, and credential persistence together. | AgentCore does not remove callback security responsibility. |
| IAM and application policy | Named workload/provider access and AWS account policy gate access. | Application IAM controls KMS/table access; application policy controls user authorization. | H4b must be evaluated as an IAM dependency, not vault-native isolation. |
| Regional dependency | AgentCore control and token paths depend on selected AWS region and service availability. | Application depends on its AWS KMS/data region plus IdP availability. | Document recovery and latency implications for each dependency. |
| Latency, quotas, and retry | Measure AgentCore plus provider and Drive stages; observe quotas and CloudTrail. | Measure application, KMS, data store, and provider stages; tune retry ownership. | Unacceptable observed latency or quotas rejects/defer adoption. |
| Audit coverage | AWS control/data-plane events and application correlation still need review. | Application emits credential lifecycle and access events in addition to AWS KMS/data events. | Accept only an attribution model security and operations can use. |
| Issuer migration and re-consent | Provider configuration and vault connections may require user re-consent. | Application migrates issuer metadata and refresh rows, then handles re-consent. | Plan a tested migration rather than assuming credentials transfer. |
| Operational ownership | AWS platform owns AgentCore availability; product team owns integration, callbacks, and downstream policy. | Product/platform team owns all token-table reliability, keys, jobs, callbacks, and provider integration. | Make ownership explicit before selecting either path. |
| Expected production cost | Price the AgentCore service, token activity, related Secrets Manager, logging, and network use. | Price KMS requests, encrypted storage, compute, queues/jobs, observability, and operational support. | Compare forecasted workload volume and personnel cost, not list prices alone. |

## Outcome

Choose AgentCore only when live evidence shows its credential-custody benefit outweighs AWS regional, IAM, quota, audit, and provider-compatibility dependencies. Otherwise retain the direct baseline or defer with the missing proof named explicitly.
