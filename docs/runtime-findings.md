# Runtime + Gateway Findings (Phase 2)

**Date:** 2026-09-26 · **Region:** ap-southeast-1 · **Deploy:** Terraform 1.14.8, hashicorp/aws 6.66.0,
direct code (S3 zip), PYTHON_3_13, PUBLIC network mode · **SDK:** bedrock-agentcore 1.18.1

## Summary

AgentCore Runtime can host an agent whose only inference path is an external, JWT-protected LLM
gateway. The agent got an Entra token with a client secret read from Secrets Manager, called the
gateway for both OpenAI and Anthropic models, and the gateway rejected calls without a valid JWT
with 401. All 12 live observations passed. The cost in latency is a cold start of about 3.5 s for
the first call in a new session, about 0.5–0.8 s for the first Entra token (cached after that),
and the gateway round trip. The work Terraform module can deploy the agent from an S3 zip with no
ECR or CodeBuild. It must wire the zip's `version_id` into the runtime, own the service-created
log groups, and treat the name prefix as fixed.

## Results

| Q | Check | Procedure | Expected | Observed | Config | Status |
|---|---|---|---|---|---|---|
| Q2.1 | egress_to_external_https | Agent calls the tunnel URL's `/healthz` from inside Runtime | 200 from inside Runtime (PUBLIC mode) | `healthz_status=200` | runtime v1 | pass |
| Q2.2 | openai_round_trip | `chat` action, provider openai | Runtime → Entra token → gateway → provider → caller | gateway 200; token 836.6 ms, gateway 2787.0 ms, client 7156.6 ms | runtime v1 | pass |
| Q2.2 | anthropic_round_trip | `chat` action, provider anthropic | as above | gateway 200; token 724.9 ms, gateway 1238.0 ms, client 4921.4 ms | runtime v1 | pass |
| Q2.2 | unauthenticated_call_rejected | Agent calls the gateway without a JWT | 401 | `gateway_status=401` | runtime v1 | pass |
| Q2.2 | direct_bad_tokens_rejected | Test client calls the public gateway URL with no token and with a malformed token | 401 for both | no_token=401, garbage=401 | runtime v1 | pass |
| Q2.3 | state_persists_within_session | Write a marker, call again with the same `runtimeSessionId` | same process, marker seen | same_boot=True, marker_seen=True | runtime v1 | pass |
| Q2.3 | state_isolated_across_sessions | Call with a different `runtimeSessionId` | different environment, no marker | different_boot=True, marker_present=False | runtime v1 | pass |
| Q2.4 | cold_vs_warm_latency | `whoami` twice in a new session | record cold vs warm | cold 3465.2 ms (uptime 0.65 s), warm 117.1 ms | runtime v1 | pass |
| Q2.4 | token_cached_across_invocations | Two `chat` calls in one warm session | second call reuses the MSAL-cached token | token 522.4 ms → 0.1 ms; gateway 200, 200; gateway 723.4 ms | runtime v1 | pass |
| Q2.4 | idle_session_reclaimed | Write a marker, wait 165 s, call the same session | fresh environment | same_boot=False, marker_present=False | idle timeout 120 s, v1 | pass |
| Q2.5 | runtime_logs_redacted | Search the session's CloudWatch events for a JWT, the secret canary, the prompt, the completion | logs arrive; no leaks | 1 log group, 33 events, 2 correlated, 0 leaks | runtime v1 | pass |
| Q2.6 | no_ecr_or_codebuild_created | ECR and CodeBuild inventory before apply and after | none created | 0 ECR repositories, 0 CodeBuild projects | runtime v1 | pass |
| TF.1 | plan_resources | `plan` then state list after apply | no ECR or CodeBuild resources | 16 state entries (12 managed resources + data sources); 0 `aws_ecr*` or `aws_codebuild*` | deploy_runtime=true | pass |
| TF.2 | second_plan_clean | `plan -detailed-exitcode` after apply | exit 0 | exit 0 | — | pass |
| TF.3 | new_zip_in_place_update | Change agent code, rebuild zip, apply while a 110 s invocation is open | runtime updated in place, version increases | `~` update; version 1 → 2 (revert: 2 → 3); open invocation completed (200, 110.9 s); same session kept its old environment | — | pass |
| Q2.6 | update_time | `time terraform apply` for TF.3 | record | 41.0 s wall-clock | — | recorded |
| TF.4 | replacement_forcing_attributes | `plan` with `name_prefix` and idle-timeout changes (not applied) | record | `name_prefix`: replaces runtime, bucket (and its versioning, SSE, public-access-block, object), secret, both IAM roles and policies, Code Interpreter. Idle timeout 120 → 300: in-place update | — | recorded |
| TF.5 | destroy_including_partial | `destroy`; `apply -target` zip; `destroy`; check bucket and runtimes | both destroys finish; bucket gone; no runtime | 12 destroyed; 3 created then 3 destroyed; `head-bucket` 404; `list-agent-runtimes` empty | — | pass |
| TF.5 | log_groups_left | List log groups under the runtime prefix after destroy, delete them | record, then 0 | 1 service-created log group left by `destroy`; 0 after manual delete | — | recorded |

## Latency breakdown

The gateway was a simulation on the operator's laptop behind a public tunnel, so the gateway
numbers include the round trip from ap-southeast-1 to the laptop.

| Segment | First call | Warm call |
|---|---|---|
| Client → Runtime (cold vs warm `whoami`) | 3465.2 ms (new microVM, uptime 0.65 s) | 117.1 ms |
| Entra token (MSAL) | 522.4–836.6 ms (4 first calls) | 0.1 ms (cached) |
| Gateway + provider | 1238.0 ms (Anthropic), 2787.0 ms (OpenAI) | 723.4 ms (one sample) |

## Implications for the work Terraform modules

- Direct code deployment needs no ECR repository, no CodeBuild project, and no Bedrock model
  permissions. The execution role needs S3 read on the one zip object, Secrets Manager read on
  the one secret, and logs, X-Ray, and CloudWatch metrics.
- Wire the zip object's `version_id` into the runtime's code configuration. A new zip then gives
  an in-place update and a new runtime version (41 s in this run). The code bucket must have
  versioning on.
- An update does not interrupt open invocations or move live sessions. A session stays on its
  old environment until it is reclaimed (idle timeout or max lifetime), so new code reaches only
  new or reclaimed sessions. Callers that need the new code at once must use new session IDs.
- `name_prefix` (every resource name) forces replacement of all resources, including a new
  runtime ARN and an empty secret. Treat names as fixed for a stack's life. The idle timeout and
  the zip update in place.
- The service creates the runtime log groups (`/aws/bedrock-agentcore/runtimes/<id>-DEFAULT`).
  They are not in Terraform state and `destroy` leaves them. Pre-create them with retention, or
  clean them up outside Terraform.
- `force_destroy = true` was needed to destroy the versioned code bucket. Decide if production
  keeps it.
- `apply -target` on the zip object created the bucket without its public-access-block and SSE
  configuration resources. Make the object depend on them if targeted applies are possible.
- Secret-shell pattern: Terraform creates the empty secret; a script puts the value. With
  `recovery_window_in_days = 0` the destroy is immediate. A production recovery window blocks a
  same-name re-create until it ends.
- Idle timeout was set to 120 s and max lifetime to 900 s for the POC. The service default idle
  timeout (15 minutes, per AWS docs) was not measured.
- The IAM-propagation retry described in the runbook was not needed in this run.

## Limits of these results

- The gateway is a simulation on a public tunnel. This proves Runtime can reach and authenticate
  to an external JWT-protected gateway in PUBLIC mode. It does not prove compatibility with the
  real gateway's schema, network placement (a private gateway would need VPC mode), or auth
  details.
- The caller was a local SigV4 script, not the unified API service. User-context propagation
  (future Phase 3) is untested. Note for Phase 3: `aws_bedrockagentcore_agent_runtime` has
  `authorizer_configuration.custom_jwt_authorizer` for inbound JWT auth; it was not used here.
- One run, in one region. Latency numbers are single samples, not distributions.
- `whoami` does not report the code version. That a reclaimed session runs the newest version is
  expected but not verified.
- The quick tunnel did not connect while Tailscale was on (port 7844 blocked, probably by an exit
  node). This is an operator-network limit, not a Runtime finding.
