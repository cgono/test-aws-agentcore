# Code Interpreter Findings (Phase 1)

**Date:** 2026-09-26 · **Region:** ap-southeast-1 · **SDK:** bedrock-agentcore 1.18.1 ·
**Terraform:** 1.14.8, hashicorp/aws 6.66.0

## Summary

An external caller, such as a Temporal worker, can use Code Interpreter with only its own
IAM credentials and a policy of four session actions. Python state, internal files, and
caller-uploaded files stay in one session and do not go into a new session. Python,
JavaScript, TypeScript, and shell commands all run in the same session. The built-in
interpreter has no internet egress. A custom interpreter in PUBLIC mode has internet egress.
A session ends at `sessionTimeoutSeconds` and activity does not extend it. After the session
ends, the service returns `ValidationException`, not `ResourceNotFoundException`. An
execution that is longer than the session lifetime does not return until the session ends.
The work Terraform modules must set the session timeout for the longest job, and they must
use the `aws`-owned ARN form for the built-in interpreter in IAM policies.

## Results

Status is the status that the probe recorded. Two notes follow the table.

| Q | Check | Procedure | Expected | Observed | Config | Status |
|---|---|---|---|---|---|---|
| Q1.1 | state_persists_within_session | set a variable, read it in a later call | variable readable in the same session | `42` | built-in, SSO | pass |
| Q1.1 | state_isolated_across_sessions | read the variable in a new session | new session cannot see it | `NameError` | built-in, SSO | pass |
| Q1.2 | javascript_executes | run JavaScript that prints 6 × 7 | prints 42 | `42` | built-in, SSO | pass |
| Q1.2 | typescript_executes | run typed TypeScript that prints 6 × 7 | prints 42 | `42` | built-in, SSO | pass |
| Q1.2 | shell_command_executes | `echo` and `uname -m` | echo output returned; architecture shown | `poc-shell-ok`, `aarch64` | built-in, SSO | pass |
| Q1.2 | python_after_other_languages | run Python after JavaScript in the same session | Python still works | `python-after-js` | built-in, SSO | pass |
| Q1.3 | internal_file_persists_within_session | code writes a file, later call reads it | file readable in the same session | marker read back | built-in, SSO | pass |
| Q1.3 | internal_file_absent_in_new_session | read the file in a new session | file not present | `poc-absent` | built-in, SSO | pass |
| Q1.3 | caller_upload_compute_download | caller uploads CSV, code writes JSON, caller downloads it | `sum_b == 6` | `{"sum_b": 6}` | built-in, SSO | pass |
| Q1.3 | binary_round_trip | upload then download 256 raw bytes | bytes unchanged | bytes, length 256 | built-in, SSO | pass |
| Q1.4 | public_internet_egress | HTTP request to a public URL | not reachable | blocked, `URLError` | built-in, SSO | pass |
| Q1.4 | public_internet_egress | HTTP request to a public URL | reachable | status 200 | custom PUBLIC, SSO | pass |
| Q1.5 | syntax_error_surfaces | run code with a syntax error | reported as a failed execution | failed, `SyntaxError` | built-in, SSO | pass |
| Q1.5 | exception_surfaces | raise an uncaught exception | reported with its message | failed, `ValueError` and message | built-in, SSO | pass |
| Q1.5 | large_output | print 2,000,000 characters | call returns; record truncation | 2,000,000 of 2,000,000 returned | built-in, SSO | pass |
| Q1.5 | sixty_second_execution | sleep 60 s | completes | completed in 60.1 s | built-in, SSO | pass |
| Q1.5 | one_gib_allocation | allocate 1 GiB | record whether it fits | allocated, no `MemoryError` | built-in, SSO | pass |
| Q1.5 | idle_session_ends_at_ttl | TTL 60 s, idle, run code at 80 s | session gone | start `ok`, at 80 s `ValidationException` | built-in, SSO | blocked (note 1) |
| Q1.5 | active_session_ends_at_ttl | TTL 60 s, run code every 15 s | activity does not extend the session | 15/30/45 s `ok`; 60/75/80 s `ValidationException` | built-in, SSO | blocked (note 1) |
| Q1.5 | per_execution_limit | sleep 600 s, session timeout 900 s | record what ends the call | `ValidationException` after 904 s | built-in, SSO | pass (note 2) |
| Q1.6 | scoped_role_can_execute | assume the caller role, start, execute, get, stop | all four actions work | executed; session `READY` | built-in, caller role | pass |
| Q1.6 | invoke_denied_without_permission | assume the role with a session policy that removes `InvokeCodeInterpreter` | execution denied | `AccessDeniedException` | built-in, caller role | pass |
| Q1.6 | scoped_role_can_execute | same as above | all four actions work | executed; session `READY` | custom PUBLIC, caller role | pass |
| Q1.6 | invoke_denied_without_permission | same as above | execution denied | `AccessDeniedException` | custom PUBLIC, caller role | pass |
| TF.1 | clean apply resource set | `terraform plan` before apply | only interpreter, role, and policy | 3 resources: interpreter, `aws_iam_role.ci_caller`, `aws_iam_role_policy.ci_caller`; no ECR or CodeBuild | poc root | pass |
| TF.2 | no drift after apply | `plan -detailed-exitcode` | exit 0 | exit 0 | poc root | pass |

**Note 1 (Q1.5 TTL).** The probe accepts only `ResourceNotFoundException` as the "session
expired" code, so it recorded `blocked`. The timing shows that the session ended at the
60 s TTL in both checks. In the active check, calls at 15, 30, and 45 s succeeded, and every
call from 60 s failed. Thus `sessionTimeoutSeconds` is a fixed lifetime, and the service
returns `ValidationException` for a call to an expired session. We did not rerun, because a
rerun gives the same code.

**Note 2 (per-execution limit).** The 600 s execution did not return after 600 s, and the
SDK's 300 s read timeout did not stop it. The call ended with `ValidationException` after
904 s. This is near the 900 s session timeout. We did not find the cause. The most
probable cause is that the session ended while the execution ran.

## Implications for the work Terraform modules

- **Built-in interpreter ARN.** IAM policies for the built-in interpreter must use
  `arn:aws:bedrock-agentcore:<region>:aws:code-interpreter/aws.codeinterpreter.v1`. The
  account field is `aws`, not the account ID. Q1.6 passed with this form.
- **Minimal caller policy.** A caller needs only `StartCodeInterpreterSession`,
  `InvokeCodeInterpreter`, `GetCodeInterpreterSession`, and `StopCodeInterpreterSession`,
  scoped to the interpreter ARNs. Without `InvokeCodeInterpreter`, execution is denied.
- **Egress.** The built-in interpreter has no internet egress. If a job needs internet
  access, the module must create a custom interpreter with `network_mode = "PUBLIC"` or
  `"VPC"`. The module requires `execution_role_arn` when the mode is `SANDBOX`.
- **Session timeout.** Set `sessionTimeoutSeconds` for the longest job plus a margin.
  Activity does not extend a session, and a long execution can end with the session.
- **Error handling in callers.** Treat `ValidationException` on an invoke as a possible
  expired session. Start a new session, and do not retry on the old session.
- **Drift.** TF.2 showed no perpetual diff, so the module needs no `ignore_changes`.

## Limits of these results

- Egress results describe only the configurations tested (built-in, custom PUBLIC); VPC mode
  was not tested.
- Q1.6 proves the minimal caller policy for the built-in and one custom interpreter only.
- Q1.1 through Q1.3 and Q1.5 ran only on the built-in interpreter.
- Q1.5 TTL used a 60 s timeout. We did not test other timeout values.
- The cause of the 904 s end in the per-execution check (note 2) is not confirmed.
- One run in one region (ap-southeast-1) on 2026-09-26.
