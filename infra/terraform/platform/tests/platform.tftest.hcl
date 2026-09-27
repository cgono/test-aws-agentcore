mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_region" {
    defaults = { region = "ap-southeast-1" }
  }
  mock_data "aws_kms_public_key" {
    defaults = { public_key_pem = "-----BEGIN PUBLIC KEY-----\nMFk=\n-----END PUBLIC KEY-----\n" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/mock" }
  }
  mock_resource "aws_kms_key" {
    defaults = { key_id = "arn:aws:kms:ap-southeast-1:123456789012:key/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" }
  }
  mock_resource "aws_bedrockagentcore_oauth2_credential_provider" {
    defaults = {
      credential_provider_arn = "arn:aws:bedrock-agentcore:ap-southeast-1:123456789012:token-vault/default/oauth2credentialprovider/mock"
      client_secret_arn       = [{ secret_arn = "arn:aws:secretsmanager:ap-southeast-1:123456789012:secret:mock" }]
    }
  }
  mock_resource "aws_lambda_function_url" {
    defaults = { function_url = "https://mock.lambda-url.ap-southeast-1.on.aws/" }
  }
}

variables {
  aws_region                     = "ap-southeast-1"
  aws_budget_name                = "example-budget"
  tenant_id                      = "example-tenant"
  hub_app_id                     = "hub-app-id"
  gateway_app_id                 = "gateway-app-id"
  runtime_app_id                 = "runtime-app-id"
  unified_api_client_id          = "unified-api-id"
  research_agent_client_id       = "research-agent-id"
  research_agent_client_secret   = "not-a-secret"
  bench_agent_client_id          = "bench-agent-id"
  bench_agent_client_secret      = "not-a-secret"
  research_agent_client_id_plain = "research-agent-id"
  bench_agent_client_id_plain    = "bench-agent-id"
  gateway_base_url               = "https://gateway.example.test"
  agent_model                    = "claude-sonnet-5"
  bootstrap_dir                  = "tests/fixtures"
}

override_resource {
  target = aws_iam_role.code_interpreter
  values = { arn = "arn:aws:iam::123456789012:role/poc3_sandbox_ci_execution" }
}

override_resource {
  target = aws_s3_bucket.workspace
  values = { arn = "arn:aws:s3:::poc3-workspace-123456789012" }
}

run "code_interpreter_is_sandboxed_with_no_s3_role" {
  command = apply

  assert {
    condition     = module.code_interpreter.network_mode == "SANDBOX"
    error_message = "Code Interpreter must use SANDBOX network mode"
  }

  assert {
    condition     = module.code_interpreter.execution_role_arn == aws_iam_role.code_interpreter.arn
    error_message = "Code Interpreter must use its dedicated execution role"
  }

  assert {
    condition     = module.code_interpreter.execution_role_arn != module.research_runtime.execution_role_arn && module.code_interpreter.execution_role_arn != module.bench_runtime.execution_role_arn
    error_message = "Code Interpreter must not share either Runtime execution role"
  }
}

run "only_the_resource_hub_reaches_the_workspace_bucket" {
  command = plan

  assert {
    condition     = !strcontains(module.research_runtime.execution_policy_json, local.workspace_bucket) && !strcontains(module.bench_runtime.execution_policy_json, local.workspace_bucket) && !strcontains(module.research_runtime.execution_policy_json, "\"s3:*\"") && !strcontains(module.bench_runtime.execution_policy_json, "\"s3:*\"")
    error_message = "Runtime roles must not reference the workspace bucket"
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.resource_hub.policy, aws_s3_bucket.workspace.arn)
    error_message = "the Resource Hub role must reach the workspace bucket"
  }
}

run "runtimes_use_the_jwt_authorizer_and_grant_header" {
  command = plan

  assert {
    condition     = module.research_runtime.authorizer_audience == toset(["runtime-app-id"])
    error_message = "research runtime must accept only the runtime app audience"
  }

  assert {
    condition     = contains(module.research_runtime.request_header_allowlist, "X-Amzn-Bedrock-AgentCore-Runtime-Custom-Grant")
    error_message = "grant header must be allow-listed"
  }

  assert {
    condition     = module.bench_runtime.authorizer_audience == toset(["runtime-app-id"]) && contains(module.bench_runtime.request_header_allowlist, "X-Amzn-Bedrock-AgentCore-Runtime-Custom-Grant")
    error_message = "bench runtime must use the same JWT audience and grant header"
  }
}

run "grant_key_is_p256_sign_verify" {
  command = plan

  assert {
    condition     = aws_kms_key.grant.customer_master_key_spec == "ECC_NIST_P256" && aws_kms_key.grant.key_usage == "SIGN_VERIFY"
    error_message = "grant key must be ECC_NIST_P256 SIGN_VERIFY"
  }

  assert {
    condition     = !contains(jsondecode(aws_kms_key.grant.policy).Statement[0].Action, "kms:Create*") && anytrue([for statement in jsondecode(aws_kms_key.grant.policy).Statement : statement.Effect == "Deny" && statement.Action == "kms:CreateGrant"]) && anytrue([for statement in jsondecode(aws_kms_key.grant.policy).Statement : statement.Effect == "Deny" && statement.Action == "kms:Sign" && try(statement.Condition.ArnNotEquals["aws:PrincipalArn"], "") == aws_iam_role.grant_signer.arn])
    error_message = "account admins must not create signing grants and other principals must not sign"
  }
}

run "raw_user_token_mode_is_off_by_default" {
  command = plan

  assert {
    condition     = aws_lambda_function.resource_hub.environment[0].variables["ALLOW_RAW_USER_TOKEN"] == "false"
    error_message = "raw-token mode must be off unless enabled for the expiry test"
  }
}
