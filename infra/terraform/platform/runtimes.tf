locals {
  runtime_authorizer = {
    discovery_url    = local.discovery_url
    allowed_audience = [var.runtime_app_id]
    custom_claims = [
      { name = "azp", value_type = "STRING", operator = "EQUALS", value = var.unified_api_client_id },
      { name = "roles", value_type = "STRING_ARRAY", operator = "CONTAINS", value = "Runtime.Invoke" },
    ]
  }
  runtime_headers = [
    "X-Amzn-Bedrock-AgentCore-Runtime-Custom-Grant",
    "X-Amzn-Bedrock-AgentCore-Runtime-Custom-User-Token",
  ]
  hub_url = trimsuffix(aws_lambda_function_url.resource_hub.function_url, "/")
}

module "research_runtime" {
  source                       = "../modules/agentcore_agent_runtime"
  name                         = "${var.name_prefix}_research"
  description                  = "Phase 3a research agent (Claude Agent SDK)"
  code_bucket_name             = aws_s3_bucket.code.id
  code_object_key              = aws_s3_object.bootstrap["bootstrap/research.zip"].key
  code_object_version_id       = aws_s3_object.bootstrap["bootstrap/research.zip"].version_id
  readable_code_keys           = ["bootstrap/research.zip", "releases/research.zip", "releases/probe.zip"]
  authorizer                   = local.runtime_authorizer
  request_header_allowlist     = local.runtime_headers
  idle_session_timeout_seconds = 900
  max_lifetime_seconds         = 10800 # the expiry test's control grant lives 2 h
  environment_variables = {
    POC_REGION          = var.aws_region
    HUB_URL             = local.hub_url
    HUB_SCOPE           = "api://${var.hub_app_id}/.default"
    GATEWAY_URL         = "${var.gateway_base_url}/anthropic"
    GATEWAY_SCOPE       = "api://${var.gateway_app_id}/.default"
    IDENTITY_PROVIDER   = aws_bedrockagentcore_oauth2_credential_provider.agent["research"].name
    CODE_INTERPRETER_ID = module.code_interpreter.code_interpreter_id
    AGENT_MODEL         = var.agent_model
    WORKSPACE_BUCKET    = aws_s3_bucket.workspace.id # name only, for the negative probes; the role has no access
  }
  extra_policy_statements = concat(local.identity_statements["research"], [{
    Sid    = "UseSandbox"
    Effect = "Allow"
    Action = [
      "bedrock-agentcore:StartCodeInterpreterSession",
      "bedrock-agentcore:InvokeCodeInterpreter",
      "bedrock-agentcore:StopCodeInterpreterSession",
      "bedrock-agentcore:GetCodeInterpreterSession",
    ]
    Resource = [module.code_interpreter.code_interpreter_arn]
  }])
}

module "bench_runtime" {
  source                       = "../modules/agentcore_agent_runtime"
  name                         = "${var.name_prefix}_bench"
  description                  = "Phase 3a file-access benchmark"
  code_bucket_name             = aws_s3_bucket.code.id
  code_object_key              = aws_s3_object.bootstrap["bootstrap/bench.zip"].key
  code_object_version_id       = aws_s3_object.bootstrap["bootstrap/bench.zip"].version_id
  readable_code_keys           = ["bootstrap/bench.zip", "releases/bench.zip"]
  authorizer                   = local.runtime_authorizer
  request_header_allowlist     = local.runtime_headers
  idle_session_timeout_seconds = 900
  max_lifetime_seconds         = 3600
  environment_variables = {
    POC_REGION        = var.aws_region
    HUB_URL           = local.hub_url
    HUB_SCOPE         = "api://${var.hub_app_id}/.default"
    IDENTITY_PROVIDER = aws_bedrockagentcore_oauth2_credential_provider.agent["bench"].name
  }
  extra_policy_statements = local.identity_statements["bench"]
}

resource "aws_cloudwatch_log_group" "runtime" {
  for_each          = { research = module.research_runtime.agent_runtime_id, bench = module.bench_runtime.agent_runtime_id }
  name              = "/aws/bedrock-agentcore/runtimes/${each.value}-DEFAULT"
  retention_in_days = 7
}
