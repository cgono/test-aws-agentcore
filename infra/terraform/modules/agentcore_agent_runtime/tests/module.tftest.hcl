mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }

  mock_data "aws_region" {
    defaults = {
      region = "ap-southeast-1"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/mock-execution-role"
    }
  }
}

variables {
  name                   = "poc_agent_test"
  code_bucket_name       = "example-bucket"
  code_object_key        = "agent/agent.zip"
  code_object_version_id = "example-version-1"
}

run "zip_artifact_passes_through" {
  command = plan

  assert {
    condition     = aws_bedrockagentcore_agent_runtime.this.agent_runtime_artifact[0].code_configuration[0].runtime == "PYTHON_3_13"
    error_message = "default runtime must be PYTHON_3_13"
  }

  assert {
    condition     = aws_bedrockagentcore_agent_runtime.this.agent_runtime_artifact[0].code_configuration[0].entry_point == tolist(["main.py"])
    error_message = "default entry point must be main.py"
  }

  assert {
    condition     = aws_bedrockagentcore_agent_runtime.this.agent_runtime_artifact[0].code_configuration[0].code[0].s3[0].version_id == "example-version-1"
    error_message = "the bootstrap zip object version must pass through on create"
  }

  assert {
    condition     = length(aws_bedrockagentcore_agent_runtime.this.agent_runtime_artifact[0].container_configuration) == 0
    error_message = "the module must never render a container configuration"
  }

  assert {
    condition     = aws_bedrockagentcore_agent_runtime.this.network_configuration[0].network_mode == "PUBLIC"
    error_message = "default network mode must be PUBLIC"
  }
}

run "lifecycle_passes_through" {
  command = plan

  variables {
    idle_session_timeout_seconds = 120
    max_lifetime_seconds         = 900
  }

  assert {
    condition     = aws_bedrockagentcore_agent_runtime.this.lifecycle_configuration[0].idle_runtime_session_timeout == 120
    error_message = "idle timeout must pass through"
  }

  assert {
    condition     = aws_bedrockagentcore_agent_runtime.this.lifecycle_configuration[0].max_lifetime == 900
    error_message = "max lifetime must pass through"
  }
}

run "execution_policy_has_no_ecr_or_bedrock_model_access" {
  command = apply

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_role_policy.execution.policy).Statement :
      alltrue([for action in flatten([statement.Action]) : !startswith(action, "ecr:") && !startswith(action, "bedrock:")])
    ])
    error_message = "execution role must not grant ECR or Bedrock model actions"
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_iam_role_policy.execution.policy).Statement :
      contains(flatten([statement.Resource]), "arn:aws:s3:::example-bucket/agent/agent.zip")
    ])
    error_message = "execution role must be able to read exactly the zip object"
  }

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_role_policy.execution.policy).Statement :
      flatten([statement.Resource]) == ["*"]
      if length(setintersection(flatten([statement.Action]), ["logs:PutResourcePolicy", "logs:DescribeLogGroups"])) > 0
    ])
    error_message = "logs:PutResourcePolicy and logs:DescribeLogGroups support only Resource \"*\""
  }

  assert {
    condition     = length(jsondecode(aws_iam_role_policy.execution.policy).Statement) == 7
    error_message = "no secret statement without secret_arns"
  }
}

run "secret_statement_scoped_to_given_arns" {
  command = apply

  variables {
    secret_arns = ["arn:aws:secretsmanager:ap-southeast-1:123456789012:secret:example"]
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_iam_role_policy.execution.policy).Statement :
      statement.Sid == "ReadNamedSecrets" && statement.Resource == ["arn:aws:secretsmanager:ap-southeast-1:123456789012:secret:example"]
    ])
    error_message = "secret access must be limited to the given ARNs"
  }
}

run "trust_policy_is_scoped_to_account_and_region" {
  command = apply

  assert {
    condition     = jsondecode(aws_iam_role.execution.assume_role_policy).Statement[0].Condition.StringEquals["aws:SourceAccount"] == "123456789012"
    error_message = "trust must be limited to this account"
  }

  assert {
    condition     = jsondecode(aws_iam_role.execution.assume_role_policy).Statement[0].Condition.ArnLike["aws:SourceArn"] == "arn:aws:bedrock-agentcore:ap-southeast-1:123456789012:*"
    error_message = "trust must be limited to AgentCore in this region"
  }
}

run "rejects_unsupported_python" {
  command = plan

  variables {
    python_runtime = "PYTHON_3_9"
  }

  expect_failures = [var.python_runtime]
}

run "rejects_three_part_entry_point" {
  command = plan

  variables {
    entry_point = ["a", "b", "c"]
  }

  expect_failures = [var.entry_point]
}

run "rejects_idle_timeout_below_60" {
  command = plan

  variables {
    idle_session_timeout_seconds = 30
  }

  expect_failures = [var.idle_session_timeout_seconds]
}

run "rejects_max_lifetime_below_idle_timeout" {
  command = plan

  variables {
    idle_session_timeout_seconds = 900
    max_lifetime_seconds         = 600
  }

  expect_failures = [var.max_lifetime_seconds]
}

run "authorizer_and_headers_render" {
  command = plan

  variables {
    authorizer = {
      discovery_url    = "https://login.microsoftonline.com/example-tenant/v2.0/.well-known/openid-configuration"
      allowed_audience = ["runtime-app-id"]
      custom_claims = [
        { name = "azp", value_type = "STRING", operator = "EQUALS", value = "unified-api-id" },
        { name = "roles", value_type = "STRING_ARRAY", operator = "CONTAINS", value = "Runtime.Invoke" },
      ]
    }
    request_header_allowlist = ["X-Amzn-Bedrock-AgentCore-Runtime-Custom-Grant"]
  }

  assert {
    condition     = aws_bedrockagentcore_agent_runtime.this.authorizer_configuration[0].custom_jwt_authorizer[0].allowed_audience == toset(["runtime-app-id"])
    error_message = "allowed_audience must pass through"
  }

  assert {
    condition     = length(aws_bedrockagentcore_agent_runtime.this.authorizer_configuration[0].custom_jwt_authorizer[0].custom_claim) == 2
    error_message = "both custom claims must render"
  }

  assert {
    condition     = aws_bedrockagentcore_agent_runtime.this.request_header_configuration[0].request_header_allowlist == toset(["X-Amzn-Bedrock-AgentCore-Runtime-Custom-Grant"])
    error_message = "header allow-list must pass through"
  }
}

run "no_authorizer_by_default" {
  command = plan

  assert {
    condition     = length(aws_bedrockagentcore_agent_runtime.this.authorizer_configuration) == 0
    error_message = "without var.authorizer the runtime keeps SigV4 (Phase 2 behavior)"
  }
}

run "execution_role_reads_every_listed_code_key" {
  command = plan

  variables {
    readable_code_keys = ["bootstrap/research.zip", "releases/research.zip", "releases/probe.zip"]
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.execution.policy, "example-bucket/releases/research.zip") && strcontains(aws_iam_role_policy.execution.policy, "example-bucket/bootstrap/research.zip") && strcontains(aws_iam_role_policy.execution.policy, "example-bucket/agent/agent.zip")
    error_message = "the execution role must read bootstrap and release keys"
  }
}

run "empty_readable_code_keys_keeps_bootstrap_access" {
  command = plan

  variables {
    readable_code_keys = []
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.execution.policy, "example-bucket/agent/agent.zip")
    error_message = "an empty extra-key list must retain bootstrap access"
  }
}

run "different_extra_policy_statement_shapes_are_accepted" {
  command = plan

  variables {
    extra_policy_statements = [
      { Sid = "One", Effect = "Allow", Action = ["kms:Decrypt"], Resource = ["arn:aws:kms:ap-southeast-1:123456789012:key/example"] },
      { Sid = "Two", Effect = "Allow", Action = ["s3:ListBucket"], Resource = ["arn:aws:s3:::example-bucket"], Condition = { StringEquals = { "s3:prefix" = "users/" } } },
    ]
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.execution.policy, "\"Sid\":\"One\"") && strcontains(aws_iam_role_policy.execution.policy, "\"Sid\":\"Two\"")
    error_message = "both differently shaped statements must be rendered"
  }
}

run "authorizer_requires_a_custom_claim" {
  command = plan

  variables {
    authorizer = {
      discovery_url    = "https://login.microsoftonline.com/example-tenant/v2.0/.well-known/openid-configuration"
      allowed_audience = ["runtime-app-id"]
      custom_claims    = []
    }
  }

  expect_failures = [var.authorizer]
}

run "authorizer_claim_needs_exactly_one_match_value" {
  command = plan

  variables {
    authorizer = {
      discovery_url    = "https://login.microsoftonline.com/example-tenant/v2.0/.well-known/openid-configuration"
      allowed_audience = ["runtime-app-id"]
      custom_claims = [
        { name = "azp", value_type = "STRING", operator = "EQUALS" },
      ]
    }
  }

  expect_failures = [var.authorizer]
}

run "authorizer_requires_an_audience" {
  command = plan

  variables {
    authorizer = {
      discovery_url    = "https://login.microsoftonline.com/example-tenant/v2.0/.well-known/openid-configuration"
      allowed_audience = []
      custom_claims    = [{ name = "azp", value_type = "STRING", operator = "EQUALS", value = "unified-api-id" }]
    }
  }

  expect_failures = [var.authorizer]
}

run "authorizer_rejects_mismatched_claim_type" {
  command = plan

  variables {
    authorizer = {
      discovery_url    = "https://login.microsoftonline.com/example-tenant/v2.0/.well-known/openid-configuration"
      allowed_audience = ["runtime-app-id"]
      custom_claims    = [{ name = "roles", value_type = "STRING", operator = "CONTAINS", value = "Runtime.Invoke" }]
    }
  }

  expect_failures = [var.authorizer]
}

run "extra_policy_statement_rejects_null_effect" {
  command = plan

  variables {
    extra_policy_statements = [{ Effect = null, Action = ["s3:GetObject"], Resource = ["arn:aws:s3:::example-bucket/x"] }]
  }

  expect_failures = [var.extra_policy_statements]
}
