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
    error_message = "the zip object version must pass through so new zips redeploy"
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
