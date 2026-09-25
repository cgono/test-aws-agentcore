mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }
}

variables {
  aws_region      = "ap-southeast-1"
  aws_budget_name = "example-budget"
}

run "caller_role_is_scoped_to_code_interpreter_sessions" {
  command = apply

  assert {
    condition = toset(jsondecode(aws_iam_role_policy.ci_caller.policy).Statement[0].Action) == toset([
      "bedrock-agentcore:StartCodeInterpreterSession",
      "bedrock-agentcore:InvokeCodeInterpreter",
      "bedrock-agentcore:StopCodeInterpreterSession",
      "bedrock-agentcore:GetCodeInterpreterSession",
    ])
    error_message = "caller policy must allow exactly the four session actions"
  }

  assert {
    condition = toset(jsondecode(aws_iam_role_policy.ci_caller.policy).Statement[0].Resource) == toset([
      "arn:aws:bedrock-agentcore:ap-southeast-1:aws:code-interpreter/aws.codeinterpreter.v1",
      module.public_code_interpreter.code_interpreter_arn,
    ])
    error_message = "caller policy must cover exactly the built-in and the custom interpreter"
  }

  assert {
    condition     = length(jsondecode(aws_iam_role_policy.ci_caller.policy).Statement) == 1
    error_message = "caller policy must have a single statement"
  }

  assert {
    condition = (
      length(jsondecode(aws_iam_role.ci_caller.assume_role_policy).Statement) == 1
      && jsondecode(aws_iam_role.ci_caller.assume_role_policy).Statement[0].Effect == "Allow"
      && jsondecode(aws_iam_role.ci_caller.assume_role_policy).Statement[0].Action == "sts:AssumeRole"
      && jsondecode(aws_iam_role.ci_caller.assume_role_policy).Statement[0].Principal.AWS == "arn:aws:iam::123456789012:root"
    )
    error_message = "trust policy must be a single sts:AssumeRole statement for this account"
  }

  assert {
    condition = (
      jsondecode(aws_iam_role.ci_caller.assume_role_policy).Statement[0].Condition.ArnLike["aws:PrincipalArn"]
      == "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/*"
    )
    error_message = "only SSO roles in this account may assume the caller role"
  }
}

run "exposes_builtin_interpreter_id" {
  command = plan

  assert {
    condition     = output.builtin_code_interpreter_id == "aws.codeinterpreter.v1"
    error_message = "built-in interpreter id must be exposed"
  }
}
