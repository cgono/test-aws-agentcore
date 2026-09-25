module "public_code_interpreter" {
  source = "../modules/agentcore_code_interpreter"

  name         = "${var.name_prefix}_public_ci"
  description  = "POC custom interpreter with PUBLIC network mode (Q1.4)"
  network_mode = "PUBLIC"
}

resource "aws_iam_role" "ci_caller" {
  name                 = "${var.name_prefix}_ci_caller"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
      Condition = {
        ArnLike = {
          "aws:PrincipalArn" = "arn:aws:iam::${local.account_id}:role/aws-reserved/sso.amazonaws.com/*"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "ci_caller" {
  name = "code-interpreter-caller"
  role = aws_iam_role.ci_caller.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "UseCodeInterpreterSessions"
      Effect = "Allow"
      Action = [
        "bedrock-agentcore:StartCodeInterpreterSession",
        "bedrock-agentcore:InvokeCodeInterpreter",
        "bedrock-agentcore:StopCodeInterpreterSession",
        "bedrock-agentcore:GetCodeInterpreterSession",
      ]
      Resource = [
        local.builtin_code_interpreter_arn,
        module.public_code_interpreter.code_interpreter_arn,
      ]
    }]
  })
}
