data "aws_caller_identity" "current" {}

# Plan fails here when the named budget does not exist: the POC's cost guard.
data "aws_budgets_budget" "required" {
  name = var.aws_budget_name
}

locals {
  account_id                   = data.aws_caller_identity.current.account_id
  builtin_code_interpreter_id  = "aws.codeinterpreter.v1"
  builtin_code_interpreter_arn = "arn:aws:bedrock-agentcore:${var.aws_region}:aws:code-interpreter/${local.builtin_code_interpreter_id}"
}
