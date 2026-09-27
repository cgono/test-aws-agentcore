data "aws_caller_identity" "current" {}

data "aws_budgets_budget" "required" {
  name = var.aws_budget_name
}

locals {
  account_id       = data.aws_caller_identity.current.account_id
  code_bucket      = "${var.name_prefix}-code-${local.account_id}"
  workspace_bucket = "${var.name_prefix}-workspace-${local.account_id}"
  discovery_url    = "https://login.microsoftonline.com/${var.tenant_id}/v2.0/.well-known/openid-configuration"
}
