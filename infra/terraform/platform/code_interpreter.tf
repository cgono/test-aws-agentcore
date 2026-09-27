resource "aws_iam_role" "code_interpreter" {
  name = "${var.name_prefix}_sandbox_ci_execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "bedrock-agentcore.amazonaws.com" }
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:aws:bedrock-agentcore:${var.aws_region}:${local.account_id}:*" }
      }
    }]
  })
}

module "code_interpreter" {
  source             = "../modules/agentcore_code_interpreter"
  name               = "${var.name_prefix}_sandbox_ci"
  description        = "Phase 3a sandbox: no network and no S3 permissions"
  network_mode       = "SANDBOX"
  execution_role_arn = aws_iam_role.code_interpreter.arn
}
