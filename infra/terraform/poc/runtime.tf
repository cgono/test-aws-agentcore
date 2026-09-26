locals {
  runtime_count = var.deploy_runtime ? 1 : 0
  code_bucket   = "${replace(var.name_prefix, "_", "-")}-agent-code-${local.account_id}"
  agent_zip_key = "agent/agent.zip"
}

resource "aws_s3_bucket" "agent_code" {
  count         = local.runtime_count
  bucket        = local.code_bucket
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "agent_code" {
  count                   = local.runtime_count
  bucket                  = aws_s3_bucket.agent_code[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "agent_code" {
  count  = local.runtime_count
  bucket = aws_s3_bucket.agent_code[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "agent_code" {
  count  = local.runtime_count
  bucket = aws_s3_bucket.agent_code[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_object" "agent_zip" {
  count       = local.runtime_count
  bucket      = aws_s3_bucket.agent_code[0].id
  key         = local.agent_zip_key
  source      = var.agent_zip_path
  source_hash = filemd5(var.agent_zip_path)

  depends_on = [aws_s3_bucket_versioning.agent_code]
}

# Terraform creates only the empty secret; scripts/put_gateway_secret.py writes the value,
# so the value never enters Terraform state or plan output.
resource "aws_secretsmanager_secret" "gateway_caller" {
  count                   = local.runtime_count
  name                    = "${var.name_prefix}/gateway-caller-client-secret"
  recovery_window_in_days = 0
}

locals {
  agent_environment = var.deploy_runtime ? {
    POC_REGION                = var.aws_region
    ENTRA_TENANT_ID           = var.entra_tenant_id
    GATEWAY_CALLER_CLIENT_ID  = var.gateway_caller_client_id
    GATEWAY_CLIENT_SECRET_ARN = aws_secretsmanager_secret.gateway_caller[0].arn
    GATEWAY_BASE_URL          = trimsuffix(var.gateway_base_url, "/")
    GATEWAY_SCOPE             = "${var.gateway_app_client_id}/.default"
    AGENT_OPENAI_MODEL        = var.agent_openai_model
    AGENT_ANTHROPIC_MODEL     = var.agent_anthropic_model
  } : {}
}

module "agent_runtime" {
  count  = local.runtime_count
  source = "../modules/agentcore_agent_runtime"

  name                         = "${var.name_prefix}_agent"
  description                  = "POC agent: inference only through the central LLM gateway"
  code_bucket_name             = aws_s3_bucket.agent_code[0].id
  code_object_key              = aws_s3_object.agent_zip[0].key
  code_object_version_id       = aws_s3_object.agent_zip[0].version_id
  secret_arns                  = [aws_secretsmanager_secret.gateway_caller[0].arn]
  environment_variables        = local.agent_environment
  idle_session_timeout_seconds = var.runtime_idle_session_timeout_seconds
  max_lifetime_seconds         = var.runtime_max_lifetime_seconds
}
