data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  account_id    = data.aws_caller_identity.current.account_id
  region        = data.aws_region.current.region
  log_group_arn = "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/bedrock-agentcore/runtimes"

  base_statements = [
    {
      Sid      = "RuntimeLogGroups"
      Effect   = "Allow"
      Action   = ["logs:CreateLogGroup", "logs:DescribeLogStreams"]
      Resource = ["${local.log_group_arn}/*"]
    },
    {
      Sid    = "RuntimeLogResourcePolicy"
      Effect = "Allow"
      Action = ["logs:PutResourcePolicy"]
      # PutResourcePolicy and DescribeLogGroups accept no resource ARN; a scoped ARN grants nothing.
      Resource = ["*"]
    },
    {
      Sid      = "DescribeLogGroups"
      Effect   = "Allow"
      Action   = ["logs:DescribeLogGroups"]
      Resource = ["*"]
    },
    {
      Sid      = "RuntimeLogStreams"
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = ["${local.log_group_arn}/*:log-stream:*"]
    },
    {
      Sid      = "Tracing"
      Effect   = "Allow"
      Action   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets"]
      Resource = ["*"]
    },
    {
      Sid       = "Metrics"
      Effect    = "Allow"
      Action    = ["cloudwatch:PutMetricData"]
      Resource  = ["*"]
      Condition = { StringEquals = { "cloudwatch:namespace" = "bedrock-agentcore" } }
    },
    {
      Sid      = "ReadCodePackage"
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:GetObjectVersion"]
      Resource = ["arn:aws:s3:::${var.code_bucket_name}/${var.code_object_key}"]
    },
  ]

  secret_statements = [
    for _ in range(length(var.secret_arns) > 0 ? 1 : 0) : {
      Sid      = "ReadNamedSecrets"
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = var.secret_arns
    }
  ]
}

resource "aws_iam_role" "execution" {
  name = "${var.name}_execution"
  tags = var.tags
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AgentCoreRuntimeAssume"
      Effect    = "Allow"
      Principal = { Service = "bedrock-agentcore.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:aws:bedrock-agentcore:${local.region}:${local.account_id}:*" }
      }
    }]
  })
}

resource "aws_iam_role_policy" "execution" {
  name = "agent-runtime-execution"
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = concat(local.base_statements, local.secret_statements)
  })
}

resource "aws_bedrockagentcore_agent_runtime" "this" {
  agent_runtime_name    = var.name
  description           = var.description
  role_arn              = aws_iam_role.execution.arn
  environment_variables = var.environment_variables
  tags                  = var.tags

  lifecycle_configuration = [{
    idle_runtime_session_timeout = var.idle_session_timeout_seconds
    max_lifetime                 = var.max_lifetime_seconds
  }]

  agent_runtime_artifact {
    code_configuration {
      entry_point = var.entry_point
      runtime     = var.python_runtime

      code {
        s3 {
          bucket     = var.code_bucket_name
          prefix     = var.code_object_key
          version_id = var.code_object_version_id
        }
      }
    }
  }

  network_configuration {
    network_mode = var.network_mode

    dynamic "network_mode_config" {
      for_each = var.network_mode == "VPC" ? [1] : []

      content {
        security_groups = var.vpc_security_group_ids
        subnets         = var.vpc_subnet_ids
      }
    }
  }

  protocol_configuration {
    server_protocol = "HTTP"
  }

  depends_on = [aws_iam_role_policy.execution]
}
