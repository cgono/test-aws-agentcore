resource "aws_iam_role" "resource_hub" {
  name = "${var.name_prefix}_resource_hub"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "lambda.amazonaws.com" } }]
  })
}

resource "aws_iam_role_policy" "resource_hub" {
  name = "resource-hub"
  role = aws_iam_role.resource_hub.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "ListUserPrefixes"
        Effect    = "Allow"
        Action    = ["s3:ListBucket"]
        Resource  = [aws_s3_bucket.workspace.arn]
        Condition = { StringLike = { "s3:prefix" = ["users/*"] } }
      },
      {
        Sid      = "ReadWriteUserObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = ["${aws_s3_bucket.workspace.arn}/users/*"]
      },
      {
        Sid      = "Logs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = ["arn:aws:logs:${var.aws_region}:${local.account_id}:log-group:/aws/lambda/${var.name_prefix}-resource-hub*"]
      },
    ]
  })
}

resource "aws_cloudwatch_log_group" "resource_hub" {
  name              = "/aws/lambda/${var.name_prefix}-resource-hub"
  retention_in_days = 7
}

resource "aws_lambda_function" "resource_hub" {
  function_name     = "${var.name_prefix}-resource-hub"
  role              = aws_iam_role.resource_hub.arn
  runtime           = "python3.13"
  architectures     = ["arm64"]
  handler           = "agentcore_platform_poc.resource_hub.handler.handler"
  memory_size       = 2048
  timeout           = 360
  s3_bucket         = aws_s3_bucket.code.id
  s3_key            = aws_s3_object.bootstrap["bootstrap/resource-hub.zip"].key
  s3_object_version = aws_s3_object.bootstrap["bootstrap/resource-hub.zip"].version_id

  environment {
    variables = {
      TENANT_ID            = var.tenant_id
      HUB_APP_ID           = var.hub_app_id
      ALLOWED_AGENT_IDS    = "${var.research_agent_client_id_plain},${var.bench_agent_client_id_plain}"
      GRANT_PUBLIC_KEY_PEM = data.aws_kms_public_key.grant.public_key_pem
      WORKSPACE_BUCKET     = aws_s3_bucket.workspace.id
      ALLOW_RAW_USER_TOKEN = tostring(var.allow_raw_user_token)
    }
  }

  # The app CD pipeline owns the code after create.
  lifecycle {
    ignore_changes = [s3_key, s3_object_version, source_code_hash]
  }

  depends_on = [aws_cloudwatch_log_group.resource_hub, aws_iam_role_policy.resource_hub]
}

resource "aws_lambda_function_url" "resource_hub" {
  function_name      = aws_lambda_function.resource_hub.function_name
  authorization_type = "NONE" # every request is authenticated in code
  invoke_mode        = "BUFFERED"
}

resource "aws_lambda_permission" "url_invoke" {
  statement_id           = "PublicFunctionUrl"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.resource_hub.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

resource "aws_lambda_permission" "url_invoke_function" {
  statement_id             = "PublicFunctionUrlInvoke"
  action                   = "lambda:InvokeFunction"
  function_name            = aws_lambda_function.resource_hub.function_name
  principal                = "*"
  invoked_via_function_url = true
}
