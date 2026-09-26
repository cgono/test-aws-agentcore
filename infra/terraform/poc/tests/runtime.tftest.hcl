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
  aws_region      = "ap-southeast-1"
  aws_budget_name = "example-budget"
}

run "runtime_is_off_by_default" {
  command = plan

  assert {
    condition     = length(module.agent_runtime) == 0 && length(aws_s3_bucket.agent_code) == 0
    error_message = "Phase 1 applies must not create runtime resources"
  }

  assert {
    condition     = output.agent_runtime_arn == ""
    error_message = "runtime ARN output must be empty when not deployed"
  }
}

run "runtime_on_wires_bucket_zip_secret_and_environment" {
  command = apply

  variables {
    deploy_runtime           = true
    entra_tenant_id          = "example-tenant"
    gateway_app_client_id    = "gateway-app-id"
    gateway_caller_client_id = "caller-a"
    gateway_base_url         = "https://gateway.example.test/"
    agent_openai_model       = "model-o"
    agent_anthropic_model    = "model-a"
    agent_zip_path           = "tests/fixtures/fake-agent.zip"
  }

  assert {
    condition     = aws_s3_bucket.agent_code[0].bucket == "ci-rt-poc-agent-code-123456789012"
    error_message = "bucket name must be derived from the prefix and account"
  }

  assert {
    condition     = aws_s3_bucket_versioning.agent_code[0].versioning_configuration[0].status == "Enabled"
    error_message = "versioning must be on so new zips get new version ids"
  }

  assert {
    condition     = aws_s3_object.agent_zip[0].source_hash == filemd5("tests/fixtures/fake-agent.zip")
    error_message = "zip object must track the local file's hash"
  }

  assert {
    condition     = aws_secretsmanager_secret.gateway_caller[0].recovery_window_in_days == 0
    error_message = "POC secret must delete immediately on destroy"
  }

  assert {
    condition     = output.agent_environment["GATEWAY_SCOPE"] == "gateway-app-id/.default"
    error_message = "scope must be the gateway app's .default scope"
  }

  assert {
    condition     = output.agent_environment["GATEWAY_BASE_URL"] == "https://gateway.example.test"
    error_message = "trailing slash must be trimmed"
  }

  assert {
    condition     = output.agent_environment["GATEWAY_CLIENT_SECRET_ARN"] == aws_secretsmanager_secret.gateway_caller[0].arn
    error_message = "agent must be told the secret ARN, not the secret"
  }
}

run "runtime_on_requires_https_gateway_url" {
  command = plan

  variables {
    deploy_runtime           = true
    entra_tenant_id          = "example-tenant"
    gateway_app_client_id    = "gateway-app-id"
    gateway_caller_client_id = "caller-a"
    gateway_base_url         = "http://gateway.example.test"
    agent_openai_model       = "model-o"
    agent_anthropic_model    = "model-a"
    agent_zip_path           = "tests/fixtures/fake-agent.zip"
  }

  expect_failures = [var.gateway_base_url]
}

run "runtime_on_requires_tenant" {
  command = plan

  variables {
    deploy_runtime           = true
    gateway_app_client_id    = "gateway-app-id"
    gateway_caller_client_id = "caller-a"
    gateway_base_url         = "https://gateway.example.test"
    agent_openai_model       = "model-o"
    agent_anthropic_model    = "model-a"
    agent_zip_path           = "tests/fixtures/fake-agent.zip"
  }

  expect_failures = [var.entra_tenant_id]
}
