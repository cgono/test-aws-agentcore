locals {
  agents = {
    research = { client_id = var.research_agent_client_id, client_secret = var.research_agent_client_secret }
    bench    = { client_id = var.bench_agent_client_id, client_secret = var.bench_agent_client_secret }
  }
}

# Client-credentials (M2M) providers. Secrets are write-only: never in state or plan.
resource "aws_bedrockagentcore_oauth2_credential_provider" "agent" {
  for_each                   = toset(["research", "bench"])
  name                       = "${var.name_prefix}-${each.key}-agent"
  credential_provider_vendor = "CustomOauth2"

  oauth2_provider_config {
    custom_oauth2_provider_config {
      client_id_wo                  = local.agents[each.key].client_id
      client_secret_wo              = local.agents[each.key].client_secret
      client_credentials_wo_version = var.credentials_version

      oauth_discovery {
        discovery_url = local.discovery_url
      }
    }
  }
}

locals {
  # Identity POC finding: bedrock-agentcore:* alone does not cover the provider's managed secret.
  identity_statements = {
    for name, provider in aws_bedrockagentcore_oauth2_credential_provider.agent : name => [
      {
        Sid    = "IdentityTokens"
        Effect = "Allow"
        Action = [
          "bedrock-agentcore:GetResourceOauth2Token",
          "bedrock-agentcore:GetWorkloadAccessToken",
          "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
        ]
        Resource = [
          "arn:aws:bedrock-agentcore:${var.aws_region}:${local.account_id}:workload-identity-directory/default",
          "arn:aws:bedrock-agentcore:${var.aws_region}:${local.account_id}:workload-identity-directory/default/workload-identity/*",
          "arn:aws:bedrock-agentcore:${var.aws_region}:${local.account_id}:token-vault/default",
          provider.credential_provider_arn,
        ]
      },
      {
        Sid      = "ProviderSecret"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [provider.client_secret_arn[0].secret_arn]
      },
    ]
  }
}
