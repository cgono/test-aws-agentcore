output "agent_runtime_arn" {
  value = aws_bedrockagentcore_agent_runtime.this.agent_runtime_arn
}

output "agent_runtime_id" {
  value = aws_bedrockagentcore_agent_runtime.this.agent_runtime_id
}

output "agent_runtime_version" {
  value = aws_bedrockagentcore_agent_runtime.this.agent_runtime_version
}

output "execution_role_arn" {
  value = aws_iam_role.execution.arn
}

output "execution_policy_json" {
  value = aws_iam_role_policy.execution.policy
}

output "authorizer_audience" {
  value = try(aws_bedrockagentcore_agent_runtime.this.authorizer_configuration[0].custom_jwt_authorizer[0].allowed_audience, null)
}

output "request_header_allowlist" {
  value = try(aws_bedrockagentcore_agent_runtime.this.request_header_configuration[0].request_header_allowlist, [])
}
